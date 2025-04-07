import * as fs from 'fs';
import * as path from 'path';
import { DetectionService } from '../../src/modules/detection-module/service';
import { DetectionRequest } from '../../src/modules/detection-module/dtos/requests/detect-request';
import { DetectionReporter, DetectionReport } from '../../src/modules/detection-module/utils/detection-reporter';
import { DetectionResponse } from '../../src/modules/detection-module/dtos/responses';
import { DetectionResult } from '../../src/modules/detection-module/types/detection-result';

/**
 * Utility to generate detailed reports for test transactions to make test cases clearer
 */
export class TestReportGenerator {
  /**
   * Generate reports for a set of test requests
   */
  static generateReports(testSuite: string, requests: DetectionRequest[]): void {
    const reports: Record<string, DetectionReport> = {};
    
    requests.forEach((request) => {
      const result = DetectionService.detect(request);
      // Transform DetectionResponse to DetectionResult
      const detectionResult: DetectionResult = {
        detected: result.detected,
        message: result.message,
        details: {},
        type: undefined
      };
      
      // Convert detectionDetails to details
      if (result.detectionDetails) {
        Object.entries(result.detectionDetails).forEach(([key, value]) => {
          detectionResult.details[key] = value;
        });
      }
      
      const report = DetectionReporter.generateReport(request, detectionResult);
      
      // Create a simple name for the report based on the test case
      let testName = `${testSuite}-${request.hash.substring(0, 8)}`;
      if (request.additionalData?.testName && typeof request.additionalData.testName === 'string') {
        testName = request.additionalData.testName;
      }
      
      reports[testName] = report;
    });
    
    // Create reports directory if it doesn't exist
    const reportsDir = path.join(__dirname, '..', 'reports');
    if (!fs.existsSync(reportsDir)) {
      fs.mkdirSync(reportsDir, { recursive: true });
    }
    
    // Save the reports
    const outputPath = path.join(reportsDir, `${testSuite}-reports.json`);
    fs.writeFileSync(outputPath, JSON.stringify(reports, null, 2));
    
    console.log(`Reports generated for ${testSuite} in ${outputPath}`);
    
    // Generate an HTML summary report for visualization
    this.generateHtmlReport(testSuite, reports, reportsDir);
  }
  
  /**
   * Generate an HTML report for visualization
   */
  private static generateHtmlReport(testSuite: string, reports: Record<string, DetectionReport>, outputDir: string): void {
    // Create a type-safe version of the reports
    const safeReports = JSON.parse(JSON.stringify(reports)) as Record<string, DetectionReport>;
    
    // Generate the HTML content
    const html = `
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Transaction Security Detection Visualization</title>
      <style>
        body {
          font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
          line-height: 1.6;
          color: #333;
          margin: 0;
          padding: 20px;
          background-color: #f5f7fa;
        }
        
        h1, h2, h3, h4 {
          color: #2c3e50;
          margin-top: 0;
        }
        
        .container {
          max-width: 1200px;
          margin: 0 auto;
          background: white;
          border-radius: 8px;
          box-shadow: 0 2px 10px rgba(0,0,0,0.05);
          padding: 30px;
        }
        
        .header {
          margin-bottom: 30px;
          border-bottom: 1px solid #eee;
          padding-bottom: 20px;
        }
        
        .test-case {
          margin-bottom: 40px;
          border: 1px solid #eee;
          border-radius: 6px;
          padding: 20px;
          box-shadow: 0 1px 3px rgba(0,0,0,0.05);
          transition: box-shadow 0.3s;
        }
        
        .test-case:hover {
          box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        
        .test-case.flagged {
          border-left: 4px solid #e74c3c;
        }
        
        .test-case.legitimate {
          border-left: 4px solid #2ecc71;
        }
        
        .test-meta {
          display: flex;
          justify-content: space-between;
          margin-bottom: 15px;
        }
        
        .test-id {
          font-weight: bold;
          color: #7f8c8d;
        }
        
        .status {
          font-weight: bold;
          display: inline-block;
          padding: 4px 10px;
          border-radius: 4px;
        }
        
        .status.detected {
          background-color: #e74c3c;
          color: white;
        }
        
        .status.safe {
          background-color: #2ecc71;
          color: white;
        }
        
        .test-info {
          display: flex;
          gap: 20px;
          margin: 20px 0;
        }
        
        .test-column {
          flex: 1;
        }
        
        .test-detail {
          margin-bottom: 20px;
        }
        
        .test-label {
          font-weight: 600;
          margin-bottom: 5px;
          color: #34495e;
        }
        
        .risk-meter {
          height: 15px;
          background: linear-gradient(to right, #2ecc71, #f1c40f, #e74c3c);
          border-radius: 10px;
          position: relative;
          margin-top: 10px;
          overflow: hidden;
        }
        
        .risk-indicator {
          width: 10px;
          height: 25px;
          background-color: #333;
          position: absolute;
          top: -5px;
        }
        
        .key-value {
          display: flex;
          margin-bottom: 5px;
        }
        
        .key {
          font-weight: 600;
          min-width: 180px;
          color: #7f8c8d;
        }
        
        .value {
          word-break: break-all;
        }
        
        .code-block {
          background-color: #f8f9fa;
          padding: 12px;
          border-radius: 4px;
          font-family: 'Consolas', 'Monaco', monospace;
          white-space: pre;
          overflow-x: auto;
          font-size: 13px;
          line-height: 1.5;
          border: 1px solid #eee;
        }
        
        .timeline {
          margin-top: 30px;
          position: relative;
        }
        
        .timeline:before {
          content: '';
          position: absolute;
          top: 0;
          left: 20px;
          height: 100%;
          width: 2px;
          background: #ddd;
        }
        
        .timeline-event {
          position: relative;
          margin-bottom: 20px;
          padding-left: 50px;
        }
        
        .timeline-step {
          position: absolute;
          left: 10px;
          width: 22px;
          height: 22px;
          border-radius: 50%;
          background: #3498db;
          color: white;
          text-align: center;
          line-height: 22px;
          font-size: 12px;
          font-weight: bold;
          z-index: 1;
        }
        
        .timeline-content {
          padding: 12px 15px;
          background: #f8f9fb;
          border-radius: 4px;
          box-shadow: 0 1px 3px rgba(0,0,0,0.05);
        }
        
        .timeline-event.value_transfer .timeline-step {
          background-color: #9b59b6;
        }
        
        .timeline-event.detected .timeline-step {
          background-color: #e74c3c;
        }
        
        .timeline-event.safe .timeline-step {
          background-color: #2ecc71;
        }
        
        .timeline-event.governance .timeline-step {
          background-color: #f39c12;
        }
        
        .timeline-event.oracle .timeline-step {
          background-color: #1abc9c;
        }
        
        .timeline-event.bridge .timeline-step {
          background-color: #34495e;
        }

        .timeline-event.flash_loan .timeline-step {
          background-color: #d35400;
        }

        .timeline-event.unlimited_approval .timeline-step {
          background-color: #c0392b;
        }
        
        .highlight {
          text-decoration: underline;
          font-weight: bold;
        }
        
        .factor-list {
          margin-top: 20px;
        }
        
        .factor {
          padding: 12px;
          border-radius: 4px;
          margin-bottom: 10px;
          position: relative;
          border-left: 4px solid #ccc;
        }
        
        .factor.positive {
          background-color: #f8f5f5;
          border-left-color: #e74c3c;
        }
        
        .factor.negative {
          background-color: #f1f9f1;
          border-left-color: #2ecc71;
        }
        
        .factor-weight {
          position: absolute;
          right: 15px;
          top: 12px;
          font-size: 12px;
          padding: 2px 8px;
          border-radius: 10px;
        }
        
        .weight-high {
          background-color: #e74c3c;
          color: white;
        }
        
        .weight-medium {
          background-color: #f39c12;
          color: white;
        }
        
        .weight-low {
          background-color: #3498db;
          color: white;
        }
        
        .additional-details {
          margin-top: 20px;
          background-color: #f8f9fa;
          border: 1px solid #eee;
          border-radius: 4px;
          padding: 15px;
        }
        
        .collapsible-toggle {
          background-color: #f8f9fa;
          border: none;
          border-radius: 4px;
          padding: 8px 15px;
          text-align: left;
          font-weight: 600;
          display: flex;
          justify-content: space-between;
          align-items: center;
          width: 100%;
          cursor: pointer;
        }
        
        .collapsible-content {
          max-height: 0;
          overflow: hidden;
          transition: max-height 0.3s ease-out;
        }
        
        .show-details {
          max-height: 1000px;
        }
        
        @media (max-width: 768px) {
          .test-info {
            flex-direction: column;
          }
        }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="header">
          <h1>Transaction Security Detection Visualization</h1>
          <p>This report shows the results of transaction security detection tests, including both legitimate transactions and those flagged as potential attacks.</p>
        </div>
        
        ${Object.entries(safeReports).map(([name, report]) => `
          <div class="test-case ${report.detected ? 'flagged' : 'legitimate'}">
            <div class="test-meta">
              <span class="test-id">${name}</span>
              <span class="status ${report.detected ? 'detected' : 'safe'}">${report.detected ? 'FLAGGED' : 'SAFE'}</span>
            </div>
            
            <h3>${name}</h3>
            <p>${report.message}</p>
            
            <div class="test-info">
              <div class="test-column">
                <div class="test-detail">
                  <div class="test-label">Transaction Summary</div>
                  <div class="key-value">
                    <div class="key">From:</div>
                    <div class="value">${report.from}</div>
                  </div>
                  <div class="key-value">
                    <div class="key">To:</div>
                    <div class="value">${report.to}</div>
                  </div>
                  ${report.value ? `
                  <div class="key-value">
                    <div class="key">Value:</div>
                    <div class="value">${report.value} ETH</div>
                  </div>
                  ` : ''}
                  ${report.type ? `
                  <div class="key-value">
                    <div class="key">Detection Type:</div>
                    <div class="value">${report.type}</div>
                  </div>
                  ` : ''}
                </div>
                
                ${report.riskScore > 0 ? `
                <div class="test-detail">
                  <div class="test-label">Risk Assessment</div>
                  <div class="risk-meter">
                    <div class="risk-indicator" style="left: ${report.riskScore}%;"></div>
                  </div>
                  <div style="margin-top: 5px; font-size: 14px; color: #7f8c8d;">
                    Risk Score: ${report.riskScore}%
                  </div>
                </div>
                ` : ''}
              </div>
              
              <div class="test-column">
                <div class="test-detail">
                  <div class="test-label">Detection Result</div>
                  <div class="key-value">
                    <div class="key">Status:</div>
                    <div class="value">${report.detected ? 'Detected as suspicious' : 'No malicious behavior detected'}</div>
                  </div>
                  <div class="key-value">
                    <div class="key">Message:</div>
                    <div class="value">${report.message}</div>
                  </div>
                </div>
              </div>
            </div>
            
            ${report.decisionFactors.length > 0 ? `
            <div class="test-detail">
              <div class="test-label">Decision Factors</div>
              <div class="factor-list">
                ${report.decisionFactors.map(factor => `
                <div class="factor ${factor.impact}">
                  <div class="factor-weight weight-${factor.weight}">${factor.weight}</div>
                  <div style="font-weight: 600;">${factor.name}</div>
                  <div style="margin-top: 5px;">${factor.description}</div>
                </div>
                `).join('')}
              </div>
            </div>
            ` : ''}
            
            <div class="timeline">
              <h4>Transaction Timeline</h4>
              ${report.visualizationData.timelineEvents.map(event => `
              <div class="timeline-event ${event.highlights.join(' ')}">
                <div class="timeline-step">${event.step}</div>
                <div class="timeline-content">
                  ${event.description}
                </div>
              </div>
              `).join('')}
            </div>
            
            ${report.code ? `
            <div class="additional-details">
              <button class="collapsible-toggle" onclick="this.nextElementSibling.classList.toggle('show-details')">
                View Transaction Code
                <span>+</span>
              </button>
              <div class="collapsible-content">
                <div class="code-block">${report.code}</div>
              </div>
            </div>
            ` : ''}
          </div>
        `).join('')}
      </div>
      
      <script>
        // Toggle collapsible sections
        document.querySelectorAll('.collapsible-toggle').forEach(button => {
          button.addEventListener('click', () => {
            const content = button.nextElementSibling;
            if (content.style.maxHeight) {
              content.style.maxHeight = null;
              button.querySelector('span').textContent = '+';
            } else {
              content.style.maxHeight = content.scrollHeight + "px";
              button.querySelector('span').textContent = '-';
            }
          });
        });
      </script>
    </body>
    </html>
    `;
    
    // Write the HTML file
    const htmlPath = path.join(outputDir, `${testSuite}-report.html`);
    fs.writeFileSync(htmlPath, html);
    
    console.log(`HTML report generated for ${testSuite} in ${htmlPath}`);
  }
} 