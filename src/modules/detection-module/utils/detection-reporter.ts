import { DetectionRequest } from '../dtos/requests/detect-request';
import { DetectionResult } from '../types/detection-result';

/**
 * Decision factor for the detection report
 */
export interface DecisionFactor {
  name: string;
  description: string;
  impact: 'positive' | 'negative'; // positive means contributing to detection, negative means safe
  weight: 'low' | 'medium' | 'high' | 'critical';
}

/**
 * Timeline event for visualization
 */
export interface TimelineEvent {
  step: number;
  description: string;
  highlights: string[];
}

/**
 * Visualization data for the detection report
 */
export interface VisualizationData {
  timelineEvents: TimelineEvent[];
}

/**
 * Detection report structure for detailed reporting
 */
export interface DetectionReport {
  requestId: string;
  from: string;
  to: string;
  value: string;
  gasUsed: number;
  detected: boolean;
  message: string;
  riskScore: number;
  threatTypes: string[];
  decisionFactors: DecisionFactor[];
  visualizationData: VisualizationData;
  type?: string;  // Type of detection (reentrancy, front-running, etc.)
  code?: string;  // Optional transaction code for display
}

interface SuspiciousPattern {
  description: string;
  severity?: string;
  confidence?: number;
}

/**
 * Utility to generate detailed reports from detection results
 */
export class DetectionReporter {
  /**
   * Generate a detailed report from a detection request and result
   */
  static generateReport(request: DetectionRequest, result: DetectionResult): DetectionReport {
    // Extract basic information
    const detected = result.detected;
    const threatTypes = this.extractThreatTypes(result);
    
    // Calculate risk score and extract decision factors
    const riskScore = this.calculateRiskScore(result);
    const decisionFactors = this.generateDecisionFactors(result);
    
    // Generate visualization data
    const visualizationData = this.generateVisualizationData(request, result);

    return {
      requestId: request.hash,
      from: request.trace.from,
      to: request.trace.to,
      value: request.trace.value || '0',
      gasUsed: Number(request.trace.gas || 0),
      detected,
      message: result.message,
      riskScore,
      threatTypes,
      decisionFactors,
      visualizationData,
      type: result.type || this.determineDetectionType(result)
    };
  }

  /**
   * Extract threat types from detection result
   */
  private static extractThreatTypes(result: DetectionResult): string[] {
    if (!result.detected) return [];
    
    const threatTypes: string[] = [];
    
    // Determine threat types based on detection details
    if (result.details.suspiciousPatterns) {
      threatTypes.push('Suspicious Pattern');
    }
    if (result.details.phishingSignature) {
      threatTypes.push('Phishing');
    }
    if (result.details.poisoningSignature) {
      threatTypes.push('Transaction Poisoning');
    }
    if (result.details.unlimitedApproval) {
      threatTypes.push('Unlimited Approval');
    }
    if (result.details.ownershipTransfer) {
      threatTypes.push('Ownership Transfer');
    }
    if (result.details.highGas) {
      threatTypes.push('High Gas Usage');
    }
    if (result.details.blacklistedAddress) {
      threatTypes.push('Blacklisted Address');
    }
    if (result.details.addressSimilarity) {
      threatTypes.push('Address Similarity Attack');
    }
    if (result.details.reentrancyPaths) {
      threatTypes.push('Reentrancy');
    }
    
    return threatTypes;
  }

  /**
   * Calculate risk score based on detection result
   */
  private static calculateRiskScore(result: DetectionResult): number {
    let score = 0;
    
    // Base score for detection
    if (result.detected) {
      score += 50;
    }
    
    // Add scores based on different factors
    if (result.details.phishingSignature) {
      score += 25;
    }
    
    if (result.details.poisoningSignature) {
      score += 20;
    }
    
    if (result.details.unlimitedApproval) {
      score += 15;
    }
    
    if (result.details.ownershipTransfer) {
      score += 20;
    }
    
    if (result.details.blacklistedAddress) {
      score += 30;
    }
    
    if (result.details.reentrancyPaths) {
      score += 25;
    }
    
    if (result.details.highGas) {
      // Score based on how high the gas is
      const gasValue = result.details.highGas as number;
      if (gasValue > 1000000) {
        score += 15;
      } else if (gasValue > 500000) {
        score += 10;
      } else if (gasValue > 200000) {
        score += 5;
      }
    }
    
    if (result.details.addressSimilarity) {
      const similarity = (result.details.addressSimilarity as { similarity: number }).similarity;
      // Score based on similarity percentage
      if (similarity > 0.9) {
        score += 25;
      } else if (similarity > 0.7) {
        score += 15;
      } else if (similarity > 0.5) {
        score += 10;
      }
    }
    
    // Cap at 100
    return Math.min(100, score);
  }

  /**
   * Generate decision factors based on detection result
   */
  private static generateDecisionFactors(result: DetectionResult): DecisionFactor[] {
    const factors: DecisionFactor[] = [];
    
    if (result.details.phishingSignature) {
      factors.push({
        name: 'Phishing Signature Detected',
        description: `Detected a known phishing signature: ${result.details.phishingSignature}`,
        impact: 'positive',
        weight: 'critical'
      });
    }
    
    if (result.details.poisoningSignature) {
      factors.push({
        name: 'Transaction Poisoning',
        description: `Detected transaction poisoning pattern: ${result.details.poisoningSignature}`,
        impact: 'positive',
        weight: 'high'
      });
    }
    
    if (result.details.unlimitedApproval) {
      factors.push({
        name: 'Unlimited Token Approval',
        description: `Transaction requests unlimited token approval to ${result.details.approvalTarget}`,
        impact: 'positive',
        weight: 'high'
      });
    }
    
    if (result.details.ownershipTransfer) {
      factors.push({
        name: 'Ownership Transfer',
        description: `Contract ownership is being transferred to ${result.details.transferTarget}`,
        impact: 'positive',
        weight: 'high'
      });
    }
    
    if (result.details.highGas) {
      factors.push({
        name: 'Abnormally High Gas',
        description: `Transaction uses abnormally high gas: ${result.details.highGas}`,
        impact: 'positive',
        weight: 'medium'
      });
    }
    
    if (result.details.blacklistedAddress) {
      factors.push({
        name: 'Blacklisted Address',
        description: `Transaction involves a blacklisted address: ${result.details.blacklistedAddress}`,
        impact: 'positive',
        weight: 'critical'
      });
    }
    
    if (result.details.addressSimilarity) {
      const similarity = result.details.addressSimilarity as { from: string; to: string; similarity: number };
      factors.push({
        name: 'Address Similarity Attack',
        description: `Detected similarity (${similarity.similarity.toFixed(2)}) between ${similarity.from} and ${similarity.to}`,
        impact: 'positive',
        weight: similarity.similarity > 0.8 ? 'high' : 'medium'
      });
    }
    
    if (result.details.reentrancyPaths && (result.details.reentrancyPaths as string[][]).length > 0) {
      factors.push({
        name: 'Reentrancy Pattern',
        description: `Detected potential reentrancy paths in transaction`,
        impact: 'positive',
        weight: 'high'
      });
    }
    
    if (result.details.suspiciousPatterns) {
      const patterns = Array.isArray(result.details.suspiciousPatterns) 
        ? result.details.suspiciousPatterns
        : [result.details.suspiciousPatterns];
        
      patterns.forEach(pattern => {
        if (typeof pattern === 'string') {
          factors.push({
            name: 'Suspicious Pattern',
            description: `Detected suspicious pattern: ${pattern}`,
            impact: 'positive',
            weight: 'medium'
          });
        } else if (pattern && typeof pattern === 'object') {
          // Cast to any to avoid TypeScript errors
          const patternObj = pattern as SuspiciousPattern;
          if (patternObj.description) {
            factors.push({
              name: 'Suspicious Pattern',
              description: `Detected suspicious pattern: ${patternObj.description}`,
              impact: 'positive',
              weight: 'medium'
            });
          }
        }
      });
    }
    
    return factors;
  }

  /**
   * Generate timeline visualization data
   */
  private static generateVisualizationData(request: DetectionRequest, result: DetectionResult): VisualizationData {
    const timelineEvents = this.generateTimelineEvents(request, result);
    return { timelineEvents };
  }
  
  /**
   * Generate timeline of significant events in the transaction
   */
  private static generateTimelineEvents(request: DetectionRequest, result: DetectionResult): TimelineEvent[] {
    const events: TimelineEvent[] = [];
    
    // Add initial transaction event
    events.push({
      step: 1,
      description: `Transaction initiated from ${request.trace.from} to ${request.trace.to}`,
      highlights: []
    });
    
    // Add value transfer if present
    if (request.trace.value && parseInt(request.trace.value) > 0) {
      events.push({
        step: events.length + 1,
        description: `Value transfer of ${request.trace.value} ETH`,
        highlights: ['value_transfer']
      });
    }
    
    // Add contract interaction events based on detection details
    let stepCount = events.length + 1;
    
    // Check for phishing details
    if (result.details.unlimitedApproval) {
      events.push({
        step: stepCount++,
        description: `Unlimited token approval requested to ${result.details.approvalTarget}`,
        highlights: ['unlimited_approval']
      });
    }
    
    if (result.details.ownershipTransfer) {
      events.push({
        step: stepCount++,
        description: `Contract ownership transferred to ${result.details.transferTarget}`,
        highlights: ['governance']
      });
    }
    
    // Check for address spoofing/similarity attack
    if (result.details.addressSimilarity) {
      const similarity = result.details.addressSimilarity as { from: string; to: string; similarity: number };
      events.push({
        step: stepCount++,
        description: `Address similarity detected (${(similarity.similarity * 100).toFixed(1)}% match) between ${similarity.from.substring(0, 8)}... and ${similarity.to.substring(0, 8)}...`,
        highlights: ['detected']
      });
    }
    
    // Check for blacklisted addresses
    if (result.details.blacklistedAddress) {
      events.push({
        step: stepCount++,
        description: `Blacklisted address detected: ${result.details.blacklistedAddress}`,
        highlights: ['detected']
      });
    }
    
    // Check for flash loan details
    if (result.details.flashLoan?.flashLoanIndicators) {
      const indicators = result.details.flashLoan.flashLoanIndicators;
      events.push({
        step: stepCount++,
        description: `Flash loan pattern detected${indicators.hasFlashLoanSignature ? ' with known flash loan signature' : ''}`,
        highlights: ['flash_loan']
      });
    }
    
    // Check for front-running details
    if (result.details.frontRunning) {
      const frontRunningDetails = result.details.frontRunning;
      events.push({
        step: stepCount++,
        description: `High gas usage detected: ${frontRunningDetails.highGas} gas (${frontRunningDetails.gasDifference || 'high'} above normal)`,
        highlights: ['detected']
      });
      
      if (frontRunningDetails.transactionType) {
        events.push({
          step: stepCount++,
          description: `Suspicious transaction type: ${frontRunningDetails.transactionType}`,
          highlights: ['detected']
        });
      }
    }
    
    // Check for reentrancy details
    if (result.details.reentrancyPaths) {
      const paths = result.details.reentrancyPaths as string[][];
      if (paths.length > 0) {
        events.push({
          step: stepCount++,
          description: `Reentrancy pattern detected with ${paths.length} circular call path(s)`,
          highlights: ['detected']
        });
        
        // If specific contracts involved, list them
        if (result.details.contractsInvolved) {
          const contracts = result.details.contractsInvolved as string[];
          events.push({
            step: stepCount++,
            description: `Contracts involved in reentrancy: ${contracts.map(c => c.substring(0, 8) + '...').join(', ')}`,
            highlights: ['detected']
          });
        }
      }
    }
    
    // Check for suspicious patterns
    if (result.details.suspiciousPatterns) {
      const patterns = Array.isArray(result.details.suspiciousPatterns) 
        ? result.details.suspiciousPatterns 
        : [result.details.suspiciousPatterns];
      
      patterns.forEach(pattern => {
        if (typeof pattern === 'string') {
          events.push({
            step: stepCount++,
            description: `Suspicious pattern: ${pattern}`,
            highlights: ['detected']
          });
        } else if (pattern && typeof pattern === 'object') {
          // Cast to any to avoid TypeScript errors
          const patternObj = pattern as SuspiciousPattern;
          if (patternObj.description) {
            events.push({
              step: stepCount++,
              description: `Suspicious pattern: ${patternObj.description}`,
              highlights: ['detected']
            });
          }
        }
      });
    }
    
    // Check for oracle manipulation
    if (result.details.oracleManipulation) {
      events.push({
        step: stepCount++,
        description: `Oracle price manipulation detected`,
        highlights: ['oracle']
      });
      
      if (result.details.priceDeviation) {
        events.push({
          step: stepCount++,
          description: `Price deviation: ${result.details.priceDeviation}%`,
          highlights: ['oracle']
        });
      }
    }
    
    // Check for bridge exploitation
    if (result.details.bridgeExploitation) {
      events.push({
        step: stepCount++,
        description: `Bridge exploitation detected`,
        highlights: ['bridge']
      });
    }
    
    // Add result summary
    events.push({
      step: stepCount,
      description: result.detected 
        ? `Transaction flagged: ${result.message}` 
        : `Transaction appears safe: ${result.message}`,
      highlights: [result.detected ? 'detected' : 'safe']
    });
    
    return events;
  }

  /**
   * Determine detection type from the result details
   */
  private static determineDetectionType(result: DetectionResult): string {
    if (!result.detected) return 'safe';
    
    if (result.details.reentrancyPaths) return 'reentrancy';
    if (result.details.highGas) return 'front-running';
    if (result.details.unlimitedApproval) return 'phishing';
    if (result.details.ownershipTransfer) return 'governance';
    if (result.details.blacklistedAddress) return 'blacklisted';
    if (result.details.addressSimilarity) return 'address-spoofing';
    if (result.details.oracleManipulation) return 'oracle-manipulation';
    if (result.details.bridgeExploitation) return 'bridge-exploitation';
    if (result.details.flashLoan) return 'flash-loan';
    
    return 'suspicious';
  }
} 