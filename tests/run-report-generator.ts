import { DetectionRequest } from '../src/modules/detection-module/dtos/requests/detect-request';
import { TestReportGenerator } from './utils/test-report-generator';

// Example legitimate transaction test case
const legitimateTransaction: DetectionRequest = {
  hash: '0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
  chainId: 1,
  trace: {
    from: '0x1234567890123456789012345678901234567890',
    to: '0x2234567890123456789012345678901234567890',
    value: '5000000000000000000', // 5 ETH
    gas: '21000',
    gasUsed: '21000',
    input: '0x',
    pre: {},
    post: {}
  },
  additionalData: {
    testName: 'Legitimate ETH Transfer',
    senderType: 'verified_entity'
  }
};

// Example suspicious transaction test case
const suspiciousTransaction: DetectionRequest = {
  hash: '0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890',
  chainId: 1,
  trace: {
    from: '0x9876543210987654321098765432109876543210',
    to: '0x8765432109876543210987654321098765432109',
    value: '100000000000000000000', // 100 ETH
    gas: '2000000',
    gasUsed: '1500000',
    input: '0xa9059cbb0000000000000000000000001234567890123456789012345678901234567890000000000000000000000000000000000000000000000000000000000000000a',
    pre: {},
    post: {},
    calls: [
      {
        from: '0x8765432109876543210987654321098765432109',
        to: '0x7654321098765432109876543210987654321098',
        input: '0xc3018a0e', // Flash loan signature
        value: '0',
        gasUsed: '500000',
        calls: []
      },
      {
        from: '0x8765432109876543210987654321098765432109',
        to: '0x1111111111111111111111111111111111111111',
        input: '0x095ea7b3000000000000000000000000222222222222222222222222222222222222222fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff', // Unlimited approval
        value: '0',
        gasUsed: '50000',
        calls: []
      }
    ]
  },
  additionalData: {
    testName: 'Suspicious Flash Loan and Unlimited Approval',
    contractsVerified: false
  }
};

// Example governance attack test case
const governanceAttackTransaction: DetectionRequest = {
  hash: '0xfedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321',
  chainId: 1,
  trace: {
    from: '0x5555555555555555555555555555555555555555',
    to: '0x6666666666666666666666666666666666666666',
    value: '0',
    gas: '5000000',
    gasUsed: '4500000',
    input: '0x0825f38f', // execute function
    pre: {},
    post: {},
    calls: [
      {
        from: '0x5555555555555555555555555555555555555555',
        to: '0x7777777777777777777777777777777777777777',
        input: '0xc3018a0e', // Flash loan signature
        value: '0',
        gasUsed: '1000000',
        calls: []
      },
      {
        from: '0x5555555555555555555555555555555555555555',
        to: '0x6666666666666666666666666666666666666666',
        input: '0x0825f38f', // execute function
        value: '0',
        gasUsed: '3000000',
        calls: [
          {
            from: '0x6666666666666666666666666666666666666666',
            to: '0x8888888888888888888888888888888888888888',
            input: '0xda95691a', // propose function
            value: '0',
            gasUsed: '1000000',
            calls: [
              {
                from: '0x8888888888888888888888888888888888888888',
                to: '0x9999999999999999999999999999999999999999',
                input: '0xa9059cbb', // transfer
                value: '10000000000000000000000', // 10,000 ETH
                gasUsed: '500000',
                calls: []
              }
            ]
          }
        ]
      }
    ]
  },
  additionalData: {
    testName: 'Governance Attack with Treasury Drain',
    operationType: 'suspicious_governance'
  }
};

// Generate reports for our test cases
const testCases = [legitimateTransaction, suspiciousTransaction, governanceAttackTransaction];
TestReportGenerator.generateReports('transaction-examples', testCases);

console.log('Reports generated successfully! Open the HTML report in your browser to view detailed visualizations.');
console.log('Look for the file at: tests/reports/transaction-examples-report.html'); 