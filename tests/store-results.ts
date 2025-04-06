import fs from 'fs';
import path from 'path';
import { DetectionService } from '../src/modules/detection-module/service';
import { DetectionRequest } from '../src/modules/detection-module/dtos/requests/detect-request';

// Test addresses
const addresses = {
  legitimate: '0x1234567890123456789012345678901234567890',
  attacker: '0x6234567890123456789012345678901234567890',
  victim: '0x7234567890123456789012345678901234567890',
  blacklisted: '0x4d90e2fc6dd6c1e0a45e15a535d89ecbe11da766',
  similar: '0x1234567890123456789012345678901234567891'
};

// Base request template
const baseRequest: Partial<DetectionRequest> = {
  id: 'test-id',
  detectorName: 'test-detector',
  chainId: 1,
  hash: '0x123',
  protocolName: 'test-protocol',
  protocolAddress: addresses.legitimate
};

// Helper function to create test requests
const createRequest = (trace: any): DetectionRequest => ({
  ...baseRequest,
  trace: {
    blockNumber: 12345,
    from: addresses.legitimate,
    to: addresses.legitimate,
    transactionHash: '0x123',
    input: '0x',
    output: '0x1',
    gas: '21000',
    gasUsed: '21000',
    value: '0',
    pre: {
      [addresses.legitimate]: {
        balance: '1000000000000000000',
        nonce: 1
      }
    },
    post: {
      [addresses.legitimate]: {
        balance: '1000000000000000000',
        nonce: 2
      }
    },
    ...trace
  }
} as DetectionRequest);

// Test cases
const testCases = {
  legitimate: {
    normal_transfer: createRequest({
      input: '0xa9059cbb',
      value: '1000000000000000000'
    }),
    normal_contract_interaction: createRequest({
      input: '0x095ea7b3',
      value: '0'
    })
  },
  spoofing: {
    blacklisted_address: createRequest({
      from: addresses.blacklisted
    }),
    address_spoofing: createRequest({
      from: addresses.legitimate,
      to: addresses.similar
    }),
    hash_manipulation: createRequest({
      transactionHash: '0x1111111111111111111111111111111111111111111111111111111111111111'
    })
  },
  phishing: {
    malicious_approve: createRequest({
      input: '0x095ea7b3ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
    }),
    ownership_transfer: createRequest({
      logs: [{
        address: addresses.legitimate,
        data: '0x',
        topics: ['0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0']
      }]
    })
  },
  poisoning: {
    known_pattern: createRequest({
      input: '0x47e7ef24'
    }),
    unusual_state_changes: createRequest({
      pre: {
        [addresses.victim]: {
          balance: '1000000000000000000',
          storage: { '0x0': '0x1' }
        }
      },
      post: {
        [addresses.victim]: {
          balance: '0',
          storage: { '0x0': '0x0', '0x1': '0x1', '0x2': '0x1' }
        }
      }
    })
  },
  reentrancy: {
    nested_calls: createRequest({
      calls: [
        {
          from: addresses.attacker,
          to: addresses.victim,
          input: '0x2e1a7d4d',
          output: '0x1',
          gasUsed: '100000',
          value: '1000000000000000000',
          calls: [
            {
              from: addresses.victim,
              to: addresses.attacker,
              input: '0x2e1a7d4d',
              output: '0x1',
              gasUsed: '100000',
              value: '1000000000000000000',
              calls: [
                {
                  from: addresses.attacker,
                  to: addresses.victim,
                  input: '0x2e1a7d4d',
                  output: '0x1',
                  gasUsed: '100000',
                  value: '1000000000000000000'
                }
              ]
            }
          ]
        }
      ]
    })
  },
  front_running: {
    high_gas: createRequest({
      gas: '2000000'
    })
  },
  abnormal_value: {
    high_value: createRequest({
      value: '100000000000000000000'
    })
  },
  flash_loan: {
    flash_loan_pattern: createRequest({
      calls: [
        {
          from: addresses.attacker,
          to: addresses.victim,
          input: '0xc3018a0e',
          output: '0x1',
          gasUsed: '100000',
          value: '1000000000000000000000'
        },
        {
          from: addresses.victim,
          to: addresses.attacker,
          input: '0x',
          output: '0x1',
          gasUsed: '100000',
          value: '1000000000000000000000'
        }
      ]
    })
  },
  honeypot: {
    failed_withdrawal: createRequest({
      calls: [
        {
          from: addresses.legitimate,
          to: addresses.victim,
          input: '0x2e1a7d4d',
          output: '0x',
          gasUsed: '100000',
          value: '0'
        }
      ]
    })
  },
  multiple_threats: {
    combined_threats: createRequest({
      from: addresses.blacklisted,
      gas: '2000000',
      value: '100000000000000000000',
      input: '0x47e7ef24'
    })
  }
};

// Run all test cases and store results
const results: Record<string, Record<string, any>> = {};

Object.entries(testCases).forEach(([category, cases]) => {
  results[category] = {};
  Object.entries(cases).forEach(([testName, request]) => {
    const result = DetectionService.detect(request);
    results[category][testName] = {
      request,
      result,
      timestamp: new Date().toISOString()
    };
  });
});

// Store results in a JSON file
const resultsDir = path.join(__dirname, '../test-results');
if (!fs.existsSync(resultsDir)) {
  fs.mkdirSync(resultsDir);
}

const resultsPath = path.join(resultsDir, `detection-results-${new Date().toISOString().replace(/:/g, '-')}.json`);
fs.writeFileSync(resultsPath, JSON.stringify(results, null, 2));

console.log(`Test results stored in: ${resultsPath}`); 