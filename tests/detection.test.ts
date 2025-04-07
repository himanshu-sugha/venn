import { DetectionService } from '../src/modules/detection-module/service';
import { DetectionRequest } from '../src/modules/detection-module/dtos/requests/detect-request';

describe('Blockchain Security Detection Tests', () => {
  // Test addresses
  const addresses = {
    legitimate: '0x1234567890123456789012345678901234567890',
    attacker: '0x6234567890123456789012345678901234567890',
    victim: '0x7234567890123456789012345678901234567890',
    blacklisted: '0x4d90e2fc6dd6c1e0a45e15a535d89ecbe11da766',
    similar: '0x1234567890123456789012345678901234567891' // Similar to legitimate
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

  describe('Legitimate Transactions', () => {
    test('should pass normal transfer', () => {
      const request = createRequest({
        input: '0xa9059cbb', // transfer
        value: '1000000000000000000' // 1 ETH
      });

      const result = DetectionService.detect(request);
      expect(result.detected).toBe(false);
      expect(result.message).toBe('No threats detected');
    });

    test('should pass normal contract interaction', () => {
      const request = createRequest({
        input: '0x095ea7b3', // approve with limited amount
        value: '0'
      });

      const result = DetectionService.detect(request);
      expect(result.detected).toBe(false);
    });

    test('should pass normal value transfer to trusted address', () => {
      const request = createRequest({
        from: addresses.legitimate,
        to: '0x2234567890123456789012345678901234567890', // Not blacklisted
        value: '5000000000000000000', // 5 ETH
        input: '0x'
      });

      const result = DetectionService.detect(request);
      expect(result.detected).toBe(false);
    });
  });

  describe('Spoofing Detection', () => {
    test('should detect blacklisted address', () => {
      const request = createRequest({
        from: addresses.blacklisted
      });

      const result = DetectionService.detect(request);
      expect(result.detected).toBe(true);
      expect(result.detectionDetails.spoofing).toBeDefined();
    });

    test('should detect address spoofing', () => {
      const request = createRequest({
        from: addresses.legitimate,
        to: addresses.similar
      });

      const result = DetectionService.detect(request);
      expect(result.detected).toBe(true);
      expect(result.detectionDetails.spoofing).toBeDefined();
    });

    test('should detect hash manipulation', () => {
      const request = createRequest({
        transactionHash: '0x1111111111111111111111111111111111111111111111111111111111111111'
      });

      const result = DetectionService.detect(request);
      expect(result.detected).toBe(true);
      expect(result.detectionDetails.spoofing).toBeDefined();
    });

    test('should detect transaction from suspicious address with high value', () => {
      const request = createRequest({
        from: addresses.blacklisted,
        value: '50000000000000000000' // 50 ETH
      });

      const result = DetectionService.detect(request);
      expect(result.detected).toBe(true);
      expect(result.detectionDetails.spoofing).toBeDefined();
    });
  });

  describe('Phishing Detection', () => {
    test('should detect malicious approve', () => {
      const request = createRequest({
        from: addresses.attacker,
        to: addresses.victim,
        input: '0x095ea7b3ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
      });

      const result = DetectionService.detect(request);
      expect(result.detected).toBe(true);
      expect(result.detectionDetails.phishing).toBeDefined();
    });

    test('should detect ownership transfer', () => {
      const request = createRequest({
        from: addresses.victim,
        to: addresses.attacker,
        logs: [{
          address: addresses.legitimate,
          data: '0x',
          topics: ['0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0']
        }]
      });

      const result = DetectionService.detect(request);
      expect(result.detected).toBe(true);
      expect(result.detectionDetails.phishing).toBeDefined();
    });

    test('should detect ownership transfer to blacklisted address', () => {
      const request = createRequest({
        from: addresses.victim,
        to: addresses.blacklisted,
        logs: [{
          address: addresses.legitimate,
          data: '0x',
          topics: ['0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0']
        }]
      });

      const result = DetectionService.detect(request);
      expect(result.detected).toBe(true);
      expect(result.detectionDetails.phishing).toBeDefined();
      expect(result.message).toContain('suspicious address');
    });
  });

  describe('Poisoning Detection', () => {
    test('should detect known poisoning pattern', () => {
      const request = createRequest({
        input: '0x47e7ef24' // known poisoning signature
      });

      const result = DetectionService.detect(request);
      expect(result.detected).toBe(true);
      expect(result.detectionDetails.poisoning).toBeDefined();
    });

    test('should detect unusual state changes', () => {
      const request = createRequest({
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
      });

      const result = DetectionService.detect(request);
      expect(result.detected).toBe(true);
      expect(result.detectionDetails.poisoning).toBeDefined();
    });

    test('should detect state changes with many new storage slots', () => {
      const preStorage: Record<string, string> = { '0x0': '0x1' };
      const postStorage: Record<string, string> = { '0x0': '0x1' };
      
      // Add many new storage slots
      for (let i = 1; i < 20; i++) {
        postStorage[`0x${i}`] = '0x1';
      }

      const request = createRequest({
        pre: {
          [addresses.victim]: {
            balance: '1000000000000000000',
            storage: preStorage
          }
        },
        post: {
          [addresses.victim]: {
            balance: '1000000000000000000',
            storage: postStorage
          }
        }
      });

      const result = DetectionService.detect(request);
      expect(result.detected).toBe(true);
      expect(result.detectionDetails.poisoning).toBeDefined();
    });
  });

  describe('Reentrancy Detection', () => {
    test('should detect reentrancy pattern', () => {
      const request = createRequest({
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
      });

      const result = DetectionService.detect(request);
      expect(result.detected).toBe(true);
      expect(result.detectionDetails.reentrancy).toBeDefined();
    });

    test('should detect multiple withdrawals pattern', () => {
      const request = createRequest({
        calls: [
          {
            from: addresses.attacker,
            to: addresses.victim,
            input: '0x2e1a7d4d', // withdraw
            output: '0x1',
            gasUsed: '100000',
            value: '1000000000000000000'
          },
          {
            from: addresses.attacker,
            to: addresses.victim,
            input: '0x2e1a7d4d', // withdraw
            output: '0x1',
            gasUsed: '100000',
            value: '1000000000000000000'
          },
          {
            from: addresses.attacker,
            to: addresses.victim,
            input: '0x2e1a7d4d', // withdraw
            output: '0x1',
            gasUsed: '100000',
            value: '1000000000000000000'
          }
        ]
      });

      const result = DetectionService.detect(request);
      expect(result.detected).toBe(true);
      expect(result.detectionDetails.reentrancy).toBeDefined();
      // Check for specific pattern
      const patterns = result.detectionDetails.reentrancy?.suspiciousPatterns;
      expect(patterns?.some((p: any) => p.pattern === 'multiple_withdrawals')).toBe(true);
    });

    test('should detect write-after-call pattern', () => {
      const request = createRequest({
        calls: [
          {
            from: addresses.attacker,
            to: addresses.victim,
            input: '0x2e1a7d4d', // withdraw
            output: '0x1',
            gasUsed: '100000',
            value: '1000000000000000000'
          },
          {
            from: addresses.victim,
            to: addresses.legitimate,
            input: '0xa9059cbb', // transfer (write operation)
            output: '0x1',
            gasUsed: '50000',
            value: '0'
          }
        ],
        pre: {
          [addresses.victim]: {
            balance: '2000000000000000000',
            storage: { '0x0': '0x1' }
          }
        },
        post: {
          [addresses.victim]: {
            balance: '1000000000000000000',
            storage: { '0x0': '0x0' }
          }
        }
      });

      const result = DetectionService.detect(request);
      expect(result.detected).toBe(true);
    });
  });

  describe('Front-Running Detection', () => {
    test('should detect high gas limit', () => {
      const request = createRequest({
        gas: '2000000' // Unusually high gas limit
      });

      const result = DetectionService.detect(request);
      expect(result.detected).toBe(true);
      expect(result.detectionDetails.frontRunning).toBeDefined();
    });

    test('should detect high gas with specific function call', () => {
      const request = createRequest({
        gas: '2000000', // High gas limit
        input: '0xa9059cbb', // transfer
        value: '1000000000000000000' // 1 ETH
      });

      const result = DetectionService.detect(request);
      expect(result.detected).toBe(true);
      expect(result.detectionDetails.frontRunning).toBeDefined();
    });
  });

  describe('Abnormal Value Detection', () => {
    test('should detect unusually high value', () => {
      const request = createRequest({
        value: '100000000000000000000' // 100 ETH
      });

      const result = DetectionService.detect(request);
      expect(result.detected).toBe(true);
      expect(result.detectionDetails.abnormalValue).toBeDefined();
    });

    test('should detect very high value with specific recipient', () => {
      const request = createRequest({
        value: '500000000000000000000', // 500 ETH
        to: addresses.attacker
      });

      const result = DetectionService.detect(request);
      expect(result.detected).toBe(true);
      expect(result.detectionDetails.abnormalValue).toBeDefined();
    });
  });

  describe('Flash Loan Attack Detection', () => {
    test('should detect flash loan pattern', () => {
      const request = createRequest({
        calls: [
          {
            from: addresses.attacker,
            to: addresses.victim,
            input: '0xc3018a0e', // AAVE flash loan
            output: '0x1',
            gasUsed: '100000',
            value: '1000000000000000000000' // Large value
          },
          {
            from: addresses.victim,
            to: addresses.attacker,
            input: '0x',
            output: '0x1',
            gasUsed: '100000',
            value: '1000000000000000000000' // Repayment
          }
        ]
      });

      const result = DetectionService.detect(request);
      expect(result.detected).toBe(true);
      expect(result.detectionDetails.flashLoan).toBeDefined();
    });

    test('should detect flash loan pattern with multiple operations', () => {
      const request = createRequest({
        calls: [
          {
            from: addresses.attacker,
            to: addresses.victim,
            input: '0xc3018a0e', // AAVE flash loan
            output: '0x1',
            gasUsed: '100000',
            value: '1000000000000000000000' // Large value
          },
          // Multiple intermediary operations
          {
            from: addresses.attacker,
            to: '0x8888888888888888888888888888888888888888',
            input: '0xa9059cbb',
            output: '0x1',
            gasUsed: '50000',
            value: '500000000000000000000'
          },
          {
            from: addresses.attacker,
            to: '0x9999999999999999999999999999999999999999',
            input: '0x095ea7b3',
            output: '0x1',
            gasUsed: '30000',
            value: '0'
          },
          // Repayment
          {
            from: addresses.attacker,
            to: addresses.victim,
            input: '0x',
            output: '0x1',
            gasUsed: '100000',
            value: '1000000000000000000000'
          }
        ]
      });

      const result = DetectionService.detect(request);
      expect(result.detected).toBe(true);
      expect(result.detectionDetails.flashLoan).toBeDefined();
    });
  });

  describe('Honeypot Detection', () => {
    test('should detect failed withdrawals', () => {
      const request = createRequest({
        calls: [
          {
            from: addresses.legitimate,
            to: addresses.victim,
            input: '0x2e1a7d4d', // withdraw
            output: '0x', // Failed
            gasUsed: '100000',
            value: '0'
          }
        ]
      });

      const result = DetectionService.detect(request);
      expect(result.detected).toBe(true);
      expect(result.detectionDetails.honeypot).toBeDefined();
    });

    test('should detect multiple failed calls', () => {
      const request = createRequest({
        calls: [
          {
            from: addresses.legitimate,
            to: addresses.victim,
            input: '0x2e1a7d4d', // withdraw
            output: '0x', // Failed
            gasUsed: '100000',
            value: '0'
          },
          {
            from: addresses.legitimate,
            to: addresses.victim,
            input: '0xa9059cbb', // transfer
            output: '0x', // Failed
            gasUsed: '50000',
            value: '0'
          }
        ]
      });

      const result = DetectionService.detect(request);
      expect(result.detected).toBe(true);
      expect(result.detectionDetails.honeypot).toBeDefined();
    });
  });

  describe('Multiple Threats Detection', () => {
    test('should detect multiple threats', () => {
      const request = createRequest({
        from: addresses.blacklisted,
        gas: '2000000',
        value: '100000000000000000000',
        input: '0x47e7ef24'
      });

      const result = DetectionService.detect(request);
      expect(result.detected).toBe(true);
      expect(Object.keys(result.detectionDetails).length).toBeGreaterThan(1);
    });

    test('should detect complex attack scenario', () => {
      const request = createRequest({
        from: addresses.attacker,
        to: addresses.victim,
        gas: '5000000',
        value: '10000000000000000000',
        input: '0xc3018a0e', // Flash loan
        calls: [
          {
            from: addresses.attacker,
            to: addresses.victim,
            input: '0xc3018a0e', // AAVE flash loan
            output: '0x1',
            gasUsed: '100000',
            value: '1000000000000000000000'
          },
          {
            from: addresses.victim,
            to: addresses.attacker,
            input: '0x2e1a7d4d', // withdraw
            output: '0x1',
            gasUsed: '200000',
            value: '500000000000000000000',
            calls: [
              {
                from: addresses.attacker,
                to: addresses.victim,
                input: '0x2e1a7d4d', // withdraw again (reentrancy)
                output: '0x1',
                gasUsed: '150000',
                value: '500000000000000000000'
              }
            ]
          },
          {
            from: addresses.attacker,
            to: addresses.victim,
            input: '0x',
            output: '0x1',
            gasUsed: '100000',
            value: '1000000000000000000000' // Repayment
          }
        ],
        pre: {
          [addresses.victim]: {
            balance: '1000000000000000000000',
            storage: { '0x0': '0x1', '0x1': '0x1' }
          }
        },
        post: {
          [addresses.victim]: {
            balance: '0',
            storage: { '0x0': '0x0', '0x1': '0x0' }
          }
        }
      });

      const result = DetectionService.detect(request);
      expect(result.detected).toBe(true);
      expect(Object.keys(result.detectionDetails).length).toBeGreaterThan(2);
    });
  });
}); 