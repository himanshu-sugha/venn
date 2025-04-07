import { DetectionService } from '../src/modules/detection-module/service';
import { DetectionRequest } from '../src/modules/detection-module/dtos/requests/detect-request';

describe('Cross-Chain Attack Detection Tests', () => {
  // Test addresses
  const addresses = {
    legitimate: '0x1234567890123456789012345678901234567890',
    attacker: '0x6234567890123456789012345678901234567890',
    victim: '0x7234567890123456789012345678901234567890',
    bridge: '0x8234567890123456789012345678901234567890',
    crossChainOracle: '0x9234567890123456789012345678901234567890',
    relayer: '0xa234567890123456789012345678901234567890',
  };

  // Base request template
  const baseRequest: Partial<DetectionRequest> = {
    id: 'test-id',
    detectorName: 'cross-chain-detector',
    chainId: 1,
    hash: '0x123',
    protocolName: 'test-bridge',
    protocolAddress: addresses.bridge
  };

  // Helper function to create test requests
  const createRequest = (trace: any): DetectionRequest => ({
    ...baseRequest,
    trace: {
      blockNumber: 12345,
      from: addresses.legitimate,
      to: addresses.bridge,
      transactionHash: '0x123',
      input: '0x',
      output: '0x1',
      gas: '21000',
      gasUsed: '21000',
      value: '0',
      pre: {
        [addresses.bridge]: {
          balance: '1000000000000000000000',
          nonce: 1
        }
      },
      post: {
        [addresses.bridge]: {
          balance: '1000000000000000000000',
          nonce: 2
        }
      },
      ...trace
    }
  } as DetectionRequest);

  describe('Bridge Exploits', () => {
    test('should detect unauthorized bridge withdrawal', () => {
      const request = createRequest({
        from: addresses.attacker,
        to: addresses.bridge,
        input: '0x89afcb44', // some bridge withdrawal function
        calls: [
          // Call to possibly manipulated verification
          {
            from: addresses.bridge,
            to: addresses.crossChainOracle, 
            input: '0xa2e62045', // verifyProof or similar
            output: '0x1',
            gasUsed: '50000',
            value: '0'
          },
          // Bridge transfers funds to attacker
          {
            from: addresses.bridge,
            to: addresses.attacker,
            input: '0xa9059cbb', // transfer
            output: '0x1',
            gasUsed: '100000',
            value: '5000000000000000000000' // Large value
          }
        ],
        pre: {
          [addresses.bridge]: {
            balance: '10000000000000000000000',
            nonce: 5
          }
        },
        post: {
          [addresses.bridge]: {
            balance: '5000000000000000000000', // Reduced by withdrawal
            nonce: 6
          }
        }
      });

      const result = DetectionService.detect(request);
      expect(result.detected).toBe(true);
      expect(result.detectionDetails.crossChainAttack).toBeDefined();
    });

    test('should detect bridge validation bypass', () => {
      const request = createRequest({
        from: addresses.attacker,
        calls: [
          // Crafted message submission
          {
            from: addresses.attacker,
            to: addresses.bridge,
            input: '0xc3805300', // submitMessage or similar
            output: '0x1',
            gasUsed: '200000',
            value: '0'
          },
          // Minimal validation (suspicious low gas usage)
          {
            from: addresses.bridge,
            to: addresses.crossChainOracle,
            input: '0xa2e62045', // verifyProof
            output: '0x1',
            gasUsed: '15000', // Suspiciously low gas for validation
            value: '0'
          },
          // Execution with insufficient validators
          {
            from: addresses.bridge,
            to: addresses.victim,
            input: '0xa9059cbb', // transfer
            output: '0x1',
            gasUsed: '100000',
            value: '5000000000000000000000' // Large value
          }
        ]
      });

      const result = DetectionService.detect(request);
      expect(result.detected).toBe(true);
      expect(result.detectionDetails.crossChainAttack).toBeDefined();
    });

    test('should detect cross-chain replay attack', () => {
      const request = createRequest({
        from: addresses.attacker,
        to: addresses.bridge,
        input: '0x89afcb44', // some bridge withdrawal function
        calls: [
          // Bridge checks for replay
          {
            from: addresses.bridge,
            to: addresses.bridge,
            input: '0xffffffff', // internal call
            output: '0x1',
            gasUsed: '10000', // Low gas usage - insufficient checks
            value: '0'
          },
          // Bridge transfers funds
          {
            from: addresses.bridge,
            to: addresses.attacker,
            input: '0xa9059cbb', // transfer
            output: '0x1',
            gasUsed: '100000',
            value: '5000000000000000000000' // Large value
          }
        ],
        // Add custom metadata to show this is a replay
        additionalData: {
          messageTx: '0x1111111111111111111111111111111111111111111111111111111111111111',
          previouslyExecuted: true,
          originalChainId: 56 // Different from tx chain
        }
      });

      const result = DetectionService.detect(request);
      expect(result.detected).toBe(true);
      expect(result.detectionDetails.crossChainAttack).toBeDefined();
    });
  });

  describe('Cross-Chain Oracle Manipulation', () => {
    test('should detect inconsistent price data across chains', () => {
      const request = createRequest({
        from: addresses.relayer,
        to: addresses.crossChainOracle,
        input: '0x6aa14edb', // updatePriceFromSource
        calls: [
          // Oracle validates the cross-chain message
          {
            from: addresses.crossChainOracle,
            to: addresses.bridge,
            input: '0xa8036d4e', // verifyMessage
            output: '0x1',
            gasUsed: '50000',
            value: '0'
          },
          // Oracle updates price with significantly different value
          {
            from: addresses.crossChainOracle,
            to: addresses.crossChainOracle,
            input: '0xffffffff', // internal call
            output: '0x1',
            gasUsed: '30000',
            value: '0'
          }
        ],
        pre: {
          [addresses.crossChainOracle]: {
            balance: '1000000000000000000',
            storage: { '0x5': '0x38D7EA4C68000' } // Price: 1000 USD
          }
        },
        post: {
          [addresses.crossChainOracle]: {
            balance: '1000000000000000000',
            storage: { '0x5': '0x84595161401484A000' } // Price: 2500 USD (150% jump)
          }
        },
        // Additional data to show cross-chain context
        additionalData: {
          sourceChainId: 56,
          destinationChainId: 1,
          sourcePrice: '1000000000000000000000', // 1000 USD
          destinationPrice: '2500000000000000000000' // 2500 USD
        }
      });

      const result = DetectionService.detect(request);
      expect(result.detected).toBe(true);
      expect(result.detectionDetails.crossChainAttack).toBeDefined();
    });

    test('should detect malicious cross-chain relayer', () => {
      const request = createRequest({
        from: addresses.attacker,
        to: addresses.relayer,
        input: '0x9b4034d6', // relayMessage
        calls: [
          // Relayer modifies the message
          {
            from: addresses.relayer,
            to: addresses.relayer,
            input: '0xffffffff', // internal processing
            output: '0x1',
            gasUsed: '30000',
            value: '0'
          },
          // Relayer submits to bridge
          {
            from: addresses.relayer, 
            to: addresses.bridge,
            input: '0x5d0bee59', // submitMessage (altered)
            output: '0x1',
            gasUsed: '200000',
            value: '0'
          },
          // Bridge processes message
          {
            from: addresses.bridge,
            to: addresses.victim,
            input: '0xa9059cbb', // transfer
            output: '0x1',
            gasUsed: '100000',
            value: '5000000000000000000000' // Large value transfer
          }
        ],
        // Additional data showing message was modified
        additionalData: {
          originalMessage: "0x000000000000000000000000a234567890123456789012345678901234567890",
          alteredMessage: "0x0000000000000000000000006234567890123456789012345678901234567890" // Changed recipient to attacker
        }
      });

      const result = DetectionService.detect(request);
      expect(result.detected).toBe(true);
      expect(result.detectionDetails.crossChainAttack).toBeDefined();
    });
  });

  describe('Token Bridge Vulnerabilities', () => {
    test('should detect bridge balance inconsistency', () => {
      const request = createRequest({
        from: addresses.attacker,
        to: addresses.bridge,
        input: '0x89afcb44', // withdraw
        calls: [
          // Bridge processes withdrawal
          {
            from: addresses.bridge,
            to: addresses.attacker,
            input: '0xa9059cbb', // transfer
            output: '0x1',
            gasUsed: '100000',
            value: '1000000000000000000000' // 1000 tokens
          }
        ],
        pre: {
          [addresses.bridge]: {
            balance: '800000000000000000000', // Only 800 tokens (insufficient)
            nonce: 5
          }
        },
        post: {
          [addresses.bridge]: {
            balance: '0', // now zero
            nonce: 6
          }
        },
        // Additional cross-chain context
        additionalData: {
          sourceTotalLocked: '800000000000000000000', // 800 tokens locked on source
          destinationTotalMinted: '1800000000000000000000' // 1800 tokens minted on destination
        }
      });

      const result = DetectionService.detect(request);
      expect(result.detected).toBe(true);
      expect(result.detectionDetails.crossChainAttack).toBeDefined();
    });

    test('should detect double spend across chains', () => {
      const request = createRequest({
        from: addresses.attacker,
        to: addresses.bridge,
        input: '0x89afcb44', // withdraw
        calls: [
          // Bridge checks for double spend
          {
            from: addresses.bridge,
            to: addresses.bridge,
            input: '0xffffffff', // internal call
            output: '0x1',
            gasUsed: '10000', // Low gas suggests insufficient validation
            value: '0'
          },
          // Bridge processes withdrawal
          {
            from: addresses.bridge,
            to: addresses.attacker,
            input: '0xa9059cbb', // transfer
            output: '0x1',
            gasUsed: '100000',
            value: '1000000000000000000000' // 1000 tokens
          }
        ],
        // Additional data showing the double spend
        additionalData: {
          withdrawalId: '0x123456',
          alreadyWithdrawnOnChain: 56,
          currentChain: 1
        }
      });

      const result = DetectionService.detect(request);
      expect(result.detected).toBe(true);
      expect(result.detectionDetails.crossChainAttack).toBeDefined();
    });
  });
}); 