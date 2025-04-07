import { DetectionService } from '../src/modules/detection-module/service';
import { DetectionRequest } from '../src/modules/detection-module/dtos/requests/detect-request';

describe('Oracle Manipulation Attack Detection Tests', () => {
  // Test addresses
  const addresses = {
    legitimate: '0x1234567890123456789012345678901234567890',
    attacker: '0x6234567890123456789012345678901234567890',
    victim: '0x7234567890123456789012345678901234567890',
    oracleContract: '0x3234567890123456789012345678901234567890',
    lendingPlatform: '0x4234567890123456789012345678901234567890',
    dex: '0x5234567890123456789012345678901234567890',
  };

  // Base request template
  const baseRequest: Partial<DetectionRequest> = {
    id: 'test-id',
    detectorName: 'oracle-detector',
    chainId: 1,
    hash: '0x123',
    protocolName: 'test-protocol',
    protocolAddress: addresses.oracleContract
  };

  // Helper function to create test requests
  const createRequest = (trace: any): DetectionRequest => ({
    ...baseRequest,
    trace: {
      blockNumber: 12345,
      from: addresses.legitimate,
      to: addresses.oracleContract,
      transactionHash: '0x123',
      input: '0x',
      output: '0x1',
      gas: '21000',
      gasUsed: '21000',
      value: '0',
      pre: {
        [addresses.oracleContract]: {
          balance: '1000000000000000000',
          nonce: 1
        }
      },
      post: {
        [addresses.oracleContract]: {
          balance: '1000000000000000000',
          nonce: 2
        }
      },
      ...trace
    }
  } as DetectionRequest);

  describe('Price Oracle Manipulation', () => {
    test('should detect flash loan based price oracle manipulation', () => {
      const request = createRequest({
        from: addresses.attacker,
        calls: [
          // Flash loan to borrow large amount
          {
            from: addresses.attacker,
            to: '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', // Flash loan provider
            input: '0xc3018a0e', // AAVE flash loan
            output: '0x1',
            gasUsed: '100000',
            value: '0',
            calls: [
              {
                from: '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                to: addresses.attacker,
                input: '0x',
                output: '0x1',
                gasUsed: '100000',
                value: '1000000000000000000000000' // Very large value
              }
            ]
          },
          // Large swap to manipulate price
          {
            from: addresses.attacker,
            to: addresses.dex,
            input: '0x38ed1739', // swapExactTokensForTokens
            output: '0x1',
            gasUsed: '500000',
            value: '0'
          },
          // Oracle updates price
          {
            from: addresses.dex,
            to: addresses.oracleContract,
            input: '0x8c0b4dad', // updatePrice
            output: '0x1',
            gasUsed: '100000',
            value: '0'
          },
          // Exploit the manipulated price (e.g., borrow with inflated collateral)
          {
            from: addresses.attacker,
            to: addresses.lendingPlatform,
            input: '0xc5ebeaec', // borrow
            output: '0x1',
            gasUsed: '300000',
            value: '0'
          },
          // Swap back to original tokens
          {
            from: addresses.attacker,
            to: addresses.dex,
            input: '0x38ed1739', // swapExactTokensForTokens
            output: '0x1',
            gasUsed: '500000',
            value: '0'
          },
          // Repay flash loan
          {
            from: addresses.attacker,
            to: '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', // Flash loan provider
            input: '0x',
            output: '0x1',
            gasUsed: '100000',
            value: '1000000000000000000000000' // Same large value
          }
        ]
      });

      const result = DetectionService.detect(request);
      expect(result.detected).toBe(true);
      expect(result.detectionDetails.oracleManipulation).toBeDefined();
    });

    test('should detect sandwich attack on oracle update', () => {
      const request = createRequest({
        from: addresses.attacker,
        calls: [
          // First trade to move price
          {
            from: addresses.attacker,
            to: addresses.dex,
            input: '0x38ed1739', // swapExactTokensForTokens
            output: '0x1',
            gasUsed: '300000',
            value: '0'
          },
          // Oracle update happens
          {
            from: '0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', // Some normal user or contract
            to: addresses.oracleContract,
            input: '0x8c0b4dad', // updatePrice
            output: '0x1',
            gasUsed: '100000',
            value: '0'
          },
          // Second trade to profit from price movement
          {
            from: addresses.attacker,
            to: addresses.dex,
            input: '0x38ed1739', // swapExactTokensForTokens (reverse direction)
            output: '0x1',
            gasUsed: '300000',
            value: '0'
          }
        ]
      });

      const result = DetectionService.detect(request);
      expect(result.detected).toBe(true);
      expect(result.detectionDetails.oracleManipulation).toBeDefined();
    });
    
    test('should detect TWAP oracle manipulation', () => {
      // Create calls array for multiple blocks of price manipulation
      const calls = [];
      
      // Add 10 sequential trades to manipulate TWAP
      for (let i = 0; i < 10; i++) {
        calls.push({
          from: addresses.attacker,
          to: addresses.dex,
          input: '0x38ed1739', // swapExactTokensForTokens
          output: '0x1',
          gasUsed: '300000',
          value: '0'
        });
      }
      
      // Add the exploit after manipulating TWAP
      calls.push({
        from: addresses.attacker,
        to: addresses.lendingPlatform,
        input: '0xc5ebeaec', // borrow with manipulated collateral value
        output: '0x1',
        gasUsed: '500000',
        value: '0'
      });
      
      const request = createRequest({
        from: addresses.attacker,
        calls
      });

      const result = DetectionService.detect(request);
      expect(result.detected).toBe(true);
      expect(result.detectionDetails.oracleManipulation).toBeDefined();
    });
  });

  describe('Chainlink Oracle Attacks', () => {
    test('should detect stale price data usage', () => {
      const request = createRequest({
        from: addresses.attacker,
        to: addresses.lendingPlatform,
        calls: [
          // Check for stale data (low gas used indicates minimal validation)
          {
            from: addresses.lendingPlatform,
            to: addresses.oracleContract, // Chainlink oracle
            input: '0x50d25bcd', // latestRoundData()
            output: '0x1',
            gasUsed: '20000', // Low gas usage
            value: '0'
          },
          // Exploit with no timestamp validation
          {
            from: addresses.lendingPlatform,
            to: addresses.victim,
            input: '0xc5ebeaec', // borrow
            output: '0x1',
            gasUsed: '300000',
            value: '0'
          }
        ]
      });

      const result = DetectionService.detect(request);
      expect(result.detected).toBe(true);
      expect(result.detectionDetails.oracleManipulation).toBeDefined();
    });
    
    test('should detect oracle price circuit breaker bypass', () => {
      const request = createRequest({
        from: addresses.attacker,
        calls: [
          // Flash loan to get funds
          {
            from: addresses.attacker,
            to: '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', // Flash loan provider
            input: '0xc3018a0e', // AAVE flash loan
            output: '0x1',
            gasUsed: '100000',
            value: '0',
            calls: [
              {
                from: '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                to: addresses.attacker,
                input: '0x',
                output: '0x1',
                gasUsed: '100000',
                value: '1000000000000000000000000' // Very large value
              }
            ]
          },
          // Multiple small swaps to avoid circuit breaker
          {
            from: addresses.attacker,
            to: addresses.dex,
            input: '0x38ed1739', // swapExactTokensForTokens
            output: '0x1',
            gasUsed: '200000',
            value: '0'
          },
          {
            from: addresses.attacker,
            to: addresses.dex,
            input: '0x38ed1739', // swapExactTokensForTokens
            output: '0x1',
            gasUsed: '200000',
            value: '0'
          },
          {
            from: addresses.attacker,
            to: addresses.dex,
            input: '0x38ed1739', // swapExactTokensForTokens
            output: '0x1',
            gasUsed: '200000',
            value: '0'
          },
          // Oracle update with price shift just under circuit breaker limit
          {
            from: addresses.dex,
            to: addresses.oracleContract,
            input: '0x8c0b4dad', // updatePrice
            output: '0x1',
            gasUsed: '100000',
            value: '0'
          },
          // Exploit
          {
            from: addresses.attacker,
            to: addresses.lendingPlatform,
            input: '0xc5ebeaec', // borrow
            output: '0x1',
            gasUsed: '300000',
            value: '0'
          },
          // Repay flash loan
          {
            from: addresses.attacker,
            to: '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', // Flash loan provider
            input: '0x',
            output: '0x1',
            gasUsed: '100000',
            value: '1000000000000000000000000' // Same large value
          }
        ]
      });

      const result = DetectionService.detect(request);
      expect(result.detected).toBe(true);
      expect(result.detectionDetails.oracleManipulation).toBeDefined();
    });
  });

  describe('DEX Oracle Attacks', () => {
    test('should detect single-block price manipulation', () => {
      const request = createRequest({
        from: addresses.attacker,
        to: addresses.dex,
        calls: [
          // Large swap in
          {
            from: addresses.attacker,
            to: addresses.dex,
            input: '0x38ed1739', // swapExactTokensForTokens
            output: '0x1',
            gasUsed: '300000',
            value: '100000000000000000000' // Large value
          },
          // DEX price updated internally
          {
            from: addresses.dex,
            to: addresses.dex,
            input: '0xffffffff', // internal call
            output: '0x1',
            gasUsed: '50000',
            value: '0'
          },
          // Exploiting contract reads manipulated price
          {
            from: addresses.victim,
            to: addresses.dex,
            input: '0x0dfe1681', // getReserves or price read
            output: '0x1',
            gasUsed: '20000',
            value: '0'
          },
          // Large swap out in opposite direction
          {
            from: addresses.attacker,
            to: addresses.dex,
            input: '0x38ed1739', // swapExactTokensForTokens
            output: '0x1',
            gasUsed: '300000',
            value: '100000000000000000000' // Large value
          }
        ],
        pre: {
          [addresses.dex]: {
            balance: '1000000000000000000000',
            storage: { 
              '0x0': '0x100000000000000000000000', // Initial reserves token 1
              '0x1': '0x100000000000000000000000'  // Initial reserves token 2
            }
          }
        },
        post: {
          [addresses.dex]: {
            balance: '1000000000000000000000',
            storage: { 
              '0x0': '0x100000000000000000000000', // Final reserves token 1
              '0x1': '0x100000000000000000000000'  // Final reserves token 2
            }
          }
        }
      });

      const result = DetectionService.detect(request);
      expect(result.detected).toBe(true);
      expect(result.detectionDetails.oracleManipulation).toBeDefined();
    });
    
    test('should detect low liquidity pool manipulation', () => {
      const request = createRequest({
        from: addresses.attacker,
        to: '0xcccccccccccccccccccccccccccccccccccccccc', // Low liquidity pool
        calls: [
          // Swap that significantly impacts price
          {
            from: addresses.attacker,
            to: '0xcccccccccccccccccccccccccccccccccccccccc', // Low liquidity pool
            input: '0x38ed1739', // swapExactTokensForTokens
            output: '0x1',
            gasUsed: '200000',
            value: '10000000000000000000' // Moderate value but large impact
          },
          // Oracle contract reads manipulated price
          {
            from: addresses.oracleContract,
            to: '0xcccccccccccccccccccccccccccccccccccccccc', // Low liquidity pool
            input: '0x0dfe1681', // getReserves or price read
            output: '0x1',
            gasUsed: '20000',
            value: '0'
          },
          // Protocol uses manipulated oracle price
          {
            from: addresses.victim,
            to: addresses.oracleContract,
            input: '0x50d25bcd', // getPrice
            output: '0x1',
            gasUsed: '20000',
            value: '0'
          }
        ],
        pre: {
          ['0xcccccccccccccccccccccccccccccccccccccccc']: { // Low liquidity pool
            balance: '100000000000000000000', // Small liquidity
            storage: { 
              '0x0': '0x10000000000000000000', // Small reserves token 1
              '0x1': '0x10000000000000000000'  // Small reserves token 2
            }
          }
        },
        post: {
          ['0xcccccccccccccccccccccccccccccccccccccccc']: { // Low liquidity pool
            balance: '100000000000000000000',
            storage: { 
              '0x0': '0x20000000000000000000', // Significantly changed reserves token 1
              '0x1': '0x5000000000000000000'  // Significantly changed reserves token 2
            }
          }
        }
      });

      const result = DetectionService.detect(request);
      expect(result.detected).toBe(true);
      expect(result.detectionDetails.oracleManipulation).toBeDefined();
    });
  });
}); 