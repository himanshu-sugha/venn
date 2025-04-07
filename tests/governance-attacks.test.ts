import { DetectionService } from '../src/modules/detection-module/service';
import { DetectionRequest } from '../src/modules/detection-module/dtos/requests/detect-request';

describe('Blockchain Governance Attack Detection Tests', () => {
  // Test addresses
  const addresses = {
    legitimate: '0x1234567890123456789012345678901234567890',
    attacker: '0x6234567890123456789012345678901234567890',
    victim: '0x7234567890123456789012345678901234567890',
    governanceContract: '0x5234567890123456789012345678901234567890',
    daoTreasury: '0x8234567890123456789012345678901234567890',
    whale: '0x9234567890123456789012345678901234567890',
  };

  // Base request template
  const baseRequest: Partial<DetectionRequest> = {
    id: 'test-id',
    detectorName: 'governance-detector',
    chainId: 1,
    hash: '0x123',
    protocolName: 'test-dao',
    protocolAddress: addresses.governanceContract
  };

  // Helper function to create test requests
  const createRequest = (trace: any): DetectionRequest => ({
    ...baseRequest,
    trace: {
      blockNumber: 12345,
      from: addresses.legitimate,
      to: addresses.governanceContract,
      transactionHash: '0x123',
      input: '0x',
      output: '0x1',
      gas: '21000',
      gasUsed: '21000',
      value: '0',
      pre: {
        [addresses.governanceContract]: {
          balance: '1000000000000000000',
          nonce: 1
        }
      },
      post: {
        [addresses.governanceContract]: {
          balance: '1000000000000000000',
          nonce: 2
        }
      },
      ...trace
    }
  } as DetectionRequest);

  describe('Flash Loan Governance Attacks', () => {
    test('should detect flash loan followed by governance proposal', () => {
      const request = createRequest({
        calls: [
          // Flash loan to borrow governance tokens
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
                value: '0'
              }
            ]
          },
          // Use borrowed tokens to create a proposal
          {
            from: addresses.attacker,
            to: addresses.governanceContract,
            input: '0xda95691a', // propose(address[],uint256[],string[],bytes[],string)
            output: '0x1',
            gasUsed: '500000',
            value: '0'
          },
          // Immediately vote on the proposal
          {
            from: addresses.attacker,
            to: addresses.governanceContract,
            input: '0x56781388', // castVote(uint256,uint8)
            output: '0x1',
            gasUsed: '200000',
            value: '0'
          },
          // Repay flash loan
          {
            from: addresses.attacker,
            to: '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', // Flash loan provider
            input: '0x',
            output: '0x1',
            gasUsed: '100000',
            value: '0'
          }
        ]
      });

      const result = DetectionService.detect(request);
      expect(result.detected).toBe(true);
      expect(result.detectionDetails.governanceAttack).toBeDefined();
    });

    test('should detect flash loan to manipulate voting power', () => {
      const request = createRequest({
        calls: [
          // Flash loan to borrow governance tokens
          {
            from: addresses.attacker,
            to: '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', // Flash loan provider
            input: '0xc3018a0e', // AAVE flash loan
            output: '0x1',
            gasUsed: '100000',
            value: '0'
          },
          // Large purchase of governance tokens
          {
            from: addresses.attacker,
            to: '0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', // DEX
            input: '0x38ed1739', // swapExactTokensForTokens
            output: '0x1',
            gasUsed: '300000',
            value: '0'
          },
          // Vote on existing proposal with large token amount
          {
            from: addresses.attacker,
            to: addresses.governanceContract, 
            input: '0x56781388', // castVote(uint256,uint8)
            output: '0x1',
            gasUsed: '200000',
            value: '0'
          },
          // Sell governance tokens
          {
            from: addresses.attacker,
            to: '0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', // DEX
            input: '0x38ed1739', // swapExactTokensForTokens
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
            value: '0'
          }
        ]
      });

      const result = DetectionService.detect(request);
      expect(result.detected).toBe(true);
      expect(result.detectionDetails.governanceAttack).toBeDefined();
    });
  });

  describe('DAO Treasury Attacks', () => {
    test('should detect malicious proposal to drain treasury', () => {
      const request = createRequest({
        calls: [
          // Submit malicious proposal
          {
            from: addresses.attacker,
            to: addresses.governanceContract,
            input: '0xda95691a', // propose(address[],uint256[],string[],bytes[],string)
            output: '0x1',
            gasUsed: '500000',
            value: '0'
          },
          // Fast forward execution (this would be in a separate transaction in real life)
          {
            from: addresses.attacker,
            to: addresses.governanceContract,
            input: '0x56781388', // castVote(uint256,uint8)
            output: '0x1',
            gasUsed: '200000',
            value: '0'
          },
          // Execute the proposal that transfers treasury funds
          {
            from: addresses.attacker,
            to: addresses.governanceContract,
            input: '0x0825f38f', // execute(uint256)
            output: '0x1',
            gasUsed: '1000000',
            value: '0',
            calls: [
              {
                from: addresses.governanceContract,
                to: addresses.daoTreasury,
                input: '0x',
                output: '0x1',
                gasUsed: '500000',
                value: '0',
                calls: [
                  {
                    from: addresses.daoTreasury,
                    to: addresses.attacker,
                    input: '0xa9059cbb', // transfer
                    output: '0x1',
                    gasUsed: '100000',
                    value: '5000000000000000000000' // Large value transfer
                  }
                ]
              }
            ]
          }
        ],
        pre: {
          [addresses.daoTreasury]: {
            balance: '10000000000000000000000',
            nonce: 1
          }
        },
        post: {
          [addresses.daoTreasury]: {
            balance: '5000000000000000000000', // Balance reduced by half
            nonce: 2
          }
        }
      });

      const result = DetectionService.detect(request);
      expect(result.detected).toBe(true);
      expect(result.detectionDetails.governanceAttack).toBeDefined();
    });

    test('should detect vote buying attack', () => {
      const request = createRequest({
        calls: [
          // Multiple transfers to potential voters
          {
            from: addresses.attacker,
            to: '0xcccccccccccccccccccccccccccccccccccccccc', // Token contract
            input: '0xa9059cbb', // transfer
            output: '0x1',
            gasUsed: '100000',
            value: '0'
          },
          {
            from: addresses.attacker,
            to: '0xcccccccccccccccccccccccccccccccccccccccc', // Token contract
            input: '0xa9059cbb', // transfer
            output: '0x1',
            gasUsed: '100000',
            value: '0'
          },
          {
            from: addresses.attacker,
            to: '0xcccccccccccccccccccccccccccccccccccccccc', // Token contract
            input: '0xa9059cbb', // transfer
            output: '0x1',
            gasUsed: '100000',
            value: '0'
          },
          // Proposal creation
          {
            from: addresses.attacker,
            to: addresses.governanceContract,
            input: '0xda95691a', // propose
            output: '0x1',
            gasUsed: '500000',
            value: '0'
          }
        ]
      });

      const result = DetectionService.detect(request);
      expect(result.detected).toBe(true);
      expect(result.detectionDetails.governanceAttack).toBeDefined();
    });
  });

  describe('Timelock Manipulation', () => {
    test('should detect attempt to bypass timelock', () => {
      const request = createRequest({
        calls: [
          // Proposal creation
          {
            from: addresses.attacker,
            to: addresses.governanceContract,
            input: '0xda95691a', // propose
            output: '0x1',
            gasUsed: '500000',
            value: '0'
          },
          // Attempt to manipulate blockchain time
          {
            from: addresses.attacker,
            to: '0xdddddddddddddddddddddddddddddddddddddddd', // Some contract with time access
            input: '0x9054c7da', // hypothetical setTime function
            output: '0x1',
            gasUsed: '200000',
            value: '0'
          },
          // Execute without proper delay
          {
            from: addresses.attacker,
            to: addresses.governanceContract,
            input: '0x0825f38f', // execute
            output: '0x1',
            gasUsed: '1000000',
            value: '0'
          }
        ]
      });

      const result = DetectionService.detect(request);
      expect(result.detected).toBe(true);
      expect(result.detectionDetails.governanceAttack).toBeDefined();
    });
  });
}); 