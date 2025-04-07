import { DetectionService } from '../src/modules/detection-module/service';
import { DetectionRequest } from '../src/modules/detection-module/dtos/requests/detect-request';

describe('False Positive Detection Tests', () => {
  // Test addresses - all legitimate
  const addresses = {
    user: '0x1234567890123456789012345678901234567890',
    protocol: '0x2234567890123456789012345678901234567890',
    dao: '0x3234567890123456789012345678901234567890',
    dex: '0x4234567890123456789012345678901234567890',
    lending: '0x5234567890123456789012345678901234567890',
    bridge: '0x6234567890123456789012345678901234567890',
    staking: '0x7234567890123456789012345678901234567890',
  };

  // Base request template
  const baseRequest: Partial<DetectionRequest> = {
    id: 'test-id',
    detectorName: 'false-positive-detector',
    chainId: 1,
    hash: '0x123',
    protocolName: 'test-protocol',
    protocolAddress: addresses.protocol
  };

  // Helper function to create test requests
  const createRequest = (trace: any): DetectionRequest => ({
    ...baseRequest,
    trace: {
      blockNumber: 12345,
      from: addresses.user,
      to: addresses.protocol,
      transactionHash: '0x123',
      input: '0x',
      output: '0x1',
      gas: '21000',
      gasUsed: '21000',
      value: '0',
      pre: {
        [addresses.protocol]: {
          balance: '1000000000000000000000',
          nonce: 1
        }
      },
      post: {
        [addresses.protocol]: {
          balance: '1000000000000000000000',
          nonce: 2
        }
      },
      ...trace
    }
  } as DetectionRequest);

  describe('Complex DeFi Transactions', () => {
    test('legitimate flash loan for arbitrage', () => {
      const request = createRequest({
        from: addresses.user,
        to: '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', // Flash loan provider
        input: '0xc3018a0e', // AAVE flash loan
        calls: [
          // Flash loan to borrow funds
          {
            from: '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            to: addresses.user,
            input: '0x',
            output: '0x1',
            gasUsed: '100000',
            value: '1000000000000000000000' // Large value
          },
          // First swap for arbitrage
          {
            from: addresses.user,
            to: addresses.dex,
            input: '0x38ed1739', // swapExactTokensForTokens
            output: '0x1',
            gasUsed: '300000',
            value: '0'
          },
          // Second swap on different DEX
          {
            from: addresses.user,
            to: '0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', // Second DEX
            input: '0x38ed1739', // swapExactTokensForTokens
            output: '0x1',
            gasUsed: '300000',
            value: '0'
          },
          // Repay flash loan
          {
            from: addresses.user,
            to: '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', // Flash loan provider
            input: '0x',
            output: '0x1',
            gasUsed: '100000',
            value: '1001000000000000000000' // Repay with interest
          }
        ]
      });

      const result = DetectionService.detect(request);
      expect(result.detected).toBe(false);
      expect(result.message).toBe('No threats detected');
    });

    test('legitimate multiple contract interactions', () => {
      const request = createRequest({
        from: addresses.user,
        to: addresses.protocol,
        input: '0xabcdef12', // some protocol function
        calls: [
          // Approve token for protocol
          {
            from: addresses.user,
            to: '0xcccccccccccccccccccccccccccccccccccccccc', // Token contract
            input: '0x095ea7b3', // approve function
            output: '0x1',
            gasUsed: '50000',
            value: '0'
          },
          // Deposit to lending platform
          {
            from: addresses.user,
            to: addresses.lending,
            input: '0xe8eda9df', // deposit function
            output: '0x1',
            gasUsed: '200000',
            value: '0'
          },
          // Stake tokens
          {
            from: addresses.user,
            to: addresses.staking,
            input: '0xa694fc3a', // stake function
            output: '0x1',
            gasUsed: '150000',
            value: '0'
          },
          // More interactions
          {
            from: addresses.user,
            to: addresses.dex,
            input: '0x38ed1739', // swap
            output: '0x1',
            gasUsed: '300000',
            value: '0'
          }
        ]
      });

      const result = DetectionService.detect(request);
      expect(result.detected).toBe(false);
      expect(result.message).toBe('No threats detected');
    });

    test('legitimate large value transfer', () => {
      // Even with high value, context shows this is a legitimate whale transaction
      const request = createRequest({
        from: '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045', // Vitalik's address
        to: '0xA2025B15a1757311bfD68cb14eaeFCc237AF5b43',
        input: '0xa9059cbb', // transfer
        value: '10000000000000000000000', // Very large value (10,000 ETH)
        // Additional context showing this is from a known address with history
        additionalData: {
          senderType: 'verified_entity',
          recipientType: 'verified_entity', 
          transactionType: 'large_donation',
          senderTransactionCount: 1500
        }
      });

      const result = DetectionService.detect(request);
      expect(result.detected).toBe(false);
      expect(result.message).toBe('No threats detected');
    });
  });

  describe('Legitimate DAO Operations', () => {
    test('legitimate proposal creation and voting', () => {
      const request = createRequest({
        from: addresses.user,
        to: addresses.dao,
        input: '0xda95691a', // propose
        calls: [
          // Create proposal
          {
            from: addresses.user,
            to: addresses.dao,
            input: '0xda95691a', // propose
            output: '0x1',
            gasUsed: '500000',
            value: '0'
          },
          // Multiple legitimate vote delegations
          {
            from: addresses.user,
            to: addresses.dao,
            input: '0x5c19a95c', // delegate
            output: '0x1',
            gasUsed: '100000',
            value: '0'
          },
          {
            from: addresses.user,
            to: addresses.dao,
            input: '0x5c19a95c', // delegate
            output: '0x1',
            gasUsed: '100000',
            value: '0'
          },
          // Vote on proposal
          {
            from: addresses.user,
            to: addresses.dao,
            input: '0x56781388', // castVote
            output: '0x1',
            gasUsed: '200000',
            value: '0'
          }
        ]
      });

      const result = DetectionService.detect(request);
      expect(result.detected).toBe(false);
      expect(result.message).toBe('No threats detected');
    });

    test('legitimate treasury management', () => {
      const request = createRequest({
        from: addresses.dao,
        to: '0xdddddddddddddddddddddddddddddddddddddddd', // Treasury
        input: '0x', 
        calls: [
          // Multiple transfers from treasury for legitimate operations
          {
            from: '0xdddddddddddddddddddddddddddddddddddddddd', // Treasury
            to: '0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee', // Recipient 1
            input: '0xa9059cbb', // transfer
            output: '0x1',
            gasUsed: '100000',
            value: '100000000000000000000' // 100 tokens
          },
          {
            from: '0xdddddddddddddddddddddddddddddddddddddddd', // Treasury
            to: '0xffffffffffffffffffffffffffffffffffffffff', // Recipient 2
            input: '0xa9059cbb', // transfer
            output: '0x1',
            gasUsed: '100000',
            value: '200000000000000000000' // 200 tokens
          }
        ],
        // Additional context showing this is authorized by multiple signatures
        additionalData: {
          signaturesRequired: 5,
          signaturesProvided: 7,
          operationType: 'scheduled_payment'
        }
      });

      const result = DetectionService.detect(request);
      expect(result.detected).toBe(false);
      expect(result.message).toBe('No threats detected');
    });
  });

  describe('Legitimate Bridge Operations', () => {
    test('legitimate cross-chain transfer', () => {
      const request = createRequest({
        from: addresses.user,
        to: addresses.bridge,
        input: '0x6e553f65', // deposit
        value: '1000000000000000000000', // 1000 ETH
        calls: [
          // Bridge locks tokens
          {
            from: addresses.bridge,
            to: addresses.bridge,
            input: '0xffffffff', // internal call
            output: '0x1',
            gasUsed: '200000',
            value: '0'
          },
          // Bridge emits event for cross-chain message
          {
            from: addresses.bridge,
            to: addresses.bridge,
            input: '0xffffffff', // internal call
            output: '0x1',
            gasUsed: '50000',
            value: '0'
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
            balance: '11000000000000000000000', // Increased by deposit
            nonce: 6
          }
        },
        // Additional context showing legitimate bridge operation
        additionalData: {
          sourceChainId: 1,
          destinationChainId: 56,
          recipientOnDestination: addresses.user
        }
      });

      const result = DetectionService.detect(request);
      expect(result.detected).toBe(false);
      expect(result.message).toBe('No threats detected');
    });

    test('legitimate bridge withdrawal', () => {
      const request = createRequest({
        from: addresses.user,
        to: addresses.bridge,
        input: '0x89afcb44', // withdraw
        calls: [
          // Bridge validates proof with multiple validators
          {
            from: addresses.bridge,
            to: '0x1111111111111111111111111111111111111111', // Validator 1
            input: '0xa2e62045', // verifyProof
            output: '0x1',
            gasUsed: '100000',
            value: '0'
          },
          {
            from: addresses.bridge,
            to: '0x2222222222222222222222222222222222222222', // Validator 2
            input: '0xa2e62045', // verifyProof
            output: '0x1',
            gasUsed: '100000',
            value: '0'
          },
          {
            from: addresses.bridge,
            to: '0x3333333333333333333333333333333333333333', // Validator 3
            input: '0xa2e62045', // verifyProof
            output: '0x1',
            gasUsed: '100000',
            value: '0'
          },
          // Bridge executes withdrawal after validation
          {
            from: addresses.bridge,
            to: addresses.user,
            input: '0xa9059cbb', // transfer
            output: '0x1',
            gasUsed: '100000',
            value: '1000000000000000000000' // 1000 tokens
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
            balance: '9000000000000000000000', // Decreased by withdrawal
            nonce: 6
          }
        },
        // Additional context showing legitimate bridge operation
        additionalData: {
          sourceChainId: 56,
          destinationChainId: 1,
          messageTx: '0x123456789abcdef',
          validatorsRequired: 3,
          validatorsConfirmed: 3
        }
      });

      const result = DetectionService.detect(request);
      expect(result.detected).toBe(false);
      expect(result.message).toBe('No threats detected');
    });
  });

  describe('Legitimate Complex Protocol Interactions', () => {
    test('legitimate complex leverage strategy', () => {
      const request = createRequest({
        from: addresses.user,
        to: addresses.protocol, // Some DeFi aggregator
        input: '0xabcdef12', // complex strategy function
        calls: [
          // Borrow from lending platform
          {
            from: addresses.protocol,
            to: addresses.lending,
            input: '0xc5ebeaec', // borrow
            output: '0x1',
            gasUsed: '300000',
            value: '0'
          },
          // Swap tokens
          {
            from: addresses.protocol,
            to: addresses.dex,
            input: '0x38ed1739', // swap
            output: '0x1',
            gasUsed: '300000',
            value: '0'
          },
          // Provide liquidity
          {
            from: addresses.protocol, 
            to: addresses.dex,
            input: '0xe8e33700', // addLiquidity
            output: '0x1',
            gasUsed: '400000',
            value: '0'
          },
          // Stake LP tokens
          {
            from: addresses.protocol,
            to: addresses.staking,
            input: '0xa694fc3a', // stake
            output: '0x1', 
            gasUsed: '200000',
            value: '0'
          }
        ]
      });

      const result = DetectionService.detect(request);
      expect(result.detected).toBe(false);
      expect(result.message).toBe('No threats detected');
    });

    test('legitimate multi-level contract calls', () => {
      // Create deep nested call structure but with legitimate operations
      const request = createRequest({
        from: addresses.user,
        to: addresses.protocol,
        input: '0xabcdef12', 
        calls: [
          {
            from: addresses.protocol,
            to: '0x1111111111111111111111111111111111111111',
            input: '0xabcdef12',
            output: '0x1',
            gasUsed: '100000',
            value: '0',
            calls: [
              {
                from: '0x1111111111111111111111111111111111111111',
                to: '0x2222222222222222222222222222222222222222',
                input: '0xabcdef12',
                output: '0x1',
                gasUsed: '100000',
                value: '0',
                calls: [
                  {
                    from: '0x2222222222222222222222222222222222222222',
                    to: '0x3333333333333333333333333333333333333333',
                    input: '0xabcdef12',
                    output: '0x1',
                    gasUsed: '100000',
                    value: '0',
                    calls: [
                      {
                        from: '0x3333333333333333333333333333333333333333',
                        to: '0x4444444444444444444444444444444444444444',
                        input: '0xabcdef12',
                        output: '0x1',
                        gasUsed: '100000',
                        value: '0'
                      }
                    ]
                  }
                ]
              }
            ]
          }
        ],
        // Additional context showing this is a known safe operation
        additionalData: {
          operationType: 'verified_protocol_action',
          callDepth: 5,
          contractsVerified: true
        }
      });

      const result = DetectionService.detect(request);
      expect(result.detected).toBe(false);
      expect(result.message).toBe('No threats detected');
    });
  });
}); 