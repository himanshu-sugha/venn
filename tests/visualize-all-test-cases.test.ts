import { DetectionRequest } from '../src/modules/detection-module/dtos/requests/detect-request';
import { TestReportGenerator } from './utils/test-report-generator';
import * as fs from 'fs';
import * as path from 'path';

describe('Comprehensive Test Case Visualization', () => {
  test('Generate visual reports for all test suites', () => {
    // Legitimate transaction test cases (from false-positives.test.ts)
    const legitimateTestCases: DetectionRequest[] = [
      // Legitimate flash loan for arbitrage
      {
        hash: '0x1111111111111111111111111111111111111111111111111111111111111111',
        chainId: 1,
        trace: {
          from: '0x1234567890123456789012345678901234567890',
          to: '0xabcdefabcdefabcdefabcdefabcdefabcdefabcd',
          value: '0',
          gas: '500000',
          gasUsed: '450000',
          input: '0xc3018a0e', // Flash loan signature
          pre: {},
          post: {},
          calls: [
            {
              from: '0xabcdefabcdefabcdefabcdefabcdefabcdefabcd',
              to: '0x1234567890123456789012345678901234567890',
              input: '0xabcdef12', // Flash loan callback
              value: '1000000000000000000', // Loan amount
              gasUsed: '200000',
              calls: []
            },
            {
              from: '0x1234567890123456789012345678901234567890',
              to: '0xabcdefabcdefabcdefabcdefabcdefabcdefabcd',
              input: '0xdef1a2b3', // Repayment
              value: '1020000000000000000', // Loan amount + fee
              gasUsed: '100000',
              calls: []
            }
          ]
        },
        additionalData: {
          testName: 'Legitimate Flash Loan for Arbitrage',
          senderType: 'verified_entity',
          detectorName: 'false-positive-detector'
        }
      },
      
      // Legitimate multiple contract interactions
      {
        hash: '0x2222222222222222222222222222222222222222222222222222222222222222',
        chainId: 1,
        trace: {
          from: '0x1234567890123456789012345678901234567890',
          to: '0xbcdefabcdefabcdefabcdefabcdefabcdefabcde',
          value: '0',
          gas: '300000',
          gasUsed: '250000',
          input: '0x12345678', // Complex protocol interaction
          pre: {},
          post: {},
          calls: [
            {
              from: '0xbcdefabcdefabcdefabcdefabcdefabcdefabcde',
              to: '0xcdefabcdefabcdefabcdefabcdefabcdefabcdef',
              input: '0x23456789',
              value: '0',
              gasUsed: '50000',
              calls: []
            },
            {
              from: '0xbcdefabcdefabcdefabcdefabcdefabcdefabcde',
              to: '0xdefabcdefabcdefabcdefabcdefabcdefabcdef1',
              input: '0x3456789a',
              value: '0',
              gasUsed: '50000',
              calls: []
            },
            {
              from: '0xbcdefabcdefabcdefabcdefabcdefabcdefabcde',
              to: '0xefabcdefabcdefabcdefabcdefabcdefabcdef12',
              input: '0x456789ab',
              value: '0',
              gasUsed: '50000',
              calls: []
            }
          ]
        },
        additionalData: {
          testName: 'Legitimate Multiple Contract Interactions',
          detectorName: 'false-positive-detector'
        }
      },
      
      // Legitimate proposal creation and voting
      {
        hash: '0x4444444444444444444444444444444444444444444444444444444444444444',
        chainId: 1,
        trace: {
          from: '0x1234567890123456789012345678901234567890',
          to: '0x6666666666666666666666666666666666666666', // DAO contract
          value: '0',
          gas: '500000',
          gasUsed: '400000',
          input: '0xda95691a', // DAO propose function
          pre: {},
          post: {},
          calls: [
            {
              from: '0x6666666666666666666666666666666666666666',
              to: '0x7777777777777777777777777777777777777777',
              input: '0x56781388', // castVote
              value: '0',
              gasUsed: '100000',
              calls: []
            }
          ]
        },
        additionalData: {
          testName: 'Legitimate DAO Proposal and Voting',
          signaturesRequired: 5,
          signaturesProvided: 7,
          detectorName: 'false-positive-detector'
        }
      },
      
      // Legitimate cross-chain transfer
      {
        hash: '0x7777777777777777777777777777777777777777777777777777777777777777',
        chainId: 1,
        trace: {
          from: '0x1234567890123456789012345678901234567890',
          to: '0x3333333333333333333333333333333333333333', // Bridge contract
          value: '5000000000000000000', // 5 ETH
          gas: '200000',
          gasUsed: '150000',
          input: '0x6e553f65', // bridge deposit
          pre: {},
          post: {}
        },
        additionalData: {
          testName: 'Legitimate Cross-Chain Transfer',
          sourceChainId: 1,
          destinationChainId: 10,
          validatorsRequired: 3, 
          validatorsConfirmed: 5,
          detectorName: 'false-positive-detector'
        }
      }
    ];
    
    // Governance attack test cases (from governance-attacks.test.ts)
    const governanceAttackTestCases: DetectionRequest[] = [
      // Flash loan followed by governance proposal
      {
        hash: '0xaaaa111111111111111111111111111111111111111111111111111111111111',
        chainId: 1,
        trace: {
          from: '0x8888888888888888888888888888888888888888',
          to: '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
          value: '0',
          gas: '1000000',
          gasUsed: '900000',
          input: '0xc3018a0e', // Flash loan
          pre: {},
          post: {},
          calls: [
            {
              from: '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
              to: '0x8888888888888888888888888888888888888888',
              input: '0x12345678', // Flash loan callback
              value: '1000000000000000000000', // 1000 ETH
              gasUsed: '100000',
              calls: []
            },
            {
              from: '0x8888888888888888888888888888888888888888',
              to: '0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', // Governance contract
              input: '0xda95691a', // propose function
              value: '0',
              gasUsed: '500000',
              calls: []
            }
          ]
        },
        additionalData: {
          testName: 'Flash Loan Followed by Governance Proposal'
        }
      },
      
      // Malicious proposal to drain treasury
      {
        hash: '0xcccc333333333333333333333333333333333333333333333333333333333333',
        chainId: 1,
        trace: {
          from: '0xcccccccccccccccccccccccccccccccccccccccc',
          to: '0xdddddddddddddddddddddddddddddddddddddddd', // DAO contract
          value: '0',
          gas: '5000000',
          gasUsed: '4500000',
          input: '0x0825f38f', // execute function
          pre: {},
          post: {},
          calls: [
            {
              from: '0xdddddddddddddddddddddddddddddddddddddddd',
              to: '0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee', // Treasury
              input: '0xa9059cbb', // transfer
              value: '100000000000000000000000', // 100,000 ETH
              gasUsed: '1000000',
              calls: []
            }
          ]
        },
        additionalData: {
          testName: 'Treasury Drain via Malicious Proposal'
        }
      },
      // Add legitimate governance transaction
      {
        hash: '0xbbbb222222222222222222222222222222222222222222222222222222222222',
        chainId: 1,
        trace: {
          from: '0x1234567890123456789012345678901234567890',
          to: '0x5555555555555555555555555555555555555555', // DAO contract
          value: '0',
          gas: '500000',
          gasUsed: '400000',
          input: '0xda95691a', // propose function
          pre: {},
          post: {},
          calls: [
            {
              from: '0x5555555555555555555555555555555555555555',
              to: '0x6666666666666666666666666666666666666666',
              input: '0x56781388', // castVote function
              value: '0',
              gasUsed: '100000',
              calls: []
            },
            {
              from: '0x5555555555555555555555555555555555555555',
              to: '0x7777777777777777777777777777777777777777',
              input: '0x0825f38f', // execute function
              value: '0',
              gasUsed: '200000',
              calls: [
                {
                  from: '0x7777777777777777777777777777777777777777',
                  to: '0x8888888888888888888888888888888888888888',
                  input: '0xa9059cbb', // transfer (for legitimate protocol usage)
                  value: '1000000000000000000', // 1 ETH (reasonably small amount)
                  gasUsed: '50000',
                  calls: []
                }
              ]
            }
          ]
        },
        additionalData: {
          testName: 'Legitimate Governance Proposal Execution',
          signaturesRequired: 7,
          signaturesProvided: 10,
          detectorName: 'false-positive-detector'
        }
      }
    ];
    
    // Oracle attack test cases (from oracle-attacks.test.ts)
    const oracleAttackTestCases: DetectionRequest[] = [
      // Flash loan based price oracle manipulation
      {
        hash: '0xdddd444444444444444444444444444444444444444444444444444444444444',
        chainId: 1,
        trace: {
          from: '0x9999999999999999999999999999999999999999',
          to: '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
          value: '0',
          gas: '2000000',
          gasUsed: '1800000',
          input: '0xc3018a0e', // Flash loan
          pre: {},
          post: {},
          calls: [
            {
              from: '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
              to: '0x9999999999999999999999999999999999999999',
              input: '0x12345678', // Flash loan callback
              value: '10000000000000000000000', // 10,000 ETH
              gasUsed: '100000',
              calls: []
            },
            {
              from: '0x9999999999999999999999999999999999999999',
              to: '0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', // DEX contract
              input: '0x38ed1739', // swapExactTokensForTokens
              value: '0',
              gasUsed: '500000',
              calls: []
            },
            {
              from: '0x9999999999999999999999999999999999999999',
              to: '0xcccccccccccccccccccccccccccccccccccccccc', // Oracle contract
              input: '0x8c0b4dad', // updatePrice
              value: '0',
              gasUsed: '300000',
              calls: []
            },
            {
              from: '0x9999999999999999999999999999999999999999',
              to: '0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', // DEX contract again
              input: '0x38ed1739', // swapExactTokensForTokens (reverse)
              value: '0',
              gasUsed: '500000',
              calls: []
            }
          ]
        },
        additionalData: {
          testName: 'Flash Loan Price Oracle Manipulation'
        }
      },
      
      // TWAP oracle manipulation
      {
        hash: '0xeeee555555555555555555555555555555555555555555555555555555555555',
        chainId: 1,
        trace: {
          from: '0x9999999999999999999999999999999999999999',
          to: '0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', // DEX contract
          value: '0',
          gas: '1000000',
          gasUsed: '900000',
          input: '0x38ed1739', // swapExactTokensForTokens
          pre: {},
          post: {},
          calls: [
            {
              from: '0x9999999999999999999999999999999999999999',
              to: '0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
              input: '0x38ed1739', // swapExactTokensForTokens
              value: '0',
              gasUsed: '200000',
              calls: []
            },
            {
              from: '0x9999999999999999999999999999999999999999',
              to: '0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
              input: '0x38ed1739', // swapExactTokensForTokens
              value: '0',
              gasUsed: '200000',
              calls: []
            },
            {
              from: '0x9999999999999999999999999999999999999999',
              to: '0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
              input: '0x38ed1739', // swapExactTokensForTokens
              value: '0',
              gasUsed: '200000',
              calls: []
            },
            {
              from: '0x9999999999999999999999999999999999999999',
              to: '0xdddddddddddddddddddddddddddddddddddddddd', // Lending protocol
              input: '0xc5ebeaec', // borrow function
              value: '0',
              gasUsed: '300000',
              calls: []
            }
          ]
        },
        additionalData: {
          testName: 'TWAP Oracle Manipulation'
        }
      },
      // Add legitimate oracle interaction
      {
        hash: '0xffff111111111111111111111111111111111111111111111111111111111111',
        chainId: 1,
        trace: {
          from: '0x1234567890123456789012345678901234567890',
          to: '0xabcdef1234567890abcdef1234567890abcdef12', // Price oracle contract
          value: '0',
          gas: '300000',
          gasUsed: '250000',
          input: '0x50d25bcd', // latestRoundData
          pre: {},
          post: {},
          calls: [
            {
              from: '0xabcdef1234567890abcdef1234567890abcdef12',
              to: '0x1234567890123456789012345678901234567890',
              input: '0x12345678', // oracle callback with price data
              value: '0',
              gasUsed: '100000',
              calls: []
            },
            {
              from: '0x1234567890123456789012345678901234567890',
              to: '0xfedcba0987654321fedcba0987654321fedcba09', // DEX contract
              input: '0x38ed1739', // swapExactTokensForTokens (legitimate trading after price check)
              value: '0',
              gasUsed: '100000',
              calls: []
            }
          ]
        },
        additionalData: {
          testName: 'Legitimate Oracle Price Check and Swap',
          sourcePrice: '1000000000000000000', // 1 ETH
          destinationPrice: '1050000000000000000', // 1.05 ETH (small price variation)
          detectorName: 'false-positive-detector'
        }
      }
    ];
    
    // Cross-chain attack test cases (from cross-chain-attacks.test.ts)
    const crossChainAttackTestCases: DetectionRequest[] = [
      // Unauthorized bridge withdrawal
      {
        hash: '0xffff666666666666666666666666666666666666666666666666666666666666',
        chainId: 1,
        trace: {
          from: '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
          to: '0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', // Bridge contract
          value: '0',
          gas: '500000',
          gasUsed: '450000',
          input: '0x89afcb44', // bridgeWithdraw
          pre: {},
          post: {},
          calls: [
            {
              from: '0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
              to: '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
              input: '0xa9059cbb', // transfer
              value: '100000000000000000000', // 100 ETH
              gasUsed: '100000',
              calls: []
            }
          ]
        },
        additionalData: {
          testName: 'Unauthorized Bridge Withdrawal',
          validatorsRequired: 5,
          validatorsConfirmed: 1
        }
      },
      
      // Bridge validation bypass
      {
        hash: '0xgggg777777777777777777777777777777777777777777777777777777777777',
        chainId: 1,
        trace: {
          from: '0xcccccccccccccccccccccccccccccccccccccccc',
          to: '0xdddddddddddddddddddddddddddddddddddddddd', // Bridge contract
          value: '0',
          gas: '1000000',
          gasUsed: '900000',
          input: '0xa2e62045', // submitSignatures
          pre: {},
          post: {},
          calls: [
            {
              from: '0xdddddddddddddddddddddddddddddddddddddddd',
              to: '0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
              input: '0x89afcb44', // bridgeWithdraw
              value: '0',
              gasUsed: '500000',
              calls: [
                {
                  from: '0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
                  to: '0xcccccccccccccccccccccccccccccccccccccccc',
                  input: '0xa9059cbb', // transfer
                  value: '500000000000000000000', // 500 ETH
                  gasUsed: '100000',
                  calls: []
                }
              ]
            }
          ]
        },
        additionalData: {
          testName: 'Bridge Validation Bypass'
        }
      },
      // Add legitimate cross-chain transaction
      {
        hash: '0xaaaa333333333333333333333333333333333333333333333333333333333333',
        chainId: 1,
        trace: {
          from: '0x1234567890123456789012345678901234567890',
          to: '0x1111222233334444555566667777888899990000', // Bridge contract
          value: '10000000000000000000', // 10 ETH
          gas: '500000',
          gasUsed: '400000',
          input: '0x6e553f65', // bridge deposit function
          pre: {},
          post: {},
          calls: [
            {
              from: '0x1111222233334444555566667777888899990000',
              to: '0x0000999988887777666655554444333322221111', // Bridge vault
              input: '0xa9059cbb', // transfer
              value: '10000000000000000000', // 10 ETH
              gasUsed: '100000',
              calls: []
            },
            {
              from: '0x1111222233334444555566667777888899990000',
              to: '0xaaaa0000bbbb1111cccc2222dddd3333eeee4444', // Message relay
              input: '0xc3805300', // submitMessage 
              value: '0',
              gasUsed: '200000',
              calls: []
            }
          ]
        },
        additionalData: {
          testName: 'Legitimate Cross-Chain Bridge Deposit',
          sourceChainId: 1,
          destinationChainId: 42161, // Arbitrum
          sourceTotalLocked: '1000000000000000000000', // 1000 ETH
          destinationTotalMinted: '1000000000000000000000', // 1000 ETH
          validatorsRequired: 3,
          validatorsConfirmed: 5,
          detectorName: 'false-positive-detector'
        }
      }
    ];
    
    // General attack test cases (from detection.test.ts)
    const generalAttackTestCases: DetectionRequest[] = [
      // Phishing - malicious approve
      {
        hash: '0xhhhh888888888888888888888888888888888888888888888888888888888888',
        chainId: 1,
        trace: {
          from: '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
          to: '0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', // Token contract
          value: '0',
          gas: '100000',
          gasUsed: '80000',
          input: '0x095ea7b3000000000000000000000000ccccccccccccccccccccccccccccccccccccccccffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff', // approve with unlimited allowance
          pre: {},
          post: {}
        },
        additionalData: {
          testName: 'Malicious Approve (Phishing)'
        }
      },
      
      // Reentrancy pattern
      {
        hash: '0xiiii999999999999999999999999999999999999999999999999999999999999',
        chainId: 1,
        trace: {
          from: '0xdddddddddddddddddddddddddddddddddddddddd',
          to: '0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee', // Vulnerable contract
          value: '0',
          gas: '500000',
          gasUsed: '450000',
          input: '0x2e1a7d4d', // withdraw
          pre: {},
          post: {},
          calls: [
            {
              from: '0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
              to: '0xdddddddddddddddddddddddddddddddddddddddd',
              input: '0x00000000', // fallback function
              value: '10000000000000000000', // 10 ETH
              gasUsed: '200000',
              calls: [
                {
                  from: '0xdddddddddddddddddddddddddddddddddddddddd',
                  to: '0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
                  input: '0x2e1a7d4d', // withdraw again
                  value: '0',
                  gasUsed: '100000',
                  calls: []
                }
              ]
            }
          ]
        },
        additionalData: {
          testName: 'Reentrancy Attack Pattern'
        }
      },
      
      // Flash loan attack
      {
        hash: '0xjjjjaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        chainId: 1,
        trace: {
          from: '0xffffffffffffffffffffffffffffffffffffffffff',
          to: '0xgggggggggggggggggggggggggggggggggggggggg', // Flash loan provider
          value: '0',
          gas: '2000000',
          gasUsed: '1800000',
          input: '0xc3018a0e', // Flash loan
          pre: {},
          post: {},
          calls: [
            {
              from: '0xgggggggggggggggggggggggggggggggggggggggg',
              to: '0xffffffffffffffffffffffffffffffffffffffffff',
              input: '0x12345678', // Flash loan callback
              value: '5000000000000000000000', // 5000 ETH
              gasUsed: '100000',
              calls: []
            },
            {
              from: '0xffffffffffffffffffffffffffffffffffffffffff',
              to: '0hhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh', // Vulnerable DeFi protocol
              input: '0x12345678',
              value: '0',
              gasUsed: '1000000',
              calls: []
            },
            {
              from: '0xffffffffffffffffffffffffffffffffffffffffff',
              to: '0xiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiii', // Another protocol
              input: '0x87654321',
              value: '0',
              gasUsed: '500000',
              calls: []
            }
          ]
        },
        additionalData: {
          testName: 'Flash Loan Attack Pattern'
        }
      },
      // Add legitimate flash loan usage
      {
        hash: '0xbbbb444444444444444444444444444444444444444444444444444444444444',
        chainId: 1, 
        trace: {
          from: '0x1234567890123456789012345678901234567890',
          to: '0xabcd1234abcd1234abcd1234abcd1234abcd1234', // Flash loan provider
          value: '0',
          gas: '600000',
          gasUsed: '500000',
          input: '0xc3018a0e', // Flash loan signature
          pre: {},
          post: {},
          calls: [
            {
              from: '0xabcd1234abcd1234abcd1234abcd1234abcd1234',
              to: '0x1234567890123456789012345678901234567890',
              input: '0x12345678', // Flash loan callback
              value: '10000000000000000000000', // 10,000 ETH
              gasUsed: '100000',
              calls: []
            },
            {
              from: '0x1234567890123456789012345678901234567890',
              to: '0x5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a', // DEX contract
              input: '0x38ed1739', // swapExactTokensForTokens
              value: '0',
              gasUsed: '100000',
              calls: []
            },
            {
              from: '0x1234567890123456789012345678901234567890',
              to: '0x6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b', // Another DEX
              input: '0x38ed1739', // swapExactTokensForTokens 
              value: '0',
              gasUsed: '100000',
              calls: []
            },
            {
              from: '0x1234567890123456789012345678901234567890',
              to: '0xabcd1234abcd1234abcd1234abcd1234abcd1234', // Repayment
              input: '0xdef1a2b3', // Repayment function
              value: '10050000000000000000000', // 10,050 ETH (loan + 0.5% fee)
              gasUsed: '100000',
              calls: []
            }
          ]
        },
        additionalData: {
          testName: 'Legitimate Flash Loan for Arbitrage Trade',
          contractsVerified: true,
          operationType: 'verified_protocol_action',
          detectorName: 'false-positive-detector'
        }
      },
      // Legitimate token approval (with limited amount)
      {
        hash: '0xcccc444444444444444444444444444444444444444444444444444444444444',
        chainId: 1,
        trace: {
          from: '0x1234567890123456789012345678901234567890',
          to: '0x9876543210fedcba9876543210fedcba98765432', // Token contract
          value: '0',
          gas: '80000',
          gasUsed: '60000',
          input: '0x095ea7b300000000000000000000000012345678901234567890123456789012345678900000000000000000000000000000000000000000000000056bc75e2d63100000', // approve with 100 token limit
          pre: {},
          post: {}
        },
        additionalData: {
          testName: 'Legitimate Token Approval (Limited)',
          senderType: 'verified_entity',
          detectorName: 'false-positive-detector'
        }
      }
    ];
    
    // Combine all test cases
    const allTestCases = [
      ...legitimateTestCases,
      ...governanceAttackTestCases,
      ...oracleAttackTestCases,
      ...crossChainAttackTestCases,
      ...generalAttackTestCases
    ];
    
    // Generate a comprehensive report with all test cases
    TestReportGenerator.generateReports('comprehensive-test-cases', allTestCases);
    
    // Generate specialized reports for each test category
    TestReportGenerator.generateReports('legitimate-transactions', legitimateTestCases);
    TestReportGenerator.generateReports('governance-attacks', governanceAttackTestCases);
    TestReportGenerator.generateReports('oracle-attacks', oracleAttackTestCases);
    TestReportGenerator.generateReports('cross-chain-attacks', crossChainAttackTestCases);
    TestReportGenerator.generateReports('general-attacks', generalAttackTestCases);
    
    // Create a directory listing HTML file to navigate between reports
    const reportsDir = path.join(__dirname, 'reports');
    const reportNavHTML = `
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Venn Detection Reports Navigation</title>
      <style>
        body {
          font-family: Arial, sans-serif;
          line-height: 1.6;
          margin: 0;
          padding: 20px;
          color: #333;
          max-width: 1200px;
          margin: 0 auto;
        }
        h1, h2 {
          color: #2c3e50;
        }
        .reports-grid {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
          gap: 20px;
          margin-top: 20px;
        }
        .report-card {
          border: 1px solid #ddd;
          border-radius: 10px;
          padding: 20px;
          box-shadow: 0 4px 6px rgba(0,0,0,0.1);
          transition: transform 0.3s ease;
        }
        .report-card:hover {
          transform: translateY(-5px);
        }
        .report-card h3 {
          margin-top: 0;
          color: #2980b9;
        }
        .report-card p {
          margin-bottom: 15px;
        }
        .report-link {
          display: inline-block;
          background-color: #3498db;
          color: white;
          padding: 8px 16px;
          border-radius: 4px;
          text-decoration: none;
          font-weight: bold;
        }
        .report-link:hover {
          background-color: #2980b9;
        }
        .footer {
          margin-top: 40px;
          padding-top: 20px;
          border-top: 1px solid #eee;
          text-align: center;
          font-size: 0.9em;
          color: #7f8c8d;
        }
      </style>
    </head>
    <body>
      <h1>Venn: Transaction Security Detection Visualization</h1>
      <p>This page provides links to visualization reports for different categories of blockchain transactions and their security analysis results.</p>
      
      <div class="reports-grid">
        <div class="report-card">
          <h3>Comprehensive Report</h3>
          <p>A complete report containing all test cases across all categories.</p>
          <a href="comprehensive-test-cases-report.html" class="report-link">View Report</a>
        </div>
        
        <div class="report-card">
          <h3>Legitimate Transactions</h3>
          <p>Examples of legitimate transactions that should not trigger security alerts.</p>
          <a href="legitimate-transactions-report.html" class="report-link">View Report</a>
        </div>
        
        <div class="report-card">
          <h3>Governance Attacks</h3>
          <p>Examples of governance manipulation attacks including flash loan voting, treasury drains, etc.</p>
          <a href="governance-attacks-report.html" class="report-link">View Report</a>
        </div>
        
        <div class="report-card">
          <h3>Oracle Attacks</h3>
          <p>Examples of price oracle manipulation attacks including TWAP manipulation, price sandwiching, etc.</p>
          <a href="oracle-attacks-report.html" class="report-link">View Report</a>
        </div>
        
        <div class="report-card">
          <h3>Cross-Chain Attacks</h3>
          <p>Examples of cross-chain attacks including bridge exploits, validation bypasses, etc.</p>
          <a href="cross-chain-attacks-report.html" class="report-link">View Report</a>
        </div>
        
        <div class="report-card">
          <h3>General Attacks</h3>
          <p>Examples of other common attack patterns including reentrancy, flash loan exploits, phishing, etc.</p>
          <a href="general-attacks-report.html" class="report-link">View Report</a>
        </div>
      </div>
      
      <div class="footer">
        <p>Venn Security Detection Framework - Transaction Security Visualization</p>
      </div>
    </body>
    </html>
    `;
    
    // Write the navigation HTML file
    fs.writeFileSync(path.join(reportsDir, 'index.html'), reportNavHTML);
    
    console.log('\n==============================================================');
    console.log('COMPREHENSIVE TEST CASE REPORTS GENERATED SUCCESSFULLY!');
    console.log('Open the following HTML file to navigate between reports:');
    console.log('tests/reports/index.html');
    console.log('==============================================================\n');
    
    // Dummy assertion for Jest
    expect(true).toBe(true);
  });
}); 