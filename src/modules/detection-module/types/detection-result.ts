export interface DetectionResult {
  detected: boolean;
  message: string;
  details: {
    [key: string]: any;
    suspiciousPatterns?: string[] | string;
    phishingSignature?: string;
    poisoningSignature?: string;
    unlimitedApproval?: boolean;
    approvalTarget?: string;
    ownershipTransfer?: boolean;
    transferTarget?: string;
    highGas?: number;
    transactionValue?: string;
    reentrancyPaths?: Array<Array<string>>;
    blacklistedAddress?: string;
    addressSimilarity?: {
      from: string;
      to: string;
      similarity: number;
    };
  };
  type?: string;
  depth?: number;
  addresses?: string[];
  counts?: number[];
} 