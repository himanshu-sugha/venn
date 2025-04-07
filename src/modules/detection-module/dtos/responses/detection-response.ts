import { DetectionResult } from '../../types/detection-result';

export interface DetectionResponse {
  requestId: string;
  chainId: number;
  protocolAddress: string;
  protocolName: string;
  message: string;
  detected: boolean;
  detectionDetails: Record<string, DetectionResult['details']>;
} 