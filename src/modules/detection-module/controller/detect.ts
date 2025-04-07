import { plainToInstance } from 'class-transformer'
import { Request, Response } from 'express'

import { logger } from '@/app'
import { ErrorHandler, validateRequest } from '@/helpers'
import { DetectionRequest } from '@/modules/detection-module/dtos'
import { DetectionResponse } from '@/modules/detection-module/dtos/responses'
import { DetectionService } from '@/modules/detection-module/service'
import { PublicClassFields } from '@/types'

export const detect = async (
    req: Request<Record<string, string>, PublicClassFields<DetectionRequest>>,
    res: Response,
) => {
    const request = plainToInstance(DetectionRequest, req.body)

    logger.debug(`detect request started. Request id: ${request.id}`)

    try {
        // validate request
        await validateRequest(request)

        // perform business logic
        const result = DetectionService.detect(request)

        logger.debug('detect request finished succesfully')

        // return response
        res.json(result)
    } catch (error) {
        // handle errors
        ErrorHandler.processApiError(res, error)
    }
}
