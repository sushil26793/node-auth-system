import { Request, Response, NextFunction } from "express";

interface RequestLog {
    timestamp: string;
    method: string;
    url: string;
    ip: string;
    userAgent: string;
    statusCode?: number;
    responseTime?: number;
    contentLength?: string;
    requestId: string;
}


const generateRequestId = (): string => {
    return `${Date.now()}-${Math.random().toString(36).substring(2, 11)}`
}
export const requestLoggerMiddleware = (req: Request, res: Response, next: NextFunction): void => {
    const startTime = Date.now();
    const requestId = generateRequestId();
    (req as any).id = requestId;

    const logData: RequestLog = {
        timestamp: new Date().toISOString(),
        method: req.method,
        url: req.originalUrl,
        ip: req.headers["x-forwared-for"] as string || req.socket.remoteAddress || '',
        userAgent: req.headers["user-agent"] || '',
        requestId
    }

    res.on("finish", () => {
        const responseTime = Date.now() - startTime;
        const finalLog: RequestLog = {
            ...logData,
            statusCode: res.statusCode,
            responseTime,
            contentLength: res.getHeader("content-length") as string
        }

        if (res.statusCode >= 500) {
            console.error(JSON.stringify(finalLog))
        } else if (res.statusCode >= 400) {
            console.warn(JSON.stringify(finalLog))
        } else {
            console.info(JSON.stringify(finalLog))
        }
    })
    next()
}