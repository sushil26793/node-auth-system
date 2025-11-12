import { Request, Response, NextFunction } from "express";
import { AppError } from "../types";
import { tokenService } from "../services/tokenService";
import { User } from "../models/User";


declare global {
    namespace Express {
        interface Request {
            userId: string;
            user?: any;
            token?: string
        }
    }
}


export async function authenticateToken(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
        const authHeader = req.headers["authorization"];
        const token = authHeader?.startsWith("Bearer ") ? authHeader.slice(7) : null;
        if (!token) {
            throw new AppError(401, "Access token is required.");
        }

        const decoded = tokenService.verifyAccessToken(token);
        const hasAnomalies = await tokenService.detectTokenAnomalies(decoded.userId, token);
        if (hasAnomalies) {
            throw new AppError(401, "Suspicious activity detected. Please login again.");
        }
        const user = await User.findById(decoded.userId);
        if (!user || !user.isActive) {
            throw new AppError(403, "User account is not available.");
        }

        req.userId = decoded.userId;
        req.user = decoded;
        req.token = token;

        next();

    } catch (error) {
        if (error instanceof AppError) {
            res.status(error.statusCode).json({
                success: false,
                message: error.message
            });
        } else {
            res.status(500).json({
                success: false,
                message: "Internal server error."
            })
        }
    }
}

export async function optionalAuth(
    req: Request,
    res: Response,
    next: NextFunction
): Promise<void> {
    try {
        const authHeader = req.headers['authorization'];
        const token = authHeader?.startsWith('Bearer ')
            ? authHeader.slice(7)
            : null;

        if (token) {
            const decoded = tokenService.verifyAccessToken(token);
            req.userId = decoded.userId;
            req.user = decoded;
        }

        next();
    } catch (error) {
        // Silently fail and continue
        next();
    }
};