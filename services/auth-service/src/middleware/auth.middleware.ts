import { Request, Response, NextFunction } from 'express';
import { TokenService } from '../services/tokenService.js';

const tokenService = new TokenService();

export const requireAuth = (req: Request, res: Response, next: NextFunction) => {
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith("Bearer")) {
        return res.status(400).json({ error: "Unauthorized." })
    }

    const token = authHeader.split(" ")[1];
    const decoded = tokenService.verifyAccessToken(token);
    if (!decoded) return res.status(401).json({ error: 'Invalid token' });
    (req as any).user = decoded;
    next()

}