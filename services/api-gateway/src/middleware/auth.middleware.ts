import { Request, Response, NextFunction } from "express";
import jwt from 'jsonwebtoken';


export const validateJwt = (req: Request, res: Response, next: NextFunction) => {
    const publicPaths = ['/auth/login', '/auth/signup', '/auth/refresh', '/auth/password-reset'];

    if (publicPaths.some(path => req.path.startsWith(path))) {
        return next();
    }

    const header = req.headers.authorization;
    if (!header?.startsWith("Bearer")) {
        return res.status(401).json({ error: "Unauthorized: No token provided." })
    }

    const token = header.split(' ')[1];
    try {
        const decoded = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET!) as any;
        req.headers['x-user-id'] = decoded.userId;
        req.headers['x-user-role'] = decoded.role;
        next();

    } catch (error) {
        return res.status(401).json({ error: 'Unauthorized: Invalid token' });

    }
}