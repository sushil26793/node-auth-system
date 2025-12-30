// services/auth-service/src/middleware/rate-limit.middleware.ts
import rateLimit from 'express-rate-limit';
export const rateLimiter = (opts) => rateLimit({
    windowMs: opts.windowMs,
    max: opts.max,
    standardHeaders: true,
    legacyHeaders: false
});
