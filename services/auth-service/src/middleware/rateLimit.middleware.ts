// services/auth-service/src/middleware/rate-limit.middleware.ts
import rateLimit from 'express-rate-limit';

interface Options {
  windowMs: number;
  max: number;
}

export const rateLimiter = (opts: Options) =>
  rateLimit({
    windowMs: opts.windowMs,
    max: opts.max,
    standardHeaders: true,
    legacyHeaders: false
  });
