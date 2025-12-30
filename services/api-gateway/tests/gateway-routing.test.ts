
import request from 'supertest';
import express from 'express';
import proxyRoutes from '../src/routes/gateway.routes';
import { globalLimiter, authLimiter } from '../src/config/rate-limit';

// Mock the proxy middleware prevents actual network calls
jest.mock('../src/middleware/proxy.middleware', () => ({
    authProxy: (req: any, res: any) => res.status(200).json({ service: 'auth-service', path: req.path }),
    userProxy: (req: any, res: any) => res.status(200).json({ service: 'user-service', path: req.path }),
}));

// Mock rate limit to avoid issues during testing
jest.mock('../src/config/rate-limit', () => ({
    globalLimiter: (req: any, res: any, next: any) => next(),
    authLimiter: (req: any, res: any, next: any) => next(),
}));

// Mock auth middleware
jest.mock('../src/middleware/auth.middleware', () => ({
    validateJwt: (req: any, res: any, next: any) => {
        req.user = { userId: 'test-user' };
        next();
    },
}));

const app = express();
app.use(express.json());
app.use('/api/v1', proxyRoutes);

describe('API Gateway Routing', () => {
    it('should route /auth requests to auth-service', async () => {
        const response = await request(app).get('/api/v1/auth/healthz');
        expect(response.status).toBe(200);
        expect(response.body).toEqual({ service: 'auth-service', path: '/healthz' });
    });

    it('should route /users requests to user-service', async () => {
        const response = await request(app).get('/api/v1/users/profile');
        expect(response.status).toBe(200);
        expect(response.body).toEqual({ service: 'user-service', path: '/profile' });
    });
});
