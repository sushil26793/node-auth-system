import request from 'supertest';
import mongoose from 'mongoose';
import { UserProfile } from '../src/models/userProfile.js';
import jwt from 'jsonwebtoken';
import express from 'express';
import userRouter from '../src/routes/user.route.js';
import "dotenv/config";
const app = express();
app.use(express.json());
app.use('/users', userRouter);
describe('User profile service', () => {
    let accessToken;
    const userId = '507f1f77bcf86cd799439011'; // Mock Mongo Object ID
    const secret = 'super-access-secret';
    beforeAll(async () => {
        // Connect to MongoDB
        await mongoose.connect(process.env.MONGO_URI);
        process.env.ACCESS_TOKEN_SECRET = secret;
        // Generate Token
        accessToken = jwt.sign({ userId, role: 'user' }, secret, { expiresIn: '1h' });
    });
    // ⭐️ FIX #2: Clean up after every test
    afterEach(async () => {
        await UserProfile.deleteOne({ userId });
    });
    afterAll(async () => {
        // Close MongoDB connection
        await mongoose.connection.close();
        // ⭐️ FIX #3: Add server/consumer shutdown logic here if not handled globally
    });
    describe('GET /users/me', () => {
        // This test now expects the corrected 404 from the server
        it('should return 404 if profile does not exist yet', async () => {
            const res = await request(app)
                .get('/users/me')
                .set('Authorization', `Bearer ${accessToken}`)
                .send();
            // This should now correctly return 404 (if middleware is fixed)
            expect(res.status).toBe(404);
        });
        it('should return the profile if it exists', async () => {
            // Manually create profile 
            await UserProfile.create({
                userId,
                email: 'test@test.com',
                firstName: 'John',
                isVerified: true
            });
            const res = await request(app)
                .get('/users/me')
                .set('Authorization', `Bearer ${accessToken}`);
            expect(res.status).toBe(200);
            expect(res.body.email).toBe('test@test.com');
            expect(res.body.firstName).toBe('John');
        });
    });
    describe('PUT /users/me', () => {
        beforeEach(async () => {
            await UserProfile.create({
                userId,
                email: 'test@test.com',
                firstName: 'Initial',
                isVerified: true
            });
        });
        it('should update the user profile fields', async () => {
            const updatedData = {
                firstName: 'Jane',
                bio: "New bio updated via API",
                preferences: {
                    theme: 'dark',
                    marketingEmails: false,
                    pushNotifications: true
                }
            };
            const res = await request(app)
                .put('/users/me')
                .set('Authorization', `Bearer ${accessToken}`)
                .send(updatedData);
            expect(res.status).toBe(200);
            expect(res.body.firstName).toBe('Jane');
            expect(res.body.bio).toBe('New bio updated via API');
            expect(res.body.preferences.theme).toBe('dark');
        });
        // new test 
        it('should prevent updating immutable fields like email', async () => {
            const res = await request(app)
                .put('/users/me')
                .set("Authorization", `Bearer ${accessToken}`)
                .send({ email: 'hacked@test.com' });
            const user = await UserProfile.findOne({ userId });
            expect(user?.email).toBe('test@test.com');
        });
        it('should return 401 without token', async () => {
            const res = await request(app).get('/users/me');
            expect(res.status).toBe(401);
        });
    });
});
