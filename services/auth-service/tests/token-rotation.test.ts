import request from 'supertest';
import mongoose from 'mongoose';
import { User } from '../src/models/User.js';
import { app } from '../src/index.js';
import { RefreshToken } from '../src/models/RefreshToken.js';

describe('Token rotation', () => {
  beforeAll(async () => {
    // Ensure we are connected to the test database
    if (mongoose.connection.readyState === 0) {
        await mongoose.connect(process.env.MONGO_URI as string);
    }
  });

  // Clean up database between tests
  afterEach(async () => {
    await User.deleteMany({});
    await RefreshToken.deleteMany({});
  });

  afterAll(async () => {
    await mongoose.connection.close();
  });

  it('rotates refresh token and marks old as used', async () => {
    const email = 'test@example.com';
    const password = 'Password1!';
    
    // FIX 1: consistent Agent and IP for device fingerprinting
    const userAgent = 'jest-test-agent/1.0'; 
    const ip = '127.0.0.1'; 

    // 1. Create User
    const user = await User.create({
      email,
      password, 
      isEmailVerified: true
    });

    // 2. Login
    const loginRes = await request(app)
      .post('/auth/login')
      .set('User-Agent', userAgent)
      .set('X-Forwarded-For', ip) 
      .send({ email, password });

    expect(loginRes.status).toBe(200);


    const cookie = loginRes.headers['set-cookie'];
    const accessToken = loginRes.body.accessToken;
    
    expect(accessToken).toBeDefined();
    expect(cookie).toBeDefined();
    // 3. Refresh Token
    const refreshRes = await request(app)
      .post('/auth/refresh')
      .set('Cookie', cookie)        // Send cleaned cookies
      .set('Authorization', `Bearer ${accessToken}`)
      .set('User-Agent', userAgent)  // Match Login UA
      .set('X-Forwarded-For', ip)    // Match Login IP
      .send();

    // FIX 3: Debug logging to see the actual error message if it fails
    if (refreshRes.status !== 200) {
        console.error('Refresh Failed. Server Response:', JSON.stringify(refreshRes.body, null, 2));
    }

    expect(refreshRes.status).toBe(200);
    expect(refreshRes.body.accessToken).toBeDefined();

    // 4. Verification
    const tokens = await RefreshToken.find({ userId: user._id.toString() });
    
    // We expect 2 tokens:
    // 1. The original one from login (should be isUsed: true)
    // 2. The new one from refresh (should be isUsed: false)
    const usedTokens = tokens.filter(t => t.isUsed);
    const unusedTokens = tokens.filter(t => !t.isUsed);

    expect(tokens.length).toBe(2);
    expect(usedTokens.length).toBe(1);
    expect(unusedTokens.length).toBe(1);
  });
});