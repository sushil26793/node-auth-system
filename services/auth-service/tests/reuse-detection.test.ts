import request from "supertest";
import mongoose from "mongoose";
import { User } from "../src/models/User.js";
import { app } from "../src/index.js";
import { RefreshToken } from "../src/models/RefreshToken.js";



describe("Refresh token reuse detection", () => {
    beforeAll(async () => {
        await mongoose.connect(process.env.MONGO_URI as string)
    });

    afterAll(async () => {
        await mongoose.connection.close()
    });

    it("revokes family when old token is reused.", async () => {
        const email = 'reuse@example.com';
        const userAgent = 'jest-test-agent/1.0';
        const ip = '127.0.0.1';

        const user = await User.create({ email, password: 'Password1!', isEmailVerified: true });
        const loginRes = await request(app)
            .post('/auth/login')
            .set("User-Agent", userAgent)
            .set('X-Forwarded-For', ip)
            .send({ email, password: "Password1!" });

        const cookie = loginRes.headers['set-cookie'][0];
        const oldToken = /refreshToken=([^;]+)/.exec(cookie)![1];
        const accessToken = loginRes.body.accessToken;

        await request(app)
            .post('/auth/refresh')
            .set("User-Agent", userAgent)
            .set('X-Forwarded-For', ip)
            .set("Cookie", cookie)
            .set("Authorization", `Bearer ${accessToken}`)
            .send()

        const reuseRes = await request(app)
            .post('/auth/refresh')
            .set("User-Agent", userAgent)
            .set('X-Forwarded-For', ip)
            .set("Authorization", `Bearer ${accessToken}`)
            .set('Cookie', `refreshToken=${oldToken}`)
            .send();

        expect(reuseRes.status).toBe(401)


        const family = await RefreshToken.find({ userId: user._id.toString() });
        const allRevoked = family.every(t => t.isRevoked);
        expect(allRevoked).toBe(true)

    })
})