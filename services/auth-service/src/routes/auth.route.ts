// services/auth-service/src/routes/auth.routes.ts

import express, { Request, Response } from 'express';
import { body, validationResult } from 'express-validator';
import { User } from '../models/User.js';
import { KafkaProducer } from '../services/kafka-producer.service.js';
import { rateLimiter } from '../middleware/rateLimit.middleware.js';
import { logger } from '../utils/logger.util.js';
import crypto from 'crypto';
import { TokenService } from '../services/tokenService.js';
import { AuthService } from '../services/auth.service.js';
import { requireAuth } from '../middleware/auth.middleware.js';

const router = express.Router();
const tokenService = new TokenService();
const authService = new AuthService();
const kafkaProducer = new KafkaProducer();

/**
 * POST /auth/signup
 * User registration with email verification
 */
router.post('/signup',
  // rateLimiter({ max: 5, windowMs: 15 * 60 * 1000 }), // 5 requests per 15 minutes
  [
    body('email').isEmail().normalizeEmail(),
    body('password')
      .isLength({ min: 8 })
      .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
      .withMessage('Password must contain uppercase, lowercase, number and special character')
  ],
  async (req: Request, res: Response) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
      }

      const { email, password } = req.body;

      const { user, verificationToken } = await authService.createUser(email, password);

      // Publish event to Kafka
      await kafkaProducer.publishEvent('user.events', {
        type: 'USER_CREATED',
        userId: user._id.toString(),
        email: user.email,
        verificationToken: verificationToken,
        timestamp: new Date()
      });

      logger.info('User created', { userId: user._id, email });

      res.status(201).json({
        message: 'User created successfully. Please check your email to verify your account.',
        userId: user._id
      });
    } catch (error: any) {
      console.log('DEBUG ERROR:', error);
      if (error.message && error.message.includes('already registered')) {
        return res.status(409).json({ error: 'Email already registered' });
      }
      logger.error('Signup error', { error: error.message });
      res.status(500).json({ error: 'Internal server error', details: error.message || String(error) });
    }
  }
);

/**
 * POST /auth/login
 * User login with multi-device support
 * Returns access token and refresh token (HttpOnly cookie)
 */
router.post('/login',
  // rateLimiter({ max: 10, windowMs: 15 * 60 * 1000 }),
  [
    body('email').isEmail().normalizeEmail(),
    body('password').notEmpty(),
    body('deviceId').optional().isString()
  ],
  async (req: Request, res: Response) => {
    try {
      const { email, password, deviceId = crypto.randomBytes(16).toString('hex') } = req.body;
      const ipAddress = req.ip || req.socket.remoteAddress || '';
      const userAgent = req.headers['user-agent'] || '';

      // Find user
      const user = await authService.validateUser(email);

      // Check if account is locked
      if (user.isLocked()) {
        return res.status(423).json({ error: 'Account is temporarily locked. Try again later.' });
      }

      // verify password 

      const isPasswordValid = await authService.verifyPassword(user, password);
      if (!isPasswordValid) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      // Check email verification
      if (!user.isEmailVerified) {
        return res.status(403).json({ error: 'Please verify your email first' });
      }

      // Generate tokens
      const accessToken = tokenService.generateAccessToken(user._id.toString(), user.role, deviceId);
      const { token: refreshToken } = await tokenService.generateRefreshToken(
        user._id.toString(),
        deviceId,
        ipAddress,
        userAgent
      );

      // Set refresh token as HttpOnly Secure cookie
      res.cookie('refreshToken', refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production', // HTTPS only in production
        sameSite: 'strict', // CSRF protection
        maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
        path: '/auth/refresh' // Limit cookie scope
      });

      // Publish login event
      await kafkaProducer.publishEvent('auth.events', {
        type: 'USER_LOGGED_IN',
        userId: user._id.toString(),
        deviceId,
        ipAddress,
        timestamp: new Date()
      });

      logger.info('User logged in', { userId: user._id, deviceId });

      res.json({
        accessToken,
        deviceId,
        user: {
          id: user._id,
          email: user.email,
          role: user.role
        }
      });
    } catch (error: any) {
      logger.error('Login error', { error: error.message });
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

/**
 * POST /auth/refresh
 * Refresh access token using refresh token rotation
 * Critical endpoint for token security
 */
router.post('/refresh', requireAuth,
  // rateLimiter({ max: 20, windowMs: 15 * 60 * 1000 }),
  async (req: Request, res: Response) => {
    try {
      const oldRefreshToken = req.cookies.refreshToken;

      if (!oldRefreshToken) {
        return res.status(401).json({ error: 'Refresh token required' });
      }

      const ipAddress = req.ip || req.socket.remoteAddress || '';
      const userAgent = req.headers['user-agent'] || '';

      // Rotate token
      const result = await tokenService.rotateRefreshToken(oldRefreshToken, ipAddress, userAgent);

      if (!result) {
        // Clear cookie on failure
        res.clearCookie('refreshToken', { path: '/auth/refresh' });
        return res.status(401).json({ error: 'Invalid or expired refresh token' });
      }

      // Set new refresh token cookie
      res.cookie('refreshToken', result.refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 7 * 24 * 60 * 60 * 1000,
        path: '/auth/refresh'
      });

      res.json({
        accessToken: result.accessToken,
        deviceId: result.deviceId
      });
    } catch (error: any) {
      logger.error('Refresh error', { error: error.message });
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

/**
 * POST /auth/logout
 * Logout user and revoke refresh token for device
 */
router.post('/logout',
  async (req: Request, res: Response) => {
    try {
      const refreshToken = req.cookies.refreshToken;
      const { deviceId } = req.body;

      if (refreshToken) {
        // Decode to get userId and deviceId
        const decoded: any = tokenService.verifyAccessToken(refreshToken);
        if (decoded) {
          await tokenService.revokeTokenFamily(decoded.userId, deviceId || decoded.deviceId);
        }
      }

      // Clear cookie
      res.clearCookie('refreshToken', { path: '/auth/refresh' });

      res.json({ message: 'Logged out successfully' });
    } catch (error: any) {
      logger.error('Logout error', { error: error.message });
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

/**
 * POST /auth/password-reset-request
 * Request password reset
 */
router.post('/password-reset-request', requireAuth,
  // rateLimiter({ max: 3, windowMs: 60 * 60 * 1000 }), // 3 per hour
  [body('email').isEmail().normalizeEmail()],
  async (req: Request, res: Response) => {
    try {
      const { email } = req.body;
      const user = await User.findOne({ email });

      // Always return success to prevent email enumeration
      if (!user) {
        return res.json({ message: 'If the email exists, a reset link will be sent' });
      }

      // Generate reset token
      const resetToken = crypto.randomBytes(32).toString('hex');
      user.passwordResetToken = crypto.createHash('sha256').update(resetToken).digest('hex');
      user.passwordResetExpires = new Date(Date.now() + 60 * 60 * 1000); // 1 hour
      await user.save();

      // Publish event
      await kafkaProducer.publishEvent('auth.events', {
        type: 'PASSWORD_RESET_REQUESTED',
        userId: user._id.toString(),
        email: user.email,
        resetToken,
        timestamp: new Date()
      });

      res.json({ message: 'If the email exists, a reset link will be sent' });
    } catch (error: any) {
      logger.error('Password reset request error', { error: error.message });
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

/**
 * POST /auth/password-reset
 * Reset password with token
 */
router.post('/password-reset', requireAuth,
  // rateLimiter({ max: 5, windowMs: 60 * 60 * 1000 }),
  [
    body('token').notEmpty(),
    body('password')
      .isLength({ min: 8 })
      .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
  ],
  async (req: Request, res: Response) => {
    try {
      const { token, password } = req.body;

      const hashedToken = crypto.createHash('sha256').update(token).digest('hex');
      const user = await User.findOne({
        passwordResetToken: hashedToken,
        passwordResetExpires: { $gt: new Date() }
      });

      if (!user) {
        return res.status(400).json({ error: 'Invalid or expired reset token' });
      }

      // Update password
      user.password = password;
      user.passwordResetToken = undefined;
      user.passwordResetExpires = undefined;
      await user.save();

      // Revoke all existing tokens (force re-login)
      await tokenService.revokeAllUserTokens(user._id.toString());

      // Publish event
      await kafkaProducer.publishEvent('auth.events', {
        type: 'PASSWORD_RESET_COMPLETED',
        userId: user._id.toString(),
        timestamp: new Date()
      });

      res.json({ message: 'Password reset successful. Please login with your new password.' });
    } catch (error: any) {
      logger.error('Password reset error', { error: error.message });
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

export default router;
