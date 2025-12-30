import express from 'express';
import { authProxy, userProxy } from '../middleware/proxy.middleware';
import { authLimiter } from '../config/rate-limit';
import { validateJwt } from '../middleware/auth.middleware';

const router = express.Router();


router.use('/auth', authLimiter, authProxy);

router.use('/users', validateJwt, userProxy)


export default router;