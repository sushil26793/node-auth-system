import { Router } from "express";
import { authController } from "../controllers/authController";
import { authenticateToken } from "../middlewares/authenticate";
import { loginLimiter, passwordResetLimiter, registerLimiter } from "../middlewares/rateLImit";
import { changePasswordSchema, loginSchema, refreshTokenSchema, registerSchema, validateRequest } from "../middlewares/validation";


const router = Router();




router.post('/register', validateRequest(registerSchema), registerLimiter, authController.register);
router.post('/login', validateRequest(loginSchema), loginLimiter, authController.login);
router.post('/refresh-token', validateRequest(refreshTokenSchema), authController.refreshToken);
router.post('/logout', authenticateToken, authController.logout);
router.get('/me', authenticateToken, authController.getCurrentUser);
router.post('/change-password', validateRequest(changePasswordSchema), authenticateToken, passwordResetLimiter, authController.changePassword);


export default router;