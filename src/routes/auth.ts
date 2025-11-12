import { Router } from "express";
import { authController } from "../controllers/authController";
import { authenticateToken } from "../middlewares/authenticate";
import { loginLimiter, passwordResetLimiter, registerLimiter } from "../middlewares/rateLImit";


const router = Router();




router.post('/register',registerLimiter, authController.register);
router.post('/login',loginLimiter ,authController.login);
router.post('/refresh-token',authController.refreshToken);
router.post('/logout',authenticateToken, authController.logout);
router.get('/me',authenticateToken, authController.getCurrentUser);
router.post('/change-password',authenticateToken,passwordResetLimiter,authController.changePassword);


export default router;