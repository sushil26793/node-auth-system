import express from "express";
import { UserService } from "../services/user.service.js";
import { requireAuth } from "../middleware/auth.middleware.js";
import { logger } from "../utils/logger.util.js";
import { body, validationResult } from "express-validator";
const router = express.Router();
const userService = new UserService();
router.get('/me', requireAuth, async (req, res) => {
    try {
        const profile = await userService.getProfile(req.user.userId);
        if (!profile)
            return res.status(404).json({ error: 'Profile not found' });
        res.json(profile);
    }
    catch (error) {
        console.error("Error fetching profile:", error);
        // logger.error("auth/me", error.message)
        res.status(500).json({ error: 'Server error' });
    }
});
router.put('/me', requireAuth, [
    body('firstName').optional().trim().notEmpty(),
    body('lastName').optional().trim().notEmpty(),
    body('bio').optional().isLength({ max: 500 }),
    body('preferences').optional().isObject()
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty())
        return res.status(400).json({ errors: errors.array() });
    try {
        const updated = await userService.updateProfile(req.user.userId, req.body);
        res.json(updated);
    }
    catch (error) {
        logger.error("profile update failed", error.message);
        res.status(500).json({ error: 'Update failed' });
    }
});
export default router;
