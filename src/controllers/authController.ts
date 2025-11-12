import { Request, Response } from "express";
import { authService } from "../services/authService";
import { asyncHandler } from "../middlewares/errorHandler";
import { AppError } from "../types";
import { tokenService } from "../services/tokenService";

export class AuthController {
    register = asyncHandler(async (req: Request, res: Response) => {
        const { email, password } = req.body;
        const result = await authService.register(email, password);
        res.status(201).json({
            success: true,
            message: "User registered successfully.",
            data: {
                user: result.user,
                accessToken: result.accessToken,
                refreshToken: result.refreshToken,
                expiresIn: result.expiresIn
            }
        });
    });

    login = asyncHandler(async (req: Request, res: Response) => {
        const { email, password } = req.body;
        const result = await authService.login(email, password);
        res.status(201).json({
            success: true,
            message: "Login successful.",
            data: {
                user: result.user,
                accessToken: result.accessToken,
                refreshToken: result.refreshToken,
                expiresIn: result.expiresIn
            }
        });
    });

    logout = asyncHandler(async (req: Request, res: Response) => {
        const userId = req.userId;
        if (!userId) {
            throw new AppError(401, "User not authenticated")
        }
        await authService.logout(userId);
        res.clearCookie("refreshToken");
        res.status(200).json({
            success: true,
            message: "Logout successful."
        });
    });

    getCurrentUser = asyncHandler(async (req: Request, res: Response) => {
        const userId = req.userId;
        if (!userId) {
            throw new AppError(401, "User not authenticated.")
        }
        const user = await authService.getCurrentUser(userId);

        res.status(200).json({
            success: true,
            data: { user }
        })
    });


    refreshToken = asyncHandler(async (req: Request, res: Response) => {
        console.log(req.cookies,"-----------------cookies ");
        const refreshToken = req?.cookies?.refreshToken || req.body?.refreshToken;
        if (!refreshToken) {
            throw new AppError(401, "Refresh token is required.")
        }

        const tokens = await tokenService.refreshAccessToken(refreshToken);
        res.status(200).json({
            success: true,
            message: "Token refreshed successfully.",
            data: {
                accessToken: tokens.accessToken,
                refreshToken: tokens.refreshToken,
                expiresIn: tokens.expiresIn
            }
        })
    });

    changePassword = asyncHandler(async (req: Request, res: Response) => {
        const { oldPassword, newPassword } = req.body;
        const userId = req.userId;
        if (!userId) throw new AppError(401, "User not authenticated.");
        await authService.changePassword(userId, oldPassword, newPassword);
        res.clearCookie("refreshToken");
        res.json({
            success: true,
            message: "Password changed successfully . Please login again."
        })
    });



}



export const authController = new AuthController();