import { Request, Response, NextFunction } from "express";
import { AppError } from "../types";


export function errorHandler(
    error: Error | AppError,
    req: Request,
    res: Response,
    next: NextFunction
): void {
    console.error("Error", error);
    if (error instanceof AppError) {
        res.status(error.statusCode).json({
            success: false,
            message: error.message,
            statusCode: error.statusCode
        })
        return;
    }

    if (error.name === "MongooseError") {
        res.status(400).json({
            success: false,
            message: "Database error.",
            statusCode: 400
        })
        return;
    }

    res.status(500).json({
        success: false,
        message: "Internal server error.",
        statusCode: 500
    })

}



export function asyncHandler(fn: (req: Request, res: Response, next: NextFunction) => Promise<any>) {

    return (req: Request, res: Response, next: NextFunction) => {
        Promise.resolve(fn(req, res, next)).catch(next)
    }
}