import z, { ZodType } from "zod";
import { NextFunction, Request, Response } from "express";


export function validateRequest<T extends ZodType>(schema: T) {
    return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
        try {
            const result = schema.safeParse({
                body: req.body,
                query: req.query,
                params: req.params,
            });
            if (!result.success) {
               const errors = result.error.issues.map((err) => ({
                    field: err.path.slice(1).join(".") || err.path[0],
                    message: err.message,
                    code: err.code,
                }));


                res.status(400).json({
                    success: false,
                    message: "Validation failed.",
                    errors,
                });
                return;
            }

            // Assign parsed & validated data back
            const { body, query, params } = result.data as {
                body?: Record<string, any>;
                query?: Record<string, any>;
                params?: Record<string, any>;
            }
            if (body) req.body = body;
            if (query) req.query = query;
            if (params) req.params = params;

            next();
        } catch (error) {
            console.error('Unexpected validation error:', error);
            next(error);
        }
    };
}



export const registerSchema = z.object({
    email: z.string({ error: "Email is required" }).email('Invalid email format').toLowerCase().trim(),
    password: z.string({ error: "Password is required." }).min(8, "Password must be at least 8 characters")
        .regex(/[a-z]/, "Password must contain at least one lowercase letter")
        .regex(/[A-Z]/, 'Password must contain at least one uppercase letter')
        .regex(/[0-9]/, 'Password must contain at least one number')
        .regex(/[^a-zA-Z0-9]/, 'Password must contain at least one special character')

});


export const loginSchema = z.object({
    body: z.object({
        email: z.string({ error: "Email is required" }).email('Invalid email format').toLowerCase().trim(),
        password: z.string({ error: "Password is required." })
    })
});



export const changePasswordSchema = z.object({
    body: z.object({
        oldPassword: z.string({
            error: 'Current password is required',
        }),
        newPassword: z
            .string({
                error: 'New password is required',
            })
            .min(8, 'Password must be at least 8 characters')
            .regex(/[a-z]/, 'Password must contain at least one lowercase letter')
            .regex(/[A-Z]/, 'Password must contain at least one uppercase letter')
            .regex(/[0-9]/, 'Password must contain at least one number')
            .regex(
                /[^a-zA-Z0-9]/,
                'Password must contain at least one special character'
            ),
    }),
});



export const refreshTokenSchema = z.object({
    body: z.object({
        refreshToken: z.string().optional(),
    }),
    // Also check cookies
});