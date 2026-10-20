import { NextFunction, Request, Response } from 'express';
import AuthService from '../services/AuthService';
import jwt from 'jsonwebtoken';

// Función para registrar un usuario nuevo
// Según el contrato, el registro no devuelve token: el frontend lleva al usuario a la página de login
const register = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const user = await AuthService.register(req.body);

        // 201 porque se ha creado un recurso nuevo
        res.status(201).json({ user });
    } catch (error) {
        // Si el email ya existe, el ErrorHandler responde 409
        next(error);
    }
};

// Función para iniciar sesión
const login = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const result = await AuthService.login(req.body.email, req.body.password);

        if (result) {
            // Usamos la caducidad real del JWT para que la cookie dure lo mismo que el refresh token.
            const refreshPayload = jwt.decode(result.refreshToken);

            if (!refreshPayload || typeof refreshPayload === 'string' || typeof refreshPayload.exp !== 'number') {
                throw new Error('No se pudo determinar la caducidad del refresh token');
            }

            res.cookie('refreshToken', result.refreshToken, {
                httpOnly: true, // JavaScript del navegador no puede leer esta cookie.
                sameSite: 'strict', // El navegador limita su envío a este sitio.
                secure: process.env.NODE_ENV === 'production', // En producción solo viaja por HTTPS.
                path: '/auth', // Se envía únicamente a las rutas de autenticación.
                expires: new Date(refreshPayload.exp * 1000) // JWT usa segundos; la cookie recibe una fecha.
            });

            // El refresh token ya no se envía en el JSON; el navegador lo guarda en la cookie.
            res.status(200).json({ token: result.token, user: result.user });
        } else {
            // 401: no se ha podido identificar al usuario
            res.status(401).json({ message: 'Email o contraseña incorrectos' });
        }
    } catch (error) {
        next(error);
    }
};

// Función para pedir un access token nuevo con el refresh token
const refresh = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const refreshToken = req.cookies?.refreshToken;

        if (!refreshToken) {
            // Sin cookie no hay sesión que renovar
            return res.status(401).json({ message: 'Falta el refresh token' });
        }

        const result = await AuthService.refresh(refreshToken);

        if (result) {
            // El refresh token no se devuelve: el cliente ya lo tiene en la cookie HttpOnly
            return res.status(200).json(result);
        }

        return res.status(401).json({ message: 'El usuario ya no existe' });
    } catch (error) {
        // Un token inválido o caducado se convierte en 401 en el ErrorHandler
        next(error);
    }
};

// Devuelve los datos del usuario autenticado por su access token.
const me = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const userId = req.user?.id;

        if (!userId) {
            return res.status(401).json({ message: 'Falta el token' });
        }

        const user = await AuthService.getById(userId);

        if (!user) {
            return res.status(401).json({ message: 'El usuario ya no existe' });
        }

        return res.status(200).json({ user });
    } catch (error) {
        next(error);
    }
};

// Cierra la sesión borrando la cookie que contiene el refresh token.
const logout = (req: Request, res: Response) => {
    res.clearCookie('refreshToken', {
        httpOnly: true,
        sameSite: 'strict',
        secure: process.env.NODE_ENV === 'production',
        path: '/auth' // Debe coincidir con el path usado al crear la cookie.
    });

    res.status(200).json({ message: 'Sesión cerrada' });
    
};

export default { register, login, refresh, me, logout };
