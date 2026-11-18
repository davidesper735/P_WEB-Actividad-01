import express from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { db } from "./db.js";

export const rutasAuth = express.Router();

// POST /registro  -> crea un usuario con la clave guardada como hash
rutasAuth.post("/registro", async function (req, res) {
    try {
        const email = req.body.email;
        const password = req.body.password;

        if (!email || !password || password.length < 6) {
            return res.status(400).json({ error: "Email y clave (mínimo 6 caracteres) son obligatorios" });
        }

        const hash = await bcrypt.hash(password, 10);

        await db.query(
            "INSERT INTO usuarios (email, password) VALUES (?, ?)",
            [email, hash]
        );

        res.status(201).json({ mensaje: "Usuario creado" });
    } catch (error) {
        if (error.code === "ER_DUP_ENTRY") {
            return res.status(409).json({ error: "Ese email ya está registrado" });
        }
        console.log(error);
        res.status(500).json({ error: "Error en el servidor" });
    }
});

// POST /login  -> entrega el token
rutasAuth.post("/login", async function (req, res) {
    try {
        const email = req.body.email;
        const password = req.body.password;

        if (!email || !password) {
            return res.status(400).json({ error: "Faltan email o clave" });
        }

        const resultado = await db.query(
            "SELECT * FROM usuarios WHERE email = ?",
            [email]
        );
        const filas = resultado[0];

        if (filas.length === 0) {
            return res.status(401).json({ error: "Email o clave incorrectos" });
        }
        const usuario = filas[0];

        const ok = await bcrypt.compare(password, usuario.password);
        if (!ok) {
            return res.status(401).json({ error: "Email o clave incorrectos" });
        }

        const token = jwt.sign(
            { id: usuario.id, rol: usuario.rol },
            process.env.JWT_SECRET,
            { expiresIn: "1h" }
        );

        res.status(200).json({ token: token });
    } catch (error) {
        console.log(error);
        res.status(500).json({ error: "Error en el servidor" });
    }
});

// Middleware: revisa que la petición traiga un token válido
export function verificarToken(req, res, next) {
    const cabecera = req.headers.authorization;

    if (!cabecera) {
        return res.status(401).json({ error: "Falta el token" });
    }

    // La cabecera llega como: "Bearer eltoken"
    const partes = cabecera.split(" ");
    const token = partes[1];

    try {
        const datos = jwt.verify(token, process.env.JWT_SECRET);
        req.usuario = datos;
        next();
    } catch (error) {
        return res.status(401).json({ error: "Token inválido o vencido" });
    }
}

// Middleware: deja pasar solo a los administradores
export function soloAdmin(req, res, next) {
    if (req.usuario.rol !== "admin") {
        return res.status(403).json({ error: "No tienes permiso para esto" });
    }
    next();
}
