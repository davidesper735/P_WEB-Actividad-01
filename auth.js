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

        if (!email || !email.includes("@") || !password || password.length < 6) {
            return res.status(400).json({ error: "Email válido y clave (mínimo 6 caracteres) son obligatorios" });
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
