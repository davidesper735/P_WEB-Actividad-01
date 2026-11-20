import jwt from "jsonwebtoken";

// Revisa que la petición traiga un token válido (401 si no)
export function verificarToken(req, res, next) {
    const cabecera = req.headers.authorization || "";

    // La cabecera llega como: "Bearer eltoken"
    const partes = cabecera.split(" ");
    const tipo = partes[0];
    const token = partes[1];

    if (tipo !== "Bearer" || !token) {
        return res.status(401).json({ error: "Falta el token" });
    }

    try {
        const datos = jwt.verify(token, process.env.JWT_SECRET);
        req.usuario = datos;
        next();
    } catch (error) {
        return res.status(401).json({ error: "Token inválido o vencido" });
    }
}

// Deja pasar solo a los administradores (403 si no)
export function soloAdmin(req, res, next) {
    if (req.usuario.rol !== "admin") {
        return res.status(403).json({ error: "No tienes permiso para esto" });
    }
    next();
}
