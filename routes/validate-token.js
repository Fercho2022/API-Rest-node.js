const jwt = require ('jsonwebtoken');

//middleware para validar token (rutas protegidas)

const verifyToken = (req, res, next) => {


    //se captura el auth-token del header enviado del lado del frontend, este es tomado por el req.
    
    const token = req.header('auth-token');

    // si no existe el token en el header enviado del lado del frontend, lo paramos con un error.

    if (!token) return res.status(401).json({error: 'Acceso denegado'})

    try{
            // verify compara el token que viene del frontend luego de que fue validado contra la la clave secreta
        const verificar= jwt.verify(token, process.env.TOKEN_SECRET)
        req.user= verificar
        next()

    }catch(error){
        res.status(400).json({error: 'token no es valido'})


    }


}

module.exports = verifyToken;