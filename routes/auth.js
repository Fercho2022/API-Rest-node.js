const router= require ('express').Router();

const User = require('../models/User');

const Joi = require ('@hapi/joi');

const bcrypt = require ('bcrypt');

const jwt = require('jsonwebtoken');





// Validation registro y guardado en base de datos mongobd

const schemaRegister = Joi.object({
    name: Joi.string().min(6).max(255).required(),
    email: Joi.string().min(6).max(255).required().email(),
    password: Joi.string().min(6).max(1024).required()

})

router.post('/register', async(req, res) => {

    //validaciones de usuario

    const {error} = schemaRegister.validate(req.body)

    // Si hay errores en la validación  devuelve json con errores y el mensaje adecuado

    if (error){

        return res.status(400).json({error: error.details[0].message})
    }

    // Si no hay error de validacion se verifica si existe ese email en la base de datos
    const existeEmail= await User.findOne({email: req.body.email})

    //Si existe ese email en base de datos hace un return de ya registrado

    if (existeEmail) {
        return res.json({error: true, mensaje: 'email ya registrado'})
   
    }


    // encriptacion del password haciendo uso de bcrypt y generando saltos, del body se captura el password inicial

    const saltos = await bcrypt.genSalt(10);
    const password = await bcrypt.hash(req.body.password, saltos)

    //una vez validado y encriptada la contraseña se crea un nuevo usuario en mongoDB

    const user = new User({

        name: req.body.name,
        email:req.body.email,
        password: password
    })

    try{
        const userDB= await user.save();
        res.json({
            error:null,
            data: userDB
        })
        
    }catch(error){
        res.status(400).json({error})

    }

    
})

//Validation Login con Joi 
const schemaLogin = Joi.object({
    
    email: Joi.string().min(6).max(255).required().email(),
    password: Joi.string().min(6).max(1024).required()

})

router.post('/login', async (req, res) =>{

    //uso de schemaLogin para validar el body del frontend
    const {error} = schemaLogin.validate(req.body);
    if (error) return res.status(400).json({ error: error.details[0].message})

    //sobre el User del model hace una busqueda del email y lo guarda en const user, el metodo findOne devuelve el user
    const user = await User.findOne({email: req.body.email});

    //si no esta ese usuario con ese email en la base de mongoDB entonces retorna un .json con error
    if (!user) return res.status(400).json({error: 'Usuario no encontrado'});

    // si el usuario esta registrado en mongoDB enotnces ahora debe comparar la contraseña del body con la de mongoDB
    const validPassword = await bcrypt.compare(req.body.password, user.password);
    if (!validPassword) return res.status(400).json({ error: 'contraseña no válida' })

    // crea el token para el acceso a rutas protegidas, ese token no debe contener nunca el password del user
    const token = jwt.sign({
        name: user.name,
        id: user._id

    }, process.env.TOKEN_SECRET)

// cuando termina de loguearse le envía con un header el token del usuario con una identificacion de auth-token
    res.header('auth-token', token).json({
        error: null,
        data:{token}
    })



})

//




module.exports = router;