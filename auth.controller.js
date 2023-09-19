const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { expressjwt: expressJwt } = require("express-jwt");
//si tengo errores, recordar que req.user no funciona, en esta version es req.auth...
const User = require('./user.model');

const validateJwt = expressJwt({secret: process.env.SECRET, algorithms: ['HS256']});

const signToken = _id => jwt.sign({_id}, process.env.SECRET);

const findAndAssingnUser = async (req, res, next) => {
    try{
        const user = await User.findById(req.auth._id);
        if (!user) {
            return res.status(401).end();
        }
        req.auth = user // le asignamos el user que encontramos
        next();
    } catch (e) {
        next(e); // si llamamos a next con un error, no se ejecuta el siguiente middleware, se ejecuta uno distinto especial para el manejo de errores.
    }
}

//lo usamos para proteger los endpoints
const isAuthenticated = express.Router().use(validateJwt, findAndAssingnUser)

//controladores para poder iniciar sesion y registrarnos
const Auth = {
    //estas funciones se llaman handler, xq despues le podemos decir a express app.get, post, etc
    login: async(req, res) => {
        const {body} = req
        try {
            const user = await User.findOne({ email: body.email })
            if(!user){
                res.status(401).send('Usuario y/o contraseña inválida')
            } else {
                //aca comparamos que lo que pasa el usuario coincida con lo del servidor
                const isMatch = await bcrypt.compare(body.password, user.password)
                if(isMatch) {
                    const signed = signToken(user._id)
                    res.status(200).send(signed)
                } else {
                    res.status(401).send('Usuario y/o contraseña inválida')
                }
            }
        } catch(e) {
            res.send(e.message)
        }
    },
    register: async(req, res) => {
        const { body } = req
        try {
            const isUser = await User.findOne({ email: body.email })
            if(isUser){
                res.send('Usuario ya existe')
            } else {
                const salt = await bcrypt.genSalt()
                const hashed = await bcrypt.hash(body.password, salt)
                const user = await User.create({ email: body.email, password: hashed, salt})

                const signed = signToken(user._id)
                res.send(signed)
            }
        } catch (e) {
            res.status(500).send(err.message)
        }
    },
}

module.exports = {Auth, isAuthenticated}
