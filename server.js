const express = require("express")
const db = require("./user-model")
const bcrypt = require("bcryptjs")
const session = require("express-session")
const KnexSessionStore = require("connect-session-knex")(session)
const dbConfig = require("./config")
const jwt = require("jsonwebtoken")
const cookieParser = require("cookie-parser")

const server = express()

const port = process.env.PORT || 5000

server.use(express.json())
server.use(cookieParser())// WILL TAKE ANY INCOMING COOKIES AND IT WILL PARSE THEM AND GIVE THEM TO US AS AN OBJECT ON THE REQUEST SO THAT WE CAN READ THE VALUES EASILY

server.get("/users", restrict, async (req, res, next) => {
    try{
        const users = await db.getusers()
        res.json(users)
    } catch(err) {
        next(err)
    }
})

server.post("/register", async (req, res, next) => {
    try{
        const { username, password, department } = req.body

        const newUser = await db.adduser({
            username,
            //hash the password with a time complexity of 15 (will take around 2 seconds on my current machine)
            password: await bcrypt.hash(password, 15),
            department,
        })

        res.json(newUser)

    } catch(err) {
        next(err)
    }
})

server.post("/login", async (req, res, next) => {
    try{
        const { username, password } = req.body
        const user = await db.findByUsername(username)

        // if user is not in the database
        if(!user) {
            return res.status(401).json({ message: "You shall not pass!"})
        }

        // compare the password the client is sending with the one in the database
        const passwordValid = await bcrypt.compare(password, user.password)

        // if password is WRONG
        if(!passwordValid) {
            return res.status(401).json({ message: "You shall not pass!"})
        }

        const payload = {
            userId: user.id,
            username:user.username,
            userRole: "normal", // this value usually comes from the database. so this user is just normal user not admin
        }

        // LINE BELOW IS USED WHEN YOU WANT THE TOKEN TO BE SAVED AS A COOKIE
        // res.cookie("token", jwt.sign(payload, process.env.JWT_SECRET))
        res.json({
            message: `Welcome ${user.username}!`,
            token: jwt.sign(payload, process.env.JWT_SECRET) // DELETE THIS FROM RESPONSE BODY IF SENDING IT AS COOKIE
        })

    } catch(err) {
        next(err)
    }
})

// MIDDELWARE
function restrict(req, res, next) {
    try {

        // verify that there is a request header named authorization
        const token = req.headers.authorization
        // THE LINE BELOW IS USED WHEN WOKRING WITH COOKIES
        // const token = req.cookies.token
        if (!token) {
            return res.status(401).json({ message: "You shall not pass!"})
        }


        // verify the token to make sure it has not been tampered with
        jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
            if (err) {
                return res.status(401).json({ message: "You shall not pass!"})
            }

            next()
        })
    } catch(err) {
        next(err)
    }
}

//  ERROR MIDDELWARE
server.use((err, req, res, next) => {
    console.log(err)
    res.status(500).json({
        message: "Something went wrong"
    })
})

server.listen(port, () => {
    console.log(`Running at http://localhost:${port}`)
})
