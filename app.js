const express = require('express')
const cors = require('cors')
require('dotenv').config()

const authRoute = require('./src/modules/auth/auth.router')
const userRoute = require('./src/modules/user/user.route')

const mongoose = require('mongoose')

const app = express()

app.use(express.json())
app.use(express.urlencoded({extended: true}))

app.use(cors())

app.use('/user',userRoute)
app.use('/auth', authRoute)

mongoose.connect(process.env.DB_CONNECTION)

app.get('/', (req,res) => {
    res.send('Welcome to Server').status(200)
})

const PORT = process.env.PORT || 3030

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`)
})