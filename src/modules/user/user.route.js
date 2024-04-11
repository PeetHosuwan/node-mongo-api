const express = require('express')
const router = express.Router()
const { checkToken } = require('../../middlewares/token-authen')

const userController = require('./controller/user.controller')

router.get('/', checkToken, userController.getUsers)

router.get('/:id', userController.getUserById)

router.post('/', userController.createUser)

router.put('/:id', userController.updataUserById)

router.delete('/:id', userController.deleteUserById)


module.exports = router