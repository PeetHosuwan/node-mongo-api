const userService = require('../../user/service/user.service')
const statusEnum = require('../../../commons/status.enum')
const { createToken} = require('../../../middlewares/token-authen')

const authController = {
    async login(req, res) {
        try{
            const payload = req.body

            const user = await userService.findOneByQuery({
                username: payload.username,
                password: payload.password,
                status: statusEnum.ACTIVE

            })

            console.log('user => ', user)

            if(user) {
                const token = createToken({
                    id: user._id,
                    firstName: user.firstName,
                    lastName: user.lastName,
                    username: user.username
                })
                res.status(200).json({
                    message: 'done',
                    data: {
                        user:{
                            id: user._id,
                        firstName: user.firstName,
                        lastName: user.lastName,
                        username: user.username
                        },
                        accessToken: token
                    }
                })
            } else {
                console.error('[Error] username and password invalid')
                res.status(401).json({
                    message: 'username and password invalid',
                    data: null 
                })
            }

        } catch (error) {
            console.error(error)
            res.status(500).json({
                message: error,
                data: null
            })
        }
    }
}

module.exports = authController