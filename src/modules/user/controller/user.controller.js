const userService = require('../service/user.service')

const userController = {
    async getUsers (req, res) {
        try{

            const data = await userService.getAll()
            res.status(200).json({
                message: 'done',
                data
            })


        } catch (error){
            res.status(500).json({
                message: error,
                data: null
            })
        }
    },

    async getUserById (req, res) {
        try{
            const { id } = req.params
            const data = await userService.getOne(id)
            
            if(data) {
                res.status(200).json({
                    message: 'done',
                    data
                })
            } else {
                res.status(404).json({
                    message: 'not found',
                    data: null
                })
            }
            
            
        }catch (error) {
            res.status(500).json({
                message: error,
                data: null
            })
        }
    },
    async createUser (req, res) {
        try{
            const payload = req.body
            const data = await userService.create( payload )
            res.status(201).json({
                message: 'done',
                data
            })

        } catch (error){
            res.status(500).json({
                message: error,
                data: null
            })
        }
    },
    async updataUserById (req, res) {
        try{
            const { id } = req.params
            const payload = req.body
            const data = await userService.update(id,payload)
            
            if(data) {
                const updateUser = await userService.getOne(id)
                res.status(200).json({
                    message: 'done',
                    data: updateUser
                })
            } else {
                res.status(404).json({
                    message: 'not found',
                    data: null
                })
            }
            
            
        }catch (error) {
            res.status(500).json({
                message: error,
                data: null
            })
        }
    },
    async deleteUserById (req, res) {
        try{
            const { id } = req.params
            const data = await userService.deleteOne(id)
            
            if(data) {
                res.status(200).json({
                    message: 'done',
                    data
                })
            } else {
                res.status(404).json({
                    message: 'not found',
                    data: null
                })
            }
            
            
        }catch (error) {
            res.status(500).json({
                message: error,
                data: null
            })
        }
    }
}

module.exports = userController