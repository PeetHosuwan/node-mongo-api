const mongoose = require('mongoose')
const { Schema } = mongoose
const statusEnum = require('../../../commons/status.enum')

const userSchema = new Schema({
    firstName: {
        type: String,
        default: ''
    },
    lastName: {
        type: String,
        default: ''
    },
    tel: {
        type: String,
        default: ''
    },
    username: {
        type: String,
        default: ''
    },
    password: {
        type: String,
        default: ''
    },
    status: {
        type: String,
        default: statusEnum.ACTIVE
    }
}, { timestamps: true })

const userModel = mongoose.model('user', userSchema)

module.exports = userModel