const userModel = require('../schema/user.schema')
const statusEnum = require('../../../commons/status.enum')

const userService = {
    getAll () {
        return userModel.find({ status: statusEnum.ACTIVE })
    },

    getOne (id) {
        return userModel.findOne({ _id: id,status: statusEnum.ACTIVE })
    },
    findOneByQuery (query) {
        return userModel.findOne({...query})
    },

    create (payload) {
        return userModel(payload).save()
    },
    update (id, payload) {
        return userModel.findOneAndUpdate({ _id: id,status: statusEnum.ACTIVE }, payload)
    },
    deleteOne (id) {
        return userModel.findByIdAndUpdate({ _id: id,status: statusEnum.ACTIVE }, { status: statusEnum.DELETED })
    }
}

module.exports = userService