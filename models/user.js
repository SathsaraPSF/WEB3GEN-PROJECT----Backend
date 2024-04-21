const mongoose = require('mongoose');
const { Schema } = mongoose;

const userSchema = new Schema({
    type: {
        type: String,
    },
    status: {
        type: String,
        required: true
    },
    basic_info: {
        first_name: String,
        last_name: String,
        dob: String, 
        gender: String
    },
    contact_info: {
        mobile_number: String,
        email: String
    },
    auth_info: {
        password: String
    }
});

const UserModel = mongoose.model('User', userSchema);

module.exports = UserModel;
