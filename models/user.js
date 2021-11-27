const mongoose = require('mongoose');

/*
 * Creating columns for the table.
 */
const UserSchema = new mongoose.Schema({
    username : {
        type : String,
        required : true
    },
    password : {
        type : String,
        required : true
    }
});


/*
 * The mongoose.model() compiles the model for us.
 */
const User = mongoose.model('users', UserSchema);


// Exporting the User.
module.exports = User;