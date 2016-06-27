// load the things we need
var mongoose = require('mongoose');
var bcrypt   = require('bcrypt-nodejs');
// define the schema for our user model
var userSchema;
userSchema = mongoose.Schema(
    {
            email: String,
            firstname: String,
            lastname: String,
            age: Number,
            mobile: Number,
            password: String,
            confirmpassword: String
    });
// generating a hash
userSchema.methods.generateHash = function(password)
 {
    return bcrypt.hashSync(password, bcrypt.genSaltSync(8), null);
 };
// checking if password is valid
userSchema.methods.validPassword = function(password)
{
    return bcrypt.compareSync(password, this.password);
};
// create the model for users and expose it to our app
module.exports = mongoose.model('User', userSchema);