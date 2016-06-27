var express = require('express');
var app = express();
var path = require('path');
var bodyParser  = require('body-parser');
var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;
app.use(bodyParser());
app.use(require('cookie-parser')());
app.use(require('body-parser').urlencoded({ extended: true }));
app.use(require('express-session')({ secret: 'keyboard cat', resave: true, saveUninitialized: true }));
app.use(passport.initialize());
app.use(passport.session());
var User = require('../app/user'); // load up the user model
// expose this function to our app using module.exports
module.exports = function(passport)
{
    // ==============passport session setup ====================
    // passport needs ability to serialize and unserialize users out of session
    passport.serializeUser(function(user, done)
    {
        done(null, user.id);
    });
    passport.deserializeUser(function(id, done)
    {
        User.findById(id, function(err, user)
        {
            done(err, user);
        });
    });
    // ==============LOCAL SIGNUP ====================
    // by default, if there was no name, it would just be called 'local'
    passport.use('local-signup', new LocalStrategy(
        {
            // by default, local strategy uses username and password, we will override with email
            usernameField : 'email',
            firstnameField : 'firstname',
            lastnameField : 'lastname',
            ageField : 'age',
            mobileField : 'mobile',
            passwordField : 'password',
            passwordField : 'confirmpassword',
            passReqToCallback : true // allows us to pass back the entire request to the callback
        },
        function(req, email, password, done)
        {
            // User.findOne wont fire unless data is sent back
            process.nextTick(function()
            {
                // we are checking to see if the user trying to login already exists
                User.findOne({ 'email' :  email }, function(err, user)
                {
                    if (err) // if there are any errors, return the error
                        return done(err);
                    if (user) 
                        return done(null, false, req.flash('signupMessage', 'That email is already taken.'));
                    else
                    {
                        // if there is no user with that email
                        var newUser = new User(); // create the user
                        // set the user's local credentials
                        newUser.email = email;
                        // newUser.firstname = req.param(firstname);
                        newUser.password = newUser.generateHash(password);
                        newUser.save(function(err) // create the user
                        {
                            if (err)
                                throw err;
                            return done(null, newUser);
                        });
                    }
                });
            });
        }));
    // ==============LOCAL LOGIN ==================
    // we are using named strategies since we have one for login and one for signup
    passport.use('local-login', new LocalStrategy(
        {
            // by default, local strategy uses username and password, we will override with email
            usernameField : 'email',
            passwordField : 'password',
            passReqToCallback : true // allows us to pass back the entire request to the callback
        },
        function(req, email, password, done) // callback with email and password from our form
        {
            User.findOne({ 'email' :  email }, function(err, user)
            {
                // if there are any errors, return the error before anything else
                if (err)
                    return done(err);
                // if no user is found, return the message
                if (!user)
                    return done(null, false, req.flash('loginMessage', 'No user found.')); // req.flash is the way to set flashdata using connect-flash
                // if the user is found but the password is wrong
                if (!user.validPassword(password))
                    return done(null, false, req.flash('loginMessage', 'Oops! Wrong password.')); // create the loginMessage and save it to session as flashdata
                // all is well, return successful user
                return done(null, user);
            });
        }));
};
