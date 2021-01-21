const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const saltRounds = 10;
const jwt = require('jsonwebtoken');

const userSchema = mongoose.Schema({
    name : {
        type : String,
        maxLength : 50,
    },
    email : {
        type : String,
        trim : true
    },
    password : {
        type : String,
        minLength : 5,
    },
    role : {
        type : Number,
        default : 0
    },
    image : String,
    token : {
        type : String
    },
    tokenExp : {
        type : Number
    }
})

userSchema.pre('save', function(next){
    var user = this;
    if (user.isModified('password')) {
        bcrypt.genSalt(saltRounds, function(err, salt) { // <-- 어쩌구 저쩌구 하는 문법은 싸이트에서 가져오는 거임
            bcrypt.hash(user.password, salt, function(err, hash) {
                if (err) return next(err);
                user.password = hash
                next();
            });
        });
    } else {
        next();
    }
})

userSchema.methods.comparePassword = function(plainPasword, cb) {
    bcrypt.compare(plainPasword, this.password, function(err, isMatch) {
        if (err) return cb(err);
        cb(null, isMatch)
    })
}

userSchema.methods.generateToken = function(cb) {
    var user = this;
    const token = jwt.sign(user._id.toHexString(), 'secretToken');
    user.token = token;
    user.save(function(err, user){
        if (err) return cb(err);
        cb(null, user);
    })
}

userSchema.statics.findByToken = function(token, cb) {
    var user = this;
    jwt.verify(token, 'secretToken', function(err, decoded){
        user.findOne({"_id":decoded, "token":token}, function(err, user){
            if (err) return cb(err);
            cb(null, user)
        })
    })
}

const User = mongoose.model('User', userSchema)
module.exports = {User};
