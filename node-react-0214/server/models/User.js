const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const saltRounds = 10;
const jwt =require('jsonwebtoken');

const userSchema = mongoose.Schema({
    name: {
        type:String,
        maxlength:50
    },
    email: {
        type:String,
        trim:true,
    },
    password: {
        type: String,
        minlength: 5
    },
    lastname: {
        type:String,
        maxlength:50
    },
    role: {
        type:Number,
        default: 0
    },
    image: String,
    token: {
        type: String
    },
    tokenExp: {
        type: Number
    }
})

userSchema.pre('save', function(next){
    var user = this;

    if(user.isModified('password')){
         //비밀번호를 암호화 시킨다.
        bcrypt.genSalt(saltRounds, function(err, salt) {
            if(err) return next(err)
            bcrypt.hash(user.password, salt, function(err, hash) {
                if(err) return next(err)
                user.password = hash
                next()
                // Store hash in your password DB.
            });
        });
    }else{
        next();
    }
})
userSchema.methods.comparePassword = function(plainPassword,cb){
    //plainPassword dnflskfk12 암호화된 비밀번호 $2b$10$YnEoO/2w9kUxmteibwd9HeLC5chv2D1ooqWjlHjXGiWxujw8d9HMW
    bcrypt.compare(plainPassword, this.password, function(err, isMatch){
        if(err) return cb(err)
        cb(null, isMatch)
    })
}
userSchema.methods.generateToken = function(cb){
    var user = this;
    //jsonwebtoken이용해서 토큰 생성
    var token = jwt.sign(user._id.toHexString(),'secretToken')
   
    user.token = token
    user.save(function(err, user){
        if(err) return cb(err)
        cb(null, user)
    })
}
userSchema.statics.findByToken = function(token,cb) {
    var user = this;
    // user._id + '' = token
    //토큰을 decoded
    jwt.verify(token, 'secretToken', function(err, decoded){
        //유저아이디를 이용해서 유저를 찾은다음
        ///클라이언트에서 가져온 토큰과 DB에 보관된 토큰이 일치하는지 확인
        user.findOne({"_id": decoded,"token":token}, function(err, user){
            if(err) return cb(err);
            cb(null, user)

        })
    })
}

const User = mongoose.model('User',userSchema)

module.exports ={ User }