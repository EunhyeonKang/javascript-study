const express = require('express')
const app = express()
const config = require('./config/key');
const cookieParser = require('cookie-parser');
const { auth } = require('./middleware/auth');
const { User } = require('./models/User');
const bodyParser =require('body-parser');


//application/x-www-form-urlencoded
app.use(bodyParser.urlencoded({extended: true}));
//application/json
app.use(bodyParser.json());
app.use(cookieParser());

const mongoose = require('mongoose')
mongoose.connect(config.mongoURI,{
    useNewUrlParser:true, useUnifiedTopology: true, useCreateIndex:true, useFindAndModify:false
}).then(() =>console.log('MongoDB Connected...'))
  .catch(err => console.log(err))

app.get('/', (req, res) => res.send('Hello World! 강은현이다'))


app.get('/api/hello', (req,res) => {
  res.send("안녕하세요~")
})


app.post('/api/users/register', (req,res) =>{
  //회원가입할때 필요한 정보들을 클라이언트에서 가져오면
  //그것을 데이터베이스에 넣어줌

  const user = new User(req.body)

  user.save((err, userInfo) => {
      if(err) return res.json({ success: false, err})
      return res.status(200).json({
        success:true
      })
  })
})

app.post('/api/users/login',(req,res)=>{
  //요청된 이메일을 데이터베이스에 있는지 확인
  
  User.findOne({email:req.body.email},(err,user)=>{
    if(!user){
      return res.json({
        loginSuccess:false,
        message:"제공된 이메일에 해당하는 유저가 없습니다."
      })
    }
    user.comparePassword(req.body.password,(err,isMatch)=>{
      if(!isMatch)
        return res.json({loginSuccess:false, message:"비밀번호가 틀렸습니다."})
      //비밀번호까지 맞다면 토큰을 생성하기
      user.generateToken((err, user)=>{
          if(err) return res.status(400).send(err);

          //token을 저장한다 어디에?쿠키, 로컬스토리지 여러군데...
              res.cookie("x_auth",user.token)
              .status(200)
              .json({loginSuccess:true, userId:user._id})   
      })
    })
  })
  //요청된 이메일이 데이터베이스에 있다면 비밀번호가 맞는 비밀번호인지 확인
})
app.get('/api/users/auth',auth,(req,res)=>{
  //여기까지 미들웨어를 통과해왔다는 얘기는 Authentication이 true라는 말
  res.status(200).json({
    _id: req.user._id,
    isAdmin: req.user.role === 0 ? false :true,
    isAuth: true,
    email:req.user.email,
    name:req.user.name,
    lastname:req.user.lastname,
    role:req.user.role,
    image:req.user.image
  })
})
app.get('/api/users/logout', auth, (req, res) => {
  console.log('req.user', req.user)
  User.findOneAndUpdate({ _id: req.user._id},
  { token: "" }
  , (err, user) => {
    if (err) return res.json({ success:false, err })
    return res.status(200).send({
      success: true
    })
  })
})

const port = 3000

app.listen(port, () => console.log(`Example app listening on port ${port}!`))