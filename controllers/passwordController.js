const asyncHandler = require("express-async-handler")
const {User} = require("../models/user")
const jwt = require("jsonwebtoken")
const bcrypt = require("bcryptjs")
const nodemailer=require("nodemailer")

module.exports.getForgotPasswordView= asyncHandler((req,res) =>{
    res.render('forgot-password')
})

module.exports.sendForgotPasswordLink= asyncHandler(async (req,res) =>{
    const user = await User.findOne({email: req.body.email})
    if(!user) {
        return res.status(400).json('The user not found');
    }

    const secret = process.env.JWT_SECRET_KEY + user.password;
        const token = jwt.sign(
            {
                email: user.email,
                id:user.id,
            },
            secret,
            {expiresIn : '1d'}
        )
        const link =`http://localhost:4021/password/reset-password/${user._id}/${token}`;

        const transporter = nodemailer.createTransport({
                service: 'gmail',
                auth: {
                  user:process.env.USER_EMAIL,
                  pass:process.env.USER_PASS
                }
              });
            
              const mailOptions = {
                from:process.env.USER_EMAIL,
                to: user.email,
                subject: 'Reset Password Link',
                html:`<div>
                <h4>click on the link to reset password</h4>
                <p>${link}</p>
                </div>`
              };
            
              transporter.sendMail(mailOptions,function(error,success){
                if(error){
                    console.log(error)
                }else{
                    console.log("Email sent: " + success.response)
                }
              });

              res.send("link-send")
            
})



module.exports.getResetPasswordView= asyncHandler(async (req,res) =>{
    const user = await User.findById(req.params.userId)
    if(!user) {
        return res.status(400).json('The user not found');
    }

    const secret = process.env.JWT_SECRET_KEY + user.password;
       
    try{
        jwt.verify(req.params.token, secret)
        res.render('reset-password', {email: user.email})

    }catch(error){
        console.log(error)
        res.json({message:"Error"})

    }
       
})


module.exports.resetThePassword= asyncHandler(async (req,res) =>{
    const user = await User.findById(req.params.userId)
    if(!user) {
        return res.status(400).json('The user not found');
    }

    const secret = process.env.JWT_SECRET_KEY + user.password;
       
    try{
        jwt.verify(req.params.token, secret)
        const salt = await bcrypt.genSalt(10)
        req.body.password= await bcrypt.hash(req.body.password,salt)
        user.password=req.body.password

        await user.save()
        res.render('success-password')

    }catch(error){
        console.log(error)
        res.json({message:"Error"})

    }
       
})