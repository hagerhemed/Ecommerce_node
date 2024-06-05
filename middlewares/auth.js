const jwt = require('jsonwebtoken')
let {promisify} = require('util')

async function auth(req,res,next){
    let{authorization}=req.headers
    if(! authorization){
        return res.status(401).json({message:'unauthenticated,you must login first'})
    }
       let decoded=await promisify(jwt.verify)(authorization,process.env.secret)
       console.log(decoded)
       req.id=decoded.userId
       req.role=decoded.role
    next()
}

function restrictTo(...roles){
    return(req,res,next)=>{
        if(!roles.includes(req.role)){
            return res.status(403).json({message:'you dont have permission to perform this action'})
        }
        next()
    }
}

module.exports={auth,restrictTo}