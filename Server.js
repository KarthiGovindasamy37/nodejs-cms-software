const express=require("express")
const app=express()
const cors=require("cors")
const mongodb=require("mongodb")
const mongoclient=mongodb.MongoClient
const dotenv=require("dotenv").config()
const bcrypt=require("bcryptjs")
const jwt=require("jsonwebtoken")
const nodemailer=require("nodemailer")
const razorpay=require("razorpay")


const URL=process.env.URL
const DB=process.env.DB
const SECRETKEY=process.env.SECRET
const USER=process.env.USER
const PASS=process.env.PASS
const RAZORPAY_KEY=process.env.RAZORPAY_KEY
const RAZORPAY_SECRET=process.env.RAZORPAY_SECRET

let instance= new razorpay({
key_id:RAZORPAY_KEY,
key_secret:RAZORPAY_SECRET
});

app.use(express.json())
app.use(cors());

    let forgotMail=async(res,temp,mail)=>{
        try {
            let transporter=nodemailer.createTransport({
                host:"smtp.gmail.com",
                port:587,
                secure:false,
                auth:{
                    user:USER,
                    pass: PASS
            }
            });

            let info=await transporter.sendMail({
                from:USER,
                to:mail,
                subject:"Temporary password from MySite.com",
                html:`<h1>Your temporary password is ${temp}</h1>
                      <h3>Copy the above password and use it by clicking the temporary password link in the forgot password page</h3>`
            });
            res.json({message:`mail sent to ${mail}`})
        } catch (error) {
            res.status(500).json({message:"Sorry something went wrong,try again"})
        }
    }

let Authorization = (req,res,next) =>{ 
    try {
        if(req.headers.authorization){
            let decode = jwt.verify(req.headers.authorization,SECRETKEY)
            next()
        }else{
            res.status(401).json({message:"Please login your account"})
        }
    } catch (error) {
        res.status(440).json({message:"Session expired please login again"})
    }
}


app.post("/register",async(req,res)=>{
    try {
        let connection=await mongoclient.connect(URL);

        let db=connection.db(DB);

        let user=await db.collection("users").findOne({email:req.body.email});

        if(!user){
            let salt=await bcrypt.genSalt(10);
            let hashedPassword=await bcrypt.hash(req.body.password,salt);

            req.body.password=hashedPassword

            let insertUser=await db.collection("users").insertOne(req.body);

            if(insertUser.acknowledged){
                res.json({message:"Account created successfully"})
            }
        }else{
            res.status(409).json({message:"Email id already exists"})
        }
    } catch (error) {
       res.status(500) .json({message:"Sorry something went wrong,try again"})
    }
})

app.post("/login",async(req,res)=>{
    try {
    
        let connection=await mongoclient.connect(URL);

        let db=connection.db(DB);

        let user=await db.collection("users").findOne({email:req.body.email});

        if(user){
            let compare=await bcrypt.compare(req.body.password,user.password);

            if(compare){
                
                let token=jwt.sign({_id:user._id},SECRETKEY,{expiresIn:"2m"})
            let {name,email}=user
            let userDetail={
                name,
                email
            }
                res.json({token,userDetail})
            }else{
                res.status(401).json({message:"Email id or password is incorrect"})  
            }

        }else{
            res.status(401).json({message:"Email id or password is incorrect"}) 
        }
        
    } catch (error) {
       res.status(500) .json({message:"Sorry something went wrong,try again"})
    }
})

app.post("/forgot",async(req,res)=>{
    try {
        let connection=await mongoclient.connect(URL);

        let db=connection.db(DB);

        let user=await db.collection("users").findOne({email:req.body.email});

        if(user){
            
            let temp=Math.random().toString(36).slice(-8);
            let mail=req.body.email

            await db.collection("users").findOneAndUpdate({email:mail},{$set:{temporaryPass:temp}})
            
            forgotMail(res,temp,mail)

        }else{
            res.status(401).json({message:"Email id is not valid"})
        }
        
    } catch (error) {
        res.status(500) .json({message:"Sorry something went wrong,try again"})
    }
})

app.post("/temppassword",async(req,res)=>{
    
    try {
        let connection=await mongoclient.connect(URL);

        let db=connection.db(DB);

        let user=await db.collection("users").findOne({email:req.body.email});

        if(user){
            if(req.body.password===user.temporaryPass){

                await db.collection("users").findOneAndUpdate({email:req.body.email},{$unset:{temporaryPass:""}})

                res.json({message:"Please change your password immediately"})
            }else{
                res.status(401).json({message:"Email id or password is incorrect"})
            }
        }else{
            res.status(401).json({message:"Email id or password is incorrect"})
        }

    } catch (error) {
        res.status(500).json({message:"Sorry something went wrong,try again"}) 
    }
})

app.post("/passwordchange",async(req,res)=>{
    try {
        
        let connection=await mongoclient.connect(URL);

        let db=connection.db(DB);

        let user=await db.collection("users").findOne({email:req.body.email});

        if(user){
            let salt=await bcrypt.genSalt(10);

            let hashedpassword=await bcrypt.hash(req.body.password,salt);

            await db.collection("users").findOneAndUpdate({email:req.body.email},{$set:{password:hashedpassword}});

            res.json({message:"Password updated successfully"})
        }else{
            res.status(401).json({message:"Email id is not valid"})
        }
        
    } catch (error) {
        res.status(500).json({message:"Sorry something went wrong,try again"}) 
    }
});

app.post("/razorpaypayment",Authorization,async(req,res)=>{
    try {
        let amount=req.body.price * 100;
        let currency="INR";

        let options={
            amount,
            currency,
            receipt:Math.random().toString(36).slice(-7)
        };

        let order=await instance.orders.create(options)
        
        res.json({
            id:order.id,
            currency:order.currency,
            amount:order.amount
        })
    } catch (error) {
        res.status(500).json({message:"Sorry something went wrong,try again"})
    }
})

app.post("/authorize",Authorization,(req,res)=>{
    res.json({message:"Proceed"})
})
app.listen(process.env.PORT || 3001);