const mongoose=require('mongoose');
const {Schema,model } =mongoose;
const UserSchema=new Schema({
    username:{type:String,required:true,min:6,unique:true},
    email:{type:String,required:true ,unique:true},
    password:{type:String,required:true},
    isAdmin:{type:Boolean,required:true,default:false}
});

const UserModel=model('User',UserSchema,'User');
module.exports=UserModel;