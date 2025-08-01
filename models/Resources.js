const mongoose=require('mongoose');
const {Schema,model}=mongoose;


const ResourceSchema= new Schema({
     title:String,
     cloudpath:String,
     summary:String,
     content:String,
     cover:String,
     website:String,
     author:{type:Schema.Types.ObjectId,ref:'User'}
},{
    timestamps:true,
})

const ResourceModel=model('Resources',ResourceSchema,'Resources');
module.exports=ResourceModel;