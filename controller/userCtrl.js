const { generateToken } = require('../config/jwtToken');
const User = require('../models/userModel');
const asyncHandler = require("express-async-handler");
const validateMongoDbId = require("../utils/validateMongodbid");
const { generateRefreshToken } = require('../config/refreshToken');
const jwt = require("jsonwebtoken");

//Register
const createUser = asyncHandler(async(req, res) => {
    const email = req.body.email;
    const findUser = await User.findOne({email: email});
    if(!findUser){
        //Create a new User
        const newUser = await User.create(req.body);
        res.json({
            success:true,
            message:"Tạo người dùng thành công",
            data:{
                _id: newUser._id,
                email: newUser.email,
                fullname: newUser.fullname,
                role: newUser.role,
            }
        });
    }
    else{
        throw new Error("Người dùng đã tồn tại");
    }
});

const loginUserCtrl = asyncHandler(async(req, res) =>{
    const {email, password} = req.body;
    //check if user exists or not
    const findUser = await User.findOne({email});
    if(findUser && await findUser.isPasswordMatched(password)){
        const refreshToken = await generateRefreshToken(findUser?.id);
        const updateuser = await User.findByIdAndUpdate(findUser.id,{
            refreshToken: refreshToken,
        },{
            new:true,
        });
        res.cookie('refreshToken',refreshToken,{
            httpOnly:true,
            maxAge:72*60*60*1000,
        })
        res.json({
            success:true,
            message:"Đăng nhập thành công",
            data:{
                _id: findUser?._id,
                email: findUser?.email,
                fullname: findUser?.fullname,
                role: findUser?.role,
                token:generateToken(findUser?._id),
            }
    });
    }else{
        throw new Error("Thông tin không hợp lệ");
    }
});

//Handle Refresh token
const handleRefreshToken = asyncHandler(async(req,res) => {
    const cookie = req.cookies;
    if (!cookie?.refreshToken) {
        throw new Error("Không có Refresh Token trong cookie");
    }
    const refreshToken = cookie.refreshToken;
    const user = await User.findOne({refreshToken});
    if (!user) {
        throw new Error("Không Refresh Token trong DB hoặc không khớp");
    }
    jwt.verify(refreshToken,process.env.JWT_SECRET,(err,decoded)=>{
        if (err || user.id !== decoded.id) {
            throw new Error("Đã xảy ra lỗi với refresh token");
        }
        const accessToken = generateToken(user?._id);
        res.json({
            success:true,
            data:{
                _id: user?._id,
                email: user?.email,
                fullname: user?.fullname,
                role: user?.role,
                token:generateToken(user?._id),
            }
        });
    })
});

//Logout functionality
const logout = asyncHandler(async(req,res)=>{
    const cookie = req.cookies;
    if (!cookie?.refreshToken) {
        throw new Error("Không có Refresh Token trong cookie");
    }
    const refreshToken = cookie.refreshToken;
    const user = await User.findOne({refreshToken});
    if (!user) {
        res.clearCookie("refreshToken", {
            httpOnly:true,
            secure:true,
        });
        return res.status(204).json({ 
            success: true, 
            message: "Đăng xuất thành công" 
        });
    }
    await User.findOneAndUpdate({refreshToken},{
        refreshToken:"",
    });
    res.clearCookie("refreshToken",{
        httpOnly:true,
        secure:true,
    });
    return res.status(204).json({ 
        success: true, 
        message: "Đăng xuất thành công" 
    });
});

module.exports = {createUser, loginUserCtrl, handleRefreshToken,logout};