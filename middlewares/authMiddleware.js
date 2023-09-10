const User = require('../models/userModel');
const jwt = require("jsonwebtoken");
const asyncHandler = require("express-async-handler");

const authMiddleware = asyncHandler(async(req,res,next)=>{
    let token;
    if (req?.headers?.authorization?.startsWith('Bearer')) {
        token = req.headers.authorization.split(" ")[1];
        try {
            if (token) {
                const decoded = jwt.verify(token, process.env.JWT_SECRET);
                const user = await User.findById(decoded?.id);
                req.user = user;
                next();
            }
        } catch (error) {
            res.json({
                message: 'Token hết hạn hoặc không chính xác',
                success: false
            });
        }
    } else {
        res.json({
            message: 'Không đủ quyền truy cập',
            success: false
        });
    }
});

module.exports = {authMiddleware};