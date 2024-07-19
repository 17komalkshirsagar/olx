const asyncHandler = require("express-async-handler")
const validator = require("validator") //check krun sagte email password kiva other key nasel tr error
const Admin = require("../models/Admin")
const { checkEmpty } = require("../utils/checkEmpty")
// const bcrypt = require("bcrypt")
// const sendEmail = require("../utils/email")
// // const { OAuth2Client } = require("google-auth-library")
// const jwt = require("jsonwebtoken")
// const { nanoid } = require("nanoid")
exports.registerAdmin = asyncHandler(async (req, res) => {
    const { name, email, password } = req.body
    const { isError, error } = checkEmpty({ name, email, password })
    const hashPass = await bcrypt.hash(password, 10)
    if (isError) {
        return res.status(400).json({ messsage: "All Feilds Required", error })
    }
    res.json({ messsage: "Register Success" })
    if (!validator.isEmail(email)) {
        return res.status(400).json({ message: "Invalid email" })
    }
    const isFound = await Admin.findOne({ email })
    if (isFound) {
        return res.status(400).json({ message: "email already registered with us" })
    }
    await Admin.create({ name, email, password: hashPass })


})




exports.logout = asyncHandler(async (req, res) => {
    const { user } = req.body
    res.clearCookie(user)
    res.json({ message: "User Logout admin Success", result: user })

})

exports.loginAdmin = asyncHandler(async (req, res) => {
    const { name, email, password } = req.body
    const { isError, error } = checkEmpty({ name, email, password })
    if (isError) {
        return res.status(400).json({ messsage: "All Feilds Required", error })
    }
    if (!validator.isEmail(email)) {
        return res.status(400).json({ message: "Invalid email" })
    }
    const isFound = await Admin.findOne({ email })
    if (isFound) {
        return res.status(400).json({ message: "email already registered with us" })
    }
    const verify = await bcrypt.compare(password, isFound.password)

    if (!verify) {
        await sendEmail({
            to: process.env.FROM_EMAIL,
            subject: "Login Attempt Failed",
            message: 'Some one Tried to login'
        })
        return res.status(400).json({
            messsage: " Invalid Credentials",
            error: " Invalid Credentials"
        })
    }

})
exports.verifyOTPAdmin = asyncHandler(async (req, res) => {

    if (!verify) {
        await sendEmail({
            to: process.env.FROM_EMAIL,
            subject: "Login Attempt Failed",
            message: 'Some one Tried to login'
        })
        return res.status(400).json({
            messsage: " Invalid Credentials",
            error: " Invalid Credentials"
        })
    }
    const token = jwt.sign({ userId: isFound._id },
        process.env.JWT_KEY,
        { expiresIn: process.env.JWT_ADMIN_EXPIRE })

    res.cookie("admin", token, {
        httpOnly: true,
        maxAge: process.env.JWT_USER_EXPIRE,
        secure: process.env.NODE_ENV === "register"
    })

    res.json({
        message: "Login Success", result: {

            email: isFound.email,
            name: isFound.name,
            password: isFound.password,


        }
    })
    const OTP = nanoid(6)
    await Admin.findByIdAndUpdate(isFound._id, { otp: OTP, otpExpire: new Date(Date.now() + 1000 * 60 * 5) })

    await sendEmail({
        to: process.env.FROM_EMAIL,
        subject: "Login OTP",
        message: `Do not share This OTP with anyone :${OTP}`
    })
    res.json({ message: "OTP sent successfully" })
})