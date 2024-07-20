const router = require("express").Router()
const authController = require("./../controllers/auth.controller")

router
    .post("/register-admin", authController.registerAdmin)
    .post("/login", authController.loginAdmin)
    .post("/verify-otp-admin", authController.verifyOTP)
    .post("/logout-admin", authController.logoutAdmin)



module.exports = router