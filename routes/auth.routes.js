const router = require("express").Router()
const authController = require("./../controllers/auth.controller")

router
    .post("/register-admin", authController.registerAdmin)
    .post("/login", authController.loginAdmin)
    .post("/verify-otp-admin", authController.verifyOTP)
    .post("/logout-admin", authController.logoutAdmin)


    .post("/login-mobile-user", authController.loginUser)
    .post("/register-mobile-user", authController.registerUser)
    .post("/logout-mobile-user", authController.logoutUser)



module.exports = router