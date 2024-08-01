
import express from "express";
import { getUser,createUser,loginUser,logoutUser ,LoggedUser,verifyEmailByOtp, ResendOtp, ForgetPasswordByOtp,setNewPassword} from "../../controllers/authControllers/authController.js";
import verifyToken from "../../middleware/verifyToken .js";

// init router
const authRouters = express.Router();


// create authRouters

authRouters.get("/", getUser);
authRouters.post("/", createUser);
authRouters.post("/verify_email_by_otp", verifyEmailByOtp);
authRouters.get("/resend_otp", ResendOtp);
authRouters.post("/login", loginUser);
authRouters.post("/logout", logoutUser);
authRouters.post("/forget_password", ForgetPasswordByOtp);
authRouters.post("/set_new_passwoord", setNewPassword);
authRouters.get("/me",verifyToken, LoggedUser);

// export authRouters
export default authRouters