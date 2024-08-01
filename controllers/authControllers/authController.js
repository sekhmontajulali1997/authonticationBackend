import expressAsyncHandler from "express-async-handler";
import { PrismaClient } from "@prisma/client";
import bcrypt from "bcryptjs";

import jwt from "jsonwebtoken";
import { generateOTP } from "../../helpers/helpers.js";
import { AccountActivationEmail } from "../../sendEmail/EmailActivation.js";
const prisma = new PrismaClient();

// create authControllers
/**
 * @description: this getUser Controller
 * @route: /api/v1/user
 * @access: public
 * @method: get
 */

export const getUser = expressAsyncHandler(async (req, res) => {
  const allUsers = await prisma.User.findMany();

  res.status(200).json({ allUsers, message: " Here is all users" });
});
/**
 * @description: this createUser Controller
 * @route: /api/v1/user
 * @access: public
 * @method: post
 */

export const createUser = expressAsyncHandler(async (req, res) => {
  const { email, name, password, securityAnswer } = req.body;

  // validation
  if (!email || !name || !password || !securityAnswer) {
    return res.status(400).json({ message: "All fields are Required" });
  }

  // check Email Already Exists Or Not
  const existingEmailUser = await prisma.user.findFirst({
    where: { email },
  });
  if (existingEmailUser) {
    return res.status(400).json({ message: "This Email Already Exists" });
  }

  // generate OTP
  const OTP = generateOTP();

  // hash password
  const hashPasssword = await bcrypt.hash(password, 10);

  const createUser = await prisma.User.create({
    data: { email, name, password: hashPasssword, securityAnswer, otp: OTP },
  });

  if (createUser) {
    // send Otp On email
    await AccountActivationEmail(email, { code: OTP });

    // create token for authontication
    const authonticationToken = await jwt.sign(
      { email },
      process.env.AUTHONTICATION_TOKEN_SECRET,
      {
        expiresIn: "365d",
      }
    );


    const isProduction = process.env.APP_MODE === 'production';

    res.cookie("authonticationToken", authonticationToken, {
      httpOnly: true,
      secure: isProduction, // Set to true in production
      path: "/",
      sameSite: isProduction ? "Lax" : "Strict", // Adjust based on cross-site needs
      maxAge: 1000 * 60 * 60 * 24 * 365, // 1 year
    });



    // res.cookie("authonticationToken", authonticationToken,{
    //   httpOnly: true,
    //   secure: process.env.APP_MODE === "development" ? true : false,
    //   path: "/",
    //   sameSite: "strict",
    //   maxAge: 1000 * 60 * 60 * 24 * 365,
    // });
    // remove importent data
    delete createUser.password;
    delete createUser.securityAnswer;
    delete createUser.otp;
  }

  res.status(201).json({ createUser, message: "User Created" });
});

/**
 * @description: this is Email verify By Otp Controller
 * @route: /api/v1/user/verify_email_by_otp
 * @access: public
 * @method: post
 */

export const verifyEmailByOtp = expressAsyncHandler(async (req, res) => {
  const { otp } = req.body;
  // validation
  if (!otp) {
    return res.status(400).json({ message: "Please Enter OTP" });
  }

  let verifyEmailByOtpUser = null;
  let ForgetPasswordByOtp = null;

  //this is for accountVerify
  // get token for new user
  const authorizedToken = req.cookies.authonticationToken;
  if (authorizedToken) {
    // verify  token
    const verifyToken = await jwt.verify(
      authorizedToken,
      process.env.AUTHONTICATION_TOKEN_SECRET,
      expressAsyncHandler(async (err, decode) => {
        if (err) {
          res.status(400).json({
            message: "Expire OTP",
          });
        }

        if (decode.email) {
          verifyEmailByOtpUser = await prisma.User.findFirst({
            where: {
              email: decode.email,
            },
          });
        }
      })
    );

    if (otp !== verifyEmailByOtpUser.otp) {
      return res.status(400).json({ message: "Wrong Otp" });
    }

    // update user data

    if (verifyEmailByOtpUser) {
      await prisma.User.updateMany({
        where: {
          email: verifyEmailByOtpUser.email,
        },
        data: {
          otp: null,
          isActivate: true,
        },
      });
    }

    // get updated data
    const getUpdatedDataAccountVerify = await prisma.User.findFirst({
      where: {
        email: verifyEmailByOtpUser.email,
      },
    });
    // remove importent data
    delete getUpdatedDataAccountVerify.password;
    delete getUpdatedDataAccountVerify.securityAnswer;
    delete getUpdatedDataAccountVerify.otp;

    // clear cokie
    res.clearCookie("authonticationToken");
    res
      .status(201)
      .json({ getUpdatedDataAccountVerify, message: "verify success" });
  } else {
    //this is for forget Password
    // get token for forget password
    const forgetPasswordToken = req.cookies.forgetPasswordToken;
    if (forgetPasswordToken) {
      // verify  token
      const verifyToken = await jwt.verify(
        forgetPasswordToken,
        process.env.forgetPassword_Token_SECRET,
        expressAsyncHandler(async (err, decode) => {
          if (err) {
            res.status(400).json({
              message: "Expire OTP",
            });
          }

          if (decode.email) {
            ForgetPasswordByOtp = await prisma.User.findFirst({
              where: {
                email: decode.email,
              },
            });
          }
        })
      );

      if (otp !== ForgetPasswordByOtp.otp) {
        return res.status(400).json({ message: "Wrong Otp" });
      }

      // update user data

      if (ForgetPasswordByOtp) {
        await prisma.User.updateMany({
          where: {
            email: ForgetPasswordByOtp.email,
          },
          data: {
            otp: null,
            isActivate: true,
          },
        });
      }

      // get updated data
      const getUpdatedDataForgetPassword = await prisma.User.findFirst({
        where: {
          email: ForgetPasswordByOtp.email,
        },
      });
      // remove importent data
      delete getUpdatedDataForgetPassword.password;
      delete getUpdatedDataForgetPassword.securityAnswer;
      delete getUpdatedDataForgetPassword.otp;

      res.status(201).json({
        getUpdatedDataForgetPassword,
        message: "Set Your New Password",
      });
    }
  }
});
/**
 * @description: this is Email verify By ResendOtp Controller
 * @route: /api/v1/user/resend_otp
 * @access: public
 * @method: post
 */

export const ResendOtp = expressAsyncHandler(async (req, res) => {
  // get valid user

  // this is for  getValidUserAccountVerify
  let getValidUserAccountVerify = null;
  let getValidUserForgetPassword = null;
  // get token for new user
  const authorizedToken = req.cookies.authonticationToken;

  if (authorizedToken) {
    // verify  token
    const verifyToken = await jwt.verify(
      authorizedToken,
      process.env.AUTHONTICATION_TOKEN_SECRET,
      expressAsyncHandler(async (err, decode) => {
        if (err) {
          res.status(400).json({
            message: "invalid ",
          });
        }

        if (decode.email) {
          getValidUserAccountVerify = await prisma.User.findFirst({
            where: {
              email: decode.email,
            },
          });
        }
      })
    );

    // generate OTP
    const OTP = generateOTP();

    // update user data

    if (getValidUserAccountVerify) {
      await prisma.User.updateMany({
        where: {
          email: getValidUserAccountVerify.email,
        },
        data: {
          otp: OTP,
        },
      });

      // send Otp On email
      await AccountActivationEmail(getValidUserAccountVerify.email, {
        code: OTP,
      });
    }

    res
      .status(201)
      .json({ message: " Resend otp  success for Account verify" });
  } else {
    // this is for  getValidUserForgetPassword
    // get token for forget password
    const forgetPasswordToken = req.cookies.forgetPasswordToken;
    // verify  token
    const verifyToken = await jwt.verify(
      forgetPasswordToken,
      process.env.forgetPassword_Token_SECRET,
      expressAsyncHandler(async (err, decode) => {
        if (err) {
          res.status(400).json({
            message: "Expire OTP,",
          });
        }

        if (decode.email) {
          getValidUserForgetPassword = await prisma.User.findFirst({
            where: {
              email: decode.email,
            },
          });
        }
      })
    );

    // generate OTP
    const OTP = generateOTP();

    // update user data

    if (getValidUserForgetPassword) {
      await prisma.User.updateMany({
        where: {
          email: getValidUserForgetPassword.email,
        },
        data: {
          otp: OTP,
        },
      });

      // send Otp On email
      await AccountActivationEmail(getValidUserForgetPassword.email, {
        code: OTP,
      });
    }

    res
      .status(201)
      .json({ message: " Resend otp  success for forget Password" });
  }
});

/**
 * @description: this is forget Password  Controller
 * @route: /api/v1/user/forget_password
 * @access: pulic
 * @method: post
 */

export const ForgetPasswordByOtp = expressAsyncHandler(async (req, res) => {
  const { email } = req.body;
  console.log(email);
  // validation
  if (!email) {
    return res.status(400).json({ message: " Email Required" });
  }

  // check Email Already Exists Or Not
  const existingEmailUser = await prisma.User.findFirst({
    where: { email },
  });

  if (existingEmailUser) {
    // generate OTP
    const OTP = generateOTP();

    // update user data

    await prisma.User.updateMany({
      where: {
        email: existingEmailUser.email,
      },
      data: {
        otp: OTP,
      },
    });

    // send Otp On email
    await AccountActivationEmail(existingEmailUser.email, { code: OTP });

    // create token for authontication
    const forgetPasswordToken = await jwt.sign(
      { email },
      process.env.forgetPassword_Token_SECRET,
      {
        expiresIn: "365d",
      }
    );
    const isProduction = process.env.APP_MODE === 'production';

    res.cookie("forgetPasswordToken", forgetPasswordToken, {
      httpOnly: true,
      secure: isProduction, // Set to true in production
      path: "/",
      sameSite: isProduction ? "Lax" : "Strict", // Adjust based on cross-site needs
      maxAge: 1000 * 60 * 60 * 24 * 365, // 1 year
    });
  } else {
    return res.status(400).json({ message: "This Email Not Exists" });
  }

  res.status(200).json({ message: "Verify your Email" });
});

/**
 * @description: this setNewPassword  Controller
 * @route: /api/v1/user/logout
 * @access: public
 * @method: post
 */

export const setNewPassword = expressAsyncHandler(async (req, res) => {
  const { newPassword } = req.body;
  let ForgetPasswordByOtp = null;
  // hash password
  const hashPasssword = await bcrypt.hash(newPassword, 10);

  const forgetPasswordToken = req.cookies.forgetPasswordToken;
  if (forgetPasswordToken) {
    // verify  token
    const verifyToken = await jwt.verify(
      forgetPasswordToken,
      process.env.forgetPassword_Token_SECRET,
      expressAsyncHandler(async (err, decode) => {
        if (err) {
          res.status(400).json({
            message: "Expire OTP, Please Register Again With Same Email",
          });
        }

        if (decode.email) {
          ForgetPasswordByOtp = await prisma.User.findFirst({
            where: {
              email: decode.email,
            },
          });
        }
      })
    );

    // update user data

    if (ForgetPasswordByOtp) {
      await prisma.User.updateMany({
        where: {
          email: ForgetPasswordByOtp.email,
        },
        data: {
          password: hashPasssword,
        },
      });
    }

    // clear cokie
    res.clearCookie("forgetPasswordToken");
    res
      .status(201)
      .json({ message: "New Password update successfull, please Login" });
  }

  res.status(200).json({ message: " Password Change SuccessFull" });
});

/**
 * @description: this UserLogin  Controller
 * @route: /api/v1/user/login
 * @access: public
 * @method: post
 */

export const loginUser = expressAsyncHandler(async (req, res) => {
  const { email, password } = req.body;
  // validation
  if (!email || !password) {
    return res.status(400).json({ message: "All fields are Required" });
  }

  // check Email  Exists Or Not

  const ValidUser = await prisma.User.findFirst({
    where: {
      email,
    },
  });
  if (!ValidUser) {
    return res.status(400).json({ message: "This Email Not Exists" });
  }

  // check password

  const validPassword = await bcrypt.compare(password, ValidUser.password);

  if (!validPassword) {
    return res.status(400).json({ message: " Wrong Password" });
  }
  // isActivate user true or false
  if (ValidUser.isActivate === false) {
    return res
      .status(400)
      .json({ message: " please verify your account by otp" });
  }

  // create Authorization Token

  const Authorization = await jwt.sign(
    { email },
    process.env.AUTHORIZATION_TOKEN_SECRET,
    {
      expiresIn: "365d",
    }
  );

  // remove importent data

  if (ValidUser) {
    delete ValidUser.password;
    delete ValidUser.securityAnswer;
    delete ValidUser.otp;
  }

  res.cookie("Authorization", Authorization, {
    httpOnly: true,
    secure: process.env.APP_MODE === "development" ? true : false,
    path: "/",
    sameSite: "strict",
    maxAge: 1000 * 60 * 60 * 24 * 365,
  });

  res.status(201).json({ ValidUser, message: "Login SuccessFull" });
});

/**
 * @description: this is authorize user (me)  Controller
 * @route: /api/v1/user/me
 * @access: private
 * @method: get
 */

export const LoggedUser = expressAsyncHandler(async (req, res) => {
  if (!req.user) {
    return res.status(400).json({ message: "login user data not found" });
  }

  res
    .status(200)
    .json({ loggedUser: req.user, message: " this is Logged User" });
});

/**
 * @description: this UserLogOut  Controller
 * @route: /api/v1/user/logout
 * @access: private
 * @method: post
 */

export const logoutUser = expressAsyncHandler(async (req, res) => {
  // crear cookie

  res.clearCookie("Authorization");
  res.status(200).json({ message: " Logout SuccessFull" });
});
