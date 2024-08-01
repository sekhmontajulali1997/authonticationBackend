import jwt from "jsonwebtoken";
import expressAsyncHandler from "express-async-handler";
import { PrismaClient } from "@prisma/client";
const prisma = new PrismaClient();

// create verify token

const verifyToken = (req, res, next) => {
  // get token

  const token = req.cookies.Authorization;

  // token validation
  if (!token) {
    return res.status(400).json({ message: "Unauthorized user" });
  }

  // store valid user data
  let me = null;
  // verify token

  jwt.verify(
    token,
    process.env.AUTHORIZATION_TOKEN_SECRET,
    expressAsyncHandler(async (err, decode) => {
      if (err) {
        return res.status(400).json({ message: " invalid Token" });
      }

      if (decode.email) {
        me = await prisma.User.findFirst({
          where: {
            email: decode.email,
          },
        });
      }

      // remove sensitive data

      if (me) {
        delete me.password;
        delete me.securityAnswer;
        delete me.otp;

        // set data 
        req.user = me;
       return next();
      }
    })
  );


};

// export verify token

export default verifyToken;
