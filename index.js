import express from "express";
import colors from "colors";
import dotenv from "dotenv";
import errorHandler from "./errorHandler/errorHandler.js";
import authRouters from "./routers/authRouters/authRouters.js";
import cookieParser from "cookie-parser";
import cors from "cors";

// environment Varibale

dotenv.config();

const PORT = process.env.PORT || 6206;

// init express

const app = express();

// express middleware

app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());

const customCors = (req, res, next) => {
  const allowedOrigins = ["https://authontication-fontend.vercel.app"];
  const origin = req.headers.origin;

  if (allowedOrigins.includes(origin)) {
    res.header("Access-Control-Allow-Origin", origin);
    res.header("Access-Control-Allow-Credentials", true);
    res.header(
      "Access-Control-Allow-Methods",
      "GET, POST, PUT, DELETE, OPTIONS"
    );
    res.header(
      "Access-Control-Allow-Headers",
      "Content-Type, Authorization, Accept"
    );
  }

  if (req.method === "OPTIONS") {
    return res.status(200).end();
  }

  next();
};

app.use(customCors);

// app.use(cors({
//   origin: "https://authontication-fontend.vercel.app",
//   credentials: true
// }))
// // app.use(
// //   cors({
// //     origin: "https://authontication-fontend.vercel.app",
// //     credentials: true,
// //   })
// // );

// use Routers

app.use("/api/v1/users", authRouters);
// errorHandler

app.use(errorHandler);
// listen server

app.listen(PORT, () => {
  console.log(`SERVER IS RUNING ON ${PORT}`.bgGreen.black);
});
