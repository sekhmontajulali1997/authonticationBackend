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
app.use(
  cors({
    origin: "https://authontication-fontend.vercel.app",
    credentials: true,
  })
);

// use Routers

app.use("/api/v1/users", authRouters);
// errorHandler

app.use(errorHandler);
// listen server

app.listen(PORT, () => {
  console.log(`SERVER IS RUNING ON ${PORT}`.bgGreen.black);
});
