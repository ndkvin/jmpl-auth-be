import express from "express"
import auth from "../routes/auth.js"
import twoFA from "../routes/twofa.js"
import dotenv from 'dotenv';

dotenv.config();

const app = express()
const port = process.env.PORT

app.use(express.json());
app.use("/auth", auth)
app.use("/2fa", twoFA )

app.listen(port, () => {
  console.log(`Example app listening on port ${process.env.PORT}`)
})