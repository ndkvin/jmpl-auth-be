import express from "express"
import router from "../routes/index.js"
import dotenv from 'dotenv';
import cors from "cors"
import errorHandler from "../utils/error.handler.js";

dotenv.config();

const app = express()
const port = process.env.PORT

app.use(cors())
app.use(express.json());
app.use(router)
app.use(errorHandler)

app.listen(port, () => {
  console.log(`Example app listening on port ${process.env.PORT}`)
})
