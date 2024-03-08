import express from "express"
import auth from "../routes/auth.js"
import twoFA from "../routes/twofa.js"

const app = express()
const port = 3000

app.use(express.json());
app.use("/auth", auth)
app.use("/2fa", twoFA )

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`)
})