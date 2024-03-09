import { Router } from "express";
import auth from "./auth.js"
import twoFA from "./twofa.js"
const router = Router()

router.use("/auth", auth)
router.use("/2fa", twoFA )

export default router