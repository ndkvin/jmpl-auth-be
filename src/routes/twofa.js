import { Router } from "express";
import TwoFAController from "../controller/two.fa.controller.js";
import AuthMiddleware from "../middleware/auth.js";

const router = Router();
const authMiddleware = new AuthMiddleware()

const twoFAController = new TwoFAController(); 

router.get("/generate", authMiddleware.isLogin, twoFAController.generate);
router.post("/verify", authMiddleware.isLogin, twoFAController.verify);

export default router;
