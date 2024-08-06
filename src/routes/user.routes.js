import { Router } from "express";
import { loginUser, logoutUser, registerUser } from "../controllers/user.controller.js";
import authenticateUser from '../middleware/authenticateUser.js';

const router = Router();

router.route("/register").post(registerUser)
router.route("/login").post(loginUser)
router.route("/logout").post(authenticateUser,logoutUser)

export default router;