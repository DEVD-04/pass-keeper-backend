import { User } from "../models/user.model.js";
import mongoose from "mongoose";




const generateAccessAndRefereshTokens = async (userId) => {
    try {
        const user = await User.findById(userId)
        const accessToken = user.generateAccessToken()
        const refreshToken = user.generateRefreshToken()

        user.refreshToken = refreshToken
        await user.save({ validateBeforeSave: false })

        return { accessToken, refreshToken }


    } catch (error) {
        console.log("error in generating token " + error);
    }
}


const registerUser = async (req, res) => {
    try {
        const { fullName, email, username, password } = req.body;
        if ([fullName, email, username, password].some((field) => field?.trim() === "")) {
            return res.status(400).json({ error: "All fields are required" });
        }
        // console.log(req.body);
        const existedUser = await User.findOne({
            $or: [{ username }, { email }]
        })
        if (existedUser) {
            return res.status(409).json({ error: "User with email or username already exists" });
        }

        const user = await User.create({
            fullName,
            email,
            password,
            username
        })
        // console.log(user)
        const createdUser = await User.findById(user._id)
        // console.log(createdUser)
        if (!createdUser) {
            return res.status(500).json({ error: "Something went wrong while registering the user" });
        }
        console.log("user registered successfully")
        return res.status(201).json({ message: "User registered successfully" });



    }
    catch (err) {
        console.log(err);
        return res.status(500).json({ error: "Internal Server Error" });

    }

};

const loginUser = async (req, res) => {
    try {
        const { email, username, password } = req.body
        // console.log(email);

        if (!username || !email) {
            return res.status(400).json({ error: "All fields are required" });
        }


        const user = await User.findOne({
            $or: [{ username }, { email }]
        })

        if (!user) {
            return res.status(404).json({ error: "user does not exist" });
        }

        const isPasswordValid = await user.isPasswordCorrect(password)

        if (!isPasswordValid) {
            return res.status(401).json({ error: "invalid user details" });
        }

        const { accessToken, refreshToken } = await generateAccessAndRefereshTokens(user._id)

        const loggedInUser = await User.findById(user._id).select("-password -refreshToken")

        const options = {
            httpOnly: true,
            secure: true
        }


        return res
            .status(200)
            .cookie("accessToken", accessToken, options)
            .cookie("refreshToken", refreshToken, options)
            .json({ message: "Login successful" })
    }
    catch (err) {
        console.error(err);
        return res.status(500).json({ error: "Internal Server Error" });
    }

};

const logoutUser = async (req, res) => {
    try {
        if (!req.user) {
            return res.status(401).json({ error: "User not authenticated" });
        }
        await User.findByIdAndUpdate(
            req.user._id,
            {
                $unset: {
                    refreshToken: 1 // this removes the field from document
                }
            },
            {
                new: true
            }
        )

        const options = {
            httpOnly: true,
            secure: true
        }

        return res
            .status(200)
            .clearCookie("accessToken", options)
            .clearCookie("refreshToken", options)
            .json({ message: "Logout successful" });
    }
    catch (err) {
        console.error(err);
        return res.status(500).json({ error: "Internal Server Error" });
    }
};

export {registerUser, loginUser, logoutUser};