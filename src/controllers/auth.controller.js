import bcrypt from "bcryptjs";
import User from "../models/user.model.js"
import { generateToken } from "../lib/utils.js";
import cloudinary from "../lib/cloudinary.js";

export const signup = async (req, res) => {
  const { email, fullName, password } = req.body
  try {

    if (!email || !fullName || !password) {
      return res.status(400).json({ message: 'All fields are required.' })
    }

    if (password.length < 6) {
      return res.status(400).json({ message: 'Password must be at least 6 character' })
    }

    const user = await User.findOne({ email })

    if (user) {
      return res.status(400).json({ message: 'Email already exists' })
    }

    const salt = await bcrypt.genSalt(10)
    const hashedPassword = await bcrypt.hash(password, salt)

    const newUser = new User({
      fullName,
      email,
      password: hashedPassword
    })

    if (newUser) {
      //Generate jwt token
      generateToken(newUser._id, res)
      await newUser.save()

      res.status(201).json({
        _id: newUser._id,
        fullName: newUser.fullName,
        email: newUser.email,
        profilePic: newUser.profilePic
      })

    } else {
      return res.status(400).json({ message: 'Invalid user data' })
    }
  } catch (error) {
    console.log("error in signup controller", error.message)
    res.status(500).json({ message: 'Internal server error' })
  }
}

export const login = async (req, res) => {
  const { email, password } = req.body
  try {

    const user = await User.findOne({ email })

    if (!user) {
      return res.status(400).json({ message: 'Invalid credentials' })
    }

    const isPasswordMatched = await bcrypt.compare(password, user.password);

    if (!isPasswordMatched) {
      return res.status(400).json({ message: 'Invalid credentials' })
    }

    generateToken(user._id, res)
    res.status(201).json({
      _id: user._id,
      fullName: user.fullName,
      email: user.email,
      profilePic: user.profilePic
    })

  } catch (error) {
    console.log("error in login controller", error.message)
    res.status(500).json({ message: 'Internal server error' })
  }
}

export const logout = (req, res) => {
  try {
    res.cookie("jwt", "", { maxAge: 0 })
    res.status(200).json({ message: 'Logout successfully!' })
  } catch (error) {
    console.log("error in logout controller", error.message)
    res.status(500).json({ message: 'Internal server error' })
  }
}

export const updateProfile = async (req, res) => {
  try {
    const { profilePic } = req.body

    //from protected route
    const userId = req.user._id

    if (!profilePic) {
      res.status(400).json({ message: 'Profile pic is required' })
    }

    const uploadResponse = await cloudinary.uploader.upload(profilePic)
    const updatedProfile = await User.findByIdAndUpdate(userId, { profilePic: uploadResponse.secure_url }, { new: true })

    res.status(200).json(updatedProfile)

  } catch (error) {
    console.log("error in updateProfile controller", error.message)
    res.status(500).json({ message: 'Internal server error' })
  }
}

export const checkAuth = (req, res) => {
  try {
    res.status(200).json(req.user)

  } catch (error) {
    console.log("error in checkAuth controller", error.message)
    res.status(500).json({ message: 'Internal server error' })
  }
}