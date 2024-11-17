import { User } from "../models/userSchema.js";
import { catchAsyncErrors } from "./catchAsyncErrors.js";
import ErrorHandler from "./error.js";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";

// Middleware to authenticate admin users for dashboard access
export const isAdminAuthenticated = catchAsyncErrors(async (req, res, next) => {
  const token = req.cookies.adminToken;
  
  // Check if token is present
  if (!token) {
    return next(new ErrorHandler("Dashboard user is not authenticated!", 401));
  }

  try {
    // Verify the token and attach the user to req.user if token is valid
    const decoded = jwt.verify(token, process.env.JWT_SECRET_KEY);
    req.user = await User.findById(decoded.id);
    
    if (!req.user) {
      return next(new ErrorHandler("User not found!", 404));
    }

    if (req.user.role !== "Admin") {
      return next(new ErrorHandler("Not authorized as Admin!", 403));
    }
    
    next();
  } catch (error) {
    return next(new ErrorHandler("Token is invalid or expired", 401));
  }
});

// Middleware to authenticate patient users for frontend access
export const isPatientAuthenticated = catchAsyncErrors(async (req, res, next) => {
  const token = req.cookies.patientToken;

  if (!token) {
    return next(new ErrorHandler("User is not authenticated!", 401));
  }

  try {
    // Verify the token and attach the user to req.user if token is valid
    const decoded = jwt.verify(token, process.env.JWT_SECRET_KEY);
    req.user = await User.findById(decoded.id);

    if (!req.user) {
      return next(new ErrorHandler("User not found!", 404));
    }

    if (req.user.role !== "Patient") {
      return next(new ErrorHandler("Not authorized as Patient!", 403));
    }

    next();
  } catch (error) {
    return next(new ErrorHandler("Token is invalid or expired", 401));
  }
});

// General authentication middleware for any authenticated user
export const isAuthenticated = catchAsyncErrors(async (req, res, next) => {
  const token = req.cookies.token || req.headers.authorization?.split(" ")[1];

  if (!token) {
    return next(new ErrorHandler("User is not authenticated!", 401));
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET_KEY);
    req.user = await User.findById(decoded.id);

    if (!req.user) {
      return next(new ErrorHandler("User not found!", 404));
    }

    next();
  } catch (error) {
    return next(new ErrorHandler("Token is invalid or expired", 401));
  }
});


// Middleware for role-based authorization
export const isAuthorized = (...roles) => {
  return (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) {
      return next(new ErrorHandler("Not authorized for this resource!", 403));
    }
    next();
  };
};

// Register the first admin
// export const registerFirstAdmin = catchAsyncErrors(async (req, res, next) => {
//   const adminExists = await User.findOne({ role: "Admin" });
//   if (adminExists) {
//     return next(new ErrorHandler("Admin user already exists!", 400));
//   }

//   const { name, email, password } = req.body;
//   const hashedPassword = await bcrypt.hash(password, 10);

//   const newAdmin = await User.create({
//     name,
//     email,
//     password: hashedPassword,
//     role: "Admin",
//   });

//   const token = jwt.sign({ id: newAdmin._id }, process.env.JWT_SECRET_KEY, {
//     expiresIn: process.env.JWT_EXPIRES_IN,
//   });

//   res.cookie("adminToken", token, {
//     httpOnly: true,
//     secure: process.env.NODE_ENV === "production",
//     sameSite: "strict",
//   });

//   res.status(201).json({
//     success: true,
//     message: "First admin registered successfully",
//     newAdmin,
//   });
// });
