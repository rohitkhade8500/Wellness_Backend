import express from "express";
import {
  addNewAdmin,
  addNewDoctor,
  getAllDoctors,
  getUserDetails,
  login,
  logoutAdmin,
  logoutPatient,
  patientRegister,
} from "../controller/userController.js";
import {
  isAdminAuthenticated,
  // registerFirstAdmin,
  isPatientAuthenticated,
} from "../middlewares/auth.js";

const router = express.Router();

// router.post("/admin/registerFirstAdmin", registerFirstAdmin);
router.post("/patient/register", patientRegister);
router.post("/login", login);
router.post("/admin/addnew", addNewAdmin);
router.post("/doctor/addnew",  addNewDoctor);
router.get("/doctors", getAllDoctors);
router.get("/patient/me",isPatientAuthenticated , getUserDetails);
router.get("/admin/me",isAdminAuthenticated,  getUserDetails);
router.get("/patient/logout",  logoutPatient);
router.get("/admin/logout",isAdminAuthenticated,  logoutAdmin);

export default router;
