import express from "express";
import {
  addBook,
  addBookCatagory,
  getAllBookCatagories
} from "../../controllers/admin/admin.controller.js";

import { upload } from "../../middlewares/upload.js";

const router = express.Router();

router.post("/addbookcatagory", addBookCatagory);
router.get("/getallbookcatagories", getAllBookCatagories);

router.post(
  "/addbook",
  upload.fields([
    { name: "file", maxCount: 1 },
    { name: "cover", maxCount: 1 }
  ]),
  addBook
);

export default router;
 