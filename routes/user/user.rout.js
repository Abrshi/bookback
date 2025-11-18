import express from "express";
import { getBookList } from "../../controllers/user/getBook.controller.js";

const router = express.Router();

// Get book list
router.get("/getBookList", getBookList);

export default router;
