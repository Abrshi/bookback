import { PrismaClient } from "@prisma/client";
import { uploadFileToDrive } from "../googleDrive.js";


const prisma = new PrismaClient();

export const addBookCatagory = async (req, res) => {
  const { catagory } = req.body;

  if (!catagory)
    return res.status(400).json({ error: "category is required" });

  try {
    const existing = await prisma.category.findFirst({
      where: { category: catagory },
    });

    if (existing)
      return res.status(409).json({ error: "This category already exists" });

    const createdCategory = await prisma.category.create({
      data: {
        category: catagory,
      },
    });

    return res.status(201).json({
      message: "Category created successfully!",
      category: createdCategory,
    });

  } catch (err) {
    console.error("category creation error:", err);
    return res
      .status(500)
      .json({ error: "Internal server error during category creation" });
  }
};


export const getAllBookCatagories = async (req, res) => {
  try {
    const categories = await prisma.category.findMany();
    res.status(200).json(categories);
  } catch (err) {
    console.error("Error fetching categories:", err);
    res.status(500).json({ error: "Internal server error while fetching categories" });
  }
};


export const addBook = async (req, res) => {
  try {
    const { title, author, categoryId, description, publishedAt } = req.body;

    if (!title || !categoryId)
      return res.status(400).json({ error: "Missing required fields" });

    if (!req.files || !req.files.file)
      return res.status(400).json({ error: "No book file uploaded" });

    const category = parseInt(categoryId);
    if (isNaN(category))
      return res.status(400).json({ error: "Invalid categoryId" });

    // Validate publishedAt
    let pubDate = new Date(publishedAt);
    if (publishedAt && isNaN(pubDate.getTime()))
      return res.status(400).json({ error: "Invalid publishedAt date" });

    // Upload main file
    const fileUploaded = req.files.file[0];
    const fileUrl = await uploadFileToDrive(fileUploaded);
    console.log(fileUrl);
    if (!fileUrl)
      return res.status(500).json({ error: "File upload failed" });
    
    // Upload cover
    let coverUrl = null;
    if (req.files.cover && req.files.cover.length > 0) {
      const coverUploaded = req.files.cover[0];
      coverUrl = await uploadFileToDrive(coverUploaded);
    }
    const newBook = await prisma.book.create({
      data: {
        title,
        author: author || null,
        description: description || null,
        categoryId: category,
        fileUrl,
        coverUrl,
        publishedAt: publishedAt ? pubDate : new Date(),
      },
    });

    return res.status(201).json({
      message: "Book added successfully",
      book: newBook,
    });

  } catch (error) {
    console.error("Add book error:", error);
    return res.status(500).json({ error: "Internal server error" });
  }
};

