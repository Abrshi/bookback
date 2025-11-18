import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();


export const getBookList = async (req, res) => {
  try {
    const books = await prisma.book.findMany();

    const booksWithProxyCover = books.map((book) => {
      if (book.coverUrl) {
          book.coverUrl   ?book.coverUrl = `http://localhost:5500/api/v1/google-image/${book.coverUrl}`
          : null;
          console.log(book.coverUrl);
      }
      if (book.fileUrl) {
          book.fileUrl = `https://drive.google.com/file/d/${book.fileUrl}/edit`
      }
      return book;
    });

    res.status(200).json(booksWithProxyCover);
  } catch (err) {
    console.error("Error fetching books:", err);
    res.status(500).json({ error: "Internal server error while fetching books" });
  }
};

