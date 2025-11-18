import { google } from 'googleapis';
import fs from 'fs';
import path from 'path';
import dotenv from 'dotenv';

dotenv.config();

const KEY_FILE_PATH = path.join(process.cwd(), 'final-project-455209-3941f974a570.json');

// IMPORTANT: full access so permission works
const SCOPES = ['https://www.googleapis.com/auth/drive'];

const auth = new google.auth.GoogleAuth({
    keyFile: KEY_FILE_PATH,
    scopes: SCOPES,
});

const drive = google.drive({ version: 'v3', auth });

export const uploadFileToDrive = async (file) => {
    try {
        const response = await drive.files.create({
            requestBody: {
                name: file.originalname,
                mimeType: file.mimetype,
            },
            media: {
                mimeType: file.mimetype,
                body: fs.createReadStream(file.path),
            },
        });

        const fileId = response.data.id;

        // Make file PUBLIC
        await drive.permissions.create({
            fileId,
            requestBody: {
                role: 'reader',
                type: 'anyone',
            },
        });

        const fileUrl = `${fileId}`;

        fs.unlinkSync(file.path);

        return fileUrl;
    } catch (err) {
        console.error('Error uploading file:', err);
        throw new Error('Failed to upload file');
    }
};
