import { Injectable, InternalServerErrorException } from '@nestjs/common';
import { existsSync, mkdirSync, writeFileSync } from 'fs';
import { join, extname } from 'path';
import { randomUUID } from 'crypto';

@Injectable()
export class StorageService {
  private readonly uploadDir = './uploads';

  constructor() {
    this.ensureUploadDirExists();
  }

  private ensureUploadDirExists() {
    if (!existsSync(this.uploadDir)) {
      mkdirSync(this.uploadDir, { recursive: true });
    }
  }

  async saveFile(file: Express.Multer.File): Promise<string> {
    try {
      const fileExtension = extname(file.originalname);
      const fileName = `${randomUUID()}${fileExtension}`;
      const filePath = join(this.uploadDir, fileName);

      writeFileSync(filePath, file.buffer);

      // Return the filename/path that will be stored in the DB
      // In a real app, this might be a full URL or a relative path
      return `/uploads/${fileName}`;
    } catch (error) {
      throw new InternalServerErrorException('Failed to save file');
    }
  }
}
