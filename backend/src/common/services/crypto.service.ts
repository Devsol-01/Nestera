import { Injectable } from '@nestjs/common';
import * as bcrypt from 'bcrypt';

@Injectable()
export class CryptoService {
  private readonly saltRounds = 10;

  /**
   * Hashes a password using bcrypt.
   * @param password The plain-text password to hash.
   * @returns A promise that resolves to the hashed password.
   */
  async hash(password: string): Promise<string> {
    return bcrypt.hash(password, this.saltRounds);
  }

  /**
   * Compares a plain-text password with a hashed password.
   * @param plain The plain-text password.
   * @param hashed The hashed password to compare against.
   * @returns A promise that resolves to a boolean indicating the result.
   */
  async compare(plain: string, hashed: string): Promise<boolean> {
    return bcrypt.compare(plain, hashed);
  }
}
