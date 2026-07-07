export interface StoredFile {
  key: string;
  path: string;
  size: number;
  contentType: string;
}

export interface StorageProvider {
  readonly name: string;

  save(
    buffer: Buffer,
    options: {
      key: string;
      contentType: string;
      ownerId?: string;
      visibility?: 'private' | 'public';
    },
  ): Promise<StoredFile>;

  delete(key: string): Promise<void>;

  exists(key: string): Promise<boolean>;

  getSignedUrl(
    key: string,
    options: {
      operation: 'read' | 'write';
      expiresInSeconds: number;
      ownerId?: string;
    },
  ): Promise<string>;

  listAll(): Promise<{ key: string; lastModified: Date }[]>;
}
