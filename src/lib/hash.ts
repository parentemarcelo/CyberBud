// In-browser file hashing (docs/SPEC.md F4). The file is read locally and
// never leaves the browser; only its SHA-256 is looked up.
import { MAX_FILE_SIZE_BYTES } from './constants';

export interface FileHashes {
  sha256: string;
  sha1: string;
  size: number;
}

export class FileTooLargeError extends Error {
  constructor(readonly size: number) {
    super('File too large for in-browser hashing');
    this.name = 'FileTooLargeError';
  }
}

/** SHA-256 and SHA-1 of a file (lowercase hex). Rejects files over MAX_FILE_SIZE_BYTES without reading them. */
export async function hashFile(file: Pick<Blob, 'size' | 'arrayBuffer'>, maxBytes = MAX_FILE_SIZE_BYTES): Promise<FileHashes> {
  if (file.size > maxBytes) throw new FileTooLargeError(file.size);
  const data = await file.arrayBuffer();
  const [sha256, sha1] = await Promise.all([crypto.subtle.digest('SHA-256', data), crypto.subtle.digest('SHA-1', data)]);
  return { sha256: toHex(sha256), sha1: toHex(sha1), size: data.byteLength };
}

export function toHex(buf: ArrayBuffer): string {
  return Array.from(new Uint8Array(buf), (b) => b.toString(16).padStart(2, '0')).join('');
}
