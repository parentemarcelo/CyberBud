import { createHash } from 'node:crypto';
import { describe, expect, it, vi } from 'vitest';
import { FileTooLargeError, hashFile, toHex } from '../../src/lib/hash';

const blob = (data: BlobPart) => new Blob([data]);

describe('hashFile (known vectors)', () => {
  it('empty file', async () => {
    expect(await hashFile(blob(''))).toEqual({
      sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      sha1: 'da39a3ee5e6b4b0d3255bfef95601890afd80709',
      size: 0,
    });
  });

  it('"abc" (FIPS 180 test vector)', async () => {
    expect(await hashFile(blob('abc'))).toEqual({
      sha256: 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
      sha1: 'a9993e364706816aba3e25717850c26c9cd0d89d',
      size: 3,
    });
  });

  it('1 MB generated buffer matches an independent implementation (node:crypto)', async () => {
    const data = new Uint8Array(1024 * 1024);
    for (let i = 0; i < data.length; i++) data[i] = (i * 31 + 7) & 0xff;
    const r = await hashFile(blob(data));
    expect(r.sha256).toBe(createHash('sha256').update(data).digest('hex'));
    expect(r.sha1).toBe(createHash('sha1').update(data).digest('hex'));
    expect(r.size).toBe(1024 * 1024);
  });

  it('works on a File', async () => {
    const f = new File(['abc'], 'abc.txt');
    expect((await hashFile(f)).sha256).toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  });
});

describe('size limit (1 GiB)', () => {
  it('rejects larger files without reading them', async () => {
    const arrayBuffer = vi.fn();
    const huge = { size: 1024 ** 3 + 1, arrayBuffer } as unknown as Blob;
    await expect(hashFile(huge)).rejects.toBeInstanceOf(FileTooLargeError);
    await expect(hashFile(huge)).rejects.toThrow('File too large for in-browser hashing');
    expect(arrayBuffer).not.toHaveBeenCalled();
  });

  it('accepts a file exactly at the limit', async () => {
    const at = { size: 3, arrayBuffer: () => blob('abc').arrayBuffer() };
    await expect(hashFile(at, 3)).resolves.toMatchObject({ size: 3 });
    await expect(hashFile(at, 2)).rejects.toBeInstanceOf(FileTooLargeError);
  });
});

it('toHex pads bytes', () => {
  expect(toHex(new Uint8Array([0, 1, 15, 16, 255]).buffer)).toBe('00010f10ff');
});
