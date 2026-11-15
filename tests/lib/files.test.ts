import { describe, expect, it } from 'vitest';
import { basename, fileExtension, truncateMiddle } from '../../src/lib/files';

describe('fileExtension (download classifier)', () => {
  it.each([
    ['setup.exe', 'exe'],
    ['SETUP.EXE', 'exe'],
    ['Setup.ExE', 'exe'],
    ['invoice.pdf.exe', 'exe'], // double extension: the real one is last
    ['invoice.exe.pdf', 'pdf'],
    ['archive.tar.gz', 'gz'],
    ['README', ''],
    ['.bashrc', ''],
    ['name.', ''],
    ['trailing.exe. ', 'exe'], // Windows strips trailing dots/spaces
    ['C:\\Users\\me\\Downloads\\payload.ps1', 'ps1'],
    ['/home/me/Downloads/tool.AppImage', 'appimage'],
    ['/home/me/dir.with.dots/README', ''],
  ])('%s → "%s"', (name, ext) => {
    expect(fileExtension(name)).toBe(ext);
  });
});

describe('basename and truncateMiddle', () => {
  it('basename handles both separators', () => {
    expect(basename('C:\\a\\b\\file.exe')).toBe('file.exe');
    expect(basename('/a/b/file.exe')).toBe('file.exe');
    expect(basename('file.exe')).toBe('file.exe');
  });

  it('keeps start and end of long names', () => {
    const long = `${'a'.repeat(100)}.exe`;
    const t = truncateMiddle(long, 20);
    expect(t).toHaveLength(20);
    expect(t.endsWith('.exe')).toBe(true);
    expect(truncateMiddle('short.exe', 20)).toBe('short.exe');
  });
});
