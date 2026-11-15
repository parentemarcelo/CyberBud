// Filename helpers shared by the File tab and the download watcher.

/** Last path segment, for Windows and POSIX paths. */
export function basename(path: string): string {
  const parts = path.split(/[\\/]/);
  return parts[parts.length - 1] ?? path;
}

/**
 * Lowercase extension of the last segment: "invoice.pdf.exe" → "exe",
 * "archive.tar.gz" → "gz", "README" → "", ".bashrc" → "", "name." → "".
 */
export function fileExtension(path: string): string {
  const name = basename(path).trim().replace(/[\s.]+$/, '');
  const dot = name.lastIndexOf('.');
  if (dot <= 0) return '';
  return name.slice(dot + 1).toLowerCase();
}

/** Shorten long untrusted names for notifications and headings. */
export function truncateMiddle(text: string, max = 60): string {
  if (text.length <= max) return text;
  const keep = max - 1;
  return `${text.slice(0, Math.ceil(keep / 2))}…${text.slice(text.length - Math.floor(keep / 2))}`;
}
