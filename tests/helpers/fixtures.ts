import { readFileSync } from 'node:fs';
import { join } from 'node:path';

export function fixture(source: string, name: string): unknown {
  return JSON.parse(readFileSync(join(__dirname, '..', 'fixtures', source, `${name}.json`), 'utf8')) as unknown;
}
