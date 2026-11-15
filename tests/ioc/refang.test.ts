import { describe, expect, it } from 'vitest';
import { cleanToken, refang, tightenDefangs } from '../../src/lib/ioc/refang';

describe('refang: scheme (SPEC F1)', () => {
  it.each([
    ['hxxp://example.com', 'http://example.com'],
    ['hxxps://example.com', 'https://example.com'],
    ['hXXp://example.com', 'http://example.com'],
    ['HXXPS://example.com', 'https://example.com'],
    ['fxp://files.example.com', 'ftp://files.example.com'],
    ['hxxp[:]//example.com', 'http://example.com'],
    ['hxxps[://]example.com', 'https://example.com'],
  ])('%s → %s', (input, expected) => {
    expect(refang(input)).toBe(expected);
  });

  it('only rewrites hxxp when used as a scheme', () => {
    expect(refang('hxxpfoo.example.com')).toBe('hxxpfoo.example.com');
    expect(refang('the hxxp tool')).toBe('the hxxp tool');
  });
});

describe('refang: dots', () => {
  it.each([
    ['example[.]com', 'example.com'],
    ['example(.)com', 'example.com'],
    ['example{.}com', 'example.com'],
    ['example[dot]com', 'example.com'],
    ['example(dot)com', 'example.com'],
    ['example[DOT]com', 'example.com'],
    ['example[ . ]com', 'example.com'],
    ['example . com', 'example.com'],
    ['1[.]2[.]3[.]4', '1.2.3.4'],
    ['sub[.]example[.]co[.]uk', 'sub.example.co.uk'],
  ])('%s → %s', (input, expected) => {
    expect(refang(input)).toBe(expected);
  });

  it('leaves sentence-ending " . " alone when not between host characters', () => {
    expect(refang('done . ')).toBe('done . ');
  });
});

describe('refang: colon, slash, at', () => {
  it.each([
    ['https[:]//example.com', 'https://example.com'],
    ['https[://]example.com', 'https://example.com'],
    ['example.com[/]path', 'example.com/path'],
    ['user[at]example.com', 'user@example.com'],
    ['user(at)example.com', 'user@example.com'],
    ['user[@]example.com', 'user@example.com'],
    ['user[AT]example.com', 'user@example.com'],
  ])('%s → %s', (input, expected) => {
    expect(refang(input)).toBe(expected);
  });
});

describe('refang: combined and mixed case', () => {
  it('handles a fully defanged URL', () => {
    expect(refang('HXXPS[:]//Evil[.]Example[DOT]com[/]path')).toBe('https://Evil.Example.com/path');
  });

  it('handles several IOCs in one text', () => {
    expect(refang('1[.]2[.]3[.]4, hxxp://a[.]b/c')).toBe('1.2.3.4, http://a.b/c');
  });
});

describe('refang: clean input is unchanged', () => {
  it.each([
    'https://example.com/path?q=1#frag',
    'example.com',
    '8.8.8.8',
    '2001:db8::1',
    'd41d8cd98f00b204e9800998ecf8427e',
    'https://en.wikipedia.org/wiki/Foo_(bar)',
    '',
  ])('%s', (input) => {
    expect(refang(input)).toBe(input);
  });
});

describe('tightenDefangs', () => {
  it('removes inner spaces but keeps the defanged form', () => {
    expect(tightenDefangs('example[ . ]com')).toBe('example[.]com');
    expect(tightenDefangs('example . com')).toBe('example[.]com');
    expect(tightenDefangs('user[ at ]example.com')).toBe('user[at]example.com');
    expect(tightenDefangs('https[ : ]//x')).toBe('https[:]//x');
  });

  it('result refangs to the same value as the original', () => {
    for (const s of ['example[ . ]com', 'a . b . c', 'x[ dot ]y']) {
      expect(refang(tightenDefangs(s))).toBe(refang(s));
    }
  });
});

describe('cleanToken (surrounding characters)', () => {
  it.each([
    ['"example.com"', 'example.com'],
    ["'example.com'", 'example.com'],
    ['“example.com”', 'example.com'],
    ['<https://example.com>', 'https://example.com'],
    ['example.com.', 'example.com'],
    ['example.com,', 'example.com'],
    ['example.com;', 'example.com'],
    ['example.com:', 'example.com'],
    ['(example.com)', 'example.com'],
    ['example.com).', 'example.com'],
    ['"8.8.8.8",', '8.8.8.8'],
    ['example.com?!', 'example.com'],
  ])('%s → %s', (input, expected) => {
    expect(cleanToken(input)).toBe(expected);
  });

  it('keeps a balanced closing parenthesis', () => {
    expect(cleanToken('https://en.wikipedia.org/wiki/Foo_(bar)')).toBe('https://en.wikipedia.org/wiki/Foo_(bar)');
    expect(cleanToken('https://en.wikipedia.org/wiki/Foo_(bar))')).toBe('https://en.wikipedia.org/wiki/Foo_(bar)');
  });

  it('keeps a trailing IPv6 "::"', () => {
    expect(cleanToken('fe80::')).toBe('fe80::');
    expect(cleanToken('fe80::,')).toBe('fe80::');
  });

  it('returns empty for punctuation-only tokens', () => {
    expect(cleanToken('"",.')).toBe('');
  });
});
