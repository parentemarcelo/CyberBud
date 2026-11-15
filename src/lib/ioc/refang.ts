// Refanging (docs/SPEC.md F1): turn defanged IOCs back into real ones before
// detection. All rules are case-insensitive.

/** `hxxp`, `hxxps`, `hXXp`, `fxp` — only when used as a URL scheme. */
const SCHEME = /\b(hxxp|fxp)(s?)(?=\s*(?:\[:\/\/\]|\[:\]|:))/gi;

/** `[.]`, `(.)`, `{.}`, `[dot]`, `(dot)`, also with inner spaces like `[ . ]`. */
const DOT = /[[({]\s*(?:\.|dot)\s*[\])}]/gi;

/** ` . ` between two host characters, e.g. `example . com`. */
const SPACED_DOT = /(?<=[\p{L}\p{N}-]) \. (?=[\p{L}\p{N}-])/gu;

/** `[://]`, `[:]`, `[/]` (inner spaces tolerated). */
const PUNCT = /\[\s*(:\/\/|:|\/)\s*\]/g;

/** `[at]`, `(at)`, `[@]`, `{at}`. */
const AT = /[[({]\s*(?:at|@)\s*[\])}]/gi;

/**
 * Apply every refang rule to `text`. Safe on already-clean input (no change)
 * and on whole multi-IOC text.
 */
export function refang(text: string): string {
  return text
    .replace(SCHEME, (_m, scheme: string, s: string) =>
      (scheme.toLowerCase() === 'fxp' ? 'ftp' : 'http') + s.toLowerCase(),
    )
    .replace(PUNCT, '$1')
    .replace(DOT, '.')
    .replace(SPACED_DOT, '.')
    .replace(AT, '@');
}

/**
 * Remove defang patterns' inner whitespace so text can be split on whitespace
 * without breaking an IOC apart: `example[ . ]com` → `example[.]com`,
 * `example . com` → `example[.]com`. The result is still defanged, which keeps
 * the user's original form for display.
 */
export function tightenDefangs(text: string): string {
  return text
    .replace(/([[({])\s*(:\/\/|\.|dot|at|@|:|\/)\s*([\])}])/gi, '$1$2$3')
    .replace(SPACED_DOT, '[.]');
}

const LEADING = /^["'`“”‘’«»<([{]+/;
const TRAILING_QUOTES = /["'`“”‘’«»>\]}]+$/;

/**
 * Strip wrapping characters from one token: surrounding quotes and `<>`, and
 * trailing `.,;:)!?`. A trailing `)` is kept when it closes a `(` inside the
 * token (e.g. `/wiki/Foo_(bar)`), and a trailing `:` is kept for IPv6 `::`.
 */
export function cleanToken(token: string): string {
  let t = token.trim();
  for (;;) {
    const before = t;
    t = t.replace(LEADING, '').replace(TRAILING_QUOTES, '');
    const last = t.at(-1);
    if (last === ')') {
      if (count(t, '(') < count(t, ')')) t = t.slice(0, -1);
    } else if (last === ':') {
      if (!t.endsWith('::')) t = t.slice(0, -1);
    } else if (last !== undefined && '.,;!?'.includes(last)) {
      t = t.slice(0, -1);
    }
    if (t === before) return t;
  }
}

function count(s: string, ch: string): number {
  let n = 0;
  for (const c of s) if (c === ch) n++;
  return n;
}
