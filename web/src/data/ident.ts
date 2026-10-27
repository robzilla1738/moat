/**
 * App names, hostnames, session ids, paths and agent text are untrusted display data. React already escapes markup;
 * this module makes the characters a person cannot see visible, and flags identifiers built to look like others.
 */

// Bidirectional overrides/isolates and marks, zero-width characters, word joiner, BOM, soft hyphen and other
// invisible formatting characters, plus C0/C1 control characters.
const HIDDEN = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F\u00AD\u034F\u061C\u115F\u1160\u17B4\u17B5\u180E\u200B-\u200F\u202A-\u202E\u2060-\u206F\u3164\uFE00-\uFE0F\uFEFF\uFFA0\uFFF9-\uFFFB]/gu;
const BIDI = /[\u061C\u200E\u200F\u202A-\u202E\u2066-\u2069]/u;

export interface IdentReport {
  /** Text safe to show: hidden characters replaced by visible escapes like ⟨U+202E⟩, newlines shown as ⏎. */
  text: string;
  warnings: string[];
  /** True when the visible text differs from the raw value. */
  altered: boolean;
}

function scriptsOf(s: string): Set<string> {
  const out = new Set<string>();
  for (const ch of s) {
    if (/\p{Script=Latin}/u.test(ch)) out.add("Latin");
    else if (/\p{Script=Cyrillic}/u.test(ch)) out.add("Cyrillic");
    else if (/\p{Script=Greek}/u.test(ch)) out.add("Greek");
    else if (/\p{Script=Armenian}/u.test(ch)) out.add("Armenian");
    else if (/\p{Script=Cherokee}/u.test(ch)) out.add("Cherokee");
    else if (/\p{L}/u.test(ch)) out.add("other");
  }
  return out;
}

export function inspectIdent(raw: unknown, opts: { kind?: "host" | "text" | "id"; max?: number } = {}): IdentReport {
  const value = typeof raw === "string" ? raw : raw === null || raw === undefined ? "" : String(raw);
  const warnings: string[] = [];
  if (BIDI.test(value)) warnings.push("contains direction-changing characters");
  let hidden = 0;
  let text = value.replace(HIDDEN, (c) => {
    hidden++;
    return `⟨U+${c.codePointAt(0)!.toString(16).toUpperCase().padStart(4, "0")}⟩`;
  });
  if (hidden && !warnings.length) warnings.push("contains invisible characters");
  if (/[\r\n\u2028\u2029]/.test(text)) {
    text = text.replace(/\r\n|[\r\n\u2028\u2029]/g, "⏎");
    if (opts.kind !== "text") warnings.push("contains line breaks");
  }
  const scripts = scriptsOf(value);
  if (scripts.size > 1 && scripts.has("Latin")) warnings.push(`mixes ${[...scripts].join(" and ")} letters`);
  if (opts.kind === "host") {
    if (/(^|\.)xn--/i.test(value)) warnings.push("internationalized (punycode) name");
    if (/[^\x21-\x7e]/.test(value) && !/(^|\.)xn--/i.test(value)) warnings.push("not a plain ASCII hostname");
  }
  const max = opts.max ?? (opts.kind === "text" ? 600 : 160);
  if ([...text].length > max) {
    const chars = [...text];
    text = `${chars.slice(0, Math.floor(max / 2)).join("")}…${chars.slice(-Math.floor(max / 2) + 1).join("")}`;
    warnings.push(`shortened from ${chars.length} characters`);
  }
  return { text, warnings, altered: text !== value };
}
