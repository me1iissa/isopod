// Validate every diagram in the built site by RENDERING it, not by eye.
// The globals below are the ones jsdom does not provide and mermaid 11 needs;
// each one fails the whole run on its own, so they are all set up front.
import { readdirSync, readFileSync } from "node:fs";
import { JSDOM } from "jsdom";

const siteDir = process.argv[2] ?? "_site";

const dom = new JSDOM("<!doctype html><html><body></body></html>", {
  pretendToBeVisual: true,
});
global.window = dom.window;
global.document = dom.window.document;
Object.defineProperty(global, "navigator", {
  value: dom.window.navigator,
  configurable: true,
});
global.Element = dom.window.Element;
global.SVGElement = dom.window.SVGElement;
global.DOMPurify = undefined;
class StubSheet {
  constructor() {
    // mermaid 11 reads `cssRules.length` when inserting, and walks the rules to
    // build the style block — a two-method stub is not enough on its own.
    this.cssRules = [];
  }
  replaceSync() {}
  insertRule(rule, index) {
    const at = index ?? this.cssRules.length;
    this.cssRules.splice(at, 0, { cssText: rule, selectorText: "" });
    return at;
  }
}
global.CSSStyleSheet = StubSheet;
dom.window.CSSStyleSheet = StubSheet;
document.adoptedStyleSheets = [];
dom.window.SVGElement.prototype.getBBox = () => ({
  x: 0,
  y: 0,
  width: 100,
  height: 20,
});
dom.window.SVGElement.prototype.getComputedTextLength = () => 100;

const { default: mermaid } = await import("mermaid");
mermaid.initialize({ startOnLoad: false, securityLevel: "loose" });

function unescapeEntities(s) {
  return s
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&amp;/g, "&");
}

let checked = 0;
const failures = [];
const tagWarnings = [];

for (const file of readdirSync(siteDir).filter((f) => f.endsWith(".html"))) {
  const html = readFileSync(`${siteDir}/${file}`, "utf8");
  const blocks = [
    ...html.matchAll(/<pre class="mermaid">([\s\S]*?)<\/pre>/g),
  ].map((m) => unescapeEntities(m[1]).trim());
  for (const [i, src] of blocks.entries()) {
    const id = `${file}#${i + 1}`;
    checked += 1;
    // The `<i>`-in-a-label trap: mermaid renders it SUCCESSFULLY with the tag
    // silently eaten, so rendering alone never catches it.
    for (const label of src.matchAll(/[\["{(]"?([^"\]}]*<[a-zA-Z/][^"\]}]*)"?[\]}")]/g)) {
      const text = label[1];
      if (!/<br\s*\/?>/i.test(text.replace(/<br\s*\/?>/gi, ""))) {
        const stripped = text.replace(/<br\s*\/?>/gi, "");
        if (/<[a-zA-Z/]/.test(stripped)) {
          tagWarnings.push(`${id}: label contains an HTML-ish tag: ${stripped.trim()}`);
        }
      }
    }
    try {
      await mermaid.parse(src);
      await mermaid.render(`d${checked}`, src);
    } catch (e) {
      failures.push(`${id}: ${e.message?.split("\n")[0] ?? e}`);
    }
  }
}

console.log(JSON.stringify({ checked, failures, tagWarnings }, null, 2));
process.exit(failures.length || tagWarnings.length ? 1 : 0);
