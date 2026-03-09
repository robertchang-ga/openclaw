#!/usr/bin/env bun
/**
 * brd-scrape — Playwright scraper routed through BrightData remote browser.
 *
 * Credentials are read from ~/.openclaw/brightdata-endpoint (a single line
 * containing the WSS URL). The agent never sees or sets the endpoint URL.
 *
 * SINGLE-STEP USAGE
 *   brd-scrape <url> [options]
 *
 *   --format text|html|markdown   Output format for content extraction (default: text)
 *   --selector <css>              Extract a specific element instead of full page
 *   --screenshot <file>           Save a full-page screenshot
 *   --pdf <file>                  Save page as PDF
 *   --links                       Output all links as JSON array [{href,text}]
 *   --evaluate <js>               Evaluate JS on the page and print the result as JSON
 *   --click <css>                 Click an element before extracting
 *   --fill <css=value>            Fill an input field (repeatable)
 *   --select <css=value>          Select a <select> option by value (repeatable)
 *   --press <key>                 Press a keyboard key on the page (e.g. Enter, Tab)
 *   --scroll                      Scroll to the bottom before extracting (infinite scroll)
 *   --wait-for <css>              Wait for this selector to appear
 *   --wait-for-load <state>       Wait for load state: domcontentloaded|load|networkidle
 *   --wait <ms>                   Wait a fixed number of ms (after navigation)
 *   --cookie <name=value>         Set a cookie (repeatable)
 *   --header <name=value>         Set a request header (repeatable)
 *   --user-agent <string>         Override the user-agent string
 *   --block <type,...>            Block resource types: image,font,stylesheet,media,script
 *   --viewport <WxH>              Set viewport size (default: 1280x800)
 *   --timeout <ms>                Navigation timeout in ms (default: 30000)
 *   --no-extract                  Skip content extraction (useful when only taking screenshots)
 *
 * MULTI-STEP USAGE (action script)
 *   brd-scrape --actions <file.json>
 *   brd-scrape --actions -          (read JSON from stdin)
 *
 *   The action file is a JSON array of step objects. Each step has one key:
 *
 *   {"navigate": "https://..."}
 *   {"click": "css-selector"}
 *   {"fill": {"selector": "css", "value": "text"}}
 *   {"select": {"selector": "css", "value": "option-value"}}
 *   {"hover": "css-selector"}
 *   {"press": {"selector": "css", "key": "Enter"}}   -- key on focused element
 *   {"press": "Enter"}                               -- key on page (no selector)
 *   {"wait-for": "css-selector"}
 *   {"wait-for-load": "networkidle"}
 *   {"wait": 1500}
 *   {"scroll": "bottom"}   or  {"scroll": "top"}   or  {"scroll": "css-selector"}
 *   {"evaluate": "document.title"}
 *   {"screenshot": "/tmp/step.png"}
 *   {"extract": "text"}              -- extract body text, print to stdout
 *   {"extract": {"selector":"css", "format":"markdown"}}
 *   {"cookie": {"name":"x","value":"y","domain":"example.com"}}
 *   {"header": {"name": "X-Custom", "value": "val"}}
 *
 * EXAMPLES
 *   brd-scrape https://example.com
 *   brd-scrape https://example.com --format markdown --selector article
 *   brd-scrape https://example.com --screenshot /tmp/ss.png --no-extract
 *   brd-scrape https://example.com --click "#load-more" --wait-for ".results" --format text
 *   brd-scrape https://example.com --fill "#q=hello world" --press Enter --wait-for ".results"
 *   brd-scrape https://example.com --links
 *   brd-scrape https://example.com --evaluate "document.title"
 *   brd-scrape --actions /tmp/steps.json
 */

import { readFile } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

type Format = "text" | "html" | "markdown";

type Action =
  | { navigate: string }
  | { click: string }
  | { fill: { selector: string; value: string } }
  | { select: { selector: string; value: string } }
  | { hover: string }
  | { press: string | { selector: string; key: string } }
  | { "wait-for": string }
  | { "wait-for-load": "domcontentloaded" | "load" | "networkidle" }
  | { wait: number }
  | { scroll: string }
  | { evaluate: string }
  | { screenshot: string }
  | { extract: Format | { selector?: string; format?: Format } }
  | { cookie: { name: string; value: string; domain?: string; path?: string } }
  | { header: { name: string; value: string } };

// ---------------------------------------------------------------------------
// Arg parsing
// ---------------------------------------------------------------------------

const HELP = `\
Usage: brd-scrape <url> [options]
       brd-scrape --actions <file.json|->

Single-step options:
  --format text|html|markdown   Content output format (default: text)
  --selector <css>              Limit extraction to this element
  --screenshot <file>           Save full-page screenshot
  --pdf <file>                  Save page as PDF
  --links                       Output all links as JSON [{href,text}]
  --evaluate <js>               Evaluate JS and print JSON result
  --click <css>                 Click element before extracting
  --fill <css=value>            Fill input (repeatable)
  --select <css=value>          Select <select> option by value (repeatable)
  --press <key>                 Press key on page (e.g. Enter, Tab, Escape)
  --scroll                      Scroll to bottom (infinite scroll)
  --wait-for <css>              Wait for selector to appear
  --wait-for-load <state>       domcontentloaded|load|networkidle
  --wait <ms>                   Wait fixed ms after navigation
  --cookie <name=value>         Set cookie (repeatable)
  --header <name=value>         Set request header (repeatable)
  --user-agent <string>         Override user-agent
  --block <types>               Comma-separated: image,font,stylesheet,media,script
  --viewport <WxH>              Viewport size (default: 1280x800)
  --timeout <ms>                Navigation timeout (default: 30000)
  --no-extract                  Skip content extraction

Multi-step:
  --actions <file.json|->       Run a JSON action script (see docs for format)`;

const args = process.argv.slice(2);
if (!args.length || args[0] === "-h" || args[0] === "--help") {
  console.log(HELP);
  process.exit(args.length ? 0 : 1);
}

// Parsed options
let url = "";
let format: Format = "text";
let selector = "";
let screenshotFile = "";
let pdfFile = "";
let linksMode = false;
let evaluateExpr = "";
let clicks: string[] = [];
let fills: Array<{ selector: string; value: string }> = [];
let selects: Array<{ selector: string; value: string }> = [];
let pressKeys: string[] = [];
let scrollToBottom = false;
let waitForSelector = "";
let waitForLoad: "domcontentloaded" | "load" | "networkidle" | "" = "";
let waitMs = 0;
let cookies: Array<{ name: string; value: string }> = [];
let headers: Record<string, string> = {};
let userAgent = "";
let blockTypes: string[] = [];
let viewportW = 1280;
let viewportH = 800;
let timeout = 30_000;
let noExtract = false;
let actionsSource = ""; // file path or "-"

function splitFirst(s: string, sep: string): [string, string] {
  const idx = s.indexOf(sep);
  return idx === -1 ? [s, ""] : [s.slice(0, idx), s.slice(idx + sep.length)];
}

for (let i = 0; i < args.length; i++) {
  const a = args[i];
  const next = () => {
    const v = args[++i];
    if (v === undefined) {
      console.error(`${a} requires a value`);
      process.exit(1);
    }
    return v;
  };
  if (a === "--format") {
    const v = next();
    if (v !== "text" && v !== "html" && v !== "markdown") {
      console.error(`--format must be text, html, or markdown`);
      process.exit(1);
    }
    format = v;
  } else if (a === "--selector") {
    selector = next();
  } else if (a === "--screenshot") {
    screenshotFile = next();
  } else if (a === "--pdf") {
    pdfFile = next();
  } else if (a === "--links") {
    linksMode = true;
  } else if (a === "--evaluate") {
    evaluateExpr = next();
  } else if (a === "--click") {
    clicks.push(next());
  } else if (a === "--fill") {
    const [sel, val] = splitFirst(next(), "=");
    fills.push({ selector: sel, value: val });
  } else if (a === "--select") {
    const [sel, val] = splitFirst(next(), "=");
    selects.push({ selector: sel, value: val });
  } else if (a === "--press") {
    pressKeys.push(next());
  } else if (a === "--scroll") {
    scrollToBottom = true;
  } else if (a === "--wait-for") {
    waitForSelector = next();
  } else if (a === "--wait-for-load") {
    const v = next();
    if (v !== "domcontentloaded" && v !== "load" && v !== "networkidle") {
      console.error(`--wait-for-load must be domcontentloaded, load, or networkidle`);
      process.exit(1);
    }
    waitForLoad = v;
  } else if (a === "--wait") {
    waitMs = parseInt(next(), 10);
  } else if (a === "--cookie") {
    const [name, value] = splitFirst(next(), "=");
    cookies.push({ name, value });
  } else if (a === "--header") {
    const [name, value] = splitFirst(next(), "=");
    headers[name] = value;
  } else if (a === "--user-agent") {
    userAgent = next();
  } else if (a === "--block") {
    blockTypes = next()
      .split(",")
      .map((s) => s.trim());
  } else if (a === "--viewport") {
    const [w, h] = next().split("x").map(Number);
    viewportW = w;
    viewportH = h;
  } else if (a === "--timeout") {
    timeout = parseInt(next(), 10);
  } else if (a === "--no-extract") {
    noExtract = true;
  } else if (a === "--actions") {
    actionsSource = next();
  } else if (!a.startsWith("-")) {
    url = a;
  } else {
    console.error(`Unknown option: ${a}\n\n${HELP}`);
    process.exit(1);
  }
}

if (!actionsSource && !url) {
  console.error("Error: URL or --actions required.\n\n" + HELP);
  process.exit(1);
}

// ---------------------------------------------------------------------------
// Load BrightData endpoint (never exposed to callers)
// ---------------------------------------------------------------------------

async function loadEndpoint(): Promise<string> {
  const configPath = join(homedir(), ".openclaw", "brightdata-endpoint");
  try {
    const raw = await readFile(configPath, "utf8");
    const endpoint = raw.trim();
    if (!endpoint) {
      throw new Error("brightdata-endpoint file is empty");
    }
    return endpoint;
  } catch (err) {
    console.error(
      `brd-scrape: cannot read BrightData endpoint from ${configPath}\n` +
        `Create that file with the WSS URL on a single line.\n` +
        String(err),
    );
    process.exit(1);
  }
}

// ---------------------------------------------------------------------------
// HTML → Markdown (lightweight, for agent consumption)
// ---------------------------------------------------------------------------

function htmlToMarkdown(html: string): string {
  return html
    .replace(/<script[\s\S]*?<\/script>/gi, "")
    .replace(/<style[\s\S]*?<\/style>/gi, "")
    .replace(
      /<h([1-6])[^>]*>([\s\S]*?)<\/h\1>/gi,
      (_m, l, t) => `${"#".repeat(Number(l))} ${t.replace(/<[^>]+>/g, "").trim()}\n`,
    )
    .replace(
      /<a[^>]+href="([^"]*)"[^>]*>([\s\S]*?)<\/a>/gi,
      (_m, href, text) => `[${text.replace(/<[^>]+>/g, "").trim()}](${href})`,
    )
    .replace(/<strong[^>]*>([\s\S]*?)<\/strong>/gi, "**$1**")
    .replace(/<em[^>]*>([\s\S]*?)<\/em>/gi, "_$1_")
    .replace(/<li[^>]*>([\s\S]*?)<\/li>/gi, "- $1\n")
    .replace(/<br\s*\/?>/gi, "\n")
    .replace(/<p[^>]*>([\s\S]*?)<\/p>/gi, "$1\n\n")
    .replace(/<[^>]+>/g, "")
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&nbsp;/g, " ")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
}

// ---------------------------------------------------------------------------
// Page helpers
// ---------------------------------------------------------------------------

// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function extractContent(page: any, fmt: Format, sel: string): Promise<string> {
  if (fmt === "html") {
    return sel ? await page.locator(sel).first().innerHTML() : await page.content();
  }
  if (fmt === "markdown") {
    const html = sel
      ? await page.locator(sel).first().innerHTML()
      : await page.evaluate(() => document.body.innerHTML);
    return htmlToMarkdown(html);
  }
  // text
  return sel
    ? await page.locator(sel).first().innerText()
    : await page.evaluate(() => document.body.innerText);
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function scrollPage(page: any): Promise<void> {
  // Repeatedly scroll to the bottom to trigger lazy-loaded content.
  await page.evaluate(async () => {
    await new Promise<void>((resolve) => {
      let lastHeight = document.body.scrollHeight;
      const interval = setInterval(() => {
        window.scrollTo(0, document.body.scrollHeight);
        if (document.body.scrollHeight === lastHeight) {
          clearInterval(interval);
          resolve();
        }
        lastHeight = document.body.scrollHeight;
      }, 300);
    });
  });
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function applyResourceBlocking(context: any, types: string[]): Promise<void> {
  if (!types.length) {
    return;
  }
  const blocked = new Set(types);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  await context.route("**/*", (route: any) => {
    if (blocked.has(route.request().resourceType())) {
      route.abort();
    } else {
      route.continue();
    }
  });
}

// ---------------------------------------------------------------------------
// Action runner (multi-step mode)
// ---------------------------------------------------------------------------

// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function runActions(page: any, context: any, actions: Action[]): Promise<void> {
  for (const action of actions) {
    if ("navigate" in action) {
      await page.goto(action.navigate, { waitUntil: "domcontentloaded", timeout });
    } else if ("click" in action) {
      await page.locator(action.click).first().click();
    } else if ("fill" in action) {
      await page.locator(action.fill.selector).first().fill(action.fill.value);
    } else if ("select" in action) {
      await page.locator(action.select.selector).first().selectOption(action.select.value);
    } else if ("hover" in action) {
      await page.locator(action.hover).first().hover();
    } else if ("press" in action) {
      if (typeof action.press === "string") {
        await page.keyboard.press(action.press);
      } else {
        await page.locator(action.press.selector).first().press(action.press.key);
      }
    } else if ("wait-for" in action) {
      await page.waitForSelector(action["wait-for"], { timeout });
    } else if ("wait-for-load" in action) {
      await page.waitForLoadState(action["wait-for-load"]);
    } else if ("wait" in action) {
      await new Promise((r) => setTimeout(r, action.wait));
    } else if ("scroll" in action) {
      const target = action.scroll;
      if (target === "bottom") {
        await scrollPage(page);
      } else if (target === "top") {
        await page.evaluate(() => window.scrollTo(0, 0));
      } else {
        await page.locator(target).first().scrollIntoViewIfNeeded();
      }
    } else if ("evaluate" in action) {
      // eslint-disable-next-line no-eval -- intentional: agent-supplied expression
      const result = await page.evaluate(action.evaluate);
      console.log(JSON.stringify(result, null, 2));
    } else if ("screenshot" in action) {
      await page.screenshot({ path: action.screenshot, fullPage: true });
      console.error(`Screenshot saved to ${action.screenshot}`);
    } else if ("extract" in action) {
      const spec = action.extract;
      const fmt: Format = typeof spec === "string" ? spec : (spec.format ?? "text");
      const sel = typeof spec === "object" ? (spec.selector ?? "") : "";
      console.log(await extractContent(page, fmt, sel));
    } else if ("cookie" in action) {
      const c = action.cookie;
      await context.addCookies([
        {
          name: c.name,
          value: c.value,
          domain: c.domain ?? new URL(page.url()).hostname,
          path: c.path ?? "/",
        },
      ]);
    } else if ("header" in action) {
      // Headers set mid-session apply to subsequent navigations via extraHTTPHeaders.
      await page.setExtraHTTPHeaders({ [action.header.name]: action.header.value });
    }
  }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  const endpoint = await loadEndpoint();

  // playwright is a runtime dep resolved via npx/node_modules; not in project tsconfig.
  // eslint-disable-next-line @typescript-eslint/ban-ts-comment
  // @ts-expect-error
  const { chromium } = await import("playwright").catch(() => {
    console.error("playwright package not found. Install with: npm install -g playwright");
    process.exit(1);
  });

  const browser = await chromium.connectOverCDP(endpoint);
  try {
    const contextOpts = {
      viewport: { width: viewportW, height: viewportH },
      ...(userAgent ? { userAgent } : {}),
      ...(Object.keys(headers).length ? { extraHTTPHeaders: headers } : {}),
    };
    const context = await browser.newContext(contextOpts);

    // Add cookies before creating the page so they're available on first navigation.
    if (cookies.length) {
      await context.addCookies(
        cookies.map((c) => ({
          name: c.name,
          value: c.value,
          domain: url ? new URL(url).hostname : "localhost",
          path: "/",
        })),
      );
    }

    await applyResourceBlocking(context, blockTypes);

    const page = await context.newPage();

    // ── Multi-step action mode ────────────────────────────────────────────
    if (actionsSource) {
      const raw =
        actionsSource === "-" ? await Bun.stdin.text() : await readFile(actionsSource, "utf8");
      const actions = JSON.parse(raw) as Action[];
      await runActions(page, context, actions);
      await context.close();
      return;
    }

    // ── Single-step mode ──────────────────────────────────────────────────
    await page.goto(url, { waitUntil: "domcontentloaded", timeout });

    if (waitForLoad) {
      await page.waitForLoadState(waitForLoad);
    }
    if (waitMs > 0) {
      await new Promise((r) => setTimeout(r, waitMs));
    }

    // Interactions (in order: fill → select → click → press)
    for (const f of fills) {
      await page.locator(f.selector).first().fill(f.value);
    }
    for (const s of selects) {
      await page.locator(s.selector).first().selectOption(s.value);
    }
    for (const css of clicks) {
      await page.locator(css).first().click();
    }
    for (const key of pressKeys) {
      await page.keyboard.press(key);
    }

    if (waitForSelector) {
      await page.waitForSelector(waitForSelector, { timeout });
    }
    if (scrollToBottom) {
      await scrollPage(page);
    }

    // Outputs
    if (screenshotFile) {
      await page.screenshot({ path: screenshotFile, fullPage: true });
      console.error(`Screenshot saved to ${screenshotFile}`);
    }

    if (pdfFile) {
      await page.pdf({ path: pdfFile, format: "A4" });
      console.error(`PDF saved to ${pdfFile}`);
    }

    if (linksMode) {
      const links = await page.evaluate(() =>
        Array.from(document.querySelectorAll("a[href]")).map((a) => ({
          href: (a as HTMLAnchorElement).href,
          text: (a as HTMLAnchorElement).innerText.trim(),
        })),
      );
      console.log(JSON.stringify(links, null, 2));
    } else if (evaluateExpr) {
      const result = await page.evaluate(evaluateExpr);
      console.log(JSON.stringify(result, null, 2));
    } else if (!noExtract) {
      console.log(await extractContent(page, format, selector));
    }

    await context.close();
  } finally {
    await browser.close();
  }
}

await main();
