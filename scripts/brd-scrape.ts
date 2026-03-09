#!/usr/bin/env bun
/**
 * brd-scrape — Playwright scraper routed through BrightData remote browser.
 *
 * Credentials are read from ~/.openclaw/brightdata-endpoint (a single line
 * containing the WSS URL). The agent never sees or sets the endpoint URL.
 *
 * Usage:
 *   brd-scrape <url> [options]
 *
 * Options:
 *   --format text|html|markdown   Output format (default: text)
 *   --selector <css>              Extract a specific element instead of full page
 *   --screenshot <file>           Save a screenshot to <file>
 *   --wait-for <css>              Wait for this selector before extracting
 *   --timeout <ms>                Navigation timeout in ms (default: 30000)
 *   -h, --help                    Show help
 */

import { readFile } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";

// ---------------------------------------------------------------------------
// Arg parsing
// ---------------------------------------------------------------------------

function usage(): void {
  console.log(
    `Usage: brd-scrape <url> [--format text|html|markdown] [--selector <css>]
       [--screenshot <file>] [--wait-for <css>] [--timeout <ms>]`,
  );
}

const args = process.argv.slice(2);
if (!args.length || args[0] === "-h" || args[0] === "--help") {
  usage();
  process.exit(args.length ? 0 : 1);
}

let url = "";
let format: "text" | "html" | "markdown" = "text";
let selector = "";
let screenshotFile = "";
let waitFor = "";
let timeout = 30_000;

for (let i = 0; i < args.length; i++) {
  const a = args[i];
  if (a === "--format") {
    const v = args[++i];
    if (v !== "text" && v !== "html" && v !== "markdown") {
      console.error(`Unknown format: ${v}. Must be text, html, or markdown.`);
      process.exit(1);
    }
    format = v;
  } else if (a === "--selector") {
    selector = args[++i] ?? "";
  } else if (a === "--screenshot") {
    screenshotFile = args[++i] ?? "";
  } else if (a === "--wait-for") {
    waitFor = args[++i] ?? "";
  } else if (a === "--timeout") {
    timeout = parseInt(args[++i] ?? "30000", 10);
  } else if (!a.startsWith("-")) {
    url = a;
  } else {
    console.error(`Unknown option: ${a}`);
    usage();
    process.exit(1);
  }
}

if (!url) {
  console.error("Error: URL is required.");
  usage();
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
// Text-to-markdown: minimal conversion for readability
// ---------------------------------------------------------------------------

function htmlToMarkdown(html: string): string {
  // Very lightweight HTML→Markdown for agent consumption.
  // For full fidelity, use a dedicated library; this covers common cases.
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
// Main
// ---------------------------------------------------------------------------

const endpoint = await loadEndpoint();

// Dynamic import so startup doesn't fail if playwright isn't installed
const { chromium } = await import("playwright").catch(() => {
  console.error("playwright package not found. Install with: npm install -g playwright");
  process.exit(1);
});

const browser = await chromium.connectOverCDP(endpoint);
try {
  const context = await browser.newContext();
  const page = await context.newPage();

  await page.goto(url, { waitUntil: "domcontentloaded", timeout });

  if (waitFor) {
    await page.waitForSelector(waitFor, { timeout });
  }

  if (screenshotFile) {
    await page.screenshot({ path: screenshotFile, fullPage: true });
    console.log(`Screenshot saved to ${screenshotFile}`);
  }

  // Extract content
  if (format === "html") {
    const html = selector ? await page.locator(selector).first().innerHTML() : await page.content();
    console.log(html);
  } else if (format === "markdown") {
    const html = selector
      ? await page.locator(selector).first().innerHTML()
      : await page.evaluate(() => document.body.innerHTML);
    console.log(htmlToMarkdown(html));
  } else {
    // text (default)
    const text = selector
      ? await page.locator(selector).first().innerText()
      : await page.evaluate(() => document.body.innerText);
    console.log(text);
  }

  await context.close();
} finally {
  await browser.close();
}
