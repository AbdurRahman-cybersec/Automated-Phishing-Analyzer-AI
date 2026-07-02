#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const os = require('os');

function isExecutable(filePath) {
  try {
    fs.accessSync(filePath, fs.constants.X_OK);
    return true;
  } catch {
    return false;
  }
}

function findFirstExecutable(patternRoot, segments) {
  if (!fs.existsSync(patternRoot)) return null;

  const walk = (base, remaining) => {
    if (!remaining.length) {
      return isExecutable(base) ? base : null;
    }

    const [segment, ...rest] = remaining;
    if (segment === '*') {
      let entries = [];
      try {
        entries = fs.readdirSync(base, { withFileTypes: true });
      } catch {
        return null;
      }

      for (const entry of entries) {
        const found = walk(path.join(base, entry.name), rest);
        if (found) return found;
      }
      return null;
    }

    return walk(path.join(base, segment), rest);
  };

  return walk(patternRoot, segments);
}

function findBrowserExecutable() {
  const envPath = process.env.BROWSER_PATH || process.env.PUPPETEER_EXECUTABLE_PATH;
  if (envPath && isExecutable(envPath)) return envPath;

  const candidates = [
    '/usr/bin/google-chrome',
    '/usr/bin/google-chrome-stable',
    '/usr/bin/chromium',
    '/usr/bin/chromium-browser',
    '/usr/local/bin/google-chrome',
    '/usr/local/bin/chromium',
    '/snap/bin/chromium',
    '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
    '/Applications/Chromium.app/Contents/MacOS/Chromium',
  ];

  for (const candidate of candidates) {
    if (isExecutable(candidate)) return candidate;
  }

  const home = os.homedir();
  const cacheRoot = path.join(home, '.cache', 'ms-playwright');
  return (
    findFirstExecutable(cacheRoot, ['*', 'chrome-linux64', 'chrome']) ||
    findFirstExecutable(cacheRoot, ['*', 'chrome-linux', 'chrome']) ||
    findFirstExecutable(path.join(home, '.cache', 'puppeteer', 'chrome'), ['*', 'chrome-linux64', 'chrome']) ||
    findFirstExecutable(path.join(home, '.cache', 'puppeteer', 'chrome'), ['*', 'chrome-linux', 'chrome'])
  );
}

async function main() {
  const [, , targetUrl, outputPath] = process.argv;
  if (!targetUrl || !outputPath) {
    console.error('Usage: node capture_page.js <url> <output.png>');
    process.exit(1);
  }

  let puppeteer;
  try {
    puppeteer = require('puppeteer-core');
  } catch (error) {
    console.error('Missing dependency: install npm packages first (puppeteer-core).');
    process.exit(1);
  }

  const executablePath = findBrowserExecutable();
  if (!executablePath) {
    console.error('No local Chrome/Chromium executable found. Install Chrome/Chromium or set BROWSER_PATH/PUPPETEER_EXECUTABLE_PATH.');
    process.exit(1);
  }

  const browser = await puppeteer.launch({
    executablePath,
    headless: 'new',
    args: [
      '--no-sandbox',
      '--disable-setuid-sandbox',
      '--disable-dev-shm-usage',
      '--disable-crash-reporter',
      '--disable-crashpad',
      '--no-first-run',
      '--no-default-browser-check',
      `--user-data-dir=${fs.mkdtempSync(path.join(os.tmpdir(), 'phishing-preview-'))}`,
    ],
    defaultViewport: { width: 1440, height: 1024 },
  });

  try {
    const page = await browser.newPage();
    await page.goto(targetUrl, { waitUntil: 'networkidle2', timeout: 45000 });
    await page.screenshot({
      path: outputPath,
      type: 'png',
      fullPage: true,
    });

    if (!fs.existsSync(outputPath)) {
      console.error('Screenshot was not written to disk.');
      process.exit(1);
    }

    console.log(path.resolve(outputPath));
  } finally {
    await browser.close();
  }
}

main().catch((error) => {
  console.error(error.message || String(error));
  process.exit(1);
});
