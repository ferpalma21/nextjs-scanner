# Next.js CVE-2025-29927 Vulnerability Scanner

## Overview
This script scans a list of URLs to detect if they are using **Next.js** and determines whether they are vulnerable to **CVE-2025-29927**. It optionally attempts exploitation using a wordlist.

## Features
- Identifies websites using **Next.js**.
- Checks **Next.js version** to determine vulnerability.
- Attempts to exploit vulnerable sites (trial).
- Supports **custom Chromium path** for Puppeteer.
- Allows **URL input** from a file or command-line arguments.
- **Follows redirects** (optional, may cause false positives).
- Outputs results to a **JSON object** or a file.

## Installation
```sh
# Clone the repository
git clone https://github.com/ferpalma21/Automated-Next.js-Security-Scanner-for-CVE-2025-29927.git
cd Automated-Next.js-Security-Scanner-for-CVE-2025-29927.git

# Install dependencies
npm install
```

## Usage
Run the script with different options:
```sh
node index.js -u "https://example.com" -v
```

### Command-line Arguments
| Option | Alias | Description |
|--------|-------|-------------|
| `-u` | `--urls` | List of URLs (space/comma-separated) |
| `-f` | `--file` | File containing URLs (one per line) |
| `-c` | `--chrome` | Path to Chromium (default: `/snap/bin/chromium`) |
| `-o` | `--output` | File to save vulnerable site results |
| `-v` | `--verbose` | Enables detailed output |
| `-r` | `--redirect` | Follows redirects (optional, may lead to false positives) |
| `-a` | `--attack` | Attempts exploitation (use with caution) |
| `-w` | `--wordlist` | Wordlist file for exploitation |
| `-t` | `--headless` | Runs Puppeteer in headless mode |
| `-x` | `--headers` | If fails to exploit will retry with different headers |

## Example Usages

### Scan a single website
```sh
node index.js -u "https://example.com"
```

### Scan multiple websites
```sh
node index.js -u "https://site1.com, https://site2.com"
```

### Scan websites from a file
```sh
node index.js -f urls.txt
```

### Save results to a file
```sh
node index.js -u "https://example.com" -o results.txt
```

### Run in verbose mode
```sh
node index.js -u "https://example.com" -v
```

### Attempt exploitation (use with caution!)
```sh
node index.js -u "https://example.com" -a -w wordlist.txt
```

## Output
- **Verbose Mode (`-v`)**: Detailed logs printed to the console.
- **JSON Output**: When `-v` is not set, results are printed as JSON.
- **File Output (`-o`)**: Saves detected vulnerabilities to a file.

## Example Output (Verbose Mode)
```
Analyzing: https://example.com
https://example.com is running Next.js version: 13.5.9.
Potentially vulnerable to CVE-2025-29927.
```

## Notes
- **Use at your own risk.** Ensure you have permission to scan websites.
- Set the correct **Chromium path** if Puppeteer fails to launch.

## Remediation
Upgrade to Next.js 14.2.25 or 15.2.3 or later. If upgrading is not possible, block the `x-middleware-subrequest` header at the WAF or server level. Patched versions: 15.2.3, 14.2.25, 13.5.9, 12.3.5

## Next Steps
- Error handling and retry logic
- Get emails from website and send an automatic email to the owners of the website

## License
This project is licensed under the MIT License.
