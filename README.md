# Full Spectrum Recon (FSRecon)

![FSRecon Banner](https://github.com/user-attachments/assets/3998573b-9bfd-42e9-9bf4-fc096eda9d29)

A modular domain reconnaissance framework for security professionals and bug bounty hunters.

## Features

FSRecon provides a comprehensive set of features for domain reconnaissance:

- **Port Scanning**: Discover open ports using nmap/masscan
- **Subdomain Enumeration**: Find subdomains using subfinder/amass
- **HTTP Probing**: Identify live web services using httpx/httprobe
- **Path Discovery**: Discover accessible paths using gobuster/dirb/dirsearch
- **Screenshot Capture**: Capture screenshots of web pages using gowitness/aquatone
- **Vulnerability Scanning**: Scan for vulnerabilities using nuclei
- **Comprehensive Reporting**: Generate reports in text, JSON, and HTML formats

## Installation

### Prerequisites

FSRecon requires the following tools to be installed:

- Bash (version 4.0+)
- One of the following for each scan type:
  - Port scanning: nmap or masscan
  - Subdomain enumeration: subfinder or amass
  - HTTP probing: httpx or httprobe
  - Path discovery: gobuster, dirb, or dirsearch
  - Screenshots: gowitness or aquatone
  - Vulnerability scanning: nuclei

### Manual Installation

1. Clone the repository:

```bash
git clone https://github.com/yourusername/fsrecon.git
cd fsrecon
```

2. Make the main script executable:

```bash
chmod +x fsrecon.sh
```

### NixOS Installation

FSRecon can be installed on NixOS using the provided Nix file:

```bash
nix-env -i -f fsrecon.nix
```

## Usage

### Basic Usage

Run a scan on a domain with all default settings:

```bash
./fsrecon.sh example.com
```

### Command Line Options

```
Usage: ./fsrecon.sh [options] domain1.com domain2.com ...

Options:
  -h, --help                 Show this help message
  -c, --config FILE          Use custom configuration file
  -o, --output DIR           Set output directory
  -v, --verbose              Enable verbose output
  -r, --resume               Resume previous scan
  -t, --type TYPE            Specify scan type(s) (comma-separated)
                             Available types: port,subdomain,http,path,screenshot,vuln
  --no-ports                 Skip port scanning
  --no-subdomains            Skip subdomain enumeration
  --no-http                  Skip HTTP probing
  --no-paths                 Skip path discovery
  --no-screenshots           Skip screenshotting
  --no-vulns                 Skip vulnerability scanning
  --protocol PROTOCOL        Set default protocol (http/https)
  --threads NUM              Set maximum number of threads
  --delay SECONDS            Set delay between requests
  --rate-limit NUM           Set rate limit (requests per second)
  --report-format FORMAT     Set report format (text, json, html, all)
```

### Examples

Scan a domain with verbose output:

```bash
./fsrecon.sh -v example.com
```

Scan multiple domains:

```bash
./fsrecon.sh example.com example.org example.net
```

Perform only port scanning and HTTP probing:

```bash
./fsrecon.sh -t port,http example.com
```

Skip vulnerability scanning and path discovery:

```bash
./fsrecon.sh --no-vulns --no-paths example.com
```

Generate reports in all available formats:

```bash
./fsrecon.sh --report-format all example.com
```

## Configuration

FSRecon can be configured using a configuration file. The default configuration file is located at `config/default.conf`.

### Creating a Custom Configuration

You can create a custom configuration file by copying the default configuration:

```bash
cp config/default.conf config/custom.conf
```

Then edit the `config/custom.conf` file to suit your needs and run FSRecon with the custom configuration:

```bash
./fsrecon.sh -c config/custom.conf example.com
```

### Configuration Options

The configuration file includes settings for:

- Base directories for output, wordlists, and temporary files
- Logging settings
- Scan types to enable/disable
- Default protocols
- Concurrency settings
- Tool selection and options
- Wordlist selection

## Output

FSRecon outputs results to the directory specified by the `-o` option or to the default output directory (`./output`).

Each scan creates a timestamped directory under the output directory, containing:

- Domain-specific directories with results from each scan type
- Text, JSON, and/or HTML reports (depending on the `--report-format` option)
- Master summary report

## Project Structure

```
fsrecon/
├── config/
│   └── default.conf         # Default configuration file
├── lib/
│   ├── core.sh             # Core functionality
│   ├── logger.sh           # Logging system
│   ├── utils.sh            # Utility functions
│   └── reporting.sh        # Reporting system
├── modules/
│   ├── port/               # Port scanning module
│   ├── subdomain/          # Subdomain enumeration module
│   ├── http/               # HTTP probing module
│   ├── path/               # Path discovery module
│   ├── screenshot/         # Screenshot capture module
│   └── vuln/               # Vulnerability scanning module
├── wordlists/              # Directory for wordlists
├── fsrecon.sh              # Main script
├── fsrecon.nix             # NixOS packaging
└── README.md               # This file

## Extending FSRecon

FSRecon is designed to be modular and extensible. You can add new modules or modify existing ones to suit your needs.

### Creating a New Module

To create a new module:

1. Create a new directory under `modules/` with the name of your module
2. Create a `main.sh` file in your module directory
3. Implement the required module functions:
   - `module_init()`: Initialize the module
   - `module_register()`: Register module functions
   - At least one function to perform the module's task

See existing modules for examples of how to structure your module.

### Custom Tool Integration

FSRecon supports different tools for each scan type. To add support for a new tool:

1. Edit the module's main function to handle the new tool
2. Update the configuration file to include options for the tool

## Reporting

FSRecon generates comprehensive reports in various formats:

### Text Report

The text report provides a summary of all scan results in plain text format.

### JSON Report

The JSON report contains structured data for all scan results, making it easy to parse and integrate with other tools.

### HTML Report

The HTML report provides a visual representation of the scan results, including interactive elements and screenshots.

## Logging

FSRecon uses a structured logging system with multiple log levels:

- **DEBUG**: Detailed debugging information
- **INFO**: General information about scan progress
- **WARN**: Warning messages
- **ERROR**: Error messages

You can set the log level using the `-v` flag or in the configuration file.

## Security and Ethics

Always ensure you have permission to scan domains before using FSRecon. Unauthorized scanning may be illegal in many jurisdictions.

FSRecon includes features to help minimize impact on target systems:

- Thread limiting
- Rate limiting
- Delay between requests

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

FSRecon uses several open-source tools and libraries. We acknowledge and thank their authors and contributors.