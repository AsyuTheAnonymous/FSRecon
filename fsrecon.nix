{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  name = "fsrecon-environment";
  
  buildInputs = with pkgs; [
    # Core utils
    coreutils
    findutils
    gnugrep
    gnused
    gawk
    jq
    
    # Scanning tools
    nmap        # Port scanning
    masscan     # Alternative port scanner
    subfinder   # Subdomain enumeration
    amass       # Alternative subdomain enumeration
    httpx       # HTTP probing
    httprobe    # Alternative HTTP probing
    gobuster    # Path discovery
    dirb        # Alternative path discovery
    gowitness   # Screenshot capture
    
    # Optional dependencies
    nuclei      # Vulnerability scanning
    python3     # For JSON parsing
    chromium    # Required by gowitness
    
    # Development tools
    bash
  ];
  
  shellHook = ''
    echo "FSRecon NixOS Development Environment"
    echo "====================================="
    echo "Available tools:"
    echo " - nmap: Port scanning"
    echo " - subfinder: Subdomain enumeration" 
    echo " - httpx: HTTP probing"
    echo " - gobuster: Path discovery"
    echo " - gowitness: Screenshot capture"
    echo " - nuclei: Vulnerability scanning"
    echo ""
    echo "Run './fsrecon.sh --help' to get started"
    echo ""
    
    # Create required directories if they don't exist
    mkdir -p output
    mkdir -p wordlists/directories
    
    # Download common wordlists if they don't exist
    if [ ! -f wordlists/directories/directory-list-2.3-medium.txt ]; then
      echo "Downloading common directory wordlist..."
      mkdir -p wordlists/directories
      curl -s -o wordlists/directories/directory-list-2.3-medium.txt https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/directory-list-2.3-medium.txt
    fi
    
    # Make sure PATH includes all binaries
    export PATH="$PATH:$(dirname $(realpath ./fsrecon.sh))"
  '';
}
