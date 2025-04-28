#!/usr/bin/env bash

# =============================================
#     FULL SPECTRUM RECON v1.0
# =============================================
# A modular domain reconnaissance framework
# Scans for open ports, subdomains, and file paths
# Usage: ./full_spectrum_recon.sh domain1.com domain2.com domain3.com
# =============================================

# ASCII Art Banner
display_banner() {
    echo '
    ███████╗██╗   ██╗██╗     ██╗         ███████╗██████╗ ███████╗ ██████╗████████╗██████╗ ██╗   ██╗███╗   ███╗
    ██╔════╝██║   ██║██║     ██║         ██╔════╝██╔══██╗██╔════╝██╔════╝╚══██╔══╝██╔══██╗██║   ██║████╗ ████║
    █████╗  ██║   ██║██║     ██║         ███████╗██████╔╝█████╗  ██║        ██║   ██████╔╝██║   ██║██╔████╔██║
    ██╔══╝  ██║   ██║██║     ██║         ╚════██║██╔═══╝ ██╔══╝  ██║        ██║   ██╔══██╗██║   ██║██║╚██╔╝██║
    ██║     ╚██████╔╝███████╗███████╗    ███████║██║     ███████╗╚██████╗   ██║   ██║  ██║╚██████╔╝██║ ╚═╝ ██║
    ╚═╝      ╚═════╝ ╚══════╝╚══════╝    ╚══════╝╚═╝     ╚══════╝ ╚═════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═╝     ╚═╝
                                           ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
                                           ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
                                           ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
                                           ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
                                           ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
                                           ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝  v1.0
    '
}

# =============================================
# CONFIGURATION SECTION - Edit these variables
# =============================================

# Base directories
WORDLIST_DIR="/home/asyu/Bug Bounty/Wordlists"
OUTPUT_BASE_DIR="fsr_results"

# Tool selection
PORT_SCANNER="nmap"             # Options: nmap, masscan, etc.
SUBDOMAIN_SCANNER="subfinder"   # Options: subfinder, amass, etc.
PATH_SCANNER="gobuster"         # Options: gobuster, dirb, dirsearch, etc.

# Tool options
NMAP_OPTIONS="-F"               # -F for fast scan, -p- for all ports, etc.
SUBFINDER_OPTIONS="-silent"     # Additional subfinder options
GOBUSTER_OPTIONS="-q"           # Additional gobuster options

# Wordlists
DIR_WORDLIST="$WORDLIST_DIR/directories/directory-list-2.3-medium.txt"
# Uncomment and set if you need these specific wordlists
#SUBDOMAIN_WORDLIST="$WORDLIST_DIR/subdomains/subdomains.txt"
#VHOST_WORDLIST="$WORDLIST_DIR/vhosts/vhosts.txt"

# Scan configuration
SCAN_PORTS=true                 # Set to 'false' to skip port scanning
SCAN_SUBDOMAINS=true            # Set to 'false' to skip subdomain enumeration
SCAN_PATHS=true                 # Set to 'false' to skip path discovery
HTTP_PROTOCOL="http"            # Options: http, https

# =============================================
# FUNCTION DEFINITIONS
# =============================================

# Check if required tools are installed
check_requirements() {
    local missing_tools=()
    
    if [ "$SCAN_PORTS" = true ] && ! command -v $PORT_SCANNER &> /dev/null; then
        missing_tools+=("$PORT_SCANNER")
    fi
    
    if [ "$SCAN_SUBDOMAINS" = true ] && ! command -v $SUBDOMAIN_SCANNER &> /dev/null; then
        missing_tools+=("$SUBDOMAIN_SCANNER")
    fi
    
    if [ "$SCAN_PATHS" = true ] && ! command -v $PATH_SCANNER &> /dev/null; then
        missing_tools+=("$PATH_SCANNER")
    fi
    
    if [ ${#missing_tools[@]} -ne 0 ]; then
        echo "Error: The following required tools are not installed:"
        for tool in "${missing_tools[@]}"; do
            echo "- $tool"
        done
        echo "Please install these tools to continue."
        exit 1
    fi
    
    # Check if wordlists exist
    if [ "$SCAN_PATHS" = true ] && [ ! -f "$DIR_WORDLIST" ]; then
        echo "Error: Directory wordlist not found at $DIR_WORDLIST"
        exit 1
    fi
}

# Setup output directories
setup_directories() {
    # Create timestamp for output directory
    TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    OUTPUT_DIR="${OUTPUT_BASE_DIR}_${TIMESTAMP}"
    mkdir -p "$OUTPUT_DIR"
    echo "Created output directory: $OUTPUT_DIR"
}

# Port scanning function
scan_ports() {
    local domain=$1
    local domain_dir=$2
    
    echo "[+] Scanning for open ports on $domain..."
    echo "## OPEN PORTS" >> "$SUMMARY_FILE"
    
    case $PORT_SCANNER in
        "nmap")
            nmap $NMAP_OPTIONS "$domain" -oN "$domain_dir/ports.txt" > /dev/null 2>&1
            grep "open" "$domain_dir/ports.txt" | grep -v "filtered" >> "$SUMMARY_FILE"
            ;;
        "masscan")
            # Example masscan command - adjust as needed
            masscan -p1-65535 --rate=1000 "$domain" -oG "$domain_dir/ports.txt" > /dev/null 2>&1
            grep "open" "$domain_dir/ports.txt" >> "$SUMMARY_FILE"
            ;;
        *)
            echo "Unsupported port scanner: $PORT_SCANNER" >> "$SUMMARY_FILE"
            ;;
    esac
    
    echo "" >> "$SUMMARY_FILE"
    echo "Full port scan results available at: $domain_dir/ports.txt" >> "$SUMMARY_FILE"
    echo "" >> "$SUMMARY_FILE"
}

# Subdomain enumeration function
scan_subdomains() {
    local domain=$1
    local domain_dir=$2
    
    echo "[+] Enumerating subdomains for $domain..."
    echo "## SUBDOMAINS" >> "$SUMMARY_FILE"
    
    case $SUBDOMAIN_SCANNER in
        "subfinder")
            subfinder -d "$domain" -o "$domain_dir/subdomains.txt" $SUBFINDER_OPTIONS
            ;;
        "amass")
            # Example amass command - adjust as needed
            amass enum -d "$domain" -o "$domain_dir/subdomains.txt" > /dev/null 2>&1
            ;;
        *)
            echo "Unsupported subdomain scanner: $SUBDOMAIN_SCANNER" >> "$SUMMARY_FILE"
            ;;
    esac
    
    # Count and list subdomains for the summary
    if [ -f "$domain_dir/subdomains.txt" ] && [ -s "$domain_dir/subdomains.txt" ]; then
        SUBDOMAIN_COUNT=$(wc -l < "$domain_dir/subdomains.txt")
        echo "Found $SUBDOMAIN_COUNT subdomains:" >> "$SUMMARY_FILE"
        cat "$domain_dir/subdomains.txt" >> "$SUMMARY_FILE"
    else
        echo "No subdomains found." >> "$SUMMARY_FILE"
    fi
    
    echo "" >> "$SUMMARY_FILE"
    echo "Full subdomain list available at: $domain_dir/subdomains.txt" >> "$SUMMARY_FILE"
    echo "" >> "$SUMMARY_FILE"
}

# Path discovery function
scan_paths() {
    local domain=$1
    local domain_dir=$2
    
    echo "[+] Discovering web paths on $domain..."
    echo "## WEB PATHS" >> "$SUMMARY_FILE"
    
    case $PATH_SCANNER in
        "gobuster")
            gobuster dir -u "${HTTP_PROTOCOL}://$domain" -w "$DIR_WORDLIST" $GOBUSTER_OPTIONS -o "$domain_dir/paths.txt" > /dev/null 2>&1
            ;;
        "dirb")
            # Example dirb command - adjust as needed
            dirb "${HTTP_PROTOCOL}://$domain" "$DIR_WORDLIST" -o "$domain_dir/paths.txt" -S > /dev/null 2>&1
            ;;
        "dirsearch")
            # Example dirsearch command - adjust as needed
            dirsearch -u "${HTTP_PROTOCOL}://$domain" -w "$DIR_WORDLIST" -o "$domain_dir/paths.txt" --simple-report > /dev/null 2>&1
            ;;
        *)
            echo "Unsupported path scanner: $PATH_SCANNER" >> "$SUMMARY_FILE"
            ;;
    esac
    
    # Count and list discovered paths for the summary
    if [ -f "$domain_dir/paths.txt" ] && [ -s "$domain_dir/paths.txt" ]; then
        PATH_COUNT=$(wc -l < "$domain_dir/paths.txt")
        echo "Found $PATH_COUNT accessible paths:" >> "$SUMMARY_FILE"
        cat "$domain_dir/paths.txt" >> "$SUMMARY_FILE"
    else
        echo "No accessible paths found." >> "$SUMMARY_FILE"
    fi
    
    echo "" >> "$SUMMARY_FILE"
    echo "Full path discovery results available at: $domain_dir/paths.txt" >> "$SUMMARY_FILE"
}

# Function to scan a single domain
scan_domain() {
    local domain=$1
    local domain_dir="$OUTPUT_DIR/$domain"
    mkdir -p "$domain_dir"
    
    echo "Starting reconnaissance on $domain..."
    
    # Create summary report file
    SUMMARY_FILE="$domain_dir/summary_report.txt"
    echo "===============================================" > "$SUMMARY_FILE"
    echo "      FULL SPECTRUM RECON REPORT" >> "$SUMMARY_FILE"
    echo "      Target: $domain" >> "$SUMMARY_FILE"
    echo "      Generated on $(date)" >> "$SUMMARY_FILE"
    echo "===============================================" >> "$SUMMARY_FILE"
    echo "" >> "$SUMMARY_FILE"
    
    # Run selected scans
    [ "$SCAN_PORTS" = true ] && scan_ports "$domain" "$domain_dir"
    [ "$SCAN_SUBDOMAINS" = true ] && scan_subdomains "$domain" "$domain_dir"
    [ "$SCAN_PATHS" = true ] && scan_paths "$domain" "$domain_dir"
    
    echo "[+] Reconnaissance completed for $domain"
    echo "[+] Summary report available at: $SUMMARY_FILE"
    echo ""
}

# Generate master summary
generate_master_summary() {
    MASTER_SUMMARY="$OUTPUT_DIR/master_summary.txt"
    
    echo "====================================================" > "$MASTER_SUMMARY"
    echo "      FULL SPECTRUM RECON - MASTER REPORT" >> "$MASTER_SUMMARY"
    echo "      Generated on $(date)" >> "$MASTER_SUMMARY"
    echo "====================================================" >> "$MASTER_SUMMARY"
    echo "" >> "$MASTER_SUMMARY"
    
    echo "Scan Configuration:" >> "$MASTER_SUMMARY"
    echo "- Port Scanner: $PORT_SCANNER" >> "$MASTER_SUMMARY"
    echo "- Subdomain Scanner: $SUBDOMAIN_SCANNER" >> "$MASTER_SUMMARY"
    echo "- Path Scanner: $PATH_SCANNER" >> "$MASTER_SUMMARY"
    echo "" >> "$MASTER_SUMMARY"
    
    echo "Domains scanned:" >> "$MASTER_SUMMARY"
    for domain in "$@"; do
        echo "- $domain" >> "$MASTER_SUMMARY"
    done
    
    echo "" >> "$MASTER_SUMMARY"
    echo "Individual reports are available in domain-specific folders." >> "$MASTER_SUMMARY"
    
    echo "Master summary available at: $MASTER_SUMMARY"
}

# Display help information
show_help() {
    echo "Full Spectrum Recon v1.0"
    echo "Usage: $0 [options] domain1.com domain2.com ..."
    echo ""
    echo "Options:"
    echo "  -h, --help                 Show this help message"
    echo "  --no-ports                 Skip port scanning"
    echo "  --no-subdomains            Skip subdomain enumeration"
    echo "  --no-paths                 Skip path discovery"
    echo "  --protocol <http|https>    Set protocol (default: http)"
    echo ""
    echo "Example:"
    echo "  $0 --protocol https example.com"
    echo ""
}

# Parse command line arguments
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_help
                exit 0
                ;;
            --no-ports)
                SCAN_PORTS=false
                shift
                ;;
            --no-subdomains)
                SCAN_SUBDOMAINS=false
                shift
                ;;
            --no-paths)
                SCAN_PATHS=false
                shift
                ;;
            --protocol)
                HTTP_PROTOCOL="$2"
                shift 2
                ;;
            -*)
                echo "Unknown option: $1"
                show_help
                exit 1
                ;;
            *)
                DOMAINS+=("$1")
                shift
                ;;
        esac
    done
}

# =============================================
# MAIN EXECUTION
# =============================================

# Initialize domains array
DOMAINS=()

# Display banner
display_banner

# Parse command line arguments
parse_arguments "$@"

# Display usage if no domains specified
if [ ${#DOMAINS[@]} -eq 0 ]; then
    show_help
    exit 1
fi

# Run setup functions
check_requirements
setup_directories

echo "Starting Full Spectrum Recon on $(date)"
echo "=================================="

# Process each domain
for domain in "${DOMAINS[@]}"; do
    scan_domain "$domain"
done

# Generate master summary
generate_master_summary "${DOMAINS[@]}"

echo "=================================="
echo "Full Spectrum Recon completed on $(date)"
echo "All results stored in: $OUTPUT_DIR"