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
HTTP_PROBER="httpx"             # Options: httpx, httprobe, etc.
SCREENSHOT_TOOL="gowitness"     # Options: gowitness, aquatone, etc.
VULN_SCANNER="nuclei"           # Options: nuclei

# Tool options
NMAP_OPTIONS="-F"               # -F for fast scan, -p- for all ports, etc.
SUBFINDER_OPTIONS="-silent"     # Additional subfinder options
GOBUSTER_OPTIONS="-q"           # Additional gobuster options
HTTPX_OPTIONS="-silent -no-color" # Base options for httpx, details controlled in function
GOWITNESS_OPTIONS=""            # Additional gowitness options (e.g., --disable-db)
NUCLEI_OPTIONS="-silent -severity medium,high,critical" # Default nuclei options (e.g., add -t /path/to/templates)
# NUCLEI_TEMPLATES_DIR="/path/to/nuclei-templates" # Uncomment and set if using custom/specific templates

# Wordlists
DIR_WORDLIST="$WORDLIST_DIR/directories/directory-list-2.3-medium.txt"
# Uncomment and set if you need these specific wordlists
#SUBDOMAIN_WORDLIST="$WORDLIST_DIR/subdomains/subdomains.txt"
#VHOST_WORDLIST="$WORDLIST_DIR/vhosts/vhosts.txt"

# Scan configuration
SCAN_PORTS=true                 # Set to 'false' to skip port scanning
SCAN_SUBDOMAINS=true            # Set to 'false' to skip subdomain enumeration
SCAN_PATHS=true                 # Set to 'false' to skip path discovery
SCAN_HTTP_PROBE=true            # Set to 'false' to skip HTTP probing
SCAN_SCREENSHOTS=true           # Set to 'false' to skip screenshotting
SCAN_VULNERABILITIES=true       # Set to 'false' to skip vulnerability scanning
HTTP_PROTOCOL="http"            # Default protocol for path scanning if not probing

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

    if [ "$SCAN_HTTP_PROBE" = true ] && ! command -v $HTTP_PROBER &> /dev/null; then
        missing_tools+=("$HTTP_PROBER")
    fi

    if [ "$SCAN_SCREENSHOTS" = true ] && ! command -v $SCREENSHOT_TOOL &> /dev/null; then
        missing_tools+=("$SCREENSHOT_TOOL")
    fi

    if [ "$SCAN_VULNERABILITIES" = true ] && ! command -v $VULN_SCANNER &> /dev/null; then
        missing_tools+=("$VULN_SCANNER")
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

# HTTP/HTTPS Probing function
probe_http() {
    local domain=$1
    local domain_dir=$2
    local subdomain_file="$domain_dir/subdomains.txt"
    local live_hosts_file="$domain_dir/live_hosts.txt" # Plain URL list
    local live_hosts_details_json="$domain_dir/live_hosts_details.json" # Detailed JSON output
    
    echo "[+] Probing discovered subdomains for live web servers..."
    echo "## LIVE WEB HOSTS" >> "$SUMMARY_FILE"
    
    if [ ! -f "$subdomain_file" ] || [ ! -s "$subdomain_file" ]; then
        echo "Subdomain file ($subdomain_file) not found or empty. Skipping HTTP probing." >> "$SUMMARY_FILE"
        echo "" >> "$SUMMARY_FILE"
        return
    fi
    
    case $HTTP_PROBER in
        "httpx")
            # Add the base domain itself to the list for probing
            # Output plain URLs to live_hosts.txt
            echo "$domain" | cat - "$subdomain_file" | httpx $HTTPX_OPTIONS -o "$live_hosts_file"

            # Output detailed JSON to live_hosts_details.json and suppress stdout
            echo "$domain" | cat - "$subdomain_file" | httpx $HTTPX_OPTIONS -json -o "$live_hosts_details_json" > /dev/null 2>&1
            ;;
        "httprobe")
            # Example httprobe command - adjust as needed (doesn't support JSON details easily)
            cat "$subdomain_file" | httprobe -c 50 > "$live_hosts_file"
            ;;
        *)
            echo "Unsupported HTTP prober: $HTTP_PROBER" >> "$SUMMARY_FILE"
            ;;
    esac
    
    # Count and list live hosts for the summary
    if [ -f "$live_hosts_file" ] && [ -s "$live_hosts_file" ]; then
        LIVE_HOST_COUNT=$(wc -l < "$live_hosts_file")
        echo "Found $LIVE_HOST_COUNT live web hosts:" >> "$SUMMARY_FILE"
        cat "$live_hosts_file" >> "$SUMMARY_FILE"
    else
        echo "No live web hosts found." >> "$SUMMARY_FILE"
    fi
    
    echo "" >> "$SUMMARY_FILE"
    echo "Plain list of live hosts available at: $live_hosts_file" >> "$SUMMARY_FILE"
    if [ -f "$live_hosts_details_json" ] && [ -s "$live_hosts_details_json" ]; then
        echo "Detailed JSON output available at: $live_hosts_details_json" >> "$SUMMARY_FILE"
    fi
    echo "" >> "$SUMMARY_FILE"
}

# Screenshotting function
take_screenshots() {
    local domain_dir=$1
    local live_hosts_file="$domain_dir/live_hosts.txt"
    local screenshot_dir="$domain_dir/screenshots"
    
    echo "[+] Taking screenshots of live web hosts..."
    echo "## SCREENSHOTS" >> "$SUMMARY_FILE"
    
    if [ ! -f "$live_hosts_file" ] || [ ! -s "$live_hosts_file" ]; then
        echo "Live hosts file ($live_hosts_file) not found or empty. Skipping screenshotting." >> "$SUMMARY_FILE"
        echo "" >> "$SUMMARY_FILE"
        return
    fi
    
    mkdir -p "$screenshot_dir"
    
    case $SCREENSHOT_TOOL in
        "gowitness")
            # Gowitness needs URLs, extract from httpx output if needed
            # Assuming live_hosts.txt contains one URL per line (may need adjustment based on httpx output format)
            gowitness file -f "$live_hosts_file" -d "$screenshot_dir" --no-redirect $GOWITNESS_OPTIONS > /dev/null 2>&1
            ;;
        "aquatone")
            # Example aquatone command - adjust as needed
            # Aquatone might need specific input format
            cat "$live_hosts_file" | aquatone -out "$screenshot_dir" > /dev/null 2>&1
            ;;
        *)
            echo "Unsupported screenshot tool: $SCREENSHOT_TOOL" >> "$SUMMARY_FILE"
            ;;
    esac
    
    # Check if screenshots were generated (basic check)
    if [ -d "$screenshot_dir" ] && [ "$(ls -A $screenshot_dir)" ]; then
        echo "Screenshots saved in: $screenshot_dir" >> "$SUMMARY_FILE"
        # Optionally generate an HTML report if the tool supports it
        if [ "$SCREENSHOT_TOOL" = "gowitness" ]; then
             gowitness report generate -d "$screenshot_dir" > /dev/null 2>&1
             echo "Gowitness report generated in: $screenshot_dir/report.html" >> "$SUMMARY_FILE"
        fi
    else
        echo "No screenshots were generated or the directory is empty." >> "$SUMMARY_FILE"
    fi
    
    echo "" >> "$SUMMARY_FILE"
}

# Vulnerability scanning function
scan_vulnerabilities() {
    local domain_dir=$1
    local live_hosts_file="$domain_dir/live_hosts.txt"
    local vuln_output_file="$domain_dir/vulnerabilities.txt"
    
    echo "[+] Scanning live hosts for vulnerabilities..."
    echo "## VULNERABILITIES (Nuclei Scan)" >> "$SUMMARY_FILE"
    
    if [ ! -f "$live_hosts_file" ] || [ ! -s "$live_hosts_file" ]; then
        echo "Live hosts file ($live_hosts_file) not found or empty. Skipping vulnerability scanning." >> "$SUMMARY_FILE"
        echo "" >> "$SUMMARY_FILE"
        return
    fi
    
    # Prepare Nuclei command
    local nuclei_cmd="$VULN_SCANNER -l \"$live_hosts_file\" -o \"$vuln_output_file\" $NUCLEI_OPTIONS"
    
    # Add template directory if specified
    if [ -n "$NUCLEI_TEMPLATES_DIR" ]; then
        nuclei_cmd+=" -t \"$NUCLEI_TEMPLATES_DIR\""
    fi
    
    # Execute Nuclei
    eval $nuclei_cmd > /dev/null 2>&1
    
    # Summarize results
    if [ -f "$vuln_output_file" ] && [ -s "$vuln_output_file" ]; then
        VULN_COUNT=$(wc -l < "$vuln_output_file")
        echo "Found $VULN_COUNT potential vulnerabilities/findings:" >> "$SUMMARY_FILE"
        # Add first few lines to summary for quick view (optional)
        head -n 10 "$vuln_output_file" >> "$SUMMARY_FILE"
        if [ $VULN_COUNT -gt 10 ]; then
            echo "..." >> "$SUMMARY_FILE"
            echo "(See full list below)" >> "$SUMMARY_FILE"
        fi
        echo "" >> "$SUMMARY_FILE" # Separator
        cat "$vuln_output_file" >> "$SUMMARY_FILE" # Full list
    else
        echo "No vulnerabilities found matching the criteria." >> "$SUMMARY_FILE"
    fi
    
    echo "" >> "$SUMMARY_FILE"
    echo "Full vulnerability scan results available at: $vuln_output_file" >> "$SUMMARY_FILE"
    echo "" >> "$SUMMARY_FILE"
}


# Path discovery function
scan_paths() {
    local domain=$1
    local domain_dir=$2
    local live_hosts_file="$domain_dir/live_hosts.txt" # Expect live hosts file path
    local paths_output_file="$domain_dir/paths_discovered.txt" # Consolidated output
    
    echo "[+] Discovering web paths..."
    echo "## WEB PATHS" >> "$SUMMARY_FILE"
    
    # Determine targets: use live hosts if available, otherwise use base domain
    local targets=()
    if [ "$SCAN_HTTP_PROBE" = true ] && [ -f "$live_hosts_file" ] && [ -s "$live_hosts_file" ]; then
        echo "Scanning paths on live hosts found by HTTP probe."
        mapfile -t targets < <(cat "$live_hosts_file" | sed 's/ .*//') # Extract URL part if httpx output includes extra info
    else
        echo "HTTP probing skipped or no live hosts found. Scanning base domain: ${HTTP_PROTOCOL}://$domain"
        targets+=("${HTTP_PROTOCOL}://$domain")
    fi
    
    # Clear previous results if any
    > "$paths_output_file"
    
    local total_paths_found=0
    
    for target_url in "${targets[@]}"; do
        echo "  Scanning paths on: $target_url"
        local temp_output="${paths_output_file}.tmp"
        
        case $PATH_SCANNER in
            "gobuster")
                gobuster dir -u "$target_url" -w "$DIR_WORDLIST" $GOBUSTER_OPTIONS -o "$temp_output" > /dev/null 2>&1
                ;;
            "dirb")
                dirb "$target_url" "$DIR_WORDLIST" -o "$temp_output" -S > /dev/null 2>&1
                ;;
            "dirsearch")
                # dirsearch output needs careful handling depending on version/options
                dirsearch -u "$target_url" -w "$DIR_WORDLIST" --simple-report -o "$temp_output" > /dev/null 2>&1
                ;;
            *)
                echo "Unsupported path scanner: $PATH_SCANNER" >> "$SUMMARY_FILE"
                continue # Skip to next target
                ;;
        esac
        
        # Append results to main file and summary
        local count=0 # Initialize count
        if [ -f "$temp_output" ] && [ -s "$temp_output" ]; then
            count=$(wc -l < "$temp_output")
            echo "  Found $count paths on $target_url"
            echo "### Paths for $target_url ###" >> "$paths_output_file"
            cat "$temp_output" >> "$paths_output_file"
            echo "" >> "$paths_output_file"
            
            echo "### Paths for $target_url ###" >> "$SUMMARY_FILE"
            cat "$temp_output" >> "$SUMMARY_FILE"
            echo "" >> "$SUMMARY_FILE"
            
            total_paths_found=$((total_paths_found + count))
            rm "$temp_output"
        else
             echo "  No paths found on $target_url"
        fi
    done
    
    # Final summary count
    if [ $total_paths_found -gt 0 ]; then
        echo "Total accessible paths found across all targets: $total_paths_found" >> "$SUMMARY_FILE"
    else
        echo "No accessible paths found across all targets." >> "$SUMMARY_FILE"
    fi
    
    echo "" >> "$SUMMARY_FILE"
    echo "Full path discovery results available at: $paths_output_file" >> "$SUMMARY_FILE"
    echo "" >> "$SUMMARY_FILE"
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
    [ "$SCAN_HTTP_PROBE" = true ] && probe_http "$domain" "$domain_dir"
    [ "$SCAN_VULNERABILITIES" = true ] && scan_vulnerabilities "$domain_dir"
    [ "$SCAN_SCREENSHOTS" = true ] && take_screenshots "$domain_dir"
    [ "$SCAN_PATHS" = true ] && scan_paths "$domain" "$domain_dir" # Pass domain_dir implicitly containing live_hosts.txt
    
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
    echo "- HTTP Prober: $HTTP_PROBER (Enabled: $SCAN_HTTP_PROBE)" >> "$MASTER_SUMMARY"
    echo "- Vulnerability Scanner: $VULN_SCANNER (Enabled: $SCAN_VULNERABILITIES)" >> "$MASTER_SUMMARY"
    echo "- Screenshot Tool: $SCREENSHOT_TOOL (Enabled: $SCAN_SCREENSHOTS)" >> "$MASTER_SUMMARY"
    echo "- Path Scanner: $PATH_SCANNER (Enabled: $SCAN_PATHS)" >> "$MASTER_SUMMARY"
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
    echo "  --no-probe                 Skip HTTP probing"
    echo "  --no-vulns                 Skip vulnerability scanning"
    echo "  --no-screenshots           Skip screenshotting"
    echo "  --no-paths                 Skip path discovery"
    echo "  --protocol <http|https>    Set default protocol for path scan if not probing (default: http)"
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
            --no-probe)
                SCAN_HTTP_PROBE=false
                shift
                ;;
            --no-vulns)
                SCAN_VULNERABILITIES=false
                shift
                ;;
            --no-screenshots)
                SCAN_SCREENSHOTS=false
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
