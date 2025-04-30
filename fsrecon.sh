#!/usr/bin/env bash
# fsrecon.sh - Full Spectrum Recon main script

# Set strict mode
set -euo pipefail

# Determine script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source core library
source "${SCRIPT_DIR}/lib/core.sh"

# Global variables
VERSION="2.0.0"
CONFIG_FILE="${SCRIPT_DIR}/config/default.conf"
DOMAINS=()
VERBOSE=false
RESUME=false
OUTPUT_DIR=""
SCAN_TYPES=()

# Display banner
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
                                           ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝  v'"${VERSION}"'
    '
}

# Display help message
show_help() {
    echo "Full Spectrum Recon v${VERSION}"
    echo "Usage: $0 [options] domain1.com domain2.com ..."
    echo ""
    echo "Options:"
    echo "  -h, --help                 Show this help message"
    echo "  -c, --config FILE          Use custom configuration file"
    echo "  -o, --output DIR           Set output directory"
    echo "  -v, --verbose              Enable verbose output"
    echo "  -r, --resume               Resume previous scan"
    echo "  -t, --type TYPE            Specify scan type(s) (comma-separated)"
    echo "                             Available types: port,subdomain,http,path,screenshot,vuln"
    echo "  --no-ports                 Skip port scanning"
    echo "  --no-subdomains            Skip subdomain enumeration"
    echo "  --no-http                  Skip HTTP probing"
    echo "  --no-paths                 Skip path discovery"
    echo "  --no-screenshots           Skip screenshotting"
    echo "  --no-vulns                 Skip vulnerability scanning"
    echo "  --protocol PROTOCOL        Set default protocol (http/https)"
    echo "  --threads NUM              Set maximum number of threads"
    echo "  --delay SECONDS            Set delay between requests"
    echo "  --rate-limit NUM           Set rate limit (requests per second)"
    echo "  --report-format FORMAT     Set report format (text, json, html, all)"
    echo ""
    echo "Examples:"
    echo "  $0 example.com                    # Scan example.com with default settings"
    echo "  $0 -v -t port,http example.com    # Verbose scan of ports and HTTP services"
    echo "  $0 --no-vulns --no-paths example.com   # Skip vulnerability and path scanning"
    echo ""
}

# Parse command line arguments
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help)
                show_help
                exit 0
                ;;
            -c|--config)
                CONFIG_FILE="$2"
                shift 2
                ;;
            -o|--output)
                OUTPUT_DIR="$2"
                shift 2
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -r|--resume)
                RESUME=true
                shift
                ;;
            -t|--type)
                IFS=',' read -ra SCAN_TYPES <<< "$2"
                shift 2
                ;;
            --no-ports)
                export SCANNING_SCAN_PORTS=false
                shift
                ;;
            --no-subdomains)
                export SCANNING_SCAN_SUBDOMAINS=false
                shift
                ;;
            --no-http)
                export SCANNING_SCAN_HTTP=false
                shift
                ;;
            --no-paths)
                export SCANNING_SCAN_PATHS=false
                shift
                ;;
            --no-screenshots)
                export SCANNING_SCAN_SCREENSHOTS=false
                shift
                ;;
            --no-vulns)
                export SCANNING_SCAN_VULNERABILITIES=false
                shift
                ;;
            --protocol)
                export SCANNING_DEFAULT_PROTOCOL="$2"
                shift 2
                ;;
            --threads)
                export SCANNING_MAX_THREADS="$2"
                shift 2
                ;;
            --delay)
                export SCANNING_THREAD_DELAY="$2"
                shift 2
                ;;
            --rate-limit)
                export SCANNING_RATE_LIMIT="$2"
                shift 2
                ;;
            --report-format)
                export REPORTING_FORMAT="$2"
                shift 2
                ;;
            -*)
                echo "Error: Unknown option $1"
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

# Initialize FSRecon
initialize() {
    # Initialize core systems first
    init_fsrecon
    
    # Now we can use logging functions
    log_debug "Loading configuration from $CONFIG_FILE"
    load_config "$CONFIG_FILE"
    
    # Set log level based on verbose flag
    if [[ "$VERBOSE" == true ]]; then
        export LOGGER_LEVEL=$LOG_LEVEL_DEBUG
    fi
    
    # Set output directory if provided
    if [[ -n "$OUTPUT_DIR" ]]; then
        export GENERAL_OUTPUT_DIR="$OUTPUT_DIR"
    fi
    
    # Load modules
    load_modules
    
    # Filter scan types if specified
    if [[ ${#SCAN_TYPES[@]} -gt 0 ]]; then
        # Disable all scan types
        export SCANNING_SCAN_PORTS=false
        export SCANNING_SCAN_SUBDOMAINS=false
        export SCANNING_SCAN_HTTP=false
        export SCANNING_SCAN_PATHS=false
        export SCANNING_SCAN_SCREENSHOTS=false
        export SCANNING_SCAN_VULNERABILITIES=false
        
        # Enable only specified scan types
        for type in "${SCAN_TYPES[@]}"; do
            case "$type" in
                "port")
                    export SCANNING_SCAN_PORTS=true
                    ;;
                "subdomain")
                    export SCANNING_SCAN_SUBDOMAINS=true
                    ;;
                "http")
                    export SCANNING_SCAN_HTTP=true
                    ;;
                "path")
                    export SCANNING_SCAN_PATHS=true
                    ;;
                "screenshot")
                    export SCANNING_SCAN_SCREENSHOTS=true
                    ;;
                "vuln")
                    export SCANNING_SCAN_VULNERABILITIES=true
                    ;;
                *)
                    log_warn "Unknown scan type: $type"
                    ;;
            esac
        done
    fi
}

# Process a single domain
process_domain() {
    local domain="$1"
    local domain_dir="${FSRECON_RUN_DIR}/${domain}"
    
    log_info "Processing domain: $domain"
    
    # Create domain directory
    mkdir -p "$domain_dir"
    
    # Validate domain
    if ! validate_domain "$domain"; then
        log_error "Invalid domain: $domain"
        return 1
    fi
    
    # Run port scanning if enabled
    if [[ "$(get_config scanning scan_ports "true")" == "true" ]]; then
        log_info "Starting port scan for $domain"
        port_scan "$domain" "${domain_dir}/port"
        
        # Parse port results
        port_parse_results "${domain_dir}/port"
    else
        log_debug "Port scanning disabled for $domain"
    fi
    
    # Run subdomain enumeration if enabled
    if [[ "$(get_config scanning scan_subdomains "true")" == "true" ]]; then
        log_info "Starting subdomain enumeration for $domain"
        subdomain_scan "$domain" "${domain_dir}/subdomain"
        
        # Create targets file for HTTP probing
        if [[ -f "${domain_dir}/subdomain/subdomains.txt" ]]; then
            mkdir -p "${domain_dir}/targets"
            cp "${domain_dir}/subdomain/subdomains.txt" "${domain_dir}/targets/all_targets.txt"
            
            # Add base domain to targets
            echo "$domain" >> "${domain_dir}/targets/all_targets.txt"
            
            # Sort and deduplicate
            sort -u "${domain_dir}/targets/all_targets.txt" -o "${domain_dir}/targets/all_targets.txt"
        else
            # Create targets file with just the base domain
            mkdir -p "${domain_dir}/targets"
            echo "$domain" > "${domain_dir}/targets/all_targets.txt"
        fi
    else
        log_debug "Subdomain enumeration disabled for $domain"
        
        # Create targets file with just the base domain
        mkdir -p "${domain_dir}/targets"
        echo "$domain" > "${domain_dir}/targets/all_targets.txt"
    fi
    
    # Run HTTP probing if enabled
    if [[ "$(get_config scanning scan_http "true")" == "true" ]]; then
        log_info "Starting HTTP probing for $domain"
        http_probe "${domain_dir}/targets/all_targets.txt" "${domain_dir}/http"
        
        # Parse HTTP results
        http_parse_results "${domain_dir}/http"
    else
        log_debug "HTTP probing disabled for $domain"
    fi
    
    # Run vulnerability scanning if enabled
    if [[ "$(get_config scanning scan_vulnerabilities "true")" == "true" && -f "${domain_dir}/http/live_hosts.txt" ]]; then
        log_info "Starting vulnerability scanning for $domain"
        vuln_scan "${domain_dir}/http/live_hosts.txt" "${domain_dir}/vuln"
    else
        log_debug "Vulnerability scanning disabled or no live hosts for $domain"
    fi
    
    # Run screenshot capture if enabled
    if [[ "$(get_config scanning scan_screenshots "true")" == "true" && -f "${domain_dir}/http/live_hosts.txt" ]]; then
        log_info "Starting screenshot capture for $domain"
        screenshot_capture "${domain_dir}/http/live_hosts.txt" "${domain_dir}/screenshot"
    else
        log_debug "Screenshot capture disabled or no live hosts for $domain"
    fi
    
    # Run path discovery if enabled
    if [[ "$(get_config scanning scan_paths "true")" == "true" && -f "${domain_dir}/http/live_hosts.txt" ]]; then
        log_info "Starting path discovery for $domain"
        path_discover "${domain_dir}/http/live_hosts.txt" "${domain_dir}/path"
    else
        log_debug "Path discovery disabled or no live hosts for $domain"
    fi
    
    log_info "Processing completed for domain: $domain"
    return 0
}

# Generate reports for a domain
generate_domain_reports() {
    local domain="$1"
    local domain_dir="${FSRECON_RUN_DIR}/${domain}"
    local report_format="${REPORTING_FORMAT:-text}"
    
    log_info "Generating reports for domain: $domain"
    
    case "${report_format,,}" in
        "text")
            generate_text_report "$domain" "${domain_dir}/report.txt"
            ;;
        "json")
            generate_json_report "$domain" "${domain_dir}/report.json"
            ;;
        "html")
            generate_html_report "$domain" "${domain_dir}/report.html"
            ;;
        "all")
            generate_text_report "$domain" "${domain_dir}/report.txt"
            generate_json_report "$domain" "${domain_dir}/report.json"
            generate_html_report "$domain" "${domain_dir}/report.html"
            ;;
        *)
            log_warn "Unknown report format: $report_format, defaulting to text"
            generate_text_report "$domain" "${domain_dir}/report.txt"
            ;;
    esac
    
    log_info "Reports generated for domain: $domain"
    return 0
}

# Generate master reports
generate_master_reports() {
    log_info "Generating master reports"
    
    # Create master summary report
    generate_master_summary "${DOMAINS[@]}" "${FSRECON_RUN_DIR}/master_summary.txt"
    
    log_info "Master reports generated"
    return 0
}

# Main function
main() {
    display_banner
    
    # Parse command line arguments
    parse_arguments "$@"
    
    # Display usage if no domains specified
    if [ ${#DOMAINS[@]} -eq 0 ]; then
        show_help
        exit 1
    fi
    
    # Initialize FSRecon
    initialize
    
    log_info "Starting Full Spectrum Recon v${VERSION} on $(date)"
    log_info "Target domains: ${DOMAINS[*]}"
    
    # Process each domain
    for domain in "${DOMAINS[@]}"; do
        process_domain "$domain"
        generate_domain_reports "$domain"
    done
    
    # Generate master reports
    generate_master_reports
    
    log_info "Full Spectrum Recon completed on $(date)"
    log_info "All results stored in: $FSRECON_RUN_DIR"
    
    return 0
}

# Execute main function
main "$@"
