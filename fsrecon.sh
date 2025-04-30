#!/usr/bin/env bash
# fsrecon.sh - Full Spectrum Recon main script

# Modified error handling for better debugging
set -u  # Treat unset variables as errors
# Don't use -e (exit on error) to allow error reporting
# Don't use -o pipefail to allow more flexible command chaining

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
    echo "DEBUG: Entering initialize function..."
    
    # Initialize core systems first
    echo "DEBUG: Calling init_fsrecon..."
    init_fsrecon
    echo "DEBUG: init_fsrecon completed."
    
    # Now we can use logging functions
    log_debug "Loading configuration from $CONFIG_FILE"
    load_config "$CONFIG_FILE"
    log_debug "Configuration loading completed."
    
    # Set log level based on verbose flag
    if [[ "$VERBOSE" == true ]]; then
        log_debug "Verbose mode enabled, setting LOGGER_LEVEL to DEBUG"
        export LOGGER_LEVEL=$LOG_LEVEL_DEBUG
    fi
    
    # Set output directory if provided
    if [[ -n "$OUTPUT_DIR" ]]; then
        log_debug "Output directory specified: $OUTPUT_DIR"
        export GENERAL_OUTPUT_DIR="$OUTPUT_DIR"
    fi
    
    # Load modules directly (simpler approach that works)
    log_info "Loading modules directly..."
    local module_count=0
    for module_file in "${FSRECON_ROOT}/modules"/*/main.sh; do
        if [[ -f "$module_file" ]]; then
            module_name=$(basename "$(dirname "$module_file")")
            log_debug "Attempting to load module: $module_name from $module_file"
            
            # Source the module file with error checking
            source "$module_file"
            local source_status=$?
            if [[ $source_status -ne 0 ]]; then
                log_error "Failed to source module $module_name from $module_file (Exit code: $source_status)"
                continue # Skip to the next module
            fi
            log_debug "Module sourced: $module_name"
            module_count=$((module_count + 1))
        
            # Call module initialization function if it exists
            if declare -F "${module_name}_init" > /dev/null; then
                log_debug "Initializing module: $module_name"
                "${module_name}_init" || log_warn "Initialization failed for module $module_name"
            else
                 log_debug "No _init function found for module $module_name"
            fi

            # Export primary functions explicitly
            log_debug "Exporting functions for module: $module_name"
            case "$module_name" in
                "port")
                    export -f port_scan 2>/dev/null || log_warn "Failed to export port_scan"
                    export -f port_parse_results 2>/dev/null || log_warn "Failed to export port_parse_results"
                    ;;
                "subdomain")
                    export -f subdomain_scan 2>/dev/null || log_warn "Failed to export subdomain_scan"
                    ;;
                "http")
                    export -f http_probe 2>/dev/null || log_warn "Failed to export http_probe"
                    export -f http_parse_results 2>/dev/null || log_warn "Failed to export http_parse_results"
                    ;;
                "path")
                    export -f path_discover 2>/dev/null || log_warn "Failed to export path_discover"
                    ;;
                "screenshot")
                    export -f screenshot_capture 2>/dev/null || log_warn "Failed to export screenshot_capture"
                    ;;
                "vuln")
                    export -f vuln_scan 2>/dev/null || log_warn "Failed to export vuln_scan"
                    ;;
                "reporting") # Also handle reporting module if it exists as a module
                     export -f generate_text_report 2>/dev/null || log_warn "Failed to export generate_text_report"
                     export -f generate_json_report 2>/dev/null || log_warn "Failed to export generate_json_report"
                     export -f generate_html_report 2>/dev/null || log_warn "Failed to export generate_html_report"
                     export -f generate_master_summary 2>/dev/null || log_warn "Failed to export generate_master_summary"
                    ;;
            esac
            log_debug "Finished processing module: $module_name"
        else
             log_warn "Module file not found: $module_file"
        fi
    done
    log_info "Loaded $module_count modules."
    
    # Also source reporting functions if they exist in lib
    if [[ -f "${FSRECON_ROOT}/lib/reporting.sh" ]]; then
        log_debug "Sourcing reporting library: ${FSRECON_ROOT}/lib/reporting.sh"
        source "${FSRECON_ROOT}/lib/reporting.sh"
        export -f generate_text_report 2>/dev/null || log_warn "Failed to export generate_text_report"
        export -f generate_json_report 2>/dev/null || log_warn "Failed to export generate_json_report"
        export -f generate_html_report 2>/dev/null || log_warn "Failed to export generate_html_report"
        export -f generate_master_summary 2>/dev/null || log_warn "Failed to export generate_master_summary"
    else
        log_warn "Reporting library not found at ${FSRECON_ROOT}/lib/reporting.sh"
    fi

    # Also source reporting functions if they exist in lib
    if [[ -f "${FSRECON_ROOT}/lib/reporting.sh" ]]; then
        log_debug "Sourcing reporting library: ${FSRECON_ROOT}/lib/reporting.sh"
        source "${FSRECON_ROOT}/lib/reporting.sh"
        export -f generate_text_report 2>/dev/null || log_warn "Failed to export generate_text_report"
        export -f generate_json_report 2>/dev/null || log_warn "Failed to export generate_json_report"
        export -f generate_html_report 2>/dev/null || log_warn "Failed to export generate_html_report"
        export -f generate_master_summary 2>/dev/null || log_warn "Failed to export generate_master_summary"
    else
        log_warn "Reporting library not found at ${FSRECON_ROOT}/lib/reporting.sh"
    fi

    # Apply command-line flags AFTER config loading and module sourcing
    log_debug "Applying command-line flags to override config..."
    # Filter scan types if specified by -t
    if [[ ${#SCAN_TYPES[@]} -gt 0 ]]; then
        log_debug "Scan types specified via -t: ${SCAN_TYPES[*]}"
        # Disable all scan types first, then enable only specified ones
        export SCANNING_SCAN_PORTS=false
        export SCANNING_SCAN_SUBDOMAINS=false
        export SCANNING_SCAN_HTTP=false
        export SCANNING_SCAN_PATHS=false
        export SCANNING_SCAN_SCREENSHOTS=false
        export SCANNING_SCAN_VULNERABILITIES=false
        log_debug "All scan types disabled initially due to -t flag."
        
        for type in "${SCAN_TYPES[@]}"; do
            log_debug "Processing specified type from -t: $type"
            case "$type" in
                "port") export SCANNING_SCAN_PORTS=true; log_debug "Enabled port scanning via -t." ;;
                "subdomain") export SCANNING_SCAN_SUBDOMAINS=true; log_debug "Enabled subdomain scanning via -t." ;;
                "http") export SCANNING_SCAN_HTTP=true; log_debug "Enabled HTTP probing via -t." ;;
                "path") export SCANNING_SCAN_PATHS=true; log_debug "Enabled path discovery via -t." ;;
                "screenshot") export SCANNING_SCAN_SCREENSHOTS=true; log_debug "Enabled screenshot capture via -t." ;;
                "vuln") export SCANNING_SCAN_VULNERABILITIES=true; log_debug "Enabled vulnerability scanning via -t." ;;
                *) log_warn "Unknown scan type specified via -t: $type" ;;
            esac
        done
    else
        log_debug "No -t flag used. Applying --no-* flags if present..."
        # Apply --no-* flags (these were already exported during argument parsing)
        [[ "$SCANNING_SCAN_PORTS" == "false" ]] && log_debug "Port scanning disabled via --no-ports."
        [[ "$SCANNING_SCAN_SUBDOMAINS" == "false" ]] && log_debug "Subdomain scanning disabled via --no-subdomains."
        [[ "$SCANNING_SCAN_HTTP" == "false" ]] && log_debug "HTTP probing disabled via --no-http."
        [[ "$SCANNING_SCAN_PATHS" == "false" ]] && log_debug "Path discovery disabled via --no-paths."
        [[ "$SCANNING_SCAN_SCREENSHOTS" == "false" ]] && log_debug "Screenshot capture disabled via --no-screenshots."
        [[ "$SCANNING_SCAN_VULNERABILITIES" == "false" ]] && log_debug "Vulnerability scanning disabled via --no-vulns."
    fi
    log_debug "Command-line flag application completed."

    echo "DEBUG: Exiting initialize function."
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
        
        # Check if port_scan function exists
        if declare -F "port_scan" > /dev/null; then
            log_debug "Port scan function exists, executing..."
            
            # Execute port scan with error handling
            if ! port_scan "$domain" "${domain_dir}/port"; then
                log_error "Port scan failed for $domain"
            else
                # Parse port results if function exists
                if declare -F "port_parse_results" > /dev/null; then
                    port_parse_results "${domain_dir}/port"
                else
                    log_error "port_parse_results function not found"
                fi
            fi
        else
            log_error "port_scan function not found. Module might not be properly loaded."
        fi
    else
        log_debug "Port scanning disabled for $domain"
    fi
    
    # Run subdomain enumeration if enabled
    if [[ "$(get_config scanning scan_subdomains "true")" == "true" ]]; then
        log_info "Starting subdomain enumeration for $domain"
        
        # Check if subdomain_scan function exists
        if declare -F "subdomain_scan" > /dev/null; then
            log_debug "Subdomain scan function exists, executing..."
            
            # Execute subdomain scan with error handling
            if ! subdomain_scan "$domain" "${domain_dir}/subdomain"; then
                log_error "Subdomain enumeration failed for $domain"
            fi
            
            # Create targets file for HTTP probing
            if [[ -f "${domain_dir}/subdomain/subdomains.txt" ]]; then
                log_debug "Subdomain results found, creating targets file"
                mkdir -p "${domain_dir}/targets"
                cp "${domain_dir}/subdomain/subdomains.txt" "${domain_dir}/targets/all_targets.txt"
                
                # Add base domain to targets
                echo "$domain" >> "${domain_dir}/targets/all_targets.txt"
                
                # Sort and deduplicate
                sort -u "${domain_dir}/targets/all_targets.txt" -o "${domain_dir}/targets/all_targets.txt"
                log_debug "Created targets file with $(wc -l < "${domain_dir}/targets/all_targets.txt") targets"
            else
                log_warn "No subdomain results found, using only base domain"
                # Create targets file with just the base domain
                mkdir -p "${domain_dir}/targets"
                echo "$domain" > "${domain_dir}/targets/all_targets.txt"
            fi
        else
            log_error "subdomain_scan function not found. Module might not be properly loaded."
            # Create targets file with just the base domain as fallback
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
        
        # Check if http_probe function exists
        if declare -F "http_probe" > /dev/null; then
            log_debug "HTTP probe function exists, executing..."
            
            if [[ ! -f "${domain_dir}/targets/all_targets.txt" ]]; then
                log_warn "No targets file found, creating one with base domain"
                mkdir -p "${domain_dir}/targets"
                echo "$domain" > "${domain_dir}/targets/all_targets.txt"
            fi
            
            # Execute HTTP probe with error handling
            if ! http_probe "${domain_dir}/targets/all_targets.txt" "${domain_dir}/http"; then
                log_error "HTTP probing failed for $domain"
            else
                # Parse HTTP results if function exists
                if declare -F "http_parse_results" > /dev/null; then
                    http_parse_results "${domain_dir}/http"
                else
                    log_error "http_parse_results function not found"
                fi
            fi
        else
            log_error "http_probe function not found. Module might not be properly loaded."
        fi
    else
        log_debug "HTTP probing disabled for $domain"
    fi
    
    # Run vulnerability scanning if enabled
    if [[ "$(get_config scanning scan_vulnerabilities "true")" == "true" ]]; then
        log_info "Starting vulnerability scanning for $domain"
        
        # Check if vuln_scan function exists
        if declare -F "vuln_scan" > /dev/null; then
            log_debug "Vulnerability scan function exists, executing..."
            
            if [[ -f "${domain_dir}/http/live_hosts.txt" ]]; then
                # Execute vulnerability scan with error handling
                if ! vuln_scan "${domain_dir}/http/live_hosts.txt" "${domain_dir}/vuln"; then
                    log_error "Vulnerability scanning failed for $domain"
                fi
            else
                log_warn "No live hosts found for vulnerability scanning"
            fi
        else
            log_error "vuln_scan function not found. Module might not be properly loaded."
        fi
    else
        log_debug "Vulnerability scanning disabled for $domain"
    fi
    
    # Run screenshot capture if enabled
    if [[ "$(get_config scanning scan_screenshots "true")" == "true" ]]; then
        log_info "Starting screenshot capture for $domain"
        
        # Check if screenshot_capture function exists
        if declare -F "screenshot_capture" > /dev/null; then
            log_debug "Screenshot capture function exists, executing..."
            
            if [[ -f "${domain_dir}/http/live_hosts.txt" ]]; then
                # Execute screenshot capture with error handling
                if ! screenshot_capture "${domain_dir}/http/live_hosts.txt" "${domain_dir}/screenshot"; then
                    log_error "Screenshot capture failed for $domain"
                fi
            else
                log_warn "No live hosts found for screenshot capture"
            fi
        else
            log_error "screenshot_capture function not found. Module might not be properly loaded."
        fi
    else
        log_debug "Screenshot capture disabled for $domain"
    fi
    
    # Run path discovery if enabled
    if [[ "$(get_config scanning scan_paths "true")" == "true" ]]; then
        log_info "Starting path discovery for $domain"
        
        # Check if path_discover function exists
        if declare -F "path_discover" > /dev/null; then
            log_debug "Path discovery function exists, executing..."
            
            if [[ -f "${domain_dir}/http/live_hosts.txt" ]]; then
                # Execute path discovery with error handling
                if ! path_discover "${domain_dir}/http/live_hosts.txt" "${domain_dir}/path"; then
                    log_error "Path discovery failed for $domain"
                fi
            else
                log_warn "No live hosts found for path discovery"
            fi
        else
            log_error "path_discover function not found. Module might not be properly loaded."
        fi
    else
        log_debug "Path discovery disabled for $domain"
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
    
    echo "DEBUG: Registered functions:"
    declare -F | grep -v " _" | sort
    
    # Verify all modules were loaded properly
    echo "DEBUG: Checking for required module functions..."
    for func in "port_scan" "subdomain_scan" "http_probe" "path_discover" "screenshot_capture" "vuln_scan"; do
        if declare -F "$func" > /dev/null; then
            echo "DEBUG: Function $func is available"
        else
            echo "DEBUG: WARNING - Function $func is NOT available"
        fi
    done
    
    echo "DEBUG: About to process domains: ${DOMAINS[*]}"
    
    # Process each domain
    for domain in "${DOMAINS[@]}"; do
        echo "DEBUG: ========== STARTING PROCESS FOR DOMAIN: $domain =========="
        mkdir -p "${FSRECON_RUN_DIR}/${domain}"

        echo "DEBUG: 1. Starting port scanning"
        if [[ "$(get_config scanning scan_ports "true")" == "true" ]]; then
            if declare -F "port_scan" > /dev/null; then
                echo "DEBUG: Running port_scan function"
                port_scan "$domain" "${FSRECON_RUN_DIR}/${domain}/port" || echo "DEBUG: port_scan returned error code $?"
                echo "DEBUG: Port scanning completed"
            else
                echo "DEBUG: !! port_scan function not found! !!"
            fi
        else
            echo "DEBUG: Port scanning disabled"
        fi

        echo "DEBUG: 2. Starting subdomain enumeration"
        if [[ "$(get_config scanning scan_subdomains "true")" == "true" ]]; then
            if declare -F "subdomain_scan" > /dev/null; then
                echo "DEBUG: Running subdomain_scan function"
                subdomain_scan "$domain" "${FSRECON_RUN_DIR}/${domain}/subdomain" || echo "DEBUG: subdomain_scan returned error code $?"
                echo "DEBUG: Subdomain enumeration completed"
            else
                echo "DEBUG: !! subdomain_scan function not found! !!"
            fi
        else
            echo "DEBUG: Subdomain enumeration disabled"
        fi

        echo "DEBUG: Creating targets file"
        mkdir -p "${FSRECON_RUN_DIR}/${domain}/targets"
        echo "$domain" > "${FSRECON_RUN_DIR}/${domain}/targets/all_targets.txt"
        echo "DEBUG: Target file created with domain: $domain"

        echo "DEBUG: 3. Starting HTTP probing"
        if [[ "$(get_config scanning scan_http "true")" == "true" ]]; then
            if declare -F "http_probe" > /dev/null; then
                echo "DEBUG: Running http_probe function"
                http_probe "${FSRECON_RUN_DIR}/${domain}/targets/all_targets.txt" "${FSRECON_RUN_DIR}/${domain}/http" || echo "DEBUG: http_probe returned error code $?"
                echo "DEBUG: HTTP probing completed"
            else
                echo "DEBUG: !! http_probe function not found! !!"
            fi
        else
            echo "DEBUG: HTTP probing disabled"
        fi

        echo "DEBUG: 4. Starting path discovery"
        if [[ "$(get_config scanning scan_paths "true")" == "true" ]]; then
            if declare -F "path_discover" > /dev/null; then
                local live_hosts_file="${FSRECON_RUN_DIR}/${domain}/http/live_hosts.txt"
                if [[ -f "$live_hosts_file" && -s "$live_hosts_file" ]]; then
                    echo "DEBUG: Running path_discover function using live hosts: $live_hosts_file"
                    path_discover "$live_hosts_file" "${FSRECON_RUN_DIR}/${domain}/path" || echo "DEBUG: path_discover returned error code $?"
                    echo "DEBUG: Path discovery completed"
                else
                    log_warn "No live hosts found in $live_hosts_file. Skipping path discovery."
                fi
            else
                echo "DEBUG: !! path_discover function not found! !!"
            fi
        else
            echo "DEBUG: Path discovery disabled"
        fi

        echo "DEBUG: 5. Starting screenshot capture"
        if [[ "$(get_config scanning scan_screenshots "true")" == "true" ]]; then
            if declare -F "screenshot_capture" > /dev/null; then
                local live_hosts_file="${FSRECON_RUN_DIR}/${domain}/http/live_hosts.txt"
                 if [[ -f "$live_hosts_file" && -s "$live_hosts_file" ]]; then
                    echo "DEBUG: Running screenshot_capture function using live hosts: $live_hosts_file"
                    screenshot_capture "$live_hosts_file" "${FSRECON_RUN_DIR}/${domain}/screenshot" || echo "DEBUG: screenshot_capture returned error code $?"
                    echo "DEBUG: Screenshot capture completed"
                else
                    log_warn "No live hosts found in $live_hosts_file. Skipping screenshot capture."
                fi
            else
                echo "DEBUG: !! screenshot_capture function not found! !!"
            fi
        else
            echo "DEBUG: Screenshot capture disabled"
        fi

        echo "DEBUG: 6. Starting vulnerability scanning"
        if [[ "$(get_config scanning scan_vulnerabilities "true")" == "true" ]]; then
            if declare -F "vuln_scan" > /dev/null; then
                 local live_hosts_file="${FSRECON_RUN_DIR}/${domain}/http/live_hosts.txt"
                 if [[ -f "$live_hosts_file" && -s "$live_hosts_file" ]]; then
                    echo "DEBUG: Running vuln_scan function using live hosts: $live_hosts_file"
                    vuln_scan "$live_hosts_file" "${FSRECON_RUN_DIR}/${domain}/vuln" || echo "DEBUG: vuln_scan returned error code $?"
                    echo "DEBUG: Vulnerability scanning completed"
                else
                    log_warn "No live hosts found in $live_hosts_file. Skipping vulnerability scanning."
                fi
            else
                echo "DEBUG: !! vuln_scan function not found! !!"
            fi
        else
            echo "DEBUG: Vulnerability scanning disabled"
        fi

        echo "DEBUG: 7. Generating reports"
        generate_domain_reports "$domain"
        echo "DEBUG: Reports generated"
        
        echo "DEBUG: ========== DOMAIN PROCESSING COMPLETE: $domain =========="
    done
    
    # Generate master reports
    echo "DEBUG: Generating master reports"
    generate_master_reports
    echo "DEBUG: Master reports generated"
    
    log_info "Full Spectrum Recon completed on $(date)"
    log_info "All results stored in: $FSRECON_RUN_DIR"
    
    return 0
}

# Debug before main function
echo "DEBUG: Starting execution..."
echo "DEBUG: About to call main function"

# Execute main function with error trapping
set +e  # Temporarily disable strict error handling
main "$@"
ret=$?
echo "DEBUG: Main function returned with code: $ret"
set -e  # Re-enable strict error handling
exit $ret
