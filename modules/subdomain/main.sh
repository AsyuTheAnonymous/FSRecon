#!/bin/bash
# modules/subdomain/main.sh - Subdomain enumeration module

# Register module
MODULE_NAME="subdomain"
MODULE_DESCRIPTION="Subdomain enumeration module"
MODULE_VERSION="1.0.0"
MODULE_AUTHOR="FSRecon Team"
MODULE_DEPENDENCIES=()

# Module initialization
# Called when the module is loaded
# Usage: subdomain_init
subdomain_init() {
    log_debug "Initializing subdomain enumeration module"
    
    # Check if subdomain scanner is installed
    local scanner="$(get_config tools subdomain_scanner "subfinder")"
    
    if ! command -v "$scanner" &>/dev/null; then
        log_error "Subdomain scanner '$scanner' not found"
        return 1
    fi
    
    log_debug "Subdomain enumeration module initialized"
    return 0
}

# Enumerate subdomains for a domain
# Usage: subdomain_scan domain output_dir [options]
subdomain_scan() {
    local domain="$1"
    local output_dir="$2"
    local options="${3:-}"
    
    log_info "Enumerating subdomains for $domain"
    
    # Create output directory
    mkdir -p "$output_dir"
    
    # Determine scanner and options
    local scanner="$(get_config tools subdomain_scanner "subfinder")"
    local default_options="$(get_config tools "${scanner}_options" "-silent")"
    
    if [[ -n "$options" ]]; then
        # User-provided options override defaults
        default_options="$options"
    fi
    
    log_debug "Using scanner: $scanner with options: $default_options"
    
    # Output files
    local output_file="${output_dir}/subdomains.txt"
    local json_output="${output_dir}/subdomains.json"
    
    # Run scan based on scanner type
    case "$scanner" in
        "subfinder")
            _subdomain_scan_subfinder "$domain" "$output_file" "$default_options"
            ;;
        "amass")
            _subdomain_scan_amass "$domain" "$output_file" "$default_options"
            ;;
        *)
            log_error "Unsupported subdomain scanner: $scanner"
            return 1
            ;;
    esac
    
    local exit_code=$?
    
    if [[ $exit_code -eq 0 ]]; then
        # Count discovered subdomains
        local count=0
        if [[ -f "$output_file" ]]; then
            count=$(wc -l < "$output_file")
            
            # Generate JSON output
            _subdomain_generate_json "$domain" "$output_file" "$json_output"
        fi
        
        log_info "Subdomain enumeration completed successfully. Found $count subdomains for $domain."
    else
        log_error "Subdomain enumeration failed for $domain with exit code $exit_code"
    fi
    
    return $exit_code
}

# Internal function to run subfinder
# Usage: _subdomain_scan_subfinder domain output_file options
_subdomain_scan_subfinder() {
    local domain="$1"
    local output_file="$2"
    local options="$3"
    
    log_debug "Running subfinder on $domain"
    
    # Run subfinder
    subfinder -d "$domain" -o "$output_file" $options > /dev/null 2>&1
    local exit_code=$?
    
    # Sort and deduplicate results
    if [[ $exit_code -eq 0 && -f "$output_file" ]]; then
        sort -u "$output_file" -o "$output_file"
    fi
    
    return $exit_code
}

# Internal function to run amass
# Usage: _subdomain_scan_amass domain output_file options
_subdomain_scan_amass() {
    local domain="$1"
    local output_file="$2"
    local options="$3"
    
    log_debug "Running amass on $domain"
    
    # Run amass
    amass enum -d "$domain" -o "$output_file" $options > /dev/null 2>&1
    local exit_code=$?
    
    # Sort and deduplicate results
    if [[ $exit_code -eq 0 && -f "$output_file" ]]; then
        sort -u "$output_file" -o "$output_file"
    fi
    
    return $exit_code
}

# Internal function to generate JSON from subdomain results
# Usage: _subdomain_generate_json domain input_file json_output
_subdomain_generate_json() {
    local domain="$1"
    local input_file="$2"
    local json_output="$3"
    
    log_debug "Generating JSON output from $input_file"
    
    # Generate JSON
    {
        echo '{'
        echo '  "domain": "'"$domain"'",'
        echo '  "scanner": "'"$(get_config tools subdomain_scanner "subfinder")"'",'
        echo '  "timestamp": "'"$(date -u +"%Y-%m-%dT%H:%M:%SZ")"'",'
        echo '  "subdomains": ['
        
        # Convert subdomains to JSON array
        local first=true
        while IFS= read -r line || [[ -n "$line" ]]; do
            [[ -z "$line" ]] && continue
            
            if [[ "$first" == true ]]; then
                echo '    "'"$line"'"'
                first=false
            else
                echo '    ,"'"$line"'"'
            fi
        done < "$input_file"
        
        echo '  ]'
        echo '}'
    } > "$json_output"
    
    return 0
}

# Register module functions
module_register() {
    register_function "subdomain_scan" "Enumerate subdomains for a domain"
}

# Initialize module
subdomain_init

# Export module
export -f subdomain_scan

# Report success
return 0