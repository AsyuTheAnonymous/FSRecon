#!/bin/bash
# modules/http/main.sh - HTTP probing module

# Register module
MODULE_NAME="http"
MODULE_DESCRIPTION="HTTP probing module"
MODULE_VERSION="1.0.0"
MODULE_AUTHOR="FSRecon Team"
MODULE_DEPENDENCIES=()

# Module initialization
# Called when the module is loaded
# Usage: http_init
http_init() {
    log_debug "Initializing HTTP probing module"
    
    # Check if HTTP prober is installed - NixOS compatible check
    local prober="$(get_config tools http_prober "httpx")"
    
    if ! command -v "$prober" &>/dev/null; then
        echo "WARNING: HTTP prober '$prober' not found in standard PATH"
        echo "Checking for NixOS-specific paths..."
        
        # Common NixOS binary paths
        if [[ -x "/run/current-system/sw/bin/$prober" ]]; then
            echo "Found $prober in /run/current-system/sw/bin/"
            export PATH="/run/current-system/sw/bin:$PATH"
        elif [[ -x "$HOME/.nix-profile/bin/$prober" ]]; then
            echo "Found $prober in $HOME/.nix-profile/bin/"
            export PATH="$HOME/.nix-profile/bin:$PATH"
        else
            echo "ERROR: HTTP prober '$prober' not found"
            echo "Please install it with: nix-env -iA nixos.${prober}"
            # Continue anyway to allow for testing
            echo "Continuing without HTTP probing capability"
        fi
    fi
    
    log_debug "HTTP probing module initialized"
    return 0
}

# Probe a list of hosts for HTTP/HTTPS services
# Usage: http_probe targets_file output_dir [options]
http_probe() {
    local targets_file="$1"
    local output_dir="$2"
    local options="${3:-}"
    
    log_info "Probing targets for HTTP/HTTPS services"
    
    # Check if targets file exists
    if [[ ! -f "$targets_file" ]]; then
        log_error "Targets file not found: $targets_file"
        return 1
    fi
    
    # Create output directory
    mkdir -p "$output_dir"
    
    # Determine prober and options
    local prober="$(get_config tools http_prober "httpx")"
    local default_options="$(get_config tools "${prober}_options" "")"
    
    if [[ -n "$options" ]]; then
        # User-provided options override defaults
        default_options="$options"
    fi
    
    log_debug "Using prober: $prober with options: $default_options"
    
    # Output files
    local output_file="${output_dir}/live_hosts.txt"
    local json_output="${output_dir}/live_hosts_details.json"
    
    # Run prober based on type
    case "$prober" in
        "httpx")
            _http_probe_httpx "$targets_file" "$output_file" "$json_output" "$default_options"
            ;;
        "httprobe")
            _http_probe_httprobe "$targets_file" "$output_file" "$default_options"
            ;;
        *)
            log_error "Unsupported HTTP prober: $prober"
            return 1
            ;;
    esac
    
    local exit_code=$?
    
    if [[ $exit_code -eq 0 ]]; then
        # Count live hosts
        local count=0
        if [[ -f "$output_file" ]]; then
            count=$(wc -l < "$output_file")
        fi
        
        log_info "HTTP probing completed successfully. Found $count live hosts."
    else
        log_error "HTTP probing failed with exit code $exit_code"
    fi
    
    return $exit_code
}

# Parse HTTP probe results
# Usage: http_parse_results output_dir
http_parse_results() {
    local output_dir="$1"
    local results_file="${output_dir}/http_results.json"
    
    log_debug "Parsing HTTP probe results from $output_dir"
    
    # Check if raw results exist
    if [[ ! -f "${output_dir}/live_hosts.txt" ]]; then
        log_error "No HTTP probe results found in $output_dir"
        return 1
    fi
    
    # Determine prober
    local prober="$(get_config tools http_prober "httpx")"
    
    # Parse results based on prober type
    case "$prober" in
        "httpx")
            if [[ -f "${output_dir}/live_hosts_details.json" ]]; then
                # Already in JSON format
                cp "${output_dir}/live_hosts_details.json" "$results_file"
            else
                _http_parse_httpx "${output_dir}/live_hosts.txt" "$results_file"
            fi
            ;;
        "httprobe")
            _http_parse_httprobe "${output_dir}/live_hosts.txt" "$results_file"
            ;;
        *)
            log_error "Unsupported HTTP prober results: $prober"
            return 1
            ;;
    esac
    
    local exit_code=$?
    
    if [[ $exit_code -eq 0 && -f "$results_file" ]]; then
        log_info "HTTP probe results parsed successfully to $results_file"
        return 0
    else
        log_error "Failed to parse HTTP probe results"
        return 1
    fi
}

# Internal function to run httpx
# Usage: _http_probe_httpx targets_file output_file json_output options
_http_probe_httpx() {
    local targets_file="$1"
    local output_file="$2"
    local json_output="$3"
    local options="$4"
    
    log_debug "Running httpx on targets from $targets_file"
    
    # Run httpx for plain output
    cat "$targets_file" | httpx $options -o "$output_file" > /dev/null 2>&1
    
    # Run httpx for JSON output if requested
    if [[ -n "$json_output" ]]; then
        cat "$targets_file" | httpx $options -json -o "$json_output" > /dev/null 2>&1
    fi
    
    return $?
}

# Internal function to run httprobe
# Usage: _http_probe_httprobe targets_file output_file options
_http_probe_httprobe() {
    local targets_file="$1"
    local output_file="$2"
    local options="$3"
    
    log_debug "Running httprobe on targets from $targets_file"
    
    # Run httprobe
    cat "$targets_file" | httprobe $options > "$output_file" 2>/dev/null
    
    return $?
}

# Internal function to parse httpx results
# Usage: _http_parse_httpx input_file json_output
_http_parse_httpx() {
    local input_file="$1"
    local json_output="$2"
    
    # Convert plain text to JSON
    {
        echo '{'
        echo '  "prober": "httpx",'
        echo '  "timestamp": "'"$(date -u +"%Y-%m-%dT%H:%M:%SZ")"'",'
        echo '  "hosts": ['
        
        while read -r url; do
            echo '    {'
            echo "      \"url\": \"$url\""
            echo '    },'
        done < "$input_file" | sed '$ s/,$//'
        
        echo '  ]'
        echo '}'
    } > "$json_output"
    
    return $?
}

# Internal function to parse httprobe results
# Usage: _http_parse_httprobe input_file json_output
_http_parse_httprobe() {
    local input_file="$1"
    local json_output="$2"
    
    # Convert plain text to JSON
    {
        echo '{'
        echo '  "prober": "httprobe",'
        echo '  "timestamp": "'"$(date -u +"%Y-%m-%dT%H:%M:%SZ")"'",'
        echo '  "hosts": ['
        
        while read -r url; do
            protocol=$(echo "$url" | cut -d':' -f1)
            host=$(echo "$url" | cut -d'/' -f3)
            
            echo '    {'
            echo "      \"url\": \"$url\","
            echo "      \"protocol\": \"$protocol\","
            echo "      \"host\": \"$host\""
            echo '    },'
        done < "$input_file" | sed '$ s/,$//'
        
        echo '  ]'
        echo '}'
    } > "$json_output"
    
    return $?
}

# Register module functions
module_register() {
    register_function "http_probe" "Probe hosts for HTTP/HTTPS services"
    register_function "http_parse_results" "Parse HTTP probe results"
    register_function "_http_probe_httpx" "Internal: Run httpx for HTTP probing"
    register_function "_http_probe_httprobe" "Internal: Run httprobe for HTTP probing"
    register_function "_http_parse_httpx" "Internal: Parse httpx results"
    register_function "_http_parse_httprobe" "Internal: Parse httprobe results"
}

# Initialize module
http_init

# Report success
return 0
