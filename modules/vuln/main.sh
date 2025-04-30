#!/bin/bash
# modules/vuln/main.sh - Vulnerability scanning module

# Register module
MODULE_NAME="vuln"
MODULE_DESCRIPTION="Vulnerability scanning module"
MODULE_VERSION="1.0.0"
MODULE_AUTHOR="FSRecon Team"
MODULE_DEPENDENCIES=()

# Module initialization
# Called when the module is loaded
# Usage: vuln_init
vuln_init() {
    log_debug "Initializing vulnerability scanning module"
    
    # Check if vulnerability scanner is installed - NixOS compatible check
    local scanner="$(get_config tools vuln_scanner "nuclei")"
    
    if ! command -v "$scanner" &>/dev/null; then
        echo "WARNING: Vulnerability scanner '$scanner' not found in standard PATH"
        echo "Checking for NixOS-specific paths..."
        
        # Common NixOS binary paths
        if [[ -x "/run/current-system/sw/bin/$scanner" ]]; then
            echo "Found $scanner in /run/current-system/sw/bin/"
            export PATH="/run/current-system/sw/bin:$PATH"
        elif [[ -x "$HOME/.nix-profile/bin/$scanner" ]]; then
            echo "Found $scanner in $HOME/.nix-profile/bin/"
            export PATH="$HOME/.nix-profile/bin:$PATH"
        else
            echo "ERROR: Vulnerability scanner '$scanner' not found"
            echo "Please install it with: nix-env -iA nixos.${scanner}"
            # Continue anyway to allow for testing
            echo "Continuing without vulnerability scanning capability"
        fi
    fi
    
    log_debug "Vulnerability scanning module initialized"
    return 0
}

# Scan for vulnerabilities on targets
# Usage: vuln_scan targets_file output_dir [options]
vuln_scan() {
    local targets_file="$1"
    local output_dir="$2"
    local options="${3:-}"
    
    log_info "Scanning for vulnerabilities on targets from $targets_file"
    
    # Check if targets file exists
    if [[ ! -f "$targets_file" ]]; then
        log_error "Targets file not found: $targets_file"
        return 1
    fi
    
    # Create output directory
    mkdir -p "$output_dir"
    
    # Determine scanner and options
    local scanner="$(get_config tools vuln_scanner "nuclei")"
    local default_options="$(get_config tools "${scanner}_options" "-silent -severity medium,high,critical")"
    
    if [[ -n "$options" ]]; then
        # User-provided options override defaults
        default_options="$options"
    fi
    
    log_debug "Using scanner: $scanner with options: $default_options"
    
    # Output files
    local output_file="${output_dir}/vulnerabilities.txt"
    local json_output="${output_dir}/vulnerabilities.json"
    
    # Run scanner based on type
    case "$scanner" in
        "nuclei")
            _vuln_scan_nuclei "$targets_file" "$output_file" "$json_output" "$default_options"
            ;;
        *)
            log_error "Unsupported vulnerability scanner: $scanner"
            return 1
            ;;
    esac
    
    local exit_code=$?
    
    if [[ $exit_code -eq 0 ]]; then
        # Count discovered vulnerabilities
        local count=0
        if [[ -f "$output_file" ]]; then
            count=$(wc -l < "$output_file")
        fi
        
        log_info "Vulnerability scanning completed successfully. Found $count potential vulnerabilities."
    else
        log_error "Vulnerability scanning failed with exit code $exit_code"
    fi
    
    return $exit_code
}

# Internal function to run nuclei
# Usage: _vuln_scan_nuclei targets_file output_file json_output options
_vuln_scan_nuclei() {
    local targets_file="$1"
    local output_file="$2"
    local json_output="$3"
    local options="$4"
    
    log_debug "Running nuclei on targets from $targets_file"
    
    # Run nuclei for text output
    nuclei -l "$targets_file" -o "$output_file" $options > /dev/null 2>&1
    local exit_code=$?
    
    # Run nuclei for JSON output if requested
    if [[ -n "$json_output" && $exit_code -eq 0 ]]; then
        nuclei -l "$targets_file" -json -o "$json_output" $options > /dev/null 2>&1
    fi
    
    return $exit_code
}

# Register module functions
module_register() {
    register_function "vuln_scan" "Scan for vulnerabilities on targets"
    register_function "_vuln_scan_nuclei" "Internal: Run nuclei for vulnerability scanning"
}

# Initialize module
vuln_init

# Report success
return 0
