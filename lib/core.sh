#!/bin/bash
# lib/core.sh - Core functions for FSRecon

# Global variables
FSRECON_VERSION="2.0.0"
# Fix the path issue by using the actual script path
SCRIPT_PATH="${BASH_SOURCE[0]}"
FSRECON_ROOT="$(cd "$(dirname "$(dirname "$SCRIPT_PATH")")" && pwd)"
CONFIG_FILE=""
VERBOSE=false

# Load configuration from file
# Usage: load_config [config_file]
load_config() {
    local config_file="${1:-${FSRECON_ROOT}/config/default.conf}"
    
    # Check if config file exists
    if [[ ! -f "$config_file" ]]; then
        echo "Error: Configuration file not found: $config_file"
        exit 1
    fi
    
    CONFIG_FILE="$config_file"
    
    # Source the configuration file if it's a shell script
    if [[ "$config_file" == *.sh ]]; then
        source "$config_file"
        return $?
    fi
    
    # Parse INI-style configuration file
    local section=""
    while IFS='=' read -r key value || [[ -n "$key" ]]; do
        # Skip comments and empty lines
        [[ -z "$key" || "$key" == \#* ]] && continue
        
        # Handle sections
        if [[ $key == \[*] ]]; then
            section="${key:1:-1}"
            continue
        fi
        
        # Trim whitespace
        key=$(echo "$key" | xargs)
        value=$(echo "$value" | xargs)
        
        # Expand variables in value carefully
        # First, check if the value contains any variable references
        if [[ "$value" == *'${'*'}'* ]]; then
            # Make sure CONFIG_FILE is an absolute path to ensure eval works correctly
            cd "$(dirname "$CONFIG_FILE")" || true
            # Use eval with a safe pattern
            # If variable expansion fails, keep the original value
            eval "expanded_value=\"$value\"" 2>/dev/null || expanded_value="$value"
            value="$expanded_value"
        fi
        
        # Create variable name
        if [[ -n "$section" ]]; then
            var_name="${section^^}_${key^^}"
        else
            var_name="${key^^}"
        fi
        
        # Export variable
        export "$var_name"="$value"
        
        [[ "$VERBOSE" == true ]] && echo "Loaded config: $var_name = $value"
    done < "$config_file"
    
    return 0
}

# Get configuration value
# Usage: get_config section key [default_value]
get_config() {
    local section="$1"
    local key="$2"
    local default="$3"
    
    # Make sure section and key are not empty
    if [[ -z "$section" || -z "$key" ]]; then
        echo "$default"
        return 1
    fi
    
    local var_name="${section^^}_${key^^}"
    
    # Use parameter expansion with a default to avoid unbound variable errors
    # ${!name} is an indirect reference, but if name is unbound it fails
    # We need to check if the variable exists first
    local value=""
    if [[ -n "$var_name" ]] && [[ -v "$var_name" ]]; then
        value="${!var_name}"
    fi
    
    if [[ -z "$value" && -n "$default" ]]; then
        echo "$default"
    else
        echo "$value"
    fi
}

# Check if required tools are installed
# Usage: check_requirements [tool1] [tool2] ...
check_requirements() {
    local missing_tools=()
    
    for tool in "$@"; do
        if ! command -v "$tool" &>/dev/null; then
            missing_tools+=("$tool")
        fi
    done
    
    if [[ ${#missing_tools[@]} -ne 0 ]]; then
        echo "Error: The following required tools are not installed:"
        for tool in "${missing_tools[@]}"; do
            echo "- $tool"
        done
        return 1
    fi
    
    return 0
}

# Validate domain format
# Usage: validate_domain domain
validate_domain() {
    local domain="$1"
    local domain_regex='^([a-zA-Z0-9](([a-zA-Z0-9-]){0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    
    if [[ ! "$domain" =~ $domain_regex ]]; then
        echo "Error: Invalid domain format: $domain"
        return 1
    fi
    
    return 0
}

# Initialize FSRecon
# Usage: init_fsrecon
init_fsrecon() {
    # Create output directories if they don't exist
    local output_dir="$(get_config general output_dir "${FSRECON_ROOT}/output")"
    
    # Ensure output_dir is not empty
    if [[ -z "$output_dir" ]]; then
        output_dir="${FSRECON_ROOT}/output"
        echo "Warning: Output directory not specified or empty, using default: $output_dir"
    fi
    
    mkdir -p "$output_dir"
    
    # Create timestamp for this run
    export FSRECON_TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
    export FSRECON_RUN_DIR="${output_dir}/run_${FSRECON_TIMESTAMP}"
    
    # Ensure FSRECON_RUN_DIR is not empty
    if [[ -z "$FSRECON_RUN_DIR" ]]; then
        export FSRECON_RUN_DIR="${FSRECON_ROOT}/output/run_${FSRECON_TIMESTAMP}"
        echo "Warning: Run directory not specified or empty, using default: $FSRECON_RUN_DIR"
    fi
    
    mkdir -p "$FSRECON_RUN_DIR"
    
    # Debug path information
    echo "Debug: FSRECON_ROOT is set to: ${FSRECON_ROOT}"
    echo "Debug: Attempting to source logger from: ${FSRECON_ROOT}/lib/logger.sh"
    
    # Initialize logging
    if [[ -f "${FSRECON_ROOT}/lib/logger.sh" ]]; then
        source "${FSRECON_ROOT}/lib/logger.sh"
        init_logger
    else
        echo "Error: Logger file not found at ${FSRECON_ROOT}/lib/logger.sh"
        echo "Current working directory: $(pwd)"
        echo "Script directory: $(dirname "$SCRIPT_PATH")"
        exit 1
    fi
    
    log_info "FSRecon v${FSRECON_VERSION} initialized"
    log_debug "Configuration loaded from: $CONFIG_FILE"
    log_debug "Output directory: $FSRECON_RUN_DIR"
    
    return 0
}

# Load all modules
# Usage: load_modules
load_modules() {
    local modules_dir="${FSRECON_ROOT}/modules"
    local loaded_modules=0
    
    log_info "Loading modules..."
    
    # Load each module's main.sh file
    for module_dir in "${modules_dir}"/*; do
        if [[ -d "$module_dir" && -f "${module_dir}/main.sh" ]]; then
            module_name="$(basename "$module_dir")"
            log_debug "Loading module: $module_name"
            
            source "${module_dir}/main.sh"
            
            if [[ $? -eq 0 ]]; then
                loaded_modules=$((loaded_modules + 1))
                log_debug "Module loaded: $module_name"
            else
                log_error "Failed to load module: $module_name"
            fi
        fi
    done
    
    log_info "Loaded $loaded_modules modules"
    return 0
}
