#!/bin/bash
# lib/core.sh - Core functions for FSRecon

# Global variables
FSRECON_VERSION="2.0.0"
FSRECON_ROOT="$(dirname "$(dirname "$(readlink -f "$0")")")"
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
        
        # Expand variables in value
        eval "value=\"$value\""
        
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
    
    local var_name="${section^^}_${key^^}"
    local value="${!var_name}"
    
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
    mkdir -p "$output_dir"
    
    # Create timestamp for this run
    export FSRECON_TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
    export FSRECON_RUN_DIR="${output_dir}/run_${FSRECON_TIMESTAMP}"
    mkdir -p "$FSRECON_RUN_DIR"
    
    # Initialize logging
    source "${FSRECON_ROOT}/lib/logger.sh"
    init_logger
    
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