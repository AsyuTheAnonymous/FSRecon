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
        
        # Expand variables in value safely without eval
        # Look for patterns like ${variable_name}
        while [[ "$value" =~ (\$\{([a-zA-Z_][a-zA-Z0-9_]*)\}) ]]; do
            local full_match="${BASH_REMATCH[0]}" # e.g., ${wordlist_dir}
            local var_key="${BASH_REMATCH[2]}"    # e.g., wordlist_dir
            
            # Construct potential exported variable names (assuming it might be global or section-specific)
            local potential_var_name_global="${var_key^^}"
            local potential_var_name_section="${section^^}_${var_key^^}"
            
            local replacement_value=""
            
            # Check if the section-specific variable exists
            if [[ -v "$potential_var_name_section" ]]; then
                replacement_value="${!potential_var_name_section}"
            # Check if the global-like variable exists (might be from [general] or no section)
            elif [[ -v "$potential_var_name_global" ]]; then
                 replacement_value="${!potential_var_name_global}"
            else
                # Check if a variable from the [general] section matches
                local general_var_name="GENERAL_${var_key^^}"
                if [[ -v "$general_var_name" ]]; then
                    replacement_value="${!general_var_name}"
                else
                    log_warn "Variable expansion failed: Cannot find value for '$var_key' in config value '$value'"
                    # Keep the original placeholder if var not found to avoid breaking paths.
                    replacement_value="$full_match" 
                    break # Avoid infinite loop if substitution fails
                fi
            fi
            
            # Perform substitution - use Bash parameter expansion for safety
            value="${value//$full_match/$replacement_value}"
            log_debug "Expanded variable $full_match to $replacement_value in value. New value: $value"
        done
        
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
# Prioritizes environment variables (set by flags) over config file values.
# Usage: get_config section key [default_value]
get_config() {
    local section="$1"
    local key="$2"
    local default="$3"
    local value=""

    # Make sure section and key are not empty
    if [[ -z "$section" || -z "$key" ]]; then
        echo "$default"
        return 1
    fi

    # Construct the variable name (e.g., SCANNING_SCAN_PORTS)
    local var_name="${section^^}_${key^^}"

    # 1. Check if the environment variable exists and is set (priority)
    #    This handles overrides from command-line flags like --no-ports
    if [[ -v "$var_name" ]]; then
        value="${!var_name}"
        # log_debug "get_config: Found value for '$var_name' in environment: '$value'" # Optional: Add for debugging
        echo "$value"
        return 0
    fi

    # 2. If not found in environment, check the value loaded from the config file
    #    (This part might be less relevant now if flags directly set the env vars,
    #     but kept for potential direct config loading scenarios)
    #    We assume load_config has already exported variables like SCANNING_SCAN_PORTS
    #    based on the config file if the env var wasn't set by a flag.
    #    The check '-v "$var_name"' handles this case as well.

    # 3. If still no value, use the default
    if [[ -z "$value" && -n "$default" ]]; then
        # log_debug "get_config: Using default value for '$var_name': '$default'" # Optional: Add for debugging
        echo "$default"
        return 0
    elif [[ -n "$value" ]]; then
         # This case covers when the value was found via -v check but might be empty string ""
         # log_debug "get_config: Found value for '$var_name' (potentially empty): '$value'" # Optional: Add for debugging
        echo "$value"
        return 0
    else
        # Neither env var, config var, nor default exists. Return empty.
        # log_debug "get_config: No value found for '$var_name', returning empty." # Optional: Add for debugging
        echo ""
        return 1 # Indicate no value found other than potentially default
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

# Module registration system - simplified for better compatibility
# Note: The primary module loading and function exporting is now handled directly in fsrecon.sh initialize function.
# This section is kept minimal as the previous load_modules function was redundant.
REGISTERED_MODULES=()
REGISTERED_FUNCTIONS=()

# Register a module function (Potentially deprecated if fsrecon.sh handles all exports)
# Usage: register_function function_name description
register_function() {
    local function_name="$1"
    local description="$2"
    local module_name="${CURRENT_MODULE_NAME:-unknown}" # Relies on CURRENT_MODULE_NAME being set during sourcing

    # Check if function exists
    if ! declare -F "$function_name" > /dev/null; then
        log_error "Function '$function_name' does not exist in module '$module_name' at time of registration."
        return 1
    fi

    # Register function name (primarily for informational purposes now)
    REGISTERED_FUNCTIONS+=("$function_name")

    # Export function to make it available - fsrecon.sh also does this, but belt-and-suspenders
    export -f "$function_name" || log_warn "Failed to export function '$function_name' from core register_function."

    log_debug "Registered function (core): $function_name from module $module_name"
    return 0
}

# Note: The load_modules function previously here has been removed as its logic
# was duplicated and handled more directly within the initialize function in fsrecon.sh.
