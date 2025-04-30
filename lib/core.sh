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

# Module registration system - simplified for better compatibility
REGISTERED_MODULES=()
REGISTERED_FUNCTIONS=()

# Register a module function
# Usage: register_function function_name description
register_function() {
    local function_name="$1"
    local description="$2"
    local module_name="${CURRENT_MODULE_NAME:-unknown}"
    
    # Check if function exists
    if ! declare -F "$function_name" > /dev/null; then
        echo "ERROR: Function '$function_name' does not exist in module '$module_name'"
        return 1
    fi
    
    # Register function in a simpler way
    REGISTERED_FUNCTIONS+=("$function_name")
    
    # Export function to make it available to main script
    # This is critical - we need to use the 'export -f' to make the function available globally
    export -f "$function_name"
    
    echo "DEBUG: Registered function: $function_name from module $module_name"
    return 0
}

# Load all modules
# Usage: load_modules
load_modules() {
    local modules_dir="${FSRECON_ROOT}/modules"
    local loaded_modules=0
    
    echo "INFO: Loading modules from $modules_dir"
    
    # Initialize module registries
    REGISTERED_MODULES=()
    REGISTERED_FUNCTIONS=()
    
    # Ensure all modules can access necessary core functions
    export -f get_config
    export -f log_debug
    export -f log_info
    export -f log_warn
    export -f log_error
    
    # Create a list of all module directories
    module_dirs=()
    for module_dir in "${modules_dir}"/*; do
        if [[ -d "$module_dir" && -f "${module_dir}/main.sh" ]]; then
            module_dirs+=("$module_dir")
        fi
    done
    
    echo "INFO: Found ${#module_dirs[@]} modules to load"
    
    # Load each module's main.sh file
    for module_dir in "${module_dirs[@]}"; do
        module_name="$(basename "$module_dir")"
        echo "INFO: Loading module: $module_name from $module_dir/main.sh"
        
        # Set current module name for registration
        export CURRENT_MODULE_NAME="$module_name"
        
        # Use the full path to source the module file
        if [[ -f "${module_dir}/main.sh" ]]; then
            echo "INFO: Sourcing ${module_dir}/main.sh"
            # Source the module file
            source "${module_dir}/main.sh"
            source_result=$?
            
            if [[ $source_result -eq 0 ]]; then
                # Register module in the array
                REGISTERED_MODULES+=("$module_name")
                
                # Manually export key functions according to module type
                case "$module_name" in
                    "port")
                        export -f port_scan 2>/dev/null || echo "WARNING: Failed to export port_scan"
                        export -f port_parse_results 2>/dev/null || echo "WARNING: Failed to export port_parse_results"
                        ;;
                    "subdomain")
                        export -f subdomain_scan 2>/dev/null || echo "WARNING: Failed to export subdomain_scan"
                        ;;
                    "http")
                        export -f http_probe 2>/dev/null || echo "WARNING: Failed to export http_probe"
                        export -f http_parse_results 2>/dev/null || echo "WARNING: Failed to export http_parse_results"
                        ;;
                    "path")
                        export -f path_discover 2>/dev/null || echo "WARNING: Failed to export path_discover"
                        ;;
                    "screenshot")
                        export -f screenshot_capture 2>/dev/null || echo "WARNING: Failed to export screenshot_capture"
                        ;;
                    "vuln")
                        export -f vuln_scan 2>/dev/null || echo "WARNING: Failed to export vuln_scan"
                        ;;
                esac
                
                # Call module initialization function if it exists
                if declare -F "${module_name}_init" > /dev/null; then
                    echo "INFO: Initializing module: $module_name"
                    "${module_name}_init" || echo "WARNING: Failed to initialize $module_name"
                fi
                
                # Call module registration function if it exists - this should be handled by the export above
                # but we're double-checking
                if declare -F "module_register" > /dev/null; then
                    echo "INFO: Running module_register for: $module_name"
                    module_register || echo "WARNING: Failed to register functions for $module_name"
                fi
                
                loaded_modules=$((loaded_modules + 1))
                echo "INFO: Module loaded successfully: $module_name"
            else
                echo "ERROR: Failed to source module: $module_name with exit code $source_result"
            fi
        else
            echo "ERROR: Module file not found for $module_name at ${module_dir}/main.sh"
        fi
        
        # Clear current module name
        unset CURRENT_MODULE_NAME
    done
    
    # Verify essential functions are available
    for func in "port_scan" "subdomain_scan" "http_probe" "path_discover" "screenshot_capture" "vuln_scan"; do
        if ! declare -F "$func" > /dev/null; then
            log_warn "Function '$func' is not available. Some features may not work."
        else
            log_debug "Function '$func' is available."
        fi
    done
    
    log_info "Loaded $loaded_modules modules"
    return 0
}
