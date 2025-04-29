#!/bin/bash
# modules/screenshot/main.sh - Screenshot capture module

# Register module
MODULE_NAME="screenshot"
MODULE_DESCRIPTION="Screenshot capture module"
MODULE_VERSION="1.0.0"
MODULE_AUTHOR="FSRecon Team"
MODULE_DEPENDENCIES=()

# Module initialization
# Called when the module is loaded
# Usage: screenshot_init
screenshot_init() {
    log_debug "Initializing screenshot capture module"
    
    # Check if screenshot tool is installed
    local tool="$(get_config tools screenshot_tool "gowitness")"
    
    if ! command -v "$tool" &>/dev/null; then
        log_error "Screenshot tool '$tool' not found"
        return 1
    fi
    
    log_debug "Screenshot capture module initialized"
    return 0
}

# Capture screenshots of target hosts
# Usage: screenshot_capture targets_file output_dir [options]
screenshot_capture() {
    local targets_file="$1"
    local output_dir="$2"
    local options="${3:-}"
    
    log_info "Capturing screenshots of targets from $targets_file"
    
    # Check if targets file exists
    if [[ ! -f "$targets_file" ]]; then
        log_error "Targets file not found: $targets_file"
        return 1
    fi
    
    # Create output directory
    mkdir -p "$output_dir"
    
    # Determine tool and options
    local tool="$(get_config tools screenshot_tool "gowitness")"
    local default_options="$(get_config tools "${tool}_options" "")"
    
    if [[ -n "$options" ]]; then
        # User-provided options override defaults
        default_options="$options"
    fi
    
    log_debug "Using tool: $tool with options: $default_options"
    
    # Run tool based on type
    case "$tool" in
        "gowitness")
            _screenshot_gowitness "$targets_file" "$output_dir" "$default_options"
            ;;
        "aquatone")
            _screenshot_aquatone "$targets_file" "$output_dir" "$default_options"
            ;;
        *)
            log_error "Unsupported screenshot tool: $tool"
            return 1
            ;;
    esac
    
    local exit_code=$?
    
    if [[ $exit_code -eq 0 ]]; then
        log_info "Screenshot capture completed successfully"
        
        # Generate report if available
        if [[ "$tool" == "gowitness" ]]; then
            log_info "Generating gowitness report"
            gowitness report generate -d "$output_dir" > /dev/null 2>&1
            
            if [[ -f "${output_dir}/report.html" ]]; then
                log_info "Gowitness report generated: ${output_dir}/report.html"
            fi
        fi
    else
        log_error "Screenshot capture failed with exit code $exit_code"
    fi
    
    return $exit_code
}

# Internal function to run gowitness
# Usage: _screenshot_gowitness targets_file output_dir options
_screenshot_gowitness() {
    local targets_file="$1"
    local output_dir="$2"
    local options="$3"
    
    log_debug "Running gowitness on targets from $targets_file"
    
    # Run gowitness
    gowitness file -f "$targets_file" -d "$output_dir" --no-redirect $options > /dev/null 2>&1
    
    return $?
}

# Internal function to run aquatone
# Usage: _screenshot_aquatone targets_file output_dir options
_screenshot_aquatone() {
    local targets_file="$1"
    local output_dir="$2"
    local options="$3"
    
    log_debug "Running aquatone on targets from $targets_file"
    
    # Run aquatone
    cat "$targets_file" | aquatone -out "$output_dir" $options > /dev/null 2>&1
    
    return $?
}

# Register module functions
module_register() {
    register_function "screenshot_capture" "Capture screenshots of target hosts"
}

# Initialize module
screenshot_init

# Export module
export -f screenshot_capture

# Report success
return 0