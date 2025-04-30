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
    
    # Check if screenshot tool is installed - NixOS compatible check
    local tool="$(get_config tools screenshot_tool "gowitness")"
    
    if ! command -v "$tool" &>/dev/null; then
        echo "WARNING: Screenshot tool '$tool' not found in standard PATH"
        echo "Checking for NixOS-specific paths..."
        
        # Common NixOS binary paths
        if [[ -x "/run/current-system/sw/bin/$tool" ]]; then
            echo "Found $tool in /run/current-system/sw/bin/"
            export PATH="/run/current-system/sw/bin:$PATH"
        elif [[ -x "$HOME/.nix-profile/bin/$tool" ]]; then
            echo "Found $tool in $HOME/.nix-profile/bin/"
            export PATH="$HOME/.nix-profile/bin:$PATH"
        else
            echo "ERROR: Screenshot tool '$tool' not found"
            echo "Please install it with: nix-env -iA nixos.${tool}"
            # Continue anyway to allow for testing
            echo "Continuing without screenshot capability"
        fi
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
    local default_options="$(get_config tools "${tool}_options" "--no-redirect")"
    
    if [[ -n "$options" ]]; then
        # User-provided options override defaults
        default_options="$options"
    fi
    
    log_debug "Using tool: $tool with options: $default_options"
    
    # Run capture based on tool type
    case "$tool" in
        "gowitness")
            _screenshot_capture_gowitness "$targets_file" "$output_dir" "$default_options"
            ;;
        "aquatone")
            _screenshot_capture_aquatone "$targets_file" "$output_dir" "$default_options"
            ;;
        *)
            log_error "Unsupported screenshot tool: $tool"
            return 1
            ;;
    esac
    
    local exit_code=$?
    
    if [[ $exit_code -eq 0 ]]; then
        # Count screenshots taken
        local count=$(find "$output_dir" -type f -name "*.png" | wc -l)
        
        log_info "Screenshot capture completed successfully. Took $count screenshots."
    else
        log_error "Screenshot capture failed with exit code $exit_code"
    fi
    
    return $exit_code
}

# Internal function to run gowitness
# Usage: _screenshot_capture_gowitness targets_file output_dir options
_screenshot_capture_gowitness() {
    local targets_file="$1"
    local output_dir="$2"
    local options="$3"
    
    log_debug "Running gowitness on targets from $targets_file"
    
    # Create temporary file for gowitness
    local error_log="${output_dir}/gowitness_error.log"
    
    # Run gowitness, capturing stderr
    log_debug "Executing: gowitness file -f \"$targets_file\" --destination \"$output_dir\" $options"
    gowitness file -f "$targets_file" --destination "$output_dir" $options > /dev/null 2> "$error_log"
    local exit_code=$?
    
    # Log errors if any occurred
    if [[ $exit_code -ne 0 && -s "$error_log" ]]; then
        log_error "Gowitness failed. Error log:"
        # Use cat and indent for readability in main log
        while IFS= read -r line; do log_error "  $line"; done < "$error_log"
    elif [[ -f "$error_log" ]]; then
        # Remove empty error log
        rm "$error_log"
    fi
    
    return $exit_code
}

# Internal function to run aquatone
# Usage: _screenshot_capture_aquatone targets_file output_dir options
_screenshot_capture_aquatone() {
    local targets_file="$1"
    local output_dir="$2"
    local options="$3"
    
    log_debug "Running aquatone on targets from $targets_file"
    
    # Run aquatone
    cat "$targets_file" | aquatone -out "$output_dir" $options > /dev/null 2>&1
    local exit_code=$?
    
    return $exit_code
}

# Register module functions
module_register() {
    register_function "screenshot_capture" "Capture screenshots of target hosts"
    register_function "_screenshot_capture_gowitness" "Internal: Run gowitness for screenshot capture"
    register_function "_screenshot_capture_aquatone" "Internal: Run aquatone for screenshot capture"
}

# Initialize module
screenshot_init

# Report success
return 0
