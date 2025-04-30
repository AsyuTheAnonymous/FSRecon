#!/bin/bash
# lib/logger.sh - Logging functionality for FSRecon

# Log levels
export LOG_LEVEL_DEBUG=0
export LOG_LEVEL_INFO=1
export LOG_LEVEL_WARN=2
export LOG_LEVEL_ERROR=3

# ANSI color codes
export COLOR_RESET="\033[0m"
export COLOR_DEBUG="\033[36m"   # Cyan
export COLOR_INFO="\033[32m"    # Green
export COLOR_WARN="\033[33m"    # Yellow
export COLOR_ERROR="\033[31m"   # Red

# Global variables
LOGGER_LEVEL=$LOG_LEVEL_INFO
LOGGER_FILE=""
LOGGER_USE_COLOR=true
LOGGER_INITIALIZED=false

# Initialize logger
# Usage: init_logger
init_logger() {
    [[ "$LOGGER_INITIALIZED" == true ]] && return 0
    
    # Set log level from configuration
    local log_level="$(get_config general log_level "INFO")"
    case "${log_level^^}" in
        "DEBUG") LOGGER_LEVEL=$LOG_LEVEL_DEBUG ;;
        "INFO")  LOGGER_LEVEL=$LOG_LEVEL_INFO ;;
        "WARN")  LOGGER_LEVEL=$LOG_LEVEL_WARN ;;
        "ERROR") LOGGER_LEVEL=$LOG_LEVEL_ERROR ;;
        *)       LOGGER_LEVEL=$LOG_LEVEL_INFO ;;
    esac
    
    # Set log file from configuration
    LOGGER_FILE="$(get_config general log_file "${FSRECON_RUN_DIR}/fsrecon.log")"
    
    # Set color output from configuration
    LOGGER_USE_COLOR="$(get_config general color_output "true")"
    
    # Create log file directory if it doesn't exist
    mkdir -p "$(dirname "$LOGGER_FILE")"
    
    # Write header to log file
    echo "# FSRecon Log - $(date)" > "$LOGGER_FILE"
    echo "# Version: $FSRECON_VERSION" >> "$LOGGER_FILE"
    echo "# Run timestamp: $FSRECON_TIMESTAMP" >> "$LOGGER_FILE"
    echo "# Log level: $log_level" >> "$LOGGER_FILE"
    echo "---" >> "$LOGGER_FILE"
    
    LOGGER_INITIALIZED=true
    return 0
}

# Internal logging function
# Usage: _log level color tag message
_log() {
    local level="$1"
    local color="$2"
    local tag="$3"
    local message="$4"
    
    # Skip if log level is too low
    [[ $level -lt $LOGGER_LEVEL ]] && return 0
    
    # Format timestamp
    local timestamp="$(date +"%Y-%m-%d %H:%M:%S")"
    
    # Format message for console
    local console_msg
    if [[ "$LOGGER_USE_COLOR" == true ]]; then
        console_msg="${color}${timestamp} [${tag}] ${message}${COLOR_RESET}"
    else
        console_msg="${timestamp} [${tag}] ${message}"
    fi
    
    # Format message for log file
    local file_msg="${timestamp} [${tag}] ${message}"
    
    # Output to console
    echo -e "$console_msg"
    
    # Output to log file if set
    if [[ -n "$LOGGER_FILE" ]]; then
        echo "$file_msg" >> "$LOGGER_FILE"
    fi
    
    return 0
}

# Log debug message
# Usage: log_debug message
log_debug() {
    _log $LOG_LEVEL_DEBUG "$COLOR_DEBUG" "DEBUG" "$1"
}

# Log info message
# Usage: log_info message
log_info() {
    _log $LOG_LEVEL_INFO "$COLOR_INFO" "INFO" "$1"
}

# Log warning message
# Usage: log_warn message
log_warn() {
    _log $LOG_LEVEL_WARN "$COLOR_WARN" "WARN" "$1"
}

# Log error message
# Usage: log_error message
log_error() {
    _log $LOG_LEVEL_ERROR "$COLOR_ERROR" "ERROR" "$1"
}

# Display progress bar
# Usage: show_progress current total [label]
show_progress() {
    local current="$1"
    local total="$2"
    local label="${3:-Progress}"
    
    # Skip if not in interactive terminal or log level is debug
    [[ ! -t 1 || $LOGGER_LEVEL -eq $LOG_LEVEL_DEBUG ]] && return 0
    
    local percent=$((current * 100 / total))
    local bar_length=50
    local filled_length=$((bar_length * current / total))
    local empty_length=$((bar_length - filled_length))
    
    local bar=""
    local i
    
    # Build progress bar
    for ((i=0; i<filled_length; i++)); do
        bar+="▓"
    done
    
    for ((i=0; i<empty_length; i++)); do
        bar+="░"
    done
    
    # Print progress bar
    printf "\r%s: [%s] %d%% (%d/%d)" "$label" "$bar" "$percent" "$current" "$total"
    
    # Add newline if completed
    if [[ $current -eq $total ]]; then
        echo
    fi
    
    return 0
}
