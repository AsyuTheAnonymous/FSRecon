#!/bin/bash
# lib/utils.sh - Utility functions for FSRecon

# Generate a random string
# Usage: random_string [length]
random_string() {
    local length="${1:-16}"
    cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w "$length" | head -n 1
}

# Convert seconds to human-readable time
# Usage: human_time seconds
human_time() {
    local seconds="$1"
    local days=$((seconds / 86400))
    local hours=$(( (seconds % 86400) / 3600 ))
    local minutes=$(( (seconds % 3600) / 60 ))
    local remaining_seconds=$((seconds % 60))
    
    if [[ $days -gt 0 ]]; then
        echo "${days}d ${hours}h ${minutes}m ${remaining_seconds}s"
    elif [[ $hours -gt 0 ]]; then
        echo "${hours}h ${minutes}m ${remaining_seconds}s"
    elif [[ $minutes -gt 0 ]]; then
        echo "${minutes}m ${remaining_seconds}s"
    else
        echo "${remaining_seconds}s"
    fi
}

# Get file size in human-readable format
# Usage: human_size bytes
human_size() {
    local bytes="$1"
    local units=("B" "KB" "MB" "GB" "TB")
    local unit=0
    local size="$bytes"
    
    while [[ $size -ge 1024 && $unit -lt 4 ]]; do
        size=$((size / 1024))
        unit=$((unit + 1))
    done
    
    echo "${size}${units[$unit]}"
}

# Get domain from URL
# Usage: get_domain url
get_domain() {
    local url="$1"
    
    # Remove protocol
    url="${url#http://}"
    url="${url#https://}"
    
    # Remove path and query
    url="${url%%/*}"
    url="${url%%\?*}"
    
    # Remove port
    url="${url%%:*}"
    
    echo "$url"
}

# Check if a string is in an array
# Usage: array_contains array element
array_contains() {
    local array="$1[@]"
    local element="$2"
    
    for item in "${!array}"; do
        [[ "$item" == "$element" ]] && return 0
    done
    
    return 1
}

# Join array elements with a delimiter
# Usage: join_by delimiter array
join_by() {
    local delimiter="$1"
    local array="$2[@]"
    local result=""
    local first=true
    
    for item in "${!array}"; do
        if [[ "$first" == true ]]; then
            result="$item"
            first=false
        else
            result+="${delimiter}${item}"
        fi
    done
    
    echo "$result"
}

# URL encode a string
# Usage: url_encode string
url_encode() {
    local string="$1"
    local encoded=""
    local i
    
    for ((i=0; i<${#string}; i++)); do
        local c="${string:$i:1}"
        case "$c" in
            [a-zA-Z0-9.~_-]) encoded+="$c" ;;
            *) encoded+="$(printf '%%%02X' "'$c")" ;;
        esac
    done
    
    echo "$encoded"
}

# Check if a port is open
# Usage: is_port_open host port [timeout]
is_port_open() {
    local host="$1"
    local port="$2"
    local timeout="${3:-2}"
    
    (echo > "/dev/tcp/$host/$port") &>/dev/null
    if [[ $? -eq 0 ]]; then
        return 0
    else
        return 1
    fi
}

# Convert JSON to Bash variables
# Usage: json_to_vars json [prefix]
json_to_vars() {
    local json="$1"
    local prefix="${2:-}"
    
    if command -v jq &>/dev/null; then
        local keys=$(echo "$json" | jq -r 'keys[]')
        
        for key in $keys; do
            local value=$(echo "$json" | jq -r ".[\"$key\"]")
            
            if [[ "$value" == "{" ]]; then
                # Nested object
                json_to_vars "$(echo "$json" | jq -r ".[\"$key\"]")" "${prefix}${key}_"
            else
                # Value
                local var_name="${prefix}${key}"
                var_name="${var_name//-/_}"
                var_name="${var_name//[^a-zA-Z0-9_]/}"
                
                export "$var_name"="$value"
            fi
        done
    else
        log_error "jq command not found, can't parse JSON"
        return 1
    fi
    
    return 0
}

# Run a command with timeout
# Usage: run_with_timeout timeout command [args...]
run_with_timeout() {
    local timeout="$1"
    shift
    
    if command -v timeout &>/dev/null; then
        timeout "$timeout" "$@"
        return $?
    else
        # Fallback if timeout command not available
        local pid
        
        # Run the command in background
        "$@" &
        pid=$!
        
        # Start a subprocess to kill the command after timeout
        (
            sleep "$timeout"
            kill -TERM $pid &>/dev/null
        ) &
        local timer_pid=$!
        
        # Wait for the command to finish
        wait $pid &>/dev/null
        local exit_code=$?
        
        # Kill the timer subprocess
        kill -TERM $timer_pid &>/dev/null
        
        return $exit_code
    fi
}