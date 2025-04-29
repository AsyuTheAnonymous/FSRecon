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
    
    # Check if vulnerability scanner is installed
    local scanner="$(get_config tools vuln_scanner "nuclei")"
    
    if ! command -v "$scanner" &>/dev/null; then
        log_error "Vulnerability scanner '$scanner' not found"
        return 1
    fi
    
    log_debug "Vulnerability scanning module initialized"
    return 0
}

# Scan targets for vulnerabilities
# Usage: vuln_scan targets_file output_dir [options]
vuln_scan() {
    local targets_file="$1"
    local output_dir="$2"
    local options="${3:-}"
    
    log_info "Scanning targets for vulnerabilities from $targets_file"
    
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
    local templates_dir="$(get_config tools nuclei_templates_dir "")"
    
    if [[ -n "$options" ]]; then
        # User-provided options override defaults
        default_options="$options"
    fi
    
    log_debug "Using scanner: $scanner with options: $default_options"
    
    # Output files
    local output_file="${output_dir}/vulnerabilities.txt"
    local json_output="${output_dir}/vulnerabilities.json"
    
    # Prepare command
    local cmd="$scanner -l \"$targets_file\" -o \"$output_file\" $default_options"
    
    # Add template directory if specified
    if [[ -n "$templates_dir" ]]; then
        cmd+=" -t \"$templates_dir\""
    fi
    
    # Add JSON output if supported
    if [[ "$scanner" == "nuclei" ]]; then
        cmd+=" -json -jsonl -o $json_output"
    fi
    
    log_debug "Running command: $cmd"
    
    # Run scanner
    eval $cmd > /dev/null 2>&1
    local exit_code=$?
    
    if [[ $exit_code -eq 0 ]]; then
        # Count vulnerabilities
        local count=0
        if [[ -f "$output_file" ]]; then
            count=$(wc -l < "$output_file")
        fi
        
        log_info "Vulnerability scanning completed successfully. Found $count potential issues."
        
        # Process JSON output if needed
        if [[ "$scanner" != "nuclei" && -f "$output_file" ]]; then
            _vuln_generate_json "$output_file" "$json_output"
        fi
    else
        log_error "Vulnerability scanning failed with exit code $exit_code"
    fi
    
    return $exit_code
}

# Internal function to generate JSON from vulnerability results
# Usage: _vuln_generate_json input_file json_output
_vuln_generate_json() {
    local input_file="$1"
    local json_output="$2"
    
    log_debug "Generating JSON output from $input_file"
    
    # Generate JSON
    {
        echo '{'
        echo '  "scanner": "'"$(get_config tools vuln_scanner "nuclei")"'",'
        echo '  "timestamp": "'"$(date -u +"%Y-%m-%dT%H:%M:%SZ")"'",'
        echo '  "vulnerabilities": ['
        
        # Process vulnerabilities
        local first=true
        while IFS= read -r line || [[ -n "$line" ]]; do
            [[ -z "$line" ]] && continue
            
            # Parse line based on format (assuming nuclei-like format)
            if [[ "$line" =~ ^\[([^]]+)\]\ \[([^]]+)\]\ \[([^]]+)\]\ (.+)\ \[\[(.+)\]\] ]]; then
                local host="${BASH_REMATCH[1]}"
                local severity="${BASH_REMATCH[2]}"
                local type="${BASH_REMATCH[3]}"
                local vuln="${BASH_REMATCH[4]}"
                local tags="${BASH_REMATCH[5]}"
                
                if [[ "$first" == true ]]; then
                    first=false
                else
                    echo '    ,'
                fi
                
                echo '    {'
                echo '      "host": "'"$host"'",'
                echo '      "severity": "'"$severity"'",'
                echo '      "type": "'"$type"'",'
                echo '      "name": "'"$vuln"'",'
                echo '      "tags": "'"$tags"'"'
                echo '    }'
            else
                # Fallback for unparseable lines
                if [[ "$first" == true ]]; then
                    first=false
                else
                    echo '    ,'
                fi
                
                echo '    {'
                echo '      "raw": "'"${line//\"/\\\"}"'"'
                echo '    }'
            fi
        done < "$input_file"
        
        echo '  ]'
        echo '}'
    } > "$json_output"
    
    return 0
}

# Register module functions
module_register() {
    register_function "vuln_scan" "Scan targets for vulnerabilities"
}

# Initialize module
vuln_init

# Export module
export -f vuln_scan

# Report success
return 0