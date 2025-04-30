#!/bin/bash
# modules/path/main.sh - Path discovery module

# Register module
MODULE_NAME="path"
MODULE_DESCRIPTION="Path discovery module"
MODULE_VERSION="1.0.0"
MODULE_AUTHOR="FSRecon Team"
MODULE_DEPENDENCIES=()

# Module initialization
# Called when the module is loaded
# Usage: path_init
path_init() {
    log_debug "Initializing path discovery module"
    
    # Check if path scanner is installed - NixOS compatible check
    local scanner="$(get_config tools path_scanner "gobuster")"
    
    if ! command -v "$scanner" &>/dev/null; then
        echo "WARNING: Path scanner '$scanner' not found in standard PATH"
        echo "Checking for NixOS-specific paths..."
        
        # Common NixOS binary paths
        if [[ -x "/run/current-system/sw/bin/$scanner" ]]; then
            echo "Found $scanner in /run/current-system/sw/bin/"
            export PATH="/run/current-system/sw/bin:$PATH"
        elif [[ -x "$HOME/.nix-profile/bin/$scanner" ]]; then
            echo "Found $scanner in $HOME/.nix-profile/bin/"
            export PATH="$HOME/.nix-profile/bin:$PATH"
        else
            echo "ERROR: Path scanner '$scanner' not found"
            echo "Please install it with: nix-env -iA nixos.${scanner}"
            # Continue anyway to allow for testing
            echo "Continuing without path discovery capability"
        fi
    fi
    
    log_debug "Path discovery module initialized"
    return 0
}

# Discover paths on target hosts
# Usage: path_discover targets_file output_dir [options]
path_discover() {
    local targets_file="$1"
    local output_dir="$2"
    local options="${3:-}"
    
    log_info "Discovering paths on targets from $targets_file"
    
    # Check if targets file exists
    if [[ ! -f "$targets_file" ]]; then
        log_error "Targets file not found: $targets_file"
        return 1
    fi
    
    # Create output directory
    mkdir -p "$output_dir"
    
    # Determine scanner and options
    local scanner="$(get_config tools path_scanner "gobuster")"
    local default_options="$(get_config tools "${scanner}_options" "-q")"
    # Use FSRECON_ROOT to ensure absolute path for wordlist
    local wordlist_relative="$(get_config wordlists dir_wordlist "wordlists/directories/directory-list-2.3-medium.txt")"
    # Correct path joining: remove potential leading ./ from relative path
    wordlist_relative="${wordlist_relative#./}" 
    local wordlist="${FSRECON_ROOT}/${wordlist_relative}"
    
    if [[ -n "$options" ]]; then
        # User-provided options override defaults
        default_options="$options"
    fi
    
    # Check if wordlist exists
    if [[ ! -f "$wordlist" ]]; then
        log_error "Directory wordlist not found: $wordlist"
        return 1
    fi
    
    log_debug "Using scanner: $scanner with options: $default_options"
    log_debug "Using wordlist: $wordlist"
    
    # Output file for consolidated results
    local output_file="${output_dir}/paths_discovered.txt"
    local json_output="${output_dir}/paths_discovered.json"
    
    # Clear previous results if any
    > "$output_file"
    
    # Initialize JSON structure
    {
        echo '{'
        echo '  "scanner": "'"$scanner"'",'
        echo '  "timestamp": "'"$(date -u +"%Y-%m-%dT%H:%M:%SZ")"'",'
        echo '  "targets": {'
    } > "$json_output"
    
    # Process each target
    local total_targets=$(wc -l < "$targets_file")
    local current_target=0
    local first_target=true
    local total_paths_found=0
    
    while IFS= read -r target_url || [[ -n "$target_url" ]]; do
        # Skip empty lines
        [[ -z "$target_url" ]] && continue
        
        # Extract URL part if additional info is present
        target_url=$(echo "$target_url" | sed 's/ .*//') 
        
        current_target=$((current_target + 1))
        log_debug "Processing target $current_target/$total_targets: $target_url"
        show_progress $current_target $total_targets "Path Discovery"
        
        # Create temporary output file
        local temp_output="${output_dir}/.tmp_${current_target}.txt"
        
        # Run scanner based on type
        case "$scanner" in
            "gobuster")
                _path_discover_gobuster "$target_url" "$wordlist" "$temp_output" "$default_options"
                ;;
            "dirb")
                _path_discover_dirb "$target_url" "$wordlist" "$temp_output" "$default_options"
                ;;
            "dirsearch")
                _path_discover_dirsearch "$target_url" "$wordlist" "$temp_output" "$default_options"
                ;;
            *)
                log_error "Unsupported path scanner: $scanner"
                continue # Skip to next target
                ;;
        esac
        
        local exit_code=$?
        local paths_found=0
        
        # Append results to main file if scan was successful
        if [[ $exit_code -eq 0 && -f "$temp_output" && -s "$temp_output" ]]; then
            paths_found=$(wc -l < "$temp_output")
            total_paths_found=$((total_paths_found + paths_found))
            
            # Append to text output
            echo "### Paths for $target_url ###" >> "$output_file"
            cat "$temp_output" >> "$output_file"
            echo "" >> "$output_file"
            
            # Append to JSON output
            if [[ "$first_target" == true ]]; then
                first_target=false
            else
                echo ',' >> "$json_output"
            fi
            
            {
                echo '    "'"$target_url"'": {'
                echo '      "count": '"$paths_found"','
                echo '      "paths": ['
                
                # Convert paths to JSON array
                local first_path=true
                while IFS= read -r line || [[ -n "$line" ]]; do
                    [[ -z "$line" ]] && continue
                    
                    # Extract path from scanner output (format depends on scanner)
                    local path=""
                    case "$scanner" in
                        "gobuster")
                            # Example: /admin (Status: 200) [Size: 1234]
                            path=$(echo "$line" | awk '{print $1}')
                            ;;
                        "dirb")
                            # Example: + /admin (CODE:200|SIZE:1234)
                            path=$(echo "$line" | awk '{print $2}')
                            ;;
                        "dirsearch")
                            # Example: 200   1234B   /admin
                            path=$(echo "$line" | awk '{print $3}')
                            ;;
                        *)
                            path="$line"
                            ;;
                    esac
                    
                    if [[ "$first_path" == true ]]; then
                        echo '        "'"$path"'"'
                        first_path=false
                    else
                        echo '        ,"'"$path"'"'
                    fi
                done < "$temp_output"
                
                echo '      ]'
                echo '    }'
            } >> "$json_output"
            
            log_debug "Found $paths_found paths on $target_url"
        else
            log_debug "No paths found or scan failed for $target_url"
            
            # Add empty entry to JSON
            if [[ "$first_target" == true ]]; then
                first_target=false
            else
                echo ',' >> "$json_output"
            fi
            
            {
                echo '    "'"$target_url"'": {'
                echo '      "count": 0,'
                echo '      "paths": []'
                echo '    }'
            } >> "$json_output"
        fi
        
        # Clean up temp file
        [[ -f "$temp_output" ]] && rm "$temp_output"
        
    done < "$targets_file"
    
    # Complete JSON structure
    {
        echo '  }'
        echo '  ,"total_paths_found": '"$total_paths_found"
        echo '}'
    } >> "$json_output"
    
    # Final summary
    log_info "Path discovery completed. Found $total_paths_found total paths across all targets."
    
    return 0
}

# Internal function to run gobuster
# Usage: _path_discover_gobuster target_url wordlist output_file options
_path_discover_gobuster() {
    local target_url="$1"
    local wordlist="$2"
    local output_file="$3"
    local options="$4"
    
    log_debug "Running gobuster on $target_url"
    
    # Run gobuster
    gobuster dir -u "$target_url" -w "$wordlist" $options -o "$output_file" > /dev/null 2>&1
    
    return $?
}

# Internal function to run dirb
# Usage: _path_discover_dirb target_url wordlist output_file options
_path_discover_dirb() {
    local target_url="$1"
    local wordlist="$2"
    local output_file="$3"
    local options="$4"
    
    log_debug "Running dirb on $target_url"
    
    # Run dirb
    dirb "$target_url" "$wordlist" -o "$output_file" $options > /dev/null 2>&1
    
    return $?
}

# Internal function to run dirsearch
# Usage: _path_discover_dirsearch target_url wordlist output_file options
_path_discover_dirsearch() {
    local target_url="$1"
    local wordlist="$2"
    local output_file="$3"
    local options="$4"
    
    log_debug "Running dirsearch on $target_url"
    
    # Run dirsearch
    dirsearch -u "$target_url" -w "$wordlist" --simple-report="$output_file" $options > /dev/null 2>&1
    
    return $?
}

# Register module functions
module_register() {
    register_function "path_discover" "Discover paths on target hosts"
}

# Initialize module
path_init

# Export module
export -f path_discover

# Report success
return 0
