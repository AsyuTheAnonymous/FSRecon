#!/bin/bash
# modules/port/main.sh - Port scanning module

# Register module
MODULE_NAME="port"
MODULE_DESCRIPTION="Port scanning module"
MODULE_VERSION="1.0.0"
MODULE_AUTHOR="FSRecon Team"
MODULE_DEPENDENCIES=()

# Module initialization
# Called when the module is loaded
# Usage: port_init
port_init() {
    log_debug "Initializing port scanning module"
    
    # Check if port scanner is installed
    local scanner="$(get_config tools port_scanner "nmap")"
    
    if ! command -v "$scanner" &>/dev/null; then
        log_error "Port scanner '$scanner' not found"
        return 1
    fi
    
    log_debug "Port scanning module initialized"
    return 0
}

# Scan ports on a target
# Usage: port_scan target output_dir [options]
port_scan() {
    local target="$1"
    local output_dir="$2"
    local options="${3:-}"
    
    log_info "Scanning ports on $target"
    
    # Create output directory
    mkdir -p "$output_dir"
    
    # Determine scanner and options
    local scanner="$(get_config tools port_scanner "nmap")"
    local default_options="$(get_config tools "${scanner}_options" "")"
    
    if [[ -n "$options" ]]; then
        # User-provided options override defaults
        default_options="$options"
    fi
    
    log_debug "Using scanner: $scanner with options: $default_options"
    
    # Run scan based on scanner type
    case "$scanner" in
        "nmap")
            _port_scan_nmap "$target" "$output_dir" "$default_options"
            ;;
        "masscan")
            _port_scan_masscan "$target" "$output_dir" "$default_options"
            ;;
        *)
            log_error "Unsupported port scanner: $scanner"
            return 1
            ;;
    esac
    
    local exit_code=$?
    
    if [[ $exit_code -eq 0 ]]; then
        log_info "Port scan completed successfully for $target"
    else
        log_error "Port scan failed for $target with exit code $exit_code"
    fi
    
    return $exit_code
}

# Parse port scan results
# Usage: port_parse_results output_dir
port_parse_results() {
    local output_dir="$1"
    local results_file="${output_dir}/ports.json"
    
    log_debug "Parsing port scan results from $output_dir"
    
    # Check if raw results exist
    if [[ ! -f "${output_dir}/ports.xml" && ! -f "${output_dir}/ports.txt" ]]; then
        log_error "No port scan results found in $output_dir"
        return 1
    fi
    
    # Determine scanner
    local scanner="$(get_config tools port_scanner "nmap")"
    
    # Parse results based on scanner type
    case "$scanner" in
        "nmap")
            _port_parse_nmap "$output_dir" "$results_file"
            ;;
        "masscan")
            _port_parse_masscan "$output_dir" "$results_file"
            ;;
        *)
            log_error "Unsupported port scanner results: $scanner"
            return 1
            ;;
    esac
    
    local exit_code=$?
    
    if [[ $exit_code -eq 0 && -f "$results_file" ]]; then
        log_info "Port scan results parsed successfully to $results_file"
        return 0
    else
        log_error "Failed to parse port scan results"
        return 1
    fi
}

# Internal function to run nmap scan
# Usage: _port_scan_nmap target output_dir options
_port_scan_nmap() {
    local target="$1"
    local output_dir="$2"
    local options="$3"
    
    local output_file="${output_dir}/ports.xml"
    local txt_output="${output_dir}/ports.txt"
    
    log_debug "Running nmap scan on $target"
    
    # Run nmap
    nmap $options -oX "$output_file" -oN "$txt_output" "$target" > /dev/null 2>&1
    local exit_code=$?
    
    return $exit_code
}

# Internal function to parse nmap results
# Usage: _port_parse_nmap output_dir json_output
_port_parse_nmap() {
    local output_dir="$1"
    local json_output="$2"
    
    local xml_file="${output_dir}/ports.xml"
    
    # Check if XML file exists
    if [[ ! -f "$xml_file" ]]; then
        log_error "Nmap XML output not found: $xml_file"
        return 1
    fi
    
    # Convert XML to JSON using Python (if available)
    if command -v python3 &>/dev/null; then
        python3 -c '
import sys
import json
import xml.etree.ElementTree as ET

try:
    # Parse XML
    tree = ET.parse(sys.argv[1])
    root = tree.getroot()
    
    # Initialize result
    result = {
        "scanner": "nmap",
        "target": "",
        "start_time": "",
        "end_time": "",
        "hosts": []
    }
    
    # Get scan info
    if root.find("./runstats/finished") is not None:
        result["start_time"] = root.get("start", "")
        result["end_time"] = root.find("./runstats/finished").get("time", "")
    
    # Process each host
    for host in root.findall("./host"):
        host_data = {
            "ip": "",
            "hostname": "",
            "status": "",
            "ports": []
        }
        
        # Get IP address
        addr = host.find("./address")
        if addr is not None and addr.get("addrtype") == "ipv4":
            host_data["ip"] = addr.get("addr", "")
        
        # Get hostname
        hostname = host.find("./hostnames/hostname")
        if hostname is not None:
            host_data["hostname"] = hostname.get("name", "")
        
        # Get status
        status = host.find("./status")
        if status is not None:
            host_data["status"] = status.get("state", "")
        
        # Get ports
        for port in host.findall("./ports/port"):
            port_data = {
                "protocol": port.get("protocol", ""),
                "port": port.get("portid", ""),
                "state": "",
                "service": "",
                "version": ""
            }
            
            # Get state
            state = port.find("./state")
            if state is not None:
                port_data["state"] = state.get("state", "")
            
            # Get service
            service = port.find("./service")
            if service is not None:
                port_data["service"] = service.get("name", "")
                port_data["version"] = service.get("product", "") + " " + service.get("version", "")
                port_data["version"] = port_data["version"].strip()
            
            # Add port to host
            if port_data["state"] == "open":
                host_data["ports"].append(port_data)
        
        # Add host to result
        if host_data["status"] == "up" and len(host_data["ports"]) > 0:
            result["hosts"].append(host_data)
    
    # Output JSON
    print(json.dumps(result, indent=2))
    
except Exception as e:
    sys.stderr.write(f"Error processing XML: {e}\n")
    sys.exit(1)
' "$xml_file" > "$json_output" 2>/dev/null
        
        return $?
    else
        log_error "Python3 not found, can't convert XML to JSON"
        
        # Fallback to simple grep
        {
            echo '{'
            echo '  "scanner": "nmap",'
            echo '  "hosts": ['
            echo '    {'
            echo '      "ports": ['
            
            grep "open" "${output_dir}/ports.txt" | grep -v "filtered" | while read line; do
                port=$(echo "$line" | awk '{print $1}')
                service=$(echo "$line" | awk '{print $3}')
                
                echo '        {'
                echo "          \"port\": \"$port\","
                echo "          \"service\": \"$service\","
                echo "          \"state\": \"open\""
                echo '        },'
            done | sed '$ s/,$//'
            
            echo '      ]'
            echo '    }'
            echo '  ]'
            echo '}'
        } > "$json_output"
        
        return $?
    fi
}

# Internal function to run masscan
# Usage: _port_scan_masscan target output_dir options
_port_scan_masscan() {
    local target="$1"
    local output_dir="$2"
    local options="$3"
    
    local output_file="${output_dir}/ports.txt"
    
    log_debug "Running masscan on $target"
    
    # Run masscan
    masscan $options -oG "$output_file" "$target" > /dev/null 2>&1
    local exit_code=$?
    
    return $exit_code
}

# Internal function to parse masscan results
# Usage: _port_parse_masscan output_dir json_output
_port_parse_masscan() {
    local output_dir="$1"
    local json_output="$2"
    
    local txt_file="${output_dir}/ports.txt"
    
    # Check if txt file exists
    if [[ ! -f "$txt_file" ]]; then
        log_error "Masscan output not found: $txt_file"
        return 1
    fi
    
    # Convert to JSON
    {
        echo '{'
        echo '  "scanner": "masscan",'
        echo '  "hosts": ['
        echo '    {'
        echo '      "ports": ['
        
        grep "open" "$txt_file" | while read line; do
            ip=$(echo "$line" | awk '{print $4}')
            port=$(echo "$line" | awk '{print $5}' | cut -d'/' -f1)
            proto=$(echo "$line" | awk '{print $5}' | cut -d'/' -f2)
            
            echo '        {'
            echo "          \"ip\": \"$ip\","
            echo "          \"port\": \"$port\","
            echo "          \"protocol\": \"$proto\","
            echo "          \"state\": \"open\""
            echo '        },'
        done | sed '$ s/,$//'
        
        echo '      ]'
        echo '    }'
        echo '  ]'
        echo '}'
    } > "$json_output"
    
    return $?
}

# Register module functions
module_register() {
    register_function "port_scan" "Scan ports on a target"
    register_function "port_parse_results" "Parse port scan results"
}

# Initialize module
port_init

# Export module
export -f port_scan
export -f port_parse_results

# Report success
return 0

### HTTP Probing Module (`modules/http/main.sh`)

```bash
#!/bin/bash
# modules/http/main.sh - HTTP probing module

# Register module
MODULE_NAME="http"
MODULE_DESCRIPTION="HTTP probing module"
MODULE_VERSION="1.0.0"
MODULE_AUTHOR="FSRecon Team"
MODULE_DEPENDENCIES=()

# Module initialization
# Called when the module is loaded
# Usage: http_init
http_init() {
    log_debug "Initializing HTTP probing module"
    
    # Check if HTTP prober is installed
    local prober="$(get_config tools http_prober "httpx")"
    
    if ! command -v "$prober" &>/dev/null; then
        log_error "HTTP prober '$prober' not found"
        return 1
    fi
    
    log_debug "HTTP probing module initialized"
    return 0
}

# Probe a list of hosts for HTTP/HTTPS services
# Usage: http_probe targets_file output_dir [options]
http_probe() {
    local targets_file="$1"
    local output_dir="$2"
    local options="${3:-}"
    
    log_info "Probing targets for HTTP/HTTPS services"
    
    # Check if targets file exists
    if [[ ! -f "$targets_file" ]]; then
        log_error "Targets file not found: $targets_file"
        return 1
    fi
    
    # Create output directory
    mkdir -p "$output_dir"
    
    # Determine prober and options
    local prober="$(get_config tools http_prober "httpx")"
    local default_options="$(get_config tools "${prober}_options" "")"
    
    if [[ -n "$options" ]]; then
        # User-provided options override defaults
        default_options="$options"
    fi
    
    log_debug "Using prober: $prober with options: $default_options"
    
    # Output files
    local output_file="${output_dir}/live_hosts.txt"
    local json_output="${output_dir}/live_hosts_details.json"
    
    # Run prober based on type
    case "$prober" in
        "httpx")
            _http_probe_httpx "$targets_file" "$output_file" "$json_output" "$default_options"
            ;;
        "httprobe")
            _http_probe_httprobe "$targets_file" "$output_file" "$default_options"
            ;;
        *)
            log_error "Unsupported HTTP prober: $prober"
            return 1
            ;;
    esac
    
    local exit_code=$?
    
    if [[ $exit_code -eq 0 ]]; then
        # Count live hosts
        local count=0
        if [[ -f "$output_file" ]]; then
            count=$(wc -l < "$output_file")
        fi
        
        log_info "HTTP probing completed successfully. Found $count live hosts."
    else
        log_error "HTTP probing failed with exit code $exit_code"
    fi
    
    return $exit_code
}

# Parse HTTP probe results
# Usage: http_parse_results output_dir
http_parse_results() {
    local output_dir="$1"
    local results_file="${output_dir}/http_results.json"
    
    log_debug "Parsing HTTP probe results from $output_dir"
    
    # Check if raw results exist
    if [[ ! -f "${output_dir}/live_hosts.txt" ]]; then
        log_error "No HTTP probe results found in $output_dir"
        return 1
    fi
    
    # Determine prober
    local prober="$(get_config tools http_prober "httpx")"
    
    # Parse results based on prober type
    case "$prober" in
        "httpx")
            if [[ -f "${output_dir}/live_hosts_details.json" ]]; then
                # Already in JSON format
                cp "${output_dir}/live_hosts_details.json" "$results_file"
            else
                _http_parse_httpx "${output_dir}/live_hosts.txt" "$results_file"
            fi
            ;;
        "httprobe")
            _http_parse_httprobe "${output_dir}/live_hosts.txt" "$results_file"
            ;;
        *)
            log_error "Unsupported HTTP prober results: $prober"
            return 1
            ;;
    esac
    
    local exit_code=$?
    
    if [[ $exit_code -eq 0 && -f "$results_file" ]]; then
        log_info "HTTP probe results parsed successfully to $results_file"
        return 0
    else
        log_error "Failed to parse HTTP probe results"
        return 1
    fi
}

# Internal function to run httpx
# Usage: _http_probe_httpx targets_file output_file json_output options
_http_probe_httpx() {
    local targets_file="$1"
    local output_file="$2"
    local json_output="$3"
    local options="$4"
    
    log_debug "Running httpx on targets from $targets_file"
    
    # Run httpx for plain output
    cat "$targets_file" | httpx $options -o "$output_file" > /dev/null 2>&1
    
    # Run httpx for JSON output if requested
    if [[ -n "$json_output" ]]; then
        cat "$targets_file" | httpx $options -json -o "$json_output" > /dev/null 2>&1
    fi
    
    return $?
}

# Internal function to run httprobe
# Usage: _http_probe_httprobe targets_file output_file options
_http_probe_httprobe() {
    local targets_file="$1"
    local output_file="$2"
    local options="$3"
    
    log_debug "Running httprobe on targets from $targets_file"
    
    # Run httprobe
    cat "$targets_file" | httprobe $options > "$output_file" 2>/dev/null
    
    return $?
}

# Internal function to parse httpx results
# Usage: _http_parse_httpx input_file json_output
_http_parse_httpx() {
    local input_file="$1"
    local json_output="$2"
    
    # Convert plain text to JSON
    {
        echo '{'
        echo '  "prober": "httpx",'
        echo '  "timestamp": "'"$(date -u +"%Y-%m-%dT%H:%M:%SZ")"'",'
        echo '  "hosts": ['
        
        while read -r url; do
            echo '    {'
            echo "      \"url\": \"$url\""
            echo '    },'
        done < "$input_file" | sed '$ s/,$//'
        
        echo '  ]'
        echo '}'
    } > "$json_output"
    
    return $?
}

# Internal function to parse httprobe results
# Usage: _http_parse_httprobe input_file json_output
_http_parse_httprobe() {
    local input_file="$1"
    local json_output="$2"
    
    # Convert plain text to JSON
    {
        echo '{'
        echo '  "prober": "httprobe",'
        echo '  "timestamp": "'"$(date -u +"%Y-%m-%dT%H:%M:%SZ")"'",'
        echo '  "hosts": ['
        
        while read -r url; do
            protocol=$(echo "$url" | cut -d':' -f1)
            host=$(echo "$url" | cut -d'/' -f3)
            
            echo '    {'
            echo "      \"url\": \"$url\","
            echo "      \"protocol\": \"$protocol\","
            echo "      \"host\": \"$host\""
            echo '    },'
        done < "$input_file" | sed '$ s/,$//'
        
        echo '  ]'
        echo '}'
    } > "$json_output"
    
    return $?
}

# Register module functions
module_register() {
    register_function "http_probe" "Probe hosts for HTTP/HTTPS services"
    register_function "http_parse_results" "Parse HTTP probe results"
}

# Initialize module
http_init

# Export module
export -f http_probe
export -f http_parse_results

# Report success
return 0