#!/bin/bash
# lib/reporting.sh - Reporting system for FSRecon

# Generate a text report for a domain
# Usage: generate_text_report domain output_file
generate_text_report() {
    local domain="$1"
    local output_file="$2"
    local domain_dir="${FSRECON_RUN_DIR}/${domain}"
    
    log_debug "Generating text report for $domain"
    
    {
        echo "==============================================="
        echo "      FULL SPECTRUM RECON REPORT"
        echo "      Target: $domain"
        echo "      Generated on $(date)"
        echo "==============================================="
        echo ""
        
        # Port scan summary
        echo "## OPEN PORTS"
        if [[ -f "${domain_dir}/port/ports.txt" ]]; then
            grep "open" "${domain_dir}/port/ports.txt" | grep -v "filtered"
        else
            echo "No port scan results available"
        fi
        echo ""
        
        # Subdomain summary
        echo "## SUBDOMAINS"
        if [[ -f "${domain_dir}/subdomain/subdomains.txt" ]]; then
            local count=$(wc -l < "${domain_dir}/subdomain/subdomains.txt")
            echo "Found $count subdomains:"
            cat "${domain_dir}/subdomain/subdomains.txt"
        else
            echo "No subdomains found"
        fi
        echo ""
        
        # HTTP probe summary
        echo "## LIVE WEB HOSTS"
        if [[ -f "${domain_dir}/http/live_hosts.txt" ]]; then
            local count=$(wc -l < "${domain_dir}/http/live_hosts.txt")
            echo "Found $count live web hosts:"
            cat "${domain_dir}/http/live_hosts.txt"
        else
            echo "No live web hosts found"
        fi
        echo ""
        
        # Vulnerability summary
        echo "## VULNERABILITIES"
        if [[ -f "${domain_dir}/vuln/vulnerabilities.txt" ]]; then
            local count=$(wc -l < "${domain_dir}/vuln/vulnerabilities.txt")
            echo "Found $count potential vulnerabilities/findings:"
            cat "${domain_dir}/vuln/vulnerabilities.txt"
        else
            echo "No vulnerabilities found matching the criteria"
        fi
        echo ""
        
        # Path discovery summary
        echo "## WEB PATHS"
        if [[ -f "${domain_dir}/path/paths_discovered.txt" ]]; then
            local count=$(grep -v "^$" "${domain_dir}/path/paths_discovered.txt" | wc -l)
            echo "Found $count accessible paths"
            cat "${domain_dir}/path/paths_discovered.txt"
        else
            echo "No accessible paths found"
        fi
        echo ""
        
        # Screenshots summary
        echo "## SCREENSHOTS"
        if [[ -d "${domain_dir}/screenshot" && "$(ls -A "${domain_dir}/screenshot")" ]]; then
            echo "Screenshots saved in: ${domain_dir}/screenshot"
            if [[ -f "${domain_dir}/screenshot/report.html" ]]; then
                echo "Screenshot report available at: ${domain_dir}/screenshot/report.html"
            fi
        else
            echo "No screenshots were generated"
        fi
        echo ""
    } > "$output_file"
    
    log_info "Text report generated: $output_file"
    
    return 0
}

# Generate a JSON report for a domain
# Usage: generate_json_report domain output_file
generate_json_report() {
    local domain="$1"
    local output_file="$2"
    local domain_dir="${FSRECON_RUN_DIR}/${domain}"
    
    log_debug "Generating JSON report for $domain"
    
    {
        echo '{'
        echo '  "domain": "'"$domain"'",'
        echo '  "timestamp": "'"$(date -u +"%Y-%m-%dT%H:%M:%SZ")"'",'
        echo '  "results": {'
        
        # Port scan results
        echo '    "ports": {'
        if [[ -f "${domain_dir}/port/ports.json" ]]; then
            echo '      "found": true,'
            echo '      "data": '
            cat "${domain_dir}/port/ports.json"
        else
            echo '      "found": false,'
            echo '      "data": null'
        fi
        echo '    },'
        
        # Subdomain results
        echo '    "subdomains": {'
        if [[ -f "${domain_dir}/subdomain/subdomains.json" ]]; then
            echo '      "found": true,'
            echo '      "data": '
            cat "${domain_dir}/subdomain/subdomains.json"
        else
            echo '      "found": false,'
            echo '      "data": null'
        fi
        echo '    },'
        
        # HTTP probe results
        echo '    "http": {'
        if [[ -f "${domain_dir}/http/live_hosts_details.json" ]]; then
            echo '      "found": true,'
            echo '      "data": '
            cat "${domain_dir}/http/live_hosts_details.json"
        else
            echo '      "found": false,'
            echo '      "data": null'
        fi
        echo '    },'
        
        # Path discovery results
        echo '    "paths": {'
        if [[ -f "${domain_dir}/path/paths_discovered.json" ]]; then
            echo '      "found": true,'
            echo '      "data": '
            cat "${domain_dir}/path/paths_discovered.json"
        elif [[ -f "${domain_dir}/path/paths_discovered.txt" ]]; then # Corrected 'else if' to 'elif'
            echo '      "found": true,'
            echo '      "count": '"$(grep -v "^$" "${domain_dir}/path/paths_discovered.txt" | wc -l)"','
            echo '      "data": ['
            
            # Convert paths to JSON array
            local first=true
            while IFS= read -r line || [[ -n "$line" ]]; do
                [[ -z "$line" || "$line" == \#* ]] && continue
                
                if [[ "$first" == true ]]; then
                    echo '        "'"$line"'"'
                    first=false
                else
                    echo '        ,"'"$line"'"'
                fi
            done < "${domain_dir}/path/paths_discovered.txt"
            
            echo '      ]'
        else
            echo '      "found": false,'
            echo '      "count": 0,'
            echo '      "data": []'
        fi
        echo '    },'
        
        # Screenshot results
        echo '    "screenshots": {'
        if [[ -d "${domain_dir}/screenshot" && "$(ls -A "${domain_dir}/screenshot")" ]]; then
            echo '      "found": true,'
            echo '      "count": '"$(find "${domain_dir}/screenshot" -type f -name "*.png" | wc -l)"','
            echo '      "report": "'"${domain_dir}/screenshot/report.html"'"'
        else
            echo '      "found": false,'
            echo '      "count": 0,'
            echo '      "report": null'
        fi
        echo '    },'
        
        # Vulnerability results
        echo '    "vulnerabilities": {'
        if [[ -f "${domain_dir}/vuln/vulnerabilities.json" ]]; then
            echo '      "found": true,'
            echo '      "data": '
            cat "${domain_dir}/vuln/vulnerabilities.json"
        elif [[ -f "${domain_dir}/vuln/vulnerabilities.txt" ]]; then # Corrected 'else if' to 'elif'
            echo '      "found": true,'
            echo '      "count": '"$(wc -l < "${domain_dir}/vuln/vulnerabilities.txt")"','
            echo '      "data": ['
        
            # Convert vulnerabilities to JSON array
            local first=true
            while IFS= read -r line || [[ -n "$line" ]]; do
                [[ -z "$line" ]] && continue
            
                if [[ "$first" == true ]]; then
                    echo '        "'"${line//\"/\\\"}"'"'
                    first=false
                else
                    echo '        ,"'"${line//\"/\\\"}"'"'
                fi
            done < "${domain_dir}/vuln/vulnerabilities.txt"
        
            echo '      ]'
        else
            echo '      "found": false,'
            echo '      "count": 0,'
            echo '      "data": []'
        fi
        echo '    }'
    
        echo '  }'
        echo '}'
    } > "$output_file"

    log_info "JSON report generated: $output_file"

    return 0
}

# Generate a master summary report for all domains
# Usage: generate_master_summary domains_array output_file
generate_master_summary() {
    local domains=("$@")
    local output_file="${FSRECON_RUN_DIR}/master_summary.txt"
    
    # Remove last argument (output file)
    unset 'domains[${#domains[@]}-1]'
    
    log_debug "Generating master summary report for ${#domains[@]} domains"
    
    {
        echo "===================================================="
        echo "      FULL SPECTRUM RECON - MASTER REPORT"
        echo "      Generated on $(date)"
        echo "===================================================="
        echo ""
        
        echo "Scan Configuration:"
        echo "- Port Scanner: $(get_config tools port_scanner "nmap")"
        echo "- Subdomain Scanner: $(get_config tools subdomain_scanner "subfinder")"
        echo "- HTTP Prober: $(get_config tools http_prober "httpx")"
        echo "- Path Scanner: $(get_config tools path_scanner "gobuster")"
        echo "- Screenshot Tool: $(get_config tools screenshot_tool "gowitness")"
        echo "- Vulnerability Scanner: $(get_config tools vuln_scanner "nuclei")"
        echo ""
        
        echo "Domains scanned:"
        for domain in "${domains[@]}"; do
            echo "- $domain"
        done
        echo ""
        
        echo "Summary of findings:"
        echo ""
        
        for domain in "${domains[@]}"; do
            local domain_dir="${FSRECON_RUN_DIR}/${domain}"
            
            echo "# Domain: $domain"
            echo "----------------"
            
            # Subdomain summary
            local subdomain_count=0
            if [[ -f "${domain_dir}/subdomain/subdomains.txt" ]]; then
                subdomain_count=$(wc -l < "${domain_dir}/subdomain/subdomains.txt")
            fi
            echo "Subdomains found: $subdomain_count"
            
            # Live hosts summary
            local live_hosts_count=0
            if [[ -f "${domain_dir}/http/live_hosts.txt" ]]; then
                live_hosts_count=$(wc -l < "${domain_dir}/http/live_hosts.txt")
            fi
            echo "Live web hosts: $live_hosts_count"
            
            # Open ports summary
            local open_ports_count=0
            if [[ -f "${domain_dir}/port/ports.txt" ]]; then
                open_ports_count=$(grep "open" "${domain_dir}/port/ports.txt" | grep -v "filtered" | wc -l)
            fi
            echo "Open ports: $open_ports_count"
            
            # Vulnerability summary
            local vuln_count=0
            if [[ -f "${domain_dir}/vuln/vulnerabilities.txt" ]]; then
                vuln_count=$(wc -l < "${domain_dir}/vuln/vulnerabilities.txt")
            fi
            echo "Vulnerabilities found: $vuln_count"
            
            # Paths summary
            local paths_count=0
            if [[ -f "${domain_dir}/path/paths_discovered.txt" ]]; then
                # Count paths excluding header lines and empty lines
                paths_count=$(grep -v "^$" "${domain_dir}/path/paths_discovered.txt" | grep -v "^#" | wc -l)
            fi
            echo "Accessible paths: $paths_count"
            
            # Screenshots summary
            local screenshots_count=0
            if [[ -d "${domain_dir}/screenshot" ]]; then
                screenshots_count=$(find "${domain_dir}/screenshot" -type f -name "*.png" | wc -l)
            fi
            echo "Screenshots captured: $screenshots_count"
            
            echo ""
        done
        
        echo "Individual reports are available in domain-specific folders."
        echo "Full details can be found in the domain-specific reports."
    } > "$output_file"
    
    log_info "Master summary report generated: $output_file"
    
    return 0
}

# Generate an HTML report for a domain
# Usage: generate_html_report domain output_file
generate_html_report() {
    local domain="$1"
    local output_file="$2"
    local domain_dir="${FSRECON_RUN_DIR}/${domain}"
    
    log_debug "Generating HTML report for $domain"
    
    {
        echo "<!DOCTYPE html>"
        echo "<html>"
        echo "<head>"
        echo "  <title>FSRecon Report: $domain</title>"
        echo "  <style>"
        echo "    body { font-family: Arial, sans-serif; margin: 20px; line-height: 1.6; }"
        echo "    h1 { color: #2c3e50; }"
        echo "    h2 { color: #3498db; margin-top: 30px; }"
        echo "    .container { max-width: 1200px; margin: 0 auto; }"
        echo "    pre { background-color: #f8f8f8; padding: 10px; border-radius: 5px; overflow-x: auto; }"
        echo "    table { border-collapse: collapse; width: 100%; }"
        echo "    th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }"
        echo "    th { background-color: #f2f2f2; }"
        echo "    tr:nth-child(even) { background-color: #f9f9f9; }"
        echo "    .severity-critical { color: #e74c3c; font-weight: bold; }"
        echo "    .severity-high { color: #e67e22; font-weight: bold; }"
        echo "    .severity-medium { color: #f39c12; }"
        echo "    .severity-low { color: #27ae60; }"
        echo "  </style>"
        echo "</head>"
        echo "<body>"
        echo "  <div class=\"container\">"
        echo "    <h1>Full Spectrum Recon Report</h1>"
        echo "    <p><strong>Target:</strong> $domain</p>"
        echo "    <p><strong>Generated on:</strong> $(date)</p>"
        
        # Port scan results
        echo "    <h2>Open Ports</h2>"
        if [[ -f "${domain_dir}/port/ports.txt" ]]; then
            echo "    <pre>"
            grep "open" "${domain_dir}/port/ports.txt" | grep -v "filtered"
            echo "    </pre>"
        else
            echo "    <p>No port scan results available</p>"
        fi
        
        # Subdomain results
        echo "    <h2>Subdomains</h2>"
        if [[ -f "${domain_dir}/subdomain/subdomains.txt" ]]; then
            local count=$(wc -l < "${domain_dir}/subdomain/subdomains.txt")
            echo "    <p>Found $count subdomains:</p>"
            echo "    <pre>"
            cat "${domain_dir}/subdomain/subdomains.txt"
            echo "    </pre>"
        else
            echo "    <p>No subdomains found</p>"
        fi
        
        # HTTP probe results
        echo "    <h2>Live Web Hosts</h2>"
        if [[ -f "${domain_dir}/http/live_hosts.txt" ]]; then
            local count=$(wc -l < "${domain_dir}/http/live_hosts.txt")
            echo "    <p>Found $count live web hosts:</p>"
            echo "    <pre>"
            cat "${domain_dir}/http/live_hosts.txt"
            echo "    </pre>"
        else
            echo "    <p>No live web hosts found</p>"
        fi
        
        # Vulnerability results
        echo "    <h2>Vulnerabilities</h2>"
        if [[ -f "${domain_dir}/vuln/vulnerabilities.txt" ]]; then
            local count=$(wc -l < "${domain_dir}/vuln/vulnerabilities.txt")
            echo "    <p>Found $count potential vulnerabilities/findings:</p>"
            echo "    <table>"
            echo "      <tr><th>Host</th><th>Severity</th><th>Type</th><th>Detail</th></tr>"
            
            # Process vulnerabilities (assuming nuclei-like format)
            while IFS= read -r line || [[ -n "$line" ]]; do
                [[ -z "$line" ]] && continue
                
                if [[ "$line" =~ ^\[([^]]+)\]\ \[([^]]+)\]\ \[([^]]+)\]\ (.+)\ \[\[(.+)\]\] ]]; then
                    local host="${BASH_REMATCH[1]}"
                    local severity="${BASH_REMATCH[2]}"
                    local type="${BASH_REMATCH[3]}"
                    local detail="${BASH_REMATCH[4]}"
                    
                    local severity_class=""
                    case "${severity,,}" in
                        "critical") severity_class="severity-critical" ;;
                        "high") severity_class="severity-high" ;;
                        "medium") severity_class="severity-medium" ;;
                        "low") severity_class="severity-low" ;;
                        *) severity_class="" ;;
                    esac
                    
                    echo "      <tr>"
                    echo "        <td>$host</td>"
                    echo "        <td class=\"$severity_class\">$severity</td>"
                    echo "        <td>$type</td>"
                    echo "        <td>$detail</td>"
                    echo "      </tr>"
                else
                    # Fallback for unparseable lines
                    echo "      <tr><td colspan=\"4\">$line</td></tr>"
                fi
            done < "${domain_dir}/vuln/vulnerabilities.txt"
            
            echo "    </table>"
        else
            echo "    <p>No vulnerabilities found matching the criteria</p>"
        fi
        
        # Path discovery results
        echo "    <h2>Web Paths</h2>"
        if [[ -f "${domain_dir}/path/paths_discovered.txt" ]]; then
            local count=$(grep -v "^$" "${domain_dir}/path/paths_discovered.txt" | grep -v "^#" | wc -l)
            echo "    <p>Found $count accessible paths:</p>"
            echo "    <pre>"
            cat "${domain_dir}/path/paths_discovered.txt"
            echo "    </pre>"
        else
            echo "    <p>No accessible paths found</p>"
        fi
        
        # Screenshots section
        echo "    <h2>Screenshots</h2>"
        if [[ -d "${domain_dir}/screenshot" && "$(ls -A "${domain_dir}/screenshot")" ]]; then
            local screenshots=$(find "${domain_dir}/screenshot" -type f -name "*.png" | wc -l)
            echo "    <p>Captured $screenshots screenshots</p>"
            
            if [[ -f "${domain_dir}/screenshot/report.html" ]]; then
                echo "    <p><a href=\"${domain_dir}/screenshot/report.html\" target=\"_blank\">View Screenshot Report</a></p>"
            fi
            
            # Option to display thumbnails
            echo "    <div style=\"display: flex; flex-wrap: wrap; gap: 10px;\">"
            for img in "${domain_dir}/screenshot"/*.png; do
                [[ -f "$img" ]] || continue
                local img_name=$(basename "$img")
                local target=$(echo "$img_name" | sed 's/\.png$//')
                
                echo "      <div style=\"margin-bottom: 20px; text-align: center;\">"
                echo "        <a href=\"$img\" target=\"_blank\">"
                echo "          <img src=\"$img\" style=\"max-width: 300px; max-height: 200px; border: 1px solid #ddd;\">"
                echo "        </a>"
                echo "        <p style=\"margin-top: 5px;\">$target</p>"
                echo "      </div>"
            done
            echo "    </div>"
        else
            echo "    <p>No screenshots were generated</p>"
        fi
        
        echo "  </div>"
        echo "</body>"
        echo "</html>"
    } > "$output_file"
    
    log_info "HTML report generated: $output_file"
    
    return 0
}

# Register module functions
module_register() {
    register_function "generate_text_report" "Generate a text report for a domain"
    register_function "generate_json_report" "Generate a JSON report for a domain"
    register_function "generate_html_report" "Generate an HTML report for a domain"
    register_function "generate_master_summary" "Generate a master summary report for all domains"
}

# Initialize reporting module
reporting_init() {
    log_debug "Initializing reporting module"
    log_debug "Reporting module initialized"
    return 0
}

# Initialize module
reporting_init
