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
        if [[ -f "${domain_dir}/path/paths_discovered.txt" ]]; then
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