#!/usr/bin/env bash
# Recon Flow (Nahamsec-inspired, NixOS-friendly) — WITH tool variables
# - Domain-first layout: ./<domain>/recon/...
# - Bug-bounty httpx (no -ports spray). Ferox only on alive URLs.
# - Scope + Out-of-scope filtering; amass passive is opt-in with timeout.
# - Wayback param keys; JS/endpoint harvest; historical split (.js/.php/.aspx/.jsp).
# - Optional HTML dashboard: --report-html (offline).
# - Centralized tool commands/flags at the top.
# - ### PERF: Added parallelization (background jobs + wait, xargs -P), isolated outputs,
#            and targeted Nmap scanning on RustScan-open ports.

set -uo pipefail

########################################
#            TOOL VARIABLES
########################################
TOOL_SUBFINDER="subfinder"
SUBFINDER_FLAGS="-silent"

TOOL_ASSETFINDER="assetfinder"
ASSETFINDER_FLAGS="--subs-only"

TOOL_AMASS="amass"
AMASS_ENUM_FLAGS="enum -passive -silent"

TOOL_HTTPX="httpx"
HTTPX_COMMON_FLAGS="-follow-redirects -timeout 10 -retries 1"
HTTPX_LIST_FLAGS="-silent"     # toggled off in --verbose
HTTPX_INFO_FLAGS="-status-code -title -tech-detect -ip -web-server"

TOOL_FEROX="feroxbuster"
FEROX_FLAGS="-q -t 20 -e -k -n -x php,html,js,json,txt"

TOOL_WAYBACKURLS="waybackurls"
TOOL_WAYMORE="waymore"

TOOL_GOWITNESS="gowitness"   # we auto-detect chromium/chrome path on NixOS

TOOL_RUSTSCAN="rustscan"
RUSTSCAN_FLAGS="--ulimit 5000 -g"

TOOL_NMAP="nmap"
NMAP_FLAGS="-Pn -sV"  # ### PERF: let RustScan pick ports; we avoid blanket --top-ports here

TOOL_KATANA="katana"
KATANA_FLAGS="-jc -fx -d 2"

TOOL_ARJUN="arjun"
ARJUN_FLAGS="-t"

TOOL_JQ="jq"
########################################

# Runtime defaults & flags
THREADS=10
OUTBASE="."    # final layout: ./<domain>/recon/...
SHOTS=1
PORTS=1
SUMMARY=0
REPORT_HTML=0
DEBUG=0
DRYRUN=0
VERBOSE=0

# module gating
SKIP_FEROX=false
SKIP_PARAMS=false
SKIP_JS=false
USE_AMASS=false

# scope & OOS
STRICT_SCOPE=true
SCOPE_FILE=""
OOS_FILE=""
SCOPE_ITER_FILE=""

WORDLIST_DEFAULT="/home/asyu/Wordlists/SecLists/Discovery/Web-Content/common.txt"
WORDLIST="$WORDLIST_DEFAULT"

die(){ echo -e "[x] $*" >&2; exit 1; }
info(){ echo -e "[+] $*"; }

# httpx -silent toggler for verbose
sflag(){ if [[ $VERBOSE -eq 1 ]]; then echo ""; else echo "$HTTPX_LIST_FLAGS"; fi; }

# pipe to tee depending on verbose; use as: $(tee_to "file")
tee_to(){
  local file="$1"
  if [[ $VERBOSE -eq 1 ]]; then
    echo "| tee -a '$file'"
  else
    echo "| tee -a '$file' >/dev/null"
  fi
}

# eval runner with optional logfile (honors verbose)
run(){
  local cmd="$1" log="${2:-}"
  if [[ $DEBUG -eq 1 || $VERBOSE -eq 1 ]]; then echo ">> $cmd"; fi
  if [[ $DRYRUN -eq 1 ]]; then return 0; fi
  if [[ -n "$log" && $VERBOSE -eq 0 ]]; then
    eval "$cmd" >>"$log" 2>>"$log"
  else
    eval "$cmd"
  fi
}

check_tools(){
  local tools=(
    "$TOOL_SUBFINDER" "$TOOL_ASSETFINDER" "$TOOL_AMASS" "$TOOL_HTTPX"
    "$TOOL_FEROX" "$TOOL_RUSTSCAN" "$TOOL_NMAP" "$TOOL_WAYBACKURLS"
    "$TOOL_WAYMORE" "$TOOL_GOWITNESS" "$TOOL_JQ" "$TOOL_KATANA" "$TOOL_ARJUN"
  )
  for t in "${tools[@]}"; do
    local bin="${t%% *}"
    command -v "$bin" >/dev/null 2>&1 || echo "[!] missing: $bin (will skip if optional)"
  done
}

mk_layout(){ local T="$1"; mkdir -p "$OUTBASE/$T/recon"/{seeds,subdomains,ports,dirs,params,historical,shots,logs,artifacts,vulns,report}; :> "$OUTBASE/$T/recon/notes.md"; }

# ---------- scope helpers ----------
scope_keep(){
  local tld="$1" esc allow_re
  esc="$(printf '%s' "$tld" | sed 's/[.[*^$()+?{}|\\/]/\\&/g')"
  allow_re="(^|[.:/])${esc}([:/]|$)"
  if [[ -n "$SCOPE_FILE" && -s "$SCOPE_FILE" ]]; then
    local tmp="" p e
    while IFS= read -r p; do
      [[ -z "${p// }" || "$p" =~ ^# ]] && continue
      p="${p#*.}"; e="$(printf '%s' "$p" | sed 's/[.[*^$()+?{}|\\/]/\\&/g')"
      tmp="${tmp}${tmp:+|}(^|[.:/])(${e}|([^.]+\\.)+${e})([:/]|$)"
    done < "$SCOPE_FILE"
    [[ -n "$tmp" ]] && allow_re="${allow_re}|${tmp}"
  fi
  if [[ -n "$OOS_FILE" && -s "$OOS_FILE" ]]; then
    grep -E "$allow_re" | grep -Ev -f "$OOS_FILE"
  else
    grep -E "$allow_re"
  fi
}

host_scope_keep(){
  local tld="$1" esc; esc="$(printf '%s' "$tld" | sed 's/[.[*^$()+?{}|\\/]/\\&/g')"
  local rx="(^|\\.)${esc}$"
  if [[ -n "$SCOPE_FILE" && -s "$SCOPE_FILE" ]]; then
    while IFS= read -r p; do
      [[ -z "${p// }" || "$p" =~ ^# ]] && continue
      p="${p#*.}"; local e; e="$(printf '%s' "$p" | sed 's/[.[*^$()+?{}|\\/]/\\&/g')"
      rx="${rx}|(^|\\.)${e}$"
    done < "$SCOPE_FILE"
  fi
  if [[ -n "$OOS_FILE" && -s "$OOS_FILE" ]]; then
    grep -Ei "$rx" | grep -Eiv -f "$OOS_FILE"
  else
    grep -Ei "$rx"
  fi
}

# ---------- subdomains ----------
enum_subdomains(){
  local T="$1" SD="$OUTBASE/$T/recon/subdomains" LOG="$OUTBASE/$T/recon/logs/subdomains.log"
  info "$T :: subdomain enumeration"
  mkdir -p "$SD"
  :> "$SD/subfinder.txt"; :> "$SD/assetfinder.txt"; :> "$SD/amass.txt" 2>/dev/null || true
  :> "$SD/raw.txt"

  # ### PERF: run finders in parallel, isolate outputs, then merge
  local pids=()

  if command -v "${TOOL_SUBFINDER%% *}" >/dev/null; then
    (
      if [[ $DEBUG -eq 1 || $VERBOSE -eq 1 ]]; then echo ">> $TOOL_SUBFINDER $SUBFINDER_FLAGS -d '$T'"; fi
      [[ $DRYRUN -eq 1 ]] && exit 0
      $TOOL_SUBFINDER $SUBFINDER_FLAGS -d "$T" 2>>"$LOG" | sed '/^\s*$/d' | sort -u > "$SD/subfinder.txt"
    ) & pids+=($!)
  fi

  if command -v "${TOOL_ASSETFINDER%% *}" >/dev/null; then
    (
      if [[ $DEBUG -eq 1 || $VERBOSE -eq 1 ]]; then echo ">> $TOOL_ASSETFINDER $ASSETFINDER_FLAGS '$T'"; fi
      [[ $DRYRUN -eq 1 ]] && exit 0
      $TOOL_ASSETFINDER $ASSETFINDER_FLAGS "$T" 2>>"$LOG" | sed '/^\s*$/d' | sort -u > "$SD/assetfinder.txt"
    ) & pids+=($!)
  fi

  if [[ "$USE_AMASS" == true ]] && command -v "${TOOL_AMASS%% *}" >/dev/null; then
    (
      if [[ $DEBUG -eq 1 || $VERBOSE -eq 1 ]]; then echo ">> $TOOL_AMASS $AMASS_ENUM_FLAGS -d '$T'"; fi
      [[ $DRYRUN -eq 1 ]] && exit 0
      if [[ -n "${AMASS_TO:-}" ]]; then
        timeout "${AMASS_TO}s" $TOOL_AMASS $AMASS_ENUM_FLAGS -d "$T" 2>>"$LOG" | sed '/^\s*$/d' | sort -u > "$SD/amass.txt" || true
      else
        $TOOL_AMASS $AMASS_ENUM_FLAGS -d "$T" 2>>"$LOG" | sed '/^\s*$/d' | sort -u > "$SD/amass.txt"
      fi
    ) & pids+=($!)
  else
    info "$T :: skipping amass (opt-in only)"
  fi

  # seeds (sync, tiny) — no need to parallelize
  local SEED="$OUTBASE/$T/recon/seeds/targets.txt"
  [[ -s "$SEED" ]] && run "sed 's/^[[:space:]]*//' \"$SEED\" | grep -E '^[A-Za-z0-9.-]+$' >> \"$SD/raw.txt\" || true" "$LOG"

  # wait for parallel finders
  [[ ${#pids[@]} -gt 0 ]] && wait "${pids[@]}"

  # merge & scope
  run "cat \"$SD\"/subfinder.txt \"$SD\"/assetfinder.txt \"$SD\"/amass.txt \"$SD\"/raw.txt 2>/dev/null | sed '/^\\s*$/d' | sort -u > \"$SD/all.txt\""
  if [[ "$STRICT_SCOPE" == true ]]; then
    run "host_scope_keep '$T' < '$SD/all.txt' | sort -u > '$SD/all_scoped.txt'"
  else
    run "cp '$SD/all.txt' '$SD/all_scoped.txt'"
  fi
  info "$T :: subdomains (scoped): $(wc -l < "$SD/all_scoped.txt" 2>/dev/null || echo 0)"
}

# ---------- probe (bug-bounty style) ----------
probe_live(){
  local T="$1" SD="$OUTBASE/$T/recon/subdomains" LOG="$OUTBASE/$T/recon/logs/httpx.log"
  [[ -s "$SD/all_scoped.txt" ]] || die "$T :: no subdomains found to probe"

  info "$T :: probing live hosts (httpx; no port spray)"
  run "$TOOL_HTTPX -l '$SD/all_scoped.txt' $HTTPX_COMMON_FLAGS $(sflag) -threads '$THREADS' -o '$SD/live.txt'" "$LOG"
  run "sed 's#/\$##' '$SD/live.txt' | awk 'NF' | sort -u > '$SD/live.tmp' && mv '$SD/live.tmp' '$SD/live.txt'"

  run "$TOOL_HTTPX -l '$SD/all_scoped.txt' $HTTPX_COMMON_FLAGS $HTTPX_INFO_FLAGS $(sflag) -threads '$THREADS' -o '$SD/live_info.txt'" "$LOG"
  run "awk 'NF' '$SD/live_info.txt' | sort -u > '$SD/live_info.tmp' && mv '$SD/live_info.tmp' '$SD/live_info.txt'"

  info "$T :: live hosts: $(wc -l < "$SD/live.txt" 2>/dev/null || echo 0)"
}

# ---------- screenshots (gowitness) ----------
shoot(){
  local T="$1" SD="$OUTBASE/$T/recon/subdomains" OUTD="$OUTBASE/$T/recon/shots" LOG="$OUTBASE/$T/recon/logs/gowitness.log"
  [[ "$SHOTS" -eq 1 ]] || { info "$T :: screenshots skipped"; return; }
  command -v "${TOOL_GOWITNESS%% *}" >/dev/null || { info "gowitness not installed; skipping shots"; return; }
  [[ -s "$SD/live.txt" ]] || { info "$T :: no live URLs for screenshots"; return; }
  info "$T :: screenshots (gowitness)"; run "mkdir -p '$OUTD'"

  # Determine CLI flavor and chrome flag
  local CHROME_FLAG="" CLI_SCAN=0
  if $TOOL_GOWITNESS help 2>&1 | grep -qE '\bscan\b'; then
    CLI_SCAN=1
    if $TOOL_GOWITNESS scan file -h 2>&1 | grep -q -- '--chrome-path'; then
      for c in chromium chromium-browser google-chrome chrome; do
        if command -v "$c" >/dev/null 2>&1; then CHROME_FLAG="--chrome-path $(command -v $c)"; break; fi
      done
    fi
  fi

  if [[ $CLI_SCAN -eq 1 ]]; then
    run "$TOOL_GOWITNESS scan file -f '$SD/live.txt' -s '$OUTD' $CHROME_FLAG -t '$THREADS' --timeout 60 || true" "$LOG"
  else
    # legacy CLI
    run "gowitness file -f '$SD/live.txt' -P '$OUTD' || true" "$LOG"
  fi
}

# ---------- ports ----------
scan_ports(){
  local T="$1" SD="$OUTBASE/$T/recon/subdomains" PD="$OUTBASE/$T/recon/ports" LOG="$OUTBASE/$T/recon/logs/ports.log"
  [[ "$PORTS" -eq 1 ]] || { info "$T :: port scanning skipped"; return; }
  [[ -s "$SD/live.txt" ]] || { info "$T :: no live URLs for port scan"; return; }
  run "mkdir -p '$PD'"

  info "$T :: rustscan fast ports"
  : > "$PD/rustscan.txt"
  if command -v "${TOOL_RUSTSCAN%% *}" >/dev/null; then
    # scan hosts in parallel via xargs
    run "sed 's#^https\\?://##' '$SD/live.txt' | awk -F/ '{print \$1}' | cut -d: -f1 | sort -u | \
xargs -I{} -P '$THREADS' bash -c '$TOOL_RUSTSCAN $RUSTSCAN_FLAGS -a \"{}\" || true' $(tee_to "$PD/rustscan.txt")" "$LOG"
  fi

  # ### PERF: Build per-host open-port map, then run Nmap per host in parallel
  info "$T :: parsing rustscan results -> targeted nmap"
  : > "$PD/nmap.txt"
  : > "$PD/rs_open_ports.txt"

  if grep -q '^Open ' "$PD/rustscan.txt" 2>/dev/null; then
    awk '/^Open /{print $2}' "$PD/rustscan.txt" | awk -F: '{h=$1;p=$2;g[h]=g[h] (g[h]?"," :"") p} END{for(h in g) print h" "g[h]}' > "$PD/rs_open_ports.txt"
  fi

  if [[ -s "$PD/rs_open_ports.txt" ]] && command -v "${TOOL_NMAP%% *}" >/dev/null; then
    info "$T :: nmap service/version (per-host, open ports only)"
    local npids=()
    while read -r host ports; do
      [[ -z "${host// }" || -z "${ports// }" ]] && continue
      (
        if [[ $DEBUG -eq 1 || $VERBOSE -eq 1 ]]; then echo ">> $TOOL_NMAP $NMAP_FLAGS -p $ports $host"; fi
        [[ $DRYRUN -eq 1 ]] && exit 0
        safe="${host//[:\/]/_}"
        $TOOL_NMAP -p "$ports" $NMAP_FLAGS "$host" -oN "$PD/nmap_$safe.txt" 2>>"$LOG" || true
      ) & npids+=($!)
    done < "$PD/rs_open_ports.txt"
    [[ ${#npids[@]} -gt 0 ]] && wait "${npids[@]}"
    # merge per-host outputs (safe, no concurrent writes)
    cat "$PD"/nmap_*.txt 2>/dev/null >> "$PD/nmap.txt" || true
  else
    # fallback if rustscan produced nothing useful
    info "$T :: nmap fallback (--top-ports 1000)"
    run "sed 's#^https\\?://##' '$SD/live.txt' | awk -F/ '{print \$1}' | cut -d: -f1 | sort -u > '$PD/hosts.txt'"
    run "$TOOL_NMAP -iL '$PD/hosts.txt' -Pn -sV --top-ports 1000 -oN '$PD/nmap.txt' || true" "$LOG"
  fi
}

# ---------- ferox (only alive URLs) ----------
dir_bust(){
  local T="$1" SD="$OUTBASE/$T/recon/subdomains" DD="$OUTBASE/$T/recon/dirs" LOG="$OUTBASE/$T/recon/logs/dirs.log"
  [[ "$SKIP_FEROX" == true ]] && { info "$T :: skipping ferox (by flag)"; return; }
  [[ -s "$SD/live.txt" ]] || { info "$T :: no live URLs for dir bust"; return; }
  [[ -f "$WORDLIST" ]] || die "wordlist not found: $WORDLIST"

  info "$T :: content discovery (feroxbuster)"
  run "mkdir -p '$DD'"
  # ### PERF: parallelize ferox per-URL with xargs -P, one output per target
  if command -v "${TOOL_FEROX%% *}" >/dev/null; then
    xargs -P "$THREADS" -I{} sh -c '
      url="$1"
      [ -z "${url// }" ] && exit 0
      safe=$(echo "$url" | sed "s#https\\?://##; s#[/:]#_#g")
      '"$TOOL_FEROX"' -u "$url" -w "'"$WORDLIST"'" '"$FEROX_FLAGS"' -o "'"$DD"'/$safe.txt" || true
    ' sh < "$SD/live.txt" >>"$LOG" 2>&1
  fi
}

# ---------- historicals ----------
historicals(){
  local T="$1" SD="$OUTBASE/$T/recon/subdomains" HD="$OUTBASE/$T/recon/historical" LOG="$OUTBASE/$T/recon/logs/historical.log"
  info "$T :: historical URLs (wayback/waymore)"
  run "mkdir -p '$HD'"; run ": > '$HD/wayback.txt' ; : > '$HD/waymore.txt'"

  if command -v "${TOOL_WAYBACKURLS%% *}" >/dev/null; then
    if [[ -s "$SD/live.txt" ]]; then
      run "sed 's#^https\\?://##' '$SD/live.txt' | awk -F/ '{print \$1}' | sort -u | \
xargs -I{} -P '$THREADS' bash -c 'echo {} | $TOOL_WAYBACKURLS || true' $(tee_to "$HD/wayback.txt")"
    else
      run "echo '$T' | $TOOL_WAYBACKURLS $(tee_to "$HD/wayback.txt") || true" "$LOG"
    fi
  fi
  if command -v "${TOOL_WAYMORE%% *}" >/dev/null; then
    run "$TOOL_WAYMORE -i '$T' -mode U -oU '$HD/waymore.txt' || true" "$LOG"
  fi

  if [[ "$STRICT_SCOPE" == true ]]; then
    run "sort -u '$HD/wayback.txt' '$HD/waymore.txt' | sed '/^\\s*$/d' | scope_keep '$T' > '$HD/all.txt'"
  else
    run "sort -u '$HD/wayback.txt' '$HD/waymore.txt' | sed '/^\\s*$/d' > '$HD/all.txt'"
  fi

  # nahamsec-style splits
  run "grep -Pi '\\\\.js(\\?|$)'   '$HD/all.txt' | sort -u > '$HD/jsurls.txt'  || true"
  run "grep -Pi '\\\\.php(\\?|$)'  '$HD/all.txt' | sort -u > '$HD/phpurls.txt' || true"
  run "grep -Pi '\\\\.aspx?(\\?|$)' '$HD/all.txt' | sort -u > '$HD/aspxurls.txt' || true"
  run "grep -Pi '\\\\.jsp(\\?|$)'   '$HD/all.txt' | sort -u > '$HD/jspurls.txt'  || true"

  if command -v "${TOOL_HTTPX%% *}" >/dev/null; then
    run "$TOOL_HTTPX -l '$HD/all.txt' $HTTPX_COMMON_FLAGS $(sflag) -threads '$THREADS' -o '$HD/alive.txt' || true" "$LOG"
    run "awk 'NF' '$HD/alive.txt' | sort -u > '$HD/alive.tmp' && mv '$HD/alive.tmp' '$HD/alive.txt'"
  fi
}

# ---------- params (arjun + wayback param keys) ----------
params(){
  local T="$1" SD="$OUTBASE/$T/recon/subdomains" PDIR="$OUTBASE/$T/recon/params" LOG="$OUTBASE/$T/recon/logs/params.log"
  [[ "$SKIP_PARAMS" == true ]] && { info "$T :: skipping param discovery (by flag)"; return; }
  info "$T :: parameter discovery"; run "mkdir -p '$PDIR'"

  if [[ -s "$SD/live.txt" ]] && command -v "${TOOL_ARJUN%% *}" >/dev/null; then
    run "$TOOL_ARJUN -i '$SD/live.txt' $ARJUN_FLAGS '$THREADS' -o '$PDIR/arjun.json' || true" "$LOG"
  fi

  local HD="$OUTBASE/$T/recon/historical"
  if [[ -s "$HD/all.txt" ]]; then
    run "grep -oE '[?&][A-Za-z0-9_%-]+' '$HD/all.txt' | sed 's/^[?&]//' | sed 's/%[0-9A-Fa-f][0-9A-Fa-f]/_/g' | sed 's/[^A-Za-z0-9_].*//' | awk 'length>0' | sort -u > '$PDIR/param-keys.txt'"
    info "$T :: wayback param keys -> $PDIR/param-keys.txt ($(wc -l < "$PDIR/param-keys.txt" 2>/dev/null || echo 0))"
  fi
}

# ---------- JS/endpoint harvest (katana) ----------
js_harvest(){
  local T="$1" SD="$OUTBASE/$T/recon/subdomains" AD="$OUTBASE/$T/recon/artifacts" HD="$OUTBASE/$T/recon/historical" LOG="$OUTBASE/$T/recon/logs/js-harvest.log"
  [[ "$SKIP_JS" == true ]] && { info "$T :: skipping JS/endpoint harvest (by flag)"; return; }
  info "$T :: JS & endpoint harvest (katana)"; run "mkdir -p '$AD'"
  : > "$AD/katana-all.txt" ; : > "$AD/js-files.txt" ; : > "$AD/js-endpoints.txt"

  command -v "${TOOL_KATANA%% *}" >/dev/null || { info "katana not installed; skipping JS harvest"; return; }

  # ### PERF: use katana -list to crawl all live hosts in one (internally parallel) run
  if [[ -s "$SD/live.txt" ]]; then
    run "$TOOL_KATANA -list '$SD/live.txt' $KATANA_FLAGS -o '$AD/katana-all.txt' || true" "$LOG"
  fi

  if [[ "$STRICT_SCOPE" == true ]]; then
    run "scope_keep '$T' < '$AD/katana-all.txt' | sort -u > '$AD/katana-in-scope.txt'"
  else
    run "awk 'NF' '$AD/katana-all.txt' | sort -u > '$AD/katana-in-scope.txt'"
  fi

  run "grep -Ei '\\.js(\\?|$)'  '$AD/katana-in-scope.txt' | sort -u > '$AD/js-files.txt'  || true"
  run "grep -Evi '\\.js(\\?|$)' '$AD/katana-in-scope.txt' | sort -u > '$AD/js-endpoints.txt' || true"

  if [[ -f "$HD/all.txt" ]]; then
    run "cat '$AD/js-endpoints.txt' '$HD/all.txt' | sort -u > '$AD/endpoints-plus-historical.txt'"
  else
    run "cp '$AD/js-endpoints.txt' '$AD/endpoints-plus-historical.txt'"
  fi

  info "$T :: endpoints: $(wc -l < "$AD/js-endpoints.txt" 2>/dev/null || echo 0), js files: $(wc -l < "$AD/js-files.txt" 2>/dev/null || echo 0)"
}

# ---------- summary ----------
summarize(){
  local T="$1"; [[ "$SUMMARY" -eq 1 ]] || return
  local SD="$OUTBASE/$T/recon/subdomains" HD="$OUTBASE/$T/recon/historical" AD="$OUTBASE/$T/recon/artifacts" PD="$OUTBASE/$T/recon/ports" OUT="$OUTBASE/$T/recon/summary.md"
  local SUBS LIVE HIST_ALL HIST_ALIVE JS_EP JS_FILES OPEN_PORTS
  SUBS="$(wc -l < "$SD/all_scoped.txt" 2>/dev/null || echo 0)"
  LIVE="$(wc -l < "$SD/live.txt" 2>/dev/null || echo 0)"
  HIST_ALL="$(wc -l < "$HD/all.txt" 2>/dev/null || echo 0)"
  HIST_ALIVE="$(wc -l < "$HD/alive.txt" 2>/dev/null || echo 0)"
  JS_EP="$(wc -l < "$AD/js-endpoints.txt" 2>/dev/null || echo 0)"
  JS_FILES="$(wc -l < "$AD/js-files.txt" 2>/dev/null || echo 0)"
  OPEN_PORTS="$(grep -cE '\\bopen\\b' "$PD/nmap.txt" 2>/dev/null || echo 0)"
  {
    echo "# Recon Summary: $T"
    echo "- Subdomains (scoped): $SUBS"
    echo "- Live hosts: $LIVE"
    echo "- Historical URLs (total/alive): $HIST_ALL / $HIST_ALIVE"
    echo "- Param keys (wayback): $(wc -l < "$OUTBASE/$T/recon/params/param-keys.txt" 2>/dev/null || echo 0)"
    echo "- JS endpoints: $JS_EP"
    echo "- JS files: $JS_FILES"
    echo "- Open ports: $OPEN_PORTS"
    echo
    echo "## Top Live Hosts"
    [[ -s "$SD/live_info.txt" ]] && head -n 50 "$SD/live_info.txt" || echo "_none_"
  } > "$OUT"
  info "$T :: wrote summary -> $OUT"
}

# ---------- HTML report (offline) ----------
report_html(){
  local T="$1"
  local ROOT="$OUTBASE/$T/recon"
  local RDIR="$ROOT/report"
  local SD="$ROOT/subdomains"
  local HD="$ROOT/historical"
  local AD="$ROOT/artifacts"
  local PD="$ROOT/ports"
  local DD="$ROOT/dirs"
  mkdir -p "$RDIR"

  local LIVE_N=$(wc -l < "$SD/live.txt" 2>/dev/null || echo 0)
  local SUBS_N=$(wc -l < "$SD/all_scoped.txt" 2>/dev/null || echo 0)
  local HIST_N=$(wc -l < "$HD/all.txt" 2>/dev/null || echo 0)
  local JSF_N=$(wc -l < "$AD/js-files.txt" 2>/dev/null || echo 0)
  local JSE_N=$(wc -l < "$AD/js-endpoints.txt" 2>/dev/null || echo 0)
  local PRM_N=$(wc -l < "$ROOT/params/param-keys.txt" 2>/dev/null || echo 0)
  local NMAP_N=$(grep -cE '\bopen\b' "$PD/nmap.txt" 2>/dev/null || echo 0)

  local OUT="$RDIR/index.html"
  cat > "$OUT" <<'CSSHTML'
<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<title>Recon Report</title>
<style>
  :root{--bg:#0e1117;--fg:#e6edf3;--mut:#9aa4af;--card:#161b22;--acc:#58a6ff;--ok:#39d353;--warn:#d29922;--bad:#ff7b72}
  *{box-sizing:border-box} body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,"Liberation Mono","Courier New",monospace}
  header{padding:18px 20px;border-bottom:1px solid #30363d}
  h1{margin:0;font-size:18px}
  main{display:grid;grid-template-columns:320px 1fr;gap:18px;padding:18px}
  .card{background:var(--card);border:1px solid #30363d;border-radius:8px}
  .pad{padding:14px}
  .grid{display:grid;gap:10px}
  .kpi{display:flex;justify-content:space-between;align-items:center;padding:8px 10px;background:#0b0f14;border:1px solid #22272e;border-radius:6px}
  .kpi span{color:var(--mut)}
  .kpi b{color:var(--acc)}
  a{color:var(--acc);text-decoration:none}
  a:hover{text-decoration:underline}
  table{width:100%;border-collapse:collapse}
  th,td{padding:8px 10px;border-bottom:1px solid #30363d;vertical-align:top}
  th{color:var(--mut);text-align:left}
  .code{white-space:pre-wrap;word-break:break-all;font-size:12px}
  .shots{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:10px}
  .shots img{width:100%;height:auto;border:1px solid #30363d;border-radius:6px;background:#000}
</style>
CSSHTML

  {
    echo "<header><h1>Recon Report — $T</h1></header>"
    echo "<main>"
    echo "  <aside class='grid'>"
    echo "    <div class='card pad grid'>"
    echo "      <div class='kpi'><span>Subdomains (scoped)</span><b>$SUBS_N</b></div>"
    echo "      <div class='kpi'><span>Live hosts</span><b>$LIVE_N</b></div>"
    echo "      <div class='kpi'><span>Historical URLs</span><b>$HIST_N</b></div>"
    echo "      <div class='kpi'><span>JS endpoints</span><b>$JSE_N</b></div>"
    echo "      <div class='kpi'><span>JS files</span><b>$JSF_N</b></div>"
    echo "      <div class='kpi'><span>Param keys</span><b>$PRM_N</b></div>"
    echo "      <div class='kpi'><span>Nmap open ports</span><b>$NMAP_N</b></div>"
    echo "    </div>"

    echo "    <div class='card pad grid'>"
    echo "      <div><b>Artifacts</b></div>"
    [[ -s "$SD/live_info.txt" ]] && echo "      <div><a href='../subdomains/live_info.txt'>subdomains/live_info.txt</a></div>"
    [[ -s "$SD/live.txt" ]]      && echo "      <div><a href='../subdomains/live.txt'>subdomains/live.txt</a></div>"
    [[ -s "$SD/all_scoped.txt" ]]&& echo "      <div><a href='../subdomains/all_scoped.txt'>subdomains/all_scoped.txt</a></div>"
    [[ -s "$HD/all.txt" ]]       && echo "      <div><a href='../historical/all.txt'>historical/all.txt</a></div>"
    [[ -s "$HD/jsurls.txt" ]]    && echo "      <div><a href='../historical/jsurls.txt'>historical/jsurls.txt</a></div>"
    [[ -s "$HD/phpurls.txt" ]]   && echo "      <div><a href='../historical/phpurls.txt'>historical/phpurls.txt</a></div>"
    [[ -s "$HD/aspxurls.txt" ]]  && echo "      <div><a href='../historical/aspxurls.txt'>historical/aspxurls.txt</a></div>"
    [[ -s "$HD/jspurls.txt" ]]   && echo "      <div><a href='../historical/jspurls.txt'>historical/jspurls.txt</a></div>"
    [[ -s "$AD/js-endpoints.txt" ]] && echo "   <div><a href='../artifacts/js-endpoints.txt'>artifacts/js-endpoints.txt</a></div>"
    [[ -s "$AD/js-files.txt" ]]     && echo "   <div><a href='../artifacts/js-files.txt'>artifacts/js-files.txt</a></div>"
    [[ -s "$ROOT/params/param-keys.txt" ]] && echo " <div><a href='../params/param-keys.txt'>params/param-keys.txt</a></div>"
    [[ -s "$ROOT/params/arjun.json" ]]     && echo " <div><a href='../params/arjun.json'>params/arjun.json</a></div>"
    [[ -s "$PD/nmap.txt" ]] && echo "         <div><a href='../ports/nmap.txt'>ports/nmap.txt</a></div>"
    echo "    </div>"
    echo "  </aside>"

    echo "  <section class='grid'>"
    echo "    <div class='card pad'>"
    echo "      <b>Live hosts (triage)</b>"
    echo "      <table><thead><tr><th>URL</th><th>Status</th><th>Title</th><th>IP</th><th>Tech/Server</th></tr></thead><tbody>"
    if [[ -s "$SD/live_info.txt" ]]; then
      while IFS= read -r line; do
        url="$(sed -E 's/ \[.*$//' <<<"$line")"
        status="$(grep -oE '\[[0-9]{3}(,[0-9]{3})*\]' <<<"$line" | head -n1)"
        title="$(sed -n 's/.*\] \[\([^]]*\)\] \[.*/\1/p' <<<"$line")"
        ip="$(sed -n 's/.*\] \[[^]]*\] \[\([^]]*\)\].*/\1/p' <<<"$line")"
        tech="$(sed -n 's/.*\[[^]]*\] \[[^]]*\] \[[^]]*\] \[\(.*\)\]/\1/p' <<<"$line")"
        [[ -z "$url" ]] && continue
        echo "<tr><td class='code'>${url}</td><td>${status}</td><td class='code'>${title}</td><td class='code'>${ip}</td><td class='code'>${tech}</td></tr>"
      done < "$SD/live_info.txt"
    fi
    echo "      </tbody></table>"
    echo "    </div>"

    echo "    <div class='card pad'>"
    echo "      <b>Screenshots</b>"
    echo "      <div class='shots'>"
    shopt -s nullglob
    for img in "$ROOT/shots"/*.{jpg,jpeg,png}; do
      base="$(basename "$img")"
      echo "        <a href='../shots/$base'><img src='../shots/$base' alt='$base'></a>"
    done
    shopt -u nullglob
    echo "      </div>"
    echo "    </div>"

    if [[ -d "$DD" ]]; then
      echo "    <div class='card pad'>"
      echo "      <b>Ferox results</b>"
      echo "      <table><thead><tr><th>Target</th><th>Output file</th></tr></thead><tbody>"
      for f in "$DD"/*.txt; do
        [[ -e "$f" ]] || continue
        tgt="$(basename "$f" .txt | sed 's/_/:/; s/_/\//g')"
        rel="../dirs/$(basename "$f")"
        echo "<tr><td class='code'>$tgt</td><td><a href='$rel'>$(basename "$f")</a></td></tr>"
      done
      echo "      </tbody></table>"
      echo "    </div>"
    fi

    if [[ -s "$HD/all.txt" ]]; then
      echo "    <div class='card pad'>"
      echo "      <b>Historical samples</b>"
      echo "      <div class='code'>"
      head -n 100 "$HD/all.txt" | sed 's/&/\&amp;/g; s/</\&lt;/g'
      echo "      </div>"
      echo "    </div>"
    fi

    echo "  </section>"
    echo "</main>"
  } >> "$OUT"

  info "$T :: HTML report -> $OUT"
}

# ---------- driver ----------
run_target(){
  local T="$1"
  mk_layout "$T"
  [[ -s "$OUTBASE/$T/recon/seeds/targets.txt" ]] || echo "$T" > "$OUTBASE/$T/recon/seeds/targets.txt"

  enum_subdomains "$T"
  probe_live "$T"

  # ### PERF: Run independent modules concurrently; respect dependencies:
  # - Start shots/ports/ferox in background.
  # - Run historicals (foreground), then params (needs historicals), then js_harvest.
  local bg_pids=()

  [[ "$SHOTS" -eq 1 ]] && { shoot "$T" & bg_pids+=($!); }
  [[ "$PORTS" -eq 1 ]] && { scan_ports "$T" & bg_pids+=($!); }
  dir_bust "$T" & bg_pids+=($!)

  # historicals -> params -> js_harvest (sequential to leverage historicals output)
  historicals "$T"
  params "$T"
  js_harvest "$T"

  # wait for background jobs to finish before summary/report
  [[ ${#bg_pids[@]} -gt 0 ]] && wait "${bg_pids[@]}"

  [[ "$SUMMARY" -eq 1 ]] && summarize "$T" || true
  [[ "$REPORT_HTML" -eq 1 ]] && report_html "$T" || true

  echo
  echo "=== Done: $T ==="
  echo "Subdomains (scoped):  $OUTBASE/$T/recon/subdomains/all_scoped.txt"
  echo "Live hosts (URLs):    $OUTBASE/$T/recon/subdomains/live.txt"
  echo "Live info (triage):   $OUTBASE/$T/recon/subdomains/live_info.txt"
  echo "Ports (nmap):         $OUTBASE/$T/recon/ports/nmap.txt"
  echo "Dirs (ferox outputs): $OUTBASE/$T/recon/dirs/"
  echo "Params (arjun/json):  $OUTBASE/$T/recon/params/arjun.json"
  echo "Param keys (WB):      $OUTBASE/$T/recon/params/param-keys.txt"
  echo "Historical (alive):   $OUTBASE/$T/recon/historical/alive.txt"
  echo "JS endpoints:         $OUTBASE/$T/recon/artifacts/js-endpoints.txt"
  echo "Endpoints+Historical: $OUTBASE/$T/recon/artifacts/endpoints-plus-historical.txt"
  echo "HTML report:          $OUTBASE/$T/recon/report/index.html"
  echo
}

usage() {
  cat <<EOF
Usage: $0 [options]

Options:
  -d, --domain <domain>       Run recon on a single domain
  -f, --file <file>           Run recon on a list of domains (one per line)

General:
  --threads <n>               Set number of threads (default: 10)
  --wordlist <path>           Path to ferox wordlist
  --out <dir>                 Base output directory (default: .)

Toggles:
  --skip-shots                Skip screenshots
  --skip-ports                Skip port scanning
  --no-ferox                  Skip feroxbuster content discovery
  --no-params                 Skip parameter discovery
  --no-js                     Skip JS/endpoint harvest
  --amass                     Enable amass passive enumeration
  --summarize                 Write summary.md
  --report-html               Generate HTML report
  --no-strict-scope           Disable strict scope filtering

Other:
  --scope-file <file>         Scope file (in-scope domains)
  --oos-file <file>           Out-of-scope file
  --scope <file>              Iterate through file + apply as scope
  --fast                      Fast triage preset (threads=50, no shots, skip ferox)
  --debug                     Print commands as they run
  --dry-run                   Parse options only, don’t execute
  -v, --verbose               Verbose logging
  -h, --help                  Show this help

EOF
}

main(){
  check_tools
  local TARGET="" FILE=""

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -d|--domain) TARGET="$2"; shift 2;;
      -f|--file)   FILE="$2"; shift 2;;
      --threads)   THREADS="${2:-10}"; shift 2;;
      --wordlist)  WORDLIST="$2"; shift 2;;
      --skip-shots) SHOTS=0; shift;;
      --skip-ports) PORTS=0; shift;;
      --no-ferox)  SKIP_FEROX=true; shift;;
      --no-params) SKIP_PARAMS=true; shift;;
      --no-js)     SKIP_JS=true; shift;;
      --amass)     USE_AMASS=true; shift;;
      --summarize) SUMMARY=1; shift;;
      --report-html) REPORT_HTML=1; shift;;
      --out) OUTBASE="$2"; shift 2;;
      --scope-file) SCOPE_FILE="$2"; shift 2;;
      --oos-file)  OOS_FILE="$2"; shift 2;;
      --scope) SCOPE_ITER_FILE="$2"; shift 2;;
      --no-strict-scope) STRICT_SCOPE=false; shift;;
      --fast)      THREADS=50; SHOTS=0; SKIP_FEROX=true; info "FAST mode: threads=50, no shots, skip ferox"; shift;;
      --debug) DEBUG=1; shift;;
      --dry-run) DRYRUN=1; shift;;
      -v|--verbose) VERBOSE=1; shift;;
      -h|--help) usage; exit 0;;
      *) die "unknown arg: $1";;
    esac
  done

  if [[ -n "$SCOPE_ITER_FILE" ]]; then
    FILE="$SCOPE_ITER_FILE"
    if [[ -z "$SCOPE_FILE" ]]; then
      SCOPE_FILE="$SCOPE_ITER_FILE"
      info "Using --scope '$SCOPE_ITER_FILE' as allowlist for strict scope filtering."
    fi
  fi

  [[ -n "$TARGET" || -n "$FILE" ]] || die "pass -d <domain> or -f file or --scope scope.txt"

  if [[ -n "$TARGET" ]]; then
    run_target "$TARGET"
  else
    while read -r d; do
      [[ -z "${d// }" || "$d" =~ ^# ]] && continue
      run_target "$d"
    done < "$FILE"
  fi
}


main "$@"
