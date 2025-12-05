#!/bin/bash
set -euo pipefail

# Color definitions
: "${blue:=\033[0;34m}"
: "${cyan:=\033[0;36m}"
: "${reset:=\033[0m}"
: "${red:=\033[0;31m}"
: "${green:=\033[0;32m}"
: "${orange:=\033[0;33m}"
: "${bold:=\033[1m}"
: "${b_green:=\033[1;32m}"
: "${b_red:=\033[1;31m}"
: "${b_orange:=\033[1;33m}"

# Defaults
nreg=false
update_tld=false
tld_file="tlds.txt"
tld_url="https://data.iana.org/TLD/tlds-alpha-by-domain.txt"
keyword=""
tld=""
exts=""
delay="${DELAY:-1.5}"
output_file=""
resume=false
quiet=false
max_attempts=3
whois_timeout="${WHOIS_TIMEOUT:-15}"

available_regex="no match|not found|no data found|no entries found|domain not found|status:[[:space:]]*free|not registered|available"
rate_limit_regex="limit exceeded|exceeded port 43|quota exceeded|try again later|too many requests|please wait|please try again|temporarily unavailable"

last_status=""
last_message=""
last_log=""

banner() {
    cat << "EOF"
 _____ _    ___  _  _          _   
|_   _| |  |   \| || |_  _ _ _| |_ 
  | | | |__| |) | __ | || | ' \  _|
  |_| |____|___/|_||_|\_,_|_||_\__|
        Domain Availability Checker
EOF
}

usage() {
    echo "Usage: $0 -k <keyword> [-e <tld> | -E <tld-file>] [-x] [--update-tld] [options]"
    echo ""
    echo "Options:"
    echo "  -k, --keyword         Base keyword for domains (required)"
    echo "  -e, --tld             Single TLD to check (e.g. .com)"
    echo "  -E, --tld-file        File containing list of TLDs, one per line"
    echo "  -x, --not-registered  Show only domains that are not registered"
    echo "      --update-tld      Fetch and update the local TLD file from IANA"
    echo "  -d, --delay SECS      Delay between queries (default: ${delay})"
    echo "  -o, --output FILE     Save results to file (default: tldhunt-<timestamp>.txt)"
    echo "  -r, --resume          Skip domains already present in output file"
    echo "  -q, --quiet           Less verbose output"
    echo ""
    echo "Example: $0 -k linuxsec -E tlds.txt"
    echo "         $0 -k mybrand -e .com -d 2.0 -o results.txt"
    echo "         $0 --update-tld"
    exit 1
}

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || { echo "$1 not installed. Please install it first." >&2; exit 1; }
}

whois_runner() {
    local domain="$1"
    if command -v timeout >/dev/null 2>&1; then
        timeout "$whois_timeout" whois "$domain" 2>/dev/null
    else
        perl -e 'alarm shift; exec @ARGV' "$whois_timeout" whois "$domain" 2>/dev/null
    fi
}

parse_expiry() {
    local output="$1"
    local expiry_block
    expiry_block=$(echo "$output" | grep -iE "Expiry Date|Expiration Date|Registry Expiry Date|Expiration Time|paid-till|renewal date|expire date|expires on|valid until" || true)
    if [[ -z $expiry_block ]]; then
        echo ""
        return
    fi
    echo "$expiry_block" | grep -Eo '[0-9]{4}[-/.][0-9]{2}[-/.][0-9]{2}' | head -n1 || true
}

check_domain_once() {
    local domain="$1"
    local whois_output
    whois_output=$(whois_runner "$domain" || true)
    whois_output=$(printf "%s" "$whois_output" | tr -d '\r')

    if [[ -z $whois_output ]]; then
        last_status="retry"
        last_message="[${b_orange}retry${reset}] $domain - empty whois response"
        last_log="$domain|error|empty-whois"
        return
    fi

    if echo "$whois_output" | grep -qiE "$rate_limit_regex"; then
        last_status="retry"
        last_message="[${b_orange}retry${reset}] $domain - rate limited, backing off"
        last_log="$domain|retry|rate-limit"
        return
    fi

    if echo "$whois_output" | grep -qiE "$available_regex"; then
        last_status="avail"
        last_message="[${b_green}avail${reset}] $domain"
        last_log="$domain|avail|"
        return
    fi

    local expiry_date
    expiry_date=$(parse_expiry "$whois_output")
    if [[ -n $expiry_date ]]; then
        last_status="taken"
        last_message="[${b_red}taken${reset}] $domain - Exp Date: ${orange}$expiry_date${reset}"
        last_log="$domain|taken|$expiry_date"
        return
    fi

    last_status="taken"
    last_message="[${b_red}taken${reset}] $domain"
    last_log="$domain|taken|"
}

emit_result() {
    if [[ $quiet == false ]]; then
        if [[ $nreg == true && $last_status == "taken" ]]; then
            :
        else
            echo -e "$last_message"
        fi
    fi
    echo "$last_log" >> "$output_file"
}

check_domain_with_retry() {
    local domain="$1"
    local attempt=1
    while (( attempt <= max_attempts )); do
        check_domain_once "$domain"
        if [[ $last_status == "avail" || $last_status == "taken" ]]; then
            emit_result
            return 0
        fi

        if (( attempt == max_attempts )); then
            last_status="error"
            last_message="[${b_orange}error${reset}] $domain - failed after ${max_attempts} attempts"
            last_log="$domain|error|retries-exceeded"
            emit_result
            return 1
        fi

        local backoff=$((2 ** attempt))
        if [[ $quiet == false ]]; then
            echo "    rate limited; retrying in ${backoff}s..."
        fi
        ((attempt++))
        sleep "$backoff"
    done
}

load_tlds() {
    tlds=()
    if [[ -n $exts ]]; then
        while IFS= read -r line; do
            [[ -z $line ]] && continue
            [[ $line =~ ^# ]] && continue
            tlds+=("$line")
        done < "$exts"
    else
        tlds=("$tld")
    fi
}

already_processed() {
    local domain="$1"
    [[ $resume == true && -f $output_file ]] && grep -F -q "^${domain}|" "$output_file"
}

# Dependencies
require_cmd whois
require_cmd curl

banner

# Argument parsing
while [[ "$#" -gt 0 ]]; do
    case $1 in
        -k|--keyword) keyword="$2"; shift ;;
        -e|--tld) tld="$2"; shift ;;
        -E|--tld-file) exts="$2"; shift ;;
        -x|--not-registered) nreg=true ;;
        --update-tld) update_tld=true ;;
        -d|--delay) delay="$2"; shift ;;
        -o|--output) output_file="$2"; shift ;;
        -r|--resume) resume=true ;;
        -q|--quiet) quiet=true ;;
        *) echo "Unknown parameter passed: $1"; usage ;;
    esac
    shift
done

# Validate arguments
if [[ "$update_tld" = true ]]; then
    [[ -n $keyword || -n $tld || -n $exts || "$nreg" = true ]] && { echo "--update-tld cannot be used with other flags."; usage; }
    echo "Fetching TLD data from $tld_url..."
    curl -s "$tld_url" | \
        grep -v '^#' | \
        tr '[:upper:]' '[:lower:]' | \
        sed 's/^/./' > "$tld_file"
    echo "TLDs have been saved to $tld_file."
    exit 0
fi

[[ -z $keyword ]] && { echo "Keyword is required."; usage; }
[[ -n $tld && -n $exts ]] && { echo "You can only specify one of -e or -E options."; usage; }
[[ -z $tld && -z $exts ]] && { echo "Either -e or -E option is required."; usage; }
[[ -n $exts && ! -f $exts ]] && { echo "TLD file $exts not found."; usage; }

if [[ -z $output_file ]]; then
    output_file="tldhunt-$(date +%Y%m%d-%H%M%S).txt"
fi

touch "$output_file"

load_tlds

total=${#tlds[@]}
current=0

for ext in "${tlds[@]}"; do
    domain="${keyword}${ext}"
    ((current++))

    if already_processed "$domain"; then
        if [[ $quiet == false ]]; then
            echo "[skip] $domain (already in $output_file)"
        fi
        continue
    fi

    if [[ $quiet == false ]]; then
        echo "[${current}/${total}] Checking ${domain}..."
    fi

    check_domain_with_retry "$domain"
    sleep "$delay"
done