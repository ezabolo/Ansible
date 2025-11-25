#!/usr/bin/env bash
#
# privileged_users_report_rhel.sh
#
# Generate a CSV report of privileged users on this RHEL-like system.
# For each privileged user:
#   - username, uid
#   - primary group
#   - list of all groups
#   - number of successful logins in the current month
#   - number of failed logins in the current month
#   - violation flag (any failed login attempts)
#   - account expired or not
#   - account created this month or not (approx via password change date)
#
# Usage:
#   ./privileged_users_report_rhel.sh [output_csv_file]
#
# Default output: /tmp/privileged_users_report.csv

set -euo pipefail

OUTPUT_FILE="${1:-/tmp/privileged_users_report.csv}"

# Global default for creation date (used with set -u)
CREATION_DATE="N/A"

# --- Helpers ---------------------------------------------------------------

csv_escape() {
    # Escape a value for CSV (wrap in quotes, double any internal quotes)
    local s="${1//\"/\"\"}"
    printf '"%s"' "$s"
}

detect_auth_source() {
    # RHEL/CentOS/Rocky/Alma: /var/log/secure is standard
    if [[ -f /var/log/secure ]]; then
        echo "/var/log/secure"
    else
        echo ""
    fi
}

get_privileged_users() {
    # UID 0 users
    awk -F: '($3 == 0) {print $1}' /etc/passwd

    # Members of typical privileged groups on RHEL (tune as needed)
    # Include developer_limited and developer_unlimited as privileged groups
    local groups="wheel root developer_limited developer_unlimited"
    for g in $groups; do
        if getent group "$g" >/dev/null 2>&1; then
            getent group "$g" | awk -F: '{print $4}' | tr ',' '\n' | sed '/^$/d'
        fi
    done
}

account_expired() {
    local user="$1"
    if ! chage -l "$user" >/dev/null 2>&1; then
        echo "unknown"
        return
    fi

    local exp
    exp=$(chage -l "$user" | awk -F: '/Account expires/ {gsub(/^ +/, "", $2); print $2}')
    if [[ -z "$exp" || "$exp" == "never" ]]; then
        echo "no"
        return
    fi

    local now_epoch exp_epoch
    now_epoch=$(date +%s)
    if ! exp_epoch=$(date -d "$exp" +%s 2>/dev/null); then
        echo "unknown"
        return
    fi

    if (( exp_epoch < now_epoch )); then
        echo "yes"
    else
        echo "no"
    fi
}

created_this_month() {
    local user="$1"
    CREATION_DATE="N/A"

    # Derive "creation" from useradd "new user" entries in /var/log/secure* for the current month.
    local month_abbr year
    month_abbr=$(date +%b)
    year=$(date +%Y)

    # Get first matching useradd line for this user (current and rotated secure logs)
    local line
    line=$(grep -h "useradd" /var/log/secure /var/log/secure-* 2>/dev/null \
           | grep "new user:" \
           | grep "name=$user" \
           | head -n 1 || true)

    if [[ -z "$line" ]]; then
        echo "no"
        CREATION_DATE="N/A"
        return
    fi

    # Expected format: "Mon DD HH:MM:SS host useradd[PID]: new user: name=USER, ..."
    local m d t
    m=$(printf '%s\n' "$line" | awk '{print $1}')
    d=$(printf '%s\n' "$line" | awk '{print $2}')
    t=$(printf '%s\n' "$line" | awk '{print $3}')

    # Only consider entries from the current month
    if [[ "$m" != "$month_abbr" ]]; then
        echo "no"
        CREATION_DATE="N/A"
        return
    fi

    local dt
    dt=$(date -d "$m $d $year $t" +%Y-%m-%d 2>/dev/null || printf '%s %s' "$m" "$d")

    CREATION_DATE="$dt"
    echo "yes"
}

log_counts_for_user_file() {
    # Args: user log_file
    local user="$1"
    local logfile="$2"
    local month_abbr
    month_abbr=$(date +%b)

    local success fails

    # Successful SSH logins
    success=$(grep -E "sshd\[.*\]: Accepted (password|publickey)" "$logfile" 2>/dev/null \
              | grep " $month_abbr " \
              | grep -w " $user" \
              | wc -l || echo 0)

    # Failed SSH logins
    fails=$(grep -E "sshd\[.*\]: Failed password" "$logfile" 2>/dev/null \
            | grep " $month_abbr " \
            | grep -w " $user" \
            | wc -l || echo 0)

    echo "$success" "$fails"
}

log_counts_for_user_journal() {
    # Args: user
    local user="$1"
    local since
    since="$(date +%Y-%m-01)"

    local success fails
    success=$(journalctl -u sshd -S "$since" 2>/dev/null \
              | grep -E "Accepted (password|publickey)" \
              | grep -w " $user" \
              | wc -l || echo 0)

    fails=$(journalctl -u sshd -S "$since" 2>/dev/null \
            | grep -E "Failed password" \
            | grep -w " $user" \
            | wc -l || echo 0)

    echo "$success" "$fails"
}

log_counts_for_user() {
    # Wrapper that prefers /var/log/secure but falls back to journalctl.
    local user="$1"
    local logfile="$2"

    if [[ -n "$logfile" ]]; then
        log_counts_for_user_file "$user" "$logfile"
    else
        log_counts_for_user_journal "$user"
    fi
}

# --- Main ------------------------------------------------------------------

AUTH_LOG_FILE=$(detect_auth_source)

mapfile -t PRIV_USERS < <(get_privileged_users | sort -u)

# CSV header
{
    echo "username,uid,groups,logins_current_month,failed_logins_current_month,violation,account_expired,created_current_month,creation_date"
} > "$OUTPUT_FILE"

for user in "${PRIV_USERS[@]}"; do
    if ! getent passwd "$user" >/dev/null 2>&1; then
        continue
    fi

    uid=$(id -u "$user" 2>/dev/null || echo "")
    primary_group=$(id -gn "$user" 2>/dev/null || echo "")
    groups=$(id -nG "$user" 2>/dev/null | tr ' ' ';' || echo "")

    read -r logins fails <<<"$(log_counts_for_user "$user" "$AUTH_LOG_FILE")"

    violation="no"
    if [[ "$fails" -gt 0 ]]; then
        violation="yes"
    fi

    expired=$(account_expired "$user")
    created_month=$(created_this_month "$user")
    CREATION_DATE=${CREATION_DATE:-N/A}

    {
        csv_escape "$user"
        printf ","
        csv_escape "$uid"
        printf ","
        csv_escape "$groups"
        printf ","
        csv_escape "$logins"
        printf ","
        csv_escape "$fails"
        printf ","
        csv_escape "$violation"
        printf ","
        csv_escape "$expired"
        printf ","
        csv_escape "$created_month"
        printf ","
        csv_escape "$CREATION_DATE"
        printf "\n"
    } >> "$OUTPUT_FILE"

done

echo "Report written to: $OUTPUT_FILE"
