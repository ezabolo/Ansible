# Find creation date for a user by scanning /var/log/secure*
# Sets:
#   CREATION_DATE = DD-MM-YYYY if created in CURRENT month, otherwise N/A
#   CREATION_LOG  = log file where found, or N/A
# Echoes "yes" if created this month, "no" otherwise.
created_this_month_from_secure() {
    local user="$1"
    CREATION_DATE="N/A"
    CREATION_LOG="N/A"

    local month_abbr year
    month_abbr=$(date +%b)      # e.g. Nov
    year=$(date +%Y)            # e.g. 2025

    # Search current and rotated secure logs
    local log
    for log in /var/log/secure /var/log/secure-*; do
        [[ -f "$log" ]] || continue

        # Look for useradd \"new user\" lines for this username
        local line
        line=$(grep -h "useradd" "$log" 2>/dev/null \
               | grep "new user:" \
               | grep "name=$user" \
               | head -n 1 || true)

        [[ -z "$line" ]] && continue

        # Fields: Mon DD HH:MM:SS host useradd[PID]: new user: name=USER, ...
        local m d t
        m=$(printf '%s\n' "$line" | awk '{print $1}')
        d=$(printf '%s\n' "$line" | awk '{print $2}')
        t=$(printf '%s\n' "$line" | awk '{print $3}')

        # Only accept entries from the CURRENT month
        if [[ "$m" != "$month_abbr" ]]; then
            continue
        fi

        # Build DD-MM-YYYY
        local dt
        dt=$(date -d "$m $d $year $t" +%d-%m-%Y 2>/dev/null || printf '%s-%s-%s' "$d" "$m" "$year")

        CREATION_DATE="$dt"
        CREATION_LOG="$log"
        echo "yes"
        return
    done

    # No matching useradd log this month
    echo "no"
    CREATION_DATE="N/A"
    CREATION_LOG="N/A"
}
