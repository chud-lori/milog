# ==============================================================================
# MODE: rate — nginx-only
# ==============================================================================
mode_rate() {
    while true; do
        milog_update_geometry
        clear
        local CUR_TIME TIMESTAMP TOTAL=0
        CUR_TIME=$(date '+%d/%b/%Y:%H:%M')
        TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

        bdr_top
        draw_row " MiLog   ${TIMESTAMP}" " ${W}MiLog${NC}   ${D}${TIMESTAMP}${NC}"
        bdr_mid
        bdr_hdr
        hdr_row
        bdr_hdr

        for name in "${LOGS[@]}"; do
            nginx_row "$name" "$CUR_TIME" TOTAL
        done

        bdr_sep
        draw_row " TOTAL: ${TOTAL} req/min" " ${W}TOTAL:${NC} ${TOTAL} req/min"
        bdr_bot
        printf "${D} Ctrl+C to exit  |  Refresh: ${REFRESH}s${NC}\n"
        sleep "$REFRESH"
    done
}

