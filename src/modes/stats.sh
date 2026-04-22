# ==============================================================================
# MODE: stats
# ==============================================================================
mode_stats() {
    local name="${1:-}"
    [[ -z "$name" || ! " ${LOGS[*]} " =~ " $name " ]] && {
        echo -e "${R}Usage: $0 stats <app>${NC}  Apps: ${LOGS[*]}"; exit 1; }
    local file="$LOG_DIR/$name.access.log"
    [[ -f "$file" ]] || { echo -e "${R}Not found: $file${NC}"; exit 1; }
    echo -e "\n${W}── MiLog: Hourly breakdown — ${name} ──${NC}\n"
    awk '{match($4,/\[([0-9]{2}\/[A-Za-z]+\/[0-9]{4}):([0-9]{2})/,a)
         if(a[2]!="")h[a[2]]++}
         END{for(x in h)print x,h[x]}' "$file" | sort | \
    awk -v g="$G" -v y="$Y" -v r="$R" -v nc="$NC" '
    BEGIN{max=0}{if($2>max)max=$2;d[NR]=$0;n=NR}
    END{for(i=1;i<=n;i++){split(d[i],a," ")
        b=int((a[2]/max)*40); bars=""
        for(j=0;j<b;j++) bars=bars"|"
        col=g; if(a[2]/max>0.6)col=y; if(a[2]/max>0.85)col=r
        printf "%s:00  %s%-40s%s  %d\n",a[1],col,bars,nc,a[2]}}'
    echo ""
}

