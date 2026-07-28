#!/bin/bash
. /tmp/wibuku_env
cd $WORKDIR
LIVE_HOSTS=$(awk '{print $1}' live/httpx.txt | sed 's|https\?://||' | sort -u)
echo "$LIVE_HOSTS" > per_host_list.txt
echo "Probing: $(wc -l < per_host_list.txt) hosts"
echo "$LIVE_HOSTS" | xargs -I{} -P 4 bash -c 'H="{}"; bash probe.sh "$H" "per_host/$H"'
echo "DONE"
