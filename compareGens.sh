#!/bin/bash

if [ $# -ne 2 ]; then
    echo "$0 left-gen right-gen"
    exit 1
fi

LEFT="$1"
RIGHT="$2"

LTOPOS=$(find "$LEFT" -name topology.json | grep endhost | sort)
RTOPOS=$(find "$RIGHT" -name topology.json | grep endhost | sort)
readarray -t LTOPOS <<<"$LTOPOS"
readarray -t RTOPOS <<<"$RTOPOS"

if [ ${#LTOPOS[@]} -ne ${#RTOPOS[@]} ]; then
    echo "Different number of files: ${#LTOPOS[@]} and ${#RTOPOS[@]}"
    exit 1
fi

differ=0
for i in `seq 0 $((${#LTOPOS[@]} -1))`; do
    LTP=${LTOPOS[i]}
    RTP=${RTOPOS[i]}
    jq -S . $LTP > /tmp/left.json
    jq -S . $RTP > /tmp/right.json
    diff /tmp/left.json /tmp/right.json >/dev/null || { echo -e "$LTP\t\t!=\t\t$RTP"; differ=1; }
done
exit $differ
