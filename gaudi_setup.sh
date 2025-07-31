#!/bin/bash
# filepath: gaudi_setup.sh

export LD_LIBRARY_PATH=/usr/lib/habanalabs:/workspace/ucx-gaudi/install/lib:${LD_LIBRARY_PATH}
export PATH=/usr/bin:/workspace/ucx-gaudi/install/bin:${PATH}

# Check if hl-smi is available
if ! command -v hl-smi &> /dev/null; then
    echo "Error: hl-smi not found in PATH"
    return 1 2>/dev/null || exit 1
fi

# Query Gaudi device mapping using hl-smi
mapping_json="["
first=1

while IFS=',' read -r index module_id bus_id; do
    # Remove whitespace
    index=$(echo "$index" | xargs)
    module_id=$(echo "$module_id" | xargs)
    bus_id=$(echo "$bus_id" | xargs)
    if [ -z "$index" ] || [ -z "$module_id" ] || [ -z "$bus_id" ]; then
        continue
    fi
    if [ $first -eq 0 ]; then
        mapping_json="${mapping_json},"
    fi
    mapping_json="${mapping_json}{\"index\":$index,\"module_id\":$module_id,\"bus_id\":\"$bus_id\"}"
    first=0
done < <(hl-smi -Q index,module_id,bus_id -f csv,noheader)

mapping_json="${mapping_json}]"

export GAUDI_MAPPING_TABLE="$mapping_json"
echo "GAUDI_MAPPING_TABLE=$GAUDI_MAPPING_TABLE"
