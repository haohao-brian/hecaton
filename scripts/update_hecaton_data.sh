#!/bin/bash

OBJDUMP="aarch64-linux-gnu-objdump"
DUMP_DIR="scripts/mod_dumps"
HEADER_OUT="scripts/hecaton_data.h"
DEST_HEADER="modified_kernels/hecaton_kernel/kernel/hecaton_data.h"

# 1. 檢查參數
if [ "$#" -lt 3 ]; then
    echo "Usage: source scripts/update_hecaton_data.sh <parse_script> <vmlinux> [module1.ko ...] <bug_id>"
    return 1 2>/dev/null || exit 1
fi

# 2. 提取 Script 和 Vmlinux
PARSE_SCRIPT="$1"
VMLINUX_BIN="$2"

# 3. 移除前兩個參數，現在參數列剩下：[module1.ko ... bug_id]
shift 2

# 4. [修正] 使用穩健的迴圈分離 Modules 和 BugID
# 邏輯：只要參數數量大於 1，當前的 $1 就是 module；剩下最後 1 個時，那個就是 BugID
MODULE_LIST=()
while [ "$#" -gt 1 ]; do
    MODULE_LIST+=("$1")
    shift
done

# 最後剩下的一個參數就是 BugID
BUG_ID="$1"

echo "[*] Target Bug ID: $BUG_ID"
echo "[*] Modules found: ${#MODULE_LIST[@]}"

# Ensure directories exist
mkdir -p "$DUMP_DIR"

# 5. Dump vmlinux
echo "[*] Disassembling vmlinux..."
$OBJDUMP -d "$VMLINUX_BIN" > scripts/vmlinux.txt

# 6. Dump Modules
MODULE_TXT_ARGS=""

if [ ${#MODULE_LIST[@]} -gt 0 ]; then
    echo "[*] Disassembling modules..."
    for ko_file in "${MODULE_LIST[@]}"; do
        # Extract filename (e.g., 'dummy.ko' -> 'dummy')
        mod_name=$(basename "$ko_file" .ko)
        txt_path="$DUMP_DIR/${mod_name}.txt"
        
        echo "    Processing $mod_name -> $txt_path"
        $OBJDUMP -d "$ko_file" > "$txt_path"
        
        # Add to the python argument list
        MODULE_TXT_ARGS="$MODULE_TXT_ARGS $txt_path"
    done
else
    echo "[*] No modules provided."
fi

# 7. Run Python Script
# Usage: python parse.py <input1> [input2...] <supported> <output>
# 參數順序：先放 vmlinux 和所有 modules (Inputs)，最後放 supported 和 output
echo "[*] Running Hecaton parser..."
python3 "$PARSE_SCRIPT" \
    scripts/vmlinux.txt \
    $MODULE_TXT_ARGS \
    "bugs/$BUG_ID/functions.txt" \
    "$HEADER_OUT"

# 8. Update Kernel Source
if [ -f "$HEADER_OUT" ]; then
    echo "[*] Updating header file to $DEST_HEADER..."
    cp "$HEADER_OUT" "$DEST_HEADER"
    echo "Done."
else
    echo "[!] Error: Header file was not generated."
    return 1 2>/dev/null || exit 1
fi
