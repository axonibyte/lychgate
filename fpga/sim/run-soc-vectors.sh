#!/bin/sh
# The soc-test vector runs (invoked by `make soc-test` from fpga/): one
# harness run per token. cap-v1-small must load AND autonomously drop;
# every reject-corpus sample must refuse without raising the gate.
set -u
VECTORS="${VECTORS:-../wire/vectors}"

run() { # kat record expect
    len="$(python3 sim/kat2mem.py token "${VECTORS}/$1" "$2" build/token.hex)" || exit 1
    echo "==> $2 (expect $3)"
    ./build/soc/Vlg_soc +FW_HEX=build/fw.hex +TOKEN_HEX=build/token.hex \
        "+TOKEN_LEN=${len}" "+EXPECT=$3" || exit 1
}

run lgcap_v1.kat cap-v1-small loaded
run lgcap_reject.kat flipped-sig-v1 refused
run lgcap_reject.kat cross-type refused
run lgcap_reject.kat wrong-key refused
run lgcap_reject.kat trailing-byte refused
echo "soc-test: ok (verify + load + autonomous drop, refusals refused)"
