// The verilator harness for lg_soc (E9-M2). One run judges one token:
//   soc_harness +FW_HEX=fw.hex +TOKEN_HEX=token.hex +TOKEN_LEN=N +EXPECT=loaded|refused
// For EXPECT=loaded it then keeps the clock running and demands the gate
// DROP at the counter's zero while the core is still alive — the "the core
// cannot hold it" demonstration on top of lg_gate's formal proof.

#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "Vlg_soc.h"
#include "verilated.h"

static vluint64_t sim_time = 0;

int main(int argc, char **argv) {
    Verilated::commandArgs(argc, argv);
    Vlg_soc top;

    const char *expect = nullptr;
    unsigned token_len = 0;
    for (int i = 1; i < argc; i++) {
        if (strncmp(argv[i], "+EXPECT=", 8) == 0)
            expect = argv[i] + 8;
        if (strncmp(argv[i], "+TOKEN_LEN=", 11) == 0)
            token_len = strtoul(argv[i] + 11, nullptr, 10);
    }
    if (!expect || token_len == 0) {
        fprintf(stderr, "usage: +FW_HEX=.. +TOKEN_HEX=.. +TOKEN_LEN=N +EXPECT=loaded|refused\n");
        return 2;
    }

    top.clk = 0;
    top.rst_n = 0;
    top.token_ready = 0;
    top.token_len = token_len;

    auto tick = [&]() {
        top.clk = 0;
        top.eval();
        top.clk = 1;
        top.eval();
        sim_time++;
    };

    for (int i = 0; i < 4; i++) tick();
    top.rst_n = 1;
    top.token_ready = 1;

    // Ed25519 verify on a simulated rv32i: generously budgeted.
    const vluint64_t budget = 400'000'000;
    while (top.result == 0 && sim_time < budget) tick();

    if (top.result == 0) {
        fprintf(stderr, "FAIL: no verdict within %llu cycles\n",
                (unsigned long long)budget);
        return 1;
    }

    bool loaded = top.result == 1;
    bool want_loaded = strcmp(expect, "loaded") == 0;
    if (loaded != want_loaded || (want_loaded && !top.gate_en)) {
        fprintf(stderr, "FAIL: result=%u gate_en=%u (expected %s)\n",
                (unsigned)top.result, (unsigned)top.gate_en, expect);
        return 1;
    }
    if (!want_loaded) {
        if (top.gate_en) {
            fprintf(stderr, "FAIL: a refused token raised the gate\n");
            return 1;
        }
        printf("soc: refused as expected (%llu cycles)\n",
               (unsigned long long)sim_time);
        return 0;
    }

    // The gate is up. Keep clocking: the counter (GATE_CLK_HZ=4, ttl from
    // the token) must bring it DOWN with the core still running — assert the
    // absence with (simulated) time passing.
    unsigned ttl = top.remaining_secs;
    vluint64_t deadline = sim_time + (vluint64_t)(ttl + 2) * 4 + 64;
    while (top.gate_en && sim_time < deadline) tick();
    if (top.gate_en) {
        fprintf(stderr, "FAIL: the gate outlived its counter (ttl=%u)\n", ttl);
        return 1;
    }
    if (top.result != 1) {
        fprintf(stderr, "FAIL: the core died (result=%u) — the drop must not depend on it\n",
                (unsigned)top.result);
        return 1;
    }
    printf("soc: loaded, and the gate dropped at zero with the core alive (%llu cycles)\n",
           (unsigned long long)sim_time);
    return 0;
}
