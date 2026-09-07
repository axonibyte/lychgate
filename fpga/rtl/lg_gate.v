// The lychgate fabric gate: the TTL countdown and the enable line are the
// SAME hardware (docs/EMBEDDED.md §8c). gate_en is combinational on the
// counter — assign gate_en = |counter — with no state of its own, so no
// instruction stream (not even the soft core that loads it) can hold the
// gate open past expiry: the only ways gate_en stays high are "the counter
// is nonzero" and nothing else. The soft core may LOAD the counter (after
// verifying a capability token) and CLEAR it (on revocation); time does the
// rest.
//
// The formal section proves the safety property outright (never open at
// zero — structural here, but machine-checked so a refactor cannot quietly
// break it) and covers the drop actually happening; `make formal-mutation`
// runs the same proof against lg_gate_broken.v and demands it FAIL — the
// oracle self-test, in gates.
`default_nettype none

module lg_gate #(
    // Clock ticks per second-tick. 12 MHz default (iCE40-UP5K's usual osc);
    // small in simulation via parameter override.
    parameter CLK_HZ = 12_000_000,
    // Counter width in bits: 17 bits of seconds > 24h (86400s < 2^17).
    parameter WIDTH = 17
) (
    input wire clk,
    input wire rst_n,

    // Load a fresh TTL (seconds) — the soft core, after verify.
    input wire load_en,
    input wire [WIDTH-1:0] load_secs,
    // Clear immediately — revocation.
    input wire clear,

    output wire gate_en,
    output wire [WIDTH-1:0] remaining_secs
);

    reg [$clog2(CLK_HZ)-1:0] prescale;
    reg [WIDTH-1:0] counter;

    assign gate_en = |counter;
    assign remaining_secs = counter;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            counter <= 0;
            prescale <= 0;
        end else if (clear) begin
            counter <= 0;
            prescale <= 0;
        end else if (load_en) begin
            counter <= load_secs;
            prescale <= 0;
        end else if (counter != 0) begin
            if (prescale == CLK_HZ - 1) begin
                prescale <= 0;
                counter <= counter - 1;
            end else begin
                prescale <= prescale + 1;
            end
        end
    end

`ifdef FORMAL
    // Constrain the proof to runs that begin in reset — the standard idiom;
    // without it the solver invents an arbitrary pre-history for the $past
    // chains. The combinational safety assert below needs no such help.
    initial assume (!rst_n);

    // The headline safety property: the gate is NEVER asserted while the
    // counter is zero. Structural for this implementation — which is the
    // point; the proof pins the structure.
    always @(*) begin
        assert (!(gate_en && counter == 0));
    end

    // Liveness cover: the drop is reachable (a gate that could never close
    // would satisfy the assert vacuously... it couldn't here, but the cover
    // proves the interesting trajectory exists: open, then closed at zero).
    reg was_open;
    initial was_open = 0;
    always @(posedge clk) begin
        if (gate_en)
            was_open <= 1;
        cover (was_open && !gate_en && counter == 0);
    end

    // clear is immediate: one clock after clear (without a simultaneous
    // load), the gate is down.
    always @(posedge clk) begin
        if ($past(clear) && !$past(load_en) && $past(rst_n) && rst_n)
            assert (!gate_en);
    end
`endif

endmodule
`default_nettype wire
