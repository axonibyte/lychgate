// The reference iCE40-UP5K build (E9-M3): the formally-proved lg_gate on
// real fabric, clocked by the internal HFOSC, with a bench-jumper load
// interface — the smallest REAL instantiation of "TTL enforced in gates".
// The soft-core verifier stays simulation-tier for now (the UP5K's 128 KB
// SPRAM could hold an Ed25519 image; wiring that is named future work —
// this build's claim is that the GATE itself places, routes and closes
// timing on the part the gate exists for).
//
// Bench semantics: load_btn (debounced externally / a jumper) loads
// LOAD_SECS; clear_btn clears; gate_led is the gate.
`default_nettype none

module lg_gate_top (
    input wire load_btn,
    input wire clear_btn,
    output wire gate_led
);
    localparam LOAD_SECS = 60;

    wire clk;
    // The UP5K internal oscillator: 48 MHz / 4 = 12 MHz.
    SB_HFOSC #(.CLKHF_DIV("0b01")) hfosc (
        .CLKHFEN(1'b1),
        .CLKHFPU(1'b1),
        .CLKHF(clk)
    );

    // Power-on reset: a small counter holds reset for the first cycles.
    reg [7:0] por = 8'h00;
    wire rst_n = por[7];
    always @(posedge clk) if (!por[7]) por <= por + 1;

    // Edge-detect the load jumper so holding it does not re-load forever.
    reg [1:0] load_sync = 2'b00;
    always @(posedge clk) load_sync <= {load_sync[0], load_btn};
    wire load_pulse = load_sync[0] & ~load_sync[1];

    wire [16:0] remaining;
    lg_gate #(.CLK_HZ(12_000_000), .WIDTH(17)) gate (
        .clk(clk),
        .rst_n(rst_n),
        .load_en(load_pulse),
        .load_secs(LOAD_SECS[16:0]),
        .clear(clear_btn),
        .gate_en(gate_led),
        .remaining_secs(remaining)
    );
endmodule
`default_nettype wire
