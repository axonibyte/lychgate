// The COMMITTED MUTATION: a gate that latches open. `make formal-mutation`
// runs the same SymbiYosys proof against this module and demands FAILURE —
// the formal harness's own oracle self-test (a proof never observed
// failing proves nothing about the prover setup). Never instantiate this
// outside the formal-mutation target.
`default_nettype none

module lg_gate #(
    parameter CLK_HZ = 12_000_000,
    parameter WIDTH = 17
) (
    input wire clk,
    input wire rst_n,
    input wire load_en,
    input wire [WIDTH-1:0] load_secs,
    input wire clear,
    output wire gate_en,
    output wire [WIDTH-1:0] remaining_secs
);

    reg [$clog2(CLK_HZ)-1:0] prescale;
    reg [WIDTH-1:0] counter;
    reg latched; // THE BUG: software-visible state on the enable path.

    assign gate_en = |counter | latched;
    assign remaining_secs = counter;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            counter <= 0;
            prescale <= 0;
            latched <= 0;
        end else if (clear) begin
            counter <= 0;
            prescale <= 0;
        end else if (load_en) begin
            counter <= load_secs;
            latched <= 1; // never released: the gate outlives the counter
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
    always @(*) begin
        assert (!(gate_en && counter == 0));
    end
`endif

endmodule
`default_nettype wire
