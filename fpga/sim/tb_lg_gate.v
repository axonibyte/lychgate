// iverilog testbench for lg_gate: load, count to zero, watch the gate drop;
// clear mid-count; reset mid-grant. CLK_HZ=4 so one "second" is 4 clocks.
`timescale 1ns/1ns
`default_nettype none

module tb_lg_gate;
    reg clk = 0;
    reg rst_n = 0;
    reg load_en = 0;
    reg clear = 0;
    reg [16:0] load_secs = 0;
    wire gate_en;
    wire [16:0] remaining_secs;

    lg_gate #(.CLK_HZ(4), .WIDTH(17)) dut (
        .clk(clk), .rst_n(rst_n),
        .load_en(load_en), .load_secs(load_secs), .clear(clear),
        .gate_en(gate_en), .remaining_secs(remaining_secs)
    );

    always #5 clk = ~clk;

    integer errors = 0;
    task check(input cond, input [255:0] what);
        if (!cond) begin
            errors = errors + 1;
            $display("FAIL: %0s (t=%0t gate=%b counter=%0d)", what, $time, gate_en, remaining_secs);
        end
    endtask

    initial begin
        // Reset: closed.
        repeat (2) @(posedge clk);
        rst_n = 1;
        @(posedge clk);
        check(!gate_en, "closed out of reset");

        // Load 3 "seconds": open immediately, drop after 3*4 clocks.
        load_secs = 3; load_en = 1; @(posedge clk); load_en = 0;
        @(posedge clk);
        check(gate_en, "open after load");
        // one clock before the final decrement it must still be open
        repeat (9) @(posedge clk);
        check(gate_en, "still open before expiry");
        // by 12 clocks + slack the counter reaches zero and the gate drops
        repeat (4) @(posedge clk);
        check(!gate_en, "dropped at expiry");
        check(remaining_secs == 0, "counter at zero");

        // Clear mid-count.
        load_secs = 100; load_en = 1; @(posedge clk); load_en = 0;
        @(posedge clk);
        check(gate_en, "open again");
        clear = 1; @(posedge clk); clear = 0;
        @(posedge clk);
        check(!gate_en, "clear closes immediately");

        // Reset mid-grant: closed.
        load_secs = 100; load_en = 1; @(posedge clk); load_en = 0;
        @(posedge clk);
        check(gate_en, "open a third time");
        rst_n = 0; @(posedge clk); rst_n = 1;
        @(posedge clk);
        check(!gate_en, "reset closes");

        if (errors == 0)
            $display("tb_lg_gate: ok");
        else begin
            $display("tb_lg_gate: %0d failure(s)", errors);
            $fatal(1);
        end
        $finish;
    end
endmodule
`default_nettype wire
