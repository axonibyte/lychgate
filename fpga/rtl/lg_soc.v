// The lychgate soft-core SoC (E9-M2): a vendored picorv32 running the SAME
// lychgate-wire verifier the daemon and firmware compile, wired to the
// formally-proved lg_gate. The division of trust is the whole design: the
// core VERIFIES tokens and may load or clear the counter; the gate's enable
// is combinational on the counter, so the core cannot hold it open — the
// property lg_gate's proof pins.
//
// Memory map (native picorv32 interface):
//   0x0000_0000 .. RAM_WORDS*4    RAM (firmware image + data + stack)
//   0x1000_0000  R  token_ready (the harness raised a token)
//   0x1000_0004  R  token_len
//   0x1000_0008  W  result (1 = verified & loaded, 2 = refused; ends the run)
//   0x1000_000c  W  gate load_secs (pulses lg_gate load_en)
//   0x1000_0010  W  gate clear (pulses lg_gate clear)
//   0x1000_0400+ R  token bytes (one byte per WORD, low 8 bits)
//
// Simulation-only sizing: RAM_WORDS defaults far beyond any iCE40 (the
// crypto firmware is tens of KB) — E9-M2 proves logic and interop, NOT
// resource fit; see TESTING.md's tier notes and the M3 synth target for
// what the fabric build actually carries.
`default_nettype none

module lg_soc #(
    parameter RAM_WORDS = 262144, // 1 MB
    parameter GATE_CLK_HZ = 4,    // tiny prescale: observable expiry in sim
    parameter TOKEN_BYTES = 256
) (
    input wire clk,
    input wire rst_n,

    // Harness side: raise a token for the core to judge.
    input wire token_ready,
    input wire [31:0] token_len,

    output reg [31:0] result,
    output wire gate_en,
    output wire [16:0] remaining_secs
);

    // --- memories ----------------------------------------------------------
    reg [31:0] ram [0:RAM_WORDS-1];
    reg [7:0] token [0:TOKEN_BYTES-1];
    initial begin : init_mem
        integer i;
        reg [1023:0] fw_hex;
        reg [1023:0] token_hex;
        for (i = 0; i < TOKEN_BYTES; i = i + 1) token[i] = 8'h00;
        if ($value$plusargs("FW_HEX=%s", fw_hex))
            $readmemh(fw_hex, ram);
        if ($value$plusargs("TOKEN_HEX=%s", token_hex))
            $readmemh(token_hex, token);
    end

    // --- the gate ----------------------------------------------------------
    reg gate_load_en;
    reg [16:0] gate_load_secs;
    reg gate_clear;

    lg_gate #(.CLK_HZ(GATE_CLK_HZ), .WIDTH(17)) gate (
        .clk(clk),
        .rst_n(rst_n),
        .load_en(gate_load_en),
        .load_secs(gate_load_secs),
        .clear(gate_clear),
        .gate_en(gate_en),
        .remaining_secs(remaining_secs)
    );

    // --- the core ----------------------------------------------------------
    wire mem_valid;
    wire mem_instr;
    reg mem_ready;
    wire [31:0] mem_addr;
    wire [31:0] mem_wdata;
    wire [3:0] mem_wstrb;
    reg [31:0] mem_rdata;

    picorv32 #(
        .ENABLE_COUNTERS(0),
        .ENABLE_COUNTERS64(0),
        .ENABLE_REGS_16_31(1),
        .ENABLE_REGS_DUALPORT(1),
        .BARREL_SHIFTER(1),
        .COMPRESSED_ISA(0),
        // riscv32im: without a hardware multiplier, every curve25519 field
        // multiply is a ~500-cycle __mulsi3 shift-add loop and one Ed25519
        // verify blows past any sane cycle budget.
        .ENABLE_FAST_MUL(1),
        .ENABLE_DIV(1),
        .ENABLE_IRQ(0),
        .STACKADDR(RAM_WORDS * 4)
    ) cpu (
        .clk(clk),
        .resetn(rst_n),
        .mem_valid(mem_valid),
        .mem_instr(mem_instr),
        .mem_ready(mem_ready),
        .mem_addr(mem_addr),
        .mem_wdata(mem_wdata),
        .mem_wstrb(mem_wstrb),
        .mem_rdata(mem_rdata),
        // unused interfaces tied off
        .mem_la_read(),
        .mem_la_write(),
        .mem_la_addr(),
        .mem_la_wdata(),
        .mem_la_wstrb(),
        .pcpi_valid(),
        .pcpi_insn(),
        .pcpi_rs1(),
        .pcpi_rs2(),
        .pcpi_wr(1'b0),
        .pcpi_rd(32'b0),
        .pcpi_wait(1'b0),
        .pcpi_ready(1'b0),
        .irq(32'b0),
        .eoi(),
        .trace_valid(),
        .trace_data(),
        .trap()
    );

    wire is_mmio = mem_addr[31:28] == 4'h1;
    wire [31:0] ram_word = ram[mem_addr[$clog2(RAM_WORDS)+1:2]];

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            mem_ready <= 0;
            mem_rdata <= 0;
            result <= 0;
            gate_load_en <= 0;
            gate_load_secs <= 0;
            gate_clear <= 0;
        end else begin
            gate_load_en <= 0;
            gate_clear <= 0;
            mem_ready <= 0;
            if (mem_valid && !mem_ready) begin
                mem_ready <= 1;
                if (!is_mmio) begin
                    mem_rdata <= ram_word;
                    if (mem_wstrb[0]) ram[mem_addr[$clog2(RAM_WORDS)+1:2]][7:0] <= mem_wdata[7:0];
                    if (mem_wstrb[1]) ram[mem_addr[$clog2(RAM_WORDS)+1:2]][15:8] <= mem_wdata[15:8];
                    if (mem_wstrb[2]) ram[mem_addr[$clog2(RAM_WORDS)+1:2]][23:16] <= mem_wdata[23:16];
                    if (mem_wstrb[3]) ram[mem_addr[$clog2(RAM_WORDS)+1:2]][31:24] <= mem_wdata[31:24];
                end else begin
                    // MMIO
                    if (mem_wstrb == 4'b0000) begin
                        case (mem_addr[11:0])
                            12'h000: mem_rdata <= {31'b0, token_ready};
                            12'h004: mem_rdata <= token_len;
                            default: begin
                                if (mem_addr[11:10] == 2'b01)
                                    mem_rdata <= {24'b0, token[mem_addr[9:2]]};
                                else
                                    mem_rdata <= 0;
                            end
                        endcase
                    end else begin
                        case (mem_addr[11:0])
                            12'h008: result <= mem_wdata;
                            12'h00c: begin
                                gate_load_secs <= mem_wdata[16:0];
                                gate_load_en <= 1;
                            end
                            12'h010: gate_clear <= 1;
                            default: ;
                        endcase
                    end
                end
            end
        end
    end

endmodule
`default_nettype wire
