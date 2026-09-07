# The FPGA tier (E9). Probe-or-skip on tool presence everywhere: `sim` needs
# iverilog; `formal`/`formal-mutation` need SymbiYosys + an SMT solver;
# `synth` (M3) needs yosys+nextpnr-ice40. CI runs sim; formal per its
# availability (see bitbucket-pipelines.yml).
IVERILOG ?= iverilog
VVP ?= vvp
SBY ?= sby

.PHONY: sim sim-mutation formal formal-mutation soc-test synth clean

# --- E9-M3: the reference iCE40-UP5K build ----------------------------------
# yosys + nextpnr-ice40 + icepack. The CI-side claim is buildability (a
# bitstream exists and timing closes); flashing a real board is manual-HIL.
synth:
	mkdir -p build/synth
	yosys -q -p "read_verilog synth/lg_gate_top.v rtl/lg_gate.v; synth_ice40 -top lg_gate_top -json build/synth/lg_gate_top.json"
	nextpnr-ice40 --up5k --package sg48 --json build/synth/lg_gate_top.json 	    --pcf synth/lg_gate_top.pcf --asc build/synth/lg_gate_top.asc 	    --freq 12 2> build/synth/nextpnr.log || { tail -20 build/synth/nextpnr.log; exit 1; }
	icepack build/synth/lg_gate_top.asc build/synth/lg_gate_top.bin
	@echo "synth: bitstream at build/synth/lg_gate_top.bin"

# --- E9-M2: the soft-core SoC under verilator -------------------------------
# Needs: verilator, python3, cargo with the riscv32im-unknown-none-elf
# rust-std (rustup hosts / the Ubuntu guest container / CI). The firmware is
# the SAME lychgate-wire verifier everything else compiles; the vectors are
# the SAME committed .kat files. One harness run judges one token; the
# loaded case then watches the gate DROP with the core still alive.
VECTORS = ../wire/vectors
SOC_SRC = rtl/lg_soc.v rtl/lg_gate.v rtl/vendor/picorv32.v

# The build runs FROM fw/ so cargo discovers fw/.cargo/config.toml — the
# -Tlink.x rustflags live there, and .cargo discovery is cwd-based, not
# manifest-based. A --manifest-path build from here silently links with
# lld's default layout and puts the image at 0x10000 while the core resets
# to 0 (observed: the core trapped on zeros).
build/fw.hex:
	cd fw && cargo build --release 	    --target riscv32im-unknown-none-elf --locked
	mkdir -p build
	python3 sim/kat2mem.py elf2hex 	    fw/target/riscv32im-unknown-none-elf/release/lychgate-fpga-fw build/fw.hex

build/soc/Vlg_soc: $(SOC_SRC) sim/soc_harness.cpp
	verilator --cc --exe --build -O2 -Wno-fatal --top-module lg_soc 	    -Mdir build/soc $(SOC_SRC) ../fpga/sim/soc_harness.cpp -o Vlg_soc

soc-test: build/fw.hex build/soc/Vlg_soc
	sh sim/run-soc-vectors.sh

sim:
	mkdir -p build
	$(IVERILOG) -g2005-sv -o build/tb_lg_gate sim/tb_lg_gate.v rtl/lg_gate.v
	$(VVP) build/tb_lg_gate

# The sim-level oracle self-test: the same testbench against the COMMITTED
# broken gate must FAIL. This is what CI runs (Debian ships no sby); the
# formal pair below is the stronger form, run where SymbiYosys exists.
sim-mutation:
	mkdir -p build
	$(IVERILOG) -g2005-sv -o build/tb_broken sim/tb_lg_gate.v rtl/lg_gate_broken.v
	@if $(VVP) build/tb_broken >/dev/null 2>&1; then \
	    echo "sim-mutation: FAILED — the testbench passed a latched-open gate"; exit 1; \
	else \
	    echo "sim-mutation: ok (the testbench caught the latched-open gate)"; \
	fi

# sby wants the RTL named in [files]; the two targets differ only in WHICH
# lg_gate.v they hand it (the real one, or the committed mutation).
formal:
	mkdir -p build/formal
	sed 's|FILE_PLACEHOLDER|lg_gate.v ../../rtl/lg_gate.v|' formal/lg_gate.sby > build/formal/real.sby
	cd build/formal && $(SBY) -f real.sby prove cover
	@echo "formal: proved (safety by induction, drop covered)"

formal-mutation:
	mkdir -p build/formal
	sed 's|FILE_PLACEHOLDER|lg_gate.v ../../rtl/lg_gate_broken.v|' formal/lg_gate.sby > build/formal/broken.sby
	@echo "the proof over the BROKEN gate must FAIL:"
	cd build/formal && if $(SBY) -f broken.sby prove >/dev/null 2>&1; then \
	    echo "formal-mutation: FAILED — the prover accepted a latched-open gate"; exit 1; \
	else \
	    echo "formal-mutation: ok (the prover caught the latched-open gate)"; \
	fi

clean:
	rm -rf build
