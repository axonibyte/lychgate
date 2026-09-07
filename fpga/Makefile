# The FPGA tier (E9). Probe-or-skip on tool presence everywhere: `sim` needs
# iverilog; `formal`/`formal-mutation` need SymbiYosys + an SMT solver;
# `synth` (M3) needs yosys+nextpnr-ice40. CI runs sim; formal per its
# availability (see bitbucket-pipelines.yml).
IVERILOG ?= iverilog
VVP ?= vvp
SBY ?= sby

.PHONY: sim sim-mutation formal formal-mutation clean

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
