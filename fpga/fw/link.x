/* The SoC's flat RAM: firmware at 0, stack grows down from the top (the
 * core's STACKADDR parameter). */
MEMORY { RAM : ORIGIN = 0x00000000, LENGTH = 1M }
ENTRY(_start)
SECTIONS {
    .text : { KEEP(*(.text._start)) *(.text*) } > RAM
    .rodata : { *(.rodata*) *(.srodata*) } > RAM
    .data : { *(.data*) *(.sdata*) } > RAM
    .bss : { *(.bss*) *(.sbss*) *(COMMON) } > RAM
    /DISCARD/ : { *(.eh_frame*) }
}
