ENTRY(_start)
SECTIONS
{
	. = 0x80000000;
	.text : {  *(.except*); *(.pagetable); pagetable_end = .; *(.text*); *(.init*); }
	.elfldr : { elfldr_start = .;*(.elfldr); elfldr_end = .;}
	
	.data : { *(.data*) }
	.sdata : { *(.sdata*) }
	.rodata : { *(.rodata*)}

	.ctors : { __CTOR_LIST__ = .; *(.ctors); __CTOR_END__ = .; }
	.dtors : {__DTOR_LIST__ = .; *(.dtors); __DTOR_END__ = .; }

	.eh_frame_hdr : { *(.eh_frame_hdr) }
	.eh_frame : { KEEP (*(.eh_frame)) }
	.gcc_except_table :  { *(.gcc_except_table .gcc_except_table.*) }

	bss_start = .;
	.bss : { *(.bss*) }
	.sbss : { *(.sbss*) }
	bss_end = .;

	heap_begin = .;
	. = 0x90000000;
	__libc_stack_end = . ;
	heap_end = .;
	. = 0xa0000000;
}
