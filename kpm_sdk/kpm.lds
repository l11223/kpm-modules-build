SECTIONS {
    /DISCARD/ : {
        *(.plt)
        *(.plt.*)
        *(.got)
        *(.got.*)
        *(__mcount_loc)
        *(.note.*)
        *(.comment)
        *(.eh_frame)
        *(.eh_frame_hdr)
    }
}
