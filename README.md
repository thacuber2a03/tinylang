# tinylang
an embeddable, small and fast toy programming language implemented in C99
that fits in (well, actually, that I've shoehorned in) a pair of .h/.c files.

*NOTE*: I am doing this whole thing on the spot.
I can always add whatever comes into my mind I deem useful;
the language is in really early development anyways.

### features

- small but expressive bytecode; compiles in a single pass

## ultra quick overview, go

`tl_vm* vm = tl_new_vm()`, `tl_compile_string(vm, "print(\"hi\")")`, `tl_run(vm)`.
of course, the middle step doesn't work yet, so the most you can do at this point
is to call `tl_load_test_program(vm)`.
