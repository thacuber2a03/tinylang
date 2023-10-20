# tinylang
an embeddable, small and fast toy programming language implemented in C99
that fits in (well, actually, that I've shoehorned in) a pair of .h/.c files.

*NOTE*: I am doing this whole thing on the spot.
I can always add whatever comes into my mind I deem useful;
the language is in really early development anyways.

### features

- small but expressive bytecode; compiles in a single pass

## ultra quick overview, go

`tl_vm* vm = tl_new_vm()`, `tl_compile_string(vm, "1 + 2 == 3")`, `tl_run(vm)`. yeah, right now it's, uhh, an expression evaluator