# tinylang
a tiny, bytecode interpreted toy programming language implemented in C99
that fits in (well, actually, that I've shoehorned in) one C file.

## ultra quick overview, go

`tl_vm* vm = tl_new_vm()`, `tl_compile_string(vm, "print(\"hi\")")`, `tl_run(vm)`.
of course, the middle step doesn't work yet, so the most you can do at this point
is to call `tl_load_test_program(vm)`.
