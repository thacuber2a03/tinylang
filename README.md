# tinylang
a tiny, bytecode based toy programming language implemented in C99
that fits (well, that I've shoehorned in) one C file.

## ultra quick overview

`tl_vm* vm = tl_new_vm()`, `tl_dostring("print(\"hi\")")`, `tl_run(vm)`.
of course, the middle step doesn't work, so the most you can do at this point
is to call `tl_load_test_program(vm)`.