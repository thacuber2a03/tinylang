#include <stdlib.h>
#include <stdio.h>

#include "tl.h"

int main(void)
{
  tl_vm* vm = tl_new_vm();

  // I am so unfunny
  tl_compile_string(vm, "1 20 12.3 420.69");

  tl_load_test_program(vm);

  switch (tl_run(vm))
  {
    case TL_RES_OK: printf("a-ok!\n"); break;
    case TL_RES_RUNERR: printf("syntax error\n"); break;
    case TL_RES_SYNERR: printf("runtime error\n"); break;
  }

  tl_free_vm(vm);
  return EXIT_SUCCESS;
}

