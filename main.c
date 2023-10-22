#include <stdlib.h>
#include <stdio.h>

#include "tl.h"

static void repl(void)
{
  tl_vm* vm = tl_new_vm();

  for (;;)
  {
    printf("> ");

    int count = 0, cap = 32;
    char* buf = malloc(cap);
    *buf = '\0';

    int c; while ((c = fgetc(stdin)) != '\n')
    {
      if (c == EOF) break;
      if (count + 1 > cap)
      {
        cap *= 2;
        buf = realloc(buf, cap);
      }
      buf[count++] = c;
    }

    if (c == EOF)
    {
      free(buf);
      break;
    }

    tl_do_string(vm, (const char*)buf);
    free(buf);
  }

  tl_free_vm(vm);
}

int main(void)
{
  repl();
}

