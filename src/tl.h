#include <stdint.h>

#define TL_DEBUG
#define TL_DISASSEMBLE

typedef enum
{
	TL_RES_OK,
	TL_RES_RUNERR,
	TL_RES_SYNERR,
} tl_result;

typedef enum
{
	TL_TYPE_NUM,
} tl_val_type;

typedef struct tl_val tl_val;
#define tl_is_num(val) ((val).type == TL_TYPE_NUM)
#define tl_to_num(val) ((val).as.number)
#define tl_as_num(num) ((tl_val) { .type = TL_TYPE_NUM, .as.number = num })

typedef struct tl_func tl_func;
typedef struct tl_vm tl_vm;

tl_vm* tl_new_vm();
void tl_free_vm(tl_vm* vm);
tl_result tl_run(tl_vm* vm);
