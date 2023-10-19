#include <stdint.h>

//#define TL_DEBUG
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
	TL_TYPE_BOOL,
} tl_val_type;

typedef struct tl_val tl_val;

#define tl_val_is_num(val) ((val).type == TL_TYPE_NUM)
#define tl_val_to_num(val) ((val).as.number)
#define tl_val_from_num(num) ((tl_val) { .type = TL_TYPE_NUM, .as.number = num })

#define tl_val_is_bool(val) ((val).type == TL_TYPE_BOOL)
#define tl_val_to_bool(val) ((val).as.boolean)
#define tl_val_from_bool(bool) ((tl_val) { .type = TL_TYPE_BOOL, .as.boolean = bool })

typedef struct tl_vm tl_vm;
tl_vm* tl_new_vm(void);
void tl_free_vm(tl_vm* vm);
void tl_load_test_program(tl_vm* vm);
void tl_load_error_test_program(tl_vm* vm);
tl_result tl_run(tl_vm* vm);
void tl_compile_string(tl_vm* vm, const char* string);

