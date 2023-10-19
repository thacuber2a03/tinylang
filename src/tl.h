#include <stdbool.h>
#include <stdint.h>

//#define TL_DEBUG
#define TL_DEBUG_RUNTIME
#define TL_DISASSEMBLE

typedef enum
{
	TL_RES_OK,
	TL_RES_RUNERR,
	TL_RES_SYNERR,
} tl_result;

typedef enum
{
	TL_TYPE_NULL,
	TL_TYPE_NUM,
	TL_TYPE_BOOL,
} tl_val_type;

typedef struct tl_val tl_val;
void tl_val_print(tl_val value);
bool tl_val_is_falsy(tl_val value);

#define tl_val_is_num(val) ((val).type == TL_TYPE_NUM)
#define tl_val_to_num(val) ((val).as.number)
#define tl_val_from_num(num) ((tl_val) { .type = TL_TYPE_NUM, .as.number = num })

#define tl_val_true (tl_val_from_bool(1))
#define tl_val_false (tl_val_from_bool(0))
#define tl_val_is_bool(val) ((val).type == TL_TYPE_BOOL)
#define tl_val_to_bool(val) ((val).as.boolean)
#define tl_val_from_bool(bool) ((tl_val) { .type = TL_TYPE_BOOL, .as.boolean = bool })

#define tl_val_null ((tl_val) { .type = TL_TYPE_NULL })
#define tl_val_is_null(val) ((val).type == TL_TYPE_NULL)

typedef struct tl_vm tl_vm;
tl_vm* tl_new_vm(void);
void tl_free_vm(tl_vm* vm);
tl_result tl_run(tl_vm* vm);
void tl_clear_code(tl_vm* vm);
bool tl_compile_string(tl_vm* vm, const char* string);

