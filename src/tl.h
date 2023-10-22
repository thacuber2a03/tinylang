#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

// #define TL_DEBUG
#define TL_DEBUG_RUNTIME
#define TL_DISASSEMBLE

typedef enum
{
	TL_RES_OK,
	TL_RES_RUNERR,
	TL_RES_SYNERR,
	TL_RES_EMPTY, // input code was empty
} tl_result;

typedef enum {
	TL_OBJ_STRING,
} tl_obj_type;

typedef struct tl_obj tl_obj;
typedef struct tl_obj_string tl_obj_string;

typedef enum
{
	TL_TYPE_NULL,
	TL_TYPE_NUM,
	TL_TYPE_BOOL,
	TL_TYPE_OBJ,
} tl_val_type;

struct tl_obj_string {
	tl_obj* obj;
	size_t length;
	char* chars;
};

typedef struct
{
	tl_val_type type;
	union {
		double number;
		bool boolean;
		tl_obj* object;
	} as;
} tl_val;

void tl_val_print(tl_val value);
bool tl_val_is_truthy(tl_val value);

#define tl_val_type(val) ((val).type)

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

#define tl_val_is_obj(val) ((val).type == TL_TYPE_OBJ)
#define tl_val_to_obj(val) ((val).as.object)
#define tl_val_from_obj(obj) ((tl_val) { .type = TL_TYPE_OBJ, .as.object = ((tl_obj*)obj) })

#define tl_obj_to_str(obj) ((tl_obj_string*)obj)
#define tl_obj_to_cstr(obj) (((tl_obj_string*)obj)->chars)

#define tl_val_from_str(vm, chars, len) tl_val_from_obj(tl_obj_from_str(vm, chars, len))

typedef struct tl_vm tl_vm;

tl_vm* tl_new_vm(void);
void tl_free_vm(tl_vm* vm);
void tl_clear_code(tl_vm* vm);
tl_result tl_do_string(tl_vm* vm, const char* string);

