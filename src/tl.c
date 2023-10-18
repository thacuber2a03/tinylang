#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "tl.h"

///// defs /////

#define unused(x) ((void) x)

typedef enum
{
	TL_OP_RETURN,
	TL_OP_LOAD,
	TL_OP_ADD,
} tl_op;

struct tl_val
{
	tl_val_type type;
	union {
		double number;
	} as;
};

typedef struct {
	tl_val* data;
	size_t count, cap;
} tl_list;

typedef struct {
	uint8_t* code;
	size_t count, cap;
} tl_func;

#define TL_STACK_MAX 256

struct tl_vm {
	tl_list* constants;
	tl_val stack[TL_STACK_MAX];
	tl_val* stack_top;
	tl_func* code;
	size_t bytes_allocated;
};

///// val /////

void tl_val_print(tl_val value)
{
	switch (value.type)
	{
		case TL_TYPE_NUM: printf("%g", tl_to_num(value));
		default: return; // unreachable
	}
}

///// mem /////

#define grow_cap(cap) ((cap) == 0 ? 8 : (cap) * 2)

void* tl_realloc(tl_vm* vm, void* ptr, size_t size)
{
	if (size == 0)
	{
		vm->bytes_allocated -= size;
		free(ptr);
		return NULL;
	}

	void* res = realloc(ptr, size);
	if (!res)
	{
		// TODO(thacuber2a03): do something better than this
		fprintf(stderr, "tinylang: fatal allocation error");
		exit(EXIT_FAILURE);
	}

	vm->bytes_allocated += size;
#ifdef TL_DEBUG
	fprintf(stderr, "tinylang: allocating %lu bytes\n", vm->bytes_allocated);
#endif

	return res;
}

#define tl_alloc(vm, size) tl_realloc(vm, NULL, size)
#define tl_free(vm, ptr) tl_realloc(vm, ptr, 0)

#define tl_grow_cap(cap) ((cap) == 0 ? 8 : (cap) * 2)

///// list /////

static tl_list* tl_new_list(tl_vm* vm)
{
	tl_list* list = tl_alloc(vm, sizeof *list);
	list->data = NULL;
	list->count = list->cap = 0;
	return list;
}

static size_t tl_list_push(tl_vm* vm, tl_list* list, tl_val value)
{
	if (list->count + 1 > list->cap)
	{
		list->cap = tl_grow_cap(list->cap);
		list->data = tl_realloc(vm, list->data, list->cap * sizeof *list->data);
	}
	size_t idx = list->count++;
	list->data[idx] = value;
	return idx;
}

static tl_val tl_list_pop(tl_list* list)
{
	return list->data[--list->count];
}

static tl_val tl_list_get(tl_list* list, size_t idx)
{
	// TODO(thacuber2a03): bounds checking
	return list->data[idx];
}

static void tl_list_free(tl_vm* vm, tl_list* list)
{
	tl_free(vm, list->data);
	tl_free(vm, list);
}

///// func /////

tl_func* tl_new_func(tl_vm* vm)
{
	tl_func* func = tl_alloc(vm, sizeof *func);
	func->code = NULL;
	func->count = func->cap = 0;
	return func;
}

void tl_func_write(tl_vm* vm, tl_func* func, uint8_t code)
{
	if (func->count + 1 > func->cap)
	{
		func->cap = tl_grow_cap(func->cap);
		func->code = tl_realloc(vm, func->code, func->cap);
	}
	func->code[func->count++] = code;
}

static size_t disassemble_simple(const char* name, size_t offset)
{
	printf("%04ld %s\n", offset, name);
	return offset+1;
}

static size_t disasssemble_const(tl_vm* vm, tl_func* func, const char* name, size_t offset)
{
	printf("%04ld %-16s index %i (", offset, name, func->code[offset+1]);
	tl_val_print(tl_list_get(vm->constants, func->code[offset+1]));
	printf(")\n");
	return offset+2;
}

void tl_func_disassemble(tl_vm* vm, tl_func* func)
{
	size_t offset = 0;
	while (offset < func->count)
	{
		switch (func->code[offset])
		{
			case TL_OP_RETURN: offset = disassemble_simple("TL_OP_RETURN", offset); break;
			case TL_OP_ADD: offset = disassemble_simple("TL_OP_ADD", offset); break;
			case TL_OP_LOAD: offset = disasssemble_const(vm, func, "TL_OP_LOAD", offset); break;
			default:
				printf("unknown opcode\n");
				offset++;
				break;
		}
	}
}

void tl_func_free(tl_vm* vm, tl_func* func)
{
	tl_free(vm, func->code);
	func->code = 0;
	func->cap = 0;
}

///// vm /////

tl_vm* tl_new_vm()
{
	tl_vm* vm = malloc(sizeof *vm);
	vm->code = NULL;
	vm->constants = tl_new_list(vm);
	vm->stack_top = vm->stack;
	vm->bytes_allocated = 0;
	return vm;
}

void tl_vm_write(tl_vm* vm, tl_op opcode)
{
	tl_func_write(vm, vm->code, opcode);
}

void tl_vm_load(tl_vm* vm, tl_func* code)
{
	// lol
	vm->code = code;
}

void tl_load_test_program(tl_vm* vm)
{
	vm->code = tl_new_func(vm);

	size_t a = tl_list_push(vm, vm->constants, tl_as_num(42));
	size_t b = tl_list_push(vm, vm->constants, tl_as_num(21));
	tl_func_write(vm, vm->code, TL_OP_LOAD);
	tl_func_write(vm, vm->code, a);
	tl_func_write(vm, vm->code, TL_OP_LOAD);
	tl_func_write(vm, vm->code, b);
	tl_func_write(vm, vm->code, TL_OP_ADD);
	tl_func_write(vm, vm->code, TL_OP_RETURN);
}

void tl_vm_push(tl_vm* vm, tl_val value)
{
	*vm->stack_top = value;
	vm->stack_top++;
}

tl_val tl_vm_pop(tl_vm* vm)
{
	return *--vm->stack_top;
}

tl_result tl_run(tl_vm* vm)
{
#ifdef TL_DISASSEMBLE
	fprintf(stderr, "tinylang: code listing:\n");
	tl_func_disassemble(vm, vm->code);
#endif

#define read_byte() (*ip++)

	uint8_t* ip = vm->code->code;
	for (;;)
	{
		uint8_t instruction = read_byte();
		switch (instruction)
		{
			case TL_OP_LOAD:
				tl_vm_push(vm, tl_list_get(vm->constants, read_byte()));
				break;
			case TL_OP_ADD: {
				tl_val b = tl_vm_pop(vm);
				tl_val a = tl_vm_pop(vm);
				tl_vm_push(vm, tl_as_num(tl_to_num(a) + tl_to_num(b)));
				break;
			}
			case TL_OP_RETURN:
				printf("return val: ");
				tl_val_print(tl_vm_pop(vm));
				printf("\n");
				return TL_RES_OK;
		}
	}

#undef read_byte
}

void tl_free_vm(tl_vm* vm)
{
	tl_func_free(vm, vm->code);
	tl_list_free(vm, vm->constants);
	free(vm);
}
