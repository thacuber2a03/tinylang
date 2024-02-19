#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdarg.h>
#include <ctype.h>

#include "tl.h"

// TODO(thacuber2a03):
// - string escape sequences
// - "finish tokenizer"
// - "finish parser"
// - more possible values
// - lists, maps, etc. as objects
// - more vm operations (logic operations; and/or)
// - get the object printing functions out of here

///// defs /////

#define unused(x) ((void) x)

typedef enum {
	TL_OP_LOAD, // load a value from constants table
	TL_OP_LOAD_IMM, // load a byte just after the instruction

	TL_OP_TRUE, TL_OP_FALSE, TL_OP_NULL,

	TL_OP_ADD, TL_OP_SUB, TL_OP_MUL, TL_OP_DIV,
	TL_OP_NEG, TL_OP_NOT,

	TL_OP_NEQ, TL_OP_LESS, TL_OP_GREATER, TL_OP_LEQ, TL_OP_GEQ,

	TL_OP_DEF_GLOBAL, TL_OP_GET_GLOBAL,

	TL_OP_POP,
	TL_OP_RETURN, // return from function; at top level, halt
} tl_op;

// TODO(thacuber2a03): bunch of code repetition

typedef struct {
	tl_val* data;
	size_t count, cap;
} tl_list;

typedef struct {
	uint8_t* code;
	tl_list* constants;
	size_t count, cap;
} tl_func;

typedef struct {
	tl_obj_string* key;
	tl_val value;
} tl_map_entry;

typedef struct {
	tl_map_entry* data;
	size_t count, cap;
} tl_map;

#define TL_STACK_MAX 256

struct tl_vm {
	tl_func* code;
	tl_val stack[TL_STACK_MAX];
	tl_val* stack_top;
	tl_map *strings, *globals;
	tl_obj* objects;
	size_t bytes_allocated;
};

///// mem /////

#define tl_grow_cap(cap) ((cap) == 0 ? 8 : (cap) * 2)

void* tl_realloc(tl_vm* vm, void* ptr, size_t old_size, size_t new_size)
{
	size_t diff = new_size - old_size;

	if (new_size == 0)
	{
		vm->bytes_allocated -= diff;
		free(ptr);
#ifdef TL_DEBUG
		if (old_size != 0) printf("tinylang: %lu bytes freed\n", -diff);
#endif
		return NULL;
	}

#ifdef TL_DEBUG
	if (ptr) printf("tinylang: reallocating pointer %p\n", ptr);
#endif

	void* res = realloc(ptr, new_size);
	if (!res)
	{
		// TODO(thacuber2a03): do something better than this
		fprintf(stderr, "tinylang: fatal allocation error");
		exit(EXIT_FAILURE);
	}

	vm->bytes_allocated += diff;
#ifdef TL_DEBUG
	printf("tinylang: %lu bytes allocated\n", diff);
#endif

	return res;
}

#define tl_alloc(vm, size) tl_realloc(vm, NULL, 0, size)
#define tl_free(vm, ptr, old_size) tl_realloc(vm, ptr, old_size, 0)

///// object /////

static bool tl_map_insert(tl_vm* vm, tl_map* map, tl_obj_string* key, tl_val value);
static tl_obj_string* tl_map_find_string(tl_map* map, const char* chars, size_t length, uint32_t hash);

static tl_obj* tl_obj_new(tl_vm* vm, size_t byte_size, tl_obj_type type)
{
	tl_obj* obj = tl_alloc(vm, byte_size);
	obj->type = type;
	obj->next = vm->objects;
	vm->objects = obj;
	return obj;
}

static tl_obj_string* tl_obj_new_str(tl_vm* vm, char* chars, size_t length, uint32_t hash)
{
	tl_obj_string* string = (tl_obj_string*)tl_obj_new(vm, sizeof *string, TL_OBJ_STRING);
	string->chars = chars;
	string->length = length;
	string->hash = hash;
	tl_map_insert(vm, vm->strings, string, tl_val_from_bool(true));
	return string;
}

// FNV-1a
static uint32_t hash_ptr(const void* data, size_t size)
{
#define FNV_PRIME 2166136261
#define FNV_OFFSET 16777619

	uint32_t hash = FNV_PRIME;
	const unsigned char* p = data;
	while (size--) hash = (hash ^ *p++) * FNV_OFFSET;
	return hash;

#undef FNV_PRIME
#undef FNV_OFFSET
}

static tl_obj_string* tl_obj_copy_str(tl_vm* vm, char* chars, size_t length)
{
	uint32_t hash = hash_ptr(chars, length);
	tl_obj_string* interned = tl_map_find_string(vm->strings, chars, length, hash);
	if (interned != NULL) return interned;

	char* heapChars = tl_alloc(vm, length+1);
	memcpy(heapChars, chars, length);
	heapChars[length] = '\0';
	return tl_obj_new_str(vm, heapChars, length, hash);
}

static void tl_obj_print(tl_val obj)
{
	switch (tl_val_to_obj(obj)->type)
	{
		case TL_OBJ_STRING: printf("%s", tl_val_to_cstr(obj)); break;
		default: return; // unreachable
	}
}

static void tl_obj_free(tl_vm* vm, tl_obj* obj)
{
	switch (obj->type)
	{
		case TL_OBJ_STRING:
		{
			tl_obj_string* str = (tl_obj_string*)obj;
			tl_free(vm, str->chars, str->length * sizeof *str->chars);
			tl_free(vm, str, sizeof *str);
			break;
		}
		default: return; // unreachable
	}
}

///// val /////

static void tl_val_print(tl_val value)
{
	switch (value.type)
	{
		case TL_TYPE_NUM: printf("%g", tl_val_to_num(value)); break;
		case TL_TYPE_BOOL: printf(tl_val_to_bool(value) ? "true" : "false"); break;
		case TL_TYPE_NULL: printf("null"); break;
		case TL_TYPE_OBJ: tl_obj_print(value); break;
		default: return; // unreachable
	}
}

static bool tl_val_is_falsy(tl_val value)
{
	if (tl_val_is_bool(value)) return !tl_val_to_bool(value);
	if (tl_val_is_null(value)) return true;
	return false;
}

static bool tl_val_not_equal(tl_val a, tl_val b)
{
	if (tl_val_type(a) != tl_val_type(b)) return true;
	if (tl_val_is_num(a)) return tl_val_to_num(a) != tl_val_to_num(b);
	if (tl_val_is_bool(a)) return tl_val_to_bool(a) != tl_val_to_bool(b);
	if (tl_val_is_str(a)) return tl_val_to_obj(a) != tl_val_to_obj(b);
	return false;
}

///// list /////

static tl_list* tl_list_new(tl_vm* vm)
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
		// TODO(thacuber2a03)!: program crashes when allocating space for a tl_obj_string???
		size_t old_cap = list->cap;
		list->cap = tl_grow_cap(list->cap);
		list->data = tl_realloc(vm, list->data,
			old_cap * sizeof *list->data, list->cap * sizeof *list->data);
	}
	size_t idx = list->count++;
	list->data[idx] = value;
	return idx;
}

/*
static inline tl_val tl_list_pop(tl_list* list)
{
	return list->data[--list->count];
}
*/

static inline tl_val tl_list_get(tl_list* list, size_t idx)
{
	// TODO(thacuber2a03): bounds checking
	return list->data[idx];
}

static void tl_list_free(tl_vm* vm, tl_list* list)
{
	tl_free(vm, list->data, list->cap * sizeof *list->data);
	tl_free(vm, list, sizeof *list);
}

///// map /////

static tl_map* tl_map_new(tl_vm* vm)
{
	tl_map* map = tl_alloc(vm, sizeof *map);
	map->data = NULL;
	// NOTE(thacuber2a03): cap is always a power of 2
	map->count = map->cap = 0;
	return map;
}

static tl_map_entry* tl_map_find_entry(tl_map_entry* entries, size_t cap, tl_obj_string* key)
{
	uint32_t index = key->hash % cap;
	for (;;)
	{
		tl_map_entry* entry = entries + index;
		if (entry->key == key || entry->key == NULL) return entry;

		index = (index + 1) % cap;
	}
}

static void tl_map_adjust_cap(tl_vm* vm, tl_map* map, size_t new_cap)
{
	size_t i;

	tl_map_entry* entries = tl_alloc(vm, new_cap * sizeof *entries);
	for (i = 0; i < new_cap; i++)
	{
		entries[i].key = NULL;
		entries[i].value = tl_val_null;
	}

	for (i = 0; i < map->cap; i++)
	{
		tl_map_entry* entry = map->data + i;
		if (entry->key == NULL) continue;

		tl_map_entry* dest = tl_map_find_entry(entries, new_cap, entry->key);
		dest->key = entry->key;
		dest->value = entry->value;
	}

	tl_free(vm, map->data, map->cap * sizeof *map->data);
	map->data = entries;
	map->cap = new_cap;
}

// TODO(thacuber2a03): tune and benchmark
#define tl_map_load_factor 0.6

static bool tl_map_insert(tl_vm* vm, tl_map* map, tl_obj_string* key, tl_val value)
{
	if (map->count + 1 > map->cap * tl_map_load_factor)
	{
		size_t new_cap = tl_grow_cap(map->cap);
		tl_map_adjust_cap(vm, map, new_cap);
	}

	tl_map_entry* entry = tl_map_find_entry(map->data, map->cap, key);
	bool new_key = entry->key == NULL;
	if (new_key) map->count++;

	entry->key = key;
	entry->value = value;
	return new_key;
}

static bool tl_map_get(tl_map* map, tl_obj_string* key, tl_val* value)
{
	if (map->count == 0) return false;

	tl_map_entry* entry = tl_map_find_entry(map->data, map->cap, key);
	if (entry->key == NULL) return false;

	*value = entry->value;
	return true;
}

static tl_obj_string* tl_map_find_string(tl_map* map, const char* chars, size_t length, uint32_t hash)
{
	if (map->count == 0) return NULL;

	uint32_t index = hash % map->cap;
	for (;;)
	{
		tl_map_entry* entry = map->data + index;
		if (entry->key == NULL) return NULL;

		if (entry->key->length == length &&
		    entry->key->hash == hash &&
		    memcmp(entry->key->chars, chars, length) == 0)
			return entry->key;

		index = (index + 1) % map->cap;
	}
}

static void tl_map_free(tl_vm* vm, tl_map* map)
{
	tl_free(vm, map->data, map->cap * sizeof *map->data);
	tl_free(vm, map, sizeof *map);
}

///// func /////

static tl_func* tl_func_new(tl_vm* vm)
{
	tl_func* func = tl_alloc(vm, sizeof *func);
	func->code = NULL;
	func->constants = tl_list_new(vm);
	func->count = func->cap = 0;
	return func;
}

static void tl_func_write(tl_vm* vm, tl_func* func, uint8_t code)
{
	if (func->count + 1 > func->cap)
	{
		size_t old_cap = func->cap;
		func->cap = tl_grow_cap(func->cap);
		func->code = tl_realloc(vm, func->code,
			old_cap * sizeof *func->code, func->cap * sizeof *func->code);
	}
	func->code[func->count++] = code;
}

static inline size_t tl_func_load_const(tl_vm* vm, tl_func* func, tl_val value)
{
	return tl_list_push(vm, func->constants, value);
}

// disassembler //
#ifdef TL_DISASSEMBLE

static size_t disassemble_simple(const char* name, size_t offset)
{
	printf("%04ld %s\n", offset, name);
	return offset+1;
}

static size_t disassemble_const(tl_func* func, const char* name, size_t offset)
{
	printf("%04ld %-16s index %i (", offset, name, func->code[offset+1]);
	tl_val_print(tl_list_get(func->constants, func->code[offset+1]));
	printf(")\n");
	return offset+2;
}

static size_t disassemble_immediate(tl_func* func, const char* name, size_t offset)
{
	printf("%04ld %-16s %i\n", offset, name, func->code[offset+1]);
	return offset+2;
}

static size_t tl_func_disassemble_instruction(tl_func* func, size_t offset)
{
	switch (func->code[offset])
	{
		case TL_OP_LOAD_IMM: return disassemble_immediate(func, "TL_OP_LOAD_IMM", offset); break;
		case TL_OP_LOAD:     return disassemble_const(func, "TL_OP_LOAD", offset);     break;

		case TL_OP_TRUE:       return disassemble_simple("TL_OP_TRUE",    offset); break;
		case TL_OP_FALSE:      return disassemble_simple("TL_OP_FALSE",   offset); break;
		case TL_OP_NULL:       return disassemble_simple("TL_OP_NULL",    offset); break;
		case TL_OP_ADD:        return disassemble_simple("TL_OP_ADD",     offset); break;
		case TL_OP_SUB:        return disassemble_simple("TL_OP_SUB",     offset); break;
		case TL_OP_MUL:        return disassemble_simple("TL_OP_MUL",     offset); break;
		case TL_OP_DIV:        return disassemble_simple("TL_OP_DIV",     offset); break;
		case TL_OP_NEG:        return disassemble_simple("TL_OP_NEG",     offset); break;
		case TL_OP_NOT:        return disassemble_simple("TL_OP_NOT",     offset); break;

		case TL_OP_NEQ:        return disassemble_simple("TL_OP_NEQ",     offset); break;
		case TL_OP_GEQ:        return disassemble_simple("TL_OP_GEQ",     offset); break;
		case TL_OP_LEQ:        return disassemble_simple("TL_OP_LEQ",     offset); break;
		case TL_OP_GREATER:    return disassemble_simple("TL_OP_GREATER", offset); break;
		case TL_OP_LESS:       return disassemble_simple("TL_OP_LESS",    offset); break;

		case TL_OP_DEF_GLOBAL: return disassemble_const(func, "TL_OP_DEF_GLOBAL", offset); break;
		case TL_OP_GET_GLOBAL: return disassemble_const(func, "TL_OP_GET_GLOBAL", offset); break;

		case TL_OP_POP:        return disassemble_simple("TL_OP_POP",     offset); break;
		case TL_OP_RETURN:     return disassemble_simple("TL_OP_RETURN",  offset); break;

		default: printf("unknown opcode\n"); return offset + 1; break;
	}
}

static void tl_func_disassemble(tl_func* func)
{
	size_t offset = 0;
	while (offset < func->count)
		offset = tl_func_disassemble_instruction(func, offset);
}

#endif // TL_DISASSEMBLE

//////////////////

static void tl_func_free(tl_vm* vm, tl_func* func)
{
	tl_free(vm, func->code, func->cap * sizeof *func->code);
	tl_list_free(vm, func->constants);
	tl_free(vm, func, sizeof *func);
}

///// vm /////

static void tl_vm_reset_stack(tl_vm* vm)
{
	vm->stack_top = vm->stack;
}

tl_vm* tl_vm_new(void)
{
	tl_vm* vm = malloc(sizeof *vm);
	vm->bytes_allocated = 0;
	vm->objects = NULL;
	vm->strings = tl_map_new(vm);
	vm->globals = tl_map_new(vm);
	tl_vm_reset_stack(vm);
	return vm;
}

static size_t tl_vm_load_const(tl_vm* vm, tl_val constant)
{
	for (size_t i = 0; i < vm->code->constants->count; i++)
	{
		if (tl_val_not_equal(tl_list_get(vm->code->constants, i), constant))
			return i;
	}
	return tl_func_load_const(vm, vm->code, constant);
}

static inline void tl_vm_push(tl_vm* vm, tl_val value)
{
	*vm->stack_top = value;
	vm->stack_top++;
}

static inline tl_val tl_vm_pop(tl_vm* vm)
{
	return *--vm->stack_top;
}

static inline tl_val tl_vm_peek(tl_vm* vm, size_t off)
{
	return vm->stack_top[-1-off];
}

static tl_result tl_vm_runtime_error(tl_vm* vm, const char* msg, ...)
{
	unused(vm);

	va_list arg;
	va_start(arg, msg);
	vfprintf(stderr, msg, arg);
	va_end(arg);
	return TL_RES_RUNERR;
}

tl_result tl_vm_run(tl_vm* vm, tl_func* code)
{
#ifdef TL_DISASSEMBLE
	printf("tinylang: code listing:\n");
	tl_func_disassemble(code);
	printf("\n");
#endif

#define arith_op(op, result, action) \
  do {                                                                          \
    if (!tl_val_is_num(tl_vm_peek(vm, 0)) || !tl_val_is_num(tl_vm_peek(vm, 1))) \
      return tl_vm_runtime_error(vm, "can't " action " non-number values\n");   \
    double b = tl_val_to_num(tl_vm_pop(vm));                                    \
    double a = tl_val_to_num(tl_vm_pop(vm));                                    \
    tl_vm_push(vm, tl_val_from_##result(a op b));                               \
  } while(0)


#ifdef TL_DEBUG_RUNTIME
	printf("tinylang: execution listing:\n");
#endif

	uint8_t* ip = code->code;
#define read_byte() (*ip++)
#define read_constant() (tl_list_get(code->constants, read_byte()))
#define read_string() tl_val_to_str(read_constant())

	for (;;)
	{
#ifdef TL_DEBUG_RUNTIME
		tl_func_disassemble_instruction(code, ip - code->code);
#endif

		uint8_t instruction = read_byte();
		switch (instruction)
		{
			case TL_OP_LOAD:     tl_vm_push(vm, read_constant());              break;
			case TL_OP_LOAD_IMM: tl_vm_push(vm, tl_val_from_num(read_byte())); break;
			case TL_OP_TRUE:     tl_vm_push(vm, tl_val_true);                  break;
			case TL_OP_FALSE:    tl_vm_push(vm, tl_val_false);                 break;
			case TL_OP_NULL:     tl_vm_push(vm, tl_val_null);                  break;

			case TL_OP_ADD: arith_op(+, num, "add");      break;
			case TL_OP_SUB: arith_op(-, num, "subtract"); break;
			case TL_OP_MUL: arith_op(*, num, "multiply"); break;
			case TL_OP_DIV: arith_op(/, num, "divide");   break;

			case TL_OP_NEG:
				if (!tl_val_is_num(tl_vm_peek(vm, 0)))
					return tl_vm_runtime_error(vm, "can't negate a non-number");
				tl_val_to_num(vm->stack_top[-1]) *= -1;
				break;

			case TL_OP_NOT:
				vm->stack_top[-1] = tl_val_from_bool(tl_val_is_falsy(vm->stack_top[-1]));
				break;

			case TL_OP_NEQ:
			{
				tl_val a = tl_vm_pop(vm);
				tl_val b = tl_vm_pop(vm);
				tl_vm_push(vm, tl_val_from_bool(tl_val_not_equal(a, b)));
				break;
			}

			case TL_OP_LEQ:     arith_op(<=, bool, "compare"); break;
			case TL_OP_GEQ:     arith_op(>=, bool, "compare"); break;
			case TL_OP_LESS:    arith_op(<,  bool, "compare"); break;
			case TL_OP_GREATER: arith_op(>,  bool, "compare"); break;

			case TL_OP_DEF_GLOBAL:
			{
				tl_obj_string* name = read_string();
				tl_map_insert(vm, vm->globals, name, tl_vm_peek(vm, 0));
				tl_vm_pop(vm);
				break;
			}

			case TL_OP_GET_GLOBAL:
			{
				tl_obj_string* name = read_string();
				tl_val value;
				if (!tl_map_get(vm->globals, name, &value))
				{
					tl_vm_runtime_error(vm, "undefined variable %s", name->chars);
					return TL_RES_RUNERR;
				}
				tl_vm_push(vm, value);
				break;
			}

			case TL_OP_POP: tl_vm_pop(vm); break;

			case TL_OP_RETURN: return TL_RES_OK;
		}

#ifdef TL_DEBUG_RUNTIME
		printf("stack: ");
		for (tl_val* val = vm->stack; val < vm->stack_top; val++)
		{
			printf("| ");
			tl_val_print(*val);
			putchar(' ');
			if (val + 1 == vm->stack_top) putchar('|');
		}
		printf("\n");
#endif
	}

#undef read_string
#undef read_constant
#undef read_byte
#undef arith_op
}

static void tl_vm_free_objs(tl_vm* vm)
{
	tl_obj* obj = vm->objects;
	while (obj)
	{
		tl_obj* next = obj->next;
		tl_obj_free(vm, obj);
		obj = next;
	}
}

void tl_vm_free(tl_vm* vm)
{
	tl_vm_free_objs(vm);
	tl_map_free(vm, vm->strings);
	tl_map_free(vm, vm->globals);
	free(vm);
}

///// tokenizer /////

typedef enum {
	TL_TOK_PLUS, TL_TOK_MINUS, TL_TOK_STAR, TL_TOK_SLASH, TL_TOK_BANG,
	TL_TOK_NEQ, TL_TOK_EQ, TL_TOK_GEQ, TL_TOK_LEQ, TL_TOK_LESS, TL_TOK_GREATER,
	TL_TOK_LPAREN, TL_TOK_RPAREN,

	TL_TOK_DOT, TL_TOK_ASSIGN,  TL_TOK_SEMI,

	TL_TOK_TRUE, TL_TOK_FALSE, TL_TOK_NULL,
	TL_TOK_NUM, TL_TOK_ID, TL_TOK_STR,

	TL_TOK_LET,

	TL_TOK_EOF,
	TL_TOK_ERROR,
} tl_token_type;

typedef struct
{
	tl_token_type type;
	size_t line, length;
	char *start;
} tl_token;

typedef struct
{
	const char* source;
	char *start, *current;
	size_t line;
	bool had_error;
} tl_tokenizer;

static void tl_tokenizer_init(tl_tokenizer* tk, const char* source)
{
	tk->source = source;
	tk->start = tk->current = (char*)source;
	tk->line = 1;
	tk->had_error = false;
}

static tl_token tl_tokenizer_new_token(tl_tokenizer* tk, tl_token_type type)
{
	tl_token tok;
	tok.type = type;
	tok.line = tk->line;
	tok.start = tk->start;
	tok.length = tk->current - tk->start;
	return tok;
}

static tl_token tl_tokenizer_new_error(tl_tokenizer* tk, const char* msg)
{
	tl_token tok;
	tok.type = TL_TOK_ERROR;
	tok.line = tk->line;
	tok.start = (char*) msg;
	tok.length = strlen(msg);
	return tok;
}

#define tl_tokenizer_peek(tk) (*(tk)->current)
#define tl_tokenizer_peekn(tk, n) ((tk)->current[n])
#define tl_tokenizer_at_end(tk) (tl_tokenizer_peek(tk) == '\0')
#define tl_tokenizer_advance(tk) ((tk)->current++)
#define tl_tokenizer_advancec(tk) (*((tk)->current++))

static bool tl_tokenizer_match(tl_tokenizer* tk, char c)
{
	if (tl_tokenizer_peek(tk) != c) return false;
	tl_tokenizer_advance(tk);
	return true;
}

static tl_token tl_tokenizer_scan_num(tl_tokenizer* tk)
{
	while (isdigit(tl_tokenizer_peek(tk))) tl_tokenizer_advance(tk);

	if (tl_tokenizer_peek(tk) == '.' && isdigit(tl_tokenizer_peekn(tk, 1)))
	{
		tl_tokenizer_advance(tk);
		while (isdigit(tl_tokenizer_peek(tk))) tl_tokenizer_advance(tk);
	}

	return tl_tokenizer_new_token(tk, TL_TOK_NUM);
}

static tl_token tl_tokenizer_check_keyword(
	tl_tokenizer* tk, const char* keyword, size_t len, tl_token_type type)
{
	if ((size_t)(tk->current - tk->start) != len)
		return tl_tokenizer_new_token(tk, TL_TOK_ID);

	if (memcmp(tk->start, keyword, len) != 0)
		return tl_tokenizer_new_token(tk, TL_TOK_ID);

	return tl_tokenizer_new_token(tk, type);
}

static tl_token tl_tokenizer_check_word(tl_tokenizer* tk)
{
	if (*tk->start == 't') return tl_tokenizer_check_keyword(tk, "true",  4, TL_TOK_TRUE );
	if (*tk->start == 'f') return tl_tokenizer_check_keyword(tk, "false", 5, TL_TOK_FALSE);
	if (*tk->start == 'n') return tl_tokenizer_check_keyword(tk, "null",  4, TL_TOK_NULL );
	if (*tk->start == 'l') return tl_tokenizer_check_keyword(tk, "let",   3, TL_TOK_LET  );

	return tl_tokenizer_new_token(tk, TL_TOK_ID);
}

static tl_token tl_tokenizer_scan_id(tl_tokenizer* tk)
{
	while (isalpha(tl_tokenizer_peek(tk)) || isdigit(tl_tokenizer_peek(tk)))
		tl_tokenizer_advance(tk);

	return tl_tokenizer_check_word(tk);
}

static tl_token tl_tokenizer_scan_str(tl_tokenizer* tk)
{
	while (tl_tokenizer_peek(tk) != '"' && !tl_tokenizer_at_end(tk))
	{
		if (tl_tokenizer_peek(tk) == '\n') tk->line++;
		tl_tokenizer_advance(tk);
	}

	if (tl_tokenizer_at_end(tk)) return tl_tokenizer_new_error(tk, "unterminated string");

	tl_tokenizer_advance(tk);
	return tl_tokenizer_new_token(tk, TL_TOK_STR);
}

static tl_token tl_tokenizer_next_tok(tl_tokenizer* tk)
{
	tk->start = tk->current;
	if (tl_tokenizer_at_end(tk)) return tl_tokenizer_new_token(tk, TL_TOK_EOF);

	char c = tl_tokenizer_advancec(tk);

	switch (c)
	{
		case '\n':
			tk->line++;
			// fallthrough
		case '\r':
		case '\t':
		case ' ':
			return tl_tokenizer_next_tok(tk);

		case '(': return tl_tokenizer_new_token(tk, TL_TOK_LPAREN);
		case ')': return tl_tokenizer_new_token(tk, TL_TOK_RPAREN);

		case '!': return tl_tokenizer_new_token(tk, tl_tokenizer_match(tk, '=') ? TL_TOK_NEQ : TL_TOK_BANG);
		case '=': return tl_tokenizer_new_token(tk, tl_tokenizer_match(tk, '=') ? TL_TOK_EQ : TL_TOK_ASSIGN);
		case '>': return tl_tokenizer_new_token(tk, tl_tokenizer_match(tk, '=') ? TL_TOK_GEQ : TL_TOK_GREATER);
		case '<': return tl_tokenizer_new_token(tk, tl_tokenizer_match(tk, '=') ? TL_TOK_LEQ : TL_TOK_LESS);
		case '.': return tl_tokenizer_new_token(tk, TL_TOK_DOT);
		case '+': return tl_tokenizer_new_token(tk, TL_TOK_PLUS);
		case '-': return tl_tokenizer_new_token(tk, TL_TOK_MINUS);
		case '*': return tl_tokenizer_new_token(tk, TL_TOK_STAR);

		case '/':
			if (tl_tokenizer_match(tk, '/'))
			{
				// comment
				while (tl_tokenizer_peek(tk) != '\n') tl_tokenizer_advance(tk);
				return tl_tokenizer_next_tok(tk);
			}
			else return tl_tokenizer_new_token(tk, TL_TOK_SLASH);

		case '"': return tl_tokenizer_scan_str(tk);

		case ';': return tl_tokenizer_new_token(tk, TL_TOK_SEMI);

		default:
			if (isdigit(c)) return tl_tokenizer_scan_num(tk);
			if (isalpha(c)) return tl_tokenizer_scan_id(tk);
	}

	return tl_tokenizer_new_error(tk, "unrecognized character");
}

///// parser /////

typedef struct {
	tl_tokenizer* tk;
	tl_func* code;
	tl_token cur_tok, next_tok;
	tl_vm* vm;
	bool panic, error;
} tl_parser;

typedef enum {
	TL_PREC_NONE,
	TL_PREC_EQUALITY,
	TL_PREC_COMPARISON,
	TL_PREC_TERM,
	TL_PREC_FACTOR,
	TL_PREC_UNARY,
} tl_parser_precedence;

typedef void (*tl_parser_parselet)(tl_parser* tp);

typedef struct {
	tl_parser_parselet prefix, infix;
	tl_parser_precedence precedence;
} tl_parser_parse_rule;

static void tl_parser_advance(tl_parser* tp);

static void tl_parser_init(tl_parser* tp, tl_tokenizer* tk, tl_func* code)
{
	tp->tk = tk;
	tp->vm = NULL;
	tp->error = tp->panic = false;
	tp->code = code;
	tl_parser_advance(tp);
}

static void tl_parser_error_raw(tl_parser* tp, tl_token tok, const char* msg, va_list arg)
{
	if (tp->panic) return;

	fprintf(stderr, "error");

	switch (tok.type)
	{
		case TL_TOK_EOF: fprintf(stderr, " at end of"); break;
		default:
			fprintf(stderr, " near \"%.*s\"", (int)tok.length, tok.start);
			// fallthrough
		case TL_TOK_ERROR: fprintf(stderr, " in"); break;
	}

	fprintf(stderr, " line %i: ", (int)tok.line);
	vfprintf(stderr, msg, arg);

	tp->error = tp->panic = true;
}

static inline void tl_parser_error(tl_parser* tp, tl_token tok, const char* msg, ...)
{
	va_list arg;
	va_start(arg, msg);
	tl_parser_error_raw(tp, tok, msg, arg);
	va_end(arg);
}

static void tl_parser_advance(tl_parser* tp)
{
	tp->cur_tok = tp->next_tok;

	for (;;)
	{
		tp->next_tok = tl_tokenizer_next_tok(tp->tk);
		if (tp->next_tok.type != TL_TOK_ERROR) return;

		tl_parser_error(tp, tp->next_tok, tp->next_tok.start);
	}
}

#define tl_parser_check(tp, t) ((tp)->next_tok.type == (t))

static bool tl_parser_match(tl_parser* tp, tl_token_type type)
{
	if (tl_parser_check(tp, type))
	{
		tl_parser_advance(tp);
		return true;
	}
	return false;
}

static void tl_parser_expect(tl_parser* tp, tl_token_type expected, const char* msg, ...)
{
	if (tl_parser_check(tp, expected))
	{
		tl_parser_advance(tp);
		return;
	}

	va_list arg;
	va_start(arg, msg);
	tl_parser_error_raw(tp, tp->next_tok, msg, arg);
	va_end(arg);
}

#define tl_parser_write_byte(tp, b) tl_func_write((tp)->vm, (tp)->code, b)
#define tl_parser_write_bytes(tp, b1, b2) \
	do { \
		tl_parser_write_byte(tp, b1); \
		tl_parser_write_byte(tp, b2); \
	} while (0) \

static size_t tl_parser_load_const(tl_parser* tp, tl_val constant)
{
	size_t idx = tl_vm_load_const(tp->vm, constant);
	tl_parser_write_bytes(tp, TL_OP_LOAD, idx);
	return idx;
}

static uint8_t tl_parser_id_const(tl_parser* tp, tl_token* tok)
{
	return tl_parser_load_const(tp,
		tl_val_from_obj(tl_obj_copy_str(tp->vm, tok->start, tok->length))
	);
}

static uint8_t tl_parser_parse_var(tl_parser* tp, const char* msg)
{
	tl_parser_expect(tp, TL_TOK_ID, msg);
	return tl_parser_id_const(tp, &tp->cur_tok);
}

static void tl_parser_define_var(tl_parser* tp, uint8_t global)
{
	tl_parser_write_bytes(tp, TL_OP_DEF_GLOBAL, global);
}

static void tl_parser_named_variable(tl_parser* tp, tl_token tok)
{
	uint8_t arg = tl_parser_id_const(tp, &tok);
	tl_parser_write_bytes(tp, TL_OP_GET_GLOBAL, arg);
}

static void tl_parser_write_return(tl_parser* tp)
{
	tl_parser_write_byte(tp, TL_OP_RETURN);
}

static void tl_parser_expression(tl_parser* tp);
static void tl_parser_parse_prec(tl_parser* tp, tl_parser_precedence prec);
static tl_parser_parse_rule* tl_parser_get_rule(tl_token_type type);

static void tl_parser_number(tl_parser* tp)
{
	double num = strtod(tp->cur_tok.start, NULL);
	if (num > 0 && num < 256)
		tl_parser_write_bytes(tp, TL_OP_LOAD_IMM, (uint8_t)num);
	else
		tl_parser_load_const(tp, tl_val_from_num(num));
}

static void tl_parser_literal(tl_parser* tp)
{
	switch (tp->cur_tok.type)
	{
		case TL_TOK_TRUE:  tl_parser_write_byte(tp, TL_OP_TRUE); break;
		case TL_TOK_FALSE: tl_parser_write_byte(tp, TL_OP_FALSE); break;
		case TL_TOK_NULL:  tl_parser_write_byte(tp, TL_OP_NULL); break;
		default: return; // unreachable
	}
}

static void tl_parser_string(tl_parser* tp)
{
	tl_token* tok = &tp->cur_tok;
	tl_parser_load_const(tp,
		tl_val_from_obj(tl_obj_copy_str(tp->vm, tok->start+1, tok->length-2))
	);
}

static void tl_parser_variable(tl_parser* tp)
{
	tl_parser_named_variable(tp, tp->cur_tok);
}

static void tl_parser_binary(tl_parser* tp)
{
	tl_token_type type = tp->cur_tok.type;
	tl_parser_precedence prec = tl_parser_get_rule(type)->precedence;
	tl_parser_parse_prec(tp, prec + 1);

	switch (type)
	{
		case TL_TOK_PLUS:    tl_parser_write_byte(tp, TL_OP_ADD);             break;
		case TL_TOK_MINUS:   tl_parser_write_byte(tp, TL_OP_SUB);             break;
		case TL_TOK_STAR:    tl_parser_write_byte(tp, TL_OP_MUL);             break;
		case TL_TOK_SLASH:   tl_parser_write_byte(tp, TL_OP_DIV);             break;
		case TL_TOK_NEQ:     tl_parser_write_byte(tp, TL_OP_NEQ);             break;
		case TL_TOK_EQ:      tl_parser_write_bytes(tp, TL_OP_NEQ, TL_OP_NOT); break;
		case TL_TOK_GEQ:     tl_parser_write_byte(tp, TL_OP_GEQ);             break;
		case TL_TOK_LEQ:     tl_parser_write_byte(tp, TL_OP_LEQ);             break;
		case TL_TOK_LESS:    tl_parser_write_byte(tp, TL_OP_LESS);            break;
		case TL_TOK_GREATER: tl_parser_write_byte(tp, TL_OP_GREATER);         break;
		default: return; // unreachable
	}
}

static void tl_parser_unary(tl_parser* tp)
{
	tl_token_type type = tp->cur_tok.type;
	tl_parser_parse_prec(tp, TL_PREC_UNARY);
	switch (type)
	{
		case TL_TOK_BANG:  tl_parser_write_byte(tp, TL_OP_NOT); break;
		case TL_TOK_MINUS: tl_parser_write_byte(tp, TL_OP_NEG); break;
		default: return; // unreachable
	}
}

static void tl_parser_grouping(tl_parser* tp)
{
	tl_parser_parse_prec(tp, TL_PREC_EQUALITY);
	tl_parser_expect(tp, TL_TOK_RPAREN, "expected ')' after expression");
}

static tl_parser_parse_rule tl_parser_parse_rules[] = {
	[TL_TOK_NUM    ] = { tl_parser_number,   NULL,             TL_PREC_NONE       },
	[TL_TOK_ID     ] = { tl_parser_variable, NULL,             TL_PREC_NONE       },
	[TL_TOK_STR    ] = { tl_parser_string,   NULL,             TL_PREC_NONE       },

	[TL_TOK_PLUS   ] = { NULL,               tl_parser_binary, TL_PREC_TERM       },
	[TL_TOK_MINUS  ] = { tl_parser_unary,    tl_parser_binary, TL_PREC_TERM       },
	[TL_TOK_STAR   ] = { NULL,               tl_parser_binary, TL_PREC_FACTOR     },
	[TL_TOK_SLASH  ] = { NULL,               tl_parser_binary, TL_PREC_FACTOR     },
	[TL_TOK_LPAREN ] = { tl_parser_grouping, NULL,             TL_PREC_FACTOR     },
	[TL_TOK_RPAREN ] = { NULL,               NULL,             TL_PREC_NONE       },

	[TL_TOK_TRUE   ] = { tl_parser_literal,  NULL,             TL_PREC_NONE       },
	[TL_TOK_FALSE  ] = { tl_parser_literal,  NULL,             TL_PREC_NONE       },
	[TL_TOK_NULL   ] = { tl_parser_literal,  NULL,             TL_PREC_NONE       },

	[TL_TOK_BANG   ] = { tl_parser_unary,    NULL,             TL_PREC_UNARY      },
	[TL_TOK_DOT    ] = { NULL,               NULL,             TL_PREC_NONE       },

	[TL_TOK_EQ     ] = { NULL,               tl_parser_binary, TL_PREC_EQUALITY   },
	[TL_TOK_NEQ    ] = { NULL,               tl_parser_binary, TL_PREC_EQUALITY   },
	[TL_TOK_LEQ    ] = { NULL,               tl_parser_binary, TL_PREC_COMPARISON },
	[TL_TOK_GEQ    ] = { NULL,               tl_parser_binary, TL_PREC_COMPARISON },
	[TL_TOK_LESS   ] = { NULL,               tl_parser_binary, TL_PREC_COMPARISON },
	[TL_TOK_GREATER] = { NULL,               tl_parser_binary, TL_PREC_COMPARISON },

	[TL_TOK_EOF    ] = { NULL,               NULL,             TL_PREC_NONE       },
};

static inline tl_parser_parse_rule* tl_parser_get_rule(tl_token_type type)
{
	return &tl_parser_parse_rules[type];
}

static void tl_parser_parse_prec(tl_parser* tp, tl_parser_precedence prec)
{
	// yay, pratt parsing
	tl_parser_advance(tp);
	tl_parser_parselet prefix = tl_parser_get_rule(tp->cur_tok.type)->prefix;
	if (prefix == NULL)
	{
		tl_parser_error(tp, tp->cur_tok, "expected expression");
		return;
	}
	prefix(tp);

	while (prec <= tl_parser_get_rule(tp->next_tok.type)->precedence)
	{
		tl_parser_advance(tp);
		tl_parser_parselet infix = tl_parser_get_rule(tp->cur_tok.type)->infix;
		infix(tp);
	}
}

static void tl_parser_expression(tl_parser* tp)
{
	tl_parser_parse_prec(tp, TL_PREC_EQUALITY);
}

static void tl_parser_var_decl(tl_parser* tp)
{
	uint8_t global = tl_parser_parse_var(tp, "expected identifier after 'let'");

	if (tl_parser_match(tp, TL_TOK_ASSIGN))
		tl_parser_expression(tp);
	else
		tl_parser_write_byte(tp, TL_OP_NULL);

	tl_parser_expect(tp, TL_TOK_SEMI, "expected ';' after var decl\n");
	tl_parser_define_var(tp, global);
}

static void tl_parser_expr_statement(tl_parser* tp)
{
	tl_parser_expression(tp);
	tl_parser_expect(tp, TL_TOK_SEMI, "expected ';' after expression\n");
	tl_parser_write_byte(tp, TL_OP_POP);
}

static void tl_parser_declaration(tl_parser* tp)
{
	if (tl_parser_match(tp, TL_TOK_LET)) tl_parser_var_decl(tp);
	else tl_parser_expr_statement(tp);
}

void tl_parser_parse(tl_parser* tp, tl_vm* vm)
{
	tp->vm = vm;

	while (tp->next_tok.type != TL_TOK_EOF)
		tl_parser_declaration(tp);

	tl_parser_expect(tp, TL_TOK_EOF, "expected end of file");
	tl_parser_write_return(tp);
}

///// frontend /////

static tl_result tl_compile_string(tl_vm* vm, const char* string, tl_func* code)
{
	if (!*string) return false;

	tl_tokenizer tk;
	tl_tokenizer_init(&tk, string);

	tl_parser tp;
	tl_parser_init(&tp, &tk, code);
	tl_parser_parse(&tp, vm);

	return !tp.error ? TL_RES_OK : TL_RES_SYNERR;
}

tl_result tl_do_string(tl_vm* vm, const char* string)
{
	if (!*string) return TL_RES_EMPTY;
	tl_result res;

	tl_func* code = tl_func_new(vm);
	vm->code = code;
	res = tl_compile_string(vm, string, code);

	if (res == TL_RES_OK) res = tl_vm_run(vm, code);

	tl_func_free(vm, code);
	return res;
}

