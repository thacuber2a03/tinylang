#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdarg.h>
#include <ctype.h>

#include "tl.h"

// TODO(thacuber2a03):
// - finish tokenizer
// - finish parser
// - more possible values
// - objects; strings, lists, maps, etc.
// - more vm operations
// - etc. you know the drill

///// defs /////

#define unused(x) ((void) x)

typedef enum {
	TL_OP_LOAD, // load a value from constants table
	TL_OP_TRUE,
	TL_OP_FALSE,
	TL_OP_NULL,

	TL_OP_ADD,
	TL_OP_SUB,
	TL_OP_MUL,
	TL_OP_DIV,
	TL_OP_NEG,
	TL_OP_NOT,

	TL_OP_RETURN, // return from function; at top level, halt
} tl_op;

struct tl_val
{
	tl_val_type type;
	union {
		double number;
		bool boolean;
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
	tl_result res;
	size_t bytes_allocated;
};

///// val /////

void tl_val_print(tl_val value)
{
	switch (value.type)
	{
		case TL_TYPE_NUM: printf("%g", tl_val_to_num(value)); break;
		case TL_TYPE_BOOL: printf(tl_val_to_bool(value) ? "true" : "false"); break;
		case TL_TYPE_NULL: printf("null"); break;
		default: return; // unreachable
	}
}

bool tl_val_is_falsy(tl_val value)
{
	if (tl_val_is_bool(value)) return !tl_val_to_bool(value);
	if (tl_val_is_null(value)) return true;
	return false;
}

///// mem /////

#define tl_grow_cap(cap) ((cap) == 0 ? 8 : (cap) * 2)
#define tl_grow_list(vm, list) tl_realloc(vm, list->data, list->cap * sizeof *list->data)

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
		list->data = tl_grow_list(vm, list);
	}
	size_t idx = list->count++;
	list->data[idx] = value;
	return idx;
}

static inline tl_val tl_list_pop(tl_list* list)
{
	return list->data[--list->count];
}

static inline tl_val tl_list_get(tl_list* list, size_t idx)
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

static tl_func* tl_new_func(tl_vm* vm)
{
	tl_func* func = tl_alloc(vm, sizeof *func);
	func->code = NULL;
	func->count = func->cap = 0;
	return func;
}

static void tl_func_write(tl_vm* vm, tl_func* func, uint8_t code)
{
	if (func->count + 1 > func->cap)
	{
		func->cap = tl_grow_cap(func->cap);
		func->code = tl_realloc(vm, func->code, func->cap);
	}
	func->code[func->count++] = code;
}

// disassembler //

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

static size_t tl_func_disassemble_instruction(tl_vm* vm, tl_func* func, size_t offset)
{
	switch (func->code[offset])
	{
		case TL_OP_LOAD:  return disasssemble_const(vm, func, "TL_OP_LOAD", offset); break;
		case TL_OP_TRUE:  return disassemble_simple("TL_OP_TRUE", offset); break;
		case TL_OP_FALSE: return disassemble_simple("TL_OP_FALSE", offset); break;
		case TL_OP_NULL:  return disassemble_simple("TL_OP_NULL", offset); break;

		case TL_OP_ADD: return disassemble_simple("TL_OP_ADD", offset); break;
		case TL_OP_SUB: return disassemble_simple("TL_OP_SUB", offset); break;
		case TL_OP_MUL: return disassemble_simple("TL_OP_MUL", offset); break;
		case TL_OP_DIV: return disassemble_simple("TL_OP_DIV", offset); break;
		case TL_OP_NEG: return disassemble_simple("TL_OP_NEG", offset); break;
		case TL_OP_NOT: return disassemble_simple("TL_OP_NOT", offset); break;

		case TL_OP_RETURN: return disassemble_simple("TL_OP_RETURN", offset); break;

		default: printf("unknown opcode\n"); return offset + 1; break;
	}
}

static void tl_func_disassemble(tl_vm* vm, tl_func* func)
{
	size_t offset = 0;
	while (offset < func->count)
	{
		offset = tl_func_disassemble_instruction(vm, func, offset);
	}
}

//////////////////

static void tl_func_free(tl_vm* vm, tl_func* func)
{
	tl_free(vm, func->code);
	func->code = 0;
	func->cap = 0;
}

///// vm /////

tl_vm* tl_new_vm(void)
{
	tl_vm* vm = malloc(sizeof *vm);
	vm->bytes_allocated = 0;
	vm->stack_top = vm->stack;
	vm->res = TL_RES_OK;
	vm->code = tl_new_func(vm);
	vm->constants = tl_new_list(vm);
	return vm;
}

static inline void tl_vm_write(tl_vm* vm, tl_op opcode)
{
	tl_func_write(vm, vm->code, opcode);
}

static size_t tl_vm_load_const(tl_vm* vm, tl_val constant)
{
	return tl_list_push(vm, vm->constants, constant);
}

// these might be useful later
/*
void tl_load_test_program(tl_vm* vm)
{
	vm->code = tl_new_func(vm);

	size_t a = tl_vm_load_const(vm, tl_val_from_num(42)  );
	size_t b = tl_vm_load_const(vm, tl_val_from_num(21)  );
	size_t c = tl_vm_load_const(vm, tl_val_from_num(10.5));

	tl_vm_write(vm, TL_OP_LOAD); tl_vm_write(vm, a);
	tl_vm_write(vm, TL_OP_LOAD); tl_vm_write(vm, b);
	tl_vm_write(vm, TL_OP_ADD);

	tl_vm_write(vm, TL_OP_LOAD); tl_vm_write(vm, c);
	tl_vm_write(vm, TL_OP_SUB);
	tl_vm_write(vm, TL_OP_NEG);

	tl_vm_write(vm, TL_OP_LOAD); tl_vm_write(vm, c);
	tl_vm_write(vm, TL_OP_MUL);

	tl_vm_write(vm, TL_OP_LOAD); tl_vm_write(vm, b);
	tl_vm_write(vm, TL_OP_DIV);

	tl_vm_write(vm, TL_OP_RETURN);
}

void tl_load_error_test_program(tl_vm* vm)
{
	vm->code = tl_new_func(vm);

	size_t num = tl_list_push(vm, vm->constants, tl_val_from_num(42));

	tl_vm_write(vm, TL_OP_LOAD); tl_vm_write(vm, num);
	tl_vm_write(vm, TL_OP_TRUE);
	tl_vm_write(vm, TL_OP_ADD);
	tl_vm_write(vm, TL_OP_RETURN);
}
*/

static void tl_vm_push(tl_vm* vm, tl_val value)
{
	*vm->stack_top = value;
	vm->stack_top++;
}

static tl_val tl_vm_pop(tl_vm* vm)
{
	return *--vm->stack_top;
}

static tl_val tl_vm_peek(tl_vm* vm, size_t off)
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

tl_result tl_run(tl_vm* vm)
{
	if (vm->res != TL_RES_OK) return vm->res;

#ifdef TL_DISASSEMBLE
	fprintf(stderr, "tinylang: code listing:\n");
	tl_func_disassemble(vm, vm->code);
#endif

#define arith_op(op, action) \
  do {                                    \
    if (!tl_val_is_num(tl_vm_peek(vm, 0)) || !tl_val_is_num(tl_vm_peek(vm, 1))) \
      return tl_vm_runtime_error(vm, "can't " #action " non-number values\n"); \
    double b = tl_val_to_num(tl_vm_pop(vm)); \
    double a = tl_val_to_num(tl_vm_pop(vm)); \
    tl_vm_push(vm, tl_val_from_num(a op b));  \
  } while(0)

	uint8_t* ip = vm->code->code;
#define read_byte() (*ip++)
#define read_constant() (tl_list_get(vm->constants, read_byte()))
	for (;;)
	{
#ifdef TL_DEBUG_RUNTIME
		printf("current instruction: ");
		tl_func_disassemble_instruction(vm, vm->code, ip - vm->code->code);
#endif

		uint8_t instruction = read_byte();
		switch (instruction)
		{
			case TL_OP_LOAD: tl_vm_push(vm, read_constant()); break;
			case TL_OP_TRUE: tl_vm_push(vm, tl_val_true); break;
			case TL_OP_FALSE: tl_vm_push(vm, tl_val_false); break;
			case TL_OP_NULL: tl_vm_push(vm, tl_val_null); break;

			case TL_OP_ADD: arith_op(+); break;
			case TL_OP_SUB: arith_op(-); break;
			case TL_OP_MUL: arith_op(*); break;
			case TL_OP_DIV: arith_op(/); break;
			case TL_OP_NEG:
				if (!tl_val_is_num(tl_vm_peek(vm, 0)))
					return tl_vm_runtime_error(vm, "can't negate a non-number");
				tl_val_to_num(vm->stack_top[-1]) *= -1;
				break;
			case TL_OP_NOT:
				vm->stack_top[-1] = tl_val_from_bool(tl_val_is_falsy(vm->stack_top[-1]));
				break;

			case TL_OP_RETURN:
				// TODO(thacuber2a03): change this, of course
				printf("return val: ");
				tl_val_print(tl_vm_pop(vm));
				printf("\n");
				return TL_RES_OK;
		}

#ifdef TL_DEBUG_RUNTIME
		printf("stack: ");
		for (tl_val* val = vm->stack; val < vm->stack_top; val++)
		{
			tl_val_print(*val);
			if (val + 1 != vm->stack_top)
				printf("|");
		}
		printf("\n");
#endif
	}

#undef read_constant
#undef read_byte
#undef arith_op
}

void tl_clear_code(tl_vm* vm)
{
	tl_func_free(vm, vm->code);
	vm->code = tl_new_func(vm);
}

void tl_free_vm(tl_vm* vm)
{
	tl_func_free(vm, vm->code);
	tl_list_free(vm, vm->constants);
	free(vm);
}

///// tokenizer /////

typedef enum {
	TL_TOK_PLUS, TL_TOK_MINUS, TL_TOK_STAR, TL_TOK_SLASH, TL_TOK_BANG,
	TL_TOK_NEQ, TL_TOK_EQ, TL_TOK_GEQ, TL_TOK_LEQ, TL_TOK_LESS, TL_TOK_GREATER,
	TL_TOK_DOT, TL_TOK_ASSIGN,

	TL_TOK_TRUE, TL_TOK_FALSE, TL_TOK_NULL,
	TL_TOK_NUM, TL_TOK_ID,

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

/*
static tl_token tl_token_none = {
	.type = TL_TOK_ERROR,
	.line = -1,
	.start = "no token to peek",
	.length = sizeof "no token to peek"
};
*/

#define tl_tokenizer_peek(tk) (*(tk)->current)
#define tl_tokenizer_peekn(tk, n) ((tk)->current[n])
#define tl_tokenizer_at_end(tk) (tl_tokenizer_peek(tk) == '\0')
#define tl_tokenizer_advance(tk) ((tk)->current++)
#define tl_tokenizer_advancec(tk) (*(tk)->current++)

#define tl_tokenizer_is_digit(c) ((c) >= '0' && (c) <= '9')

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
	if (*tk->start == 't') return tl_tokenizer_check_keyword(tk, "true",  4, TL_TOK_TRUE);
	if (*tk->start == 'f') return tl_tokenizer_check_keyword(tk, "false", 5, TL_TOK_FALSE);
	if (*tk->start == 'n') return tl_tokenizer_check_keyword(tk, "null",  4, TL_TOK_NULL);

	return tl_tokenizer_new_token(tk, TL_TOK_ID);
}

static tl_token tl_tokenizer_scan_id(tl_tokenizer* tk)
{
	while (isalpha(tl_tokenizer_peek(tk)) || isdigit(tl_tokenizer_peek(tk)))
		tl_tokenizer_advance(tk);

	return tl_tokenizer_check_word(tk);
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

		default:
			if (isdigit(c)) return tl_tokenizer_scan_num(tk);
			if (isalpha(c)) return tl_tokenizer_scan_id(tk);
	}

	return tl_tokenizer_new_error(tk, "unrecognized character");
}

///// parser /////

typedef struct {
	tl_tokenizer* tk;
	tl_token cur_tok, next_tok;
	tl_vm* vm;
	bool panic, error;
} tl_parser;

typedef enum {
	TL_PREC_NONE,
	TL_PREC_TERM,
	TL_PREC_FACTOR,
	TL_PREC_UNARY,
} tl_parser_precedence;

typedef void (*tl_parser_parselet)(tl_parser* tp);

typedef struct {
	tl_parser_parselet prefix, infix;
	tl_parser_precedence precedence;
} tl_parser_parse_rule;

static tl_token tl_parser_next(tl_parser* tp);

static void tl_parser_init(tl_parser* tp, tl_tokenizer* tk)
{
	tp->tk = tk;
	tp->vm = NULL;
	tp->error = tp->panic = false;
	tl_parser_next(tp);
}

static tl_token tl_parser_next(tl_parser* tp)
{
	tp->cur_tok = tp->next_tok;
	tp->next_tok = tl_tokenizer_next_tok(tp->tk);
	return tp->next_tok;
}

static void tl_parser_error(tl_parser* tp, tl_token tok, const char* msg)
{
	fprintf(stderr,
		"[line %i] error near '%.*s': %s\n",
		(int)tok.line, (int)tok.length, tok.start, msg
	);

	tp->error = tp->panic = true;
}

#define tl_parser_write_byte(tp, b) tl_vm_write((tp)->vm, (b))
#define tl_parser_write_bytes(tp, b1, b2) \
	do { \
		tl_parser_write_byte(tp, b1); \
		tl_parser_write_byte(tp, b2); \
	} while (0) \

static void tl_parser_load_const(tl_parser* tp, tl_val constant)
{
	size_t idx = tl_vm_load_const(tp->vm, constant);
	tl_parser_write_bytes(tp, TL_OP_LOAD, idx);
}

static void tl_parser_expression(tl_parser* tp);
static void tl_parser_parse_prec(tl_parser* tp, tl_parser_precedence prec);
static tl_parser_parse_rule* tl_parser_get_rule(tl_token_type type);

static void tl_parser_number(tl_parser* tp)
{
	double num = strtod(tp->cur_tok.start, NULL);
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

static void tl_parser_binary(tl_parser* tp)
{
	tl_token_type type = tp->cur_tok.type;
	tl_parser_precedence prec = tl_parser_get_rule(type)->precedence;
	tl_parser_parse_prec(tp, prec + 1);

	switch (type)
	{
		case TL_TOK_PLUS:  tl_parser_write_byte(tp, TL_OP_ADD); break;
		case TL_TOK_MINUS: tl_parser_write_byte(tp, TL_OP_SUB); break;
		case TL_TOK_STAR:  tl_parser_write_byte(tp, TL_OP_MUL); break;
		case TL_TOK_SLASH: tl_parser_write_byte(tp, TL_OP_DIV); break;
		default: return; // unreachable
	}
}

static void tl_parser_unary(tl_parser* tp)
{
	tl_token_type type = tp->cur_tok.type;
	tl_parser_parse_prec(tp, TL_PREC_UNARY);
	switch (type)
	{
		case TL_TOK_BANG: tl_parser_write_byte(tp, TL_OP_NOT); break;
		case TL_TOK_MINUS: tl_parser_write_byte(tp, TL_OP_NEG); break;
		default: return; // unreachable
	}
}

static tl_parser_parse_rule tl_parser_parse_rules[] = {
	[TL_TOK_NUM  ] = { tl_parser_number,  NULL,             TL_PREC_NONE   },
	[TL_TOK_BANG ] = { tl_parser_unary,   NULL,             TL_PREC_UNARY  },
	[TL_TOK_DOT ]  = { NULL,              NULL,             TL_PREC_NONE   },
	[TL_TOK_PLUS ] = { NULL,              tl_parser_binary, TL_PREC_TERM   },
	[TL_TOK_MINUS] = { tl_parser_unary,   tl_parser_binary, TL_PREC_TERM   },
	[TL_TOK_STAR ] = { NULL,              tl_parser_binary, TL_PREC_FACTOR },
	[TL_TOK_SLASH] = { NULL,              tl_parser_binary, TL_PREC_FACTOR },
	[TL_TOK_TRUE ] = { tl_parser_literal, NULL,             TL_PREC_NONE   },
	[TL_TOK_FALSE] = { tl_parser_literal, NULL,             TL_PREC_NONE   },
	[TL_TOK_NULL ] = { tl_parser_literal, NULL,             TL_PREC_NONE   },
	[TL_TOK_EOF  ] = { NULL,              NULL,             TL_PREC_NONE   },
};

static inline tl_parser_parse_rule* tl_parser_get_rule(tl_token_type type)
{
	return &tl_parser_parse_rules[type];
}

static void tl_parser_parse_prec(tl_parser* tp, tl_parser_precedence prec)
{
	// yay, pratt parsing
	tl_parser_next(tp);
	tl_parser_parselet prefix = tl_parser_get_rule(tp->cur_tok.type)->prefix;
	if (prefix == NULL)
	{
		tl_parser_error(tp, tp->cur_tok, "expected expression");
		return;
	}
	prefix(tp);

	while (prec <= tl_parser_get_rule(tp->next_tok.type)->precedence)
	{
		tl_parser_next(tp);
		tl_parser_parselet infix = tl_parser_get_rule(tp->cur_tok.type)->infix;
		infix(tp);
	}
}

static void tl_parser_expression(tl_parser* tp)
{
	tl_parser_parse_prec(tp, TL_PREC_TERM);
}

void tl_parser_parse(tl_parser* tp, tl_vm* vm)
{
	tp->vm = vm;
	tl_parser_expression(tp);
	tl_parser_write_byte(tp, TL_OP_RETURN);
}

///// frontend /////

bool tl_compile_string(tl_vm* vm, const char* string)
{
	tl_tokenizer tk;
	tl_tokenizer_init(&tk, string);
	tl_parser tp;
	tl_parser_init(&tp, &tk);
	tl_parser_parse(&tp, vm);
	return !tp.error;
}

