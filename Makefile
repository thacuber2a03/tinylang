OUT := tl

CFLAGS := -std=c99 -Isrc

all: $(OUT)

$(OUT): main.c $(wildcard src/*.c)
	gcc -g $(CFLAGS) $^ -o $@


