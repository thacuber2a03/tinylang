OUT := tl

CFLAGS := -std=c99 -Isrc -Wall -Wextra -pedantic -Wno-unused-function

all: $(OUT)

$(OUT): main.c $(wildcard src/*.c)
	gcc -g $(CFLAGS) $^ -o $@

clean:
	rm $(OUT)
