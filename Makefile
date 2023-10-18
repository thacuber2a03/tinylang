OUT := tl

CFLAGS := -std=c99 -Isrc -Wall -Wextra -pedantic

all: $(OUT)

$(OUT): main.c $(wildcard src/*.c)
	gcc -g $(CFLAGS) $^ -o $@

clean:
	rm $(OUT)
