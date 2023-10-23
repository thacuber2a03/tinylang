OUT := tl
FILES := main.c $(wildcard src/*.c)

CFLAGS := -std=c99 -Isrc -Wall -Wextra -pedantic

all: $(OUT)

$(OUT): $(FILES) $(wildcard src/*.h)
	gcc -g $(CFLAGS) $(FILES) -o $@

clean:
	rm $(OUT)
