CC := afl-clang
CFLAGS := -D_FORTIFY_SOURCE=0
LDFLAGS :=

hello-vulnerable-world: src/hello-vulnerable-world.o
	$(CC) -o bin/hello-vulnerable-world src/hello-vulnerable-world.o $(LDFLAGS)

all: hello-vulnerable-world

.PHONY: clean
clean:
	-rm -rf src/*.o
	-find bin/ -type f -not -name 'EMPTY' -print0 | xargs -0 rm --
