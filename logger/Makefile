CC=gcc
CFLAGS=

.PHONY: all
all: logger logger.so

logger: main.c
	$(CC) $(CFLAGS) $< -o $@

logger.so: logger.c
	$(CC) -shared -fPIC $< -o $@ -ldl
