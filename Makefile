CC=gcc
CFLAGS= -g -I. -lm
DEPS = feistel.h mersenne.h cache.h
OBJ = main.o feistel.o mersenne.o cache.o

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

simCollision: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS)

clean:
	rm -f $(OBJ)
