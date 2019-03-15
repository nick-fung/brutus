CC=gcc
CFLAGS= -g -I. -lm -O4
DEPS = feistel.h mersenne.h cache.h
OBJ = main.o feistel.o mersenne.o cache.o
OBJ2 = formEviction.o feistel.o mersenne.o cache.o

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

simCollision: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS)

formEviction: $(OBJ2)
	$(CC) -o $@ $^ $(CFLAGS)

clean:
	rm -f $(OBJ2)
	rm -f $(OBJ) \
