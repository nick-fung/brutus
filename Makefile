CC=gcc
CFLAGS= -g -I. -lm #-O4
DEPS = feistel.h mersenne.h cache.h
OBJ = part1.o feistel.o mersenne.o cache.o
OBJ2 = part2.o feistel.o mersenne.o cache.o

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

simPart1: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS) 
	rm -f $(OBJ)

simPart2: $(OBJ2)
	$(CC) -o $@ $^ $(CFLAGS) 
	rm -f $(OBJ2) 

clean:
	rm -f $(OBJ2)
	rm -f $(OBJ) \
