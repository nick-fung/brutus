IDIR = ../include
ODIR=obj

CC=gcc
CFLAGS= -g -I$(IDIR) -lm #-O4


_DEPS = feistel.h mersenne.h cache.h
DEPS = $(patsubst %,$(IDIR)/%,$(_DEPS))

_OBJ = overflow.o feistel.o mersenne.o cache.o
OBJ = $(patsubst %,$(ODIR)/%,$(_OBJ))

$(ODIR)/%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

simOverflow: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS) 

clean:
	rm -f $(ODIR)/*.o \
