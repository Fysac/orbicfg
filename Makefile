PROG := orbicfg

all: $(PROG)

$(PROG): main.c uclibc/random_r.c uclibc/random.c
	$(CC) $(CFLAGS) -o $(PROG) $^

clean:
	rm $(PROG)
