PROG := orbicfg

all: $(PROG)

$(PROG): main.c
	musl-gcc $(CFLAGS) -o $(PROG) $^

clean:
	rm $(PROG)
