OBJECTS=crypt.o
CFLAGS+=-fPIC

all: BUILD_LIB main.c
	$(CC) $(CFLAGS) -L./ main.c -lwrap_crypt -lcrypto

BUILD_LIB: $(OBJECTS)
	$(LD) -r $(OBJECTS) -o libwrap_crypt.a

%.o: %.c
	$(CC) -c $(CFLAGS) $< -o $@

clean:
	rm -f *.o *.out