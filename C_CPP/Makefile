all: cl.out sv.out

sv.out: server.c
	gcc -o $@ $< -lssl -lcrypto -lpthread

cl.out: client.cpp
	g++ -o $@ $< -lssl -lcrypto


clean:
	rm -f *.out *.o