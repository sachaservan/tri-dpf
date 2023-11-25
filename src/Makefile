TARGET = test
CFLAGS = -O3
LDFLAGS = -lcrypto -lssl -lm

$(TARGET): test.o libdpf.a
	gcc $^ -o $@ $(LDFLAGS)

test.o: test.c ../include/prf.h ../include/dpf.h 
	gcc $(CFLAGS) -c $< -o $@ $(LDFLAGS)

libdpf.a: prf.o dpf.o 
	ar rcs $@ $^

dpf.o: dpf.c ../include/prf.h ../include/dpf.h
	gcc $(CFLAGS) -c -o $@ $< $(LDFLAGS)

clean:
	rm -f *.o *.a $(TARGET)