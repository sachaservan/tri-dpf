TARGET = test
CFLAGS = -O3
LDFLAGS = -lcrypto -lssl -lm -mavx2 -maes

$(TARGET): test.o libdpf.a
	gcc $^ -o $@ $(LDFLAGS)

test.o: test.c ../include/utils.h ../include/prf.h ../include/dpf.h ../include/fastdpf.h 
	gcc $(CFLAGS) -c $< -o $@ $(LDFLAGS)

libdpf.a: prf.o dpf.o fastdpf.o 
	ar rcs $@ $^

dpf.o: dpf.c ../include/utils.h ../include/prf.h ../include/dpf.h ../include/fastdpf.h
	gcc $(CFLAGS) -c -o $@ $< $(LDFLAGS)

clean:
	rm -f *.o *.a $(TARGET)