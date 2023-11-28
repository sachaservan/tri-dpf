TARGET = test
CFLAGS = -O3
LDFLAGS = -march=native -lcrypto -lssl -lm -maes -ffast-math

$(TARGET): test.o prf.o dpf.o fastdpf.o
	gcc $^ -o $@ $(LDFLAGS)

test.o: test.c ../include/utils.h ../include/prf.h ../include/dpf.h ../include/fastdpf.h 
	gcc $(CFLAGS) -c $< -o $@ $(LDFLAGS)

dpf.o: dpf.c ../include/utils.h ../include/prf.h ../include/dpf.h ../include/fastdpf.h
	gcc $(CFLAGS) -c -o $@ $< $(LDFLAGS)

prf.o: prf.c ../include/utils.h ../include/prf.h 
	gcc $(CFLAGS) -c -o $@ $< $(LDFLAGS)

fastdpf.o: fastdpf.c ../include/utils.h ../include/prf.h ../include/dpf.h ../include/fastdpf.h
	gcc $(CFLAGS) -c -o $@ $< $(LDFLAGS)

clean:
	rm -f *.o *.a $(TARGET)