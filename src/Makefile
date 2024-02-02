TARGET = test
CFLAGS = -O3
LDFLAGS = -march=native -lcrypto -lssl -lm -maes -ffast-math

$(TARGET): test.c prf.c dpf.c fastdpf.c extensions.c

clean:
	rm -f *.o *.a $(TARGET)