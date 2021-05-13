GCC = g++
CFLAGS = -std=c++14 -O2

all: decode_test rate_test

decode_test: decode_test.cc
	$(GCC) $(CFLAGS) decode_test.cc -o decode_test

rate_test: rate_test.cc
	$(GCC) $(CFLAGS) rate_test.cc -o rate_test

clean:
	rm -f decode_test rate_test
