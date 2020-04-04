.PHONY: all clean test

CPPFLAGS := -std=c++14 -Wall -O3 `pkg-config --cflags botan-2`
LDFLAGS := `pkg-config --libs botan-2`
OBJS := startradersdecryptor.o

all: startradersdecryptor

clean:
	rm -f $(OBJS) startradersdecryptor

test: all
	./startradersdecryptor core ~/.config/startraders2/core.db core_decrypted.db

startradersdecryptor: $(OBJS)
	$(CXX) $(CPPFLAGS) -o $@ $^ $(LDFLAGS)

.cpp.o:
	$(CXX) -c $(CPPFLAGS) -o $@ $<
