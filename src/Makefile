SRC=$(wildcard *.c  machine-learning/*.c libinjection/*.c waf/*.c foreign/*.c libev/ev.c libev/event.c )
LIB=-lssl -lcrypto -lm -lrt -lpcre
OBJ=$(addprefix ./, $(addsuffix .o, $(basename $(SRC))))
TARGET=aihttps
all: $(TARGET)
$(TARGET): $(SRC)
	$(CC)  -w -o $@  $^ $(CFLAGS) $(LDFLAGS) $(LIB)
clean:
	rm -f $(TARGET) $(OBJ)
	

