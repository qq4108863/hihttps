SRC=$(wildcard *.c)
LIB=
OBJ=$(addprefix ./, $(addsuffix .o, $(basename $(SRC))))
TARGET=libinjection.a
all: $(TARGET)
$(TARGET): $(SRC)
	$(CC)  -o $@  $^ $(CFLAGS) $(LDFLAGS) $(LIB)
clean:
	rm -f $(TARGET) $(OBJ)

