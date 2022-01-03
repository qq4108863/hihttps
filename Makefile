TARGET=aihttps

all:
	cd src; make
	/bin/cp -rf ./src/$(TARGET) ./


clean:
	rm -f $(TARGET)
	cd src; make clean
	
