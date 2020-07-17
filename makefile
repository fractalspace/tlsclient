
TARGET=sslconnect
SRC=$(TARGET).cpp

all:$(SRC)
	@rm -f $(TARGET).exe
	$(CC) $(CFLAGS) $(CPPFLAGS) $(SRC) -o $(TARGET) -lssl -lcrypto
	@echo Built $(TARGET)
	./$(TARGET) google.com 443


