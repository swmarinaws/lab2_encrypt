# Makefile

# Определение операционной системы
UNAME_S := $(shell uname -s)

# Настройка компилятора и флагов в зависимости от ОС
ifeq ($(UNAME_S),Linux)
    CC = gcc
    TARGET = encryptor
    CFLAGS = `pkg-config --cflags gtk+-2.0` -Wall
    LIBS = `pkg-config --libs gtk+-2.0` -lssl -lcrypto
endif

ifeq ($(findstring MINGW,$(UNAME_S)),MINGW) # Windows (MinGW)
    CC = x86_64-w64-mingw32-gcc
    TARGET = encryptor.exe
    CFLAGS = `pkg-config --cflags gtk+-2.0` -Wall
    LIBS = `pkg-config --libs gtk+-2.0` -lssl -lcrypto
endif

all: $(TARGET)

$(TARGET): main.o
	$(CC) -o $(TARGET) main.o $(LIBS)

main.o: main.c
	$(CC) $(CFLAGS) -c main.c

clean:
	rm -f *.o $(TARGET)

