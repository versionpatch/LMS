CC = g++
CFLAGS = -O2 -Wall -Wextra -Wshadow -Wpedantic -Werror
LIBS = -lgmpxx -lgmp


all : lts ots

lts : lms_keygen lms_sign lms_verify sha256
	$(CC) sha256.o lms_keygen.o $(LIBS) -o lms_keygen
	$(CC) sha256.o lms_sign.o $(LIBS) -o lms_sign
	$(CC) sha256.o lms_verify.o $(LIBS) -o lms_verify

ots : ots_keygen ots_sign ots_verify sha256 
	$(CC) sha256.o ots_keygen.o $(LIBS) -o ots_keygen
	$(CC) sha256.o ots_sign.o $(LIBS) -o ots_sign
	$(CC) sha256.o ots_verify.o $(LIBS) -o ots_verify


lms_keygen : lms_keygen.cpp
	$(CC) $(CFLAGS) -c lms_keygen.cpp
lms_sign : lms_sign.cpp
	$(CC) $(CFLAGS) -c lms_sign.cpp
lms_verify : lms_verify.cpp
	$(CC) $(CFLAGS) -c lms_verify.cpp

ots_verify : ots_verify.cpp
	$(CC) $(CFLAGS) -c ots_verify.cpp

ots_sign : ots_sign.cpp
	$(CC) $(CFLAGS) -c ots_sign.cpp

ots_keygen : ots_keygen.cpp
	$(CC) $(CFLAGS) -c ots_keygen.cpp

sha256 : sha256.cpp 
	$(CC) $(CFLAGS) -c sha256.cpp

clean : 
	rm *.o ots_keygen ots_sign ots_verify lms_keygen lms_sign lms_verify
