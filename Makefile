all: encryptor decryptor

init:
	go run genkeys.go
encryptor:
	go build -o bin/ cmd/encryptor/*
decryptor:
	go build -o bin/ cmd/decryptor/*
tester: 
	go build -o bin/ cmd/tester/*
clean:
	rm bin/encryptor bin/decryptor bin/tester
