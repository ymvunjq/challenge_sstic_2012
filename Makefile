CC=gcc
EXEC=layer1 layer2 layer3 rc4_decrypt

all: $(EXEC)

layer1: layer1.c
	$(CC) -o $@ $<

layer2: layer2.c
	$(CC) -o $@ $<

layer3: layer3.c
	$(CC) -o $@ $<

rc4_decrypt: rc4_decrypt.c
	$(CC) -o $@ $< -lssl -lmagic

clean:
	rm -f $(EXEC)
	rm -f *.pyc
	rm -f history.txt
