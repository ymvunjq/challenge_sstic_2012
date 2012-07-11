#include <stdio.h>
#include <openssl/rc4.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <string.h>
#include <magic.h>

#define KEY2 "e5df94e3f63d"
#define KEY1 "fd4185ff66a94afd"
#define LEN 32
#define LEN_SECRET 1048592

#define CORE 1

char indata[LEN_SECRET];
uint32_t inlen;

void unencode(char *data, int size) {
   int i;
   for(i=1;i<size;i++) {
	  data[i-1] = data[i-1] ^ data[i];
   }
}

void decrypt_rc4(char *key, char *indata, int size) {
   RC4_KEY rc4_k;
   char outdata[size];

   RC4_set_key(&rc4_k,LEN,key);
   RC4(&rc4_k,size,indata,outdata);

   int i;
   for(i=0;i<size;i++) {
	  printf("%c",outdata[i]);
   }
}

void gen_file(char *key, char *hexkey) {
   RC4_KEY rc4_k;
   char outdata[LEN_SECRET];

   RC4_set_key(&rc4_k,LEN,key);
   RC4(&rc4_k,LEN_SECRET-16,indata+16,outdata);

   char fname[1024] = "rc4/secret_";
   strcat(fname,hexkey);

   FILE *fd = fopen(fname,"w");
   fwrite(outdata,1,LEN_SECRET-16,fd);
   fclose(fd);
}

void check_key(char *key) {
   RC4_KEY rc4_k;
   char outdata[LEN_SECRET];

   RC4_set_key(&rc4_k,LEN,key);
   RC4(&rc4_k,LEN_SECRET-16,indata+16,outdata);

   magic_t cookie;
   cookie = magic_open(MAGIC_NONE);
   magic_load(cookie,NULL);
   char *s = magic_buffer(cookie,outdata,LEN_SECRET);
   if(s == NULL) {
	  printf("ERROR: %s\n",magic_error(cookie));
   } else {
	  printf("%s => %s\n",key,s);
   }
   magic_close(cookie);
}

void range(uint32_t min, uint32_t max) {
   uint32_t i;
   uint8_t j;
   for(i=min;i<=max;i++) {
	  char key[LEN+1];
	  sprintf(key,"%s%s%02x%02x",KEY1,KEY2,(i>>8)&0xff,i&0xff);
	  key[LEN] = '\0';
	  //gen_file(key,hexkey);
	  //printf("%s\n",key);
	  check_key(key);
   }
}

int main(int argc, char **argv) {
   FILE *fd;
   if(argc == 3) {
	  int size;
	  char indata[LEN_SECRET];

	  fd = fopen(argv[2],"r");
	  size = fread(indata,1,LEN_SECRET,fd);
	  fclose(fd);

	  unencode(indata+16,LEN_SECRET-16);

	  decrypt_rc4(argv[1],indata+16,LEN_SECRET-16);
   } else {
	  int core;
	  uint64_t step = (1ULL<<16)/CORE;
	  int size;

	  fd = fopen("secret","r");
	  size = fread(indata,1,LEN_SECRET,fd);
	  fclose(fd);

	  unencode(indata+16,LEN_SECRET);

	  for(core=0;core<CORE;core++) {
		 switch(fork()) {
		 case 0:
			range(core*step,(core+1)*step);
			printf("END OF SON %u\n",core);
			return 0;
			break;
		 }
	  }
	  waitpid(-1,NULL,0);
   }
}
