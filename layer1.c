#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/wait.h>

int is_valid_key(uint32_t key) {
   uint8_t k0 = key&0xff;
   uint8_t k1 = (key>>8)&0xff;
   uint8_t k2 = (key>>16)&0xff;
   uint8_t k3 = (key>>24)&0xff;
   uint16_t k = (k3^k1^k0)<<8 | (k0^k1^k2^k3);

   if(k != 0xae4d) {
	  return 0;
   } else {
	  uint16_t x = (((k1^0x95)<<8) | (k1^k0^0x77))-0x539;

	  if(((x+0x94ec)&0xffff) == 0) {
		 printf("Key=%x A000=%x A002=%x",key,0x8cfa,x^0xbeef);
	  }
   }
}

void range(uint32_t min, uint32_t max, int son) {
   uint32_t i;
   for(i=min;i<=max;i++) {
	  is_valid_key(i);
   }
}

#define CORE 4

int main(int argc, char **argv) {

   if(argc > 1) {
	  uint32_t key;

	  key = strtoul(argv[1],NULL,16);
	  is_valid_key(key);
   } else {
	  int core = 0;
	  uint64_t step = ((1ULL<<32)/CORE)-1;

	  for(core=0;core<CORE;core++) {
		 switch(fork()) {
		 case 0:
			range(core*step,(core+1)*step,core);
			return 0;
			break;
		 }
	  }
	  waitpid(-1,NULL,0);
   }
}
