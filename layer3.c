#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>

#define NOT(x) (~(x)&0xffff)
#define ROL(x,y) ((((x)<<(y)) | ((x)>>(16-(y))))&0xffff)
#define ROR(x,y) ((((x)>>(y)) | ((x)<<(16-(y))))&0xffff)
#define SIZE_BLAH 33
#define BLAH "./blah.bin"
#define SOLUTION "V29vdCAhISBTbWVsbHMgZ29vZCA6KQ=="

#define KEY_PART1 0xf63d

uint8_t blah_orig[SIZE_BLAH];

uint16_t o(uint16_t addr, uint16_t reg, uint16_t obf, uint16_t val) {
   uint16_t r5 = ((((obf<<6) + obf)<<4)+obf)&0xffff;
   r5 ^= 0x464d;
   uint16_t r2 = addr ^ 0x6c38;
   uint16_t r1 = reg + 2;
   uint16_t r6 = 0;
   uint16_t r8 = 0;
   uint16_t r7;

   for(;;) {
	  r7 = r6;
	  r5 = ROL(r5,1);
	  r2 = ROR(r2,2);
	  r2 += r5;
	  r2 &= 0xffff;
	  r5 += 2;
	  r5 &= 0xffff;
	  r6 = r2 ^ r5;
	  r8 = (r6>>8) & 0xff;
	  r6 &= 0xff;
	  r6 ^= r8;
	  r1 -= 1;
	  if(r1 == 0) break;
   }
   r6 <<= 8;
   r6 &= 0xffff;
   r6 |= r7;
   r2 = val;
   r2 ^= r6;
   return r2;
}

int is_valid_key(uint16_t key) {
   uint8_t i;
   uint8_t x = (KEY_PART1&0xff)^(key&0xff);
   uint8_t y = (KEY_PART1>>8)^(key>>8);
   uint16_t k = (y<<8) + x + y;

   uint16_t blah[SIZE_BLAH];
   memcpy(blah,blah_orig,SIZE_BLAH);

   for(i=0;i<32;i+=2) {
	  // o = fonction de chiffrement
	  uint16_t v = o(0xa00c,i+4,0x33,*((uint16_t*)blah+(i/2)));
	  ((uint16_t*)blah)[i/2] = v ^ k;
   }
   if(!strncmp((const char *)blah,SOLUTION,32))
	  return 1;
   return 0;
}

void range(uint32_t min, uint32_t max, int son) {
   uint32_t i;
   for(i=min;i<=max;i++) {
	  if(is_valid_key(i)) {
		 printf("KEY = %x\n",i);
		 exit(0);
	  }
   }
}

#define CORE 4

int main(int argc, char **argv) {
   FILE *fd;
   fd = fopen(BLAH,"r");
   if(fd == NULL) {
	  fprintf(stderr,"Unable to open %s\n",BLAH);
	  exit(1);
   }
   fread(blah_orig,1,SIZE_BLAH,fd);
   fclose(fd);

   if(argc > 1) {
	  uint32_t key;

	  key = strtoul(argv[1],NULL,16);
	  is_valid_key(key);
   } else {
	  int core = 0;
	  uint64_t step = ((1ULL<<16)/CORE)-1;

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
   exit(1);
}
