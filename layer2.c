#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <arpa/inet.h>

#define NOT(x) (~(x)&0xffff)
#define ROL(x,y) ((((x)<<(y)) | ((x)>>(16-(y))))&0xffff)
#define ROR(x,y) ((((x)>>(y)) | ((x)<<(16-(y))))&0xffff)
#define SWAP(x) (((x)>>8)|(((x)<<8)&0xffff))

#define SIZE_LAYER 1763
#define BLOB_SIZE 0x100
#define BLOB "./blob.bin"
#define LAYER "./layer3.bin"
#define LAYER_UNENCODE "layer3_unencode"
#define VALUE_AT(x) (*(uint8_t*)(x))
#define VALUE16_AT(x) (*(uint16_t*)(x))

uint8_t layer3[SIZE_LAYER];

void unencode_layer3(uint8_t *layer, uint8_t *blob, uint8_t *ptr) {
   uint16_t count = 0;
   uint8_t byte = 0;
   uint8_t store1 = 0;

   while(count<SIZE_LAYER) {
	  uint8_t store2;
	  uint8_t addr;
	  uint8_t v1,v0,a0,a2;

	  byte += 1;

	  // SWAP
	  store1 += VALUE_AT(blob+byte);
	  store2 = VALUE_AT(blob+byte);
	  v1 = VALUE_AT(blob+store1);
	  VALUE_AT(blob+byte) = v1;
	  VALUE_AT(blob+store1) = store2;

	  a2 = VALUE_AT(layer+count);
	  a0 = VALUE_AT(blob+byte);
	  v0 = VALUE_AT(blob+store1);

	  v1 = (v0+a0) & 0xff;
	  v0 = VALUE_AT(blob+v1);

	  v0 ^= a2;
	  VALUE_AT(ptr+count) = v0;
	  count += 1;
   }
}

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

#define KEY1 0xe5df

void write_layer(uint8_t *blob) {
   FILE *fd;
   uint8_t ptr[SIZE_LAYER];
   char fname[1024];

   unencode_layer3(layer3, blob, ptr);

   sprintf(fname,"%s.bin",LAYER_UNENCODE);
   fd = fopen(fname,"w");
   fwrite(ptr,1,SIZE_LAYER,fd);
   fclose(fd);
}

uint16_t is_valid(uint16_t key) {
   int i;
   uint16_t k = key;
   uint16_t k1 = 0x94e3;
   uint8_t blob[BLOB_SIZE];

   FILE *fd = fopen(BLOB,"r");
   if(fd == NULL) {
	  fprintf(stderr,"Unable to open %s\n",BLOB);
	  exit(1);
   }
   fread(blob,1,BLOB_SIZE,fd);
   fclose(fd);

   for(i=0;i<64;i++) {
	  uint16_t v = o(0x9fc0,0x50+4*i+2,7,*((uint16_t*)blob+2*i+1));
	  uint16_t v1 = o(0x9fc0,0x50+4*i,7,*((uint16_t*)blob+2*i));

	  ((uint16_t*)blob)[2*i] = v1 ^ k1;
	  ((uint16_t*)blob)[2*i+1] = v ^ k;
	  k -= i;
	  k1 += i;
   }
   if(((uint16_t*)blob)[127] == 0xbe92) {
	  write_layer(blob);
	  printf("layer written\n");
	  return 1;
   }
   return 0;
}

void range(uint32_t min, uint32_t max, int son) {
   uint64_t i;
   for(i=min;i<max;i++) {
	  if(is_valid(i)) {
		 printf("KEY = %x\n",i);
		 exit(0);
	  }
   }
}

#define CORE 4

int main(int argc, char **argv) {
   FILE *fd;
   fd = fopen(LAYER,"r");
   if(fd == NULL) {
	  fprintf(stderr,"Unable to open %s\n",LAYER);
	  exit(1);
   }
   fread(layer3,1,SIZE_LAYER,fd);
   fclose(fd);

   if(argc > 1) {
	  uint32_t key;

	  key = strtoul(argv[1],NULL,16);
	  is_valid(key);
   } else {
	  int core = 0;
	  uint64_t step = (1ULL<<16)/CORE;

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
   exit(0);
}
