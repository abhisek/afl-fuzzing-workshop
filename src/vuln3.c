#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

struct functions {
   void (*hi)();
   void (*bye)();
};

void func_hi()
{
   printf("Hello world\n");
}

void func_bye()
{
   printf("Bye bye world\n");
}

int main(int argc, char **argv)
{
   char buf[512];
   char *ptr = NULL;
   int count;
   int flag;
   struct functions *f = NULL;
   char *ebuf = malloc(256);
   assert(ebuf != NULL);

   while(fgets(buf, sizeof(buf) - 1, stdin)) {
      count = *((int*)buf + 10);
      flag = *((int*)buf + 10);

      if(flag == 100) {
         f = (struct functions*) malloc(sizeof(*f));
         assert(f != NULL);
         f->hi = (void*) func_hi;
         f->bye = (void*) func_bye;
      }

      if(flag == 200) {
         ptr = (char*) malloc(count);
         assert(ptr != NULL);
         fgets(ptr, count - 1, stdin);
      }

      if(flag == 50) {
         if(f) {
            f->hi();
            f->bye();

            free(f);
            f = NULL;
         }

         if(ptr) {
            free(ptr);
            ptr = NULL;
         }
      }

      if(flag == 300) {
         if(ptr)
            strcpy(ebuf, ptr);
      }
   }
}
