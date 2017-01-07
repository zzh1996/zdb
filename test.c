#include <stdio.h>

int i;

void f(){
    printf("Loop %d\n",i);
}

int main(){
    for(i=0;i<10;i++)
        f();
    return 0;
}
