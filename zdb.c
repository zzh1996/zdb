#include <stdio.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <bfd.h>
#include <sys/user.h>
#include <stdlib.h>
#include <string.h>

struct symbol{
    char *name;
    long addr;
};

struct symbol *symbol_table;
int symbol_count;

struct break_point{
    long addr;
    char olddata;
};

struct break_point bp[100];
int bp_count=0;

struct user_regs_struct get_regs(pid_t pid){
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS,pid,NULL,&regs);
    return regs;
}

void load_symbols(char *path){
    bfd_init();
    bfd *b=bfd_openr(path,NULL);
    bfd_check_format(b,bfd_object);
    size_t size=bfd_get_symtab_upper_bound(b);
    asymbol **symbols=malloc(size);
    int count=bfd_canonicalize_symtab(b,symbols);
    symbol_table=malloc(count*sizeof(struct symbol));
    for(int i=0;i<count;i++){
        symbol_table[i].name=bfd_asymbol_name(symbols[i]);
        symbol_table[i].addr=bfd_asymbol_value(symbols[i]);
    }
    symbol_count=count;
}

long parse(char *s){
    for(int i=0;i<symbol_count;i++){
        if(strcmp(s,symbol_table[i].name)==0){
            return symbol_table[i].addr;
        }
    }
    long num;
    if(sscanf(s,"%lx",&num)!=1)return 0;
    return num;
}

char *show(long addr){
    char *name=NULL;
    for(int i=0;i<symbol_count;i++){
        if(addr==symbol_table[i].addr){
            name=symbol_table[i].name;
            break;
        }
    }
    static char s[100];
    if(name)
        sprintf(s,"%s(0x%lx)",name,addr);
    else
        sprintf(s,"0x%lx",addr);
    return s;
}

int main(int argc,char **argv){
    pid_t pid;
    pid=fork();
    if(pid==0){
        ptrace(PTRACE_TRACEME);
        execl(argv[1],argv[1],NULL);
    }

    load_symbols(argv[1]);

    int status;
    wait(&status);
    while(1){
        if(WIFSTOPPED(status)){
            printf("Program stopped at %s\n",show(get_regs(pid).rip));
        }else if(WIFEXITED(status)){
            printf("Program exited\n");
            exit(0);
        }

        char command[256],arg[256];
        scanf("%s",command);
        if(strcmp(command,"b")==0){//set break point
            scanf("%s",arg);
            long addr=parse(arg);
            if(addr==0){
                printf("Unknown address: %s\n",arg);
                continue;
            }
            long data=ptrace(PTRACE_PEEKTEXT,pid,addr,NULL);
            bp[bp_count].olddata=data&0xFF;
            bp[bp_count++].addr=addr;
            data=(data&~0xFFL)|0xCC;
            ptrace(PTRACE_POKETEXT,pid,addr,data);
            printf("Break point %d set at %s\n",bp_count,show(addr));
        }else if(strcmp(command,"c")==0){//continue


        }else if(strcmp(command,"q")==0){//quit
        }else if(strcmp(command,"s")==0){//step
        }else if(strcmp(command,"r")==0){//show registers
        }else if(strcmp(command,"p")==0){//print 32bit memory

        }else{
            printf("b: set break point\n");
            printf("c: continue\n");
            printf("q: quit\n");
            printf("s: step one instruction\n");
            printf("r: show registers\n");
            printf("p: print 32bit memory\n");
        }
    }
    return 0;
}
