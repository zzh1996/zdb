#include <stdio.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <bfd.h>
#include <sys/user.h>
#include <sys/reg.h>
#include <stdlib.h>
#include <string.h>

#define TEXT_OFFSET 0x555555554000

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
        symbol_table[i].addr=bfd_asymbol_value(symbols[i])+TEXT_OFFSET;
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
    char *s=malloc(100);
    if(name)
        sprintf(s,"%s(0x%lx)",name,addr);
    else
        sprintf(s,"0x%lx",addr);
    return s;
}

void set_bp(pid_t pid,long addr){
    for(int i=0;i<bp_count;i++){
        if(bp[i].addr==addr){
            long data=ptrace(PTRACE_PEEKTEXT,pid,addr,NULL);
            bp[i].olddata=data&0xFF;
            data=(data&~0xFFL)|0xCC;
            ptrace(PTRACE_POKETEXT,pid,addr,data);
            return;
        }
    }
}

void reset_bp(pid_t pid,long addr){
    for(int i=0;i<bp_count;i++){
        if(bp[i].addr==addr){
            long data=ptrace(PTRACE_PEEKTEXT,pid,addr,NULL);
            data=(data&~0xFFL)|bp[i].olddata;
            ptrace(PTRACE_POKETEXT,pid,addr,data);
            return;
        }
    }
}

int main(int argc,char **argv){
    if(argc!=2){
        printf("Usage: zdb <executable>\n");
        exit(0);
    }
    pid_t pid;
    pid=fork();
    if(pid==0){
        ptrace(PTRACE_TRACEME);
        execl(argv[1],argv[1],NULL);
    }

    load_symbols(argv[1]);

    int status;
    int rewind;
    wait(&status);
    rewind=0;
    while(1){
        if(WIFSTOPPED(status)){
            long rip=get_regs(pid).rip;
            if(rewind){
                rip--;
                ptrace(PTRACE_POKEUSER,pid,8*RIP,rip);
                rewind=0;
            }
            printf("Program stopped at %s\n",show(rip));
        }else if(WIFEXITED(status)){
            printf("Program exited\n");
            exit(0);
        }

        char command[256],arg[256];
        printf("(zdb) ");
        scanf("%s",command);
        if(strcmp(command,"b")==0){//set break point
            scanf("%s",arg);
            long addr=parse(arg);
            if(addr==0){
                printf("Unknown address: %s\n",arg);
                continue;
            }
            bp[bp_count++].addr=addr;
            set_bp(pid,addr);
            printf("Break point %d set at %s\n",bp_count,show(addr));
        }else if(strcmp(command,"c")==0){//continue
            long rip=get_regs(pid).rip;
            reset_bp(pid,rip);
            ptrace(PTRACE_SINGLESTEP,pid,NULL,NULL);
            wait(&status);
            set_bp(pid,rip);
            ptrace(PTRACE_CONT,pid,NULL,NULL);
            wait(&status);
            rewind=1;
        }else if(strcmp(command,"q")==0){//quit
            exit(0);
        }else if(strcmp(command,"s")==0){//step
            long rip=get_regs(pid).rip;
            reset_bp(pid,rip);
            ptrace(PTRACE_SINGLESTEP,pid,NULL,NULL);
            wait(&status);
            set_bp(pid,rip);
        }else if(strcmp(command,"r")==0){//show registers
            struct user_regs_struct regs=get_regs(pid);
            printf("rax=%s\n",show(regs.rax));
            printf("rbx=%s\n",show(regs.rbx));
            printf("rcx=%s\n",show(regs.rcx));
            printf("rdx=%s\n",show(regs.rdx));
            printf("rsi=%s\n",show(regs.rsi));
            printf("rdi=%s\n",show(regs.rdi));
            printf("rbp=%s\n",show(regs.rbp));
            printf("rsp=%s\n",show(regs.rsp));
            printf("r8=%s\n",show(regs.r8));
            printf("r9=%s\n",show(regs.r9));
            printf("r10=%s\n",show(regs.r10));
            printf("r11=%s\n",show(regs.r11));
            printf("r12=%s\n",show(regs.r12));
            printf("r13=%s\n",show(regs.r13));
            printf("r14=%s\n",show(regs.r14));
            printf("r15=%s\n",show(regs.r15));
            printf("rip=%s\n",show(regs.rip));
            printf("eflags=%s\n",show(regs.eflags));
        }else if(strcmp(command,"p")==0){//print 64bit memory
            scanf("%s",arg);
            long addr=parse(arg);
            if(addr==0){
                printf("Unknown address: %s\n",arg);
                continue;
            }
            long data=ptrace(PTRACE_PEEKTEXT,pid,addr,NULL);
            printf("Data at %s is %s\n",show(addr),show(data));
        }else if(strcmp(command,"t")==0){//print call stack

        }else{
            printf("b: set break point\n");
            printf("c: continue\n");
            printf("q: quit\n");
            printf("s: step one instruction\n");
            printf("r: show registers\n");
            printf("p: print 64bit memory\n");
        }
    }
    return 0;
}
