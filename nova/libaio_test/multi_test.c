#define _GNU_SOURCE /* syscall() is not POSIX */ 
#include<stdlib.h>
#include<string.h>
#include<libaio.h>
#include<errno.h>
#include<stdio.h>
#include<unistd.h>
#include<fcntl.h>
#include<stdbool.h>

/*you should edit also:
    io_nums;
    *p[io_nums] = {&io[0].....&io[io_nums-1]};

*/
#define io_nums 10003

int main()
{
    io_context_t context;
    struct iocb io[io_nums], *p[io_nums];
     int ret = 0, comp_num = 0, i = 0;
    for(i=0;i<io_nums;++i){
        p[i] = &io[i];
    }
    struct io_event e[io_nums];
    unsigned nr_events = io_nums;


    struct timespec timeout;
    timeout.tv_sec = 0;
    timeout.tv_nsec = 10000000;

    char *wbuf[io_nums]={0};
    char *rbuf[io_nums] = {0};

    int wbuflen = 4096;
    int rbuflen = wbuflen+1;

    for(i=0;i<io_nums;++i){
        posix_memalign((void**)&wbuf[i], 4096, wbuflen);
        posix_memalign((void**)&rbuf[i], 4096, rbuflen);
    }

    char ch[26]={'a','b','c','d','e','f','g','h','i','j','k','l','m','n',
                  'o','p','q','r','s','t','u','v','w','x','y','z'  };

    for(i=0;i<io_nums;++i){
        memset(wbuf[i],ch[i%26],wbuflen);
        memset(rbuf[i], 0, rbuflen);
    }
    /*this is a rule: io_context_t should init with 0*/
    memset(&context, 0, sizeof(io_context_t)); 

   

    int fd = open("/mnt/ramdisk/test.txt", O_CREAT|O_RDWR|O_DIRECT, 0644);

    if(fd < 0)
	{
        printf("open file failed ！\n");
        return 0;
    }

    if( 0 != io_setup(nr_events, &context) ){

        printf("io_setup error:%d\n", errno);
        return 0;
    }
    
    for(i=0;i<io_nums;++i){
        io_prep_pwrite(&io[i], fd, wbuf[i], wbuflen, 0);
    }



    if((ret = io_submit(context,io_nums,p)) != io_nums)
    {
        printf("io_submit error:%d\n", ret);
        io_destroy(context);
        return -1;
    }
    int k=0;
    while(true)
	{
        ret = io_getevents(context,1,1,e,&timeout);
        if(ret == 0){
             printf("comp_num: %d,io_nums : %d,k:%d\n", comp_num,io_nums,++k);

             sleep(1);
             printf("have not done !k = %d\n",++k);
        }
        if(ret < 0)
        {
            printf("io_getevents error:%d\n", ret);
            break;
        }

        if(ret > 0)
        {
            comp_num += ret;
            for( i = 0;i < ret; ++i)
			{
                printf("result,res2:%d, res:%d\n", e[i].res2, e[i].res);
            }
            
        }

        if(comp_num >= io_nums)
		{
            printf("done !\n");
            break;
        }
      
    }
    read(fd,rbuf[0],4096);
    printf("%s \n",rbuf[0]);
    io_destroy(context);
    return 0;
}