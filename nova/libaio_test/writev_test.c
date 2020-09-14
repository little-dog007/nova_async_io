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
#define io_nums 4

int main()
{
    io_context_t context;
    struct iocb io[io_nums], *p[io_nums];
    struct iovec myiov_write[2],myiov_read[2];

    for(int i=0;i<io_nums;++i){
        p[i] = &io[i];
    }
    struct io_event e[io_nums];
    unsigned nr_events = io_nums;

    struct timespec timeout;
    timeout.tv_sec = 0;
    timeout.tv_nsec = 10000000;

    /*edit here*/
    char *wbuf_1 = 0, *rbuf_1 = 0;
    char *wbuf_2 =0,*rbuf_2 = 0;
    char *wbuf_3 = 0, *rbuf_3 = 0;
    char *wbuf_4 =0,*rbuf_4 = 0;
    char *wbuf_5 = 0, *rbuf_5 = 0;
    char *wbuf_6 =0,*rbuf_6 = 0;
    char *rbuf_all = 0;

    int wbuflen = 4096;
    int rbuflen = wbuflen+1;

    posix_memalign((void**)&wbuf_1, 4096, wbuflen);
    posix_memalign((void**)&rbuf_1, 4096, rbuflen);
    posix_memalign((void**)&wbuf_2, 4096, wbuflen);
    posix_memalign((void**)&rbuf_2, 4096, rbuflen);
    posix_memalign((void**)&wbuf_3, 4096, wbuflen);
    posix_memalign((void**)&rbuf_3, 4096, rbuflen);
    posix_memalign((void**)&wbuf_4, 4096, wbuflen);
    posix_memalign((void**)&rbuf_4, 4096, rbuflen);
    posix_memalign((void**)&wbuf_5, 4096, wbuflen);
    posix_memalign((void**)&rbuf_5, 4096, rbuflen);
    posix_memalign((void**)&wbuf_6, 4096, wbuflen);
    posix_memalign((void**)&rbuf_6, 4096, rbuflen);
    posix_memalign((void**)&rbuf_all, 4096, wbuflen*2+1);

    memset(wbuf_1, 'a', wbuflen);
    memset(wbuf_2, 'b', wbuflen);
    memset(wbuf_3, 'c', wbuflen);
    memset(wbuf_4, 'd', wbuflen);
    memset(wbuf_5, 'e', wbuflen);
    memset(wbuf_6, 'f', wbuflen);

    memset(rbuf_1, 0, rbuflen);
    memset(rbuf_2, 0, rbuflen);
    memset(rbuf_3, 0, rbuflen);
    memset(rbuf_4, 0, rbuflen);
    memset(rbuf_5, 0, rbuflen);
    memset(rbuf_6, 0, rbuflen);
    memset(rbuf_all,0,wbuflen*2+1);
    /*this is a rule: io_context_t should init with 0*/
    memset(&context, 0, sizeof(io_context_t)); 

    int ret = 0, comp_num = 0, i = 0;

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

    myiov_write[0].iov_len = wbuflen;
    myiov_write[0].iov_base = wbuf_1;
    myiov_write[1].iov_len = wbuflen;
    myiov_write[1].iov_base = wbuf_2;

    myiov_read[0].iov_len = wbuflen;
    myiov_read[0].iov_base = rbuf_1;
    myiov_read[1].iov_len = wbuflen;
    myiov_read[1].iov_base = rbuf_2;


   io_prep_pwritev(&io[0],fd,myiov_write,2,0);
   io_prep_preadv(&io[1],fd,myiov_read,2,0);

   io_prep_pwrite(&io[2], fd, wbuf_3, wbuflen, 0);
   io_prep_pread(&io[3], fd, rbuf_all, wbuflen*2, 0);
    


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
    printf("%s \n\n\n",rbuf_1);
    printf("%s \n\n\n",rbuf_2);

    printf("%s \n\n\n",rbuf_3);
    printf("%s \n\n\n",rbuf_4);

    printf("%s \n\n\n",rbuf_5);
    printf("%s \n\n\n",rbuf_6);

    io_destroy(context);
    return 0;
}