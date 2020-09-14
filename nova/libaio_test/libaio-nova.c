#include<fcntl.h>                                                                                                                                                                                            
#include <string.h>
#include <stdlib.h>
#include <libaio.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#define MAX_COUNT 256
#define BUF_SIZE  8*1024*1024
		   
#ifndef O_DIRECT  
#define O_DIRECT         040000 /* direct disk access hint */  
#endif
		        
int main(int args, void *argv[])
{
	//S1  数据预定义
	struct timespec start_time= {0, 0};
	struct timespec end_time= {0, 0};
	struct iocb io_read, io_write, *p[MAX_COUNT];
	struct io_event e[MAX_COUNT];
	struct timespec timeout;
	long long lat;
	io_context_t ctx;
       	
	//S2 数据初始化
        int fd, n = 0, i = 0;
	void *buf = NULL;
	int pagesize = sysconf(_SC_PAGESIZE);            //处理页对齐                                                                                                             
        posix_memalign(&buf, pagesize, BUF_SIZE);
	memset(buf, 'A' , BUF_SIZE);
			 
	//S3  创建并初始化ctx
        memset(&ctx , 0 , sizeof(ctx));
	if(io_setup(256 , &ctx)!=0)
	{
		printf("io_setup error\n");
		return -1;
	}
	if((fd = open("/mnt/ramdisk/test-32G", O_RDWR | O_CREAT | O_DIRECT, 0644))<0)
	{
		perror("open error"); 
		io_destroy(ctx);  
		return -1;   
	}       
				             
	//S4   填充读写请求并分别创建128读请求和写请求
	io_prep_pread(&io_read, fd, buf, BUF_SIZE, 0);
	io_prep_pwrite(&io_write, fd, buf, BUF_SIZE, 0);
	while( n < MAX_COUNT)
	{
		if(n < MAX_COUNT/2)
			p[n]=&io_write;
		else
      			p[n]=&io_read;
		n++;
	}
	
	//S5  提交请求并记录io_submit调用时间
	clock_gettime(CLOCK_REALTIME, &start_time);  
	int res = io_submit(ctx, MAX_COUNT, p);
	clock_gettime(CLOCK_REALTIME, &end_time);
        lat = 1000000000 * (end_time.tv_sec - start_time.tv_sec) + end_time.tv_nsec - start_time.tv_nsec;
	printf("io_submit调用时间为：%lld\n", lat);
					  
	//S6  检查是否提交成功 
	if(res<0)
	{
		io_destroy(ctx);
		printf("io_submit error\n");
 		printf("%d\n", res);
		return -1;
	}
	else
		printf("submited number:%d\n",res);

	//S7 获取完成事件
	int ret = io_getevents(ctx, 1, MAX_COUNT, e, NULL);              
	if (ret < 0) 
	{
		perror("ret != 1");
		exit(1);
	}
	printf("io请求处理成功的个数：%d\n",ret);
	close(fd);
	io_destroy(ctx);
	return 0;
}
