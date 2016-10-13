//#include "config.h"
#include "defines.h"
//#include "common.h"

#include <ctype.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>

#include "tcpbridge.h"
#include "bridge.h"
//#include "tcpbridge_opts.h"
//#include "bridge.h"
//#include "tcpedit/tcpedit.h"
//#include "send_packets.h"

#include "commonCapture/commonfunc.h"
#include "ssh/ssh.h"

#define SENDPACKET_ERRBUF_SIZE 1024
COUNTER bytes_sent, total_bytes, failed, pkts_sent, cache_packets;
struct timeval begin, end;
volatile int didsig;
tcpbridge_opt_t options;
//tcpedit_t *tcpedit;

/* local functions */
void init(void);
void post_args(int argc, char *argv[]);

//TYPE_NUM表示处理不同协议的子进程数
//g_type表示当前进程处理的协议类型
u_int32_t g_type = 0;
#define TYPE_NUM 2

char NetCardName0[256] = "";
char NetCardName1[256] = "";



int find_net_dev()
{
	pcap_if_t *netdevs;
	pcap_if_t *d;
	char errbuf[PCAP_ERRBUF_SIZE];
	char dev_names[1024] = "em EM rl RL";
	char buf_tmp[32];
	if(-1 == pcap_findalldevs(&netdevs, errbuf))
	{
		printf("\nfind no netdev\n");
		return -1;
	}
	d = netdevs;
	while(d)
	{
		if(d->flags == 0)
		{
			memset(buf_tmp, 0, sizeof(buf_tmp));
			strcpy(buf_tmp, d->name);
			buf_tmp[strlen(d->name) - 1] = 0;
			if(strstr(dev_names, buf_tmp))
			{
				if(strlen(NetCardName0) == 0)
				{
					strcpy(NetCardName0, d->name);
				}
				else if(strlen(NetCardName1) == 0)
				{
					strcpy(NetCardName1, d->name);
				}
				else
				{
					break;
				}
			}
		}
		
		d = d->next;
	}
	pcap_freealldevs(netdevs);
	return 1;
}
pid_t pid[TYPE_NUM];
void exit_child_process(int signumber)
{
    int ret;
	int status;
	char pszBuf[256];
	ret=wait(&status);
	//printf("ret=%d pid[1]=%d",ret,pid[1]);
	if(ret==pid[1])
	{
	     
         printf("have child process exit signumber=%d\n",signumber);
		 system("killall tcpbridge");
		 exit(0);
    }
   
}


int main(int argc, char *argv[])
{
    int optct, rcode;

	//此处创建子进程来处理不同的协议
	
	int i;
	pthread_t thread[256];//注意linux下创建线程的时候，编译要添加 -pthread选项
	signal(SIGCHLD,exit_child_process);
	//printf("main process id is %d\n",getpid());
	
	if(-1 == find_net_dev())
	{
		printf("\nCan not found any net devs!\n");
		return -1;
	}
	if((strlen(NetCardName0) == 0) || (strlen(NetCardName1) == 0))
	{
		printf("\nCan not found any net devs!\n");
		return -1;
	}

	//printf("NetCard name\n0:%s\n1:%s\n", NetCardName0, NetCardName1);
	
	for(i=0;i<TYPE_NUM;i++)
	{
		if((pid[i]=fork())<0)
		{
			fprintf(stderr,"fork() error!\n");
			exit(-1);
		}
		if(pid[i] == 0)
		{
#ifdef DEBUG_ALL_PRINT
			fprintf(stderr,"parent is %d,child is %d\n",getppid(),getpid());
#endif
			g_type = i;
			break;
		}
		else
		{
			g_type = -1;
		}
	}


	if(g_type == -1)	//主进程处理ftp、http、telnet、tds
	{
#ifdef DEBUG_ALL_PRINT
		fprintf(stderr,"\nListen NetCard: %s\n",NetCardName0);//<<<<NetCardName<<endl;
#endif
		if(-1 == capture_info_init(NetCardName0))
		{
			fprintf(stderr,"\ncapture init fail\n");
			return -1;
		}
		if(pthread_create(&thread[0],NULL,(void *(*)(void *))Capture_FTP,(void*)&NetCardName0)!=0)
			fprintf(stderr,"\nError:Thread Capture_FTP can not create\n");
		if(pthread_create(&thread[1],NULL,(void *(*)(void *))Capture_Telnet,(void*)&NetCardName0)!=0)
			fprintf(stderr,"\nError:Thread Capture_Telnet can not create\n");
		if(pthread_create(&thread[2],NULL,(void *(*)(void *))Capture_Http,(void*)&NetCardName0)!=0)
			fprintf(stderr,"\nError:Thread Capture_Http can not create\n");
		if(pthread_create(&thread[3],NULL,(void *(*)(void *))Capture_TDS,(void*)&NetCardName0)!=0)
			fprintf(stderr,"\nError:Thread Capture_TDS can not create\n");
		if(pthread_create(&thread[4],NULL,(void *(*)(void *))Capture_Oracle,(void*)&NetCardName0)!=0)
			fprintf(stderr,"\nError:Thread Capture_DATABASE Oracle can not create\n");
		if(pthread_create(&thread[5],NULL,(void *(*)(void *))Capture_Db2,(void*)&NetCardName0)!=0)
			fprintf(stderr,"\nError:Thread Capture_DATABASE Db2 can not create\n");
		if(pthread_create(&thread[6],NULL,(void *(*)(void *))Capture_Smtp,(void*)&NetCardName0)!=0)
			fprintf(stderr,"\nError:Thread Capture_DATABASE Smtp can not create\n");
		DelList();
/*wp
		 pthread_attr_t attr;
		if ( 0 !=pthread_attr_init(&attr) )
			printf("pthread_attr_init func == -1\n");
		if( 0 != pthread_attr_setinheritsched(&attr,PTHREAD_INHERIT_SCHED) )
			printf("pthread_attr_setinheritsched func == -1 \n");
		if( 0 != pthread_attr_set)
		
		if(pthread_create(&thread[6],&attr,(void *(*)(void *))DelList, NULL)!=0)
			fprintf(stderr,"\nError:Thread DelList can not create\n");
			*/
	}

	if(g_type == 0)		//处理ssh进程
	{
		//Initialssh();
	}


    init();

    post_args(argc, argv);


    if (gettimeofday(&begin, NULL) < 0)
        err(-1, "gettimeofday() failed");


    /* process packets */
    do_bridge(&options);

    /* clean up after ourselves */
    pcap_close(options.pcap1);
    
    pcap_close(options.pcap2);
    return 0;
}

void init(void)
{
    
    bytes_sent = total_bytes = failed = pkts_sent = cache_packets = 0;
    memset(&options, 0, sizeof(options));
    
    options.snaplen = 65535;
    options.promisc = 1;
    options.to_ms = 1;

    total_bytes = 0;

    if (fcntl(STDERR_FILENO, F_SETFL, O_NONBLOCK) < 0)
        warnx("Unable to set STDERR to non-blocking: %s", strerror(errno));

}


void post_args(int argc,char *argv[])
{
    char ebuf[SENDPACKET_ERRBUF_SIZE];
    
    options.intf1 = malloc(strlen(NetCardName0)+1);
    strncpy(options.intf1, NetCardName0, strlen(NetCardName0)+1);
    
    options.intf2 = malloc(strlen(NetCardName1)+1);
    strncpy(options.intf2, NetCardName1, strlen(NetCardName1)+1);
    
    /* 
     * Open interfaces for sending & receiving 
     */
    if ((options.pcap1 = pcap_open_live(options.intf1, options.snaplen, 
                                          options.promisc, options.to_ms, ebuf)) == NULL)
        errx(-1, "Unable to open interface %s: %s", options.intf1, ebuf);


    if (strcmp(options.intf1, options.intf2) == 0)
        errx(-1, "Whoa tiger!  You don't want to use %s twice!", options.intf1);


    /* we always have to open the other pcap handle to send, but we may not listen */
    if ((options.pcap2 = pcap_open_live(options.intf2, options.snaplen,
                                          options.promisc, options.to_ms, ebuf)) == NULL)
        errx(-1, "Unable to open interface %s: %s", options.intf2, ebuf);
    
    /* poll should be -1 to wait indefinitely */
    options.poll_timeout = -1;
}
