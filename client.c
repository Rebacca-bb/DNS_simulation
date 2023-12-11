#include<stdio.h>
#include<sys/types.h>
#include<string.h>
#include<unistd.h>
#include<stdlib.h>
#include<stdint.h>
#include "DNS.h"

#define DNS_MAX_LENGTH 1023
#define DNS_Local_SVR "127.0.0.2"
#define IN 1
#define A 1
#define MX 0x000F
#define CNAME 5

void querycpy(dns_query *b, char* a);// 指针定义的字符串的复制

int main(int argc, char *argv[]){
    /* 结构体定义 */
    // 结构体内容初始化
    dns_query *sendQuery  = (dns_query *)malloc(sizeof(dns_query));initQuery(sendQuery);
    dns_header *sendHead = (dns_header *)malloc(sizeof(dns_header));initHead(sendHead);
    dns_rr *sendRecord = (dns_rr *)malloc(sizeof(dns_rr));initRR(sendRecord);
    //得到的的结构体 
    dns_query *recvQuery = (dns_query *)malloc(sizeof(dns_query));initQuery(recvQuery);
    dns_header *recvHead = (dns_header *)malloc(sizeof(dns_header));initHead(recvHead);
    dns_rr *recvRecord = (dns_rr *)malloc(sizeof(dns_rr));initRR(recvRecord);
    //MX第二次查询ip
	dns_query *mxQuery = (dns_query *)malloc(sizeof(dns_query));initQuery(mxQuery);
	dns_header *mxHead = (dns_header *)malloc(sizeof(dns_header));initHead(mxHead);
	dns_rr *mxRecord = (dns_rr *)malloc(sizeof(dns_rr));initRR(mxRecord);

    /* 解析用户输入的query domain name和qtype */
    char *queryInfo;   // 要查询的name
    char *qType;      // 要查询的type
    char bufOut[DNS_MAX_LENGTH]; memset(bufOut, 0, DNS_MAX_LENGTH);
    char bufIn[DNS_MAX_LENGTH]; memset(bufIn, 0, DNS_MAX_LENGTH);
    char *o = bufOut + 2; //开头留两字节显示大小便于抓包 
    char *i = bufIn; //将接收到的前两字节删掉 
    unsigned short offset = 0;
    unsigned short *offsetptr; 

    if (argc != 3) 
    {
        printf("Usage: %s <Name in query> <qtype>\n", argv[0]);
        exit(1);
    }
    queryInfo = argv[1];
    qType = argv[2];
    printf("qType is %s\n", qType);
    while(!strcmp(qType, "A") && !strcmp(qType, "MX") && !strcmp(qType, "0") && !strcmp(qType, "CNAME"))
    {
        printf("The qtype allowed: A, MX, PTR\n");
        exit(1);
    }    

    printf("------------------QUERY------------------\n");
    printf("The Query Domain Name is: %s\n", queryInfo);
    printf("The Query Type is: %s\n", qType);
    printf("Now Start the Query Process\n");
    printf("-----------------------------------------\n");

    // 封装header
    sendHead->id = htons(sendHead->id = 1);  // 主机字节序（小端）转化为网络字节序（大端）
    sendHead->tag = htons(sendHead->tag = 4);
    sendHead->queryNum = htons(sendHead->queryNum = 1);
    sendHead->answerNum = 0;
    sendHead->authorNum = 0;
    sendHead->addNum = 0;

    o +=head2buf(o,sendHead);  // 把header放到缓存 bufOut 内，同时指针后移到新的空的位置

    // 封装query   strcmp(str1,str2)，若str1=str2，则返回零；若str1<str2，则返回负数；若str1>str2，则返回正数
    if(!strcmp(qType,"A")) 
        sendQuery->qtype = A_TYPE;
    else if(!strcmp(qType,"MX"))
        sendQuery->qtype = MX_TYPE;
    else if(!strcmp(qType,"CNAME"))
        sendQuery->qtype = CNAME_TYPE;
    else if(!strcmp(qType,"0"))
        sendQuery->qtype = 0;
      
    querycpy(sendQuery, queryInfo);  // 由于不能直接两指针相等,得用这种方式，把queryInfo放到query里面的name上
    sendQuery->qclass = IN;

    o +=query2buf(o, sendQuery);  // 把header放到缓存 bufOut 内，同时指针后移到新的空的位置
    offset = o - bufOut - 2;   // header和query模块的偏移量
    printf("offset_valeue:%d",( o - bufOut - 2));
    offsetptr = &offset;
    uint16_t temp = htons(offset); 
    memcpy(bufOut, &temp, sizeof(short)); //将DNS包长度写在bufOut的前两字节 

    // if(query->qtype==0) break;
      
    /* 发送 */
    int sock;
    struct sockaddr_in dest;

    // 创建socket 套接字 
    if ((sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
        printf("socket() failed.\n");

    // 创建local server的address structure
    memset(&dest, 0, sizeof(dest));/*Zero out structure*/
    dest.sin_family = AF_INET; /* Internet addr family */
    dest.sin_addr.s_addr = inet_addr(DNS_Local_SVR);/*Server IP address*/
    dest.sin_port = htons(53); /* Server port */


    if ((sendto(sock, bufOut+2, offset, 0, (struct sockaddr *) &dest, sizeof(dest)))!= (offset))
        printf("sendto() sent a different number of bytes than expected.\n");
    printf("Send Query to Local Server\n");


    /* 接收 */
    int rev;
    struct sockaddr_in fromAddr;
    unsigned int fromSize;
    fromSize = sizeof(fromAddr);

	// 长度不发了 因为UDP报文的query段在wireshark中不会解析出length字段！！！
    memset(bufIn,0,sizeof(bufIn));
    if ((rev = recvfrom(sock, bufIn, DNS_MAX_LENGTH, 0,(struct sockaddr *) &fromAddr, &fromSize)) < 0)
        printf("recvfrom() failed.\n"); 
    printf("receive successful!\n");

    //以下为接收答案并解析的代码
    printf("------------------ANSWER------------------\n");
    i += getHeader(i, recvHead); 
    if((recvHead->tag == 33152)){  //成功找到并返回结果
        printf("Find the Answers\n");
        i += getQuery(i, recvQuery); 
        recvRecord->name = recvQuery->name; 
        recvRecord->type = recvQuery->qtype;
        recvRecord->rclass = recvQuery->qclass;
        
        i += 6; //压缩指针那两个字节和后面的2个type，共6字节  
        //在这里送去解析的只有rr的后几个值 
        i += getRRs(i, recvRecord);
        if(recvQuery->qtype == MX){
            mxRecord->name = (char*)malloc((strlen(recvRecord->rdata)+1)*sizeof(char));
            strcpy(mxRecord->name, recvRecord->rdata);
            mxRecord->type = A_TYPE;
            mxRecord->rclass = 1;
            i += getRRs(i, mxRecord);
        }

        printf("Query Name: %s\n", recvRecord->name); 
        if(recvRecord->type == A_TYPE){
            printf("Query Type: A\n"); 
            printf("Query Class: IN\n"); 
            printf("TTL: %d\n", recvRecord->ttl);
            printf("IP Addr: %s\n", recvRecord->rdata);
        }
		else if(recvRecord->type == CNAME_TYPE){
				printf("Query Type: CNAME\n");
				printf("Query Class: IN\n"); 
				printf("TTL: %d\n", recvRecord->ttl);
				printf("Another Domain Name Addr: %s\n", recvRecord->rdata);
		} 
		else if(recvRecord->type == MX_TYPE){
			printf("Query Type: MX\n");
			printf("Query Class: IN\n"); 
			printf("TTL: %d\n", recvRecord->ttl);
			printf("Mail Server Domain Name: %s\n", recvRecord->rdata);
			printf("Mail Server IP Address: %s\n", mxRecord->rdata);
		} 
    }
    else
    { //嘛也没找着
        i += getQuery(i, recvQuery); 
        printf("Sorry, we didn't found anything\n");
        printf("Please try again later!\n");
    }
	printf("----------------ANSWER END----------------\n");

    printf("Quit with Safety\n");
	close(sock);
    return 0;
}

void querycpy(dns_query *b, char* a){
	int len = strlen(a)+1;
	//printf("length: %d\n", len);
	b->name = (char*)malloc(len*sizeof(char));
	memcpy(b->name, a, len);  // memcpy用于从存储区 str2 复制 n 个字节到存储区 str1
	//printf("look: %s, %s\n", b->name, a);
}



