#include<stdio.h>
#include<sys/types.h>
#include<string.h>
#include<unistd.h>
#include<stdlib.h>
#include<stdint.h>
#include "DNS.h"

#define LINE 10   // 用于int listen(int sockfd， int backlog)中的backlog，backlog指定在请求队列中允许的最大请求数 
#define DNS_MAX_LENGTH 1023
// #define ECHOMAX 255 /* Longest string to echo */


int blocklen(char *cur);
void init_DNS_RR(dns_query *recvQuery,dns_rr *resRecord ,char *col);
void write2cache(char* filePath,dns_query *serverQuery,dns_rr *serverRecord);

int main(){

    // 创建socket
    int sersock =0;
    struct sockaddr_in seraddr; memset(&seraddr, 0, sizeof(seraddr));
   
    seraddr.sin_family = AF_INET;
    seraddr.sin_port = htons(53);
    seraddr.sin_addr.s_addr=inet_addr("127.0.0.2");

	if ((sersock = socket(PF_INET, SOCK_DGRAM, 0)) < 0)
        printf("socket() failed.\n");

    // 绑定socket
    if ((bind(sersock, (struct sockaddr *)&seraddr, sizeof(seraddr))) < 0)
    {
        printf("bind() failed.\n");
        close(sersock);
        return -1;
    }   
    printf("Bind sucessfully!");


    // 接收客户端的UDP信息
    /*  声明*/
    unsigned char queryInfo[127];
	unsigned char* convertQueryInfo;
    //用于接收client信息的的结构体
    dns_query *recvQuery = (dns_query *)malloc(sizeof(dns_query));initQuery(recvQuery);
	dns_header *recvHead = (dns_header *)malloc(sizeof(dns_header));initHead(recvHead);
	dns_rr *recvrRecord = (dns_rr *)malloc(sizeof(dns_rr));initRR(recvrRecord);  
	//回应的结构体 
	dns_query *resQuery = (dns_query *)malloc(sizeof(dns_query));initQuery(resQuery);
	dns_header *resHead = (dns_header *)malloc(sizeof(dns_header));initHead(resHead);
	dns_rr *resRecord = (dns_rr *)malloc(sizeof(dns_rr));initRR(resRecord);
	//接收DNS服务器传来的结构体
	dns_query *serverQuery = (dns_query *)malloc(sizeof(dns_query));initQuery(serverQuery);
	dns_header *serverHead = (dns_header *)malloc(sizeof(dns_header));initHead(serverHead);
	dns_rr *serverRecord = (dns_rr *)malloc(sizeof(dns_rr));initRR(serverRecord);
	//MX第二次查询ip
	dns_query *mxQuery = (dns_query *)malloc(sizeof(dns_query));initQuery(mxQuery);
	dns_header *mxHead = (dns_header *)malloc(sizeof(dns_header));initHead(mxHead);
	dns_rr *mxRecord = (dns_rr *)malloc(sizeof(dns_rr));initRR(mxRecord);

    char bufOut[DNS_MAX_LENGTH]; memset(bufOut, 0, DNS_MAX_LENGTH);
	char bufIn[DNS_MAX_LENGTH]; memset(bufIn, 0, DNS_MAX_LENGTH);
	char closeFlag[5];
	char flag[] = "exit";

    unsigned short qType, qClass;
	unsigned short offset = 0;
	unsigned short *offsetptr; 

    char *o=bufOut + 2;    // 开头留两字节显示大小便于抓包
    char *i=bufIn ;    // 接收的时候直接从头开始读
	int checkinit = 0;

    //接收 
    int rev;        /* Size of received message */
    struct sockaddr_in clientaddr;  //用于存放接收的address
    unsigned int cliAddrLen; /* Length of client address */
    cliAddrLen = sizeof(clientaddr);

    if ((rev = recvfrom(sersock, bufIn, DNS_MAX_LENGTH, 0,(struct sockaddr *) &clientaddr, &cliAddrLen)) < 0)
        printf("!!!recvfrom() failed.\n"); 
    printf("Received the query request from client!\n");
    i += getHeader(i,recvHead);
    i += getQuery(i, recvQuery); 
    
    /*
	 *解析接口（头） 
	 */ 
	resHead->id =htons(recvHead->id);
	resHead->tag =htons(0x8180);  // flags：0x8180表示为标准查询的回应
	resHead->queryNum =htons(recvHead->queryNum);
	resHead->answerNum = htons(1); //这里不一定是1，若没查到怎么办？？ 
	resHead->authorNum = 0;
	resHead->addNum = 0;
	resQuery = recvQuery;

	char *filePath;
	// 读文件的qtype
	filePath = "localCache.txt";
	FILE *fp = fopen(filePath,"r"); // 读本地缓存文件
	char col[DNSMAXLEN]; memset(col, 0, DNSMAXLEN); 
	while(fgets(col, DNSMAXLEN-1, fp) != NULL){ //逐行对比 
		//printf("in compare whileA\n");
		if(cmpRR(recvQuery, col)){
			//printf("in compareA\n");
			init_DNS_RR(recvQuery,resRecord,col);
			resHead->answerNum = htons(1); //找到answer，在answerNum处赋值 
			checkinit=1;   //表明查询完成，无需再进入下一节点查询 
			break;
		}
	}
	fclose(fp);
	if((checkinit==1)&&(resQuery->qtype==MX_TYPE)){
		// 封装MXquery
		mxQuery->name = (char*)malloc((strlen(resRecord->rdata)+1)*sizeof(char));
		strcpy(mxQuery->name, resRecord->rdata);
		//printf("mxQueryName: %s\n", mxQuery->name);
		mxQuery->qclass = recvQuery->qclass;
		mxQuery->qtype = A_TYPE; //这里要用上一次的结果A方式查询一下

		//第二次先去查一下ip地址	A
		filePath="localCache.txt";
		FILE *fp2 = fopen(filePath, "r"); //读取对应文件
		char col2[DNSMAXLEN]; memset(col2, 0, DNSMAXLEN); 
		while(fgets(col2, DNSMAXLEN-1, fp2) != NULL){ //逐行对比 
	    	// printf("in compare whileMX2\n");
			if(cmpRR(mxQuery, col2)){
				// printf("compareMX2 successfully\n");
				init_DNS_RR(mxQuery,mxRecord,col2);
				mxRecord->name = (char*)malloc((strlen(resRecord->rdata)+1)*sizeof(char));
				strcpy(mxRecord->name, resRecord->rdata);
				mxRecord->type = A_TYPE;
				mxRecord->rclass = 1;
				resHead->addNum = htons(1); //找到answer，在answerNum处赋值 
				checkinit=1;   //表明查询完成，无需再进入下一节点查询 
				break;
			}
		}
		fclose(fp2);	
	}

	/*
	 *向root查询 
	*/ 
	if(checkinit!=1){    
	    int socktcp;
		struct sockaddr_in toAddr; //去的地址 
		struct sockaddr_in fromAddr; //本机的地址 
		unsigned short toPort=53;
		unsigned int fromSize;
		
		char bufFromRoot[DNS_MAX_LENGTH];
		memset(bufFromRoot, 0, DNS_MAX_LENGTH);
		
		char *askBuf;
		askBuf = bufIn - 2;   // tcp报文前面要拿两位出来放length
		char recvBuffer[DNS_MAX_LENGTH];
		//char askBuffer[DNS_MAX_LENGTH];
		
		//int outLength; //发出的长度
		int inLength; //收到的字节长度
	
		
		// 创建用于tcp的socket
		
		if((socktcp=socket(PF_INET,SOCK_STREAM,0))<0)  
			printf("socket() failed\n");

		//localserver可以不绑定端口号，系统会随机分配
		fromAddr.sin_family = AF_INET;
		fromAddr.sin_port = 0;
		fromAddr.sin_addr.s_addr=inet_addr("127.0.0.2");	
		if ((bind(socktcp, (struct sockaddr *)&fromAddr, sizeof(fromAddr))) < 0)
		{
			printf("bind() failed.\n");
			close(socktcp);
			return -1;
		} 

		//localserver连接root服务器	
		int addrlen=0;
		init_sockaddr_in("127.0.0.3", 53, &toAddr);
		addrlen=sizeof(toAddr);
		if(connect(socktcp,(struct sockaddr *)&toAddr,addrlen)<0)
		{
			printf("connect failed\n");
			close(socktcp);
			return -1;
		}
		printf("===============trace==============");
		printf("Query to Root\n");
		/*
		 *send
		 */
		offset = i-bufIn;
		offsetptr = &offset;
		uint16_t temp = htons(offset); 
		memcpy(askBuf, &temp, sizeof(short)); //将DNS包长度写在前两字节 
		if(send(socktcp,askBuf,offset+2,0)<0){
			printf("Send error.\n");
		} 

		/*
		 *recv 从根节点接收
		 */
		if(recv(socktcp,bufFromRoot,DNS_MAX_LENGTH,0)<0)
			printf("Receive from root error!");

		//printf("buf: %s\n", bufFromRoot);
		//printf("length: %d\n", inLength);
		//bufFromRoot[inLength]='\0';
		char *p = bufFromRoot+2; 	//初始化下面服务器传来的指针，前面两位是长度，要跳过
		p += getHeader(p, serverHead);
		//printf("Head Tag From Root: %d\n", serverHead->tag);
		p += getQuery(p, serverQuery);
		serverRecord->name = serverQuery->name; 
		serverRecord->type = A_TYPE;
		serverRecord->rclass = serverQuery->qclass;
		// printf("rRecord Name: %s\n", serverRecord->name); 
		// printf("rRecord Type: %d\n", serverRecord->type); 
		// printf("rRecord Class: %d\n", serverRecord->rclass); 
		// printf("size1: %d\n", strlen(serverRecord->name)+1);
		// printf("size2: %d\n", 2*sizeof(serverRecord->type));
		p += 6; //压缩指针那两个字节和后面的2个type，共6字节  
		//printf("strlen offset: %d\n", strlen(serverRecord->name)+1);
		//i += (2*sizeof(serverRecord->type));
		//printf("sizeof2: %d\n", 2*sizeof(serverRecord->type));
		//在这里送去解析的只有rr的后几个值 
		p += getRRs(p, serverRecord);
		//printf("The next query ipAddr: %s\n", serverRecord->rdata);
		/*
		 *迭代遍历 
		 */
		close(socktcp);
        while(1){
		// 创建用于tcp的socket
		if((socktcp=socket(PF_INET,SOCK_STREAM,0))<0)  
			printf("socket() failed\n");
		if ((bind(socktcp, (struct sockaddr *)&fromAddr, sizeof(fromAddr))) < 0)
		{
			printf("bind() failed.\n");
			close(socktcp);
			return -1;
		}
			
		if(serverHead->tag==32768){   //8000
        	struct sockaddr_in askAddr; //下一阶段问的地址 	
        	unsigned int askSize; //返回的地址长度 
        	int backlength;  //返回的字节长度 
        	printf("Send Query Request to %s\n", serverRecord->rdata);
        	init_sockaddr_in(serverRecord->rdata, 53, &askAddr);
			if(connect(socktcp,(struct sockaddr *)&askAddr,sizeof(askAddr))<0)
			{
				printf("connect first sub address failed\n");
				close(socktcp);
				return -1;
			}

			if(send(socktcp,askBuf,offset+2,0)<0){
				printf("Send error.\n");
			} 

			if(recv(socktcp,bufFromRoot,DNS_MAX_LENGTH,0)<0){
				printf("Receive!");
			}
		    
		    /*
		     *这段解析代码可以弄个函数 
		     */
		    char *p1 = bufFromRoot+2; //初始化下面服务器传来的指针
		    p1 += getHeader(p1, serverHead);
	     	//printf("Head Tag From diedai: %d\n", serverHead->tag);
	    	p1 += getQuery(p1, serverQuery);
	    	serverRecord->name = serverQuery->name; 
			if(serverHead->tag==32768){
				serverRecord->type = A_TYPE;
			}else{
				serverRecord->type = serverQuery->qtype;
			} 
		    serverRecord->rclass = serverQuery->qclass;
		    // printf("dd rRecord Name: %s\n", serverRecord->name); 
	    	// printf("dd rRecord Type: %d\n", serverRecord->type); 
	    	// printf("dd rRecord Class: %d\n", serverRecord->rclass); 
	    	// printf("dd size1: %d\n", strlen(serverRecord->name)+1);
		    // printf("dd size2: %d\n", 2*sizeof(serverRecord->type));
	     	p1 += 6; //压缩指针那两个字节和后面的2个type，共6字节  
	     	//printf("dd strlen offset: %d\n", strlen(serverRecord->name)+1);
		    //i += (2*sizeof(serverRecord->type));
		   // printf("dd sizeof2: %d\n", 2*sizeof(serverRecord->type));
		    //在这里送去解析的只有rr的后几个值
			if(serverHead->tag!=33155){
	        p1 += getRRs(p1, serverRecord);
	     	    if(serverQuery->qtype==MX_TYPE)  {
	     	    	mxRecord->name = (char*)malloc((strlen(serverRecord->rdata)+1)*sizeof(char));
				    strcpy(mxRecord->name, serverRecord->rdata);
				    mxRecord->type = A_TYPE;
				    mxRecord->rclass = 1;
			    	p1 +=getRRs(p1,mxRecord);
				 }
	        }
	     	    
		    //printf("dd The next query ipAddr: %s\n", serverRecord->rdata);		    
		   
	    }
		else if(serverHead->tag==33155){  //8183
			printf("Not found!\n");
			serverRecord->type = serverQuery->qtype;
			serverHead->id = htons(serverHead->id);
			serverHead->tag = htons(serverHead->tag);
			serverHead->queryNum = htons(serverHead->queryNum);
			serverHead->answerNum = htons(serverHead->answerNum);
			serverHead->authorNum = 0;
			serverHead->addNum = 0;
			char *p2 = bufOut ;
			p2 += head2buf(p2, serverHead);
	 		p2 += query2buf(p2,serverQuery); 
	 		//p2 += rr2buf(p2,serverRecord);
			uint16_t offset = p2-bufOut;

			if ((sendto(sersock, bufOut, offset, 0, (struct sockaddr *) &clientaddr, sizeof(clientaddr)))!= offset)
			{
				printf("To client:sendto() sent a different number of bytes than expected.\n");
			}
	
			printf("Send to Client Success\n");
			break;  // 退出迭代查询的循环
		}
		else if(serverHead->tag==33152){  //8180
			printf("Found successful!");
			serverRecord->type = serverQuery->qtype;
			serverHead->id = htons(serverHead->id);
			serverHead->tag = htons(serverHead->tag);
			serverHead->queryNum = htons(serverHead->queryNum);
			serverHead->answerNum = htons(serverHead->answerNum);
			serverHead->authorNum = 0;
			serverHead->addNum = 0;
			if(serverQuery->qtype==MX_TYPE){
				serverHead->addNum = htons(1);
			}
			char *p2 = bufOut ;
			p2 += head2buf(p2, serverHead);
	 		p2 += query2buf(p2,serverQuery); 
	 		p2 += rr2buf(p2,serverRecord);
	 		if(serverQuery->qtype==MX_TYPE)
	 			p2 +=add2buf(p2,mxRecord,serverQuery);
			uint16_t offset = p2-bufOut;
			uint16_t temp = htons(offset);
			memcpy(bufOut, &temp, sizeof(short));

			if ((sendto(sersock, bufOut, offset, 0, (struct sockaddr *) &clientaddr, sizeof(clientaddr)))!= offset)
			{
				printf("To client:sendto() sent a different number of bytes than expected.\n");
			}

			printf("Send to Client Success\n");

			write2cache("localCache.txt",serverQuery,serverRecord);
			break;	// 退出迭代查询的循环
		}
        close(socktcp);		
		} 
		//printf("Recieved : %s\n", bufFromRoot);
		// close(socktcp);	
		//break;
		printf("==============trace end=============");
	}
	else{
		/*
		封装、返回client
		*/
		printf("Find in local server cache.\n");
		// char *o=bufOut + 2;
		o += head2buf(o, resHead);
		o += query2buf(o,resQuery); 
		o += rr2buf(o,resRecord);
		printf("not add to buff");
		if(recvQuery->qtype==(uint16_t)MX_TYPE){
			printf("mx add to buff");
			o +=add2buf(o,mxRecord,resQuery);
		}
		//???bufOut 是不是要再初始化一次
		offset = o - bufOut - 2;
		offsetptr = &offset;
		uint16_t temp = htons(offset); 
		memcpy(bufOut, &temp, sizeof(short)); //将DNS包长度写在前两字节 

		if ((sendto(sersock, bufOut+2, offset, 0, (struct sockaddr *) &clientaddr, sizeof(clientaddr)))!= offset)
			printf("sendto() sent a different number of bytes than expected.\n");
	}
	close(sersock);
    return 0;
}

//写入本地缓存文件
void write2cache(char* filePath,dns_query *serverQuery,dns_rr *serverRecord){
	FILE *fp = fopen(filePath,"a"); // 读本地缓存文件
	// char writeBuf[1023];	
	char temp[10];
	switch (serverQuery->qtype)
	{
	case A_TYPE:
			strcpy(temp,"A");
		break;
	case MX_TYPE:
		
			strcpy(temp,"MX");
		break;
	case CNAME_TYPE:
		
			strcpy(temp,"CNAME");
		break;
	
	default:
		printf("no this type!!");
		break;
	}
	
	fprintf(fp,"%s %s %d %s\r\n",serverQuery->name,temp,serverQuery->qclass,serverRecord->rdata);
	close(fp);

}

int blocklen(char *cur){
	int i=0;
	while(1){
		if(cur[i]==' '||cur[i]=='\n'||cur[i]=='\0')
			break;
		else i++;
	}
	return i+1;
}

void init_DNS_RR(dns_query *recvQuery,dns_rr *resRecord ,char *col){
	char* cur=col; //光标
	unsigned int len=0;
	//printf("in DNS\n");
	
	/*
	 *拷贝可从query里获取的信息
	 */
//	resRecord->name = (char*)malloc(strlen(recvQuery->name)*sizeof(char));
    resRecord->name=recvQuery->name;
    resRecord->rclass=recvQuery->qclass;
	resRecord->type=recvQuery->qtype;
	
	// 简便一点，令TTL都为86400
	int TTL = 86400;    
	resRecord->ttl=(uint32_t)TTL; 

	len=blocklen(cur);  cur+=len;//name
	//printf("name_length: %d\n",len);
	len=blocklen(cur);  cur+=len; //type
	//printf("cur length:%d\n",len);
	len=blocklen(cur);  cur+=len;//class
	//printf("len length:%d\n",len);
	 /*
	  *拷贝 rdata 
	  */
	len=blocklen(cur); 
	printf("rdata_length: %d  ",len);
	char strData[len]; memcpy(strData,cur,len-1); strData[len-2]='\0'; //啥意思
	char*strPointer=strData;
	resRecord->rdata=(char*)malloc((len-1)*sizeof(char));
	memcpy(resRecord->rdata,strPointer,len-1);
	printf("size: %d  ",strlen(resRecord->rdata));
	printf("rdata: %s\n",resRecord->rdata); 
	
	/*
	 *拷贝datalength 
	 */
	if(resRecord->type == A_TYPE){
		resRecord->data_len = 4; //永远是4byte
	}
	else if(resRecord->type == CNAME_TYPE){
		resRecord->data_len = strlen(resRecord->rdata)+1;
	}
	else if(resRecord->type == MX_TYPE){
		//这里用现在的域名减去查询的名字长度再+2(pre..)+2(压缩指针)
		resRecord->data_len = strlen(resRecord->rdata)-strlen(recvQuery->name) + 4;
	}
	  
	 //printf("%hu\n",len-1);
}

