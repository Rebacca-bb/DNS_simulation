#include<stdio.h>
#include<sys/types.h>
#include<string.h>

#include<unistd.h>
#include<stdlib.h>
#include<stdint.h>
#include "DNS.h"

#define LINE     10
#define DNS_MAX_LENGTH 1023

void splitOneDomainName(char *domainName, char *splitName);

int main(){
	int sockup;
	struct sockaddr_in localAddr;
	struct sockaddr_in upAddr;
	unsigned int upAddrLen;
	char upInBuffer[DNS_MAX_LENGTH];
	char upOutBuffer[DNS_MAX_LENGTH];
	char splitName[100];
	char ipAddr[100];
	dns_query *recvQuery = (dns_query *)malloc(sizeof(dns_query));initQuery(recvQuery);
	dns_header *recvHead = (dns_header *)malloc(sizeof(dns_header));initHead(recvHead);
	//回应的结构体 
	dns_query *resQuery = (dns_query *)malloc(sizeof(dns_query));initQuery(resQuery);
	dns_header *resHead = (dns_header *)malloc(sizeof(dns_header));initHead(resHead);
	dns_rr *resRecord = (dns_rr *)malloc(sizeof(dns_rr));initRR(resRecord);
	unsigned short port=53;
	int recvMsgSize;
	int outMsgSize; 
	char *i;
	char *o;

	//创建socket套接字
	if((sockup=socket(PF_INET,SOCK_STREAM,0))<0)  
        printf("socket() failed\n");
	
	init_sockaddr_in("127.0.0.3", 53, &localAddr);
	if((bind(sockup,(struct sockaddr*)&localAddr,sizeof(localAddr)))<0){
		printf("bind() failed\n");
	} 

    //通过调用listen将套接字设置为监听模式
	int lis=0;
	lis=listen(sockup,LINE);
	if(lis<0)
	{
		printf("listen failed");
		close(sockup);
		return -1;
	}
	printf("Listen to the client 'local server'\n");

	while(1){
        //服务器等待客户端连接中，游客户端连接时调用accept产生一个新的套接字
        int confd=0;
        upAddrLen=sizeof(upAddr);
        confd=accept(sockup,(struct sockaddr *)&upAddr,&upAddrLen);
        if(confd<0)
        {
            printf("accept failed");
            close(sockup);
            return -1;
        }
        printf("Connect with Client successfully!\n");
        printf("IP=%s, PORT=%u\n",inet_ntoa(upAddr.sin_addr),ntohs(upAddr.sin_port));

        //调用recv接收客户端（local server）的消息
        if(recvMsgSize=recv(confd,upInBuffer,DNS_MAX_LENGTH,0)<0){
            printf("recvfrom() failed\n");
        }
        printf("Handling client %s\n",inet_ntoa(upAddr.sin_addr)); // inet_ntoa() 将网络地址转换成“.”点隔的字符串格式
               
        //解析localServer传过来的数据 
        i = upInBuffer+2;
        i += getHeader(i, recvHead);
        i += getQuery(i, recvQuery); 	
        printf("The domain name is: %s\n", recvQuery->name);
        //printf("The First Class Name is: %s\n", splitOneDomainName(recvQuery->name));
        splitOneDomainName(recvQuery->name, splitName);
        
        //解析部分至上就结束了，以下为回应部分
        resHead->id =htons(recvHead->id);
        resHead->tag =htons(0x8000);
        resHead->queryNum =htons(recvHead->queryNum);
        resHead->answerNum = htons(1); //这里不一定是1，若没查到怎么办？？ 
        resHead->authorNum = 0;
        resHead->addNum = 0;
        resQuery = recvQuery;
        resRecord->name=recvQuery->name;
        resRecord->rclass=recvQuery->qclass;
        resRecord->type=A_TYPE;
        resRecord->ttl = (uint32_t)86400;
        resRecord->data_len = 4;
        
        //printf("compare:  %s\n",splitName);
        int tf=isequal(splitName,"com");
        //printf("bbbbbb: %d\n",tf);
        tf=isequal(splitName,"org");
        //printf("basafds: %d\n",tf);
        /*
        *返回一级域ip 
        */
        if(isequal(splitName,"com")||isequal(splitName,"org")){
            //在结构体里把rdata赋值为ip（127.0.0.4） ,在head里把anwernum赋值为0 
            //printf("hello, in org!\n");
            strcpy(ipAddr, "127.0.0.4");
        // printf("hello,%s\n", ipAddr);
            char *p = ipAddr;
            int len = strlen(ipAddr)+1;
            resRecord->rdata=(char*)malloc(len*sizeof(char));
            //printf("hello, in org!\n");
            memcpy(resRecord->rdata,p,len);
            //printf("resRecordDataL %s\n", resRecord->rdata);
        // printf("hello, in org!\n");
            //strcpy(resRecord->rdata, "127.0.0.4");
            o = upOutBuffer+2; 
            o += head2buf(o, resHead);
            o += query2buf(o,resQuery); 
            o += rr2buf(o,resRecord);
            
            
        }
        else if(isequal(splitName,"cn")||isequal(splitName,"us")){
            //在结构体里把rdata赋值为ip（127.0.0.5）,在head里把anwernum赋值为0
            strcpy(ipAddr, "127.0.0.5");
            char *p = ipAddr;
            int len = strlen(ipAddr)+1;
            resRecord->rdata=(char*)malloc(len*sizeof(char));
            //printf("hello, in org!\n");
            memcpy(resRecord->rdata,p,len);
            //printf("resRecordDataL %s\n", resRecord->rdata);
            o = upOutBuffer+2; 
            o += head2buf(o, resHead);
            o += query2buf(o,resQuery); 
            o += rr2buf(o,resRecord);
            //int p = 0;
            // while(1){
            // printf("%hu\n", upOutBuffer[p]);
            // p++;
            // if(p>100) break;
            // }
            // printf("\n");
        } 
        else{
            resHead->answerNum = 0;
            resHead->tag =htons(0x8183);
            o = upOutBuffer+2; 
            o += head2buf(o, resHead);
            o += query2buf(o,resQuery); 
            //rdata无数值，anwernum为0
            //查询失败 
        } 
        
        //send
        outMsgSize=o-upOutBuffer+1-2;
        uint16_t temp = htons(outMsgSize);
        memcpy(upOutBuffer,&temp,sizeof(short));
        //printf("length:%d \n",outMsgSize);
        if(send(confd,upOutBuffer,outMsgSize+2,0)<0){
            printf("sendto() problem!\n");
        }
	}	
}

void splitOneDomainName(char *domainName, char *splitName){
	int i = strlen(domainName)-1; //免去\0的影响 
	//printf("domainName: %s\n", domainName);
	int j = 0;
	int k = 0;
	char invertName[100];
	char splitOneName[100];
	memset(invertName, 0, 100);
	memset(splitOneName, 0, 100);
    // 找域名的顶级域 反着的
	while(1){
		if(domainName[i]!='.'){
			//printf("d: %c\n", domainName[i]);
			invertName[j] = domainName[i];
			//printf("s: %c\n", invertName[j]);
			i--;j++; 
		}else break;
	}
	invertName[j] = '\0';
	//printf("splitOneInvert: %s\n", invertName);
    // 把找到的顶级域 正着
	i = strlen(invertName)-1;
	while(1){
		if(k < strlen(invertName)){
			////printf("s: %c\n", invertName[i]);
			splitName[k] = invertName[i];
			i--; k++;
		}else break;
		
	}
	splitName[k] = '\0';
	
	//printf("splitOne: %s\n", splitName);
}

