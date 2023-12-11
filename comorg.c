#include<stdio.h>
#include<sys/types.h>
#include<string.h>
#include<unistd.h>
#include<stdlib.h>
#include<stdint.h>
#include "DNS.h"

#define LINE     10
#define DNS_MAX_LENGTH 1023


int main(){
	int state=0;  //查到没有 
	int sockup;
	struct sockaddr_in localAddr;
	struct sockaddr_in upAddr;
	struct sockaddr_in downAddr;
	unsigned int upAddrLen;
	char upInBuffer[DNS_MAX_LENGTH];
	char upOutBuffer[DNS_MAX_LENGTH];
	unsigned short port=53;
	int recvMsgSize;
	int outMsgSize; 
	char ipAddr[100];
	//不需要分割名字，因为已经是最底层服务器，拿文件查询即可 
	
	//接受的结构体 
	dns_query *recvQuery = (dns_query *)malloc(sizeof(dns_query));initQuery(recvQuery);
	dns_header *recvHead = (dns_header *)malloc(sizeof(dns_header));initHead(recvHead);
	dns_rr *recvrRecord = (dns_rr *)malloc(sizeof(dns_rr));initRR(recvrRecord);  
	//回应的结构体 
	dns_query *resQuery = (dns_query *)malloc(sizeof(dns_query));initQuery(resQuery);
	dns_header *resHead = (dns_header *)malloc(sizeof(dns_header));initHead(resHead);
	dns_rr *resRecord = (dns_rr *)malloc(sizeof(dns_rr));initRR(resRecord);
	//MX第二次查询ip
	dns_query *mxQuery = (dns_query *)malloc(sizeof(dns_query));initQuery(mxQuery);
	dns_header *mxHead = (dns_header *)malloc(sizeof(dns_header));initHead(mxHead);
	dns_rr *mxRecord = (dns_rr *)malloc(sizeof(dns_rr));initRR(mxRecord);
	
	//创建socket套接字
	if((sockup=socket(PF_INET,SOCK_STREAM,0))<0)  
        printf("socket() failed\n");
	
	init_sockaddr_in("127.0.0.4", 53, &localAddr);
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
        state=0;

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

        //receive
        if(recvMsgSize=recv(confd,upInBuffer,DNS_MAX_LENGTH,0)<0){
            printf("recvfrom() failed\n");
        }
        printf("Handling client %s\n",inet_ntoa(upAddr.sin_addr));
        
        //解析
        char *i = upInBuffer + 2;
        i += getHeader(i, recvHead);
        i += getQuery(i, recvQuery); 	
        printf("The domain name is: %s\n", recvQuery->name);
        
        //以下为回应的部分
        resHead->id =htons(recvHead->id);
        resHead->tag =htons(0x8000);
        resHead->queryNum =htons(recvHead->queryNum);
        resHead->answerNum = htons(1); //这里不一定是1，若没查到怎么办？？ 
        resHead->authorNum = 0;
        resHead->addNum = 0;
        resQuery = recvQuery;
        resRecord->name=recvQuery->name;
        resRecord->rclass=recvQuery->qclass;
        resRecord->type=recvQuery->qtype;
        resRecord->ttl = (uint32_t)86400;
        resRecord->data_len = 4;
        
        //printf("recvQuery->qType: %d\n",recvQuery->qtype);
        /*
        *返回查询结果 
        */
        printf("In file 'comorg.txt'\n");
        FILE *fp=freopen("comorg.txt", "r", stdin);
        char file_name[255],file_ttl[255],file_class[255],file_type[255],file_data[255];
            while(~scanf("%s%s%s%s%s", file_name, file_ttl, file_class,file_type,file_data)){
                // if(cmpTypeClass(recvQuery->qtype,file_type))
                //     printf("dasfsadas");
                // printf("file_name: %s.,file type: %s\n",file_name,file_type);
                // printf("recv-qtype:%d\n",recvQuery->qtype);
                // printf("%d %d\n",isequal(recvQuery->name,file_name),cmpTypeClass(recvQuery->qtype,file_type));
                if((isequal(recvQuery->name,file_name))&&cmpTypeClass(recvQuery->qtype,file_type)){
                    printf("file_name: %s\n",file_name);
                    printf("file_name length: %d\n",strlen(file_name));
                    printf("file_ttl: %s\n",file_ttl);
                    printf("file_class: %s\n",file_class);
                    printf("file_type: %s\n",file_type);
                    printf("file_ip: %s\n",file_data);
                    //不确定你从文件里读出来的是什么样子的，含不含空格，长度下面有可能不对

                    resRecord->name = (char*)malloc((strlen(file_name)+1)*sizeof(char));
                    strcpy(resRecord->name, file_name);
                    resRecord->ttl = (uint32_t)(atoi(file_ttl));
                    resRecord->rdata = (char*)malloc((strlen(file_data)+1)*sizeof(char));
                    strcpy(resRecord->rdata, file_data);
                    resHead->answerNum = htons(1);
                    resRecord->data_len=strlen(resRecord->rdata)+1;
                    resHead->tag = htons(0x8180);

                    printf("recv->Query: %s\n",recvQuery->name);
                    //在结构体里把rdata赋值为 file_ip ,在head里把anwernum赋值为1，flag为8180 
                    state=1;   //表明查到 
                    break;
                }
            }
        fclose(fp);   

        if((state==1)&&(recvQuery->qtype == MX_TYPE)){
            //这里用现在的域名减去查询的名字长度再+2(pre..)+2(压缩指针)  ！！！覆盖掉上面定义的
		    resRecord->data_len = strlen(resRecord->rdata)-strlen(recvQuery->name) + 4;

            mxQuery->name = (char*)malloc((strlen(resRecord->rdata)+1)*sizeof(char));
            strcpy(mxQuery->name, resRecord->rdata);
            //printf("mxQueryName: %s\n", mxQuery->name);
            mxQuery->qclass = recvQuery->qclass;
            mxQuery->qtype = A_TYPE; //这里要用上一次的结果A方式查询一下
            FILE *fp1=freopen("comorg.txt", "r", stdin);
            char file_ip[255];
            while(~scanf("%s%s%s%s%s", file_name, file_ttl, file_class,file_type,file_ip)){
                if(isequal(mxQuery->name,file_name)){
                    printf("file_name: %s\n",file_name);
                    printf("file_name length: %d\n",strlen(file_name));
                    printf("file_ttl: %s\n",file_ttl);
                    printf("file_class: %s\n",file_class);
                    printf("file_type: %s\n",file_type);
                    printf("file_ip: %s\n",file_ip);
                    //不确定你从文件里读出来的是什么样子的，含不含空格，长度下面有可能不对	
                    mxRecord->name = (char*)malloc((strlen(file_name)+1)*sizeof(char));
                    strcpy(mxRecord->name, file_name);
                    mxRecord->ttl = (uint32_t)(atoi(file_ttl));
                    mxRecord->rdata = (char*)malloc((strlen(file_data)+1)*sizeof(char));
                    strcpy(mxRecord->rdata, file_ip);
                    mxRecord->data_len=4;
                    mxRecord->type=A_TYPE; 
                    mxRecord->rclass=recvQuery->qclass;
                    resHead->addNum = htons(1); 

                    //printf("recv->Query: %s\n",recvQuery->name);
                    //在结构体里把rdata赋值为 file_ip ,在head里把anwernum赋值为1，flag为8180 
                    state=1;   //表明查到 
                    break;
                }
            }
            fclose(fp1);
        }
        	  
        //printf("state %d\n",state);
        char* o=upOutBuffer;
        //查不到的情况
        if(state==0){
            //printf("1\n");
            resHead->tag =htons(0x8183);
            //printf("2\n");
            resHead->answerNum = 0;
            //printf("3\n");
            o = upOutBuffer+2; 
            //printf("4\n");
            o += head2buf(o, resHead);
            //printf("5\n");
            o += query2buf(o,resQuery);
            //在结构体里把rdata赋值为找不到 ,在head里把anwernum赋值为 1，flag为8183 
        }else{
            o = upOutBuffer+2; 
            o += head2buf(o, resHead);
            o += query2buf(o,resQuery); 
            o += rr2buf(o,resRecord);
            if(recvQuery->qtype == MX_TYPE)
                o+=add2buf(o, mxRecord, recvQuery);
        }

        //统一返回
        //把upOutBuffer赋值 
        outMsgSize = o - upOutBuffer + 1 -2;
        uint16_t temp = htons(outMsgSize);
        memcpy(upOutBuffer,&temp,sizeof(short));

        printf("length:%d \n",outMsgSize);
        if(send(confd,upOutBuffer,outMsgSize+2,0)<0){
            printf("sendto() problem!\n");
        }
	}	

}

