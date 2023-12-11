#ifndef DNS_H_
#define DNS_H_
#define DNSMAXLEN 526
#define QR 32768
#define NAME_TO_ADDR 0
#define ADDR_TO_NAME 2048
#define SERV_STAT 4096
#define AA 1024
#define TC 512
#define RD 256
#define RA 128
#define SUCCESS 0
#define FORMAT_ERR 1
#define SERV_ERR 2
#define NOT_EXIST 3
#define FORMAT_NOT_SUPPORT 4
#define POLICY 5
#define A_TYPE 1
#define NS_TYPE 2
#define CNAME_TYPE 5
#define MX_TYPE 15
#define PTR_TYPE 12 

#include<arpa/inet.h>
#include<netinet/in.h>
#include<sys/socket.h>

//DNSHeader 的数据结构 
struct DNS_Header{
	unsigned short id;
	unsigned short tag;
	unsigned short queryNum;
	unsigned short answerNum;
	unsigned short authorNum;
	unsigned short addNum;
};

typedef struct DNS_Header dns_header;

//DNSQuery 数据结构 
struct DNS_Query{
	unsigned char* name;
	unsigned short qtype;
	unsigned short qclass;
};

typedef struct DNS_Query dns_query;

//DNSResponseMessage 数据结构 
struct DNS_RR{
	unsigned char *name;
	unsigned short type;
	unsigned short rclass;
	unsigned int ttl;
	unsigned short data_len;
	unsigned char *rdata;
};

typedef struct DNS_RR dns_rr;

//初始化Heading 
void initHead(dns_header *head){
	head->id=0;
	head->tag=0;
	head->queryNum=0;
	head->answerNum=0;
	head->authorNum=0;
	head->addNum=0;
}

//初始化Query 
void initQuery(dns_query *query){
	//printf("Hello\n"); 
	if(query->name!=NULL){
		printf("hi\n");
		free(query->name);
		query->name=NULL;
	}
	//printf("end\n"); 
	query->qtype=0;
	query->qclass=0;
}

//初始刷RR 
void initRR(dns_rr *rr){
	if(rr->name!=NULL){
		free(rr->name);
		rr->name=NULL;
	}
	if(rr->rdata!=NULL){
		free(rr->rdata);
		rr->rdata=NULL;
	}
	rr->type=0;
	rr->rclass=0;
	rr->ttl=0;
	rr->data_len=0;
}

//下面这两个函数和localServer中的一样，可以考虑打包进.h 
unsigned int getHeader(char *q, dns_header *header){
	
	header->id = ntohs(*(uint16_t*) (q));
	header->tag = ntohs(*(uint16_t*) (q+2));
	header->queryNum = ntohs(*(uint16_t*) (q+4));
	//printf("queryName: %d\n", header->id);
	header->answerNum = ntohs(*(uint16_t*) (q+6));
	header->authorNum = ntohs(*(uint16_t*) (q+8));
	header->addNum = ntohs(*(uint16_t*) (q+10));
	
	return sizeof(dns_header);
}

unsigned int getQuery(char *q, dns_query *query){
	char domainName[100];
	memset(domainName, 0, 100);
	char *d = domainName;
	//printf("d: %s\n", d);
	uint8_t count = 0;
	int i = 0; 
	//count = ntohs(*(uint8_t*)(q));
	//完成报文中数字加域名形式至点分值的转换 
	while(1){
		if(*q!='\0'){
			count = *(uint8_t*)(q);
			//("count:%d\n", count);
			q++;
			while(count){
				//printf("i: %d\n", i);
				//printf("char1:%c\n", *q);
				memcpy(&(domainName[i]), q, sizeof(char));
				//printf("domain name i: %c\n", domainName[i]);
				count--; q++; i++;
			}
			domainName[i] = '.'; //加点 
			i++;
		}
		else{
			domainName[i-1] = '\0'; //标注结束 
			q++; 
			break;
		}
	}
	// printf("i: %d\n", i);  
	// printf("Converted domain name: %s\n", domainName);
	// printf("length: %d\n", i);
	query->name = (char*)malloc(i*sizeof(char));
	memcpy(query->name, domainName, i); //此时的i便为转换后变长字符串的长度了，经过了循环遍历 
	// printf("Query name: %s\n", query->name);
	
	query->qtype = ntohs(*(uint16_t*) (q));
	query->qclass = ntohs(*(uint16_t*) (q+2));
	// printf("Query Type: %d\n", query->qtype);
	// printf("Query Class: %d\n", query->qclass);
	return i+4+1; //补一个1的原因是网络的域名形式和转换后的差一位 
}

unsigned int getRRs(char *q, dns_rr *rRecord){
	uint32_t ipAddr;
	rRecord->ttl = ntohl(*(uint32_t*)(q)); //这里是ntohl，32bit数字的转化 
	char str[INET_ADDRSTRLEN];
	struct in_addr addr;
	//printf("Query Answer TTL: %d\n", rRecord->ttl);
	q+=sizeof(rRecord->ttl);
	rRecord->data_len = ntohs(*(uint16_t*)(q));
	//printf("Data Length: %d\n", rRecord->data_len);
	q+=sizeof(rRecord->data_len);
	//rRecord->rdata = (char*)malloc((rRecord->data_len)*sizeof(char));
	//printf("hello\n");
	if(rRecord->type == MX_TYPE){
		q += 2; //将Preferencre的长度空出去
	}
	
	if(rRecord->type == A_TYPE){
		ipAddr = *(uint32_t*)(q);
		//printf("Query Answer TTL: %d\n", rRecord->ttl);
		memcpy(&addr, &ipAddr, 4);
		char *ptr = inet_ntop(AF_INET, &addr, str, sizeof(str)); //转化为十进制点分值的IP地址
		//printf("Query Answer IP: %s\n", ptr);
		rRecord->rdata = (char*)malloc((strlen(ptr)+1)*sizeof(char));
		strcpy(rRecord->rdata,ptr);
		return 4 + 2 + rRecord->data_len;
	}
	else if(rRecord->type == CNAME_TYPE){
		char domainName[100];
	memset(domainName, 0, 100);
	char *d = domainName;
	//printf("d: %s\n", d);
	uint8_t count = 0;
	int i = 0; 
	//count = ntohs(*(uint8_t*)(q));
	//完成报文中数字加域名形式至点分值的转换 
	while(1){
		if(*q!='\0'){
			count = *(uint8_t*)(q);
			//printf("count:%d\n", count);
			q++;
			while(count){
				//printf("i: %d\n", i);
				//printf("char1:%c\n", *q);
				memcpy(&(domainName[i]), q, sizeof(char));
				//printf("domain name i: %c\n", domainName[i]);
				count--; q++; i++;
			}
			domainName[i] = '.'; //加点 
			i++;
		}
		else{
			domainName[i-1] = '\0'; //标注结束 
			q++; 
			break;
		}
	}
	// printf("i: %d\n", i);  
	// printf("Converted domain name: %s\n", domainName);
	// printf("length: %d\n", i);
	rRecord->rdata = (char*)malloc(i*sizeof(char));
	memcpy(rRecord->rdata, domainName, i); //此时的i便为转换后变长字符串的长度了，经过了循环遍历 
	// printf("Query name: %s\n", rRecord->rdata);
	// 	printf("The CNAME is: %s\n", rRecord->rdata);
		return 4 + 2 + rRecord->data_len +1;
	}
	else if(rRecord->type == MX_TYPE){
		int firstlen = rRecord->data_len - 5;
		char domainName[100];
		memset(domainName, 0, 100);
		char *d = domainName;
		//printf("d: %s\n", d);
		uint8_t count = 0;
		int i = 0; 
	//count = ntohs(*(uint8_t*)(q));
	//完成报文中数字加域名形式至点分值的转换 
		while(1){
		if(*q!='\0'){
			count = *(uint8_t*)(q);
			//printf("count:%d\n", count);
			q++;
			while(count){
				//printf("i: %d\n", i);
				//printf("char1:%c\n", *q);
				memcpy(&(domainName[i]), q, sizeof(char));
				//printf("domain name i: %c\n", domainName[i]);
				count--; q++; i++;
			}
			domainName[i] = '.'; //加点 
			i++;
			domainName[i] = '\0';
			i++;
			break;
		}
	}
	//printf("i: %d\n", i);  
	//printf("Converted domain name: %s\n", domainName);
	//printf("length: %d\n", i);
	strcpy(domainName, strcat(domainName, rRecord->name)); //由于压缩了指针，对两字符串进行拼接
	//printf("Converted domain name: %s\n", domainName);
	int totalen = strlen(rRecord->name) + i; //拼接后总长度
	rRecord->rdata = (char*)malloc(totalen*sizeof(char));
	memcpy(rRecord->rdata, domainName, totalen); 
	//printf("Query name: %s\n", rRecord->rdata);
		//printf("The CNAME is: %s\n", rRecord->rdata);
		return 12+rRecord->data_len;
	}
	
}

unsigned int head2buf(char *o, dns_header *head){
	memcpy(o, head, sizeof(dns_header));
	//////////////////////////////////////////////没转主机字节序！！！！！ 
	return sizeof(dns_header);
}

unsigned int query2buf(char *o, dns_query *query){
	char* ini = o; //for initial
	uint8_t count = 0;
	int i = 0;
	int j = 1; //转换后计数 
	int tempts = 0;
	o++; //先往后移动一位 
	while(1){
		//printf("get: %c\n", query->name[i]);
		if(query->name[i] == '.'){
				memcpy(o-count-1, &count, sizeof(char));
				//printf("Count: %d\n", count);
				count = 0;
				o++; i++;
				tempts = 1;
				
		}
		else if(query->name[i] == '\0'){
			memcpy(o, &(query->name[i]), sizeof(char));
			memcpy(o-count-1, &count, sizeof(char));
			count = 0;
			break;
		}
		else{
			memcpy(o, &(query->name[i]), sizeof(char));
			o++;
			i++;
			count++; 
		}
	}
	o++;
	int len = o - ini; //计算出名字的长度
	//printf("length: %d\n", len); 
	uint16_t temp = htons(query->qtype);
	memcpy(o, &temp, sizeof(short));
	temp = htons(query->qclass);
	o+=sizeof(short);
	memcpy(o, &temp, sizeof(short));
	o+=sizeof(short);
//	int p=0;
//	while(p<=100){
//	printf("buff1: %hu\n", o[p]);
//	p++;
//	}
	//printf("length22: %d\n",  len+2*sizeof(short)); 
	return len+2*sizeof(short);
}

unsigned int rr2buf(char *o, dns_rr* rr) {
	int i = 0;
	uint16_t temp;
	uint32_t temp32;
	temp =  htons(49164); //这里指代1100000000001100，DNS报文中压缩指针的操作
	memcpy(o, &temp, sizeof(short)); 
	
//	printf("rr2leng: %d\n", strlen(rr->name));
//	memcpy(o,rr->name,strlen(rr->name)+1);
//	while(1){
//		printf("ccc: %c\n", o[i]);
//		i++;
//		if(i == 5) break;
//	}
//	printf("rrName: %s\n", o);
	o+=2;
	//printf("flag3\n");
	temp=htons(rr->type);
	memcpy(o, &temp, sizeof(short));
	//printf("rrType: %d\n", rr->type);
	o+=2;
	//printf("flag3\n");
	temp=htons(rr->rclass);
	memcpy(o, &temp, sizeof(short));
	o+=2;
	//printf("flag3\n");
	temp32=htonl(rr->ttl); //这里是htonl 32位数字的主机字节序转化 
	//printf("ttlconvert: %d\n", temp32);
	memcpy(o, &temp32, (2*sizeof(short)));
	o+=4;
	//printf("flag3\n");
	temp=htons(rr->data_len);
	memcpy(o, &temp, sizeof(short));
	o+=2;
	//printf("flag3\n");
	//这里指preference，MX里面要多两个字节哦
	if(rr->type == MX_TYPE){
		temp=htons(1);
		memcpy(o, &temp, sizeof(short));
		o+=2;
	}
	
	if(rr->type == A_TYPE){
		uint32_t  ipAddr = inet_addr(rr->rdata);
		memcpy(o, &ipAddr,rr->data_len); //将字符串转化为网络字节序的4bytes数据 
		//printf("rrDate: %s\n", o);
		o+=rr->data_len; //也就是要移动4位 
		return 16;
	}
	else if(rr->type == CNAME_TYPE){
		char* ini = o; //for initial
	uint8_t count = 0;
	int i = 0;
	int j = 1; //转换后计数 
	int tempts = 0;
	o++; //先往后移动一位 
	while(1){
		//printf("get: %c\n", rr->rdata[i]);
		if(rr->rdata[i] == '.'){
				memcpy(o-count-1, &count, sizeof(char));
				//printf("Count: %d\n", count);
				count = 0;
				o++; i++;
				tempts = 1;
				
		}
		else if(rr->rdata[i] == '\0'){
			memcpy(o, &(rr->rdata[i]), sizeof(char));
			memcpy(o-count-1, &count, sizeof(char));
			count = 0;
			break;
		}
		else{
			memcpy(o, &(rr->rdata[i]), sizeof(char));
			o++;
			i++;
			count++; 
		}
	}
		return 12 + rr->data_len + 1;
	}
	else if(rr->type == MX_TYPE){ //MX的情况
		char* ini = o; //for initial
	uint8_t count = 0;
	int i = 0;
	int j = 1; //转换后计数 
	int tempts = 0;
	o++; //先往后移动一位 
	while(1){
		//printf("get: %c\n", rr->rdata[i]);
		if(rr->rdata[i] == '.'){
				memcpy(o-count-1, &count, sizeof(char));
				//printf("Count: %d\n", count);
				count = 0;
				o++; i++;
				tempts = 1;
				break;
				
		}
		else if(rr->rdata[i] == '\0'){
			memcpy(o, &(rr->rdata[i]), sizeof(char));
			memcpy(o-count-1, &count, sizeof(char));
			count = 0;
			break;
		}
		else{
			memcpy(o, &(rr->rdata[i]), sizeof(char));
			o++;
			i++;
			count++; 
		}
	}
	o--;
	//printf("i=%d\n", i);
	temp =  htons(49164); //这里指代1100000000001100，DNS报文中压缩指针的操作
	memcpy(o, &temp, sizeof(short)); 
	return 16+i;
	}
	
	
}

//用于MX的ip查询，放到addtion里面
unsigned int add2buf(char *o, dns_rr* rr, dns_query* query) {
	//printf("add2buf rrdata: %s\n", rr->rdata);
	//printf("datalength: %d\n", strlen(rr->rdata));
	int i = 0;
	uint16_t temp;
	uint32_t temp32;
	temp =  htons(49152+12+strlen(query->name)+2+4+14); //这里指代1100000000001100，DNS报文中压缩指针的操作
	memcpy(o, &temp, sizeof(short)); 
//	printf("rr2leng: %d\n", strlen(rr->name));
//	memcpy(o,rr->name,strlen(rr->name)+1);
//	while(1){
//		printf("ccc: %c\n", o[i]);
//		i++;
//		if(i == 5) break;
//	}
//	printf("rrName: %s\n", o);
	o+=2;
	temp=htons(rr->type);
	memcpy(o, &temp, sizeof(short));
	//printf("rrType: %d\n", rr->type);
	o+=2;

	temp=htons(rr->rclass);
	memcpy(o, &temp, sizeof(short));
	o+=2;

	temp32=htonl(rr->ttl); //这里是htonl 32位数字的主机字节序转化 
	//printf("ttlconvert: %d\n", temp32);
	memcpy(o, &temp32, (2*sizeof(short)));
	o+=4;

	temp=htons(rr->data_len);
	memcpy(o, &temp, sizeof(short));
	o+=2;

	
	
	uint32_t  ipAddr = inet_addr(rr->rdata);
	memcpy(o, &ipAddr, rr->data_len); //将字符串转化为网络字节序的4bytes数据 
	//printf("rrDate: %d\n", ipAddr);
	o+=rr->data_len; //也就是要移动4位 
	return 16;
}

// 比较cache与query中的部分内容，以对应是否为匹配的RR
unsigned int cmpTypeClass( unsigned short type, char *col){
	// printf("%s",col);
	switch (type)
	{
	case A_TYPE:
		if (strcmp(col, "A")==0)
			return 1;
		break;
	case MX_TYPE:
		if (strcmp(col, "MX")==0)
			return 1;
		break;
	case CNAME_TYPE:
		if (strcmp(col, "CNAME")==0)
			return 1;
		break;
	
	default:
		printf("no this type!!");
		return 0;
		break;
	}
	return 0;
}

unsigned int cmpDomainName( char *name,  char *col){
	// printf("%s", name);
	// printf("%s", col);
	int len = strlen(name);
	int i=0;
	// printf("%d\n",len);
	while(i<len){
		// printf("namei: %c\n",name[i]);
		// printf("coli: %c\n",col[i]);
		if(name[i]!=col[i])
		{return 0;}
		i++;
	}
	if(col[i]!=' ') return 0; // 说明域名后面还有东西，一般不会出现吧
	else return len+1;  
}

unsigned int cmpRR( dns_query *query,  char *col){
	unsigned int offset = 0;
	char str[20]="";
	// printf("in cmp\n");
	if(offset = cmpDomainName(query->name,col)){
		// printf("in if 1\n");
		switch (query->qtype)
		{
		case A_TYPE:
			strncpy(str,col+offset,1);
			str[1]='\0';
			break;
		case MX_TYPE:
			strncpy(str,col+offset,2);
			str[2]='\0';
			break;
		case CNAME_TYPE:
			strncpy(str,col+offset,5);
			str[5]='\0';
			break;
		
		default:
			printf("no this type!!");
			break;
		}
 		if(cmpTypeClass(query->qtype, str))
			return 1;
	}
	return 0;
}

//others
void init_sockaddr_in(char* ip, int port, struct sockaddr_in* addr){
    addr->sin_family = AF_INET;
    addr->sin_port = htons(port);
    addr->sin_addr.s_addr=inet_addr(ip);
    memset(addr->sin_zero, 0, sizeof(addr->sin_zero));
}

int isequal(char *str1, char* str2)
{
    if (strlen(str1)!=strlen(str2))
     return 0;
     int i=0;
    for (i = 0; str1[i]!='\0'; i++){
        if (str1[i]!=str2[i])
        return 0;
     }
   return 1;
}

#endif
