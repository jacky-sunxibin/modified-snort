#ifndef _MSGQUE_H_
#define _MSGQUE_H_
#include<sys/types.h>
#include<sys/ipc.h>
#include<sys/msg.h>
#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include "LinkList.h"
#define MATCHED_RULE_LENGTH 100
#define ID_COUNT 10;
struct data_node
{
	char key[49];
	long ids[10];
};
struct msgbuf{
        long mtype;        //消息类型,由用户自定义
        struct data_node data;
};
extern LinkList head;
extern int msgId;
//创建与打开消息队列公共函数
int MessageCommon(key_t key,int flag);
//创建全新的消息队列(服务端)
int CreateMessage(key_t qid);
//打开已有的消息队列(客户端)
int GetMessage(key_t qid);
//发送消息
void SendMessage();
//receive message
void ReceiveMessage(int msgid,long* msg,int who);

#endif
