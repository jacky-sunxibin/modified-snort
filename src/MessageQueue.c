#include "MessageQueue.h"
//创建与打开消息队列公共函数
int MessageCommon(key_t key,int flag){
    int ret = 0;
    if((ret=msgget(key,flag))==-1){
        perror("msgget:");
        exit(-1);
    }
    return ret;
}
//创建全新的消息队列(服务端)
int CreateMessage(key_t qid){
        //消息队列也是具有权限结构的,因此在创建时给666权限
    return MessageCommon(qid,IPC_CREAT|0666);
}
//打开已有的消息队列(客户端)
int GetMessage(key_t qid){
    return MessageCommon(qid,IPC_CREAT);
}




//发送消息
void SendMessage(){

	/*LinkList p;
	p=head;
	while(p->next!=NULL)
	{
		struct msgbuf buf;
		buf.mtype = 1;
		p = p->next;
		strcpy(buf.data.key, p->data.key);
		//memcpy(buf.data.ids, p->data.value, sizeof(long) * 10);
		int j;
		for (j = 0; j < 10; j++) {
			buf.data.ids[j] = p->data.value[j];
		}
		if (msgsnd(msgId, &buf, sizeof(buf.data), -1) == -1) {
			perror("msgsnd");
			// DestoryMessage(msgid);
			exit(-2);
		}*/
	//}

   /*LinkList p;
   p=head;
   int i=0,j,k;
   struct msgbuf buf;*/
 //  buf.mtype=1;
   //int flag=0;
   //char msg[1000];
  /* while(p->next!=NULL)
   {
	   p=p->next;

		struct msg_node msg;
		strcpy(msg.key, p->data.key);
		memcpy(msg.value, p->data.value, sizeof(long) * 10);
		buf.data[i] = msg;
		i++;
   }
   if(head->next!=NULL)
   {
	   if (msgsnd(msgId, &buf, sizeof(buf.data), -1) == -1) {
	   			perror("msgsnd");
	   			// DestoryMessage(msgid);
	   			exit(-2);
	   		}
   }*/
/*
	   flag=1;
      p=p->next;
      strcat(msg,"\n---------\n");
      strcat(msg,"packetInfo:");
      strcat(msg,p->data.key);
      strcat(msg,"\nconflict rules ids:");
      for(j=0;j<10;j++)
      {
    	if(p->data.value[j]==0)
    		break;
        long id=p->data.value[j];
			char* szBuffer = (char *) malloc(sizeof(long) + 1);  //分配动态内存
			memset(szBuffer, 0, sizeof(long) + 1);              //内存块初始化
			sprintf(szBuffer, "%ld", id);                  //整数转化为字符串
			strcat(msg, szBuffer);
			free(szBuffer);
			strcat(msg, ",");

      }
      strcat(msg,"\n---------\n");

      i++;*/
  // }
    /*if(flag)
    {
    	strcpy(buf.data,msg);

		if (msgsnd(msgId, &buf, sizeof(buf.data), -1) == -1) {
			perror("msgsnd");
			// DestoryMessage(msgid);
			exit(-2);
		}
    }*/

}
void ReceiveMessage(int msgid,long* msg,int who){

}

