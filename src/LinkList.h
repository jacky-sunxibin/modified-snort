#ifndef _LINKLIST_H_
#define _LINKLIST_H_
#define MAX_MATCHED_RULES 10
#include<stdio.h>
#include<string.h>
#include<stdlib.h>

typedef struct
{
	char key[49];
	long value[MAX_MATCHED_RULES];
}DataType;
typedef struct node{
 DataType data;
 struct node *next;
}Node,*LinkList;
Node* GetLinkList(LinkList head,int i);
void InsertLinkList(LinkList head,DataType x,int i);
LinkList InitiateLinkList();
void AddLinkList(LinkList head,DataType x);
Node* FindLinkList(LinkList head,char value[]);
void RemoveLinkList(LinkList head,char value[]);
void ClearlinkList(LinkList head);
#endif
