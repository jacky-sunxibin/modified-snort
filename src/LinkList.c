#include "LinkList.h"

Node* FindLinkList(LinkList head,char value[])
{
	Node *p,*q=NULL;
	p=head;
	while(p->next!=NULL)
	{
		p=p->next;
		if (strcmp(p->data.key,value) == 0)
		{
			q=p;
		}
	}
	return q;
}

void RemoveLinkList(LinkList head,char value[])
{
	Node *p, *q = NULL;
	p = head;
	while (p->next != NULL) {
		q = p->next;
		if (strcmp(q->data.key, value) == 0) {
			p->next=q->next;
			free(q);
			break;
		}
		p=q;
	}
}

void AddLinkList(LinkList head,DataType x)
{
	int i,j,k;
	long tempValue;
	Node *q=NULL;
	q=FindLinkList(head,x.key);
	if(q!=NULL)
	{
        for(i=0;i<MAX_MATCHED_RULES;i++)
        {
        	tempValue=x.value[i];
        	j=0;
        	while(j<MAX_MATCHED_RULES)
        	{
        		if(tempValue==q->data.value[j])
        		{
        			break;
        		}
        		j++;
        	}
        	if(j>=MAX_MATCHED_RULES)
        	{
        		for(k=0;k<MAX_MATCHED_RULES;k++)
        		{
        			if(q->data.value[k]==0)
        			{
        				q->data.value[k]=tempValue;
        				break;
        			}
        		}
        	}

        }
	}
	else
	{
		InsertLinkList(head,x,1);
	}
}
Node* GetLinkList(LinkList head,int i)
{
	Node* p;
	int c=1;
	p=head->next;
	while(c<i&&p!=NULL)
	{
		p=p->next;
		c++;
	}
	if(c==i) return p;
	else return NULL;
}
void ClearlinkList(LinkList head)
{
	Node *p,*q;
	p=head;
	while(p->next!=NULL)
	{
		q=p->next;
		p->next=q->next;
		free(q);
	}
}
void InsertLinkList(LinkList head,DataType x,int i)
{
	Node *p,*q;
    if(i==1) q=head;
	else q=GetLinkList(head,i-1);
	if(q==NULL)
	{
       printf("find not insert place!");
	}
	else
	{
         p=malloc(sizeof(Node));
		 p->data=x;
		 p->next=q->next;
		 q->next=p;
	}
}

LinkList InitiateLinkList()
{
	LinkList head;
	head=malloc(sizeof(Node));
	head->next=NULL;
	return head;
}
