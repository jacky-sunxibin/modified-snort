#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/sem.h>

int sem_id;
int set_semvalue(void);
void del_semvalue(void);
int semaphore_p(void);
int semaphore_v(void);
void get_sem(key_t key);
