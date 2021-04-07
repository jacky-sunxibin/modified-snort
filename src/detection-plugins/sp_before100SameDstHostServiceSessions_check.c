

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <stdlib.h>
#include <ctype.h>

#include "sf_types.h"
#include "rules.h"
#include "treenodes.h"
#include "decode.h"
#include "plugbase.h"
#include "parser.h"
#include "snort_debug.h"
#include "util.h"
#include "plugin_enum.h"

#include "snort.h"
#include "profiler.h"
#ifdef PERF_PROFILING
PreprocStats before100SameDstHostServiceSessionsPerfStats;
extern PreprocStats ruleOTNEvalPerfStats;
#endif
#include "detection_options.h"
#include "session_common.h"
#define BEFORE100SAMEDSTHOSTSERVICESESSIONS_EQ                   1
#define BEFORE100SAMEDSTHOSTSERVICESESSIONS_GT                   2
#define BEFORE100SAMEDSTHOSTSERVICESESSIONS_LT                   3
#define BEFORE100SAMEDSTHOSTSERVICESESSIONS_RANGE                4
#define BEFORE100SAMEDSTHOSTSERVICESESSIONS_GTANDEQ              5
#define BEFORE100SAMEDSTHOSTSERVICESESSIONS_LTANDEQ              6

typedef struct _Before100SameDstHostServiceSessionsCheckData
{
    int dsize;
    int dsize2;
    char operator;
} Before100SameDstHostServiceSessionsCheckData;



void Before100SameDstHostServiceSessionsCheckInit(struct _SnortConfig *, char *, OptTreeNode *, int);
void ParseBefore100SameDstHostServiceSessions(struct _SnortConfig *,char *, OptTreeNode *);
int Before100SameDstHostServiceSessionsCheck(void *option_data, Packet *p);


uint32_t Before100SameDstHostServiceSessionsCheckHash(void *d)
{
    uint32_t a,b,c;

     //NO data stored for the option

    a = RULE_OPTION_TYPE_BEFORE100SAMEDSTHOSTSERVICESESSIONS;
    b = 0;
    c = 0;

    final(a,b,c);

    return c;
}

int Before100SameDstHostServiceSessionsCheckCompare(void *l, void *r)
{
	Before100SameDstHostServiceSessionsCheckData *left = (Before100SameDstHostServiceSessionsCheckData *)l;
	Before100SameDstHostServiceSessionsCheckData *right = (Before100SameDstHostServiceSessionsCheckData *)r;

	    if (!left || !right)
	        return DETECTION_OPTION_NOT_EQUAL;

	    if (( left->dsize == right->dsize) &&
	        ( left->dsize2 == right->dsize2) &&
	        ( left->operator == right->operator))
	    {
	        return DETECTION_OPTION_EQUAL;
	    }

	    return DETECTION_OPTION_NOT_EQUAL;
}
void SetupBefore100SameDstHostServiceSessionsCheck(void)

{
    /* map the keyword to an initialization/processing function */
    RegisterRuleOption("before100SameDstHostServiceSessions", Before100SameDstHostServiceSessionsCheckInit, NULL, OPT_TYPE_DETECTION, NULL);
#ifdef PERF_PROFILING
    RegisterPreprocessorProfile("before100SameDstHostServiceSessions", &before100SameDstHostServiceSessionsPerfStats, 3, &ruleOTNEvalPerfStats);
#endif
    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Plugin: Before100SameDstHostServiceSessions Check Initialized\n"););
}

void Before100SameDstHostServiceSessionsCheckInit(struct _SnortConfig *sc, char *data, OptTreeNode *otn, int protocol)
{
    OptFpList *fpl;
    void *ds_ptr_dup;

    /* multiple declaration check */
    if(otn->ds_list[PLUGIN_BEFORE100SAMEDSTHOSTSERVICESESSIONS_CHECK])
    {
        FatalError("%s(%d): Multiple before100SameDstHostServiceSessions options in rule\n", file_name,
                file_line);
    }

    /* allocate the data structure and attach it to the
       rule's data struct list */
    otn->ds_list[PLUGIN_BEFORE100SAMEDSTHOSTSERVICESESSIONS_CHECK] = (Before100SameDstHostServiceSessionsCheckData *)SnortAlloc(sizeof(Before100SameDstHostServiceSessionsCheckData));

    /* this is where the keyword arguments are processed and placed into the
       rule option's data structure */
    ParseBefore100SameDstHostServiceSessions(sc,data, otn);
}

void ParseBefore100SameDstHostServiceSessions(struct _SnortConfig *sc,char *data, OptTreeNode *otn)
{

	Before100SameDstHostServiceSessionsCheckData *ds_ptr;  /* data struct pointer */
	    char *pcEnd;
	    char *pcTok;
	    int  iDsize = 0;
	    void *ds_ptr_dup;
	    OptFpList *fpl;

	    /* set the ds pointer to make it easier to reference the option's
	       particular data struct */
	    ds_ptr = (Before100SameDstHostServiceSessionsCheckData *)otn->ds_list[PLUGIN_BEFORE100SAMEDSTHOSTSERVICESESSIONS_CHECK];

	    while(isspace((int)*data)) data++;

	    /* If a range is specified, put min in ds_ptr->dsize and max in
	       ds_ptr->dsize2 */

	    if(isdigit((int)*data) && strchr(data, '<') && strchr(data, '>'))
	    {
	        pcTok = strtok(data, " <>");
	        if(!pcTok)
	        {
	            /*
	            **  Fatal
	            */
	            FatalError("%s(%d): Invalid 'before100SameDstHostServiceSessions' argument.\n",
	                       file_name, file_line);
	        }

	        iDsize = strtol(pcTok, &pcEnd, 10);
	        if(iDsize < 0 || *pcEnd)
	        {
	            FatalError("%s(%d): Invalid 'before100SameDstHostServiceSessions' argument.\n",
	                       file_name, file_line);
	        }

	        ds_ptr->dsize = (unsigned short)iDsize;

	        pcTok = strtok(NULL, " <>");
	        if(!pcTok)
	        {
	            FatalError("%s(%d): Invalid 'before100SameDstHostServiceSessions' argument.\n",
	                       file_name, file_line);
	        }

	        iDsize = strtol(pcTok, &pcEnd, 10);
	        if(iDsize < 0 || *pcEnd)
	        {
	            FatalError("%s(%d): Invalid 'before100SameDstHostServiceSessions' argument.\n",
	                       file_name, file_line);
	        }

	        ds_ptr->dsize2 = (unsigned short)iDsize;

	        ds_ptr->operator = BEFORE100SAMEDSTHOSTSERVICESESSIONS_RANGE;

	#ifdef DEBUG_MSGS
	        DebugMessage(DEBUG_PLUGIN, "min twoSecondsSameDstHostServiceSessions: %d\n", ds_ptr->dsize);
	        DebugMessage(DEBUG_PLUGIN, "max twoSecondsSameDstHostServiceSessions: %d\n", ds_ptr->dsize2);
	#endif
	        fpl = AddOptFuncToList(Before100SameDstHostServiceSessionsCheck, otn);
	        fpl->type = RULE_OPTION_TYPE_BEFORE100SAMEDSTHOSTSERVICESESSIONS;

	        if (add_detection_option(sc, RULE_OPTION_TYPE_BEFORE100SAMEDSTHOSTSERVICESESSIONS, (void *)ds_ptr, &ds_ptr_dup) == DETECTION_OPTION_EQUAL)
	        {
	            free(ds_ptr);
	            ds_ptr = otn->ds_list[PLUGIN_BEFORE100SAMEDSTHOSTSERVICESESSIONS_CHECK] = ds_ptr_dup;
	        }
	        fpl->context = ds_ptr;

	        return;
	    }
	    else if(*data == '>')
	    {
	        data++;
	        if(*data=='='){
	        	ds_ptr->operator = BEFORE100SAMEDSTHOSTSERVICESESSIONS_GTANDEQ;
	        	data++;
	        }else{
	        	ds_ptr->operator = BEFORE100SAMEDSTHOSTSERVICESESSIONS_GT;
	        }
	        fpl = AddOptFuncToList(Before100SameDstHostServiceSessionsCheck, otn);
	    }
	    else if(*data == '<')
	    {
	        data++;
	        if(*data=='='){
	        	ds_ptr->operator = BEFORE100SAMEDSTHOSTSERVICESESSIONS_LTANDEQ;
	        	data++;
	        }else{
	        	ds_ptr->operator = BEFORE100SAMEDSTHOSTSERVICESESSIONS_LT;
	        }
	        fpl = AddOptFuncToList(Before100SameDstHostServiceSessionsCheck, otn);

	    }
	    else
	    {
	        fpl = AddOptFuncToList(Before100SameDstHostServiceSessionsCheck, otn);
	        ds_ptr->operator = BEFORE100SAMEDSTHOSTSERVICESESSIONS_EQ;
	    }

	    fpl->type = RULE_OPTION_TYPE_BEFORE100SAMEDSTHOSTSERVICESESSIONS;

	    while(isspace((int)*data)) data++;

	    iDsize = strtol(data, &pcEnd, 10);
	    if(iDsize < 0 || *pcEnd)
	    {
	        FatalError("%s(%d): Invalid 'before100SameDstHostServiceSessions' argument.\n",
	                   file_name, file_line);
	    }

	    ds_ptr->dsize = (unsigned short)iDsize;

	    if (add_detection_option(sc, RULE_OPTION_TYPE_BEFORE100SAMEDSTHOSTSERVICESESSIONS, (void *)ds_ptr, &ds_ptr_dup) == DETECTION_OPTION_EQUAL)
	    {
	        free(ds_ptr);
	        ds_ptr = otn->ds_list[PLUGIN_BEFORE100SAMEDSTHOSTSERVICESESSIONS_CHECK] = ds_ptr_dup;
	     }
	     fpl->context = ds_ptr;

	    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "BEFORE100SAMEDSTHOSTSERVICESESSIONS length = %d\n", ds_ptr->dsize););
}

long getBefore100SameDstHostServiceSessionsByPakcet(Packet *p){
	long before100SameHostService=0;
	SessionKey key;
	SessionControlBlock *scb = NULL;
    scb=(SessionControlBlock *)(p->ssnptr);
	if (scb != NULL) {
		scb->flagTrackConnection=1;
		before100SameHostService=scb->before_100_same_host_and_server;
		}
	   //printf("before100SameHostService=%ld, sp=%d,dp=%d\n",before100SameHostService,p->sp,p->dp);
	   return before100SameHostService;
	}

int Before100SameDstHostServiceSessionsCheck(void *option_data, Packet *p)
{
	Before100SameDstHostServiceSessionsCheckData *ds_ptr = (Before100SameDstHostServiceSessionsCheckData *)option_data;
	    int rval = DETECTION_OPTION_NO_MATCH;
	    PROFILE_VARS;

	    if (!ds_ptr)
	        return rval;

	    PREPROC_PROFILE_START(before100SameDstHostServiceSessionsPerfStats);

        long before100SameHostService=getBefore100SameDstHostServiceSessionsByPakcet(p);
       // printf("spantime=%ld\n",spanTime);
	    switch (ds_ptr->operator)
	    {
	        case BEFORE100SAMEDSTHOSTSERVICESESSIONS_EQ:
	            if (ds_ptr->dsize == before100SameHostService)
	                rval = DETECTION_OPTION_MATCH;
	            break;
	        case BEFORE100SAMEDSTHOSTSERVICESESSIONS_GT:
	            if (ds_ptr->dsize < before100SameHostService)
	                rval = DETECTION_OPTION_MATCH;
	            break;
	        case BEFORE100SAMEDSTHOSTSERVICESESSIONS_GTANDEQ:
	       	    if (ds_ptr->dsize <= before100SameHostService)
	       	         rval = DETECTION_OPTION_MATCH;
	       	    break;
	        case BEFORE100SAMEDSTHOSTSERVICESESSIONS_LT:
	            if (ds_ptr->dsize > before100SameHostService)
	                rval = DETECTION_OPTION_MATCH;
	            break;
	        case BEFORE100SAMEDSTHOSTSERVICESESSIONS_LTANDEQ:
	        	if (ds_ptr->dsize >= before100SameHostService)
	        	     rval = DETECTION_OPTION_MATCH;
	        	break;
	        case BEFORE100SAMEDSTHOSTSERVICESESSIONS_RANGE:
	            if ((ds_ptr->dsize <= before100SameHostService) &&
	                (ds_ptr->dsize2 >= before100SameHostService))
	                rval = DETECTION_OPTION_MATCH;
	            break;
	        default:
	            break;
	    }

	    SessionControlBlock *scb = NULL;
	    scb=(SessionControlBlock *)(p->ssnptr);

	    PREPROC_PROFILE_END(before100SameDstHostServiceSessionsPerfStats);
	   // printf("before100SameHostService=%ld,rval=%d,sp=%d,dp=%d\n",before100SameHostService,rval,scb->origin_client_port,scb->origin_server_port);
	    return rval;
}
