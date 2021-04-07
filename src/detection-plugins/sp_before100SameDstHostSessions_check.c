

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
PreprocStats before100SameDstHostSessionsPerfStats;
extern PreprocStats ruleOTNEvalPerfStats;
#endif
#include "detection_options.h"
#include "session_common.h"
#define BEFORE100SAMEDSTHOSTSESSIONS_EQ                   1
#define BEFORE100SAMEDSTHOSTSESSIONS_GT                   2
#define BEFORE100SAMEDSTHOSTSESSIONS_LT                   3
#define BEFORE100SAMEDSTHOSTSESSIONS_RANGE                4
#define BEFORE100SAMEDSTHOSTSESSIONS_GTANDEQ              5
#define BEFORE100SAMEDSTHOSTSESSIONS_LTANDEQ              6

typedef struct _Before100SameDstHostSessionsCheckData
{
    int dsize;
    int dsize2;
    char operator;
} Before100SameDstHostSessionsCheckData;



void Before100SameDstHostSessionsCheckInit(struct _SnortConfig *, char *, OptTreeNode *, int);
void ParseBefore100SameDstHostSessions(struct _SnortConfig *,char *, OptTreeNode *);
int Before100SameDstHostSessionsCheck(void *option_data, Packet *p);


uint32_t Before100SameDstHostSessionsCheckHash(void *d)
{
    uint32_t a,b,c;

     //NO data stored for the option

    a = RULE_OPTION_TYPE_BEFORE100SAMEDSTHOSTSESSIONS;
    b = 0;
    c = 0;

    final(a,b,c);

    return c;
}

int Before100SameDstHostSessionsCheckCompare(void *l, void *r)
{
	Before100SameDstHostSessionsCheckData *left = (Before100SameDstHostSessionsCheckData *)l;
	Before100SameDstHostSessionsCheckData *right = (Before100SameDstHostSessionsCheckData *)r;

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
void SetupBefore100SameDstHostSessionsCheck(void)

{
    /* map the keyword to an initialization/processing function */
    RegisterRuleOption("before100SameDstHostSessions", Before100SameDstHostSessionsCheckInit, NULL, OPT_TYPE_DETECTION, NULL);
#ifdef PERF_PROFILING
    RegisterPreprocessorProfile("before100SameDstHostSessions", &before100SameDstHostSessionsPerfStats, 3, &ruleOTNEvalPerfStats);
#endif
    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Plugin: Before100SameDstHostSessions Check Initialized\n"););
}

void Before100SameDstHostSessionsCheckInit(struct _SnortConfig *sc, char *data, OptTreeNode *otn, int protocol)
{
    OptFpList *fpl;
    void *ds_ptr_dup;

    /* multiple declaration check */
    if(otn->ds_list[PLUGIN_BEFORE100SAMEDSTHOSTSESSIONS_CHECK])
    {
        FatalError("%s(%d): Multiple before100SameDstHostSessions options in rule\n", file_name,
                file_line);
    }

    /* allocate the data structure and attach it to the
       rule's data struct list */
    otn->ds_list[PLUGIN_BEFORE100SAMEDSTHOSTSESSIONS_CHECK] = (Before100SameDstHostSessionsCheckData *)SnortAlloc(sizeof(Before100SameDstHostSessionsCheckData));

    /* this is where the keyword arguments are processed and placed into the
       rule option's data structure */
    ParseBefore100SameDstHostSessions(sc,data, otn);
}

void ParseBefore100SameDstHostSessions(struct _SnortConfig *sc,char *data, OptTreeNode *otn)
{

	Before100SameDstHostSessionsCheckData *ds_ptr;  /* data struct pointer */
	    char *pcEnd;
	    char *pcTok;
	    int  iDsize = 0;
	    void *ds_ptr_dup;
	    OptFpList *fpl;

	    /* set the ds pointer to make it easier to reference the option's
	       particular data struct */
	    ds_ptr = (Before100SameDstHostSessionsCheckData *)otn->ds_list[PLUGIN_BEFORE100SAMEDSTHOSTSESSIONS_CHECK];

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
	            FatalError("%s(%d): Invalid 'before100SameDstHostSessions' argument.\n",
	                       file_name, file_line);
	        }

	        iDsize = strtol(pcTok, &pcEnd, 10);
	        if(iDsize < 0 || *pcEnd)
	        {
	            FatalError("%s(%d): Invalid 'before100SameDstHostSessions' argument.\n",
	                       file_name, file_line);
	        }

	        ds_ptr->dsize = (unsigned short)iDsize;

	        pcTok = strtok(NULL, " <>");
	        if(!pcTok)
	        {
	            FatalError("%s(%d): Invalid 'before100SameDstHostSessions' argument.\n",
	                       file_name, file_line);
	        }

	        iDsize = strtol(pcTok, &pcEnd, 10);
	        if(iDsize < 0 || *pcEnd)
	        {
	            FatalError("%s(%d): Invalid 'before100SameDstHostSessions' argument.\n",
	                       file_name, file_line);
	        }

	        ds_ptr->dsize2 = (unsigned short)iDsize;

	        ds_ptr->operator = BEFORE100SAMEDSTHOSTSESSIONS_RANGE;

	#ifdef DEBUG_MSGS
	        DebugMessage(DEBUG_PLUGIN, "min twoSecondsSameDstHostSessions: %d\n", ds_ptr->dsize);
	        DebugMessage(DEBUG_PLUGIN, "max twoSecondsSameDstHostSessions: %d\n", ds_ptr->dsize2);
	#endif
	        fpl = AddOptFuncToList(Before100SameDstHostSessionsCheck, otn);
	        fpl->type = RULE_OPTION_TYPE_BEFORE100SAMEDSTHOSTSESSIONS;

	        if (add_detection_option(sc, RULE_OPTION_TYPE_BEFORE100SAMEDSTHOSTSESSIONS, (void *)ds_ptr, &ds_ptr_dup) == DETECTION_OPTION_EQUAL)
	        {
	            free(ds_ptr);
	            ds_ptr = otn->ds_list[PLUGIN_BEFORE100SAMEDSTHOSTSESSIONS_CHECK] = ds_ptr_dup;
	        }
	        fpl->context = ds_ptr;

	        return;
	    }
	    else if(*data == '>')
	    {
	        data++;
	        if(*data=='='){
	        	 ds_ptr->operator = BEFORE100SAMEDSTHOSTSESSIONS_GTANDEQ;
	        	data++;
	        }else{
	        	 ds_ptr->operator = BEFORE100SAMEDSTHOSTSESSIONS_GT;
	        }
	        fpl = AddOptFuncToList(Before100SameDstHostSessionsCheck, otn);

	    }
	    else if(*data == '<')
	    {
	        data++;
	        if(*data=='='){
	        	ds_ptr->operator = BEFORE100SAMEDSTHOSTSESSIONS_LTANDEQ;
	        	data++;
	        }else{
	        	ds_ptr->operator = BEFORE100SAMEDSTHOSTSESSIONS_LT;
	        }
	        fpl = AddOptFuncToList(Before100SameDstHostSessionsCheck, otn);

	    }
	    else
	    {
	        fpl = AddOptFuncToList(Before100SameDstHostSessionsCheck, otn);
	        ds_ptr->operator = BEFORE100SAMEDSTHOSTSESSIONS_EQ;
	    }

	    fpl->type = RULE_OPTION_TYPE_BEFORE100SAMEDSTHOSTSESSIONS;

	    while(isspace((int)*data)) data++;

	    iDsize = strtol(data, &pcEnd, 10);
	    if(iDsize < 0 || *pcEnd)
	    {
	        FatalError("%s(%d): Invalid 'before100SameDstHostSessions' argument.\n",
	                   file_name, file_line);
	    }

	    ds_ptr->dsize = (unsigned short)iDsize;

	    if (add_detection_option(sc, RULE_OPTION_TYPE_BEFORE100SAMEDSTHOSTSESSIONS, (void *)ds_ptr, &ds_ptr_dup) == DETECTION_OPTION_EQUAL)
	    {
	        free(ds_ptr);
	        ds_ptr = otn->ds_list[PLUGIN_BEFORE100SAMEDSTHOSTSESSIONS_CHECK] = ds_ptr_dup;
	     }
	     fpl->context = ds_ptr;

	    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "BEFORE100SAMEDSTHOSTSESSIONS length = %d\n", ds_ptr->dsize););
}

long getBefore100SameDstHostSessionsByPakcet(Packet *p){
	long before100SameHost=0;
	SessionKey key;
	SessionControlBlock *scb = NULL;
    scb=(SessionControlBlock *)(p->ssnptr);
	if (scb != NULL) {
		before100SameHost=scb->before_100_same_host;
		scb->flagTrackConnection=1;
		}
	   return before100SameHost;
	}

int Before100SameDstHostSessionsCheck(void *option_data, Packet *p)
{
	Before100SameDstHostSessionsCheckData *ds_ptr = (Before100SameDstHostSessionsCheckData *)option_data;
	    int rval = DETECTION_OPTION_NO_MATCH;
	    PROFILE_VARS;

	    if (!ds_ptr)
	        return rval;

	    PREPROC_PROFILE_START(before100SameDstHostSessionsPerfStats);

        long before100SameHost=getBefore100SameDstHostSessionsByPakcet(p);
       // printf("spantime=%ld\n",spanTime);
	    switch (ds_ptr->operator)
	    {
	        case BEFORE100SAMEDSTHOSTSESSIONS_EQ:
	            if (ds_ptr->dsize == before100SameHost)
	                rval = DETECTION_OPTION_MATCH;
	            break;
	        case BEFORE100SAMEDSTHOSTSESSIONS_GT:
	            if (ds_ptr->dsize < before100SameHost)
	                rval = DETECTION_OPTION_MATCH;
	            break;
	        case BEFORE100SAMEDSTHOSTSESSIONS_GTANDEQ:
	        	 if (ds_ptr->dsize <= before100SameHost)
	        	     rval = DETECTION_OPTION_MATCH;
	        	 break;
	        case BEFORE100SAMEDSTHOSTSESSIONS_LT:
	            if (ds_ptr->dsize > before100SameHost)
	                rval = DETECTION_OPTION_MATCH;
	            break;
	        case BEFORE100SAMEDSTHOSTSESSIONS_LTANDEQ:
	            if (ds_ptr->dsize >= before100SameHost)
	        	     rval = DETECTION_OPTION_MATCH;
	        	break;
	        case BEFORE100SAMEDSTHOSTSESSIONS_RANGE:
	            if ((ds_ptr->dsize <= before100SameHost) &&
	                (ds_ptr->dsize2 >= before100SameHost))
	                rval = DETECTION_OPTION_MATCH;
	            break;
	        default:
	            break;
	    }

	    PREPROC_PROFILE_END(before100SameDstHostSessionsPerfStats);
	    //printf("srv_host_count=%d,rval=%d\n",before100SameHost,rval);
	    return rval;
}
