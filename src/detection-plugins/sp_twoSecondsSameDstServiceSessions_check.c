

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
PreprocStats twoSecondsSameDstServiceSessionsPerfStats;
extern PreprocStats ruleOTNEvalPerfStats;
#endif
#include "detection_options.h"
#include "session_common.h"
#define TWOSECONDSSAMEDSTSERVICESESSIONS_EQ                   1
#define TWOSECONDSSAMEDSTSERVICESESSIONS_GT                   2
#define TWOSECONDSSAMEDSTSERVICESESSIONS_LT                   3
#define TWOSECONDSSAMEDSTSERVICESESSIONS_RANGE                4
#define TWOSECONDSSAMEDSTSERVICESESSIONS_GTANDEQ              5
#define TWOSECONDSSAMEDSTSERVICESESSIONS_LTANDEQ              6

typedef struct _TwoSecondsSameDstServiceSessionsCheckData
{
    int dsize;
    int dsize2;
    char operator;
} TwoSecondsSameDstServiceSessionsCheckData;



void TwoSecondsSameDstServiceSessionsCheckInit(struct _SnortConfig *, char *, OptTreeNode *, int);
void ParseTwoSecondsSameDstServiceSessions(struct _SnortConfig *,char *, OptTreeNode *);
int TwoSecondsSameDstServiceSessionsCheck(void *option_data, Packet *p);


uint32_t TwoSecondsSameDstServiceSessionsCheckHash(void *d)
{
    uint32_t a,b,c;

     //NO data stored for the option

    a = RULE_OPTION_TYPE_TWOSECONDSSAMEDSTSERVICESESSIONS;
    b = 0;
    c = 0;

    final(a,b,c);

    return c;
}

int TwoSecondsSameDstServiceSessionsCheckCompare(void *l, void *r)
{
	TwoSecondsSameDstServiceSessionsCheckData *left = (TwoSecondsSameDstServiceSessionsCheckData *)l;
	TwoSecondsSameDstServiceSessionsCheckData *right = (TwoSecondsSameDstServiceSessionsCheckData *)r;

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
void SetupTwoSecondsSameDstServiceSessionsCheck(void)

{
    /* map the keyword to an initialization/processing function */
    RegisterRuleOption("twoSecondsSameDstServiceSessions", TwoSecondsSameDstServiceSessionsCheckInit, NULL, OPT_TYPE_DETECTION, NULL);
#ifdef PERF_PROFILING
    RegisterPreprocessorProfile("twoSecondsSameDstServiceSessions", &twoSecondsSameDstServiceSessionsPerfStats, 3, &ruleOTNEvalPerfStats);
#endif
    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Plugin: TwoSecondsSameDstServiceSessions Check Initialized\n"););
}

void TwoSecondsSameDstServiceSessionsCheckInit(struct _SnortConfig *sc, char *data, OptTreeNode *otn, int protocol)
{
    OptFpList *fpl;
    void *ds_ptr_dup;

    /* multiple declaration check */
    if(otn->ds_list[PLUGIN_TWOSECONDSSAMEDSTSERVICESESSIONS_CHECK])
    {
        FatalError("%s(%d): Multiple twoSecondsSameDstServiceSessions options in rule\n", file_name,
                file_line);
    }

    /* allocate the data structure and attach it to the
       rule's data struct list */
    otn->ds_list[PLUGIN_TWOSECONDSSAMEDSTSERVICESESSIONS_CHECK] = (TwoSecondsSameDstServiceSessionsCheckData *)SnortAlloc(sizeof(TwoSecondsSameDstServiceSessionsCheckData));

    /* this is where the keyword arguments are processed and placed into the
       rule option's data structure */
    ParseTwoSecondsSameDstServiceSessions(sc,data, otn);
}

void ParseTwoSecondsSameDstServiceSessions(struct _SnortConfig *sc,char *data, OptTreeNode *otn)
{

	TwoSecondsSameDstServiceSessionsCheckData *ds_ptr;  /* data struct pointer */
	    char *pcEnd;
	    char *pcTok;
	    int  iDsize = 0;
	    void *ds_ptr_dup;
	    OptFpList *fpl;

	    /* set the ds pointer to make it easier to reference the option's
	       particular data struct */
	    ds_ptr = (TwoSecondsSameDstServiceSessionsCheckData *)otn->ds_list[PLUGIN_TWOSECONDSSAMEDSTSERVICESESSIONS_CHECK];

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
	            FatalError("%s(%d): Invalid 'twoSecondsSameDstServiceSessions' argument.\n",
	                       file_name, file_line);
	        }

	        iDsize = strtol(pcTok, &pcEnd, 10);
	        if(iDsize < 0 || *pcEnd)
	        {
	            FatalError("%s(%d): Invalid 'twoSecondsSameDstServiceSessions' argument.\n",
	                       file_name, file_line);
	        }

	        ds_ptr->dsize = (unsigned short)iDsize;

	        pcTok = strtok(NULL, " <>");
	        if(!pcTok)
	        {
	            FatalError("%s(%d): Invalid 'twoSecondsSameDstServiceSessions' argument.\n",
	                       file_name, file_line);
	        }

	        iDsize = strtol(pcTok, &pcEnd, 10);
	        if(iDsize < 0 || *pcEnd)
	        {
	            FatalError("%s(%d): Invalid 'twoSecondsSameDstServiceSessions' argument.\n",
	                       file_name, file_line);
	        }

	        ds_ptr->dsize2 = (unsigned short)iDsize;

	        ds_ptr->operator = TWOSECONDSSAMEDSTSERVICESESSIONS_RANGE;

	#ifdef DEBUG_MSGS
	        DebugMessage(DEBUG_PLUGIN, "min twoSecondsSameDstServiceSessions: %d\n", ds_ptr->dsize);
	        DebugMessage(DEBUG_PLUGIN, "max twoSecondsSameDstServiceSessions: %d\n", ds_ptr->dsize2);
	#endif
	        fpl = AddOptFuncToList(TwoSecondsSameDstServiceSessionsCheck, otn);
	        fpl->type = RULE_OPTION_TYPE_TWOSECONDSSAMEDSTSERVICESESSIONS;

	        if (add_detection_option(sc, RULE_OPTION_TYPE_TWOSECONDSSAMEDSTSERVICESESSIONS, (void *)ds_ptr, &ds_ptr_dup) == DETECTION_OPTION_EQUAL)
	        {
	            free(ds_ptr);
	            ds_ptr = otn->ds_list[PLUGIN_TWOSECONDSSAMEDSTSERVICESESSIONS_CHECK] = ds_ptr_dup;
	        }
	        fpl->context = ds_ptr;

	        return;
	    }
	    else if(*data == '>')
	    {
	        data++;
	        if(*data=='='){
	        	ds_ptr->operator = TWOSECONDSSAMEDSTSERVICESESSIONS_GTANDEQ;
	        	data++;
	        }else{
	        	ds_ptr->operator = TWOSECONDSSAMEDSTSERVICESESSIONS_GT;
	        }
	        fpl = AddOptFuncToList(TwoSecondsSameDstServiceSessionsCheck, otn);

	    }
	    else if(*data == '<')
	    {
	        data++;
	        if(*data=='='){
	        	ds_ptr->operator = TWOSECONDSSAMEDSTSERVICESESSIONS_LTANDEQ;
	        	data++;
	        }else{
	        	ds_ptr->operator = TWOSECONDSSAMEDSTSERVICESESSIONS_LT;
	        }
	        fpl = AddOptFuncToList(TwoSecondsSameDstServiceSessionsCheck, otn);

	    }
	    else
	    {
	        fpl = AddOptFuncToList(TwoSecondsSameDstServiceSessionsCheck, otn);
	        ds_ptr->operator = TWOSECONDSSAMEDSTSERVICESESSIONS_EQ;
	    }

	    fpl->type = RULE_OPTION_TYPE_TWOSECONDSSAMEDSTSERVICESESSIONS;

	    while(isspace((int)*data)) data++;

	    iDsize = strtol(data, &pcEnd, 10);
	    if(iDsize < 0 || *pcEnd)
	    {
	        FatalError("%s(%d): Invalid 'twoSecondsSameDstServiceSessions' argument.\n",
	                   file_name, file_line);
	    }

	    ds_ptr->dsize = (unsigned short)iDsize;

	    if (add_detection_option(sc, RULE_OPTION_TYPE_TWOSECONDSSAMEDSTSERVICESESSIONS, (void *)ds_ptr, &ds_ptr_dup) == DETECTION_OPTION_EQUAL)
	    {
	        free(ds_ptr);
	        ds_ptr = otn->ds_list[PLUGIN_TWOSECONDSSAMEDSTSERVICESESSIONS_CHECK] = ds_ptr_dup;
	     }
	     fpl->context = ds_ptr;

	    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "TWOSECONDSSAMEDSTSERVICESESSIONS length = %d\n", ds_ptr->dsize););
}

long getTwoSecondsSameDstServiceSessionsByPakcet(Packet *p){
	long sameService=0;
	SessionKey key;
	SessionControlBlock *scb = NULL;
    scb=(SessionControlBlock *)(p->ssnptr);
	if (scb != NULL) {
		sameService=scb->two_seconds_same_server;
		scb->flagTrackConnection=1;
		}
	   return sameService;
	}

int TwoSecondsSameDstServiceSessionsCheck(void *option_data, Packet *p)
{
	TwoSecondsSameDstServiceSessionsCheckData *ds_ptr = (TwoSecondsSameDstServiceSessionsCheckData *)option_data;
	    int rval = DETECTION_OPTION_NO_MATCH;
	    PROFILE_VARS;

	    if (!ds_ptr)
	        return rval;

	    PREPROC_PROFILE_START(twoSecondsSameDstServiceSessionsPerfStats);

        long sameDstService=getTwoSecondsSameDstServiceSessionsByPakcet(p);
       // printf("spantime=%ld\n",spanTime);
	    switch (ds_ptr->operator)
	    {
	        case TWOSECONDSSAMEDSTSERVICESESSIONS_EQ:
	            if (ds_ptr->dsize == sameDstService)
	                rval = DETECTION_OPTION_MATCH;
	            break;
	        case TWOSECONDSSAMEDSTSERVICESESSIONS_GT:
	            if (ds_ptr->dsize < sameDstService)
	                rval = DETECTION_OPTION_MATCH;
	            break;
	        case TWOSECONDSSAMEDSTSERVICESESSIONS_GTANDEQ:
	        	if (ds_ptr->dsize <= sameDstService)
	        	     rval = DETECTION_OPTION_MATCH;
	        	 break;
	        case TWOSECONDSSAMEDSTSERVICESESSIONS_LT:
	            if (ds_ptr->dsize > sameDstService)
	                rval = DETECTION_OPTION_MATCH;
	            break;
	        case TWOSECONDSSAMEDSTSERVICESESSIONS_LTANDEQ:
	        	 if (ds_ptr->dsize >= sameDstService)
	        	     rval = DETECTION_OPTION_MATCH;
	        	 break;
	        case TWOSECONDSSAMEDSTSERVICESESSIONS_RANGE:
	            if ((ds_ptr->dsize <= sameDstService) &&
	                (ds_ptr->dsize2 >= sameDstService))
	                rval = DETECTION_OPTION_MATCH;
	            break;
	        default:
	            break;
	    }

	    PREPROC_PROFILE_END(twoSecondsSameDstServiceSessionsPerfStats);
	    //printf("twoSecondsSameDstServiceSessions=%ld,rval=%d\n",sameDstService,rval);
	    return rval;
}
