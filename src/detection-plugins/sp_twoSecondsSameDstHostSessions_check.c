

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
PreprocStats twoSecondsSameDstHostSessionsPerfStats;
extern PreprocStats ruleOTNEvalPerfStats;
#endif
#include "detection_options.h"
#include "session_common.h"
#define TWOSECONDSSAMEDSTHOSTSESSIONS_EQ                   1
#define TWOSECONDSSAMEDSTHOSTSESSIONS_GT                   2
#define TWOSECONDSSAMEDSTHOSTSESSIONS_LT                   3
#define TWOSECONDSSAMEDSTHOSTSESSIONS_RANGE                4

#define TWOSECONDSSAMEDSTHOSTSESSIONS_GTANDEQ              5
#define TWOSECONDSSAMEDSTHOSTSESSIONS_LTANDEQ              6

typedef struct _TwoSecondsSameDstHostSessionsCheckData
{
    int dsize;
    int dsize2;
    char operator;
} TwoSecondsSameDstHostSessionsCheckData;



void TwoSecondsSameDstHostSessionsCheckInit(struct _SnortConfig *, char *, OptTreeNode *, int);
void ParseTwoSecondsSameDstHostSessions(struct _SnortConfig *,char *, OptTreeNode *);
int TwoSecondsSameDstHostSessionsCheck(void *option_data, Packet *p);


uint32_t TwoSecondsSameDstHostSessionsCheckHash(void *d)
{
    uint32_t a,b,c;

     //NO data stored for the option

    a = RULE_OPTION_TYPE_TWOSECONDSSAMEDSTHOSTSESSIONS;
    b = 0;
    c = 0;

    final(a,b,c);

    return c;
}

int TwoSecondsSameDstHostSessionsCheckCompare(void *l, void *r)
{
	TwoSecondsSameDstHostSessionsCheckData *left = (TwoSecondsSameDstHostSessionsCheckData *)l;
	TwoSecondsSameDstHostSessionsCheckData *right = (TwoSecondsSameDstHostSessionsCheckData *)r;

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
void SetupTwoSecondsSameDstHostSessionsCheck(void)

{
    /* map the keyword to an initialization/processing function */
    RegisterRuleOption("twoSecondsSameDstHostSessions", TwoSecondsSameDstHostSessionsCheckInit, NULL, OPT_TYPE_DETECTION, NULL);
#ifdef PERF_PROFILING
    RegisterPreprocessorProfile("twoSecondsSameDstHostSessions", &twoSecondsSameDstHostSessionsPerfStats, 3, &ruleOTNEvalPerfStats);
#endif
    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Plugin: TwoSecondsSameDstHostSessions Check Initialized\n"););
}

void TwoSecondsSameDstHostSessionsCheckInit(struct _SnortConfig *sc, char *data, OptTreeNode *otn, int protocol)
{
    OptFpList *fpl;
    void *ds_ptr_dup;

    /* multiple declaration check */
    if(otn->ds_list[PLUGIN_TWOSECONDSSAMEDSTHOSTSESSIONS_CHECK])
    {
        FatalError("%s(%d): Multiple twoSecondsSameDstHostSessions options in rule\n", file_name,
                file_line);
    }

    /* allocate the data structure and attach it to the
       rule's data struct list */
    otn->ds_list[PLUGIN_TWOSECONDSSAMEDSTHOSTSESSIONS_CHECK] = (TwoSecondsSameDstHostSessionsCheckData *)SnortAlloc(sizeof(TwoSecondsSameDstHostSessionsCheckData));

    /* this is where the keyword arguments are processed and placed into the
       rule option's data structure */
    ParseTwoSecondsSameDstHostSessions(sc,data, otn);
}

void ParseTwoSecondsSameDstHostSessions(struct _SnortConfig *sc,char *data, OptTreeNode *otn)
{

	TwoSecondsSameDstHostSessionsCheckData *ds_ptr;  /* data struct pointer */
	    char *pcEnd;
	    char *pcTok;
	    int  iDsize = 0;
	    void *ds_ptr_dup;
	    OptFpList *fpl;

	    /* set the ds pointer to make it easier to reference the option's
	       particular data struct */
	    ds_ptr = (TwoSecondsSameDstHostSessionsCheckData *)otn->ds_list[PLUGIN_TWOSECONDSSAMEDSTHOSTSESSIONS_CHECK];

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
	            FatalError("%s(%d): Invalid 'twoSecondsSameDstHostSessions' argument.\n",
	                       file_name, file_line);
	        }

	        iDsize = strtol(pcTok, &pcEnd, 10);
	        if(iDsize < 0 || *pcEnd)
	        {
	            FatalError("%s(%d): Invalid 'twoSecondsSameDstHostSessions' argument.\n",
	                       file_name, file_line);
	        }

	        ds_ptr->dsize = (unsigned short)iDsize;

	        pcTok = strtok(NULL, " <>");
	        if(!pcTok)
	        {
	            FatalError("%s(%d): Invalid 'twoSecondsSameDstHostSessions' argument.\n",
	                       file_name, file_line);
	        }

	        iDsize = strtol(pcTok, &pcEnd, 10);
	        if(iDsize < 0 || *pcEnd)
	        {
	            FatalError("%s(%d): Invalid 'twoSecondsSameDstHostSessions' argument.\n",
	                       file_name, file_line);
	        }

	        ds_ptr->dsize2 = (unsigned short)iDsize;

	        ds_ptr->operator = TWOSECONDSSAMEDSTHOSTSESSIONS_RANGE;

	#ifdef DEBUG_MSGS
	        DebugMessage(DEBUG_PLUGIN, "min twoSecondsSameDstHostSessions: %d\n", ds_ptr->dsize);
	        DebugMessage(DEBUG_PLUGIN, "max twoSecondsSameDstHostSessions: %d\n", ds_ptr->dsize2);
	#endif
	        fpl = AddOptFuncToList(TwoSecondsSameDstHostSessionsCheck, otn);
	        fpl->type = RULE_OPTION_TYPE_TWOSECONDSSAMEDSTHOSTSESSIONS;

	        if (add_detection_option(sc, RULE_OPTION_TYPE_TWOSECONDSSAMEDSTHOSTSESSIONS, (void *)ds_ptr, &ds_ptr_dup) == DETECTION_OPTION_EQUAL)
	        {
	            free(ds_ptr);
	            ds_ptr = otn->ds_list[PLUGIN_TWOSECONDSSAMEDSTHOSTSESSIONS_CHECK] = ds_ptr_dup;
	        }
	        fpl->context = ds_ptr;

	        return;
	    }
	    else if(*data == '>')
	    {
	        data++;
	        if(*data == '='){
	        	ds_ptr->operator = TWOSECONDSSAMEDSTHOSTSESSIONS_GTANDEQ;
	        	data++;
	        }else{
	        	ds_ptr->operator = TWOSECONDSSAMEDSTHOSTSESSIONS_GT;
	        }
	        fpl = AddOptFuncToList(TwoSecondsSameDstHostSessionsCheck, otn);

	    }
	    else if(*data == '<')
	    {
	        data++;
	        if(*data=='='){
	        	 ds_ptr->operator = TWOSECONDSSAMEDSTHOSTSESSIONS_LTANDEQ;
	        	 data++;
	        }else{
	        	ds_ptr->operator = TWOSECONDSSAMEDSTHOSTSESSIONS_LT;
	        }
	        fpl = AddOptFuncToList(TwoSecondsSameDstHostSessionsCheck, otn);

	    }
	    else
	    {
	        fpl = AddOptFuncToList(TwoSecondsSameDstHostSessionsCheck, otn);
	        ds_ptr->operator = TWOSECONDSSAMEDSTHOSTSESSIONS_EQ;
	    }

	    fpl->type = RULE_OPTION_TYPE_TWOSECONDSSAMEDSTHOSTSESSIONS;

	    while(isspace((int)*data)) data++;

	    iDsize = strtol(data, &pcEnd, 10);
	    if(iDsize < 0 || *pcEnd)
	    {
	        FatalError("%s(%d): Invalid 'twoSecondsSameDstHostSessions' argument.\n",
	                   file_name, file_line);
	    }

	    ds_ptr->dsize = (unsigned short)iDsize;

	    if (add_detection_option(sc, RULE_OPTION_TYPE_TWOSECONDSSAMEDSTHOSTSESSIONS, (void *)ds_ptr, &ds_ptr_dup) == DETECTION_OPTION_EQUAL)
	    {
	        free(ds_ptr);
	        ds_ptr = otn->ds_list[PLUGIN_TWOSECONDSSAMEDSTHOSTSESSIONS_CHECK] = ds_ptr_dup;
	     }
	     fpl->context = ds_ptr;

	    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "TWOSECONDSSAMEDSTHOSTSESSIONS length = %d\n", ds_ptr->dsize););
}

long getTwoSecondsSameDstHostSessionsByPakcet(Packet *p){
	long sameHost=0;
	SessionKey key;
	SessionControlBlock *scb = NULL;
    scb=(SessionControlBlock *)(p->ssnptr);
	if (scb != NULL) {
		sameHost=scb->two_seconds_same_host;
		scb->flagTrackConnection=1;
		}
	   return sameHost;
	}

int TwoSecondsSameDstHostSessionsCheck(void *option_data, Packet *p)
{
	TwoSecondsSameDstHostSessionsCheckData *ds_ptr = (TwoSecondsSameDstHostSessionsCheckData *)option_data;
	    int rval = DETECTION_OPTION_NO_MATCH;
	    PROFILE_VARS;

	    if (!ds_ptr)
	        return rval;

	    PREPROC_PROFILE_START(twoSecondsSameDstHostSessionsPerfStats);

        long sameDstHost=getTwoSecondsSameDstHostSessionsByPakcet(p);
       // printf("spantime=%ld\n",spanTime);
	    switch (ds_ptr->operator)
	    {
	        case TWOSECONDSSAMEDSTHOSTSESSIONS_EQ:
	            if (ds_ptr->dsize == sameDstHost)
	                rval = DETECTION_OPTION_MATCH;
	            break;
	        case TWOSECONDSSAMEDSTHOSTSESSIONS_GT:
	            if (ds_ptr->dsize < sameDstHost)
	                rval = DETECTION_OPTION_MATCH;
	            break;
	        case TWOSECONDSSAMEDSTHOSTSESSIONS_GTANDEQ:
	        	if(ds_ptr->dsize<=sameDstHost)
	        		rval = DETECTION_OPTION_MATCH;
	        	break;
	        case TWOSECONDSSAMEDSTHOSTSESSIONS_LT:
	            if (ds_ptr->dsize > sameDstHost)
	                rval = DETECTION_OPTION_MATCH;
	            break;
	        case TWOSECONDSSAMEDSTHOSTSESSIONS_LTANDEQ:
	        	if(ds_ptr->dsize>=sameDstHost)
	        	    rval = DETECTION_OPTION_MATCH;
	        	break;
	        case TWOSECONDSSAMEDSTHOSTSESSIONS_RANGE:
	            if ((ds_ptr->dsize <= sameDstHost) &&
	                (ds_ptr->dsize2 >= sameDstHost))
	                rval = DETECTION_OPTION_MATCH;
	            break;
	        default:
	            break;
	    }

	    PREPROC_PROFILE_END(twoSecondsSameDstHostSessionsPerfStats);
	    //printf("twoSecondsSameDstHostSessions=%ld,rval=%d\n",sameDstHost,rval);
	    return rval;
}
