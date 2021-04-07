

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
PreprocStats before100SameDstHostDiffServiceRatePerfStats;
extern PreprocStats ruleOTNEvalPerfStats;
#endif
#include "detection_options.h"
#include "session_common.h"
#define BEFORE100SAMEDSTHOSTDIFFSERVICERATE_EQ                   1
#define BEFORE100SAMEDSTHOSTDIFFSERVICERATE_GT                   2
#define BEFORE100SAMEDSTHOSTDIFFSERVICERATE_LT                   3
#define BEFORE100SAMEDSTHOSTDIFFSERVICERATE_RANGE                4
#define BEFORE100SAMEDSTHOSTDIFFSERVICERATE_GTANDEQ              5
#define BEFORE100SAMEDSTHOSTDIFFSERVICERATE_LTANDEQ              6

typedef struct _Before100SameDstHostDiffServiceRateCheckData
{
    float dsize;
    float dsize2;
    char operator;
} Before100SameDstHostDiffServiceRateCheckData;



void Before100SameDstHostDiffServiceRateCheckInit(struct _SnortConfig *, char *, OptTreeNode *, int);
void ParseBefore100SameDstHostDiffServiceRate(struct _SnortConfig *,char *, OptTreeNode *);
int Before100SameDstHostDiffServiceRateCheck(void *option_data, Packet *p);


uint32_t Before100SameDstHostDiffServiceRateCheckHash(void *d)
{
    int a,b,c;

     //NO data stored for the option

    a = RULE_OPTION_TYPE_BEFORE100SAMEDSTHOSTDIFFSERVICERATE;
    b = 0;
    c = 0;

    final(a,b,c);

    return c;
}

int Before100SameDstHostDiffServiceRateCheckCompare(void *l, void *r)
{
	Before100SameDstHostDiffServiceRateCheckData *left = (Before100SameDstHostDiffServiceRateCheckData *)l;
	Before100SameDstHostDiffServiceRateCheckData *right = (Before100SameDstHostDiffServiceRateCheckData *)r;

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
void SetupBefore100SameDstHostDiffServiceRateCheck(void)

{
    /* map the keyword to an initialization/processing function */
    RegisterRuleOption("before100SameDstHostDiffServiceRate", Before100SameDstHostDiffServiceRateCheckInit, NULL, OPT_TYPE_DETECTION, NULL);
#ifdef PERF_PROFILING
    RegisterPreprocessorProfile("before100SameDstHostDiffServiceRate", &before100SameDstHostDiffServiceRatePerfStats, 3, &ruleOTNEvalPerfStats);
#endif
    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Plugin: Before100SameDstHostDiffServiceRate Check Initialized\n"););
}

void Before100SameDstHostDiffServiceRateCheckInit(struct _SnortConfig *sc, char *data, OptTreeNode *otn, int protocol)
{
    OptFpList *fpl;
    void *ds_ptr_dup;

    /* multiple declaration check */
    if(otn->ds_list[PLUGIN_BEFORE100SAMEDSTHOSTDIFFSERVICERATE_CHECK])
    {
        FatalError("%s(%d): Multiple before100SameDstHostDiffServiceRate options in rule\n", file_name,
                file_line);
    }

    /* allocate the data structure and attach it to the
       rule's data struct list */
    otn->ds_list[PLUGIN_BEFORE100SAMEDSTHOSTDIFFSERVICERATE_CHECK] = (Before100SameDstHostDiffServiceRateCheckData *)SnortAlloc(sizeof(Before100SameDstHostDiffServiceRateCheckData));

    /* this is where the keyword arguments are processed and placed into the
       rule option's data structure */
    ParseBefore100SameDstHostDiffServiceRate(sc,data, otn);
}

void ParseBefore100SameDstHostDiffServiceRate(struct _SnortConfig *sc,char *data, OptTreeNode *otn)
{

	Before100SameDstHostDiffServiceRateCheckData *ds_ptr;  /* data struct pointer */
	    char *pcEnd;
	    char *pcTok;
	    float iDsize = 0;
	    void *ds_ptr_dup;
	    OptFpList *fpl;
	    /* set the ds pointer to make it easier to reference the option's
	       particular data struct */
	    ds_ptr = (Before100SameDstHostDiffServiceRateCheckData *)otn->ds_list[PLUGIN_BEFORE100SAMEDSTHOSTDIFFSERVICERATE_CHECK];

	    while(isspace((int)*data)) data++;

	    if(isdigit((int)*data) && strchr(data, '<') && strchr(data, '>'))
	    {
	        pcTok = strtok(data, " <>");
	        if(!pcTok)
	        {
	            /*
	            **  Fatal
	            */
	            FatalError("%s(%d): Invalid 'before100SameDstHostDiffServiceRate' argument.\n",
	                       file_name, file_line);
	        }

	        iDsize = strtof(pcTok, &pcEnd);
	        if(iDsize < 0 || *pcEnd)
	        {
	            FatalError("%s(%d): Invalid 'before100SameDstHostDiffServiceRate' argument.\n",
	                       file_name, file_line);
	        }

	        ds_ptr->dsize = iDsize;

	        pcTok = strtok(NULL, " <>");
	        if(!pcTok)
	        {
	            FatalError("%s(%d): Invalid 'before100SameDstHostSynErrorRate' argument.\n",
	                       file_name, file_line);
	        }

	        iDsize = strtof(pcTok, &pcEnd);
	        if(iDsize < 0 || *pcEnd)
	        {
	            FatalError("%s(%d): Invalid 'before100SameDstHostDiffServiceRate' argument.\n",
	                       file_name, file_line);
	        }

	        ds_ptr->dsize2 = iDsize;

	        ds_ptr->operator = BEFORE100SAMEDSTHOSTDIFFSERVICERATE_RANGE;

	#ifdef DEBUG_MSGS
	        DebugMessage(DEBUG_PLUGIN, "min before100SameDstHostDiffServiceRate: %f\n", ds_ptr->dsize);
	        DebugMessage(DEBUG_PLUGIN, "max before100SameDstHostDiffServiceRate: %f\n", ds_ptr->dsize2);
	#endif
	        fpl = AddOptFuncToList(Before100SameDstHostDiffServiceRateCheck, otn);
	        fpl->type = RULE_OPTION_TYPE_BEFORE100SAMEDSTHOSTDIFFSERVICERATE;

	        if (add_detection_option(sc, RULE_OPTION_TYPE_BEFORE100SAMEDSTHOSTDIFFSERVICERATE, (void *)ds_ptr, &ds_ptr_dup) == DETECTION_OPTION_EQUAL)
	        {
	            free(ds_ptr);
	            ds_ptr = otn->ds_list[PLUGIN_BEFORE100SAMEDSTHOSTDIFFSERVICERATE_CHECK] = ds_ptr_dup;
	        }
	        fpl->context = ds_ptr;

	        return;
	    }
	    else if(*data == '>')
	    {
	        data++;
	        if(*data=='='){
	        	ds_ptr->operator = BEFORE100SAMEDSTHOSTDIFFSERVICERATE_GTANDEQ;
	        	data++;
	        }else{
	        	ds_ptr->operator = BEFORE100SAMEDSTHOSTDIFFSERVICERATE_GT;
	        }
	        fpl = AddOptFuncToList(Before100SameDstHostDiffServiceRateCheck, otn);

	    }
	    else if(*data == '<')
	    {
	        data++;
	        if(*data=='='){
	        	ds_ptr->operator = BEFORE100SAMEDSTHOSTDIFFSERVICERATE_LTANDEQ;
	        	data++;
	        }else{
	        	ds_ptr->operator = BEFORE100SAMEDSTHOSTDIFFSERVICERATE_LT;
	        }
	        fpl = AddOptFuncToList(Before100SameDstHostDiffServiceRateCheck, otn);

	    }
	    else
	    {
	        fpl = AddOptFuncToList(Before100SameDstHostDiffServiceRateCheck, otn);
	        ds_ptr->operator = BEFORE100SAMEDSTHOSTDIFFSERVICERATE_EQ;
	    }

	    fpl->type = RULE_OPTION_TYPE_BEFORE100SAMEDSTHOSTDIFFSERVICERATE;

	    while(isspace((int)*data)) data++;

	    iDsize = strtof(data, &pcEnd);
	    if(iDsize < 0 || *pcEnd)
	    {
	        FatalError("%s(%d): Invalid 'before100SameDstHostDiffServiceRate' argument.\n",
	                   file_name, file_line);
	    }

	    ds_ptr->dsize = iDsize;

	    if (add_detection_option(sc, RULE_OPTION_TYPE_BEFORE100SAMEDSTHOSTDIFFSERVICERATE, (void *)ds_ptr, &ds_ptr_dup) == DETECTION_OPTION_EQUAL)
	    {
	        free(ds_ptr);
	        ds_ptr = otn->ds_list[PLUGIN_BEFORE100SAMEDSTHOSTDIFFSERVICERATE_CHECK] = ds_ptr_dup;
	     }
	     fpl->context = ds_ptr;

	    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "BEFORE100SAMEDSTHOSTDIFFSERVICERATE length = %f\n", ds_ptr->dsize););
}

float getBefore100SameDstHostDiffServiceRateByPakcet(Packet *p){
	float before100SameHostDiffServiceRate = 0;
	SessionKey key;
	SessionControlBlock *scb = NULL;
	scb = (SessionControlBlock *) (p->ssnptr);
	if (scb != NULL) {
		scb->flagTrackConnection=1;
		before100SameHostDiffServiceRate =
				scb->before_100_same_host == 0 ?
						0 :
						((float) ((int) ((( (scb->before_100_same_host-scb->before_100_same_host_and_server)
								* 1.0) / scb->before_100_same_host + 0.005)
								* 100))) / 100;
	}
	return before100SameHostDiffServiceRate;
}

int Before100SameDstHostDiffServiceRateCheck(void *option_data, Packet *p)
{
	Before100SameDstHostDiffServiceRateCheckData *ds_ptr = (Before100SameDstHostDiffServiceRateCheckData *)option_data;
	    int rval = DETECTION_OPTION_NO_MATCH;
	    PROFILE_VARS;

	    if (!ds_ptr)
	        return rval;

	    PREPROC_PROFILE_START(before100SameDstHostDiffServiceRatePerfStats);

        float before100SameHostDiffServiceRate=getBefore100SameDstHostDiffServiceRateByPakcet(p);
	    switch (ds_ptr->operator)
	    {
	        case BEFORE100SAMEDSTHOSTDIFFSERVICERATE_EQ:
	            if (ds_ptr->dsize == before100SameHostDiffServiceRate)
	                rval = DETECTION_OPTION_MATCH;
	            break;
	        case BEFORE100SAMEDSTHOSTDIFFSERVICERATE_GT:
	            if (ds_ptr->dsize < before100SameHostDiffServiceRate)
	                rval = DETECTION_OPTION_MATCH;
	            break;
	        case BEFORE100SAMEDSTHOSTDIFFSERVICERATE_GTANDEQ:
	       	    if (ds_ptr->dsize <= before100SameHostDiffServiceRate)
	       	         rval = DETECTION_OPTION_MATCH;
	       	    break;
	        case BEFORE100SAMEDSTHOSTDIFFSERVICERATE_LT:
	            if (ds_ptr->dsize > before100SameHostDiffServiceRate)
	                rval = DETECTION_OPTION_MATCH;
	            break;
	        case BEFORE100SAMEDSTHOSTDIFFSERVICERATE_LTANDEQ:
	        	if (ds_ptr->dsize >= before100SameHostDiffServiceRate)
	        	     rval = DETECTION_OPTION_MATCH;
	        	break;
	        case BEFORE100SAMEDSTHOSTDIFFSERVICERATE_RANGE:
	            if ((ds_ptr->dsize <= before100SameHostDiffServiceRate) &&
	                (ds_ptr->dsize2 >= before100SameHostDiffServiceRate))
	                rval = DETECTION_OPTION_MATCH;
	            break;
	        default:
	            break;
	    }

	    PREPROC_PROFILE_END(before100SameDstHostDiffServiceRatePerfStats);
	    //printf("before100SameHostDiffServiceRate=%f,rval=%d\n",before100SameHostDiffServiceRate,rval);
	    return rval;
}
