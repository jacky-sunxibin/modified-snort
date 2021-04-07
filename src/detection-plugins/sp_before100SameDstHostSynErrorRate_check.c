

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
#include "spp_session.h" //added by jacky
#include "snort.h"
#include "profiler.h"
#ifdef PERF_PROFILING
PreprocStats before100SameDstHostSynErrorRatePerfStats;
extern PreprocStats ruleOTNEvalPerfStats;
#endif
#include "detection_options.h"
#include "session_common.h"
#define BEFORE100SAMEDSTHOSTSYNERRORRATE_EQ                   1
#define BEFORE100SAMEDSTHOSTSYNERRORRATE_GT                   2
#define BEFORE100SAMEDSTHOSTSYNERRORRATE_LT                   3
#define BEFORE100SAMEDSTHOSTSYNERRORRATE_RANGE                4
#define BEFORE100SAMEDSTHOSTSYNERRORRATE_GTANDEQ              5
#define BEFORE100SAMEDSTHOSTSYNERRORRATE_LTANDEQ              6

typedef struct _Before100SameDstHostSynErrorRateCheckData
{
    float dsize;
    float dsize2;
    char operator;
} Before100SameDstHostSynErrorRateCheckData;



void Before100SameDstHostSynErrorRateCheckInit(struct _SnortConfig *, char *, OptTreeNode *, int);
void ParseBefore100SameDstHostSynErrorRate(struct _SnortConfig *,char *, OptTreeNode *);
int Before100SameDstHostSynErrorRateCheck(void *option_data, Packet *p);


uint32_t Before100SameDstHostSynErrorRateCheckHash(void *d)
{
    int a,b,c;

     //NO data stored for the option

    a = RULE_OPTION_TYPE_BEFORE100SAMEDSTHOSTSYNERRORRATE;
    b = 0;
    c = 0;

    final(a,b,c);

    return c;
}

int Before100SameDstHostSynErrorRateCheckCompare(void *l, void *r)
{
	Before100SameDstHostSynErrorRateCheckData *left = (Before100SameDstHostSynErrorRateCheckData *)l;
	Before100SameDstHostSynErrorRateCheckData *right = (Before100SameDstHostSynErrorRateCheckData *)r;

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
void SetupBefore100SameDstHostSynErrorRateCheck(void)

{
    /* map the keyword to an initialization/processing function */
    RegisterRuleOption("before100SameDstHostSynErrorRate", Before100SameDstHostSynErrorRateCheckInit, NULL, OPT_TYPE_DETECTION, NULL);
#ifdef PERF_PROFILING
    RegisterPreprocessorProfile("before100SameDstHostSynErrorRate", &before100SameDstHostSynErrorRatePerfStats, 3, &ruleOTNEvalPerfStats);
#endif
    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Plugin: Before100SameDstHostSynErrorRate Check Initialized\n"););
}

void Before100SameDstHostSynErrorRateCheckInit(struct _SnortConfig *sc, char *data, OptTreeNode *otn, int protocol)
{
    OptFpList *fpl;
    void *ds_ptr_dup;

    /* multiple declaration check */
    if(otn->ds_list[PLUGIN_BEFORE100SAMEDSTHOSTSYNERRORRATE_CHECK])
    {
        FatalError("%s(%d): Multiple before100SameDstHostSynErrorRate options in rule\n", file_name,
                file_line);
    }

    /* allocate the data structure and attach it to the
       rule's data struct list */
    otn->ds_list[PLUGIN_BEFORE100SAMEDSTHOSTSYNERRORRATE_CHECK] = (Before100SameDstHostSynErrorRateCheckData *)SnortAlloc(sizeof(Before100SameDstHostSynErrorRateCheckData));

    /* this is where the keyword arguments are processed and placed into the
       rule option's data structure */
    ParseBefore100SameDstHostSynErrorRate(sc,data, otn);
}

void ParseBefore100SameDstHostSynErrorRate(struct _SnortConfig *sc,char *data, OptTreeNode *otn)
{

	Before100SameDstHostSynErrorRateCheckData *ds_ptr;  /* data struct pointer */
	    char *pcEnd;
	    char *pcTok;
	    float iDsize = 0;
	    void *ds_ptr_dup;
	    OptFpList *fpl;
	    /* set the ds pointer to make it easier to reference the option's
	       particular data struct */
	    ds_ptr = (Before100SameDstHostSynErrorRateCheckData *)otn->ds_list[PLUGIN_BEFORE100SAMEDSTHOSTSYNERRORRATE_CHECK];

	    while(isspace((int)*data)) data++;

	    if(isdigit((int)*data) && strchr(data, '<') && strchr(data, '>'))
	    {
	        pcTok = strtok(data, " <>");
	        if(!pcTok)
	        {
	            /*
	            **  Fatal
	            */
	            FatalError("%s(%d): Invalid 'before100SameDstHostSynErrorRate' argument.\n",
	                       file_name, file_line);
	        }

	        iDsize = strtof(pcTok, &pcEnd);
	        if(iDsize < 0 || *pcEnd)
	        {
	            FatalError("%s(%d): Invalid 'before100SameDstHostSynErrorRate' argument.\n",
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
	            FatalError("%s(%d): Invalid 'before100SameDstHostSynErrorRate' argument.\n",
	                       file_name, file_line);
	        }

	        ds_ptr->dsize2 = iDsize;

	        ds_ptr->operator = BEFORE100SAMEDSTHOSTSYNERRORRATE_RANGE;

	#ifdef DEBUG_MSGS
	        DebugMessage(DEBUG_PLUGIN, "min before100SameDstHostSynErrorRate: %f\n", ds_ptr->dsize);
	        DebugMessage(DEBUG_PLUGIN, "max before100SameDstHostSynErrorRate: %f\n", ds_ptr->dsize2);
	#endif
	        fpl = AddOptFuncToList(Before100SameDstHostSynErrorRateCheck, otn);
	        fpl->type = RULE_OPTION_TYPE_BEFORE100SAMEDSTHOSTSYNERRORRATE;

	        if (add_detection_option(sc, RULE_OPTION_TYPE_BEFORE100SAMEDSTHOSTSYNERRORRATE, (void *)ds_ptr, &ds_ptr_dup) == DETECTION_OPTION_EQUAL)
	        {
	            free(ds_ptr);
	            ds_ptr = otn->ds_list[PLUGIN_BEFORE100SAMEDSTHOSTSYNERRORRATE_CHECK] = ds_ptr_dup;
	        }
	        fpl->context = ds_ptr;

	        return;
	    }
	    else if(*data == '>')
	    {
	        data++;
	        if(*data=='='){
	        	ds_ptr->operator = BEFORE100SAMEDSTHOSTSYNERRORRATE_GTANDEQ;
	        	data++;
	        }else{
	        	ds_ptr->operator = BEFORE100SAMEDSTHOSTSYNERRORRATE_GT;
	        }
	        fpl = AddOptFuncToList(Before100SameDstHostSynErrorRateCheck, otn);

	    }
	    else if(*data == '<')
	    {
	        data++;
	        if(*data=='='){
	        	ds_ptr->operator = BEFORE100SAMEDSTHOSTSYNERRORRATE_LTANDEQ;
	        	data++;
	        }else{
	        	ds_ptr->operator = BEFORE100SAMEDSTHOSTSYNERRORRATE_LT;
	        }
	        fpl = AddOptFuncToList(Before100SameDstHostSynErrorRateCheck, otn);

	    }
	    else
	    {
	        fpl = AddOptFuncToList(Before100SameDstHostSynErrorRateCheck, otn);
	        ds_ptr->operator = BEFORE100SAMEDSTHOSTSYNERRORRATE_EQ;
	    }

	    fpl->type = RULE_OPTION_TYPE_BEFORE100SAMEDSTHOSTSYNERRORRATE;

	    while(isspace((int)*data)) data++;

	    iDsize = strtof(data, &pcEnd);
	    if(iDsize < 0 || *pcEnd)
	    {
	        FatalError("%s(%d): Invalid 'before100SameDstHostSynErrorRate' argument.\n",
	                   file_name, file_line);
	    }

	    ds_ptr->dsize = iDsize;

	    if (add_detection_option(sc, RULE_OPTION_TYPE_BEFORE100SAMEDSTHOSTSYNERRORRATE, (void *)ds_ptr, &ds_ptr_dup) == DETECTION_OPTION_EQUAL)
	    {
	        free(ds_ptr);
	        ds_ptr = otn->ds_list[PLUGIN_BEFORE100SAMEDSTHOSTSYNERRORRATE_CHECK] = ds_ptr_dup;
	     }
	     fpl->context = ds_ptr;

	    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "BEFORE100SAMEDSTHOSTSYNERRORRATE length = %f\n", ds_ptr->dsize););
	    //printf("dsize=%f\n",ds_ptr->dsize);
}

float getBefore100SameDstHostSynErrorRateByPakcet(Packet *p){
	float before100SameHostSynErrorRate = 0;
	SessionKey key;
	SessionControlBlock *scb = NULL;
	scb = (SessionControlBlock *) (p->ssnptr);
	if (scb != NULL) {
		CountBefore100TCPSessionErrorStatistics(scb);
		scb->flagTrackConnection=1;
		before100SameHostSynErrorRate =
				scb->before_100_same_host == 0 ?
						0 :
						((float) ((int) (((scb->before_100_same_host_syn_error
								* 1.0) / scb->before_100_same_host + 0.005)
								* 100))) / 100;
	}
	//printf("synError=%ld,sameHost=%ld,sameHostError=%f\n",scb->two_seconds_same_host_syn_error,scb->two_seconds_same_host,sameHostErrorRate);
	return before100SameHostSynErrorRate;
}

int Before100SameDstHostSynErrorRateCheck(void *option_data, Packet *p)
{
	Before100SameDstHostSynErrorRateCheckData *ds_ptr = (Before100SameDstHostSynErrorRateCheckData *)option_data;
	    int rval = DETECTION_OPTION_NO_MATCH;
	    PROFILE_VARS;

	    if (!ds_ptr)
	        return rval;

	    PREPROC_PROFILE_START(before100SameDstHostSynErrorRatePerfStats);

        float before100SameHostSynErrorRate=getBefore100SameDstHostSynErrorRateByPakcet(p);
       // printf("spantime=%ld\n",spanTime);
	    switch (ds_ptr->operator)
	    {
	        case BEFORE100SAMEDSTHOSTSYNERRORRATE_EQ:
	            if (ds_ptr->dsize == before100SameHostSynErrorRate)
	                rval = DETECTION_OPTION_MATCH;
	            break;
	        case BEFORE100SAMEDSTHOSTSYNERRORRATE_GT:
	            if (ds_ptr->dsize < before100SameHostSynErrorRate)
	                rval = DETECTION_OPTION_MATCH;
	            break;
	        case BEFORE100SAMEDSTHOSTSYNERRORRATE_GTANDEQ:
	       	    if (ds_ptr->dsize <= before100SameHostSynErrorRate)
	       	         rval = DETECTION_OPTION_MATCH;
	       	    break;
	        case BEFORE100SAMEDSTHOSTSYNERRORRATE_LT:
	            if (ds_ptr->dsize > before100SameHostSynErrorRate)
	                rval = DETECTION_OPTION_MATCH;
	            break;
	        case BEFORE100SAMEDSTHOSTSYNERRORRATE_LTANDEQ:
	        	if (ds_ptr->dsize >= before100SameHostSynErrorRate)
	        	     rval = DETECTION_OPTION_MATCH;
	        	break;
	        case BEFORE100SAMEDSTHOSTSYNERRORRATE_RANGE:
	            if ((ds_ptr->dsize <= before100SameHostSynErrorRate) &&
	                (ds_ptr->dsize2 >= before100SameHostSynErrorRate))
	                rval = DETECTION_OPTION_MATCH;
	            break;
	        default:
	            break;
	    }

	    PREPROC_PROFILE_END(before100SameDstHostSynErrorRatePerfStats);
	    return rval;
}
