

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
#include "spp_session.h" //added by jacky
#ifdef PERF_PROFILING
PreprocStats before100SameDstHostServiceSynErrorRatePerfStats;
extern PreprocStats ruleOTNEvalPerfStats;
#endif
#include "detection_options.h"
#include "session_common.h"
#define BEFORE100SAMEDSTHOSTSERVICESYNERRORRATE_EQ                   1
#define BEFORE100SAMEDSTHOSTSERVICESYNERRORRATE_GT                   2
#define BEFORE100SAMEDSTHOSTSERVICESYNERRORRATE_LT                   3
#define BEFORE100SAMEDSTHOSTSERVICESYNERRORRATE_RANGE                4
#define BEFORE100SAMEDSTHOSTSERVICESYNERRORRATE_GTANDEQ              5
#define BEFORE100SAMEDSTHOSTSERVICESYNERRORRATE_LTANDEQ              6

typedef struct _Before100SameDstHostServiceSynErrorRateCheckData
{
    float dsize;
    float dsize2;
    char operator;
} Before100SameDstHostServiceSynErrorRateCheckData;



void Before100SameDstHostServiceSynErrorRateCheckInit(struct _SnortConfig *, char *, OptTreeNode *, int);
void ParseBefore100SameDstHostServiceSynErrorRate(struct _SnortConfig *,char *, OptTreeNode *);
int Before100SameDstHostServiceSynErrorRateCheck(void *option_data, Packet *p);


uint32_t Before100SameDstHostServiceSynErrorRateCheckHash(void *d)
{
    int a,b,c;

     //NO data stored for the option

    a = RULE_OPTION_TYPE_BEFORE100SAMEDSTHOSTSERVICESYNERRORRATE;
    b = 0;
    c = 0;

    final(a,b,c);

    return c;
}

int Before100SameDstHostServiceSynErrorRateCheckCompare(void *l, void *r)
{
	Before100SameDstHostServiceSynErrorRateCheckData *left = (Before100SameDstHostServiceSynErrorRateCheckData *)l;
	Before100SameDstHostServiceSynErrorRateCheckData *right = (Before100SameDstHostServiceSynErrorRateCheckData *)r;

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
void SetupBefore100SameDstHostServiceSynErrorRateCheck(void)

{
    /* map the keyword to an initialization/processing function */
    RegisterRuleOption("before100SameDstHostServiceSynErrorRate", Before100SameDstHostServiceSynErrorRateCheckInit, NULL, OPT_TYPE_DETECTION, NULL);
#ifdef PERF_PROFILING
    RegisterPreprocessorProfile("before100SameDstHostServiceSynErrorRate", &before100SameDstHostServiceSynErrorRatePerfStats, 3, &ruleOTNEvalPerfStats);
#endif
    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Plugin: Before100SameDstHostServiceSynErrorRate Check Initialized\n"););
}

void Before100SameDstHostServiceSynErrorRateCheckInit(struct _SnortConfig *sc, char *data, OptTreeNode *otn, int protocol)
{
    OptFpList *fpl;
    void *ds_ptr_dup;

    /* multiple declaration check */
    if(otn->ds_list[PLUGIN_BEFORE100SAMEDSTHOSTSERVICESYNERRORRATE_CHECK])
    {
        FatalError("%s(%d): Multiple before100SameDstHostServiceSynErrorRate options in rule\n", file_name,
                file_line);
    }

    /* allocate the data structure and attach it to the
       rule's data struct list */
    otn->ds_list[PLUGIN_BEFORE100SAMEDSTHOSTSERVICESYNERRORRATE_CHECK] = (Before100SameDstHostServiceSynErrorRateCheckData *)SnortAlloc(sizeof(Before100SameDstHostServiceSynErrorRateCheckData));

    /* this is where the keyword arguments are processed and placed into the
       rule option's data structure */
    ParseBefore100SameDstHostServiceSynErrorRate(sc,data, otn);
}

void ParseBefore100SameDstHostServiceSynErrorRate(struct _SnortConfig *sc,char *data, OptTreeNode *otn)
{

	Before100SameDstHostServiceSynErrorRateCheckData *ds_ptr;  /* data struct pointer */
	    char *pcEnd;
	    char *pcTok;
	    float iDsize = 0;
	    void *ds_ptr_dup;
	    OptFpList *fpl;
	    /* set the ds pointer to make it easier to reference the option's
	       particular data struct */
	    ds_ptr = (Before100SameDstHostServiceSynErrorRateCheckData *)otn->ds_list[PLUGIN_BEFORE100SAMEDSTHOSTSERVICESYNERRORRATE_CHECK];

	    while(isspace((int)*data)) data++;

	    if(isdigit((int)*data) && strchr(data, '<') && strchr(data, '>'))
	    {
	        pcTok = strtok(data, " <>");
	        if(!pcTok)
	        {
	            /*
	            **  Fatal
	            */
	            FatalError("%s(%d): Invalid 'before100SameDstHostServiceSynErrorRate' argument.\n",
	                       file_name, file_line);
	        }

	        iDsize = strtof(pcTok, &pcEnd);
	        if(iDsize < 0 || *pcEnd)
	        {
	            FatalError("%s(%d): Invalid 'before100SameDstHostServiceSynErrorRate' argument.\n",
	                       file_name, file_line);
	        }

	        ds_ptr->dsize = iDsize;

	        pcTok = strtok(NULL, " <>");
	        if(!pcTok)
	        {
	            FatalError("%s(%d): Invalid 'before100SameDstHostServiceSynErrorRate' argument.\n",
	                       file_name, file_line);
	        }

	        iDsize = strtof(pcTok, &pcEnd);
	        if(iDsize < 0 || *pcEnd)
	        {
	            FatalError("%s(%d): Invalid 'before100SameDstHostServiceSynErrorRate' argument.\n",
	                       file_name, file_line);
	        }

	        ds_ptr->dsize2 = iDsize;

	        ds_ptr->operator = BEFORE100SAMEDSTHOSTSERVICESYNERRORRATE_RANGE;

	#ifdef DEBUG_MSGS
	        DebugMessage(DEBUG_PLUGIN, "min before100SameDstHostServiceSynErrorRate: %f\n", ds_ptr->dsize);
	        DebugMessage(DEBUG_PLUGIN, "max before100SameDstHostServiceSynErrorRate: %f\n", ds_ptr->dsize2);
	#endif
	        fpl = AddOptFuncToList(Before100SameDstHostServiceSynErrorRateCheck, otn);
	        fpl->type = RULE_OPTION_TYPE_BEFORE100SAMEDSTHOSTSERVICESYNERRORRATE;

	        if (add_detection_option(sc, RULE_OPTION_TYPE_BEFORE100SAMEDSTHOSTSERVICESYNERRORRATE, (void *)ds_ptr, &ds_ptr_dup) == DETECTION_OPTION_EQUAL)
	        {
	            free(ds_ptr);
	            ds_ptr = otn->ds_list[PLUGIN_BEFORE100SAMEDSTHOSTSERVICESYNERRORRATE_CHECK] = ds_ptr_dup;
	        }
	        fpl->context = ds_ptr;

	        return;
	    }
	    else if(*data == '>')
	    {
	        data++;
	        if(*data=='='){
	        	ds_ptr->operator = BEFORE100SAMEDSTHOSTSERVICESYNERRORRATE_GTANDEQ;
	        	data++;
	        }else{
	        	ds_ptr->operator = BEFORE100SAMEDSTHOSTSERVICESYNERRORRATE_GT;
	        }
	        fpl = AddOptFuncToList(Before100SameDstHostServiceSynErrorRateCheck, otn);
	    }
	    else if(*data == '<')
	    {
	        data++;
	        if(*data=='='){
	        	ds_ptr->operator = BEFORE100SAMEDSTHOSTSERVICESYNERRORRATE_LTANDEQ;
	        	data++;
	        }else{
	        	ds_ptr->operator = BEFORE100SAMEDSTHOSTSERVICESYNERRORRATE_LT;
	        }
	        fpl = AddOptFuncToList(Before100SameDstHostServiceSynErrorRateCheck, otn);
	    }
	    else
	    {
	        fpl = AddOptFuncToList(Before100SameDstHostServiceSynErrorRateCheck, otn);
	        ds_ptr->operator = BEFORE100SAMEDSTHOSTSERVICESYNERRORRATE_EQ;
	    }

	    fpl->type = RULE_OPTION_TYPE_BEFORE100SAMEDSTHOSTSERVICESYNERRORRATE;

	    while(isspace((int)*data)) data++;

	    iDsize = strtof(data, &pcEnd);
	    if(iDsize < 0 || *pcEnd)
	    {
	        FatalError("%s(%d): Invalid 'before100SameDstHostServiceSynErrorRate' argument.\n",
	                   file_name, file_line);
	    }

	    ds_ptr->dsize = iDsize;

	    if (add_detection_option(sc, RULE_OPTION_TYPE_BEFORE100SAMEDSTHOSTSERVICESYNERRORRATE, (void *)ds_ptr, &ds_ptr_dup) == DETECTION_OPTION_EQUAL)
	    {
	        free(ds_ptr);
	        ds_ptr = otn->ds_list[PLUGIN_BEFORE100SAMEDSTHOSTSERVICESYNERRORRATE_CHECK] = ds_ptr_dup;
	     }
	     fpl->context = ds_ptr;

	    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "BEFORE100SAMEDSTHOSTSERVICESYNERRORRATE length = %f\n", ds_ptr->dsize););
	    //printf("dsize=%f\n",ds_ptr->dsize);
}

float getBefore100SameDstHostServiceSynErrorRateByPakcet(Packet *p){
	float before100SameHostServiceSynErrorRate = 0;
	SessionKey key;
	SessionControlBlock *scb = NULL;
	scb = (SessionControlBlock *) (p->ssnptr);
	if (scb != NULL) {
		CountBefore100TCPSessionErrorStatistics(scb);
		scb->flagTrackConnection=1;
		before100SameHostServiceSynErrorRate =
				scb->before_100_same_host_and_server == 0 ?
						0 :
						((float) ((int) (((scb->before_100_same_host_and_server_syn_error
								* 1.0) / scb->before_100_same_host_and_server + 0.005)
								* 100))) / 100;
	}
	//printf("synError=%d, sameHostServer=%d sp=%d,dp=%d,flag=%d\n",scb->before_100_same_host_and_server_syn_error,scb->before_100_same_host_and_server,p->sp,p->dp,scb->flagAlert);
	return before100SameHostServiceSynErrorRate;
}

int Before100SameDstHostServiceSynErrorRateCheck(void *option_data, Packet *p)
{
	Before100SameDstHostServiceSynErrorRateCheckData *ds_ptr = (Before100SameDstHostServiceSynErrorRateCheckData *)option_data;
	    int rval = DETECTION_OPTION_NO_MATCH;
	    PROFILE_VARS;

	    if (!ds_ptr)
	        return rval;

	    PREPROC_PROFILE_START(before100SameDstHostServiceSynErrorRatePerfStats);

        float before100SameHostServiceSynErrorRate=getBefore100SameDstHostServiceSynErrorRateByPakcet(p);
       // printf("spantime=%ld\n",spanTime);
	    switch (ds_ptr->operator)
	    {
	        case BEFORE100SAMEDSTHOSTSERVICESYNERRORRATE_EQ:
	            if (ds_ptr->dsize == before100SameHostServiceSynErrorRate)
	                rval = DETECTION_OPTION_MATCH;
	            break;
	        case BEFORE100SAMEDSTHOSTSERVICESYNERRORRATE_GT:
	            if (ds_ptr->dsize < before100SameHostServiceSynErrorRate)
	                rval = DETECTION_OPTION_MATCH;
	            break;
	        case BEFORE100SAMEDSTHOSTSERVICESYNERRORRATE_GTANDEQ:
	        	if (ds_ptr->dsize <= before100SameHostServiceSynErrorRate)
	        	     rval = DETECTION_OPTION_MATCH;
	        	break;
	        case BEFORE100SAMEDSTHOSTSERVICESYNERRORRATE_LT:
	            if (ds_ptr->dsize > before100SameHostServiceSynErrorRate)
	                rval = DETECTION_OPTION_MATCH;
	            break;
	        case BEFORE100SAMEDSTHOSTSERVICESYNERRORRATE_LTANDEQ:
	        	 if (ds_ptr->dsize >= before100SameHostServiceSynErrorRate)
	        	     rval = DETECTION_OPTION_MATCH;
	        	 break;
	        case BEFORE100SAMEDSTHOSTSERVICESYNERRORRATE_RANGE:
	            if ((ds_ptr->dsize <= before100SameHostServiceSynErrorRate) &&
	                (ds_ptr->dsize2 >= before100SameHostServiceSynErrorRate))
	                rval = DETECTION_OPTION_MATCH;
	            break;
	        default:
	            break;
	    }

	    PREPROC_PROFILE_END(before100SameDstHostServiceSynErrorRatePerfStats);
	    //printf("dst_host_srv_serror_rate=%f,rval=%d,sp=%d,dp=%d\n",before100SameHostServiceSynErrorRate,rval,p->sp,p->dp);
	    return rval;
}
