

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
PreprocStats twoSecondsSameDstServiceSynErrorRatePerfStats;
extern PreprocStats ruleOTNEvalPerfStats;
#endif
#include "detection_options.h"
#include "session_common.h"
#define TWOSECONDSSAMEDSTSERVICESYNERRORRATE_EQ                   1
#define TWOSECONDSSAMEDSTSERVICESYNERRORRATE_GT                   2
#define TWOSECONDSSAMEDSTSERVICESYNERRORRATE_LT                   3
#define TWOSECONDSSAMEDSTSERVICESYNERRORRATE_RANGE                4
#define TWOSECONDSSAMEDSTSERVICESYNERRORRATE_GTANDEQ              5
#define TWOSECONDSSAMEDSTSERVICESYNERRORRATE_LTANDEQ              6

typedef struct _TwoSecondsSameDstServiceSynErrorRateCheckData
{
    float dsize;
    float dsize2;
    char operator;
} TwoSecondsSameDstServiceSynErrorRateCheckData;



void TwoSecondsSameDstServiceSynErrorRateCheckInit(struct _SnortConfig *, char *, OptTreeNode *, int);
void ParseTwoSecondsSameDstServiceSynErrorRate(struct _SnortConfig *,char *, OptTreeNode *);
int TwoSecondsSameDstServiceSynErrorRateCheck(void *option_data, Packet *p);


uint32_t TwoSecondsSameDstServiceSynErrorRateCheckHash(void *d)
{
    int a,b,c;

     //NO data stored for the option

    a = RULE_OPTION_TYPE_TWOSECONDSSAMEDSTSERVICESYNERRORRATE;
    b = 0;
    c = 0;

    final(a,b,c);

    return c;
}

int TwoSecondsSameDstServiceSynErrorRateCheckCompare(void *l, void *r)
{
	TwoSecondsSameDstServiceSynErrorRateCheckData *left = (TwoSecondsSameDstServiceSynErrorRateCheckData *)l;
	TwoSecondsSameDstServiceSynErrorRateCheckData *right = (TwoSecondsSameDstServiceSynErrorRateCheckData *)r;

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
void SetupTwoSecondsSameDstServiceSynErrorRateCheck(void)

{
    /* map the keyword to an initialization/processing function */
    RegisterRuleOption("twoSecondsSameDstServiceSynErrorRate", TwoSecondsSameDstServiceSynErrorRateCheckInit, NULL, OPT_TYPE_DETECTION, NULL);
#ifdef PERF_PROFILING
    RegisterPreprocessorProfile("twoSecondsSameDstServiceSynErrorRate", &twoSecondsSameDstServiceSynErrorRatePerfStats, 3, &ruleOTNEvalPerfStats);
#endif
    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Plugin: TwoSecondsSameDstServiceSynErrorRate Check Initialized\n"););
}

void TwoSecondsSameDstServiceSynErrorRateCheckInit(struct _SnortConfig *sc, char *data, OptTreeNode *otn, int protocol)
{
    OptFpList *fpl;
    void *ds_ptr_dup;

    /* multiple declaration check */
    if(otn->ds_list[ PLUGIN_TWOSECONDSSAMEDSTSERVICESYNERRORRATE_CHECK])
    {
        FatalError("%s(%d): Multiple twoSecondsSameDstServiceSynErrorRate options in rule\n", file_name,
                file_line);
    }

    /* allocate the data structure and attach it to the
       rule's data struct list */
    otn->ds_list[PLUGIN_TWOSECONDSSAMEDSTSERVICESYNERRORRATE_CHECK] = (TwoSecondsSameDstServiceSynErrorRateCheckData *)SnortAlloc(sizeof(TwoSecondsSameDstServiceSynErrorRateCheckData));

    /* this is where the keyword arguments are processed and placed into the
       rule option's data structure */
    ParseTwoSecondsSameDstServiceSynErrorRate(sc,data, otn);
}

void ParseTwoSecondsSameDstServiceSynErrorRate(struct _SnortConfig *sc,char *data, OptTreeNode *otn)
{

	TwoSecondsSameDstServiceSynErrorRateCheckData *ds_ptr;  /* data struct pointer */
	    char *pcEnd;
	    char *pcTok;
	    float iDsize = 0;
	    void *ds_ptr_dup;
	    OptFpList *fpl;

	    /* set the ds pointer to make it easier to reference the option's
	       particular data struct */
	    ds_ptr = (TwoSecondsSameDstServiceSynErrorRateCheckData *)otn->ds_list[PLUGIN_TWOSECONDSSAMEDSTSERVICESYNERRORRATE_CHECK];

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
	            FatalError("%s(%d): Invalid 'twoSecondsSameDstServiceSynErrorRate' argument.\n",
	                       file_name, file_line);
	        }

	        iDsize = strtof(pcTok, &pcEnd);
	        if(iDsize < 0 || *pcEnd)
	        {
	            FatalError("%s(%d): Invalid 'twoSecondsSameDstServiceSynErrorRate' argument.\n",
	                       file_name, file_line);
	        }

	        ds_ptr->dsize = iDsize;

	        pcTok = strtok(NULL, " <>");
	        if(!pcTok)
	        {
	            FatalError("%s(%d): Invalid 'twoSecondsSameDstServiceSynErrorRate' argument.\n",
	                       file_name, file_line);
	        }

	        iDsize = strtof(pcTok, &pcEnd);
	        if(iDsize < 0 || *pcEnd)
	        {
	            FatalError("%s(%d): Invalid 'twoSecondsSameDstServiceSynErrorRate' argument.\n",
	                       file_name, file_line);
	        }

	        ds_ptr->dsize2 = iDsize;

	        ds_ptr->operator = TWOSECONDSSAMEDSTSERVICESYNERRORRATE_RANGE;

	#ifdef DEBUG_MSGS
	        DebugMessage(DEBUG_PLUGIN, "min twoSecondsSameDstServiceSynErrorRate: %f\n", ds_ptr->dsize);
	        DebugMessage(DEBUG_PLUGIN, "max twoSecondsSameDstServiceSynErrorRate: %f\n", ds_ptr->dsize2);
	#endif
	        fpl = AddOptFuncToList(TwoSecondsSameDstServiceSynErrorRateCheck, otn);
	        fpl->type = RULE_OPTION_TYPE_TWOSECONDSSAMEDSTSERVICESYNERRORRATE;

	        if (add_detection_option(sc, RULE_OPTION_TYPE_TWOSECONDSSAMEDSTSERVICESYNERRORRATE, (void *)ds_ptr, &ds_ptr_dup) == DETECTION_OPTION_EQUAL)
	        {
	            free(ds_ptr);
	            ds_ptr = otn->ds_list[PLUGIN_TWOSECONDSSAMEDSTSERVICESYNERRORRATE_CHECK] = ds_ptr_dup;
	        }
	        fpl->context = ds_ptr;

	        return;
	    }
	    else if(*data == '>')
	    {
	        data++;
	        if(*data=='='){
	        	ds_ptr->operator = TWOSECONDSSAMEDSTSERVICESYNERRORRATE_GTANDEQ;
	        	data++;
	        }else{
	        	ds_ptr->operator = TWOSECONDSSAMEDSTSERVICESYNERRORRATE_GT;
	        }
	        fpl = AddOptFuncToList(TwoSecondsSameDstServiceSynErrorRateCheck, otn);

	    }
	    else if(*data == '<')
	    {
	        data++;
	        if(*data=='='){
	        	ds_ptr->operator = TWOSECONDSSAMEDSTSERVICESYNERRORRATE_LTANDEQ;
	        	data++;
	        }else{
	        	ds_ptr->operator = TWOSECONDSSAMEDSTSERVICESYNERRORRATE_LT;
	        }
	        fpl = AddOptFuncToList(TwoSecondsSameDstServiceSynErrorRateCheck, otn);

	    }
	    else
	    {
	        fpl = AddOptFuncToList(TwoSecondsSameDstServiceSynErrorRateCheck, otn);
	        ds_ptr->operator = TWOSECONDSSAMEDSTSERVICESYNERRORRATE_EQ;
	    }

	    fpl->type = RULE_OPTION_TYPE_TWOSECONDSSAMEDSTSERVICESYNERRORRATE;

	    while(isspace((int)*data)) data++;

	    iDsize = strtof(data, &pcEnd);
	    if(iDsize < 0 || *pcEnd)
	    {
	        FatalError("%s(%d): Invalid 'twoSecondsSameDstServiceSynErrorRate' argument.\n",
	                   file_name, file_line);
	    }

	    ds_ptr->dsize = iDsize;

	    if (add_detection_option(sc, RULE_OPTION_TYPE_TWOSECONDSSAMEDSTSERVICESYNERRORRATE, (void *)ds_ptr, &ds_ptr_dup) == DETECTION_OPTION_EQUAL)
	    {
	        free(ds_ptr);
	        ds_ptr = otn->ds_list[PLUGIN_TWOSECONDSSAMEDSTSERVICESYNERRORRATE_CHECK] = ds_ptr_dup;
	     }
	     fpl->context = ds_ptr;

	    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "TWOSECONDSSAMEDSTSERVICESYNERRORRATE length = %f\n", ds_ptr->dsize););
	    //printf("dsize=%f\n",ds_ptr->dsize);
}

float getTwoSecondsSameDstServiceSynErrorRateByPakcet(Packet *p){
	float sameServiceErrorRate = 0;
	SessionKey key;
	SessionControlBlock *scb = NULL;
	scb = (SessionControlBlock *) (p->ssnptr);
	if (scb != NULL) {
		CountBefore2SecondsTCPSessionErrorStatistics(scb);
		scb->flagTrackConnection=1;
		sameServiceErrorRate =
				scb->two_seconds_same_server == 0 ?
						0 :
						((float) ((int) (((scb->two_seconds_same_server_syn_error
								* 1.0) / scb->two_seconds_same_server + 0.005)
								* 100))) / 100;
	}
	//printf("synError=%ld,sameServer=%ld,sp=%d,dp=%d\n",scb->two_seconds_same_server_syn_error,scb->two_seconds_same_server,p->sp,p->dp);
	return sameServiceErrorRate;
}

int TwoSecondsSameDstServiceSynErrorRateCheck(void *option_data, Packet *p)
{
	TwoSecondsSameDstServiceSynErrorRateCheckData *ds_ptr = (TwoSecondsSameDstServiceSynErrorRateCheckData *)option_data;
	    int rval = DETECTION_OPTION_NO_MATCH;
	    PROFILE_VARS;

	    if (!ds_ptr)
	        return rval;

	    PREPROC_PROFILE_START(twoSecondsSameDstServiceSynErrorRatePerfStats);

        float sameServiceErrorRate=getTwoSecondsSameDstServiceSynErrorRateByPakcet(p);
       // printf("spantime=%ld\n",spanTime);
	    switch (ds_ptr->operator)
	    {
	        case TWOSECONDSSAMEDSTSERVICESYNERRORRATE_EQ:
	            if (ds_ptr->dsize == sameServiceErrorRate)
	                rval = DETECTION_OPTION_MATCH;
	            break;
	        case TWOSECONDSSAMEDSTSERVICESYNERRORRATE_GT:
	            if (ds_ptr->dsize < sameServiceErrorRate)
	                rval = DETECTION_OPTION_MATCH;
	            break;
	        case TWOSECONDSSAMEDSTSERVICESYNERRORRATE_GTANDEQ:
	        	if (ds_ptr->dsize <= sameServiceErrorRate)
	        	     rval = DETECTION_OPTION_MATCH;
	        	break;
	        case TWOSECONDSSAMEDSTSERVICESYNERRORRATE_LT:
	            if (ds_ptr->dsize > sameServiceErrorRate)
	                rval = DETECTION_OPTION_MATCH;
	            break;
	        case TWOSECONDSSAMEDSTSERVICESYNERRORRATE_LTANDEQ:
	        	if (ds_ptr->dsize >= sameServiceErrorRate)
	        	     rval = DETECTION_OPTION_MATCH;
	        	 break;
	        case TWOSECONDSSAMEDSTSERVICESYNERRORRATE_RANGE:
	            if ((ds_ptr->dsize <= sameServiceErrorRate) &&
	                (ds_ptr->dsize2 >= sameServiceErrorRate))
	                rval = DETECTION_OPTION_MATCH;
	            break;
	        default:
	            break;
	    }

	    PREPROC_PROFILE_END(twoSecondsSameDstServiceSynErrorRatePerfStats);
	    //printf("twoSecondsSameDstServiceSynErrorRate=%f,rval=%d, sp=%d,dp=%d\n",sameServiceErrorRate,rval,p->sp,p->dp);
	    return rval;
}
