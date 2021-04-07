

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
PreprocStats twoSecondsSameDstServiceDiffDstHostRatePerfStats;
extern PreprocStats ruleOTNEvalPerfStats;
#endif
#include "detection_options.h"
#include "session_common.h"
#define TWOSECONDSSAMEDSTSERVICEDIFFDSTHOSTRATE_EQ                   1
#define TWOSECONDSSAMEDSTSERVICEDIFFDSTHOSTRATE_GT                   2
#define TWOSECONDSSAMEDSTSERVICEDIFFDSTHOSTRATE_LT                   3
#define TWOSECONDSSAMEDSTSERVICEDIFFDSTHOSTRATE_RANGE                4
#define TWOSECONDSSAMEDSTSERVICEDIFFDSTHOSTRATE_GTANDEQ              5
#define TWOSECONDSSAMEDSTSERVICEDIFFDSTHOSTRATE_LTANDEQ              6

typedef struct _TwoSecondsSameDstServiceDiffDstHostRateCheckData
{
    float dsize;
    float dsize2;
    char operator;
} TwoSecondsSameDstServiceDiffDstHostRateCheckData;



void TwoSecondsSameDstServiceDiffDstHostRateCheckInit(struct _SnortConfig *, char *, OptTreeNode *, int);
void ParseTwoSecondsSameDstServiceDiffDstHostRate(struct _SnortConfig *,char *, OptTreeNode *);
int TwoSecondsSameDstServiceDiffDstHostRateCheck(void *option_data, Packet *p);


uint32_t TwoSecondsSameDstServiceDiffDstHostRateCheckHash(void *d)
{
    int a,b,c;

     //NO data stored for the option

    a = RULE_OPTION_TYPE_TWOSECONDSSAMEDSTSERVICEDIFFDSTHOSTRATE;
    b = 0;
    c = 0;

    final(a,b,c);

    return c;
}

int TwoSecondsSameDstServiceDiffDstHostRateCheckCompare(void *l, void *r)
{
	TwoSecondsSameDstServiceDiffDstHostRateCheckData *left = (TwoSecondsSameDstServiceDiffDstHostRateCheckData *)l;
	TwoSecondsSameDstServiceDiffDstHostRateCheckData *right = (TwoSecondsSameDstServiceDiffDstHostRateCheckData *)r;

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
void SetupTwoSecondsSameDstServiceDiffDstHostRateCheck(void)

{
    /* map the keyword to an initialization/processing function */
    RegisterRuleOption("twoSecondsSameDstServiceDiffDstHostRate", TwoSecondsSameDstServiceDiffDstHostRateCheckInit, NULL, OPT_TYPE_DETECTION, NULL);
#ifdef PERF_PROFILING
    RegisterPreprocessorProfile("twoSecondsSameDstServiceDiffDstHostRate", &twoSecondsSameDstServiceDiffDstHostRatePerfStats, 3, &ruleOTNEvalPerfStats);
#endif
    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Plugin: TwoSecondsSameDstServiceDiffDstHostRate Check Initialized\n"););
}

void TwoSecondsSameDstServiceDiffDstHostRateCheckInit(struct _SnortConfig *sc, char *data, OptTreeNode *otn, int protocol)
{
    OptFpList *fpl;
    void *ds_ptr_dup;

    /* multiple declaration check */
    if(otn->ds_list[ PLUGIN_TWOSECONDSSAMEDSTSERVICEDIFFDSTHOSTRATE_CHECK])
    {
        FatalError("%s(%d): Multiple twoSecondsSameDstServiceDiffDstHostRate options in rule\n", file_name,
                file_line);
    }

    /* allocate the data structure and attach it to the
       rule's data struct list */
    otn->ds_list[PLUGIN_TWOSECONDSSAMEDSTSERVICEDIFFDSTHOSTRATE_CHECK] = (TwoSecondsSameDstServiceDiffDstHostRateCheckData *)SnortAlloc(sizeof(TwoSecondsSameDstServiceDiffDstHostRateCheckData));

    /* this is where the keyword arguments are processed and placed into the
       rule option's data structure */
    ParseTwoSecondsSameDstServiceDiffDstHostRate(sc,data, otn);
}

void ParseTwoSecondsSameDstServiceDiffDstHostRate(struct _SnortConfig *sc,char *data, OptTreeNode *otn)
{

	TwoSecondsSameDstServiceDiffDstHostRateCheckData *ds_ptr;  /* data struct pointer */
	    char *pcEnd;
	    char *pcTok;
	    float iDsize = 0;
	    void *ds_ptr_dup;
	    OptFpList *fpl;

	    /* set the ds pointer to make it easier to reference the option's
	       particular data struct */
	    ds_ptr = (TwoSecondsSameDstServiceDiffDstHostRateCheckData *)otn->ds_list[PLUGIN_TWOSECONDSSAMEDSTSERVICEDIFFDSTHOSTRATE_CHECK];

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
	            FatalError("%s(%d): Invalid 'twoSecondsSameDstServiceDiffDstHostRate' argument.\n",
	                       file_name, file_line);
	        }

	        iDsize = strtof(pcTok, &pcEnd);
	        if(iDsize < 0 || *pcEnd)
	        {
	            FatalError("%s(%d): Invalid 'twoSecondsSameDstServiceDiffDstHostRate' argument.\n",
	                       file_name, file_line);
	        }

	        ds_ptr->dsize = iDsize;

	        pcTok = strtok(NULL, " <>");
	        if(!pcTok)
	        {
	            FatalError("%s(%d): Invalid 'twoSecondsSameDstServiceDiffDstHostRate' argument.\n",
	                       file_name, file_line);
	        }

	        iDsize = strtof(pcTok, &pcEnd);
	        if(iDsize < 0 || *pcEnd)
	        {
	            FatalError("%s(%d): Invalid 'twoSecondsSameDstServiceDiffDstHostRate' argument.\n",
	                       file_name, file_line);
	        }

	        ds_ptr->dsize2 = iDsize;

	        ds_ptr->operator = TWOSECONDSSAMEDSTSERVICEDIFFDSTHOSTRATE_RANGE;

	#ifdef DEBUG_MSGS
	        DebugMessage(DEBUG_PLUGIN, "min twoSecondsSameDstServiceDiffDstHostRate: %f\n", ds_ptr->dsize);
	        DebugMessage(DEBUG_PLUGIN, "max twoSecondsSameDstServiceDiffDstHostRate: %f\n", ds_ptr->dsize2);
	#endif
	        fpl = AddOptFuncToList(TwoSecondsSameDstServiceDiffDstHostRateCheck, otn);
	        fpl->type = RULE_OPTION_TYPE_TWOSECONDSSAMEDSTSERVICEDIFFDSTHOSTRATE;

	        if (add_detection_option(sc, RULE_OPTION_TYPE_TWOSECONDSSAMEDSTSERVICEDIFFDSTHOSTRATE, (void *)ds_ptr, &ds_ptr_dup) == DETECTION_OPTION_EQUAL)
	        {
	            free(ds_ptr);
	            ds_ptr = otn->ds_list[PLUGIN_TWOSECONDSSAMEDSTSERVICEDIFFDSTHOSTRATE_CHECK] = ds_ptr_dup;
	        }
	        fpl->context = ds_ptr;

	        return;
	    }
	    else if(*data == '>')
	    {
	        data++;
	        if(*data=='='){
	        	ds_ptr->operator = TWOSECONDSSAMEDSTSERVICEDIFFDSTHOSTRATE_GTANDEQ;
	        	data++;
	        }else{
	        	ds_ptr->operator = TWOSECONDSSAMEDSTSERVICEDIFFDSTHOSTRATE_GT;
	        }
	        fpl = AddOptFuncToList(TwoSecondsSameDstServiceDiffDstHostRateCheck, otn);

	    }
	    else if(*data == '<')
	    {
	        data++;
	        if(*data=='='){
	        	ds_ptr->operator = TWOSECONDSSAMEDSTSERVICEDIFFDSTHOSTRATE_LTANDEQ;
	        	data++;
	        }else{
	        	ds_ptr->operator = TWOSECONDSSAMEDSTSERVICEDIFFDSTHOSTRATE_LT;
	        }
	        fpl = AddOptFuncToList(TwoSecondsSameDstServiceDiffDstHostRateCheck, otn);

	    }
	    else
	    {
	        fpl = AddOptFuncToList(TwoSecondsSameDstServiceDiffDstHostRateCheck, otn);
	        ds_ptr->operator = TWOSECONDSSAMEDSTSERVICEDIFFDSTHOSTRATE_EQ;
	    }

	    fpl->type = RULE_OPTION_TYPE_TWOSECONDSSAMEDSTSERVICEDIFFDSTHOSTRATE;

	    while(isspace((int)*data)) data++;

	    iDsize = strtof(data, &pcEnd);
	    if(iDsize < 0 || *pcEnd)
	    {
	        FatalError("%s(%d): Invalid 'twoSecondsSameDstServiceDiffDstHostRate' argument.\n",
	                   file_name, file_line);
	    }

	    ds_ptr->dsize = iDsize;

	    if (add_detection_option(sc, RULE_OPTION_TYPE_TWOSECONDSSAMEDSTSERVICEDIFFDSTHOSTRATE, (void *)ds_ptr, &ds_ptr_dup) == DETECTION_OPTION_EQUAL)
	    {
	        free(ds_ptr);
	        ds_ptr = otn->ds_list[PLUGIN_TWOSECONDSSAMEDSTSERVICEDIFFDSTHOSTRATE_CHECK] = ds_ptr_dup;
	     }
	     fpl->context = ds_ptr;

	    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "TWOSECONDSSAMEDSTSERVICEDIFFDSTHOSTRATE length = %f\n", ds_ptr->dsize););
	    //printf("dsize=%f\n",ds_ptr->dsize);
}

float getTwoSecondsSameDstServiceDiffDstHostRateByPakcet(Packet *p){
	float sameServiceDiffDstHostRate = 0;
	SessionKey key;
	SessionControlBlock *scb = NULL;
	scb = (SessionControlBlock *) (p->ssnptr);
	if (scb != NULL) {
		scb->flagTrackConnection=1;
		sameServiceDiffDstHostRate =
				scb->two_seconds_same_server == 0 ?
						0 :
						((float) ((int) ((( (scb->two_seconds_same_server-scb->two_seconds_same_host_and_server)
								* 1.0) / scb->two_seconds_same_server + 0.005)
								* 100))) / 100;
	}
	return sameServiceDiffDstHostRate;
}

int TwoSecondsSameDstServiceDiffDstHostRateCheck(void *option_data, Packet *p)
{
	TwoSecondsSameDstServiceDiffDstHostRateCheckData *ds_ptr = (TwoSecondsSameDstServiceDiffDstHostRateCheckData *)option_data;
	    int rval = DETECTION_OPTION_NO_MATCH;
	    PROFILE_VARS;

	    if (!ds_ptr)
	        return rval;

	    PREPROC_PROFILE_START(twoSecondsSameDstServiceDiffDstHostRatePerfStats);

        float sameServiceDiffDstHostRate=getTwoSecondsSameDstServiceDiffDstHostRateByPakcet(p);
       // printf("spantime=%ld\n",spanTime);
	    switch (ds_ptr->operator)
	    {
	        case TWOSECONDSSAMEDSTSERVICEDIFFDSTHOSTRATE_EQ:
	            if (ds_ptr->dsize == sameServiceDiffDstHostRate)
	                rval = DETECTION_OPTION_MATCH;
	            break;
	        case TWOSECONDSSAMEDSTSERVICEDIFFDSTHOSTRATE_GT:
	            if (ds_ptr->dsize < sameServiceDiffDstHostRate)
	                rval = DETECTION_OPTION_MATCH;
	            break;
	        case TWOSECONDSSAMEDSTSERVICEDIFFDSTHOSTRATE_GTANDEQ:
	        	 if (ds_ptr->dsize <= sameServiceDiffDstHostRate)
	        	     rval = DETECTION_OPTION_MATCH;
	        	 break;
	        case TWOSECONDSSAMEDSTSERVICEDIFFDSTHOSTRATE_LT:
	            if (ds_ptr->dsize > sameServiceDiffDstHostRate)
	                rval = DETECTION_OPTION_MATCH;
	            break;
	        case TWOSECONDSSAMEDSTSERVICEDIFFDSTHOSTRATE_LTANDEQ:
	        	if (ds_ptr->dsize >= sameServiceDiffDstHostRate)
	        	     rval = DETECTION_OPTION_MATCH;
	        	break;
	        case TWOSECONDSSAMEDSTSERVICEDIFFDSTHOSTRATE_RANGE:
	            if ((ds_ptr->dsize <= sameServiceDiffDstHostRate) &&
	                (ds_ptr->dsize2 >= sameServiceDiffDstHostRate))
	                rval = DETECTION_OPTION_MATCH;
	            break;
	        default:
	            break;
	    }

	    PREPROC_PROFILE_END(twoSecondsSameDstServiceDiffDstHostRatePerfStats);
	    return rval;
}
