

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
PreprocStats twoSecondsSameDstServiceRejErrorRatePerfStats;
extern PreprocStats ruleOTNEvalPerfStats;
#endif
#include "detection_options.h"
#include "session_common.h"
#define TWOSECONDSSAMEDSTSERVICEREJERRORRATE_EQ                   1
#define TWOSECONDSSAMEDSTSERVICEREJERRORRATE_GT                   2
#define TWOSECONDSSAMEDSTSERVICEREJERRORRATE_LT                   3
#define TWOSECONDSSAMEDSTSERVICEREJERRORRATE_RANGE                4
#define TWOSECONDSSAMEDSTSERVICEREJERRORRATE_GTANDEQ              5
#define TWOSECONDSSAMEDSTSERVICEREJERRORRATE_LTANDEQ              6

typedef struct _TwoSecondsSameDstServiceRejErrorRateCheckData
{
    float dsize;
    float dsize2;
    char operator;
} TwoSecondsSameDstServiceRejErrorRateCheckData;



void TwoSecondsSameDstServiceRejErrorRateCheckInit(struct _SnortConfig *, char *, OptTreeNode *, int);
void ParseTwoSecondsSameDstServiceRejErrorRate(struct _SnortConfig *,char *, OptTreeNode *);
int TwoSecondsSameDstServiceRejErrorRateCheck(void *option_data, Packet *p);


uint32_t TwoSecondsSameDstServiceRejErrorRateCheckHash(void *d)
{
    int a,b,c;

     //NO data stored for the option

    a = RULE_OPTION_TYPE_TWOSECONDSSAMEDSTSERVICEREJERRORRATE;
    b = 0;
    c = 0;

    final(a,b,c);

    return c;
}

int TwoSecondsSameDstServiceRejErrorRateCheckCompare(void *l, void *r)
{
	TwoSecondsSameDstServiceRejErrorRateCheckData *left = (TwoSecondsSameDstServiceRejErrorRateCheckData *)l;
	TwoSecondsSameDstServiceRejErrorRateCheckData *right = (TwoSecondsSameDstServiceRejErrorRateCheckData *)r;

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
void SetupTwoSecondsSameDstServiceRejErrorRateCheck(void)

{
    /* map the keyword to an initialization/processing function */
    RegisterRuleOption("twoSecondsSameDstServiceRejErrorRate", TwoSecondsSameDstServiceRejErrorRateCheckInit, NULL, OPT_TYPE_DETECTION, NULL);
#ifdef PERF_PROFILING
    RegisterPreprocessorProfile("twoSecondsSameDstServiceRejErrorRate", &twoSecondsSameDstServiceRejErrorRatePerfStats, 3, &ruleOTNEvalPerfStats);
#endif
    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Plugin: TwoSecondsSameDstServiceRejErrorRate Check Initialized\n"););
}

void TwoSecondsSameDstServiceRejErrorRateCheckInit(struct _SnortConfig *sc, char *data, OptTreeNode *otn, int protocol)
{
    OptFpList *fpl;
    void *ds_ptr_dup;

    /* multiple declaration check */
    if(otn->ds_list[ PLUGIN_TWOSECONDSSAMEDSTSERVICEREJERRORRATE_CHECK])
    {
        FatalError("%s(%d): Multiple twoSecondsSameDstServiceRejErrorRate options in rule\n", file_name,
                file_line);
    }

    /* allocate the data structure and attach it to the
       rule's data struct list */
    otn->ds_list[PLUGIN_TWOSECONDSSAMEDSTSERVICEREJERRORRATE_CHECK] = (TwoSecondsSameDstServiceRejErrorRateCheckData *)SnortAlloc(sizeof(TwoSecondsSameDstServiceRejErrorRateCheckData));

    /* this is where the keyword arguments are processed and placed into the
       rule option's data structure */
    ParseTwoSecondsSameDstServiceRejErrorRate(sc,data, otn);
}

void ParseTwoSecondsSameDstServiceRejErrorRate(struct _SnortConfig *sc,char *data, OptTreeNode *otn)
{

	TwoSecondsSameDstServiceRejErrorRateCheckData *ds_ptr;  /* data struct pointer */
	    char *pcEnd;
	    char *pcTok;
	    float iDsize = 0;
	    void *ds_ptr_dup;
	    OptFpList *fpl;

	    /* set the ds pointer to make it easier to reference the option's
	       particular data struct */
	    ds_ptr = (TwoSecondsSameDstServiceRejErrorRateCheckData *)otn->ds_list[PLUGIN_TWOSECONDSSAMEDSTSERVICEREJERRORRATE_CHECK];

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
	            FatalError("%s(%d): Invalid 'twoSecondsSameDstServiceRejErrorRate' argument.\n",
	                       file_name, file_line);
	        }

	        iDsize = strtof(pcTok, &pcEnd);
	        if(iDsize < 0 || *pcEnd)
	        {
	            FatalError("%s(%d): Invalid 'twoSecondsSameDstServiceRejErrorRate' argument.\n",
	                       file_name, file_line);
	        }

	        ds_ptr->dsize = iDsize;

	        pcTok = strtok(NULL, " <>");
	        if(!pcTok)
	        {
	            FatalError("%s(%d): Invalid 'twoSecondsSameDstServiceRejErrorRate' argument.\n",
	                       file_name, file_line);
	        }

	        iDsize = strtof(pcTok, &pcEnd);
	        if(iDsize < 0 || *pcEnd)
	        {
	            FatalError("%s(%d): Invalid 'twoSecondsSameDstServiceRejErrorRate' argument.\n",
	                       file_name, file_line);
	        }

	        ds_ptr->dsize2 = iDsize;

	        ds_ptr->operator = TWOSECONDSSAMEDSTSERVICEREJERRORRATE_RANGE;

	#ifdef DEBUG_MSGS
	        DebugMessage(DEBUG_PLUGIN, "min twoSecondsSameDstServiceRejErrorRate: %f\n", ds_ptr->dsize);
	        DebugMessage(DEBUG_PLUGIN, "max twoSecondsSameDstServiceRejErrorRate: %f\n", ds_ptr->dsize2);
	#endif
	        fpl = AddOptFuncToList(TwoSecondsSameDstServiceRejErrorRateCheck, otn);
	        fpl->type = RULE_OPTION_TYPE_TWOSECONDSSAMEDSTSERVICEREJERRORRATE;

	        if (add_detection_option(sc, RULE_OPTION_TYPE_TWOSECONDSSAMEDSTSERVICEREJERRORRATE, (void *)ds_ptr, &ds_ptr_dup) == DETECTION_OPTION_EQUAL)
	        {
	            free(ds_ptr);
	            ds_ptr = otn->ds_list[PLUGIN_TWOSECONDSSAMEDSTSERVICEREJERRORRATE_CHECK] = ds_ptr_dup;
	        }
	        fpl->context = ds_ptr;

	        return;
	    }
	    else if(*data == '>')
	    {
	        data++;
	        if(*data=='='){
	        	ds_ptr->operator = TWOSECONDSSAMEDSTSERVICEREJERRORRATE_GTANDEQ;
	        	data++;
	        }else{
	        	ds_ptr->operator = TWOSECONDSSAMEDSTSERVICEREJERRORRATE_GT;
	        }
	        fpl = AddOptFuncToList(TwoSecondsSameDstServiceRejErrorRateCheck, otn);

	    }
	    else if(*data == '<')
	    {
	        data++;
	        if(*data=='='){
	        	 ds_ptr->operator = TWOSECONDSSAMEDSTSERVICEREJERRORRATE_LTANDEQ;
	        	 data++;
	        }else{
	        	 ds_ptr->operator = TWOSECONDSSAMEDSTSERVICEREJERRORRATE_LT;
	        }
	        fpl = AddOptFuncToList(TwoSecondsSameDstServiceRejErrorRateCheck, otn);

	    }
	    else
	    {
	        fpl = AddOptFuncToList(TwoSecondsSameDstServiceRejErrorRateCheck, otn);
	        ds_ptr->operator = TWOSECONDSSAMEDSTSERVICEREJERRORRATE_EQ;
	    }

	    fpl->type = RULE_OPTION_TYPE_TWOSECONDSSAMEDSTSERVICEREJERRORRATE;

	    while(isspace((int)*data)) data++;

	    iDsize = strtof(data, &pcEnd);
	    if(iDsize < 0 || *pcEnd)
	    {
	        FatalError("%s(%d): Invalid 'twoSecondsSameDstServiceRejErrorRate' argument.\n",
	                   file_name, file_line);
	    }

	    ds_ptr->dsize = iDsize;

	    if (add_detection_option(sc, RULE_OPTION_TYPE_TWOSECONDSSAMEDSTSERVICEREJERRORRATE, (void *)ds_ptr, &ds_ptr_dup) == DETECTION_OPTION_EQUAL)
	    {
	        free(ds_ptr);
	        ds_ptr = otn->ds_list[PLUGIN_TWOSECONDSSAMEDSTSERVICEREJERRORRATE_CHECK] = ds_ptr_dup;
	     }
	     fpl->context = ds_ptr;

	    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "TWOSECONDSSAMEDSTSERVICEREJERRORRATE length = %f\n", ds_ptr->dsize););
	    //printf("dsize=%f\n",ds_ptr->dsize);
}

float getTwoSecondsSameDstServiceRejErrorRateByPakcet(Packet *p){
	float sameServiceRejErrorRate = 0;
	SessionKey key;
	SessionControlBlock *scb = NULL;
	scb = (SessionControlBlock *) (p->ssnptr);
	if (scb != NULL) {
		CountBefore2SecondsTCPSessionErrorStatistics(scb);
		scb->flagTrackConnection=1;
		sameServiceRejErrorRate =
				scb->two_seconds_same_server == 0 ?
						0 :
						((float) ((int) (((scb->two_seconds_same_server_rej_error
								* 1.0) / scb->two_seconds_same_server + 0.005)
								* 100))) / 100;
	}
	return sameServiceRejErrorRate;
}

int TwoSecondsSameDstServiceRejErrorRateCheck(void *option_data, Packet *p)
{
	TwoSecondsSameDstServiceRejErrorRateCheckData *ds_ptr = (TwoSecondsSameDstServiceRejErrorRateCheckData *)option_data;
	    int rval = DETECTION_OPTION_NO_MATCH;
	    PROFILE_VARS;

	    if (!ds_ptr)
	        return rval;

	    PREPROC_PROFILE_START(twoSecondsSameDstServiceRejErrorRatePerfStats);

        float sameServiceRejErrorRate=getTwoSecondsSameDstServiceRejErrorRateByPakcet(p);
       // printf("spantime=%ld\n",spanTime);
	    switch (ds_ptr->operator)
	    {
	        case TWOSECONDSSAMEDSTSERVICEREJERRORRATE_EQ:
	            if (ds_ptr->dsize == sameServiceRejErrorRate)
	                rval = DETECTION_OPTION_MATCH;
	            break;
	        case TWOSECONDSSAMEDSTSERVICEREJERRORRATE_GT:
	            if (ds_ptr->dsize < sameServiceRejErrorRate)
	                rval = DETECTION_OPTION_MATCH;
	            break;
	        case TWOSECONDSSAMEDSTSERVICEREJERRORRATE_GTANDEQ:
	        	if (ds_ptr->dsize <= sameServiceRejErrorRate)
	        	     rval = DETECTION_OPTION_MATCH;
	        	 break;
	        case TWOSECONDSSAMEDSTSERVICEREJERRORRATE_LT:
	            if (ds_ptr->dsize > sameServiceRejErrorRate)
	                rval = DETECTION_OPTION_MATCH;
	            break;
	        case TWOSECONDSSAMEDSTSERVICEREJERRORRATE_LTANDEQ:
	        	 if (ds_ptr->dsize >= sameServiceRejErrorRate)
	        	     rval = DETECTION_OPTION_MATCH;
	        	 break;
	        case TWOSECONDSSAMEDSTSERVICEREJERRORRATE_RANGE:
	            if ((ds_ptr->dsize <= sameServiceRejErrorRate) &&
	                (ds_ptr->dsize2 >= sameServiceRejErrorRate))
	                rval = DETECTION_OPTION_MATCH;
	            break;
	        default:
	            break;
	    }

	    PREPROC_PROFILE_END(twoSecondsSameDstServiceRejErrorRatePerfStats);
	    //printf("twoSecondsSameDstServiceRejErrorRate=%f,rval=%d\n",sameServiceRejErrorRate,rval);
	    return rval;
}
