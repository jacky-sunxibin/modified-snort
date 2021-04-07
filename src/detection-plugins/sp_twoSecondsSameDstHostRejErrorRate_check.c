

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
PreprocStats twoSecondsSameDstHostRejErrorRatePerfStats;
extern PreprocStats ruleOTNEvalPerfStats;
#endif
#include "detection_options.h"
#include "session_common.h"
#define TWOSECONDSSAMEDSTHOSTREJERRORRATE_EQ                   1
#define TWOSECONDSSAMEDSTHOSTREJERRORRATE_GT                   2
#define TWOSECONDSSAMEDSTHOSTREJERRORRATE_LT                   3
#define TWOSECONDSSAMEDSTHOSTREJERRORRATE_RANGE                4
#define TWOSECONDSSAMEDSTHOSTREJERRORRATE_GTANDEQ              5
#define TWOSECONDSSAMEDSTHOSTREJERRORRATE_LTANDEQ              6

typedef struct _TwoSecondsSameDstHostRejErrorRateCheckData
{
    float dsize;
    float dsize2;
    char operator;
} TwoSecondsSameDstHostRejErrorRateCheckData;



void TwoSecondsSameDstHostRejErrorRateCheckInit(struct _SnortConfig *, char *, OptTreeNode *, int);
void ParseTwoSecondsSameDstHostRejErrorRate(struct _SnortConfig *,char *, OptTreeNode *);
int TwoSecondsSameDstHostRejErrorRateCheck(void *option_data, Packet *p);


uint32_t TwoSecondsSameDstHostRejErrorRateCheckHash(void *d)
{
    int a,b,c;

     //NO data stored for the option

    a = RULE_OPTION_TYPE_TWOSECONDSSAMEDSTHOSTREJERRORRATE;
    b = 0;
    c = 0;

    final(a,b,c);

    return c;
}

int TwoSecondsSameDstHostRejErrorRateCheckCompare(void *l, void *r)
{
	TwoSecondsSameDstHostRejErrorRateCheckData *left = (TwoSecondsSameDstHostRejErrorRateCheckData *)l;
	TwoSecondsSameDstHostRejErrorRateCheckData *right = (TwoSecondsSameDstHostRejErrorRateCheckData *)r;

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
void SetupTwoSecondsSameDstHostRejErrorRateCheck(void)

{
    /* map the keyword to an initialization/processing function */
    RegisterRuleOption("twoSecondsSameDstHostRejErrorRate", TwoSecondsSameDstHostRejErrorRateCheckInit, NULL, OPT_TYPE_DETECTION, NULL);
#ifdef PERF_PROFILING
    RegisterPreprocessorProfile("twoSecondsSameDstHostRejErrorRate", &twoSecondsSameDstHostRejErrorRatePerfStats, 3, &ruleOTNEvalPerfStats);
#endif
    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Plugin: TwoSecondsSameDstHostRejErrorRate Check Initialized\n"););
}

void TwoSecondsSameDstHostRejErrorRateCheckInit(struct _SnortConfig *sc, char *data, OptTreeNode *otn, int protocol)
{
    OptFpList *fpl;
    void *ds_ptr_dup;

    /* multiple declaration check */
    if(otn->ds_list[PLUGIN_TWOSECONDSSAMEDSTHOSTREJERRORRATE_CHECK])
    {
        FatalError("%s(%d): Multiple twoSecondsSameDstHostRejErrorRate options in rule\n", file_name,
                file_line);
    }

    /* allocate the data structure and attach it to the
       rule's data struct list */
    otn->ds_list[PLUGIN_TWOSECONDSSAMEDSTHOSTREJERRORRATE_CHECK] = (TwoSecondsSameDstHostRejErrorRateCheckData *)SnortAlloc(sizeof(TwoSecondsSameDstHostRejErrorRateCheckData));

    /* this is where the keyword arguments are processed and placed into the
       rule option's data structure */
    ParseTwoSecondsSameDstHostRejErrorRate(sc,data, otn);
}

void ParseTwoSecondsSameDstHostRejErrorRate(struct _SnortConfig *sc,char *data, OptTreeNode *otn)
{

	TwoSecondsSameDstHostRejErrorRateCheckData *ds_ptr;  /* data struct pointer */
	    char *pcEnd;
	    char *pcTok;
	    float iDsize = 0;
	    void *ds_ptr_dup;
	    OptFpList *fpl;
	    /* set the ds pointer to make it easier to reference the option's
	       particular data struct */
	    ds_ptr = (TwoSecondsSameDstHostRejErrorRateCheckData *)otn->ds_list[PLUGIN_TWOSECONDSSAMEDSTHOSTREJERRORRATE_CHECK];

	    while(isspace((int)*data)) data++;

	    if(isdigit((int)*data) && strchr(data, '<') && strchr(data, '>'))
	    {
	        pcTok = strtok(data, " <>");
	        if(!pcTok)
	        {
	            /*
	            **  Fatal
	            */
	            FatalError("%s(%d): Invalid 'twoSecondsSameDstHostRejErrorRate' argument.\n",
	                       file_name, file_line);
	        }

	        iDsize = strtof(pcTok, &pcEnd);
	        if(iDsize < 0 || *pcEnd)
	        {
	            FatalError("%s(%d): Invalid 'twoSecondsSameDstHostRejErrorRate' argument.\n",
	                       file_name, file_line);
	        }

	        ds_ptr->dsize = iDsize;

	        pcTok = strtok(NULL, " <>");
	        if(!pcTok)
	        {
	            FatalError("%s(%d): Invalid 'twoSecondsSameDstHostRejErrorRate' argument.\n",
	                       file_name, file_line);
	        }

	        iDsize = strtof(pcTok, &pcEnd);
	        if(iDsize < 0 || *pcEnd)
	        {
	            FatalError("%s(%d): Invalid 'twoSecondsSameDstHostRejErrorRate' argument.\n",
	                       file_name, file_line);
	        }

	        ds_ptr->dsize2 = iDsize;

	        ds_ptr->operator = TWOSECONDSSAMEDSTHOSTREJERRORRATE_RANGE;

	#ifdef DEBUG_MSGS
	        DebugMessage(DEBUG_PLUGIN, "min twoSecondsSameDstHostRejErrorRate: %f\n", ds_ptr->dsize);
	        DebugMessage(DEBUG_PLUGIN, "max twoSecondsSameDstHostRejErrorRate: %f\n", ds_ptr->dsize2);
	#endif
	        fpl = AddOptFuncToList(TwoSecondsSameDstHostRejErrorRateCheck, otn);
	        fpl->type = RULE_OPTION_TYPE_TWOSECONDSSAMEDSTHOSTREJERRORRATE;

	        if (add_detection_option(sc, RULE_OPTION_TYPE_TWOSECONDSSAMEDSTHOSTREJERRORRATE, (void *)ds_ptr, &ds_ptr_dup) == DETECTION_OPTION_EQUAL)
	        {
	            free(ds_ptr);
	            ds_ptr = otn->ds_list[PLUGIN_TWOSECONDSSAMEDSTHOSTREJERRORRATE_CHECK] = ds_ptr_dup;
	        }
	        fpl->context = ds_ptr;

	        return;
	    }
	    else if(*data == '>')
	    {
	        data++;
	        if(*data=='='){
	        	ds_ptr->operator = TWOSECONDSSAMEDSTHOSTREJERRORRATE_GTANDEQ;
	        	data++;
	        }else{
	        	ds_ptr->operator = TWOSECONDSSAMEDSTHOSTREJERRORRATE_GT;
	        }
	        fpl = AddOptFuncToList(TwoSecondsSameDstHostRejErrorRateCheck, otn);
	    }
	    else if(*data == '<')
	    {
	        data++;
	        if(*data=='='){
	        	 ds_ptr->operator = TWOSECONDSSAMEDSTHOSTREJERRORRATE_LTANDEQ;
	        	 data++;
	        }else{
	        	ds_ptr->operator = TWOSECONDSSAMEDSTHOSTREJERRORRATE_LT;
	        }
	        fpl = AddOptFuncToList(TwoSecondsSameDstHostRejErrorRateCheck, otn);

	    }
	    else
	    {
	        fpl = AddOptFuncToList(TwoSecondsSameDstHostRejErrorRateCheck, otn);
	        ds_ptr->operator = TWOSECONDSSAMEDSTHOSTREJERRORRATE_EQ;
	    }

	    fpl->type = RULE_OPTION_TYPE_TWOSECONDSSAMEDSTHOSTREJERRORRATE;

	    while(isspace((int)*data)) data++;

	    iDsize = strtof(data, &pcEnd);
	    if(iDsize < 0 || *pcEnd)
	    {
	        FatalError("%s(%d): Invalid 'twoSecondsSameDstHostRejErrorRate' argument.\n",
	                   file_name, file_line);
	    }

	    ds_ptr->dsize = iDsize;

	    if (add_detection_option(sc, RULE_OPTION_TYPE_TWOSECONDSSAMEDSTHOSTREJERRORRATE, (void *)ds_ptr, &ds_ptr_dup) == DETECTION_OPTION_EQUAL)
	    {
	        free(ds_ptr);
	        ds_ptr = otn->ds_list[PLUGIN_TWOSECONDSSAMEDSTHOSTREJERRORRATE_CHECK] = ds_ptr_dup;
	     }
	     fpl->context = ds_ptr;

	    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "TWOSECONDSSAMEDSTHOSTREJERRORRATE length = %f\n", ds_ptr->dsize););
	    //printf("dsize=%f\n",ds_ptr->dsize);
}

float getTwoSecondsSameDstHostRejErrorRateByPakcet(Packet *p){
	float sameHostRejErrorRate = 0;
	SessionKey key;
	SessionControlBlock *scb = NULL;
	scb = (SessionControlBlock *) (p->ssnptr);
	if (scb != NULL) {
		CountBefore2SecondsTCPSessionErrorStatistics(scb);
		scb->flagTrackConnection=1;
		sameHostRejErrorRate =
				scb->two_seconds_same_host == 0 ?
						0 :
						((float) ((int) (((scb->two_seconds_same_host_rej_error
								* 1.0) / scb->two_seconds_same_host + 0.005)
								* 100))) / 100;
	}
	return sameHostRejErrorRate;
}

int TwoSecondsSameDstHostRejErrorRateCheck(void *option_data, Packet *p)
{
	TwoSecondsSameDstHostRejErrorRateCheckData *ds_ptr = (TwoSecondsSameDstHostRejErrorRateCheckData *)option_data;
	    int rval = DETECTION_OPTION_NO_MATCH;
	    PROFILE_VARS;

	    if (!ds_ptr)
	        return rval;

	    PREPROC_PROFILE_START(twoSecondsSameDstHostRejErrorRatePerfStats);

        float sameHostRejErrorRate=getTwoSecondsSameDstHostRejErrorRateByPakcet(p);
       // printf("spantime=%ld\n",spanTime);
	    switch (ds_ptr->operator)
	    {
	        case TWOSECONDSSAMEDSTHOSTREJERRORRATE_EQ:
	            if (ds_ptr->dsize == sameHostRejErrorRate)
	                rval = DETECTION_OPTION_MATCH;
	            break;
	        case TWOSECONDSSAMEDSTHOSTREJERRORRATE_GT:
	            if (ds_ptr->dsize < sameHostRejErrorRate)
	                rval = DETECTION_OPTION_MATCH;
	            break;
	        case TWOSECONDSSAMEDSTHOSTREJERRORRATE_GTANDEQ:
	        	if (ds_ptr->dsize <= sameHostRejErrorRate)
	        	     rval = DETECTION_OPTION_MATCH;
	        	 break;
	        case TWOSECONDSSAMEDSTHOSTREJERRORRATE_LT:
	            if (ds_ptr->dsize > sameHostRejErrorRate)
	                rval = DETECTION_OPTION_MATCH;
	            break;
	        case TWOSECONDSSAMEDSTHOSTREJERRORRATE_LTANDEQ:
	        	 if (ds_ptr->dsize >= sameHostRejErrorRate)
	        	     rval = DETECTION_OPTION_MATCH;
	        	 break;
	        case TWOSECONDSSAMEDSTHOSTREJERRORRATE_RANGE:
	            if ((ds_ptr->dsize <= sameHostRejErrorRate) &&
	                (ds_ptr->dsize2 >= sameHostRejErrorRate))
	                rval = DETECTION_OPTION_MATCH;
	            break;
	        default:
	            break;
	    }

	    PREPROC_PROFILE_END(twoSecondsSameDstHostRejErrorRatePerfStats);
	    //printf("twoSecondsSameDstHostRejErrorRate=%f,rval=%d\n",sameHostRejErrorRate,rval);
	    return rval;
}
