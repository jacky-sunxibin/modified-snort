

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
PreprocStats twoSecondsSameDstHostSynErrorRatePerfStats;
extern PreprocStats ruleOTNEvalPerfStats;
#endif
#include "detection_options.h"
#include "session_common.h"
#define TWOSECONDSSAMEDSTHOSTSYNERRORRATE_EQ                   1
#define TWOSECONDSSAMEDSTHOSTSYNERRORRATE_GT                   2
#define TWOSECONDSSAMEDSTHOSTSYNERRORRATE_LT                   3
#define TWOSECONDSSAMEDSTHOSTSYNERRORRATE_RANGE                4
#define TWOSECONDSSAMEDSTHOSTSYNERRORRATE_GTANDEQ              5
#define TWOSECONDSSAMEDSTHOSTSYNERRORRATE_LTANDEQ              6

typedef struct _TwoSecondsSameDstHostSynErrorRateCheckData
{
    float dsize;
    float dsize2;
    char operator;
} TwoSecondsSameDstHostSynErrorRateCheckData;



void TwoSecondsSameDstHostSynErrorRateCheckInit(struct _SnortConfig *, char *, OptTreeNode *, int);
void ParseTwoSecondsSameDstHostSynErrorRate(struct _SnortConfig *,char *, OptTreeNode *);
int TwoSecondsSameDstHostSynErrorRateCheck(void *option_data, Packet *p);


uint32_t TwoSecondsSameDstHostSynErrorRateCheckHash(void *d)
{
    int a,b,c;

     //NO data stored for the option

    a = RULE_OPTION_TYPE_TWOSECONDSSAMEDSTHOSTSYNERRORRATE;
    b = 0;
    c = 0;

    final(a,b,c);

    return c;
}

int TwoSecondsSameDstHostSynErrorRateCheckCompare(void *l, void *r)
{
	TwoSecondsSameDstHostSynErrorRateCheckData *left = (TwoSecondsSameDstHostSynErrorRateCheckData *)l;
	TwoSecondsSameDstHostSynErrorRateCheckData *right = (TwoSecondsSameDstHostSynErrorRateCheckData *)r;

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
void SetupTwoSecondsSameDstHostSynErrorRateCheck(void)

{
    /* map the keyword to an initialization/processing function */
    RegisterRuleOption("twoSecondsSameDstHostSynErrorRate", TwoSecondsSameDstHostSynErrorRateCheckInit, NULL, OPT_TYPE_DETECTION, NULL);
#ifdef PERF_PROFILING
    RegisterPreprocessorProfile("twoSecondsSameDstHostSynErrorRate", &twoSecondsSameDstHostSynErrorRatePerfStats, 3, &ruleOTNEvalPerfStats);
#endif
    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Plugin: TwoSecondsSameDstHostSynErrorRate Check Initialized\n"););
}

void TwoSecondsSameDstHostSynErrorRateCheckInit(struct _SnortConfig *sc, char *data, OptTreeNode *otn, int protocol)
{
    OptFpList *fpl;
    void *ds_ptr_dup;

    /* multiple declaration check */
    if(otn->ds_list[PLUGIN_TWOSECONDSSAMEDSTHOSTSYNERRORRATE_CHECK])
    {
        FatalError("%s(%d): Multiple twoSecondsSameDstHostSynErrorRate options in rule\n", file_name,
                file_line);
    }

    /* allocate the data structure and attach it to the
       rule's data struct list */
    otn->ds_list[PLUGIN_TWOSECONDSSAMEDSTHOSTSYNERRORRATE_CHECK] = (TwoSecondsSameDstHostSynErrorRateCheckData *)SnortAlloc(sizeof(TwoSecondsSameDstHostSynErrorRateCheckData));

    /* this is where the keyword arguments are processed and placed into the
       rule option's data structure */
    ParseTwoSecondsSameDstHostSynErrorRate(sc,data, otn);
}

void ParseTwoSecondsSameDstHostSynErrorRate(struct _SnortConfig *sc,char *data, OptTreeNode *otn)
{

	TwoSecondsSameDstHostSynErrorRateCheckData *ds_ptr;  /* data struct pointer */
	    char *pcEnd;
	    char *pcTok;
	    float iDsize = 0;
	    void *ds_ptr_dup;
	    OptFpList *fpl;
	    /* set the ds pointer to make it easier to reference the option's
	       particular data struct */
	    ds_ptr = (TwoSecondsSameDstHostSynErrorRateCheckData *)otn->ds_list[PLUGIN_TWOSECONDSSAMEDSTHOSTSYNERRORRATE_CHECK];

	    while(isspace((int)*data)) data++;

	    if(isdigit((int)*data) && strchr(data, '<') && strchr(data, '>'))
	    {
	        pcTok = strtok(data, " <>");
	        if(!pcTok)
	        {
	            /*
	            **  Fatal
	            */
	            FatalError("%s(%d): Invalid 'twoSecondsSameDstHostSynErrorRate' argument.\n",
	                       file_name, file_line);
	        }

	        iDsize = strtof(pcTok, &pcEnd);
	        if(iDsize < 0 || *pcEnd)
	        {
	            FatalError("%s(%d): Invalid 'twoSecondsSameDstHostSynErrorRate' argument.\n",
	                       file_name, file_line);
	        }

	        ds_ptr->dsize = iDsize;

	        pcTok = strtok(NULL, " <>");
	        if(!pcTok)
	        {
	            FatalError("%s(%d): Invalid 'twoSecondsSameDstHostSynErrorRate' argument.\n",
	                       file_name, file_line);
	        }

	        iDsize = strtof(pcTok, &pcEnd);
	        if(iDsize < 0 || *pcEnd)
	        {
	            FatalError("%s(%d): Invalid 'twoSecondsSameDstHostSynErrorRate' argument.\n",
	                       file_name, file_line);
	        }

	        ds_ptr->dsize2 = iDsize;

	        ds_ptr->operator = TWOSECONDSSAMEDSTHOSTSYNERRORRATE_RANGE;

	#ifdef DEBUG_MSGS
	        DebugMessage(DEBUG_PLUGIN, "min twoSecondsSameDstHostSynErrorRate: %f\n", ds_ptr->dsize);
	        DebugMessage(DEBUG_PLUGIN, "max twoSecondsSameDstHostSynErrorRate: %f\n", ds_ptr->dsize2);
	#endif
	        fpl = AddOptFuncToList(TwoSecondsSameDstHostSynErrorRateCheck, otn);
	        fpl->type = RULE_OPTION_TYPE_TWOSECONDSSAMEDSTHOSTSYNERRORRATE;

	        if (add_detection_option(sc, RULE_OPTION_TYPE_TWOSECONDSSAMEDSTHOSTSYNERRORRATE, (void *)ds_ptr, &ds_ptr_dup) == DETECTION_OPTION_EQUAL)
	        {
	            free(ds_ptr);
	            ds_ptr = otn->ds_list[PLUGIN_TWOSECONDSSAMEDSTHOSTSYNERRORRATE_CHECK] = ds_ptr_dup;
	        }
	        fpl->context = ds_ptr;

	        return;
	    }
	    else if(*data == '>')
	    {
	        data++;
	        if(*data=='='){
	        	ds_ptr->operator = TWOSECONDSSAMEDSTHOSTSYNERRORRATE_GTANDEQ;
	        	data++;
	        }else{
	        	ds_ptr->operator = TWOSECONDSSAMEDSTHOSTSYNERRORRATE_GT;
	        }
	        fpl = AddOptFuncToList(TwoSecondsSameDstHostSynErrorRateCheck, otn);
	    }
	    else if(*data == '<')
	    {
	        data++;
	        if(*data=='='){
	        	ds_ptr->operator = TWOSECONDSSAMEDSTHOSTSYNERRORRATE_LTANDEQ;
	        	data++;
	        }else{
	        	ds_ptr->operator = TWOSECONDSSAMEDSTHOSTSYNERRORRATE_LT;
	        }
	        fpl = AddOptFuncToList(TwoSecondsSameDstHostSynErrorRateCheck, otn);

	    }
	    else
	    {
	        fpl = AddOptFuncToList(TwoSecondsSameDstHostSynErrorRateCheck, otn);
	        ds_ptr->operator = TWOSECONDSSAMEDSTHOSTSYNERRORRATE_EQ;
	    }

	    fpl->type = RULE_OPTION_TYPE_TWOSECONDSSAMEDSTHOSTSYNERRORRATE;

	    while(isspace((int)*data)) data++;

	    iDsize = strtof(data, &pcEnd);
	    if(iDsize < 0 || *pcEnd)
	    {
	        FatalError("%s(%d): Invalid 'twoSecondsSameDstHostSynErrorRate' argument.\n",
	                   file_name, file_line);
	    }

	    ds_ptr->dsize = iDsize;

	    if (add_detection_option(sc, RULE_OPTION_TYPE_TWOSECONDSSAMEDSTHOSTSYNERRORRATE, (void *)ds_ptr, &ds_ptr_dup) == DETECTION_OPTION_EQUAL)
	    {
	        free(ds_ptr);
	        ds_ptr = otn->ds_list[PLUGIN_TWOSECONDSSAMEDSTHOSTSYNERRORRATE_CHECK] = ds_ptr_dup;
	     }
	     fpl->context = ds_ptr;

	    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "TWOSECONDSSAMEDSTHOSTSYNERRORRATE length = %f\n", ds_ptr->dsize););
	    //printf("dsize=%f\n",ds_ptr->dsize);
}

float getTwoSecondsSameDstHostSynErrorRateByPakcet(Packet *p){
	float sameHostErrorRate = 0;
	SessionKey key;
	SessionControlBlock *scb = NULL;
	scb = (SessionControlBlock *) (p->ssnptr);
	if (scb != NULL) {
		CountBefore2SecondsTCPSessionErrorStatistics(scb);
		scb->flagTrackConnection=1;
		sameHostErrorRate =
				scb->two_seconds_same_host == 0 ?
						0 :
						((float) ((int) (((scb->two_seconds_same_host_syn_error
								* 1.0) / scb->two_seconds_same_host + 0.005)
								* 100))) / 100;
	}
	//printf("synError=%ld,sameHost=%ld,sameHostError=%f\n",scb->two_seconds_same_host_syn_error,scb->two_seconds_same_host,sameHostErrorRate);
	return sameHostErrorRate;
}

int TwoSecondsSameDstHostSynErrorRateCheck(void *option_data, Packet *p)
{
	TwoSecondsSameDstHostSynErrorRateCheckData *ds_ptr = (TwoSecondsSameDstHostSynErrorRateCheckData *)option_data;
	    int rval = DETECTION_OPTION_NO_MATCH;
	    PROFILE_VARS;

	    if (!ds_ptr)
	        return rval;

	    PREPROC_PROFILE_START(twoSecondsSameDstHostSynErrorRatePerfStats);

        float sameHostErrorRate=getTwoSecondsSameDstHostSynErrorRateByPakcet(p);
       // printf("spantime=%ld\n",spanTime);
	    switch (ds_ptr->operator)
	    {
	        case TWOSECONDSSAMEDSTHOSTSYNERRORRATE_EQ:
	            if (ds_ptr->dsize == sameHostErrorRate)
	                rval = DETECTION_OPTION_MATCH;
	            break;
	        case TWOSECONDSSAMEDSTHOSTSYNERRORRATE_GT:
	            if (ds_ptr->dsize < sameHostErrorRate)
	                rval = DETECTION_OPTION_MATCH;
	            break;
	        case TWOSECONDSSAMEDSTHOSTSYNERRORRATE_GTANDEQ:
	        	if (ds_ptr->dsize <= sameHostErrorRate)
	        	     rval = DETECTION_OPTION_MATCH;
	        	break;
	        case TWOSECONDSSAMEDSTHOSTSYNERRORRATE_LT:
	            if (ds_ptr->dsize > sameHostErrorRate)
	                rval = DETECTION_OPTION_MATCH;
	            break;
	        case TWOSECONDSSAMEDSTHOSTSYNERRORRATE_LTANDEQ:
	        	if (ds_ptr->dsize >= sameHostErrorRate)
	        	     rval = DETECTION_OPTION_MATCH;
	        	break;
	        case TWOSECONDSSAMEDSTHOSTSYNERRORRATE_RANGE:
	            if ((ds_ptr->dsize <= sameHostErrorRate) &&
	                (ds_ptr->dsize2 >= sameHostErrorRate))
	                rval = DETECTION_OPTION_MATCH;
	            break;
	        default:
	            break;
	    }

	    PREPROC_PROFILE_END(twoSecondsSameDstHostSynErrorRatePerfStats);
	    //printf("twoSecondsSameDstHostSynErrorRate=%f,rval=%d,sp=%d\n",sameHostErrorRate,rval,p->sp);
	    return rval;
}
