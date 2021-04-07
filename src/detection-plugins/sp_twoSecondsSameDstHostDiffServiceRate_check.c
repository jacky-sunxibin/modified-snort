

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
PreprocStats twoSecondsSameDstHostDiffServiceRatePerfStats;
extern PreprocStats ruleOTNEvalPerfStats;
#endif
#include "detection_options.h"
#include "session_common.h"
#define TWOSECONDSSAMEDSTHOSTDIFFSERVICERATE_EQ                   1
#define TWOSECONDSSAMEDSTHOSTDIFFSERVICERATE_GT                   2
#define TWOSECONDSSAMEDSTHOSTDIFFSERVICERATE_LT                   3
#define TWOSECONDSSAMEDSTHOSTDIFFSERVICERATE_RANGE                4
#define TWOSECONDSSAMEDSTHOSTDIFFSERVICERATE_GTANDEQ              5
#define TWOSECONDSSAMEDSTHOSTDIFFSERVICERATE_LTANDEQ              6

typedef struct _TwoSecondsSameDstHostDiffServiceRateCheckData
{
    float dsize;
    float dsize2;
    char operator;
} TwoSecondsSameDstHostDiffServiceRateCheckData;



void TwoSecondsSameDstHostDiffServiceRateCheckInit(struct _SnortConfig *, char *, OptTreeNode *, int);
void ParseTwoSecondsSameDstHostDiffServiceRate(struct _SnortConfig *,char *, OptTreeNode *);
int TwoSecondsSameDstHostDiffServiceRateCheck(void *option_data, Packet *p);


uint32_t TwoSecondsSameDstHostDiffServiceRateCheckHash(void *d)
{
    int a,b,c;

     //NO data stored for the option

    a = RULE_OPTION_TYPE_TWOSECONDSSAMEDSTHOSTDIFFSERVICERATE;
    b = 0;
    c = 0;

    final(a,b,c);

    return c;
}

int TwoSecondsSameDstHostDiffServiceRateCheckCompare(void *l, void *r)
{
	TwoSecondsSameDstHostDiffServiceRateCheckData *left = (TwoSecondsSameDstHostDiffServiceRateCheckData *)l;
	TwoSecondsSameDstHostDiffServiceRateCheckData *right = (TwoSecondsSameDstHostDiffServiceRateCheckData *)r;

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
void SetupTwoSecondsSameDstHostDiffServiceRateCheck(void)

{
    /* map the keyword to an initialization/processing function */
    RegisterRuleOption("twoSecondsSameDstHostDiffServiceRate", TwoSecondsSameDstHostDiffServiceRateCheckInit, NULL, OPT_TYPE_DETECTION, NULL);
#ifdef PERF_PROFILING
    RegisterPreprocessorProfile("twoSecondsSameDstHostDiffServiceRate", &twoSecondsSameDstHostDiffServiceRatePerfStats, 3, &ruleOTNEvalPerfStats);
#endif
    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Plugin: TwoSecondsSameDstHostDiffServiceRate Check Initialized\n"););
}

void TwoSecondsSameDstHostDiffServiceRateCheckInit(struct _SnortConfig *sc, char *data, OptTreeNode *otn, int protocol)
{
    OptFpList *fpl;
    void *ds_ptr_dup;

    /* multiple declaration check */
    if(otn->ds_list[PLUGIN_TWOSECONDSSAMEDSTHOSTDIFFSERVICERATE_CHECK])
    {
        FatalError("%s(%d): Multiple twoSecondsSameDstHostDiffServiceRate options in rule\n", file_name,
                file_line);
    }

    /* allocate the data structure and attach it to the
       rule's data struct list */
    otn->ds_list[PLUGIN_TWOSECONDSSAMEDSTHOSTDIFFSERVICERATE_CHECK] = (TwoSecondsSameDstHostDiffServiceRateCheckData *)SnortAlloc(sizeof(TwoSecondsSameDstHostDiffServiceRateCheckData));

    /* this is where the keyword arguments are processed and placed into the
       rule option's data structure */
    ParseTwoSecondsSameDstHostDiffServiceRate(sc,data, otn);
}

void ParseTwoSecondsSameDstHostDiffServiceRate(struct _SnortConfig *sc,char *data, OptTreeNode *otn)
{

	TwoSecondsSameDstHostDiffServiceRateCheckData *ds_ptr;  /* data struct pointer */
	    char *pcEnd;
	    char *pcTok;
	    float iDsize = 0;
	    void *ds_ptr_dup;
	    OptFpList *fpl;
	    /* set the ds pointer to make it easier to reference the option's
	       particular data struct */
	    ds_ptr = (TwoSecondsSameDstHostDiffServiceRateCheckData *)otn->ds_list[PLUGIN_TWOSECONDSSAMEDSTHOSTDIFFSERVICERATE_CHECK];

	    while(isspace((int)*data)) data++;

	    if(isdigit((int)*data) && strchr(data, '<') && strchr(data, '>'))
	    {
	        pcTok = strtok(data, " <>");
	        if(!pcTok)
	        {
	            /*
	            **  Fatal
	            */
	            FatalError("%s(%d): Invalid 'twoSecondsSameDstHostDiffServiceRate' argument.\n",
	                       file_name, file_line);
	        }

	        iDsize = strtof(pcTok, &pcEnd);
	        if(iDsize < 0 || *pcEnd)
	        {
	            FatalError("%s(%d): Invalid 'twoSecondsSameDstHostDiffServiceRate' argument.\n",
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
	            FatalError("%s(%d): Invalid 'twoSecondsSameDstHostDiffServiceRate' argument.\n",
	                       file_name, file_line);
	        }

	        ds_ptr->dsize2 = iDsize;

	        ds_ptr->operator = TWOSECONDSSAMEDSTHOSTDIFFSERVICERATE_RANGE;

	#ifdef DEBUG_MSGS
	        DebugMessage(DEBUG_PLUGIN, "min twoSecondsSameDstHostDiffServiceRate: %f\n", ds_ptr->dsize);
	        DebugMessage(DEBUG_PLUGIN, "max twoSecondsSameDstHostDiffServiceRate: %f\n", ds_ptr->dsize2);
	#endif
	        fpl = AddOptFuncToList(TwoSecondsSameDstHostDiffServiceRateCheck, otn);
	        fpl->type = RULE_OPTION_TYPE_TWOSECONDSSAMEDSTHOSTDIFFSERVICERATE;

	        if (add_detection_option(sc, RULE_OPTION_TYPE_TWOSECONDSSAMEDSTHOSTDIFFSERVICERATE, (void *)ds_ptr, &ds_ptr_dup) == DETECTION_OPTION_EQUAL)
	        {
	            free(ds_ptr);
	            ds_ptr = otn->ds_list[PLUGIN_TWOSECONDSSAMEDSTHOSTDIFFSERVICERATE_CHECK] = ds_ptr_dup;
	        }
	        fpl->context = ds_ptr;

	        return;
	    }
	    else if(*data == '>')
	    {
	        data++;
	        if(*data=='='){
	        	ds_ptr->operator = TWOSECONDSSAMEDSTHOSTDIFFSERVICERATE_GTANDEQ;
	        	data++;
	        }else{
	        	ds_ptr->operator = TWOSECONDSSAMEDSTHOSTDIFFSERVICERATE_GT;
	        }
	        fpl = AddOptFuncToList(TwoSecondsSameDstHostDiffServiceRateCheck, otn);
	    }
	    else if(*data == '<')
	    {
	        data++;
	        if(*data=='='){
	        	 ds_ptr->operator = TWOSECONDSSAMEDSTHOSTDIFFSERVICERATE_LTANDEQ;
	        	 data++;
	        }else{
	        	 ds_ptr->operator = TWOSECONDSSAMEDSTHOSTDIFFSERVICERATE_LT;
	        }
	        fpl = AddOptFuncToList(TwoSecondsSameDstHostDiffServiceRateCheck, otn);
	    }
	    else
	    {
	        fpl = AddOptFuncToList(TwoSecondsSameDstHostDiffServiceRateCheck, otn);
	        ds_ptr->operator = TWOSECONDSSAMEDSTHOSTDIFFSERVICERATE_EQ;
	    }

	    fpl->type = RULE_OPTION_TYPE_TWOSECONDSSAMEDSTHOSTDIFFSERVICERATE;

	    while(isspace((int)*data)) data++;

	    iDsize = strtof(data, &pcEnd);
	    if(iDsize < 0 || *pcEnd)
	    {
	        FatalError("%s(%d): Invalid 'twoSecondsSameDstHostDiffServiceRate' argument.\n",
	                   file_name, file_line);
	    }

	    ds_ptr->dsize = iDsize;

	    if (add_detection_option(sc, RULE_OPTION_TYPE_TWOSECONDSSAMEDSTHOSTDIFFSERVICERATE, (void *)ds_ptr, &ds_ptr_dup) == DETECTION_OPTION_EQUAL)
	    {
	        free(ds_ptr);
	        ds_ptr = otn->ds_list[PLUGIN_TWOSECONDSSAMEDSTHOSTDIFFSERVICERATE_CHECK] = ds_ptr_dup;
	     }
	     fpl->context = ds_ptr;

	    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "TWOSECONDSSAMEDSTHOSTDIFFSERVICERATE length = %f\n", ds_ptr->dsize););
	    //printf("dsize=%f\n",ds_ptr->dsize);
}

float getTwoSecondsSameDstHostDiffServiceRateByPakcet(Packet *p){
	float sameHostDiffServiceRate = 0;
	SessionKey key;
	SessionControlBlock *scb = NULL;
	scb = (SessionControlBlock *) (p->ssnptr);
	//printf("two_seconds_same_host=%d,two_seconds_same_host_and_server=%d,origin_server_port=%d, differ_server=%d\n",scb->two_seconds_same_host,scb->two_seconds_same_host_and_server,scb->origin_server_port,scb->two_seconds_same_host-scb->two_seconds_same_host_and_server);
	if (scb != NULL) {
		scb->flagTrackConnection=1;
		sameHostDiffServiceRate =
				scb->two_seconds_same_host == 0 ?
						0 :
						((float) ((int) ((( (scb->two_seconds_same_host-scb->two_seconds_same_host_and_server)
								* 1.0) / scb->two_seconds_same_host + 0.005)
								* 100))) / 100;
	}
	//printf("two_seconds_same_host=%d,two_seconds_same_host_and_server=%d,sp=%d,dp=%d\n",scb->two_seconds_same_host,scb->two_seconds_same_host_and_server,p->sp,p->dp);
	/*if(scb->two_seconds_same_host>scb->two_seconds_same_host_and_server)
	{
		printf("two_seconds_same_host=%d,two_seconds_same_host_and_server=%d\n",scb->two_seconds_same_host,scb->two_seconds_same_host_and_server);
	}*/

	return sameHostDiffServiceRate;
}

int TwoSecondsSameDstHostDiffServiceRateCheck(void *option_data, Packet *p)
{
	TwoSecondsSameDstHostDiffServiceRateCheckData *ds_ptr = (TwoSecondsSameDstHostDiffServiceRateCheckData *)option_data;
	    int rval = DETECTION_OPTION_NO_MATCH;
	    PROFILE_VARS;

	    if (!ds_ptr)
	        return rval;

	    PREPROC_PROFILE_START(twoSecondsSameDstHostDiffServiceRatePerfStats);

        float sameHostDiffServiceRate=getTwoSecondsSameDstHostDiffServiceRateByPakcet(p);
	    switch (ds_ptr->operator)
	    {
	        case TWOSECONDSSAMEDSTHOSTDIFFSERVICERATE_EQ:
	            if (ds_ptr->dsize == sameHostDiffServiceRate)
	                rval = DETECTION_OPTION_MATCH;
	            break;
	        case TWOSECONDSSAMEDSTHOSTDIFFSERVICERATE_GT:
	            if (ds_ptr->dsize < sameHostDiffServiceRate)
	                rval = DETECTION_OPTION_MATCH;
	            break;
	       case TWOSECONDSSAMEDSTHOSTDIFFSERVICERATE_GTANDEQ:
		        if (ds_ptr->dsize <= sameHostDiffServiceRate)
			        rval = DETECTION_OPTION_MATCH;
		        break;
	        case TWOSECONDSSAMEDSTHOSTDIFFSERVICERATE_LT:
	            if (ds_ptr->dsize > sameHostDiffServiceRate)
	                rval = DETECTION_OPTION_MATCH;
	            break;
	        case TWOSECONDSSAMEDSTHOSTDIFFSERVICERATE_LTANDEQ:
	       	     if (ds_ptr->dsize >= sameHostDiffServiceRate)
	       	        rval = DETECTION_OPTION_MATCH;
	       	    break;
	        case TWOSECONDSSAMEDSTHOSTDIFFSERVICERATE_RANGE:
	            if ((ds_ptr->dsize <= sameHostDiffServiceRate) &&
	                (ds_ptr->dsize2 >= sameHostDiffServiceRate))
	                rval = DETECTION_OPTION_MATCH;
	            break;
	        default:
	            break;
	    }

	    PREPROC_PROFILE_END(twoSecondsSameDstHostDiffServiceRatePerfStats);
	   // printf("twosecondsSameHostDiffServiceRate=%f,rval=%d\n",sameHostDiffServiceRate,rval);
	   	return rval;
}
