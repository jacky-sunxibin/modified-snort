

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
PreprocStats twoSecondsSameDstHostServiceRatePerfStats;
extern PreprocStats ruleOTNEvalPerfStats;
#endif
#include "detection_options.h"
#include "session_common.h"
#define TWOSECONDSSAMEDSTHOSTSERVICERATE_EQ                   1
#define TWOSECONDSSAMEDSTHOSTSERVICERATE_GT                   2
#define TWOSECONDSSAMEDSTHOSTSERVICERATE_LT                   3
#define TWOSECONDSSAMEDSTHOSTSERVICERATE_RANGE                4
#define TWOSECONDSSAMEDSTHOSTSERVICERATE_GTANDEQ              5
#define TWOSECONDSSAMEDSTHOSTSERVICERATE_LTANDEQ              6

typedef struct _TwoSecondsSameDstHostServiceRateCheckData
{
    float dsize;
    float dsize2;
    char operator;
} TwoSecondsSameDstHostServiceRateCheckData;



void TwoSecondsSameDstHostServiceRateCheckInit(struct _SnortConfig *, char *, OptTreeNode *, int);
void ParseTwoSecondsSameDstHostServiceRate(struct _SnortConfig *,char *, OptTreeNode *);
int TwoSecondsSameDstHostServiceRateCheck(void *option_data, Packet *p);


uint32_t TwoSecondsSameDstHostServiceRateCheckHash(void *d)
{
    int a,b,c;

     //NO data stored for the option

    a = RULE_OPTION_TYPE_TWOSECONDSSAMEDSTHOSTSERVICERATE;
    b = 0;
    c = 0;

    final(a,b,c);

    return c;
}

int TwoSecondsSameDstHostServiceRateCheckCompare(void *l, void *r)
{
	TwoSecondsSameDstHostServiceRateCheckData *left = (TwoSecondsSameDstHostServiceRateCheckData *)l;
	TwoSecondsSameDstHostServiceRateCheckData *right = (TwoSecondsSameDstHostServiceRateCheckData *)r;

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
void SetupTwoSecondsSameDstHostServiceRateCheck(void)

{
    /* map the keyword to an initialization/processing function */
    RegisterRuleOption("twoSecondsSameDstHostServiceRate", TwoSecondsSameDstHostServiceRateCheckInit, NULL, OPT_TYPE_DETECTION, NULL);
#ifdef PERF_PROFILING
    RegisterPreprocessorProfile("twoSecondsSameDstHostServiceRate", &twoSecondsSameDstHostServiceRatePerfStats, 3, &ruleOTNEvalPerfStats);
#endif
    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Plugin: TwoSecondsSameDstHostServiceRate Check Initialized\n"););
}

void TwoSecondsSameDstHostServiceRateCheckInit(struct _SnortConfig *sc, char *data, OptTreeNode *otn, int protocol)
{
    OptFpList *fpl;
    void *ds_ptr_dup;

    /* multiple declaration check */
    if(otn->ds_list[PLUGIN_TWOSECONDSSAMEDSTHOSTSERVICERATE_CHECK])
    {
        FatalError("%s(%d): Multiple twoSecondsSameDstHostServiceRate options in rule\n", file_name,
                file_line);
    }

    /* allocate the data structure and attach it to the
       rule's data struct list */
    otn->ds_list[PLUGIN_TWOSECONDSSAMEDSTHOSTSERVICERATE_CHECK] = (TwoSecondsSameDstHostServiceRateCheckData *)SnortAlloc(sizeof(TwoSecondsSameDstHostServiceRateCheckData));

    /* this is where the keyword arguments are processed and placed into the
       rule option's data structure */
    ParseTwoSecondsSameDstHostServiceRate(sc,data, otn);
}

void ParseTwoSecondsSameDstHostServiceRate(struct _SnortConfig *sc,char *data, OptTreeNode *otn)
{

	TwoSecondsSameDstHostServiceRateCheckData *ds_ptr;  /* data struct pointer */
	    char *pcEnd;
	    char *pcTok;
	    float iDsize = 0;
	    void *ds_ptr_dup;
	    OptFpList *fpl;
	    /* set the ds pointer to make it easier to reference the option's
	       particular data struct */
	    ds_ptr = (TwoSecondsSameDstHostServiceRateCheckData *)otn->ds_list[PLUGIN_TWOSECONDSSAMEDSTHOSTSERVICERATE_CHECK];

	    while(isspace((int)*data)) data++;

	    if(isdigit((int)*data) && strchr(data, '<') && strchr(data, '>'))
	    {
	        pcTok = strtok(data, " <>");
	        if(!pcTok)
	        {
	            /*
	            **  Fatal
	            */
	            FatalError("%s(%d): Invalid 'twoSecondsSameDstHostServiceRate' argument.\n",
	                       file_name, file_line);
	        }

	        iDsize = strtof(pcTok, &pcEnd);
	        if(iDsize < 0 || *pcEnd)
	        {
	            FatalError("%s(%d): Invalid 'twoSecondsSameDstHostServiceRate' argument.\n",
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
	            FatalError("%s(%d): Invalid 'twoSecondsSameDstHostServiceRate' argument.\n",
	                       file_name, file_line);
	        }

	        ds_ptr->dsize2 = iDsize;

	        ds_ptr->operator = TWOSECONDSSAMEDSTHOSTSERVICERATE_RANGE;

	#ifdef DEBUG_MSGS
	        DebugMessage(DEBUG_PLUGIN, "min twoSecondsSameDstHostServiceRate: %f\n", ds_ptr->dsize);
	        DebugMessage(DEBUG_PLUGIN, "max twoSecondsSameDstHostServiceRate: %f\n", ds_ptr->dsize2);
	#endif
	        fpl = AddOptFuncToList(TwoSecondsSameDstHostServiceRateCheck, otn);
	        fpl->type = RULE_OPTION_TYPE_TWOSECONDSSAMEDSTHOSTSERVICERATE;

	        if (add_detection_option(sc, RULE_OPTION_TYPE_TWOSECONDSSAMEDSTHOSTSERVICERATE, (void *)ds_ptr, &ds_ptr_dup) == DETECTION_OPTION_EQUAL)
	        {
	            free(ds_ptr);
	            ds_ptr = otn->ds_list[PLUGIN_TWOSECONDSSAMEDSTHOSTSERVICERATE_CHECK] = ds_ptr_dup;
	        }
	        fpl->context = ds_ptr;

	        return;
	    }
	    else if(*data == '>')
	    {
	        data++;
	        if(*data=='='){
	        	ds_ptr->operator = TWOSECONDSSAMEDSTHOSTSERVICERATE_GTANDEQ;
	        	data++;
	        }else{
	        	ds_ptr->operator = TWOSECONDSSAMEDSTHOSTSERVICERATE_GT;
	        }
	        fpl = AddOptFuncToList(TwoSecondsSameDstHostServiceRateCheck, otn);
	    }
	    else if(*data == '<')
	    {
	        data++;
	        if(*data=='='){
	        	ds_ptr->operator = TWOSECONDSSAMEDSTHOSTSERVICERATE_LTANDEQ;
	        	data++;
	        }else{
	        	ds_ptr->operator = TWOSECONDSSAMEDSTHOSTSERVICERATE_LT;
	        }
	        fpl = AddOptFuncToList(TwoSecondsSameDstHostServiceRateCheck, otn);

	    }
	    else
	    {
	        fpl = AddOptFuncToList(TwoSecondsSameDstHostServiceRateCheck, otn);
	        ds_ptr->operator = TWOSECONDSSAMEDSTHOSTSERVICERATE_EQ;
	    }

	    fpl->type = RULE_OPTION_TYPE_TWOSECONDSSAMEDSTHOSTSERVICERATE;

	    while(isspace((int)*data)) data++;

	    iDsize = strtof(data, &pcEnd);
	    if(iDsize < 0 || *pcEnd)
	    {
	        FatalError("%s(%d): Invalid 'twoSecondsSameDstHostServiceRate' argument.\n",
	                   file_name, file_line);
	    }

	    ds_ptr->dsize = iDsize;

	    if (add_detection_option(sc, RULE_OPTION_TYPE_TWOSECONDSSAMEDSTHOSTSERVICERATE, (void *)ds_ptr, &ds_ptr_dup) == DETECTION_OPTION_EQUAL)
	    {
	        free(ds_ptr);
	        ds_ptr = otn->ds_list[PLUGIN_TWOSECONDSSAMEDSTHOSTSERVICERATE_CHECK] = ds_ptr_dup;
	     }
	     fpl->context = ds_ptr;

	    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "TWOSECONDSSAMEDSTHOSTSERVICERATE length = %f\n", ds_ptr->dsize););
	    //printf("dsize=%f\n",ds_ptr->dsize);
}

float getTwoSecondsSameDstHostServiceRateByPakcet(Packet *p){
	float sameHostServiceErrorRate = 0;
	SessionKey key;
	SessionControlBlock *scb = NULL;
	scb = (SessionControlBlock *) (p->ssnptr);
	if (scb != NULL) {
		scb->flagTrackConnection=1;
		sameHostServiceErrorRate =
				scb->two_seconds_same_host == 0 ?
						0 :
						((float) ((int) (((scb->two_seconds_same_host_and_server
								* 1.0) / scb->two_seconds_same_host + 0.005)
								* 100))) / 100;
	}
	char *dstP = SnortStrdup(inet_ntoa(&scb->origin_server_ip));
	//printf("samehostserver=%ld,sameHost=%ld,dstIP=%s\n",scb->two_seconds_same_host_and_server,scb->two_seconds_same_host,dstP);
	return sameHostServiceErrorRate;
}

int TwoSecondsSameDstHostServiceRateCheck(void *option_data, Packet *p)
{
	TwoSecondsSameDstHostServiceRateCheckData *ds_ptr = (TwoSecondsSameDstHostServiceRateCheckData *)option_data;
	    int rval = DETECTION_OPTION_NO_MATCH;
	    PROFILE_VARS;

	    if (!ds_ptr)
	        return rval;

	    PREPROC_PROFILE_START(twoSecondsSameDstHostServiceRatePerfStats);

        float sameHostServiceErrorRate=getTwoSecondsSameDstHostServiceRateByPakcet(p);
	    switch (ds_ptr->operator)
	    {
	        case TWOSECONDSSAMEDSTHOSTSERVICERATE_EQ:
	            if (ds_ptr->dsize == sameHostServiceErrorRate)
	                rval = DETECTION_OPTION_MATCH;
	            break;
	        case TWOSECONDSSAMEDSTHOSTSERVICERATE_GT:
	            if (ds_ptr->dsize < sameHostServiceErrorRate)
	                rval = DETECTION_OPTION_MATCH;
	            break;
	        case TWOSECONDSSAMEDSTHOSTSERVICERATE_GTANDEQ:
	        	if (ds_ptr->dsize <= sameHostServiceErrorRate)
	        	    rval = DETECTION_OPTION_MATCH;
	        	 break;
	        case TWOSECONDSSAMEDSTHOSTSERVICERATE_LT:
	            if (ds_ptr->dsize > sameHostServiceErrorRate)
	                rval = DETECTION_OPTION_MATCH;
	            break;
	        case TWOSECONDSSAMEDSTHOSTSERVICERATE_LTANDEQ:
	        	 if (ds_ptr->dsize >= sameHostServiceErrorRate)
	        	     rval = DETECTION_OPTION_MATCH;
	        	 break;
	        case TWOSECONDSSAMEDSTHOSTSERVICERATE_RANGE:
	            if ((ds_ptr->dsize <= sameHostServiceErrorRate) &&
	                (ds_ptr->dsize2 >= sameHostServiceErrorRate))
	                rval = DETECTION_OPTION_MATCH;
	            break;
	        default:
	            break;
	    }

	    PREPROC_PROFILE_END(twoSecondsSameDstHostServiceRatePerfStats);
	    //printf("sameHostServiceErrorRate=%f,rval=%d\n",sameHostServiceErrorRate,rval);
	    return rval;
}
