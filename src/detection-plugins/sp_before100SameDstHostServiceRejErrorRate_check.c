

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
PreprocStats before100SameDstHostServiceRejErrorRatePerfStats;
extern PreprocStats ruleOTNEvalPerfStats;
#endif
#include "detection_options.h"
#include "session_common.h"
#define BEFORE100SAMEDSTHOSTSERVICEREJERRORRATE_EQ                   1
#define BEFORE100SAMEDSTHOSTSERVICEREJERRORRATE_GT                   2
#define BEFORE100SAMEDSTHOSTSERVICEREJERRORRATE_LT                   3
#define BEFORE100SAMEDSTHOSTSERVICEREJERRORRATE_RANGE                4
#define BEFORE100SAMEDSTHOSTSERVICEREJERRORRATE_GTANDEQ              5
#define BEFORE100SAMEDSTHOSTSERVICEREJERRORRATE_LTANDEQ              6

typedef struct _Before100SameDstHostServiceRejErrorRateCheckData
{
    float dsize;
    float dsize2;
    char operator;
} Before100SameDstHostServiceRejErrorRateCheckData;



void Before100SameDstHostServiceRejErrorRateCheckInit(struct _SnortConfig *, char *, OptTreeNode *, int);
void ParseBefore100SameDstHostServiceRejErrorRate(struct _SnortConfig *,char *, OptTreeNode *);
int Before100SameDstHostServiceRejErrorRateCheck(void *option_data, Packet *p);


uint32_t Before100SameDstHostServiceRejErrorRateCheckHash(void *d)
{
    int a,b,c;

     //NO data stored for the option

    a = RULE_OPTION_TYPE_BEFORE100SAMEDSTHOSTSERVICEREJERRORRATE;
    b = 0;
    c = 0;

    final(a,b,c);

    return c;
}

int Before100SameDstHostServiceRejErrorRateCheckCompare(void *l, void *r)
{
	Before100SameDstHostServiceRejErrorRateCheckData *left = (Before100SameDstHostServiceRejErrorRateCheckData *)l;
	Before100SameDstHostServiceRejErrorRateCheckData *right = (Before100SameDstHostServiceRejErrorRateCheckData *)r;

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
void SetupBefore100SameDstHostServiceRejErrorRateCheck(void)

{
    /* map the keyword to an initialization/processing function */
    RegisterRuleOption("before100SameDstHostServiceRejErrorRate", Before100SameDstHostServiceRejErrorRateCheckInit, NULL, OPT_TYPE_DETECTION, NULL);
#ifdef PERF_PROFILING
    RegisterPreprocessorProfile("before100SameDstHostServiceRejErrorRate", &before100SameDstHostServiceRejErrorRatePerfStats, 3, &ruleOTNEvalPerfStats);
#endif
    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Plugin: Before100SameDstHostServiceRejErrorRate Check Initialized\n"););
}

void Before100SameDstHostServiceRejErrorRateCheckInit(struct _SnortConfig *sc, char *data, OptTreeNode *otn, int protocol)
{
    OptFpList *fpl;
    void *ds_ptr_dup;

    /* multiple declaration check */
    if(otn->ds_list[PLUGIN_BEFORE100SAMEDSTHOSTSERVICEREJERRORRATE_CHECK])
    {
        FatalError("%s(%d): Multiple Before100SameDstHostServiceRejErrorRate options in rule\n", file_name,
                file_line);
    }

    /* allocate the data structure and attach it to the
       rule's data struct list */
    otn->ds_list[PLUGIN_BEFORE100SAMEDSTHOSTSERVICEREJERRORRATE_CHECK] = (Before100SameDstHostServiceRejErrorRateCheckData *)SnortAlloc(sizeof(Before100SameDstHostServiceRejErrorRateCheckData));

    /* this is where the keyword arguments are processed and placed into the
       rule option's data structure */
    ParseBefore100SameDstHostServiceRejErrorRate(sc,data, otn);
}

void ParseBefore100SameDstHostServiceRejErrorRate(struct _SnortConfig *sc,char *data, OptTreeNode *otn)
{

	Before100SameDstHostServiceRejErrorRateCheckData *ds_ptr;  /* data struct pointer */
	    char *pcEnd;
	    char *pcTok;
	    float iDsize = 0;
	    void *ds_ptr_dup;
	    OptFpList *fpl;
	    /* set the ds pointer to make it easier to reference the option's
	       particular data struct */
	    ds_ptr = (Before100SameDstHostServiceRejErrorRateCheckData *)otn->ds_list[PLUGIN_BEFORE100SAMEDSTHOSTSERVICEREJERRORRATE_CHECK];

	    while(isspace((int)*data)) data++;

	    if(isdigit((int)*data) && strchr(data, '<') && strchr(data, '>'))
	    {
	        pcTok = strtok(data, " <>");
	        if(!pcTok)
	        {
	            /*
	            **  Fatal
	            */
	            FatalError("%s(%d): Invalid 'Before100SameDstHostServiceRejErrorRate' argument.\n",
	                       file_name, file_line);
	        }

	        iDsize = strtof(pcTok, &pcEnd);
	        if(iDsize < 0 || *pcEnd)
	        {
	            FatalError("%s(%d): Invalid 'Before100SameDstHostServiceRejErrorRate' argument.\n",
	                       file_name, file_line);
	        }

	        ds_ptr->dsize = iDsize;

	        pcTok = strtok(NULL, " <>");
	        if(!pcTok)
	        {
	            FatalError("%s(%d): Invalid 'Before100SameDstHostServiceRejErrorRate' argument.\n",
	                       file_name, file_line);
	        }

	        iDsize = strtof(pcTok, &pcEnd);
	        if(iDsize < 0 || *pcEnd)
	        {
	            FatalError("%s(%d): Invalid 'Before100SameDstHostServiceRejErrorRate' argument.\n",
	                       file_name, file_line);
	        }

	        ds_ptr->dsize2 = iDsize;

	        ds_ptr->operator = BEFORE100SAMEDSTHOSTSERVICEREJERRORRATE_RANGE;

	#ifdef DEBUG_MSGS
	        DebugMessage(DEBUG_PLUGIN, "min Before100SameDstHostServiceRejErrorRate: %f\n", ds_ptr->dsize);
	        DebugMessage(DEBUG_PLUGIN, "max Before100SameDstHostServiceRejErrorRate: %f\n", ds_ptr->dsize2);
	#endif
	        fpl = AddOptFuncToList(Before100SameDstHostServiceRejErrorRateCheck, otn);
	        fpl->type = RULE_OPTION_TYPE_BEFORE100SAMEDSTHOSTSERVICEREJERRORRATE;

	        if (add_detection_option(sc, RULE_OPTION_TYPE_BEFORE100SAMEDSTHOSTSERVICEREJERRORRATE, (void *)ds_ptr, &ds_ptr_dup) == DETECTION_OPTION_EQUAL)
	        {
	            free(ds_ptr);
	            ds_ptr = otn->ds_list[PLUGIN_BEFORE100SAMEDSTHOSTSERVICEREJERRORRATE_CHECK] = ds_ptr_dup;
	        }
	        fpl->context = ds_ptr;

	        return;
	    }
	    else if(*data == '>')
	    {
	        data++;
	        if(*data=='='){
	        	ds_ptr->operator = BEFORE100SAMEDSTHOSTSERVICEREJERRORRATE_GTANDEQ;
	        	data++;
	        }else{
	        	ds_ptr->operator = BEFORE100SAMEDSTHOSTSERVICEREJERRORRATE_GT;
	        }
	        fpl = AddOptFuncToList(Before100SameDstHostServiceRejErrorRateCheck, otn);

	    }
	    else if(*data == '<')
	    {
	        data++;
	        if(*data=='='){
	        	 ds_ptr->operator = BEFORE100SAMEDSTHOSTSERVICEREJERRORRATE_LTANDEQ;
	        	data++;
	        }else{
	        	 ds_ptr->operator = BEFORE100SAMEDSTHOSTSERVICEREJERRORRATE_LT;
	        }
	        fpl = AddOptFuncToList(Before100SameDstHostServiceRejErrorRateCheck, otn);

	    }
	    else
	    {
	        fpl = AddOptFuncToList(Before100SameDstHostServiceRejErrorRateCheck, otn);
	        ds_ptr->operator = BEFORE100SAMEDSTHOSTSERVICEREJERRORRATE_EQ;
	    }

	    fpl->type = RULE_OPTION_TYPE_BEFORE100SAMEDSTHOSTSERVICEREJERRORRATE;

	    while(isspace((int)*data)) data++;

	    iDsize = strtof(data, &pcEnd);
	    if(iDsize < 0 || *pcEnd)
	    {
	        FatalError("%s(%d): Invalid 'Before100SameDstHostServiceRejErrorRate' argument.\n",
	                   file_name, file_line);
	    }

	    ds_ptr->dsize = iDsize;

	    if (add_detection_option(sc, RULE_OPTION_TYPE_BEFORE100SAMEDSTHOSTSERVICEREJERRORRATE, (void *)ds_ptr, &ds_ptr_dup) == DETECTION_OPTION_EQUAL)
	    {
	        free(ds_ptr);
	        ds_ptr = otn->ds_list[PLUGIN_BEFORE100SAMEDSTHOSTSERVICEREJERRORRATE_CHECK] = ds_ptr_dup;
	     }
	     fpl->context = ds_ptr;

	    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "BEFORE100SAMEDSTHOSTSERVICEREJERRORRATE length = %f\n", ds_ptr->dsize););
	    //printf("dsize=%f\n",ds_ptr->dsize);
}

float getBefore100SameDstHostServiceRejErrorRateByPakcet(Packet *p){
	float before100SameHostServiceRejErrorRate = 0;
	SessionKey key;
	SessionControlBlock *scb = NULL;
	scb = (SessionControlBlock *) (p->ssnptr);
	if (scb != NULL) {
		CountBefore100TCPSessionErrorStatistics(scb);
		scb->flagTrackConnection=1;
		before100SameHostServiceRejErrorRate =
				scb->before_100_same_host_and_server == 0 ?
						0 :
						((float) ((int) (((scb->before_100_same_host_and_server_rej_error
								* 1.0) / scb->before_100_same_host_and_server + 0.005)
								* 100))) / 100;
	}
	return before100SameHostServiceRejErrorRate;
}

int Before100SameDstHostServiceRejErrorRateCheck(void *option_data, Packet *p)
{
	Before100SameDstHostServiceRejErrorRateCheckData *ds_ptr = (Before100SameDstHostServiceRejErrorRateCheckData *)option_data;
	    int rval = DETECTION_OPTION_NO_MATCH;
	    PROFILE_VARS;

	    if (!ds_ptr)
	        return rval;

	    PREPROC_PROFILE_START(before100SameDstHostServiceRejErrorRatePerfStats);

        float before100SameHostServiceRejErrorRate=getBefore100SameDstHostServiceRejErrorRateByPakcet(p);
	    switch (ds_ptr->operator)
	    {
	        case BEFORE100SAMEDSTHOSTSERVICEREJERRORRATE_EQ:
	            if (ds_ptr->dsize == before100SameHostServiceRejErrorRate)
	                rval = DETECTION_OPTION_MATCH;
	            break;
	        case BEFORE100SAMEDSTHOSTSERVICEREJERRORRATE_GT:
	            if (ds_ptr->dsize < before100SameHostServiceRejErrorRate)
	                rval = DETECTION_OPTION_MATCH;
	            break;
	        case BEFORE100SAMEDSTHOSTSERVICEREJERRORRATE_GTANDEQ:
	        	if (ds_ptr->dsize <= before100SameHostServiceRejErrorRate)
	        	     rval = DETECTION_OPTION_MATCH;
	        	break;
	        case BEFORE100SAMEDSTHOSTSERVICEREJERRORRATE_LT:
	            if (ds_ptr->dsize > before100SameHostServiceRejErrorRate)
	                rval = DETECTION_OPTION_MATCH;
	            break;
	        case BEFORE100SAMEDSTHOSTSERVICEREJERRORRATE_LTANDEQ:
	        	if (ds_ptr->dsize >= before100SameHostServiceRejErrorRate)
	        	     rval = DETECTION_OPTION_MATCH;
	        	break;
	        case BEFORE100SAMEDSTHOSTSERVICEREJERRORRATE_RANGE:
	            if ((ds_ptr->dsize <= before100SameHostServiceRejErrorRate) &&
	                (ds_ptr->dsize2 >= before100SameHostServiceRejErrorRate))
	                rval = DETECTION_OPTION_MATCH;
	            break;
	        default:
	            break;
	    }

	    PREPROC_PROFILE_END(before100SameDstHostServiceRejErrorRatePerfStats);
	    return rval;
}
