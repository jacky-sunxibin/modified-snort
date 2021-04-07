

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
PreprocStats before100SameDstHostServiceDiffSIPRatePerfStats;
extern PreprocStats ruleOTNEvalPerfStats;
#endif
#include "detection_options.h"
#include "session_common.h"
#define BEFORE100SAMEDSTHOSTSERVICEDIFFSIPRATE_EQ                   1
#define BEFORE100SAMEDSTHOSTSERVICEDIFFSIPRATE_GT                   2
#define BEFORE100SAMEDSTHOSTSERVICEDIFFSIPRATE_LT                   3
#define BEFORE100SAMEDSTHOSTSERVICEDIFFSIPRATE_RANGE                4
#define BEFORE100SAMEDSTHOSTSERVICEDIFFSIPRATE_GTANDEQ              5
#define BEFORE100SAMEDSTHOSTSERVICEDIFFSIPRATE_LTANDEQ              6

typedef struct _Before100SameDstHostServiceDiffSIPRateCheckData
{
    float dsize;
    float dsize2;
    char operator;
} Before100SameDstHostServiceDiffSIPRateCheckData;



void Before100SameDstHostServiceDiffSIPRateCheckInit(struct _SnortConfig *, char *, OptTreeNode *, int);
void ParseBefore100SameDstHostServiceDiffSIPRate(struct _SnortConfig *,char *, OptTreeNode *);
int Before100SameDstHostServiceDiffSIPRateCheck(void *option_data, Packet *p);


uint32_t Before100SameDstHostServiceDiffSIPRateCheckHash(void *d)
{
    int a,b,c;

     //NO data stored for the option

    a = RULE_OPTION_TYPE_BEFORE100SAMEDSTHOSTSERVICEDIFFSIPRATE;
    b = 0;
    c = 0;

    final(a,b,c);

    return c;
}

int Before100SameDstHostServiceDiffSIPRateCheckCompare(void *l, void *r)
{
	Before100SameDstHostServiceDiffSIPRateCheckData *left = (Before100SameDstHostServiceDiffSIPRateCheckData *)l;
	Before100SameDstHostServiceDiffSIPRateCheckData *right = (Before100SameDstHostServiceDiffSIPRateCheckData *)r;

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
void SetupBefore100SameDstHostServiceDiffSIPRateCheck(void)

{
    /* map the keyword to an initialization/processing function */
    RegisterRuleOption("before100SameDstHostServiceDiffSIPRate", Before100SameDstHostServiceDiffSIPRateCheckInit, NULL, OPT_TYPE_DETECTION, NULL);
#ifdef PERF_PROFILING
    RegisterPreprocessorProfile("before100SameDstHostServiceDiffSIPRate", &before100SameDstHostServiceDiffSIPRatePerfStats, 3, &ruleOTNEvalPerfStats);
#endif
    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Plugin: Before100SameDstHostServiceDiffSIPRate Check Initialized\n"););
}

void Before100SameDstHostServiceDiffSIPRateCheckInit(struct _SnortConfig *sc, char *data, OptTreeNode *otn, int protocol)
{
    OptFpList *fpl;
    void *ds_ptr_dup;

    /* multiple declaration check */
    if(otn->ds_list[PLUGIN_BEFORE100SAMEDSTHOSTSERVICEDIFFSIPRATE_CHECK])
    {
        FatalError("%s(%d): Multiple before100SameDstHostServiceDiffSIPRate options in rule\n", file_name,
                file_line);
    }

    /* allocate the data structure and attach it to the
       rule's data struct list */
    otn->ds_list[PLUGIN_BEFORE100SAMEDSTHOSTSERVICEDIFFSIPRATE_CHECK] = (Before100SameDstHostServiceDiffSIPRateCheckData *)SnortAlloc(sizeof(Before100SameDstHostServiceDiffSIPRateCheckData));

    /* this is where the keyword arguments are processed and placed into the
       rule option's data structure */
    ParseBefore100SameDstHostServiceDiffSIPRate(sc,data, otn);
}

void ParseBefore100SameDstHostServiceDiffSIPRate(struct _SnortConfig *sc,char *data, OptTreeNode *otn)
{

	Before100SameDstHostServiceDiffSIPRateCheckData *ds_ptr;  /* data struct pointer */
	    char *pcEnd;
	    char *pcTok;
	    float iDsize = 0;
	    void *ds_ptr_dup;
	    OptFpList *fpl;
	    /* set the ds pointer to make it easier to reference the option's
	       particular data struct */
	    ds_ptr = (Before100SameDstHostServiceDiffSIPRateCheckData *)otn->ds_list[PLUGIN_BEFORE100SAMEDSTHOSTSERVICEDIFFSIPRATE_CHECK];

	    while(isspace((int)*data)) data++;

	    if(isdigit((int)*data) && strchr(data, '<') && strchr(data, '>'))
	    {
	        pcTok = strtok(data, " <>");
	        if(!pcTok)
	        {
	            /*
	            **  Fatal
	            */
	            FatalError("%s(%d): Invalid 'before100SameDstHostServiceDiffSIPRate' argument.\n",
	                       file_name, file_line);
	        }

	        iDsize = strtof(pcTok, &pcEnd);
	        if(iDsize < 0 || *pcEnd)
	        {
	            FatalError("%s(%d): Invalid 'before100SameDstHostServiceDiffSIPRate' argument.\n",
	                       file_name, file_line);
	        }

	        ds_ptr->dsize = iDsize;

	        pcTok = strtok(NULL, " <>");
	        if(!pcTok)
	        {
	            FatalError("%s(%d): Invalid 'before100SameDstHostServiceDiffSIPRate' argument.\n",
	                       file_name, file_line);
	        }

	        iDsize = strtof(pcTok, &pcEnd);
	        if(iDsize < 0 || *pcEnd)
	        {
	            FatalError("%s(%d): Invalid 'before100SameDstHostServiceDiffSIPRate' argument.\n",
	                       file_name, file_line);
	        }

	        ds_ptr->dsize2 = iDsize;

	        ds_ptr->operator = BEFORE100SAMEDSTHOSTSERVICEDIFFSIPRATE_RANGE;

	#ifdef DEBUG_MSGS
	        DebugMessage(DEBUG_PLUGIN, "min before100SameDstHostServiceDiffSIPRate: %f\n", ds_ptr->dsize);
	        DebugMessage(DEBUG_PLUGIN, "max before100SameDstHostServiceDiffSIPRate: %f\n", ds_ptr->dsize2);
	#endif
	        fpl = AddOptFuncToList(Before100SameDstHostServiceDiffSIPRateCheck, otn);
	        fpl->type = RULE_OPTION_TYPE_BEFORE100SAMEDSTHOSTSERVICEDIFFSIPRATE;

	        if (add_detection_option(sc, RULE_OPTION_TYPE_BEFORE100SAMEDSTHOSTSERVICEDIFFSIPRATE, (void *)ds_ptr, &ds_ptr_dup) == DETECTION_OPTION_EQUAL)
	        {
	            free(ds_ptr);
	            ds_ptr = otn->ds_list[PLUGIN_BEFORE100SAMEDSTHOSTSERVICEDIFFSIPRATE_CHECK] = ds_ptr_dup;
	        }
	        fpl->context = ds_ptr;

	        return;
	    }
	    else if(*data == '>')
	    {
	        data++;
	        if(*data=='='){
	        	ds_ptr->operator = BEFORE100SAMEDSTHOSTSERVICEDIFFSIPRATE_GTANDEQ;
	        	data++;
	        }else{
	        	ds_ptr->operator = BEFORE100SAMEDSTHOSTSERVICEDIFFSIPRATE_GT;
	        }
	        fpl = AddOptFuncToList(Before100SameDstHostServiceDiffSIPRateCheck, otn);
	    }
	    else if(*data == '<')
	    {
	        data++;
	        if(*data=='='){
	        	ds_ptr->operator = BEFORE100SAMEDSTHOSTSERVICEDIFFSIPRATE_LTANDEQ;
	        	data++;
	        }else{
	        	ds_ptr->operator = BEFORE100SAMEDSTHOSTSERVICEDIFFSIPRATE_LT;
	        }
	        fpl = AddOptFuncToList(Before100SameDstHostServiceDiffSIPRateCheck, otn);

	    }
	    else
	    {
	        fpl = AddOptFuncToList(Before100SameDstHostServiceDiffSIPRateCheck, otn);
	        ds_ptr->operator = BEFORE100SAMEDSTHOSTSERVICEDIFFSIPRATE_EQ;
	    }

	    fpl->type = RULE_OPTION_TYPE_BEFORE100SAMEDSTHOSTSERVICEDIFFSIPRATE;

	    while(isspace((int)*data)) data++;

	    iDsize = strtof(data, &pcEnd);
	    if(iDsize < 0 || *pcEnd)
	    {
	        FatalError("%s(%d): Invalid 'before100SameDstHostServiceDiffSIPRate' argument.\n",
	                   file_name, file_line);
	    }

	    ds_ptr->dsize = iDsize;

	    if (add_detection_option(sc, RULE_OPTION_TYPE_BEFORE100SAMEDSTHOSTSERVICEDIFFSIPRATE, (void *)ds_ptr, &ds_ptr_dup) == DETECTION_OPTION_EQUAL)
	    {
	        free(ds_ptr);
	        ds_ptr = otn->ds_list[PLUGIN_BEFORE100SAMEDSTHOSTSERVICEDIFFSIPRATE_CHECK] = ds_ptr_dup;
	     }
	     fpl->context = ds_ptr;

	    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "BEFORE100SAMEDSTHOSTSERVICEDIFFSIPRATE length = %f\n", ds_ptr->dsize););
	    //printf("dsize=%f\n",ds_ptr->dsize);
}

float getBefore100SameDstHostServiceDiffSIPRateByPakcet(Packet *p){
	float before100SameHostServiceDiffSIPRate = 0;
	SessionKey key;
	SessionControlBlock *scb = NULL;
	scb = (SessionControlBlock *) (p->ssnptr);
	if (scb != NULL) {
		scb->flagTrackConnection=1;
		before100SameHostServiceDiffSIPRate =
				scb->before_100_same_host_and_server == 0 ?
						0 :
						((float) ((int) (((scb->before_100_same_host_and_server_differ_source_ip
								* 1.0) / scb->before_100_same_host_and_server + 0.005)
								* 100))) / 100;
	}
	return before100SameHostServiceDiffSIPRate;
}

int Before100SameDstHostServiceDiffSIPRateCheck(void *option_data, Packet *p)
{
	Before100SameDstHostServiceDiffSIPRateCheckData *ds_ptr = (Before100SameDstHostServiceDiffSIPRateCheckData *)option_data;
	    int rval = DETECTION_OPTION_NO_MATCH;
	    PROFILE_VARS;

	    if (!ds_ptr)
	        return rval;

	    PREPROC_PROFILE_START(before100SameDstHostServiceDiffSIPRatePerfStats);

        float before100SameHostServiceDiffSIPRate=getBefore100SameDstHostServiceRateByPakcet(p);
	    switch (ds_ptr->operator)
	    {
	        case BEFORE100SAMEDSTHOSTSERVICEDIFFSIPRATE_EQ:
	            if (ds_ptr->dsize == before100SameHostServiceDiffSIPRate)
	                rval = DETECTION_OPTION_MATCH;
	            break;
	        case BEFORE100SAMEDSTHOSTSERVICEDIFFSIPRATE_GT:
	            if (ds_ptr->dsize < before100SameHostServiceDiffSIPRate)
	                rval = DETECTION_OPTION_MATCH;
	            break;
	        case BEFORE100SAMEDSTHOSTSERVICEDIFFSIPRATE_GTANDEQ:
	        	if (ds_ptr->dsize <= before100SameHostServiceDiffSIPRate)
	        	     rval = DETECTION_OPTION_MATCH;
	        	break;
	        case BEFORE100SAMEDSTHOSTSERVICEDIFFSIPRATE_LT:
	            if (ds_ptr->dsize > before100SameHostServiceDiffSIPRate)
	                rval = DETECTION_OPTION_MATCH;
	            break;
	        case BEFORE100SAMEDSTHOSTSERVICEDIFFSIPRATE_LTANDEQ:
	        	if (ds_ptr->dsize >= before100SameHostServiceDiffSIPRate)
	        	     rval = DETECTION_OPTION_MATCH;
	        	break;
	        case BEFORE100SAMEDSTHOSTSERVICEDIFFSIPRATE_RANGE:
	            if ((ds_ptr->dsize <= before100SameHostServiceDiffSIPRate) &&
	                (ds_ptr->dsize2 >= before100SameHostServiceDiffSIPRate))
	                rval = DETECTION_OPTION_MATCH;
	            break;
	        default:
	            break;
	    }

	    PREPROC_PROFILE_END(before100SameDstHostServiceDiffSIPRatePerfStats);
	    return rval;
}
