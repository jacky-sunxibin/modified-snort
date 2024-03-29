

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
PreprocStats before100SameDstHostSourcePortRatePerfStats;
extern PreprocStats ruleOTNEvalPerfStats;
#endif
#include "detection_options.h"
#include "session_common.h"
#define BEFORE100SAMEDSTHOSTSOURCEPORTRATE_EQ                   1
#define BEFORE100SAMEDSTHOSTSOURCEPORTRATE_GT                   2
#define BEFORE100SAMEDSTHOSTSOURCEPORTRATE_LT                   3
#define BEFORE100SAMEDSTHOSTSOURCEPORTRATE_RANGE                4
#define BEFORE100SAMEDSTHOSTSOURCEPORTRATE_GTANDEQ              5
#define BEFORE100SAMEDSTHOSTSOURCEPORTRATE_LTANDEQ              6

typedef struct _Before100SameDstHostSourcePortRateCheckData
{
    float dsize;
    float dsize2;
    char operator;
} Before100SameDstHostSourcePortRateCheckData;



void Before100SameDstHostSourcePortRateCheckInit(struct _SnortConfig *, char *, OptTreeNode *, int);
void ParseBefore100SameDstHostSourcePortRate(struct _SnortConfig *,char *, OptTreeNode *);
int Before100SameDstHostSourcePortRateCheck(void *option_data, Packet *p);


uint32_t Before100SameDstHostSourcePortRateCheckHash(void *d)
{
    int a,b,c;

     //NO data stored for the option

    a = RULE_OPTION_TYPE_BEFORE100SAMEDSTHOSTSOURCEPORTRATE;
    b = 0;
    c = 0;

    final(a,b,c);

    return c;
}

int Before100SameDstHostSourcePortRateCheckCompare(void *l, void *r)
{
	Before100SameDstHostSourcePortRateCheckData *left = (Before100SameDstHostSourcePortRateCheckData *)l;
	Before100SameDstHostSourcePortRateCheckData *right = (Before100SameDstHostSourcePortRateCheckData *)r;

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
void SetupBefore100SameDstHostSourcePortRateCheck(void)

{
    /* map the keyword to an initialization/processing function */
    RegisterRuleOption("before100SameDstHostSourcePortRate", Before100SameDstHostSourcePortRateCheckInit, NULL, OPT_TYPE_DETECTION, NULL);
#ifdef PERF_PROFILING
    RegisterPreprocessorProfile("before100SameDstHostSourcePortRate", &before100SameDstHostSourcePortRatePerfStats, 3, &ruleOTNEvalPerfStats);
#endif
    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Plugin: Before100SameDstHostSourcePortRate Check Initialized\n"););
}

void Before100SameDstHostSourcePortRateCheckInit(struct _SnortConfig *sc, char *data, OptTreeNode *otn, int protocol)
{
    OptFpList *fpl;
    void *ds_ptr_dup;

    /* multiple declaration check */
    if(otn->ds_list[PLUGIN_BEFORE100SAMEDSTHOSTSOURCEPORTRATE_CHECK])
    {
        FatalError("%s(%d): Multiple before100SameDstHostSourcePortRate options in rule\n", file_name,
                file_line);
    }

    /* allocate the data structure and attach it to the
       rule's data struct list */
    otn->ds_list[PLUGIN_BEFORE100SAMEDSTHOSTSOURCEPORTRATE_CHECK] = (Before100SameDstHostSourcePortRateCheckData *)SnortAlloc(sizeof(Before100SameDstHostSourcePortRateCheckData));

    /* this is where the keyword arguments are processed and placed into the
       rule option's data structure */
    ParseBefore100SameDstHostSourcePortRate(sc,data, otn);
}

void ParseBefore100SameDstHostSourcePortRate(struct _SnortConfig *sc,char *data, OptTreeNode *otn)
{

	Before100SameDstHostSourcePortRateCheckData *ds_ptr;  /* data struct pointer */
	    char *pcEnd;
	    char *pcTok;
	    float iDsize = 0;
	    void *ds_ptr_dup;
	    OptFpList *fpl;
	    /* set the ds pointer to make it easier to reference the option's
	       particular data struct */
	    ds_ptr = (Before100SameDstHostSourcePortRateCheckData *)otn->ds_list[PLUGIN_BEFORE100SAMEDSTHOSTSOURCEPORTRATE_CHECK];

	    while(isspace((int)*data)) data++;

	    if(isdigit((int)*data) && strchr(data, '<') && strchr(data, '>'))
	    {
	        pcTok = strtok(data, " <>");
	        if(!pcTok)
	        {
	            /*
	            **  Fatal
	            */
	            FatalError("%s(%d): Invalid 'before100SameDstHostSourcePortRate' argument.\n",
	                       file_name, file_line);
	        }

	        iDsize = strtof(pcTok, &pcEnd);
	        if(iDsize < 0 || *pcEnd)
	        {
	            FatalError("%s(%d): Invalid 'before100SameDstHostSourcePortRate' argument.\n",
	                       file_name, file_line);
	        }

	        ds_ptr->dsize = iDsize;

	        pcTok = strtok(NULL, " <>");
	        if(!pcTok)
	        {
	            FatalError("%s(%d): Invalid 'before100SameDstHostSourcePortRate' argument.\n",
	                       file_name, file_line);
	        }

	        iDsize = strtof(pcTok, &pcEnd);
	        if(iDsize < 0 || *pcEnd)
	        {
	            FatalError("%s(%d): Invalid 'before100SameDstHostSourcePortRate' argument.\n",
	                       file_name, file_line);
	        }

	        ds_ptr->dsize2 = iDsize;

	        ds_ptr->operator = BEFORE100SAMEDSTHOSTSOURCEPORTRATE_RANGE;

	#ifdef DEBUG_MSGS
	        DebugMessage(DEBUG_PLUGIN, "min before100SameDstHostSourcePortRate: %f\n", ds_ptr->dsize);
	        DebugMessage(DEBUG_PLUGIN, "max before100SameDstHostSourcePortRate: %f\n", ds_ptr->dsize2);
	#endif
	        fpl = AddOptFuncToList(Before100SameDstHostSourcePortRateCheck, otn);
	        fpl->type = RULE_OPTION_TYPE_BEFORE100SAMEDSTHOSTSOURCEPORTRATE;

	        if (add_detection_option(sc, RULE_OPTION_TYPE_BEFORE100SAMEDSTHOSTSOURCEPORTRATE, (void *)ds_ptr, &ds_ptr_dup) == DETECTION_OPTION_EQUAL)
	        {
	            free(ds_ptr);
	            ds_ptr = otn->ds_list[PLUGIN_BEFORE100SAMEDSTHOSTSOURCEPORTRATE_CHECK] = ds_ptr_dup;
	        }
	        fpl->context = ds_ptr;

	        return;
	    }
	    else if(*data == '>')
	    {
	        data++;
	        if(*data=='='){
	        	ds_ptr->operator = BEFORE100SAMEDSTHOSTSOURCEPORTRATE_GTANDEQ;
	        	data++;
	        }else{
	        	ds_ptr->operator = BEFORE100SAMEDSTHOSTSOURCEPORTRATE_GT;
	        }
	        fpl = AddOptFuncToList(Before100SameDstHostSourcePortRateCheck, otn);

	    }
	    else if(*data == '<')
	    {
	        data++;
	        if(*data=='='){
	        	ds_ptr->operator = BEFORE100SAMEDSTHOSTSOURCEPORTRATE_LTANDEQ;
	        	data++;
	        }else{
	        	ds_ptr->operator = BEFORE100SAMEDSTHOSTSOURCEPORTRATE_LT;
	        }
	        fpl = AddOptFuncToList(Before100SameDstHostSourcePortRateCheck, otn);

	    }
	    else
	    {
	        fpl = AddOptFuncToList(Before100SameDstHostSourcePortRateCheck, otn);
	        ds_ptr->operator = BEFORE100SAMEDSTHOSTSOURCEPORTRATE_EQ;
	    }

	    fpl->type = RULE_OPTION_TYPE_BEFORE100SAMEDSTHOSTSOURCEPORTRATE;

	    while(isspace((int)*data)) data++;

	    iDsize = strtof(data, &pcEnd);
	    if(iDsize < 0 || *pcEnd)
	    {
	        FatalError("%s(%d): Invalid 'before100SameDstHostSourcePortRate' argument.\n",
	                   file_name, file_line);
	    }

	    ds_ptr->dsize = iDsize;

	    if (add_detection_option(sc, RULE_OPTION_TYPE_BEFORE100SAMEDSTHOSTSOURCEPORTRATE, (void *)ds_ptr, &ds_ptr_dup) == DETECTION_OPTION_EQUAL)
	    {
	        free(ds_ptr);
	        ds_ptr = otn->ds_list[PLUGIN_BEFORE100SAMEDSTHOSTSOURCEPORTRATE_CHECK] = ds_ptr_dup;
	     }
	     fpl->context = ds_ptr;

	    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "BEFORE100SAMEDSTHOSTSOURCEPORTRATE length = %f\n", ds_ptr->dsize););
	    //printf("dsize=%f\n",ds_ptr->dsize);
}

float getBefore100SameDstHostSourcePortRateByPakcet(Packet *p){
	float before100SameHostSourcePortRate = 0;
	SessionKey key;
	SessionControlBlock *scb = NULL;
	scb = (SessionControlBlock *) (p->ssnptr);
	if (scb != NULL) {
		scb->flagTrackConnection=1;
		before100SameHostSourcePortRate =
				scb->before_100_same_host == 0 ?
						0 :
						((float) ((int) (((scb->before_100_same_host_same_source_port
								* 1.0) / scb->before_100_same_host + 0.005)
								* 100))) / 100;
	}
	char *srcP = SnortStrdup(inet_ntoa(&scb->origin_client_ip));
    char *dstP = SnortStrdup(inet_ntoa(&scb->origin_server_ip));
    //printf("source port=%d,dest port=%d,sip=%s,dip=%s\n",scb->origin_client_port,scb->origin_server_port,srcP,dstP);
	return before100SameHostSourcePortRate;
}

int Before100SameDstHostSourcePortRateCheck(void *option_data, Packet *p)
{
	Before100SameDstHostSourcePortRateCheckData *ds_ptr = (Before100SameDstHostSourcePortRateCheckData *)option_data;
	    int rval = DETECTION_OPTION_NO_MATCH;
	    PROFILE_VARS;

	    if (!ds_ptr)
	        return rval;

	    PREPROC_PROFILE_START(before100SameDstHostSourcePortRatePerfStats);

        float before100SameHostSourcePortRate=getBefore100SameDstHostSourcePortRateByPakcet(p);
	    switch (ds_ptr->operator)
	    {
	        case BEFORE100SAMEDSTHOSTSOURCEPORTRATE_EQ:
	            if (ds_ptr->dsize == before100SameHostSourcePortRate)
	                rval = DETECTION_OPTION_MATCH;
	            break;
	        case BEFORE100SAMEDSTHOSTSOURCEPORTRATE_GT:
	            if (ds_ptr->dsize < before100SameHostSourcePortRate)
	                rval = DETECTION_OPTION_MATCH;
	            break;
	        case BEFORE100SAMEDSTHOSTSOURCEPORTRATE_GTANDEQ:
	        	if (ds_ptr->dsize <= before100SameHostSourcePortRate)
	        	     rval = DETECTION_OPTION_MATCH;
	        	break;
	        case BEFORE100SAMEDSTHOSTSOURCEPORTRATE_LT:
	            if (ds_ptr->dsize > before100SameHostSourcePortRate)
	                rval = DETECTION_OPTION_MATCH;
	            break;
	        case BEFORE100SAMEDSTHOSTSOURCEPORTRATE_LTANDEQ:
	       	    if (ds_ptr->dsize >= before100SameHostSourcePortRate)
	       	         rval = DETECTION_OPTION_MATCH;
	       	    break;
	        case BEFORE100SAMEDSTHOSTSOURCEPORTRATE_RANGE:
	            if ((ds_ptr->dsize <= before100SameHostSourcePortRate) &&
	                (ds_ptr->dsize2 >= before100SameHostSourcePortRate))
	                rval = DETECTION_OPTION_MATCH;
	            break;
	        default:
	            break;
	    }

	    PREPROC_PROFILE_END(before100SameDstHostSourcePortRatePerfStats);
	    return rval;
}
