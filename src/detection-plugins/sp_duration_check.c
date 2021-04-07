
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
PreprocStats durationPerfStats;
extern PreprocStats ruleOTNEvalPerfStats;
#endif



#include "detection_options.h"
#include "session_common.h"
#define DURATION_EQ                   1
#define DURATION_GT                   2
#define DURATION_LT                   3
#define DURATION_RANGE                4
#define DURATION_GTANDEQ              5
#define DURATION_LTANDEQ              6

typedef struct _DurationCheckData
{
    float dsize;
    float dsize2;
    char operator;
} DurationCheckData;



void DurationCheckInit(struct _SnortConfig *, char *, OptTreeNode *, int);
void ParseDuration(struct _SnortConfig *,char *, OptTreeNode *);
int DurationCheck(void *option_data, Packet *p);

uint32_t DurationCheckHash(void *d)
{
    uint32_t a,b,c;

     //NO data stored for the option
    DurationCheckData *data = (DurationCheckData *)d;
	a = data->dsize;
	b = data->dsize2;
	c = data->operator;

	mix(a, b, c);

	a += RULE_OPTION_TYPE_DSIZE;
	return c;
}

int DurationCheckCompare(void *l, void *r)
{
	 DurationCheckData *left = (DurationCheckData *)l;
	 DurationCheckData *right = (DurationCheckData *)r;

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
void SetupDurationCheck(void)
{
    /* map the keyword to an initialization/processing function */
    RegisterRuleOption("duration", DurationCheckInit, NULL, OPT_TYPE_DETECTION, NULL);
#ifdef PERF_PROFILING
    RegisterPreprocessorProfile("duration", &durationPerfStats, 3, &ruleOTNEvalPerfStats);
#endif
    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Plugin: DurationCheck Initialized\n"););
}

void DurationCheckInit(struct _SnortConfig *sc, char *data, OptTreeNode *otn, int protocol)
{

    /* multiple declaration check */
    if(otn->ds_list[PLUGIN_DURATION_CHECK])
    {
        FatalError("%s(%d): Multiple duration options in rule\n", file_name,
                file_line);
    }

    /* allocate the data structure and attach it to the
       rule's data struct list */
    otn->ds_list[PLUGIN_DURATION_CHECK] = (DurationCheckData *)SnortAlloc(sizeof(DurationCheckData));

    /* this is where the keyword arguments are processed and placed into the
       rule option's data structure */
    ParseDuration(sc,data, otn);
}

void ParseDuration(struct _SnortConfig *sc,char *data, OptTreeNode *otn)
{

	DurationCheckData *ds_ptr;  /* data struct pointer */
	    char *pcEnd;
	    char *pcTok;
	    float  iDsize = 0;
	    void *ds_ptr_dup;
	    OptFpList *fpl;

	    /* set the ds pointer to make it easier to reference the option's
	       particular data struct */
	    ds_ptr = (DurationCheckData *)otn->ds_list[PLUGIN_DURATION_CHECK];

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
	            FatalError("%s(%d): Invalid 'duration' argument.\n",
	                       file_name, file_line);
	        }

	        iDsize = strtof(pcTok, &pcEnd);
	        if(iDsize < 0 || *pcEnd)
	        {
	            FatalError("%s(%d): Invalid 'duration' argument.\n",
	                       file_name, file_line);
	        }

	        ds_ptr->dsize = iDsize;

	        pcTok = strtok(NULL, " <>");
	        if(!pcTok)
	        {
	            FatalError("%s(%d): Invalid 'duration' argument.\n",
	                       file_name, file_line);
	        }

	        iDsize = strtof(pcTok, &pcEnd);
	        if(iDsize < 0 || *pcEnd)
	        {
	            FatalError("%s(%d): Invalid 'duration' argument.\n",
	                       file_name, file_line);
	        }

	        ds_ptr->dsize2 = iDsize;

	        ds_ptr->operator = DURATION_RANGE;

	#ifdef DEBUG_MSGS
	        DebugMessage(DEBUG_PLUGIN, "min duration: %d\n", ds_ptr->dsize);
	        DebugMessage(DEBUG_PLUGIN, "max duration: %d\n", ds_ptr->dsize2);
	#endif
	        fpl = AddOptFuncToList(DurationCheck, otn);
	        fpl->type = RULE_OPTION_TYPE_DURATION;

	        if (add_detection_option(sc, RULE_OPTION_TYPE_DURATION, (void *)ds_ptr, &ds_ptr_dup) == DETECTION_OPTION_EQUAL)
	        {
	            free(ds_ptr);
	            ds_ptr = otn->ds_list[PLUGIN_DURATION_CHECK] = ds_ptr_dup;
	        }
	        fpl->context = ds_ptr;

	        return;
	    }
	    else if(*data == '>')
	    {
	        data++;
	        if(*data=='='){
	        	 ds_ptr->operator = DURATION_GTANDEQ;
	        	data++;
	        }else{
	        	 ds_ptr->operator = DURATION_GT;
	        }
	        fpl = AddOptFuncToList(DurationCheck, otn);

	    }
	    else if(*data == '<')
	    {
	        data++;
	        if(*data=='='){
	        	 ds_ptr->operator = DURATION_LTANDEQ;
	        	data++;
	        }else{
	        	 ds_ptr->operator = DURATION_LT;
	        }
	        fpl = AddOptFuncToList(DurationCheck, otn);

	    }
	    else
	    {
	        fpl = AddOptFuncToList(DurationCheck, otn);
	        ds_ptr->operator = DURATION_EQ;
	    }

	    fpl->type = RULE_OPTION_TYPE_DURATION;

	    while(isspace((int)*data)) data++;

	    iDsize = strtof(data, &pcEnd);
	    if(iDsize < 0 || *pcEnd)
	    {
	        FatalError("%s(%d): Invalid 'duration' argument.\n",
	                   file_name, file_line);
	    }

	    ds_ptr->dsize = iDsize;

	    if (add_detection_option(sc, RULE_OPTION_TYPE_DURATION, (void *)ds_ptr, &ds_ptr_dup) == DETECTION_OPTION_EQUAL)
	    {
	        free(ds_ptr);
	        ds_ptr = otn->ds_list[PLUGIN_DURATION_CHECK] = ds_ptr_dup;
	     }
	     if(fpl){
	    	 fpl->context = ds_ptr;
	    	 fpl->type=RULE_OPTION_TYPE_DURATION;
	     }
	    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "duration length = %f\n", ds_ptr->dsize););
	    //printf("min=%f,max=%f\n",ds_ptr->dsize,ds_ptr->dsize2);
}

float getSessionDurationByPakcet(Packet *p){
	float spanTime=0;
	SessionKey key;
	SessionControlBlock *scb = NULL;
    scb=(SessionControlBlock *)(p->ssnptr);
	if (scb != NULL) {
		//printf("last=%ld,first=%ld\n",scb->last_data_seen,scb->first_data_seen);
//		 spanTime=scb->last_data_seen-((scb->first_data_seen)/1000000);
		  spanTime=((scb->last_data_seen1-scb->first_data_seen)*1.0)/1000000;
		}
	   // printf("lastDataSeen=%ld,firstDataSeen=%ld,spanTime=%f\n",scb->last_data_seen1,(scb->first_data_seen),spanTime);
	   return spanTime;
	}

int DurationCheck(void *option_data, Packet *p)
{

	DurationCheckData *ds_ptr = (DurationCheckData *)option_data;
	    int rval = DETECTION_OPTION_NO_MATCH;
	    PROFILE_VARS;

	    if (!ds_ptr)
	        return rval;

	    PREPROC_PROFILE_START(durationPerfStats);
        float spanTime=getSessionDurationByPakcet(p);
         //printf("spantime=%f\n",spanTime);
	    switch (ds_ptr->operator)
	    {
	        case DURATION_EQ:
	            if (ds_ptr->dsize == spanTime)
	                rval = DETECTION_OPTION_MATCH;
	            break;
	        case DURATION_GT:
	            if (ds_ptr->dsize < spanTime)
	                rval = DETECTION_OPTION_MATCH;
	            break;
	        case DURATION_GTANDEQ:
	        	if (ds_ptr->dsize <= spanTime)
	        	     rval = DETECTION_OPTION_MATCH;
	        	break;
	        case DURATION_LT:
	            if (ds_ptr->dsize > spanTime)
	                rval = DETECTION_OPTION_MATCH;
	            break;
	        case DURATION_LTANDEQ:
	            if (ds_ptr->dsize >= spanTime)
	        	     rval = DETECTION_OPTION_MATCH;
	        	break;
	        case DURATION_RANGE:
	            if ((ds_ptr->dsize <= spanTime) &&
	                (ds_ptr->dsize2 >= spanTime))
	                rval = DETECTION_OPTION_MATCH;
	            break;
	        default:
	            break;
	    }

	    PREPROC_PROFILE_END(durationPerfStats);
        //printf("min=%f,max=%f,duration=%f,rval=%d,sp=%d,dp=%d\n",ds_ptr->dsize,ds_ptr->dsize2,spanTime,rval,p->sp,p->dp);
	    return rval;
}
