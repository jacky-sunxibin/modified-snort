/**
 * add by jacky
 * **/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
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
PreprocStats sessionFlagsPerfStats;
extern PreprocStats ruleOTNEvalPerfStats;
#endif

#include "sfhashfcn.h"
#include "detection_options.h"
#include "sp_session_flag_check.h"
#include "stream_common.h"

typedef struct _SessionFlagCheckData
{
    uint32_t session_flags;

} SessionFlagCheckData;


void SessionFlagCheckInit(struct _SnortConfig *, char *, OptTreeNode *, int);
void ParseSessionFlags(struct _SnortConfig *, char *, OptTreeNode *);
int CheckSessionFlags(void *option_data, Packet *p);

uint32_t SessionFlagCheckHash(void *d)
{
    uint32_t a,b,c;
    SessionFlagCheckData *data = (SessionFlagCheckData *)d;
    a = data->session_flags;
    b = RULE_OPTION_TYPE_SESSION_FLAG;
    c = 0;
    final(a,b,c);
    return c;
}

int SessionFlagCheckCompare(void *l, void *r)
{
	SessionFlagCheckData *left = (SessionFlagCheckData *)l;
	SessionFlagCheckData *right = (SessionFlagCheckData *)r;

    if (!left || !right)
        return DETECTION_OPTION_NOT_EQUAL;

    if ((left->session_flags == right->session_flags))
    {
        return DETECTION_OPTION_EQUAL;
    }

    return DETECTION_OPTION_NOT_EQUAL;
}


void SetupSessionFlagCheck(void)
{
    RegisterRuleOption("sessionFlags", SessionFlagCheckInit, NULL, OPT_TYPE_DETECTION, NULL);
#ifdef PERF_PROFILING
    RegisterPreprocessorProfile("sessionFlags", &sessionFlagsPerfStats, 3, &ruleOTNEvalPerfStats);
#endif
    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Plugin: SessionFlagCheck Initialized!\n"););
}



void SessionFlagCheckInit(struct _SnortConfig *sc, char *data, OptTreeNode *otn, int protocol)
{
    OptFpList *fpl;

    if(protocol != IPPROTO_TCP)
    {
        FatalError("Line %s (%d): TCP Options on non-TCP rule\n", file_name, file_line);
    }

    /* multiple declaration check */
    if(otn->ds_list[PLUGIN_SESSION_FLAG_CHECK])
    {
        FatalError("%s(%d): Multiple Session flags options in rule\n", file_name,
                file_line);
    }

    otn->ds_list[PLUGIN_SESSION_FLAG_CHECK] = (SessionFlagCheckData*)
            SnortAlloc(sizeof(SessionFlagCheckData));

    /* set up the pattern buffer */
    ParseSessionFlags(sc, data, otn);

    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Adding session flag check function (%p) to list\n",
			    CheckSessionFlags););

    /* link the plugin function in to the current OTN */
    fpl = AddOptFuncToList(CheckSessionFlags, otn);
    fpl->type = RULE_OPTION_TYPE_SESSION_FLAG;
    fpl->context = otn->ds_list[PLUGIN_SESSION_FLAG_CHECK];

    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "OTN function CheckSessionFlags added to rule!\n"););
}



/****************************************************************************
 *
 * Function: ParseTCPflags(struct _SnortConfig *, char *, OptTreeNode *)
 *
 * Purpose: Figure out which TCP flags the current rule is interested in
 *
 * Arguments: rule => the rule string
 *
 * Returns: void function
 *
 ***************************************************************************/
void ParseSessionFlags(struct _SnortConfig *sc, char *rule, OptTreeNode *otn)
{
	char **toks;
	int num_toks;
    char *fptr;
    void *ds_ptr_dup;
    char *flagName;
    int index=0;
    OptFpList *fpl;
    SessionFlagCheckData *idx =(SessionFlagCheckData *)otn->ds_list[PLUGIN_SESSION_FLAG_CHECK];

    fptr = rule;

    /* make sure there is atleast a split pointer */
    if(fptr == NULL)
    {
        FatalError("[!] Line %s (%d): Flags missing in Session flag rule\n", file_name, file_line);
    }

    while(isspace((u_char) *fptr))
        fptr++;

    if(strlen(fptr) == 0)
    {
        FatalError("[!] Line %s (%d): Flags missing in Session flag rule\n", file_name, file_line);
    }
    toks = mSplit(fptr, ",", 0, &num_toks, 0);
    if(num_toks < 1)
        {
            ParseError("ParseSessionFlagArgs: Must specify sessionFlag operation.");
        }

    while(index<num_toks){
    	flagName=toks[index++];
		if (!strcasecmp("OTH", flagName)) {
			idx->session_flags |= SESSION_STATE_OTH;
		} else if (!strcasecmp("REJ", flagName)) {
			idx->session_flags |= SESSION_STATE_REJ;
		} else if (!strcasecmp("RSTO", flagName)) {
			idx->session_flags |= SESSION_STATE_RSTO;
		} else if (!strcasecmp("RSTR", flagName)) {
			idx->session_flags |= SESSION_STATE_RSTR;
		}else if (!strcasecmp("RSTOS0", flagName)) {
			idx->session_flags |= SESSION_STATE_RSTOS0;
		} else if (!strcasecmp("S0", flagName)) {
			idx->session_flags |= SESSION_STATE_S0;
		} else if (!strcasecmp("S1", flagName)) {
			idx->session_flags |= SESSION_STATE_S1;
		} else if (!strcasecmp("S2", flagName)) {
			idx->session_flags |= SESSION_STATE_S2;
		} else if (!strcasecmp("S3", flagName)) {
			idx->session_flags |= SESSION_STATE_S3;
		} else if (!strcasecmp("SF", flagName)) {
			idx->session_flags |= SESSION_STATE_SF;
		} else if (!strcasecmp("SH", flagName)) {
			idx->session_flags |= SESSION_STATE_SH;
		}
    }
    mSplitFree(&toks, num_toks);
}

int CheckSessionFlags(void *option_data, Packet *p)
{
    SessionFlagCheckData *ds_ptr = (SessionFlagCheckData *)option_data;
    int rval = DETECTION_OPTION_NO_MATCH;
    PROFILE_VARS;
    SessionControlBlock *scb = NULL;
    PREPROC_PROFILE_START(sessionFlagsPerfStats);

    if(!p->tcph)
    {
        /* if error appeared when tcp header was processed,
         * test fails automagically */
        PREPROC_PROFILE_END(sessionFlagsPerfStats);
        return rval;
    }

    /* the flags we really want to check are all the ones
     */

     scb=(SessionControlBlock *)(p->ssnptr);
     if(scb!=NULL && ((ds_ptr->session_flags & scb->sessionState)==scb->sessionState)){
         rval=DETECTION_OPTION_MATCH;
     }

     PREPROC_PROFILE_END(sessionFlagsPerfStats);
     //printf("sessionState=%d,rval=%d\n",scb->sessionState,rval);

     return rval;
}
