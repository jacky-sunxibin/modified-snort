/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
** Copyright (C) 2002-2013 Sourcefire, Inc.
** Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
** Copyright (C) 2001 Phil Wood <cpw@lanl.gov>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

/* $Id$ */

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
PreprocStats dstBytesPerfStats;
extern PreprocStats ruleOTNEvalPerfStats;
#endif



#include "detection_options.h"
#include "session_common.h"
/*
#include "session_api.h"
#include "snort_session.h"
*/




#define DSTBYTES_EQ                   1
#define DSTBYTES_GT                   2
#define DSTBYTES_LT                   3
#define DSTBYTES_RANGE                4
#define DSTBYTES_GTANDEQ              5
#define DSTBYTES_LTANDEQ              6

typedef struct _DstBytesCheckData
{
    long dsize;
    long dsize2;
    char operator;
} DstBytesCheckData;



void DstBytesCheckInit(struct _SnortConfig *, char *, OptTreeNode *, int);
void ParseDstBytes(struct _SnortConfig *,char *, OptTreeNode *);
int DstBytesCheck(void *option_data, Packet *p);



uint32_t DstBytesCheckHash(void *d)
{
    uint32_t a,b,c;

     //NO data stored for the option

    a = RULE_OPTION_TYPE_DSTBYTES;
    b = 0;
    c = 0;

    final(a,b,c);

    return c;
}

int DstBytesCheckCompare(void *l, void *r)
{
	DstBytesCheckData *left = (DstBytesCheckData *)l;
	DstBytesCheckData *right = (DstBytesCheckData *)r;

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


/****************************************************************************
 *
 * Function: SetupIpSameCheck()
 *
 * Purpose: Associate the same keyword with IpSameCheckInit
 *
 * Arguments: None.
 *
 * Returns: void function
 *
 ****************************************************************************/
void SetupDstBytesCheck(void)
{
    /* map the keyword to an initialization/processing function */
    RegisterRuleOption("dstBytes", DstBytesCheckInit, NULL, OPT_TYPE_DETECTION, NULL);
#ifdef PERF_PROFILING
    RegisterPreprocessorProfile("dstBytes", &dstBytesPerfStats, 3, &ruleOTNEvalPerfStats);
#endif
    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Plugin: DstBytesCheck Initialized\n"););
}


/****************************************************************************
 *
 * Function: IpSameCheckInit(struct _SnortConfig *, char *, OptTreeNode *)
 *
 * Purpose: Setup the same data struct and link the function into option
 *          function pointer list
 *
 * Arguments: data => rule arguments/data
 *            otn => pointer to the current rule option list node
 *
 * Returns: void function
 *
 ****************************************************************************/
void DstBytesCheckInit(struct _SnortConfig *sc, char *data, OptTreeNode *otn, int protocol)
{
    OptFpList *fpl;
    void *ds_ptr_dup;

    /* multiple declaration check */
    if(otn->ds_list[PLUGIN_DSTBYTES_CHECK])
    {
        FatalError("%s(%d): Multiple dstBytes options in rule\n", file_name,
                file_line);
    }

    /* allocate the data structure and attach it to the
       rule's data struct list */
    otn->ds_list[PLUGIN_DSTBYTES_CHECK] = (DstBytesCheckData *)SnortAlloc(sizeof(DstBytesCheckData));

    /* this is where the keyword arguments are processed and placed into the
       rule option's data structure */
    ParseDstBytes(sc,data, otn);
}



/****************************************************************************
 *
 * Function: ParseIpSame(char *, OptTreeNode *)
 *
 * Purpose: Convert the id option argument to data and plug it into the
 *          data structure
 *
 * Arguments: data => argument data
 *            otn => pointer to the current rule's OTN
 *
 * Returns: void function
 *
 ****************************************************************************/
void ParseDstBytes(struct _SnortConfig *sc,char *data, OptTreeNode *otn)
{

	DstBytesCheckData *ds_ptr;  /* data struct pointer */
	    char *pcEnd;
	    char *pcTok;
	    long  iDsize = 0;
	    void *ds_ptr_dup;
	    OptFpList *fpl;

	    /* set the ds pointer to make it easier to reference the option's
	       particular data struct */
	    ds_ptr = (DstBytesCheckData *)otn->ds_list[PLUGIN_DSTBYTES_CHECK];

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
	            FatalError("%s(%d): Invalid 'dstBytes' argument.\n",
	                       file_name, file_line);
	        }

	        iDsize = strtol(pcTok, &pcEnd, 10);
	        if(iDsize < 0 || *pcEnd)
	        {
	            FatalError("%s(%d): Invalid 'dstBytes' argument.\n",
	                       file_name, file_line);
	        }

	        ds_ptr->dsize = iDsize;

	        pcTok = strtok(NULL, " <>");
	        if(!pcTok)
	        {
	            FatalError("%s(%d): Invalid 'dstBytes' argument.\n",
	                       file_name, file_line);
	        }

	        iDsize = strtol(pcTok, &pcEnd, 10);
	        if(iDsize < 0 || *pcEnd)
	        {
	            FatalError("%s(%d): Invalid 'dstBytes' argument.\n",
	                       file_name, file_line);
	        }

	        ds_ptr->dsize2 =iDsize;

	        ds_ptr->operator = DSTBYTES_RANGE;

	#ifdef DEBUG_MSGS
	        DebugMessage(DEBUG_PLUGIN, "min dstBytes: %d\n", ds_ptr->dsize);
	        DebugMessage(DEBUG_PLUGIN, "max dstBytes: %d\n", ds_ptr->dsize2);
	#endif
	        fpl = AddOptFuncToList(DstBytesCheck, otn);
	        fpl->type = RULE_OPTION_TYPE_DSTBYTES;
	        if (add_detection_option(sc, RULE_OPTION_TYPE_DSTBYTES, (void *)ds_ptr, &ds_ptr_dup) == DETECTION_OPTION_EQUAL)
	        {
	            free(ds_ptr);
	            ds_ptr = otn->ds_list[PLUGIN_DSTBYTES_CHECK] = ds_ptr_dup;
	        }
	        fpl->context = ds_ptr;

	        return;
	    }
	    else if(*data == '>')
	    {
	        data++;
	        if(*data=='='){
	        	ds_ptr->operator = DSTBYTES_GTANDEQ;
	        	data++;
	        }else{
	        	ds_ptr->operator = DSTBYTES_GT;
	        }
	        fpl = AddOptFuncToList(DstBytesCheck, otn);

	    }
	    else if(*data == '<')
	    {
	        data++;
	        if(*data=='='){
	        	ds_ptr->operator = DSTBYTES_LTANDEQ;
	        	data++;
	        }else{
	        	ds_ptr->operator = DSTBYTES_LT;
	        }
	        fpl = AddOptFuncToList(DstBytesCheck, otn);

	    }
	    else
	    {
	        fpl = AddOptFuncToList(DstBytesCheck, otn);
	        ds_ptr->operator = DSTBYTES_EQ;
	    }

	    fpl->type = RULE_OPTION_TYPE_DSTBYTES;

	    while(isspace((int)*data)) data++;

	    iDsize = strtol(data, &pcEnd, 10);
	    if(iDsize < 0 || *pcEnd)
	    {
	        FatalError("%s(%d): Invalid 'dstBytes' argument.\n",
	                   file_name, file_line);
	    }

	    ds_ptr->dsize =iDsize;

	    if (add_detection_option(sc, RULE_OPTION_TYPE_DSTBYTES, (void *)ds_ptr, &ds_ptr_dup) == DETECTION_OPTION_EQUAL)
	    {
	        free(ds_ptr);
	        ds_ptr = otn->ds_list[PLUGIN_DSTBYTES_CHECK] = ds_ptr_dup;
	     }
	     fpl->context = ds_ptr;

	    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "dst_bytes = %ld\n", ds_ptr->dsize););
}

long getDstBytesByPakcet(Packet *p){
	long total=0;
	SessionControlBlock *scb = NULL;
    scb=(SessionControlBlock *)(p->ssnptr);
	if (scb != NULL) {
		 total=scb->dst_bytes;
		}
	   return total;
	}


/****************************************************************************
 *
 * Function: IpSameCheck(char *, OptTreeNode *)
 *
 * Purpose: Test the ip header's id field to see if its value is equal to the
 *          value in the rule.  This is useful to detect things like "elite"
 *          numbers, oddly repeating numbers, etc.
 *
 * Arguments: data => argument data
 *            otn => pointer to the current rule's OTN
 *
 * Returns: void function
 *
 ****************************************************************************/
int DstBytesCheck(void *option_data, Packet *p)
{
	DstBytesCheckData *ds_ptr = (DstBytesCheckData *)option_data;
	    int rval = DETECTION_OPTION_NO_MATCH;
	    PROFILE_VARS;

	    if (!ds_ptr)
	        return rval;

	    PREPROC_PROFILE_START(dstBytesPerfStats);

	    /* fake packet dsizes are always wrong */
	    /* (unless they are PDUs) */
	    if (
	        (p->packet_flags & PKT_REBUILT_STREAM) &&
	        !(p->packet_flags & PKT_PDU_HEAD) )
	    {
	        PREPROC_PROFILE_END(dstBytesPerfStats);
	        return rval;
	    }
        long total=getDstBytesByPakcet(p);
       // printf("spantime=%ld\n",spanTime);
	    switch (ds_ptr->operator)
	    {
	        case DSTBYTES_EQ:
	            if (ds_ptr->dsize == total)
	                rval = DETECTION_OPTION_MATCH;
	            break;
	        case DSTBYTES_GT:
	            if (ds_ptr->dsize < total)
	                rval = DETECTION_OPTION_MATCH;
	            break;
	        case DSTBYTES_GTANDEQ:
	        	if (ds_ptr->dsize <= total)
	        	     rval = DETECTION_OPTION_MATCH;
	        	break;
	        case DSTBYTES_LT:
	            if (ds_ptr->dsize > total)
	                rval = DETECTION_OPTION_MATCH;
	            break;
	        case DSTBYTES_LTANDEQ:
	       	    if (ds_ptr->dsize >= total)
	       	         rval = DETECTION_OPTION_MATCH;
	       	    break;
	        case DSTBYTES_RANGE:
	            if ((ds_ptr->dsize <= total) &&
	                (ds_ptr->dsize2 >= total))
	                rval = DETECTION_OPTION_MATCH;
	            break;
	        default:
	            break;
	    }

	    PREPROC_PROFILE_END(dstBytesPerfStats);
	    //printf("dst_bytes=%ld,rval=%d sp=%d,dp=%d\n",total,rval,p->sp,p->dp);
	    return rval;
}
