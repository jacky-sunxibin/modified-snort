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
PreprocStats wrongFragmentPerfStats;
extern PreprocStats ruleOTNEvalPerfStats;
#endif

#include "detection_options.h"

/*typedef struct _IpSameData
{
    u_char ip_same;

} IpSameData;*/

void WrongFragmentCheckInit(struct _SnortConfig *, char *, OptTreeNode *, int);
void ParseWrongFragment(char *, OptTreeNode *);
int WrongFragmentCheck(void *option_data, Packet *p);

uint32_t WrongFragmentCheckHash(void *d)
{
    uint32_t a,b,c;

     //NO data stored for the option

    a = RULE_OPTION_TYPE_WRONG_FRAGMENT;
    b = 0;
    c = 0;

    final(a,b,c);

    return c;
}

int WrongFragmentCheckCompare(void *l, void *r)
{
     //NO data stored for the option
    return DETECTION_OPTION_WRONG_FRAGMENT;
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
void SetupWrongFragmentCheck(void)
{
    /* map the keyword to an initialization/processing function */
    RegisterRuleOption("overlapfragment", WrongFragmentCheckInit, NULL, OPT_TYPE_DETECTION, NULL);
#ifdef PERF_PROFILING
    RegisterPreprocessorProfile("overlapfragment", &wrongFragmentPerfStats, 3, &ruleOTNEvalPerfStats);
#endif
    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Plugin: WrongFragmentCheck Initialized\n"););
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
void WrongFragmentCheckInit(struct _SnortConfig *sc, char *data, OptTreeNode *otn, int protocol)
{
    OptFpList *fpl;
    void *ds_ptr_dup;

    /* multiple declaration check */
    if(otn->ds_list[PLUGIN_WRONG_FRAGMENT_CHECK])
    {
        FatalError("%s(%d): Multiple wrongfragment options in rule\n", file_name,
                file_line);
    }

    /* allocate the data structure and attach it to the
       rule's data struct list */
    otn->ds_list[PLUGIN_WRONG_FRAGMENT_CHECK] = (void *)1; /* Just store something there */
    //otn->ds_list[PLUGIN_IP_SAME_CHECK] = (IpSameData *)
    //        SnortAlloc(sizeof(IpSameData));

    /* this is where the keyword arguments are processed and placed into the
       rule option's data structure */
    ParseWrongFragment(data, otn);

    if (add_detection_option(sc, RULE_OPTION_TYPE_WRONG_FRAGMENT, (void *)NULL, &ds_ptr_dup) == DETECTION_OPTION_EQUAL)
    {
        //otn->ds_list[PLUGIN_IP_SAME_CHECK] = ds_ptr_dup;
    }

    /* finally, attach the option's detection function to the rule's
       detect function pointer list */
    fpl = AddOptFuncToList(WrongFragmentCheck, otn);
    fpl->type = RULE_OPTION_TYPE_WRONG_FRAGMENT;
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
void ParseWrongFragment(char *data, OptTreeNode *otn)
{
    return; /* the check below bombs. */
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
int WrongFragmentCheck(void *option_data, Packet *p)
{
	//printf("overlapCount=%d\n",p->overlapCount);
    int rval =DETECTION_OPTION_NO_WRONG_FRAGMENT;
    PROFILE_VARS;

    if(!IPH_IS_VALID(p))
        return rval; /* if error occured while ip header
                   * was processed, return 0 automagically.  */

    PREPROC_PROFILE_START(wrongFragmentPerfStats);

    //if (IP_EQUALITY( GET_SRC_IP(p), GET_DST_IP(p)))
    if (p->overlapCount>0)
    {
    	DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,"overlap!  %x ->",sfip_ntoa(GET_SRC_IP(p)));
        DebugMessage(DEBUG_PLUGIN, " %x\n",sfip_ntoa(GET_DST_IP(p))));
        rval = DETECTION_OPTION_WRONG_FRAGMENT;
    }
    else
    {
    	DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,"No overlap!  %x ->",sfip_ntoa(GET_SRC_IP(p)));
        DebugMessage(DEBUG_PLUGIN, " %x\n",sfip_ntoa(GET_DST_IP(p))));
    }

    /* if the test isn't successful, return 0 */
    PREPROC_PROFILE_END(wrongFragmentPerfStats);
    char *srcP = SnortStrdup(inet_ntoa(&p->ip4h->ip_src));
    char *dstP = SnortStrdup(inet_ntoa(&p->ip4h->ip_dst));
    //printf("overlapCount=%d,rval=%d, srcP=%s,dstP=%s\n",p->overlapCount,rval,srcP,dstP);
    return rval;
}
