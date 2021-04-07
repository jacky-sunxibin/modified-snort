/*
added by jacky

/* $Id$ */
#ifndef __SP_BEFORE_100_SAMEDSTHOST_SESSIONS_CHECK_H__
#define __SP_BEFORE_100_SAMEDSTHOST_SESSIONS_CHECK_H__

void SetupBefore100SameDstHostSessionsCheck(void);
uint32_t Before100SameDstHostSessionsSameCheckHash(void *d);
int Before100SameDstHostSessionsCheckCompare(void *l, void *r);

#endif  /* __SP_BEFORE_100_SAMEDSTHOST_SESSIONS_CHECK_H__ */
