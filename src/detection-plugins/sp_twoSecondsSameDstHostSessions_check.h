/*
added by jacky

/* $Id$ */
#ifndef __SP_TWOSECONDS_SAMEDSTHOST_SESSIONS_CHECK_H__
#define __SP_TWOSECONDS_SAMEDSTHOST_SESSIONS_CHECK_H__

void SetupTwoSecondsSameDstHostSessionsCheck(void);
uint32_t TwoSecondsSameDstHostSessionsSameCheckHash(void *d);
int TwoSecondsSameDstHostSessionsCheckCompare(void *l, void *r);

#endif  /* __SP_TWOSECONDS_SAMEDSTHOST_SESSIONS_CHECK_H__ */
