/*
added by jacky

/* $Id$ */
#ifndef __SP_TWOSECONDS_SAMEDSTSERVICE_SESSIONS_CHECK_H__
#define __SP_TWOSECONDS_SAMEDSTSERVICE_SESSIONS_CHECK_H__

void SetupTwoSecondsSameDstServiceSessionsCheck(void);
uint32_t TwoSecondsSameDstServiceSessionsSameCheckHash(void *d);
int TwoSecondsSameDstServiceSessionsCheckCompare(void *l, void *r);

#endif  /* __SP_TWOSECONDS_SAMEDSTSERVICE_SESSIONS_CHECK_H__ */
