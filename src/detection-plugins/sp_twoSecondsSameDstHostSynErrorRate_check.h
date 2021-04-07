/*
added by jacky

/* $Id$ */
#ifndef __SP_TWOSECONDS_SAMEDSTHOST_SYN_ERROR_RATE_CHECK_H__
#define __SP_TWOSECONDS_SAMEDSTHOST_SYN_ERROR_RATE_CHECK_H__

void SetupTwoSecondsSameDstHostSynErrorRateCheck(void);
uint32_t TwoSecondsSameDstHostSynErrorRateSameCheckHash(void *d);
int TwoSecondsSameDstHostSynErrorRateCheckCompare(void *l, void *r);

#endif  /* __SP_TWOSECONDS_SAMEDSTHOST_SYN_ERROR_RATE_CHECK_H__ */
