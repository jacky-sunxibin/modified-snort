/*
added by jacky

/* $Id$ */
#ifndef __SP_TWOSECONDS_SAMEDSTHOST_SERVICE_RATE_CHECK_H__
#define __SP_TWOSECONDS_SAMEDSTHOST_SERVICE_RATE_CHECK_H__

void SetupTwoSecondsSameDstHostServiceRateCheck(void);
uint32_t TwoSecondsSameDstHostServiceRateSameCheckHash(void *d);
int TwoSecondsSameDstHostServiceRateCheckCompare(void *l, void *r);

#endif  /* __SP_TWOSECONDS_SAMEDSTHOST_SERVICE_RATE_CHECK_H__ */
