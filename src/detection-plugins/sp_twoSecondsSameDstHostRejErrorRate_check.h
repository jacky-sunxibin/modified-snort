/*
added by jacky

/* $Id$ */
#ifndef __SP_TWOSECONDS_SAMEDSTHOST_REJ_ERROR_RATE_CHECK_H__
#define __SP_TWOSECONDS_SAMEDSTHOST_REJ_ERROR_RATE_CHECK_H__

void SetupTwoSecondsSameDstHostRejErrorRateCheck(void);
uint32_t TwoSecondsSameDstHostRejErrorRateSameCheckHash(void *d);
int TwoSecondsSameDstHostRejErrorRateCheckCompare(void *l, void *r);

#endif  /* __SP_TWOSECONDS_SAMEDSTHOST_REJ_ERROR_RATE_CHECK_H__ */
