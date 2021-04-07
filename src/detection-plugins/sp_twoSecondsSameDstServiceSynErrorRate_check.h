/*
added by jacky

/* $Id$ */
#ifndef __SP_TWOSECONDS_SAMEDSTSERVICE_SYN_ERROR_RATE_CHECK_H__
#define __SP_TWOSECONDS_SAMEDSTSERVICE_SYN_ERROR_RATE_CHECK_H__

void SetupTwoSecondsSameDstServiceSynErrorRateCheck(void);
uint32_t TwoSecondsSameDstServiceSynErrorRateSameCheckHash(void *d);
int TwoSecondsSameDstServiceSynErrorRateCheckCompare(void *l, void *r);

#endif  /* __SP_TWOSECONDS_SAMEDSTSERVICE_SYN_ERROR_RATE_CHECK_H__ */
