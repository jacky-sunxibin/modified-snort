/*
added by jacky

/* $Id$ */
#ifndef __SP_TWOSECONDS_SAMEDSTSERVICE_REJ_ERROR_RATE_CHECK_H__
#define __SP_TWOSECONDS_SAMEDSTSERVICE_REJ_ERROR_RATE_CHECK_H__

void SetupTwoSecondsSameDstServiceRejErrorRateCheck(void);
uint32_t TwoSecondsSameDstServiceRejErrorRateSameCheckHash(void *d);
int TwoSecondsSameDstServiceRejErrorRateCheckCompare(void *l, void *r);

#endif  /* __SP_TWOSECONDS_SAMEDSTSERVICE_REJ_ERROR_RATE_CHECK_H__ */
