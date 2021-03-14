#include "pch.h"
#include "CertificateQuoteValidator.h"

bool validatequotesshim::CertificateQuoteValidator::HasEmbeddedQuote()
{
	return true;
}

bool validatequotesshim::CertificateQuoteValidator::EmbeddedQuoteIsValid()
{
	return false;
}
