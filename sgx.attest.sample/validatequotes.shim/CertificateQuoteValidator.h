#pragma once

using namespace System;

namespace validatequotesshim {
	public ref class CertificateQuoteValidator
	{
	public:
		CertificateQuoteValidator(String^ certificate) {
			_certificate = certificate;
		}

		bool HasEmbeddedQuote();
		bool EmbeddedQuoteIsValid();

	private:
		String^ _certificate;
	};
}

