using System;
using System.Runtime.InteropServices;
using validatequotesshim;

namespace validatequotes
{
    class MaaQuoteValidator
    {
        static public void ValidateMaaQuote(string x5c, bool includeDetails)
        {
            var validator = new CertificateQuoteValidator(x5c);

            if (validator.HasEmbeddedQuote())
            {
                Logger.WriteLine($"MAA signing certificate has embedded Open Enclave SGX quote.");

                if (validator.EmbeddedQuoteIsValid())
                {
                    Logger.WriteLine($"Embedded Open Enclave SGX quote is valid and matches certificate key value.");
                }
                else
                {
                    Logger.WriteLine($"Embedded Open Enclave SGX quote is not valid!");
                }
            }
            else
            {
                Logger.WriteLine($"MAA signing certificate does not have embedded Open Enclave SGX quote.");
            }
        }
    }
}
