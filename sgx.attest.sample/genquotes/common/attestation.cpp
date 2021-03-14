// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "attestation.h"
#include <string.h>
#include "log.h"

Attestation::Attestation(Crypto* crypto)
{
    m_crypto = crypto;
}

static oe_uuid_t sgx_remote_uuid = {OE_FORMAT_UUID_SGX_ECDSA};

/**
 * Generate a remote report for the given data. The SHA256 digest of the data is
 * stored in the report_data field of the generated remote report.
 */
bool Attestation::generate_remote_report(
    const uint8_t* data,
    const size_t data_size,
    uint8_t** remote_report_buf,
    size_t* remote_report_buf_size)
{
    bool ret = false;
    uint8_t sha256[32];
    oe_result_t result = OE_OK;
    uint8_t* temp_buf = NULL;
    const oe_uuid_t *format_id = &sgx_remote_uuid;
    uint8_t* format_settings = NULL;
    size_t format_settings_size = 0;
    uint8_t* temp_buf2 = NULL;
    size_t temp_buf2_size = 0;

    if (oe_verifier_initialize() != OE_OK)
    {
        TRACE_ENCLAVE("oe_verifier_initialize failed.");
        goto exit;
    }

    if (oe_verifier_get_format_settings(
        format_id, &format_settings, &format_settings_size) != OE_OK)
    {
        TRACE_ENCLAVE("oe_verifier_get_format_settings failed.");
        goto exit;
    }

    if (m_crypto->Sha256(data, data_size, sha256) != 0)
    {
        goto exit;
    }

    // To generate a remote report that can be attested remotely by an enclave
    // running  on a different platform, pass the
    // OE_REPORT_FLAGS_REMOTE_ATTESTATION option. This uses the trusted
    // quoting enclave to generate the report based on this enclave's local
    // report.
    // To generate a remote report that just needs to be attested by another
    // enclave running on the same platform, pass 0 instead. This uses the
    // EREPORT instruction to generate this enclave's local report.
    // Both kinds of reports can be verified using the oe_verify_report
    // function.
    result = oe_get_report(
        OE_REPORT_FLAGS_REMOTE_ATTESTATION,
        sha256, // Store sha256 in report_data field
        sizeof(sha256),
        NULL, // opt_params must be null
        0,
        &temp_buf,
        remote_report_buf_size);

    if (result != OE_OK)
    {
        TRACE_ENCLAVE("oe_get_report failed.");
        goto exit;
    }
    *remote_report_buf = temp_buf;

    result = oe_get_evidence(
        format_id,
        0,
        sha256,
        sizeof(sha256),
        NULL,
        0,
        remote_report_buf,
        remote_report_buf_size,
        &temp_buf2,
        &temp_buf2_size);
    if (result != OE_OK)
    {
        TRACE_ENCLAVE("oe_get_evidence failed.");
        goto exit;
    }

    ret = true;
    TRACE_ENCLAVE("generate_remote_report succeeded.");
exit:
    return ret;
}
