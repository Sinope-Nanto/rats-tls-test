/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <rats-tls/log.h>
#include <rats-tls/verifier.h>

enclave_verifier_err_t demoverifier_verify_evidence(enclave_verifier_ctx_t *ctx,
						    attestation_evidence_t *evidence, uint8_t *hash,
						    __attribute__((unused)) unsigned int hash_len,
						    attestation_endorsement_t *endorsements)
{
	RTLS_DEBUG("ctx %p, evidence %p, hash %p endorsements %p\n", ctx, evidence, hash,
		   endorsements);

	return ENCLAVE_VERIFIER_ERR_NONE;
}
