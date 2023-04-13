/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <rats-tls/verifier.h>
#include <rats-tls/log.h>

extern enclave_verifier_err_t enclave_verifier_register(enclave_verifier_opts_t *);
extern enclave_verifier_err_t demoverifier_pre_init(void);
extern enclave_verifier_err_t demoverifier_init(enclave_verifier_ctx_t *,
						rats_tls_cert_algo_t algo);
extern enclave_verifier_err_t demoverifier_verify_evidence(enclave_verifier_ctx_t *,
							   attestation_evidence_t *, uint8_t *,
							   uint32_t hash_len,
							   attestation_endorsement_t *endorsements);
extern enclave_verifier_err_t demoverifier_cleanup(enclave_verifier_ctx_t *);

static enclave_verifier_opts_t demoverifier_opts = {
	.api_version = ENCLAVE_VERIFIER_API_VERSION_DEFAULT,
	.flags = ENCLAVE_VERIFIER_OPTS_FLAGS_DEFAULT,
	.name = "demoverifier",
	.priority = 0,
	.pre_init = demoverifier_pre_init,
	.init = demoverifier_init,
	.verify_evidence = demoverifier_verify_evidence,
	.cleanup = demoverifier_cleanup,
};

#ifdef SGX
void libverifier_null_init(void)
#else
void __attribute__((constructor)) libverifier_demo_init(void)
#endif
{
	RTLS_DEBUG("called\n");

	enclave_verifier_err_t err = enclave_verifier_register(&demoverifier_opts);
	if (err != ENCLAVE_VERIFIER_ERR_NONE)
		RTLS_ERR("failed to register the enclave verifier 'demoverifier' %#x\n", err);
}
