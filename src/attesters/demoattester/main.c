/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <rats-tls/attester.h>
#include <rats-tls/log.h>

extern enclave_attester_err_t enclave_attester_register(enclave_attester_opts_t *);
extern enclave_attester_err_t demoattester_pre_init(void);
extern enclave_attester_err_t demoattester_init(enclave_attester_ctx_t *,
						rats_tls_cert_algo_t algo);
//extern enclave_attester_err_t nullattester_extend_cert(enclave_attester_ctx_t *ctx,
//					    const rats_tls_cert_info_t *cert_info);
extern enclave_attester_err_t demoattester_collect_evidence(enclave_attester_ctx_t *,
							    attestation_evidence_t *,
							    rats_tls_cert_algo_t algo, uint8_t *,
							    uint32_t hash_len);
extern enclave_attester_err_t
demoattester_collect_endorsements(enclave_attester_ctx_t *ctx, attestation_evidence_t *evidence,
				  attestation_endorsement_t *endorsements);
extern enclave_attester_err_t demoattester_cleanup(enclave_attester_ctx_t *);

static enclave_attester_opts_t demoattester_opts = {
	.api_version = ENCLAVE_ATTESTER_API_VERSION_DEFAULT,
	.flags = ENCLAVE_ATTESTER_FLAGS_DEFAULT,
	.name = "demoattester",
	.priority = 0,
	.pre_init = demoattester_pre_init,
	.init = demoattester_init,
	//.extend_cert = demoattester_extend_cert,
	.collect_evidence = demoattester_collect_evidence,
	.collect_endorsements = demoattester_collect_endorsements,
	.cleanup = demoattester_cleanup,
};

void __attribute__((constructor)) libattester_demo_init(void)
{
	RTLS_DEBUG("called\n");

	enclave_attester_err_t err = enclave_attester_register(&demoattester_opts);
	if (err != ENCLAVE_ATTESTER_ERR_NONE)
		RTLS_ERR("failed to register the enclave attester 'demoattester' %#x\n", err);
}
