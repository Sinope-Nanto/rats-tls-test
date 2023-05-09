/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <rats-tls/log.h>
#include <rats-tls/attester.h>
#include <rats-tls/cert.h>
#include <string.h>
int collect_evidence_from_file(const char* filename, uint8_t* buffer, unsigned* buffer_size)
{
	FILE* measurements = fopen(filename, "rb");
	if(!measurements){
		RTLS_DEBUG("Failed to open file '%s'", filename);
			return 0;
	}
	*buffer_size = fread(buffer, 1, 8096, measurements);
	fclose(measurements);
	if(!(*buffer_size)){
		RTLS_DEBUG("File '%s' exceeds 8096 bytes", filename);
			return 0;
	}
	if(!buffer || buffer[0] == '\0'){ 
		RTLS_DEBUG("Failed to read file '%s' ", filename);
			return 0;		
	}
	return 1;
}

enclave_attester_err_t demoattester_collect_evidence(enclave_attester_ctx_t *ctx,
						attestation_evidence_t *evidence,
						rats_tls_cert_algo_t algo, uint8_t *hash,
						uint32_t hash_len)
{
	RTLS_DEBUG("ctx %p, evidence %p, algo %d, hash %p\n", ctx, evidence, algo, hash);

	uint8_t report[8096];
	report[0] = '\0';
	int report_len;
	if(! collect_evidence_from_file("/mnt/d/code/rats-tls-test/demo_report/ascii_runtime_measurements" , report, &report_len)){
		return ENCLAVE_ATTESTER_ERR_INVALID;
	}
	demo_attestation_evidence_t *demo_report = &evidence->demo;
	memcpy(demo_report->report, report, report_len);
	demo_report->report_len = report_len;

	snprintf(evidence->type, sizeof(evidence->type), "demo");

	RTLS_DEBUG("ctx %p, evidence %p, report_len %d\n", ctx, evidence, evidence->demo.report_len);

	return ENCLAVE_ATTESTER_ERR_NONE;
}
