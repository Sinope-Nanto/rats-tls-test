/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <rats-tls/log.h>
#include <rats-tls/crypto_wrapper.h>

crypto_wrapper_err_t nullcrypto_gen_pubkey_hash(crypto_wrapper_ctx_t *ctx,
						rats_tls_cert_algo_t algo, uint8_t *hash)
{
	RTLS_DEBUG("ctx %p, algo %d, hash %p\n", ctx, algo, hash);

	return CRYPTO_WRAPPER_ERR_NONE;
}