/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <rats-tls/log.h>
#include <rats-tls/tls_wrapper.h>

tls_wrapper_err_t nulltls_use_cert(tls_wrapper_ctx_t *ctx, rats_tls_cert_info_t *cert_info)
{
	RTLS_DEBUG("ctx %p, cert_info %p\n", ctx, cert_info);

	return TLS_WRAPPER_ERR_NONE;
}
