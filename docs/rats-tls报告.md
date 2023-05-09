# rats-tls-test
## Build Requirements
+ git
+ make & cmake
+ gcc
+ libssl-dev

## Compile & Install
git clone git@github.com:Sinope-Nanto/rats-tls-test.git  
cd rats-tls-test  
git submodule init  
git submodule update  
cd src  
mkdir build && cd build  
cmake ..  
sudo make install  

## Run Samples
cd rats-tls-test/rats-tls-client  
./install.sh  
cd ../rats-tls-server  
./install.sh  
cd ../samples  
./server.sh  
(another terminal)  
./client.sh  

# rats-tls编译过程
1. 编译libcbor  
编译rats-tls需要首先编译其依赖库libcbor, libcbor的编译过程位于src/LibCBOR.cmake中。
2. 编译attesters与verifiers  
attesters与verifiers并不依赖其他实例，可以直接进行编译。实例会被编译为动态链接库.so文件供core调用。每个实例可以单独被编译(单独编译时改一下每个模块下面的CMakeList里面的路径即可。)
3. 编译crypto_wrappers与tls_wrappers
crypto_wrappers与tls_wrappers的编译过程与attesters与verifiers相同。
4. 编译core
core会被编译为librats_tls.so文件，core也可以单独被编译成.so文件，供服务端或客户端运行时进行链接。  
目前前4步都被整合到src/CMakeLists中，直接进行编译即可。编译后的lib文件会被安装到/usr/local/lib/rats-tls目录下,该目录可以在CMakeList中更改，但是要同时更改源码中加载实例so文件的路径。该配置在src/include/internal/*.h文件中的`ENCLAVE_VERIFIERS_DIR`宏定义中。
5. 编译server与client
把server与client链接到librats_tls.so即可。

# rats-tls运行流程
## 客户端
0. 在执行main函数之前，调用`librats_tls_init`函数，加载所有的实例。  
   
1. 建立socket连接
   
2. 调用`rats_tls_init`函数进行初始化  
函数调用流程  
`rats_tls_init(&conf, &handle)` 该函数负责初始化rats_tls实例
   + `rtls_crypto_wrapper_select()` 该函数会加载默认路径中与-c参数指定的文件名相同的so文件作为实例的crypto wrapper, 参数可以为nullcrypto或者openssl
   + `rtls_attester_select()`  该函数会加载默认路径中与-a参数指定的文件名相同的so文件作为实例的attester
   + `rtls_verifier_select()`  该函数会加载默认路径中与-v参数指定的文件名相同的so文件作为实例的verifier
   + `rtls_tls_wrapper_select()`  该函数会加载默认路径中与-t参数指定的文件名相同的so文件作为实例的tls wrapper, 参数可以为nullcrypto或者openssl
   + `rtls_core_generate_certificate()`  该函数会根据attester提供的度量值和背书以及用户claim生成证书并加载进对话环境
      - `dice_generate_claims_buffer()`  该函数会将custom_claims以无格式二进制串的形式填入claims_buffer_out
      - `dice_generate_evidence_buffer_with_tag()`  该函数会将evidence与evidence的type以无格式二进制串的形式填入evidence_buffer_out
      - `dice_generate_endorsements_buffer_with_tag()`  该函数与`dice_generate_evidence_buffer_with_tag()`相同，只不过操作目标为_endorsements
      - `crypto_wrapper->opts->gen_cert()` , 对于nullcrypto该函数会直接返回。对于opensslcrypto，该函数会将公钥，私钥，利用evidence和endorsements生成的签名后的X509证书加载到cert_info的cert_buffer中。
      - `tls_wrapper->opts->use_privkey()`  对于nulltls该函数会直接返回。对于openssltls，该函数会将储存在`privkey_buf`中的密钥加载到`ctx->tls_private`中。
      - `tls_wrapper->opts->use_cert()`   对于nulltls该函数会直接返回。对于openssltls，该函数会将储存在cert_info的cert_buffer中加载到`ctx->tls_private`中。
3. 调用`rats_tls_set_verification_callback`设置通过证书验证后的回调函数
   
4. 调用`rats_tls_negotiate`进行协商  
通过调用`tls_wrapper->opts->negotiate`进行，此过程会调用`verify_certificate`验证服务端证书;
该函数会验证证书，并与服务端建立SSL链接。
函数调用流程(以openssl为例, null不会进行某些函数调用而是直接返回)  
`rats_tls_err_t rats_tls_negotiate(rats_tls_handle handle, int fd)`
   + `tls_wrapper->opts->negotiate()` / `openssl_tls_negotiate()` 函数会设定`verify_certificate`为证书的验证函数
      - `openssl_internal_negotiate()` 该函数为实际验证证书并建立SSL链接的函数
         + `SSL_CTX_set_verify(ssl_ctx->sctx, mode, verify);` 设定证书验证函数
         + `SSL_set_fd(ssl, fd)`指定SSL端口  
         + `SSL_connect(ssl)`调用ssl的verify函数验证证书并建立SSL连接
            -  `verify_certificate(int preverify_ok, X509_STORE_CTX *ctx)` 解析证书，从证书中提取extension，并调用`tls_wrapper_verify_certificate_extension()`
               + `tls_wrapper_verify_certificate_extension()`该函数负责对服务端证书进行验证，此过程中会调用`verifier->opts->verify_evidence`，该函数在null中会直接返回。

5. 成功建立通讯，此时可以通过`rats_tls_transmit`与`rats_tls_receive`向服务端传递信息或者接受从服务端传送的信息。

## 服务端
服务端流程与客户端基本想同，只是在建立SSL连接时客户端是发起方，服务端是接收方。

# RATS-TLS API 接口分析
## 1 init
函数入口：
```C
rats_tls_err_t rats_tls_init(const rats_tls_conf_t *conf, rats_tls_handle *handle)
```
其中参数结构体的定义
```C
typedef struct {
	unsigned int api_version;
	unsigned long flags;
	rats_tls_log_level_t log_level; 
	char tls_type[TLS_TYPE_NAME_SIZE];
	char attester_type[ENCLAVE_ATTESTER_TYPE_NAME_SIZE];
	char verifier_type[ENCLAVE_VERIFIER_TYPE_NAME_SIZE];
	char crypto_type[CRYPTO_TYPE_NAME_SIZE];
	rats_tls_cert_algo_t cert_algo; // 加密算法
    // typedef enum {
    //     RATS_TLS_CERT_ALGO_RSA_3072_SHA256,
    //     RATS_TLS_CERT_ALGO_ECC_256_SHA256,
    //     RATS_TLS_CERT_ALGO_MAX,
    //     RATS_TLS_CERT_ALGO_DEFAULT,
    // } rats_tls_cert_algo_t;
	claim_t *custom_claims;
    // typedef struct claim claim_t;
    // struct claim {
    //     char *name;
    //     uint8_t *value;
    //     size_t value_size;
    // } __attribute__((packed));

	size_t custom_claims_length;

	/* FIXME: SGX EPID quote type specific parameters */
	struct {
		bool valid;
		uint8_t spid[ENCLAVE_SGX_SPID_LENGTH];
		bool linkable;
	} quote_sgx_epid;

	/* FIXME: SGX ECDSA quote type specific parameters */
	struct {
		bool valid;
		uint8_t cert_type;
	} quote_sgx_ecdsa;
} rats_tls_conf_t;


typedef struct rtls_core_context_t *rats_tls_handle;

typedef struct rtls_core_context_t {
	rats_tls_conf_t config;
	unsigned long flags;
	rats_tls_callback_t user_callback; // 回调函数
	enclave_attester_ctx_t *attester; // 提供证明
	enclave_verifier_ctx_t *verifier; // 验证证明
	tls_wrapper_ctx_t *tls_wrapper; // 建立通讯
	crypto_wrapper_ctx_t *crypto_wrapper; // 加密与签名
} rtls_core_context_t;
```
之后init函数进行以下操作：
+ 对API版本进行检验；
+ 指定加密算法
+ 将conf赋给handle的config
+ 将conf赋给handle的custom claims
+  设置handle的crypto_wrapper, attester, verifier, tls_wrapper设置过程如下：
   - 以设置 tls_wrapper为例
		`api\init.c`中`rtls_tls_wrapper_select(ctx, choice)`调用`tls_wrappers\internal\rtls_tls_wrapper_select.c`中的：
		```C
		rats_tls_err_t rtls_tls_wrapper_select(rtls_core_context_t *ctx, const char *name)
		```
		该函数会在注册的tls_wrapper中选择name指定的tls_wrapper，如果name为NULL，则会选择第一个tls_wrapper。其他模块设置过程基本相同。
+ 检测是否需要TLS证书(使用`config.flog`位)
	```C
	if ((ctx->config.flags & RATS_TLS_CONF_FLAGS_SERVER) || (ctx->config.flags & RATS_TLS_CONF_FLAGS_MUTUAL)) {
		err = rtls_core_generate_certificate(ctx);
		if (err != RATS_TLS_ERR_NONE)
			goto err_ctx;
	}
	```
+ 对于开启了双向认证支持的客户端以及TLS服务端来说，需要调用`rtls_core_generate_certificate()`创建Rats TLS证书,`rtls_core_generate_certificate()`的实现在`core/rtls_core_generate_certificate.c`中,创建过程如下：
  - 调用Crypto Wrapperr实例的`gen_privkey`和`gen_pubkey_hash`方法生成新的key pair和公钥的摘要值
  - 调用Enclave Attester实例的`collect_evidence`方法收集当前平台的证明材料
  - 调用Crypto Wrapper实例的`gen_cert`方法生成TLS证书
  - 调用TLS Wrapper实例的`use_privkey`和`use_cert`方法将私钥和证书加载到tls wrapper上下文



## 2 cleanup
函数入口
```C
rats_tls_err_t rats_tls_cleanup(rats_tls_handle handle)
```
cleanup会清理handle的占用的内存，内存释放成功后返回`RATS_TLS_ERR_NONE`。

## 3 callback
函数入口
```C
rats_tls_err_t rats_tls_set_verification_callback(rats_tls_handle *handle, rats_tls_callback_t cb)
```
callback会将handle认证后的回调函数设置为cb

## 4 negotiate
函数入口如下：
```C
rats_tls_err_t rats_tls_negotiate(rats_tls_handle handle, int fd)
{
	rtls_core_context_t *ctx = (rtls_core_context_t *)handle;
	// rtls_core_context_t* = rats_tls_handle
	RTLS_DEBUG("handle %p, fd %d\n", ctx, fd);

	if (!ctx || !ctx->tls_wrapper || !ctx->tls_wrapper->opts ||
	    !ctx->tls_wrapper->opts->negotiate || fd < 0)
		return -RATS_TLS_ERR_INVALID;
	
	// 调用初始化中设定的tls_wrapper->opts->negotiate函数
	tls_wrapper_err_t t_err = ctx->tls_wrapper->opts->negotiate(ctx->tls_wrapper, fd);
	// tls_wrapper_ctx_t *tls_wrapper;

	if (t_err != TLS_WRAPPER_ERR_NONE)
		return t_err;

	ctx->tls_wrapper->fd = fd;

	return RATS_TLS_ERR_NONE;
}
```
其中`tls_wrapper_ctx_t`的结构如下：
```C
typedef struct tls_wrapper_ctx tls_wrapper_ctx_t;

struct tls_wrapper_ctx {
	/* associate tls wrapper with the enclave verifier instances */
	struct rtls_core_context_t *rtls_handle;
	tls_wrapper_opts_t *opts;
	void *tls_private;
	int fd;
	unsigned long conf_flags;
	rats_tls_log_level_t log_level;
	void *handle;
};

typedef struct {
	uint8_t api_version;
	unsigned long flags;
	const char name[TLS_TYPE_NAME_SIZE];
	uint8_t priority;

	/* Optional */
	tls_wrapper_err_t (*pre_init)(void);
	tls_wrapper_err_t (*init)(tls_wrapper_ctx_t *ctx);
	tls_wrapper_err_t (*use_privkey)(tls_wrapper_ctx_t *ctx, rats_tls_cert_algo_t algo,
					 void *privkey_buf, size_t privkey_len);
	tls_wrapper_err_t (*use_cert)(tls_wrapper_ctx_t *ctx, rats_tls_cert_info_t *cert_info);
	tls_wrapper_err_t (*negotiate)(tls_wrapper_ctx_t *ctx, int fd);
	tls_wrapper_err_t (*transmit)(tls_wrapper_ctx_t *ctx, void *buf, size_t *buf_size);
	tls_wrapper_err_t (*receive)(tls_wrapper_ctx_t *ctx, void *buf, size_t *buf_size);
	tls_wrapper_err_t (*cleanup)(tls_wrapper_ctx_t *ctx);
} tls_wrapper_opts_t;
```

## 5 negotiate & 6 transmit
两者与negotiate接口基本相同，分别调用`tls_wrapper->opts->receive`与`tls_wrapper->opts->transmit`方法。利用参数中的buffer读写网络协议栈，进行信息传输。

# RATS-TLS core 模块分析
## main.c 
main.c定义了`void __attribute__((constructor)) librats_tls_init(void)`函数，该函数会在客户端或者服务器端的main进入之前被调用，该函数完成以下操作：  
加载core的初始化配置与所有的实例，使用`rtls_*_wrapper_load_all()`函数加载配置目录下所有实例，该函数被实现在`*/internal/rtls_enclave_*_load_all.c` 下。配置目录默认为:`/usr/local/lib/rats-tls/*/`, 该路径被定义为`ENCLAVE_*_DIR`，位于`include/internal/*.h`文件中。

## rtls_core_generate_certificate.c
+ 该文件实现了`rtls_core_generate_certificate`函数，该函数用于创建Rats TLS证书，其功能包括：
  - 调用Crypto Wrapperr实例的`gen_privkey`和`gen_pubkey_hash`方法生成新的key pair和公钥的摘要值
  - 调用Enclave Attester实例的`collect_evidence`方法收集当前平台的证明材料
  - 调用Crypto Wrapper实例的`gen_cert`方法生成TLS证书
  - 调用TLS Wrapper实例的`use_privkey`和`use_cert`方法将私钥和证书加载到tls wrapper上下文

+ 函数入口：
```C
rats_tls_err_t rtls_core_generate_certificate(rtls_core_context_t *ctx)
```
+ 函数执行过程

  0. 首先对ctx是否正确完成初始化，绑定模块实例，是否已经生成过TLS证书进行检测。
  ```C
  	RTLS_DEBUG("ctx %p\n", ctx);

  	if (!ctx || !ctx->tls_wrapper || !ctx->tls_wrapper->opts || !ctx->crypto_wrapper ||
  	    !ctx->crypto_wrapper->opts || !ctx->crypto_wrapper->opts->gen_pubkey_hash ||
  	    !ctx->crypto_wrapper->opts->gen_cert)
  		return -RATS_TLS_ERR_INVALID;

  	if (ctx->flags & RATS_TLS_CTX_FLAGS_CERT_CREATED)
  		return RATS_TLS_ERR_NONE;
  ``` 
  1. 根据使用的加密算法确定哈希值长度
  ```C
  	unsigned int hash_size;

  	switch (ctx->config.cert_algo) {
  	case RATS_TLS_CERT_ALGO_RSA_3072_SHA256:
  	case RATS_TLS_CERT_ALGO_ECC_256_SHA256:
  		hash_size = SHA256_HASH_SIZE;
  		break;
  	default:
  		RTLS_DEBUG("unknown algorithm %d\n", ctx->config.cert_algo);
  		return -RATS_TLS_ERR_UNSUPPORTED_CERT_ALGO;
  	}
  ```
  2. 利用crypto_wrapper实例生成私钥和公钥哈希
  ```C
  	/* Generate the new key */
  	crypto_wrapper_err_t c_err;
  	uint8_t privkey_buf[2048];
  	unsigned int privkey_len = sizeof(privkey_buf);
  	c_err = ctx->crypto_wrapper->opts->gen_privkey(ctx->crypto_wrapper, ctx->config.cert_algo,
  						       privkey_buf, &privkey_len);
  	if (c_err != CRYPTO_WRAPPER_ERR_NONE)
  		return c_err;

  	/* Generate the hash of public key */
  	uint8_t hash[hash_size];
  	c_err = ctx->crypto_wrapper->opts->gen_pubkey_hash(ctx->crypto_wrapper,
  							   ctx->config.cert_algo, hash);
  	if (c_err != CRYPTO_WRAPPER_ERR_NONE)
  		return c_err;
  ```
  3. 利用attester实例收集证明
  ```C
  	/* Collect evidence */
  	attestation_evidence_t evidence;
  	memset(&evidence, 0, sizeof(attestation_evidence_t));
      // 申请并置零存放证明的内存

  	// TODO: implement per-session freshness and put "nonce" in custom claims list.
  	uint8_t *claims_buffer = NULL;
  	size_t claims_buffer_size = 0;

  	/* Using sha256 hash of claims_buffer as user data */
  	RTLS_DEBUG("fill evidence user-data field with sha256 of claims_buffer\n");
  	/* Generate claims_buffer */
      // 将claims混合随机数放入claims_buffer，防止重放攻击
  	enclave_attester_err_t a_ret = dice_generate_claims_buffer(
  		HASH_ALGO_SHA256, hash, ctx->config.custom_claims, ctx->config.custom_claims_length,
  		&claims_buffer, &claims_buffer_size);
  	if (a_ret != ENCLAVE_ATTESTER_ERR_NONE) {
  		RTLS_DEBUG("generate claims_buffer failed. a_ret: %#x\n", a_ret);
  		return a_ret;
  	}

  	/* Note here we reuse `uint8_t hash[hash_size]` to store sha256 hash of claims_buffer */
      // 生成claims的哈希值
  	ctx->crypto_wrapper->opts->gen_hash(ctx->crypto_wrapper, HASH_ALGO_SHA256, claims_buffer,
  					    claims_buffer_size, hash);
  	if (hash_size >= 16)
  		RTLS_DEBUG(
  			"evidence user-data field [%zu] %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x...\n",
  			(size_t)hash_size, hash[0], hash[1], hash[2], hash[3], hash[4], hash[5],
  			hash[6], hash[7], hash[8], hash[9], hash[10], hash[11], hash[12], hash[13],
  			hash[14], hash[15]);
  	enclave_attester_err_t q_err = ctx->attester->opts->collect_evidence(
  		ctx->attester, &evidence, ctx->config.cert_algo, hash, hash_size);
  	if (q_err != ENCLAVE_ATTESTER_ERR_NONE) {
  		free(claims_buffer);
  		claims_buffer = NULL;
  		return q_err;
  	}
  	RTLS_DEBUG("evidence.type: '%s'\n", evidence.type);
  ```
  其中```dice_generate_claims_buffer```函数的实现在```core/dice.c```中。

  4. 利用crypto_wrapper生成TLS证书，TLS证书的定义在```included/rats-tls/cert.h```中。
  ```C
  	// 初始化证TLS证书
  	rats_tls_cert_info_t cert_info = {
  		.subject = {
  			.organization = (const unsigned char *)"Inclavare Containers",
  			.common_name = (const unsigned char *)"RATS-TLS",
  		},
  	};
  	cert_info.evidence_buffer = NULL;
  	cert_info.evidence_buffer_size = 0;
  	cert_info.endorsements_buffer = NULL;
  	cert_info.endorsements_buffer_size = 0;

  	// 如果使用nullattester, evidence_buffer_size会为0。
      // 反之会使用evidence，claim与随机数对evidence_buffer进行填充，并释放claims_buffer
      // 最后将evidence写入cert_info的evidence_buffer中
  	if (evidence.type[0] == '\0') {
  		RTLS_WARN(
  			"evidence type is empty, which is normal only when you are using nullattester.\n");
  	} else {
  		enclave_attester_err_t d_ret = dice_generate_evidence_buffer_with_tag(
  			&evidence, claims_buffer, claims_buffer_size, &cert_info.evidence_buffer,
  			&cert_info.evidence_buffer_size);
  		free(claims_buffer);
  		claims_buffer = NULL;
  		if (d_ret != ENCLAVE_ATTESTER_ERR_NONE) {
  			return d_ret;
  		}
  	}
  	RTLS_DEBUG("evidence buffer size: %zu\n", cert_info.evidence_buffer_size);

  	/* Collect endorsements if required */
      // 在需要时收集背书，需要attester支持背书，写入cert_info的endorsements_buffer中
      // 只有SGX_ECDSA与TDX_ECDSA支持背书，可以忽略此部分
  	if ((evidence.type[0] != '\0' /* skip for nullattester */ &&
  	     ctx->config.flags & RATS_TLS_CONF_FLAGS_PROVIDE_ENDORSEMENTS) &&
  	    ctx->attester->opts->collect_endorsements) {
  		attestation_endorsement_t endorsements;
  		memset(&endorsements, 0, sizeof(attestation_endorsement_t));

  		enclave_attester_err_t q_ret = ctx->attester->opts->collect_endorsements(
  			ctx->attester, &evidence, &endorsements);
  		if (q_ret != ENCLAVE_ATTESTER_ERR_NONE) {
  			RTLS_WARN("failed to collect collateral: %#x\n", q_ret);
  			/* Since endorsements are not essential, we tolerate the failure to occur. */
  		} else {
  			/* Get DICE endorsements buffer */
  			enclave_attester_err_t d_ret = dice_generate_endorsements_buffer_with_tag(
  				evidence.type, &endorsements, &cert_info.endorsements_buffer,
  				&cert_info.endorsements_buffer_size);
  			free_endorsements(evidence.type, &endorsements);
  			if (d_ret != ENCLAVE_ATTESTER_ERR_NONE) {
  				RTLS_ERR("Failed to generate endorsements buffer %#x\n", d_ret);
  				return d_ret;
  			}
  		}
  	}
  	RTLS_DEBUG("endorsements buffer size: %zu\n", cert_info.endorsements_buffer_size);

  	/* Generate the TLS certificate */
      // 调用crypto_wrapper使用cert_info生成TLS证书
  	c_err = ctx->crypto_wrapper->opts->gen_cert(ctx->crypto_wrapper, ctx->config.cert_algo,
  						    &cert_info);
  	if (c_err != CRYPTO_WRAPPER_ERR_NONE)
  		return c_err;
  ```
  5. 调用tls_wrapper实例使用TLS证书建立TLS通讯
  ```C
  	/* Use the TLS certificate and private key for TLS session */
  	if (privkey_len) {
  		tls_wrapper_err_t t_err;

  		t_err = ctx->tls_wrapper->opts->use_privkey(ctx->tls_wrapper, ctx->config.cert_algo,
  							    privkey_buf, privkey_len);
  		if (t_err != TLS_WRAPPER_ERR_NONE)
  			return t_err;

  		t_err = ctx->tls_wrapper->opts->use_cert(ctx->tls_wrapper, &cert_info);
  		if (t_err != TLS_WRAPPER_ERR_NONE)
  			return t_err;
  	}

  	/* Prevent from re-generation of TLS certificate */
  	ctx->flags |= RATS_TLS_CTX_FLAGS_CERT_CREATED;
  ```

## endorsement.c
释放背书内存，只有SGX_ECDSA与TDX_ECDSA需要此文件。

## rtls_common.c
定义了一些通用的函数，如读写文件、读写目录。对于SGX定义了进入与离开rtls enclave的方法。

## cpu.c
获取CPU环境（位长，对HW-TEE的支持情况）。  

## claim.c
提供free_claims_list和free_claims_list函数，前者供init函数将conf中的claim复制到handle中使用，后者在cleanup中被调用。

## dice.c
该文件实现了由evidence生成证书了过程，包含下列函数。如果对证书类型进行扩展，应该对该文件以及相关宏定义进行修改。
+ `uint64_t tag_of_evidence_type(const char *type)`根据type返回对应的tag。
+ `bool tag_is_valid(uint64_t tag)`检测tag合法性。
+ `const uint8_t *evidence_get_raw_as_ref(const attestation_evidence_t *evidence, size_t *size_out)`获取evidence中的quote或report。
+ `int evidence_from_raw(const uint8_t *data, size_t size, uint64_t tag, attestation_evidence_t *evidence)`将data中的数据复制到evidence的report或quote中。

以下函数除生成endorsements外与HW-TEE环境无关。
+ 生成公钥哈希值
```C
enclave_attester_err_t dice_generate_pubkey_hash_value_buffer(hash_algo_t pubkey_hash_algo,
							const uint8_t *pubkey_hash,
							uint8_t **pubkey_hash_value_buffer,
							size_t *pubkey_hash_value_buffer_size)
```
该函数与下列函数均使用了libcbor库(<https://github.com/PJK/libcbor.git>), 文档(<https://libcbor.readthedocs.org>)。libcbor 是一个用于解析和生成 CBOR 的 C 库，CBOR 是一种通用的无模式二进制数据格式。  
该函数的作用是将生成的`pubkey_hash`值写入`pubkey_hash_value_buffer`。
+ `dice_generate_claims_buffer`生成claims_buffer与`dice_generate_pubkey_hash_value_buffer`基本一致。
+ `dice_generate_evidence_buffer_with_tag`与`dice_generate_endorsements_buffer_with_tag`函数会将evidence与endorsements信息写入buffer.
+ `dice_parse_claims_buffer`将claims写入claims_buffer
``` C   
/* Parse the claims buffer and return the custom claims and pubkey hash. Note that
 * the content of the claims buffer is untrusted user input, and its format match
 * the format defined by Interoperable RA-TLS.
 * 
 * claims_buffer: The claims buffer to be parsed.
 * claims_buffer_size: Size of claims buffer in bytes.
 * pubkey_hash_algo_out: The `hash_algo_id` of pubkey `hash-entry`
 * pubkey_hash_out: A buffer for writing pubkey hash to, should be large enough
 *     (MAX_HASH_SIZE) to write the hash.
 * custom_claims_out: The list of claims stored in the claims buffer, user-defined
 *     custom claims included only. The caller should manage its memory.
 * custom_claims_length_out: The length of claims list.
 *  */
enclave_verifier_err_t
dice_parse_claims_buffer(const uint8_t *claims_buffer, size_t claims_buffer_size,
			 hash_algo_t *pubkey_hash_algo_out, uint8_t *pubkey_hash_out,
			 claim_t **custom_claims_out, size_t *custom_claims_length_out) 
```

# RATS-TLS 模块加载与注册过程
## \*/internal/\*.c
该文件定义了`*_opts`,`*_ctx`两数组，用于储存注册的*实例(.so文件/当环境为SGX时为.a文件)。
## internal/rtls_*_load_single.c
1. 初始化*实例的函数，函数入口：
```c
rats_tls_err_t rtls_*_post_init(const char *name, void *handle)
```
该函数会在已注册的*_opts中寻找name与参数相同的*_opts，之后调用`pre_init()`函数进行初始化，之后将\*注册到\*_ctx中。  

2. 加载*实例的函数：
```C
rats_tls_err_t rtls_*_load_single(const char *fname)
```
该函数会从`*_DIR`目录下的名为`fname`文件中通过调用`rtls_*_post_init`加载*，并初始化handle。
## internal/rtls_*_load_all.c
加载目录下所有*实例的函数，通过调用`rtls_*_load_single`实现。
```C
rats_tls_err_t rtls_*_load_all(void)
```
## internal/rtls_*_select.c
1. 初始化*的函数
```C
static rats_tls_err_t init_*(rtls_core_context_t *ctx,
					    *_ctx_t **_ctx,
					    rats_tls_cert_algo_t algo)
```
该函数通过调用的init方法进行初始化,`init()`函数会调用`*_register()`将opt注册到*_opts中。

2. 选择经过注册的*的函数
```C
rats_tls_err_t rtls_*_select(rtls_core_context_t *ctx, const char *name,
				    rats_tls_cert_algo_t algo)
```
该函数会将`*_ctx`中与name相同的attenter赋值给`ctx->*`。
## api/*_register.c
函数入口
```C
*_err_t *_register(const *_opts_t *opts)
```
该函数会检查HW-TEE是否支持\*的类型，检查opts是否合法，然后在数组`*_opts`中注册此\*_opts。

## tls_wrappers/api/tls_wrapper_verify_certificate_extension.c
该文件为tls_wrappers独有的文件，负责检验对方证书。
+ 该函数首先会检查verify的类型是否与evidence的类型一致，之后调用verifier的verify_evidence方法检验evidence。
	```C
	tls_wrapper_err_t
	tls_wrapper_verify_evidence(tls_wrapper_ctx_t *tls_ctx, attestation_evidence_t *evidence,
					uint8_t *hash, uint32_t hash_len,
					attestation_endorsement_t *endorsements /* Optional */)
	```
+ 该函数会利用`tls_wrapper_verify_evidence`检查evidence，在检查通过后调用用户设置的回调函数。
	```C
	tls_wrapper_err_t tls_wrapper_verify_certificate_extension(
		tls_wrapper_ctx_t *tls_ctx,
		const uint8_t *pubkey_buffer /* in SubjectPublicKeyInfo format */,
		size_t pubkey_buffer_size, uint8_t *evidence_buffer /* optional, for nullverifier */,
		size_t evidence_buffer_size, uint8_t *endorsements_buffer /* optional */,
		size_t endorsements_buffer_size)
	```

# crypto(openssl)
## gen_cert

函数入口：
```C
crypto_wrapper_err_t openssl_gen_cert(crypto_wrapper_ctx_t *ctx, rats_tls_cert_algo_t algo,
				      rats_tls_cert_info_t *cert_info)
```
首先，该函数生成一个加密密钥pkey，并将其加载进ctx的密钥。
```C
EVP_PKEY *pkey = NULL;
if (algo == RATS_TLS_CERT_ALGO_ECC_256_SHA256) {
    if (!EVP_PKEY_assign_EC_KEY(pkey, octx->eckey))
        goto err;
} else if (algo == RATS_TLS_CERT_ALGO_RSA_3072_SHA256) {
    if (!EVP_PKEY_assign_RSA(pkey, octx->key))
        goto err;
} else {
    return -CRYPTO_WRAPPER_ERR_UNSUPPORTED_ALGO;
}
```
之后该函数生成了一个X509证书，并进行初始化，并将证书的公钥设置为pkey
```C
cert = X509_new();
if (!cert)
    goto err;

X509_set_version(cert, 2 /* x509 version 3 cert */);
ASN1_INTEGER_set(X509_get_serialNumber(cert), CERT_SERIAL_NUMBER);
if (!using_cert_nonce) {
    /* WORKAROUND: allow 1 hour delay for the systems behind current clock */
    X509_gmtime_adj(X509_get_notBefore(cert), -3600);
    /* 1 year */
    X509_gmtime_adj(X509_get_notAfter(cert), (long)3600 * 24 * 365 * 1);
} else {
    /* WORKAROUND: with nonce mechanism, the validity of cert can be fixed within a larger range. */
    const char timestr_notBefore[] = "19700101000001Z";
    const char timestr_notAfter[] = "20491231235959Z";
    ASN1_TIME_set_string(X509_get_notBefore(cert), timestr_notBefore);
    ASN1_TIME_set_string(X509_get_notAfter(cert), timestr_notAfter);
}

ret = -CRYPTO_WRAPPER_ERR_PUB_KEY_LEN;
if (!X509_set_pubkey(cert, pkey))
    goto err;
```
然后函数会将cert_info中的evidence_buffer，cert_info->endorsements_buffer使用`x509_extension_add`函数写入x509证书。
```C
if (!x509_extension_add_common(cert))
    goto err;

/* Add evidence extension */
if (cert_info->evidence_buffer_size) {
    /* The DiceTaggedEvidence extension criticality flag SHOULD be marked critical. */
    if (!x509_extension_add(cert, TCG_DICE_TAGGED_EVIDENCE_OID, false,
                cert_info->evidence_buffer,
                cert_info->evidence_buffer_size) != RATS_TLS_ERR_NONE)
        goto err;
}

/* Add endorsements extension */
if (cert_info->endorsements_buffer_size) {
    if (!x509_extension_add(cert, TCG_DICE_ENDORSEMENT_MANIFEST_OID, false,
                cert_info->endorsements_buffer,
                cert_info->endorsements_buffer_size) != RATS_TLS_ERR_NONE)
        goto err;
}
```
最后使用私钥对证书进行签名,并将签名后的证书加载到cert_info中
```C
ret = -CRYPTO_WRAPPER_ERR_CERT;
if (!X509_sign(cert, pkey, EVP_sha256()))
    goto err;

der = cert_info->cert_buf;
len = i2d_X509(cert, &der);
if (len < 0)
    goto err;

cert_info->cert_len = len;
```

## pre_init
该函数会直接返回。

## init
该函数会初始化openssl密钥即`ctx->crypto_private`，为其申请内存。

## gen_privkey
在openssl实例中，该函数指针指向`crypto_wrapper_err_t openssl_gen_privkey(crypto_wrapper_ctx_t *ctx, rats_tls_cert_algo_t algo, uint8_t *privkey_buf, uint32_t *privkey_len)`, 该函数会生成一个参数`algo`指定算法的密钥并填入`privkey_buf`中,将`ctx->crypto_private`填入指定密钥结构，
密码算法可以为`ECC_256_SHA256`或`RSA_3072_SHA256`。

## gen_pubkey_hash
在openssl实例中，该函数指针指向`crypto_wrapper_err_t openssl_gen_pubkey_hash(crypto_wrapper_ctx_t *ctx, rats_tls_cert_algo_t algo, uint8_t *hash)`, 该函数会将`ctx->crypto_private`中公钥的SHA256散列值填入hash中，algo参数指定的是公钥对应的加密算法。

## gen_hash
在openssl实例中，该函数指针指向`crypto_wrapper_err_t openssl_gen_hash(crypto_wrapper_ctx_t *ctx, hash_algo_t hash_algo, const uint8_t *data, size_t size, uint8_t *hash)`, 该函数会将`data`使用`hash_algo`指定散列算法计算后的散列值填入`hash`中。

## cleanup
该函数负责释放`ctx->crypto_private`。

# tls(openssl)
## pre_init
该函数会直接返回

## init
该函数首先加载openssl环境
```C
OpenSSL_add_all_algorithms();
SSL_load_error_strings();
ERR_load_crypto_strings();
OpenSSL_add_all_ciphers();
```
之后对`ctx->tls_private`进行初始化
```C
	openssl_ctx_t *ssl_ctx = calloc(1, sizeof(*ssl_ctx));
	if (ctx->conf_flags & RATS_TLS_CONF_FLAGS_SERVER)
#if OPENSSL_VERSION_NUMBER < 0x10100000L // 服务端的初始化
		ssl_ctx->sctx = SSL_CTX_new(TLSv1_2_server_method());
#else
		ssl_ctx->sctx = SSL_CTX_new(TLS_server_method());
#endif
	else
#if OPENSSL_VERSION_NUMBER < 0x10100000L // 客户端的初始化
		ssl_ctx->sctx = SSL_CTX_new(TLSv1_2_client_method());
#else
		ssl_ctx->sctx = SSL_CTX_new(TLS_client_method());
#endif
	ctx->tls_private = ssl_ctx;
```
最后对每个线程的密钥进行初始化
```C
per_thread_key_init();
```

## use_privkey
该函数会将储存在`privkey_buf`中的密钥加载到`ctx->tls_private`中
```C
tls_wrapper_err_t openssl_tls_use_privkey(tls_wrapper_ctx_t *ctx, rats_tls_cert_algo_t algo,
					  void *privkey_buf, size_t privkey_len)
{
	RTLS_DEBUG("ctx %p, privkey_buf %p, privkey_len %zu\n", ctx, privkey_buf, privkey_len);

	if (!ctx || !privkey_buf || !privkey_len)
		return -TLS_WRAPPER_ERR_INVALID;

	openssl_ctx_t *ssl_ctx = (openssl_ctx_t *)ctx->tls_private;

	int EPKEY;

	if (algo == RATS_TLS_CERT_ALGO_ECC_256_SHA256) {
		EPKEY = EVP_PKEY_EC;
	} else if (algo == RATS_TLS_CERT_ALGO_RSA_3072_SHA256) {
		EPKEY = EVP_PKEY_RSA;
	} else {
		return -CRYPTO_WRAPPER_ERR_UNSUPPORTED_ALGO;
	}

	int ret = SSL_CTX_use_PrivateKey_ASN1(EPKEY, ssl_ctx->sctx, privkey_buf, (long)privkey_len);

	if (ret != SSL_SUCCESS) {
		RTLS_ERR("failed to use private key %d\n", ret);
		return OPENSSL_ERR_CODE(ret);
	}

	return TLS_WRAPPER_ERR_NONE;
}
```

## use_cert
该函数会将储存在cert_info的cert_buffer中加载到`ctx->tls_private`中。
```C
tls_wrapper_err_t openssl_tls_use_cert(tls_wrapper_ctx_t *ctx, rats_tls_cert_info_t *cert_info)
{
	RTLS_DEBUG("ctx %p, cert_info %p\n", ctx, cert_info);

	if (!ctx || !cert_info)
		return -TLS_WRAPPER_ERR_INVALID;

	openssl_ctx_t *ssl_ctx = (openssl_ctx_t *)ctx->tls_private;
	int ret = SSL_CTX_use_certificate_ASN1(ssl_ctx->sctx, cert_info->cert_len,
					       cert_info->cert_buf);
	if (ret != SSL_SUCCESS) {
		RTLS_ERR("failed to use certificate %d\n", ret);
		return OPENSSL_ERR_CODE(ret);
	}

	return TLS_WRAPPER_ERR_NONE;
}

```

## negotiate
`openssl_tls_negotiate`是一个函数入口，其将验证方法设置为`verify_certificate`之后调用`openssl_internal_negotiate`函数验证证书。
```C
tls_wrapper_err_t openssl_tls_negotiate(tls_wrapper_ctx_t *ctx, int fd)
{
	RTLS_DEBUG("ctx %p, fd %d\n", ctx, fd);

	if (!ctx)
		return -TLS_WRAPPER_ERR_INVALID;

	int (*verify)(int, X509_STORE_CTX *) = NULL;
	unsigned long conf_flags = ctx->conf_flags;

	if (!(conf_flags & RATS_TLS_CONF_FLAGS_SERVER) ||
	    (conf_flags & RATS_TLS_CONF_FLAGS_MUTUAL)) {
		verify = verify_certificate;
	}

	return openssl_internal_negotiate(ctx, conf_flags, fd, verify);
}
```
`openssl_internal_negotiate`是实际负责认证证书的函数。
首先函数会设定建立SSL链接的verify函数
```C
if (verify) {
    int mode = SSL_VERIFY_NONE;

    if (!(conf_flags & RATS_TLS_CONF_FLAGS_SERVER))
        mode |= SSL_VERIFY_PEER;
    else if (conf_flags & RATS_TLS_CONF_FLAGS_MUTUAL)
        mode |= SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT;

    SSL_CTX_set_verify(ssl_ctx->sctx, mode, verify); 
}
```
之后会与服务端/客户端建立SSL链接
```C
SSL *ssl = SSL_new(ssl_ctx->sctx);
if (!ssl)
    return -TLS_WRAPPER_ERR_NO_MEM;

X509_STORE *cert_store = SSL_CTX_get_cert_store(ssl_ctx->sctx);
int ex_data_idx = X509_STORE_get_ex_new_index(0, "ex_data", NULL, NULL, NULL);
X509_STORE_set_ex_data(cert_store, ex_data_idx, ctx);

int *ex_data = calloc(1, sizeof(*ex_data));
if (!ex_data) {
    RTLS_ERR("failed to calloc ex_data\n");
    return -TLS_WRAPPER_ERR_NO_MEM;
}

*ex_data = ex_data_idx;
if (!per_thread_setspecific((void *)ex_data)) {
    RTLS_ERR("failed to store ex_data\n");
    return -TLS_WRAPPER_ERR_INVALID;
}

/* Attach openssl to the socket */
int ret = SSL_set_fd(ssl, fd);
if (ret != SSL_SUCCESS) {
    RTLS_ERR("failed to attach SSL with fd, ret is %x\n", ret);
    return -TLS_WRAPPER_ERR_INVALID;
}

int err;
if (conf_flags & RATS_TLS_CONF_FLAGS_SERVER) // 回调函数会在执行SSL_accept的过程中被调用
    err = SSL_accept(ssl);
else
    err = SSL_connect(ssl);
```

## transmit
transmit利用建立的ssl信道向对方传达buf中的信息。

## receive
receive接受ssl信道对方传递的信息并写入buf中。

## cleanup
cleanup函数会关闭建立的SSL链接并释放`ctx->tls_private`占用的内存。

# attesters
## pre_init
该函数会直接返回。

## init
该函数会将`ctx->attester_private`设置为一个固定值`&dummy_private`后返回。

## collect_evidence (需要自己实现的部分)
该函数原型为：`enclave_attester_err_t *_collect_evidence(enclave_attester_ctx_t *ctx, attestation_evidence_t *evidence, rats_tls_cert_algo_t algo, uint8_t *hash, uint32_t hash_len)`该函数利用HW-TEE收集evidence，并将evidence填入`evidence->*`中。

## collect_endorsements (需要自己实现的部分)
该函数与`collect_evidence`基本一致，会将收集的背书填入`endorsements->*`中。

## cleanup
该函数会直接返回。

#  verifiers
## pre_init
该函数会直接返回。

## init
该函数会将`ctx->verifier_private`设置为一个固定值`&dummy_private`后返回。

## verify_evidence (需要自己实现的部分)
该函数会检验证书是否正确

## cleanup
该函数会直接返回。

# 添加新类型的实例

## 修改结构体定义和宏定义
1. rats-tls/api.h文件中定义了rats-tls使用的evidence的结构体，需要添加新类型evidence的结构体。
2. 对rats-tls/attester.h中attester的声明进行修改，添加新类型实例的定义。
3. 在rats-tls/cert.h中添加新类型的证书定义。
4. 在rats-tls/verifier.h中对verifier的声明进行修改，添加新类型实例的定义。
5. 在internal/dice.h中添加新类型CBOR的宏定义并修改`OCBR_TAG_EVIDENCE_MAX`

## 在实现中添加新类型的分支
1. 在core/dice中添加新类型的分支。  
在完成这两步之后，core便可以被编译，server与client也可以被编译。之后只需要按照要求，重写attester/verifiers的相关函数，实现相关功能之后编译出so文件放入指定路径即可。 


## 实现新类型attester与verifier的功能
1. cleanup， 对于attester与verifier，该函数直接返回`ENCLAVE_*_ERR_NONE`即可。
2. pre_init，该函数会在init前调用。无特殊需求直接返回`ENCLAVE_*_ERR_NONE`即可。(该函数可以用作检查环境)
3. init，该函数被其他实例用于申请内存，但是attester与verifier并不需要额外申请内存，故将其句柄设置为哑变量返回`ENCLAVE_*_ERR_NONE`即可。
4. collect_endorsements，该函数用于SGX收集背书，对于其他类型的实例不会被调用。
5. collect_evidence。该函数是实际收集evidence的函数，此函数是需要编写的部分，函数原型为：
```C
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
```
该函数负责将收集的report填入evidence->\*中，其中\*是头文件中定义的实例类型之一。ctx是会话句柄，algo，hash，hash_len三个参数并没有被使用。
在之后的通讯过程中，evidence会被填入X509证书的拓展部份，并被通讯目标解析出来(解析证书的工作会由openssl库完成，无需重新编写)。在evidence收集成功后，该函数应返回`ENCLAVE_ATTESTER_ERR_NONE`。

1. verify_evidence， 该函数是实际验证evidence的函数，函数原型为：
```C
enclave_verifier_err_t demoverifier_verify_evidence(enclave_verifier_ctx_t *ctx,
						    attestation_evidence_t *evidence, uint8_t *hash,
						    unsigned int hash_len,
						    attestation_endorsement_t *endorsements)
{
	RTLS_DEBUG("ctx %p, evidence %p, hash %p endorsements %p\n", ctx, evidence, hash,
		   endorsements);
	return ENCLAVE_VERIFIER_ERR_NONE;
}
```
参数evidence即为需要验证的evidence，与attester填入的数据相同，验证通过后返回`ENCLAVE_VERIFIER_ERR_NONE`。ctx是会话句柄，hash，hash_len两个参数并没有被使用，endorsements只有验证平台为SGX时才会被使用。

在实现attester与verifier的功能后，将attester与verifier实例进行编译，core便可以对新实例加载运行。core在初始化时便加载所有实例，其使用name作为查找实例的键值。name在实例的main.c文件里被定义。