// SPDX-License-Identifier: GPL-2.0-only
#define _GNU_SOURCE
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <ucode/module.h>

#define PEM_LIMIT 16384

static uc_value_t *identifier(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *value = uc_fn_arg(0);
	if (ucv_type(value) != UC_STRING)
		return ucv_boolean_new(false);
	size_t length = ucv_string_length(value);
	if (!length || length > 64)
		return ucv_boolean_new(false);
	const unsigned char *name = (const unsigned char *)ucv_string_get(value);
	for (size_t i = 0; i < length; i++) {
		unsigned char c = name[i];
		if (c != '_' && !(c >= '0' && c <= '9') &&
		    !(c >= 'A' && c <= 'Z') && !(c >= 'a' && c <= 'z'))
			return ucv_boolean_new(false);
	}
	return ucv_boolean_new(true);
}

/* Packed short strings are bytes in their uc_value_t * variable slot. Keep
 * that borrowed slot in the native caller, not in this returning helper. */
static const char *string_arg(uc_vm_t *vm, size_t nargs, size_t index, uc_value_t **slot)
{
	*slot = uc_fn_arg(index);
	if (ucv_type(*slot) != UC_STRING || ucv_string_length(*slot) > PEM_LIMIT ||
	    memchr(ucv_string_get(*slot), 0, ucv_string_length(*slot)))
		return NULL;
	return ucv_string_get(*slot);
}

static int identity(const char *id)
{
	if (!id || strlen(id) != 32)
		return 0;
	for (size_t i = 0; i < 32; i++)
		if (!((id[i] >= '0' && id[i] <= '9') || (id[i] >= 'a' && id[i] <= 'f')))
			return 0;
	return 1;
}

static uc_value_t *bio_string(BIO *bio)
{
	char *p;
	long n = BIO_get_mem_data(bio, &p);
	return n > 0 && n <= PEM_LIMIT ? ucv_string_new_length(p, (size_t)n) : NULL;
}

static EVP_PKEY *read_key(const char *pem)
{
	BIO *bio = pem ? BIO_new_mem_buf(pem, (int)strlen(pem)) : NULL;
	EVP_PKEY *key = bio ? PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL) : NULL;
	BIO_free(bio);
	return key;
}

static X509 *read_cert(const char *pem)
{
	BIO *bio = pem ? BIO_new_mem_buf(pem, (int)strlen(pem)) : NULL;
	X509 *cert = bio ? PEM_read_bio_X509(bio, NULL, NULL, NULL) : NULL;
	BIO_free(bio);
	return cert;
}

/* Local trust files contain one CA, or exactly two during a manual rotation.
 * Enrollment still normalizes its independently pinned first certificate. */
static int trust_store(X509_STORE *store, const char *pem)
{
	BIO *bio = pem ? BIO_new_mem_buf(pem, (int)strlen(pem)) : NULL;
	X509 *cert;
	int count = 0, ok = store && bio;
	while (ok && (cert = PEM_read_bio_X509(bio, NULL, NULL, NULL))) {
		EVP_PKEY *pub = X509_get_pubkey(cert);
		ok = ++count <= 2 && pub && EVP_PKEY_base_id(pub) == EVP_PKEY_ED25519 &&
			X509_check_ca(cert) > 0 && X509_verify(cert, pub) == 1 &&
			X509_NAME_cmp(X509_get_subject_name(cert), X509_get_issuer_name(cert)) == 0 &&
			X509_STORE_add_cert(store, cert) == 1;
		EVP_PKEY_free(pub);
		X509_free(cert);
	}
	BIO_free(bio);
	return ok && count > 0;
}

static uc_value_t *hex_digest(const unsigned char *data, size_t len)
{
	unsigned char hash[EVP_MAX_MD_SIZE];
	unsigned int n;
	char hex[65];
	static const char digits[] = "0123456789abcdef";
	if (!EVP_Digest(data, len, hash, &n, EVP_sha256(), NULL) || n != 32)
		return NULL;
	for (size_t i = 0; i < 32; i++) {
		hex[i * 2] = digits[hash[i] >> 4];
		hex[i * 2 + 1] = digits[hash[i] & 15];
	}
	hex[64] = 0;
	return ucv_string_new(hex);
}

static int key_identity(EVP_PKEY *key, const char *id)
{
	unsigned char *der = NULL;
	uc_value_t *digest;
	int n, ok;

	if (!identity(id) || !key)
		return 0;
	n = i2d_PUBKEY(key, &der);
	digest = n > 0 ? hex_digest(der, (size_t)n) : NULL;
	ok = digest && !strncmp(ucv_string_get(digest), id, 32);
	ucv_put(digest);
	OPENSSL_free(der);
	return ok;
}

static uc_value_t *hash(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *v = uc_fn_arg(0);
	return ucv_type(v) == UC_STRING ? hex_digest((const unsigned char *)ucv_string_get(v), ucv_string_length(v)) : NULL;
}

static uc_value_t *hmac(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *key = uc_fn_arg(0), *data = uc_fn_arg(1);
	unsigned char digest[EVP_MAX_MD_SIZE];
	unsigned int len = 0;
	char hex[65];
	if (ucv_type(key) != UC_STRING || ucv_string_length(key) != 64 ||
	    ucv_type(data) != UC_STRING || ucv_string_length(data) > 4 * 1024 * 1024)
		return NULL;
	if (!HMAC(EVP_sha256(), ucv_string_get(key), 64,
	          (const unsigned char *)ucv_string_get(data), ucv_string_length(data), digest, &len) || len != 32)
		return NULL;
	for (size_t i = 0; i < 32; i++)
		snprintf(hex + i * 2, 3, "%02x", digest[i]);
	OPENSSL_cleanse(digest, sizeof(digest));
	return ucv_string_new(hex);
}

static uc_value_t *constant_equal(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *a = uc_fn_arg(0), *b = uc_fn_arg(1);
	if (ucv_type(a) != UC_STRING || ucv_type(b) != UC_STRING || ucv_string_length(a) != ucv_string_length(b))
		return ucv_boolean_new(false);
	return ucv_boolean_new(!CRYPTO_memcmp(ucv_string_get(a), ucv_string_get(b), ucv_string_length(a)));
}

static uc_value_t *keypair(uc_vm_t *vm, size_t nargs)
{
	(void)vm; (void)nargs;
	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
	EVP_PKEY *key = NULL;
	BIO *bio = BIO_new(BIO_s_mem());
	uc_value_t *result = NULL;
	if (ctx && bio && EVP_PKEY_keygen_init(ctx) == 1 && EVP_PKEY_keygen(ctx, &key) == 1 &&
	    PEM_write_bio_PrivateKey(bio, key, NULL, NULL, 0, NULL, NULL))
		result = bio_string(bio);
	EVP_PKEY_free(key);
	EVP_PKEY_CTX_free(ctx);
	BIO_free(bio);
	return result;
}

static uc_value_t *key_fingerprint(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *string_values[1];
	EVP_PKEY *key = read_key(string_arg(vm, nargs, 0, &string_values[0]));
	unsigned char *der = NULL;
	int n = key ? i2d_PUBKEY(key, &der) : -1;
	uc_value_t *result = n > 0 ? hex_digest(der, (size_t)n) : NULL;
	OPENSSL_free(der);
	EVP_PKEY_free(key);
	return result;
}

static uc_value_t *public_key(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *slots[1], *result = NULL;
	EVP_PKEY *key = read_key(string_arg(vm, nargs, 0, &slots[0]));
	BIO *bio = BIO_new(BIO_s_mem());
	if (key && bio && EVP_PKEY_base_id(key) == EVP_PKEY_ED25519 && PEM_write_bio_PUBKEY(bio, key))
		result = bio_string(bio);
	BIO_free(bio);
	EVP_PKEY_free(key);
	return result;
}

static int subject(X509_NAME *name, const char *id)
{
	return identity(id) && X509_NAME_add_entry_by_NID(name, NID_commonName, MBSTRING_ASC,
		(const unsigned char *)id, -1, -1, 0);
}

static int same_subject(X509_NAME *name, const char *id)
{
	char cn[33];
	return identity(id) && X509_NAME_entry_count(name) == 1 &&
		X509_NAME_get_text_by_NID(name, NID_commonName, cn, sizeof(cn)) == 32 && !strcmp(cn, id);
}

static uc_value_t *csr(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *string_values[2];
	const char *id = string_arg(vm, nargs, 1, &string_values[1]);
	EVP_PKEY *key = read_key(string_arg(vm, nargs, 0, &string_values[0]));
	X509_REQ *req = X509_REQ_new();
	BIO *bio = BIO_new(BIO_s_mem());
	uc_value_t *result = NULL;
	if (key && EVP_PKEY_base_id(key) == EVP_PKEY_ED25519 && key_identity(key, id) && req && bio &&
	    X509_REQ_set_version(req, 0) && subject(X509_REQ_get_subject_name(req), id) &&
	    X509_REQ_set_pubkey(req, key) && X509_REQ_sign(req, key, NULL) > 0 && PEM_write_bio_X509_REQ(bio, req))
		result = bio_string(bio);
	X509_REQ_free(req);
	EVP_PKEY_free(key);
	BIO_free(bio);
	return result;
}

static int serial(X509 *cert)
{
	unsigned char bytes[16];
	BIGNUM *number;
	int ok;
	if (RAND_bytes(bytes, sizeof(bytes)) != 1)
		return 0;
	bytes[0] &= 0x7f;
	bytes[0] |= 1;
	number = BN_bin2bn(bytes, sizeof(bytes), NULL);
	ok = number && BN_to_ASN1_INTEGER(number, X509_get_serialNumber(cert)) != NULL;
	BN_free(number);
	return ok;
}

static int extension(X509 *cert, X509 *issuer, int nid, const char *value)
{
	X509V3_CTX ctx;
	X509_EXTENSION *ext;
	X509V3_set_ctx(&ctx, issuer, cert, NULL, NULL, 0);
	ext = X509V3_EXT_conf_nid(NULL, &ctx, nid, (char *)value);
	int ok = ext && X509_add_ext(cert, ext, -1);
	X509_EXTENSION_free(ext);
	return ok;
}

static uc_value_t *ca(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *string_values[2];
	EVP_PKEY *key = read_key(string_arg(vm, nargs, 0, &string_values[0]));
	const char *id = string_arg(vm, nargs, 1, &string_values[1]);
	X509 *cert = X509_new();
	BIO *bio = BIO_new(BIO_s_mem());
	uc_value_t *result = NULL;
	char name[64];
	if (!identity(id)) goto done;
	snprintf(name, sizeof(name), "mesh-manager-network-%s", id);
	if (key && EVP_PKEY_base_id(key) == EVP_PKEY_ED25519 && cert && bio &&
	    X509_set_version(cert, 2) && serial(cert) &&
	    X509_gmtime_adj(X509_getm_notBefore(cert), -300) &&
	    X509_gmtime_adj(X509_getm_notAfter(cert), 86400L * 3650) &&
	    X509_NAME_add_entry_by_NID(X509_get_subject_name(cert), NID_commonName, MBSTRING_ASC,
		(const unsigned char *)name, -1, -1, 0) && X509_set_issuer_name(cert, X509_get_subject_name(cert)) &&
	    X509_set_pubkey(cert, key) && extension(cert, cert, NID_basic_constraints, "critical,CA:TRUE,pathlen:0") &&
	    extension(cert, cert, NID_key_usage, "critical,keyCertSign,cRLSign") &&
	    extension(cert, cert, NID_subject_key_identifier, "hash") &&
	    X509_sign(cert, key, NULL) > 0 && PEM_write_bio_X509(bio, cert))
		result = bio_string(bio);
done:
	X509_free(cert);
	EVP_PKEY_free(key);
	BIO_free(bio);
	return result;
}

static int leaf_times(X509 *cert, X509 *issuer, long days)
{
	/* Issuance never extends beyond the issuer or revives an expired CA. */
	if (X509_cmp_current_time(X509_get0_notBefore(issuer)) > 0 ||
	    X509_cmp_current_time(X509_get0_notAfter(issuer)) <= 0 ||
	    !X509_gmtime_adj(X509_getm_notBefore(cert), -300) ||
	    !X509_gmtime_adj(X509_getm_notAfter(cert), 86400L * days))
		return 0;
	if (ASN1_TIME_compare(X509_get0_notBefore(cert), X509_get0_notBefore(issuer)) < 0 &&
	    !X509_set1_notBefore(cert, X509_get0_notBefore(issuer)))
		return 0;
	if (ASN1_TIME_compare(X509_get0_notAfter(cert), X509_get0_notAfter(issuer)) > 0 &&
	    !X509_set1_notAfter(cert, X509_get0_notAfter(issuer)))
		return 0;
	return 1;
}

static uc_value_t *sign(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *duration = uc_fn_arg(4);
	int64_t days = nargs < 5 ? 365 : ucv_type(duration) == UC_INTEGER ? ucv_int64_get(duration) : 0;
	if (days < 1 || days > 365) return NULL;
	uc_value_t *string_values[4];
	EVP_PKEY *key = read_key(string_arg(vm, nargs, 0, &string_values[0]));
	X509 *issuer = read_cert(string_arg(vm, nargs, 1, &string_values[1])), *cert = X509_new();
	const char *request = string_arg(vm, nargs, 2, &string_values[2]), *id = string_arg(vm, nargs, 3, &string_values[3]);
	BIO *in = request ? BIO_new_mem_buf(request, (int)strlen(request)) : NULL;
	X509_REQ *req = in ? PEM_read_bio_X509_REQ(in, NULL, NULL, NULL) : NULL;
	EVP_PKEY *pub = req ? X509_REQ_get_pubkey(req) : NULL;
	BIO *out = BIO_new(BIO_s_mem());
	uc_value_t *result = NULL;
	/* Discard every CSR extension; only this restricted leaf profile is signed. */
	if (key && issuer && cert && pub && out && X509_check_ca(issuer) > 0 &&
	    X509_check_private_key(issuer, key) == 1 && EVP_PKEY_base_id(pub) == EVP_PKEY_ED25519 &&
	    same_subject(X509_REQ_get_subject_name(req), id) && key_identity(pub, id) && X509_REQ_verify(req, pub) == 1 &&
	    X509_set_version(cert, 2) && serial(cert) &&
	    leaf_times(cert, issuer, days) &&
	    X509_set_subject_name(cert, X509_REQ_get_subject_name(req)) &&
	    X509_set_issuer_name(cert, X509_get_subject_name(issuer)) && X509_set_pubkey(cert, pub) &&
	    extension(cert, issuer, NID_basic_constraints, "critical,CA:FALSE") &&
	    extension(cert, issuer, NID_key_usage, "critical,digitalSignature") &&
	    extension(cert, issuer, NID_ext_key_usage, "clientAuth,serverAuth") &&
	    extension(cert, issuer, NID_subject_key_identifier, "hash") &&
	    extension(cert, issuer, NID_authority_key_identifier, "keyid:always") &&
	    X509_sign(cert, key, NULL) > 0 && PEM_write_bio_X509(out, cert))
		result = bio_string(out);
	BIO_free(in);
	BIO_free(out);
	EVP_PKEY_free(pub);
	EVP_PKEY_free(key);
	X509_REQ_free(req);
	X509_free(issuer);
	X509_free(cert);
	return result;
}

static uc_value_t *verify_leaf(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *string_values[4];
	const char *trust = string_arg(vm, nargs, 0, &string_values[0]);
	X509 *issuer = read_cert(trust), *leaf = read_cert(string_arg(vm, nargs, 1, &string_values[1]));
	EVP_PKEY *key = read_key(string_arg(vm, nargs, 2, &string_values[2]));
	const char *id = string_arg(vm, nargs, 3, &string_values[3]);
	X509_STORE *store = X509_STORE_new();
	X509_STORE_CTX *ctx = X509_STORE_CTX_new();
	int ok = issuer && leaf && key && store && ctx && X509_check_ca(issuer) > 0 &&
		X509_check_ca(leaf) == 0 && same_subject(X509_get_subject_name(leaf), id) &&
		X509_check_private_key(leaf, key) == 1 && trust_store(store, trust) &&
		X509_STORE_CTX_init(ctx, store, leaf, NULL) == 1 && X509_verify_cert(ctx) == 1;
	X509_STORE_CTX_free(ctx);
	X509_STORE_free(store);
	X509_free(issuer);
	X509_free(leaf);
	EVP_PKEY_free(key);
	return ucv_boolean_new(ok);
}

static uc_value_t *fingerprint(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *string_values[1];
	X509 *cert = read_cert(string_arg(vm, nargs, 0, &string_values[0]));
	unsigned char *der = NULL;
	int n = cert ? i2d_X509(cert, &der) : -1;
	uc_value_t *result = n > 0 ? hex_digest(der, (size_t)n) : NULL;
	OPENSSL_free(der);
	X509_free(cert);
	return result;
}

static uc_value_t *certificate_key_fingerprint(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *string_values[1];
	X509 *cert = read_cert(string_arg(vm, nargs, 0, &string_values[0]));
	EVP_PKEY *key = cert ? X509_get_pubkey(cert) : NULL;
	unsigned char *der = NULL;
	int n = key ? i2d_PUBKEY(key, &der) : -1;
	uc_value_t *result = n > 0 ? hex_digest(der, (size_t)n) : NULL;
	OPENSSL_free(der);
	EVP_PKEY_free(key);
	X509_free(cert);
	return result;
}

static uc_value_t *normalize_cert(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *string_values[1];
	X509 *cert = read_cert(string_arg(vm, nargs, 0, &string_values[0]));
	BIO *bio = BIO_new(BIO_s_mem());
	uc_value_t *result = cert && bio && PEM_write_bio_X509(bio, cert) ? bio_string(bio) : NULL;
	X509_free(cert);
	BIO_free(bio);
	return result;
}

/* Configuration signatures are deliberately separate from CSR issuance. */
static int signing_leaf(X509 *cert, const char *id)
{
	EVP_PKEY *pub = cert ? X509_get_pubkey(cert) : NULL;
	int ok = pub && EVP_PKEY_base_id(pub) == EVP_PKEY_ED25519 &&
		X509_check_ca(cert) == 0 && same_subject(X509_get_subject_name(cert), id) &&
		key_identity(pub, id) && (X509_get_extension_flags(cert) & EXFLAG_KUSAGE) &&
		(X509_get_key_usage(cert) & KU_DIGITAL_SIGNATURE);
	EVP_PKEY_free(pub);
	return ok;
}

static uc_value_t *certificate_identity(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *string_values[1];
	X509 *cert = read_cert(string_arg(vm, nargs, 0, &string_values[0]));
	char id[33];
	uc_value_t *result = NULL;
	if (cert && X509_NAME_get_text_by_NID(X509_get_subject_name(cert), NID_commonName,
		id, sizeof(id)) == 32 && signing_leaf(cert, id))
		result = ucv_string_new(id);
	X509_free(cert);
	return result;
}

/* Read-only diagnostics. The supplied clock is never used by authentication. */
static uc_value_t *certificate_summary(uc_vm_t *vm, X509 *cert, const char *state, time_t clock)
{
	uc_value_t *out = ucv_object_new(vm);
	int64_t expires = -1;
	struct tm end;
	if (cert && ASN1_TIME_to_tm(X509_get0_notAfter(cert), &end) == 1)
		expires = (int64_t)timegm(&end);
	ucv_object_add(out, "status", ucv_string_new(state));
	ucv_object_add(out, "expires_at", expires >= 0 ? ucv_int64_new(expires) : NULL);
	ucv_object_add(out, "remaining_days", expires >= 0 ? ucv_int64_new(expires <= clock ? 0 : (expires - clock) / 86400) : NULL);
	return out;
}

static const char *certificate_time(X509 *cert, const ASN1_TIME *clock)
{
	int starts = ASN1_TIME_compare(X509_get0_notBefore(cert), clock);
	int ends = ASN1_TIME_compare(X509_get0_notAfter(cert), clock);
	int days, seconds;
	if (starts == -2 || ends == -2 || !ASN1_TIME_diff(&days, &seconds, clock, X509_get0_notAfter(cert)))
		return "invalid";
	if (starts > 0) return "not_yet_valid";
	if (ends <= 0) return "expired";
	return days < 30 || (days == 30 && seconds == 0) ? "expiring" : "valid";
}

static uc_value_t *certificate_status(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *out = ucv_object_new(vm), *wall = uc_fn_arg(3);
	int64_t clock = ucv_type(wall) == UC_INTEGER ? ucv_int64_get(wall) : 0;
	/* Reject unset or unrepresentable time, including 32-bit time_t overflow. */
	if (clock < 1704067200 || clock > 4102444800LL || (int64_t)(time_t)clock != clock) {
		ucv_object_add(out, "ca", certificate_summary(vm, NULL, "clock_invalid", 0));
		ucv_object_add(out, "device", certificate_summary(vm, NULL, "clock_invalid", 0));
		return out;
	}
	uc_value_t *string_values[3];
	const char *ca_pem = string_arg(vm, nargs, 0, &string_values[0]), *leaf_pem = string_arg(vm, nargs, 1, &string_values[1]);
	const char *id = string_arg(vm, nargs, 2, &string_values[2]);
	X509 *issuer = read_cert(ca_pem), *leaf = read_cert(leaf_pem);
	EVP_PKEY *ca_pub = issuer ? X509_get_pubkey(issuer) : NULL;
	ASN1_TIME *at = ASN1_TIME_set(NULL, (time_t)clock);
	X509_STORE *store = X509_STORE_new();
	X509_STORE_CTX *chain = X509_STORE_CTX_new();
	const char *ca_state = issuer ? "invalid" : ucv_type(uc_fn_arg(0)) == UC_NULL ? "missing" : "invalid";
	const char *leaf_state = leaf ? "invalid" : ucv_type(uc_fn_arg(1)) == UC_NULL ? "missing" : "invalid";
	int ca_ok = issuer && ca_pub && at && EVP_PKEY_base_id(ca_pub) == EVP_PKEY_ED25519 &&
		X509_check_ca(issuer) > 0 && (X509_get_extension_flags(issuer) & EXFLAG_KUSAGE) &&
		(X509_get_key_usage(issuer) & KU_KEY_CERT_SIGN) &&
		X509_NAME_cmp(X509_get_subject_name(issuer), X509_get_issuer_name(issuer)) == 0 &&
		X509_verify(issuer, ca_pub) == 1;
	if (ca_ok) ca_state = certificate_time(issuer, at);
	if (leaf && at) {
		if (!signing_leaf(leaf, id)) leaf_state = "identity_mismatch";
		else if (X509_check_purpose(leaf, X509_PURPOSE_SSL_CLIENT, 0) != 1 ||
		         X509_check_purpose(leaf, X509_PURPOSE_SSL_SERVER, 0) != 1) leaf_state = "invalid";
		else if (!ca_ok || !store || !chain || !trust_store(store, ca_pem) ||
		         X509_STORE_CTX_init(chain, store, leaf, NULL) != 1) leaf_state = "untrusted";
		else {
			/* First verify signatures/constraints; classify dates explicitly afterwards. */
			X509_VERIFY_PARAM_set_flags(X509_STORE_CTX_get0_param(chain), X509_V_FLAG_NO_CHECK_TIME);
			if (X509_verify_cert(chain) != 1) leaf_state = "untrusted";
			else if (strcmp(ca_state, "valid") && strcmp(ca_state, "expiring")) leaf_state = "untrusted";
			else {
				STACK_OF(X509) *verified = X509_STORE_CTX_get0_chain(chain);
				X509 *anchor = verified ? sk_X509_value(verified, sk_X509_num(verified) - 1) : NULL;
				const char *state = anchor ? certificate_time(anchor, at) : "invalid";
				leaf_state = !strcmp(state, "valid") || !strcmp(state, "expiring") ?
					certificate_time(leaf, at) : "untrusted";
			}
		}
	}
	ucv_object_add(out, "ca", certificate_summary(vm, issuer, ca_state, (time_t)clock));
	ucv_object_add(out, "device", certificate_summary(vm, leaf, leaf_state, (time_t)clock));
	X509_STORE_CTX_free(chain);
	X509_STORE_free(store);
	ASN1_TIME_free(at);
	EVP_PKEY_free(ca_pub);
	X509_free(issuer);
	X509_free(leaf);
	return out;
}

static int message_value(uc_value_t *v)
{
	return ucv_type(v) == UC_STRING && ucv_string_length(v) > 0 &&
		ucv_string_length(v) <= 65536;
}

static uc_value_t *message_sign(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *data = uc_fn_arg(1), *result = NULL;
	if (!message_value(data)) return NULL;
	uc_value_t *string_values[1];
	EVP_PKEY *key = read_key(string_arg(vm, nargs, 0, &string_values[0]));
	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	unsigned char signature[64];
	size_t len = sizeof(signature);
	char hex[129];
	if (key && ctx && EVP_PKEY_base_id(key) == EVP_PKEY_ED25519 &&
		EVP_DigestSignInit(ctx, NULL, NULL, NULL, key) == 1 &&
		EVP_DigestSign(ctx, signature, &len, (const unsigned char *)ucv_string_get(data),
			ucv_string_length(data)) == 1 && len == sizeof(signature)) {
		for (size_t i = 0; i < len; i++) snprintf(hex + 2 * i, 3, "%02x", signature[i]);
		result = ucv_string_new(hex);
	}
	EVP_MD_CTX_free(ctx);
	EVP_PKEY_free(key);
	return result;
}

static int hex_nibble(char c)
{
	return c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : -1;
}

static int verify_message(EVP_PKEY *key, uc_value_t *data, const char *signature)
{
	unsigned char bytes[64];
	if (!key || EVP_PKEY_base_id(key) != EVP_PKEY_ED25519 || !message_value(data) ||
	    !signature || strlen(signature) != 128) return 0;
	for (size_t i = 0; i < sizeof(bytes); i++) {
		int a = hex_nibble(signature[i * 2]), b = hex_nibble(signature[i * 2 + 1]);
		if (a < 0 || b < 0) return 0;
		bytes[i] = (unsigned char)((a << 4) | b);
	}
	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	int ok = ctx && EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, key) == 1 &&
		EVP_DigestVerify(ctx, bytes, sizeof(bytes), (const unsigned char *)ucv_string_get(data),
			ucv_string_length(data)) == 1;
	EVP_MD_CTX_free(ctx);
	return ok;
}

static uc_value_t *message_verify_key(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *slots[2];
	const char *pem = string_arg(vm, nargs, 0, &slots[0]), *signature = string_arg(vm, nargs, 2, &slots[1]);
	BIO *bio = pem ? BIO_new_mem_buf(pem, (int)strlen(pem)) : NULL;
	EVP_PKEY *key = bio ? PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL) : NULL;
	int ok = verify_message(key, uc_fn_arg(1), signature);
	EVP_PKEY_free(key);
	BIO_free(bio);
	return ucv_boolean_new(ok);
}

static uc_value_t *message_verify_time(uc_vm_t *vm, size_t nargs, bool explicit_time)
{
	int64_t wall = 0;
	if (explicit_time) {
		uc_value_t *at = uc_fn_arg(5);
		if (nargs != 6 || ucv_type(at) != UC_INTEGER)
			return ucv_boolean_new(false);
		wall = ucv_int64_get(at);
		if (wall < 1704067200 || wall > 4102444800 || (int64_t)(time_t)wall != wall)
			return ucv_boolean_new(false);
	}
	uc_value_t *data = uc_fn_arg(3);
	uc_value_t *string_values[5];
	const char *signature = string_arg(vm, nargs, 4, &string_values[4]);
	if (!message_value(data) || !signature || strlen(signature) != 128)
		return ucv_boolean_new(false);
	const char *trust = string_arg(vm, nargs, 0, &string_values[0]);
	X509 *issuer = read_cert(trust), *leaf = read_cert(string_arg(vm, nargs, 1, &string_values[1]));
	const char *id = string_arg(vm, nargs, 2, &string_values[2]);
	X509_STORE *store = X509_STORE_new();
	X509_STORE_CTX *chain = X509_STORE_CTX_new();
	EVP_PKEY *pub = leaf ? X509_get_pubkey(leaf) : NULL;
	int ok = issuer && leaf && store && chain && pub && X509_check_ca(issuer) > 0 &&
		signing_leaf(leaf, id) && trust_store(store, trust) &&
		X509_STORE_CTX_init(chain, store, leaf, NULL) == 1;
	/* Bootstrap verifies a fresh signed controller time. Dates remain checked
	 * at that exact time; ordinary message and TLS validation use system time. */
	if (ok && explicit_time)
		X509_VERIFY_PARAM_set_time(X509_STORE_CTX_get0_param(chain), (time_t)wall);
	ok = ok && X509_verify_cert(chain) == 1 && verify_message(pub, data, signature);
	EVP_PKEY_free(pub);
	X509_STORE_CTX_free(chain);
	X509_STORE_free(store);
	X509_free(issuer);
	X509_free(leaf);
	return ucv_boolean_new(ok);
}

static uc_value_t *message_verify(uc_vm_t *vm, size_t nargs)
{
	return message_verify_time(vm, nargs, false);
}

static uc_value_t *message_verify_at(uc_vm_t *vm, size_t nargs)
{
	return message_verify_time(vm, nargs, true);
}

static const uc_function_list_t functions[] = {
	{ "identifier", identifier },
	{ "sha256", hash }, { "hmac", hmac }, { "constant_equal", constant_equal }, { "keypair", keypair },
	{ "key_fingerprint", key_fingerprint }, { "csr", csr }, { "ca", ca },
	{ "public_key", public_key }, { "message_verify_key", message_verify_key },
	{ "sign", sign }, { "verify_leaf", verify_leaf }, { "fingerprint", fingerprint },
	{ "certificate_key_fingerprint", certificate_key_fingerprint },
	{ "normalize_cert", normalize_cert }, { "certificate_identity", certificate_identity },
	{ "certificate_status", certificate_status },
	{ "message_sign", message_sign }, { "message_verify", message_verify },
	{ "message_verify_at", message_verify_at }
};

void uc_module_init(uc_vm_t *vm, uc_value_t *scope)
{
	(void)vm;
	uc_function_list_register(scope, functions);
}
