#include <assert.h>
#include <bitcoin/privkey.h>
#include <bitcoin/pubkey.h>
#include <ccan/array_size/array_size.h>
#include <common/podle.h>
#include <common/utils.h>
#include <secp256k1.h>
#include <sodium/randombytes.h>
#include <stdio.h>

/* e = [ kG || kJ || P || P2 ], all of which
 * are of size PUBKEY_CMPR_LEN */
#define E_MEMBERS 4
#define E_LEN E_MEMBERS * PUBKEY_CMPR_LEN

static bool init_G(struct pubkey *G)
{
	/* G's seed is the scalar value 'one' */
	unsigned char g_priv[32] = {0};
	g_priv[31]++;

	/* Convert the scalar 'one' into a point value, G */
	if (!secp256k1_ec_pubkey_create(secp256k1_ctx, &G->pubkey, g_priv))
		return false;

	return true;
}

#ifdef SUPERVERBOSE
static void print_arr(unsigned char *arr, size_t len)
{
	size_t j;
	for (j = 0; j < len; j++)
		fprintf(stderr, "%02x", ((u8 *)arr)[j]);
	fprintf(stderr, "\n");
}
#endif

/* Assumes that pubkeys are packed in correct order (kG, kJ, P, P2) */
static bool pack_e(unsigned char *e_arr, size_t e_len, struct pubkey **pubkeys, size_t pk_len)
{
	unsigned char compressed[PUBKEY_CMPR_LEN];
	size_t clen = sizeof(compressed), i;

	assert(e_len == pk_len * PUBKEY_CMPR_LEN);

	for (i = 0; i < pk_len; i++) {
		if (!secp256k1_ec_pubkey_serialize(secp256k1_ctx, compressed,
						   &clen, &pubkeys[i]->pubkey,
						   SECP256K1_EC_COMPRESSED))
			return false;

#ifdef SUPERVERBOSE
		print_arr(compressed, clen);
#endif
		memcpy(e_arr + PUBKEY_CMPR_LEN * i, compressed, clen);
	}

	return true;
}

static bool find_NUM(unsigned char *arr, size_t arr_len, struct pubkey *nums_key)
{
	struct sha256 sha;
	u16 i;

	/* Placeholder for sha-result + compression marker */
	unsigned char cmp_key[PUBKEY_CMPR_LEN];
	size_t len = sizeof(cmp_key);

	/* Set the first bit to 0x02, denoting positive compressed
	 * pubkey serialization */
	((u8 *)cmp_key)[0] = 2;

	for (i = 0; i < 256; i++) {
		arr[arr_len - 1] = i;
		sha256(&sha, arr, arr_len);
		memcpy(cmp_key + 1, &sha.u.u8, sizeof(sha.u.u8));
		/* Attempt to co-erce to pubkey (positive) */
		if (secp256k1_ec_pubkey_parse(secp256k1_ctx, &nums_key->pubkey,
					       cmp_key, len))
			return true;
	}

	return false;
}

bool derive_NUMS_point_at(u8 index, struct pubkey *nums_key)
{
	struct pubkey G;

	/* G (compressed/uncompressed) + 1-byte index + 1-byte counter */
	unsigned char seed_cmp_g[PUBKEY_CMPR_LEN + 2];
	unsigned char seed_uncmp_g[65 + 2];
	size_t c_len = sizeof(seed_cmp_g), uc_len = sizeof(seed_uncmp_g), outlen;

	if (!init_G(&G))
		return false;

	/* Pull out the compressed serializiation of G */
	outlen = c_len - 2;
	if (!secp256k1_ec_pubkey_serialize(secp256k1_ctx, seed_cmp_g,
					   &outlen, &G.pubkey, SECP256K1_EC_COMPRESSED))
		return false;
	/* We add the index into the hash */
	seed_cmp_g[c_len - 2] = index;
	if (find_NUM(seed_cmp_g, c_len, nums_key))
		return true;

	/* We failed to find a valid pubkey with the compressed G pubkey hash, now we
	 * try again but using the uncompressed serializiation of G as the sha base */
	outlen = uc_len - 2;
	if (!secp256k1_ec_pubkey_serialize(secp256k1_ctx, seed_uncmp_g,
					   &outlen, &G.pubkey, SECP256K1_EC_UNCOMPRESSED))
		return false;
	seed_uncmp_g[uc_len - 2] = index;
	return find_NUM(seed_cmp_g, uc_len, nums_key);
}

bool generate_proof_of_dle(struct privkey *x, struct pubkey *j,
			   struct proof_dle *podle)
{
	/* A proof of discrete log equivalence requires:
	 *  - a private key, x
	 *  - a second generator point, j
	 *  - a nonce, k (generated herein)
	 *
	 *  With these, we calculate
	 *  - the point k*G and k*J
	 *  - the point 'P2', x*J
	 *  - the point 'P', x*G
	 *  - the commitment, sha256(P2)
	 *  - e, sha256(kG || kJ || P || P2 ), and finally
	 *  - the signature, k + x * e
	 */
	struct pubkey kG, p, kJ, p2, * pubkeys[E_MEMBERS];
	unsigned char compressed[PUBKEY_CMPR_LEN];
	unsigned char e_arr[E_LEN];
	size_t clen = sizeof(compressed), pk_len = ARRAY_SIZE(pubkeys),
	       elen = sizeof(e_arr);

	/* Init our nonce `k` */
	u8 k[32];
	randombytes_buf(k, sizeof(k));

	kJ = *j;
	p2 = *j;

	/* First we find kG, kJ, p + p2 */
	if (!secp256k1_ec_pubkey_create(secp256k1_ctx, &kG.pubkey, k))
		return false;

	if (!secp256k1_ec_pubkey_tweak_mul(secp256k1_ctx, &kJ.pubkey, k))
		return false;

	if (!secp256k1_ec_pubkey_create(secp256k1_ctx, &p.pubkey, x->secret.data))
		return false;

	if (!secp256k1_ec_pubkey_tweak_mul(secp256k1_ctx, &p2.pubkey, x->secret.data))
		return false;

	/* Serialize the pubkeys (compressed) and pack into e's preimage */
	pubkeys[0] = &kG;
	pubkeys[1] = &kJ;
	pubkeys[2] = &p;
	pubkeys[3] = &p2;
	if (!pack_e(e_arr, elen, pubkeys, pk_len))
		return false;

	/* Compute the commitment */
	if (!secp256k1_ec_pubkey_serialize(secp256k1_ctx, compressed,
					   &clen, &p2.pubkey,
					   SECP256K1_EC_COMPRESSED))
		return false;

	sha256(&podle->commitment, compressed, clen);

	/* Compute e */
	sha256(&podle->e, e_arr, elen);
	memcpy(&podle->sig, podle->e.u.u8, sizeof(podle->e.u.u8));

	/* Compute the signature */
	if (!secp256k1_ec_privkey_tweak_mul(secp256k1_ctx, podle->sig, x->secret.data)) {
		// Is it weird to release the object here? I don't want to
		// 'return' a half-filled in object
		podle = tal_free(podle);
		return false;
	}

	if (!secp256k1_ec_privkey_tweak_add(secp256k1_ctx, podle->sig, k)) {
		podle = tal_free(podle);
		return false;
	}

	/* Fill in p2 for the result */
	podle->pk2 = p2;

	return true;
}

bool verify_proof_of_dle(struct pubkey *p, struct pubkey *j, struct proof_dle *podle)
{
	/*
	 * From https://joinmarket.me/blog/blog/poodle/
	 *
	 * Given P, P2, s, e and the original commitment, verify:
	 *  - sha256(P2) is equal to the original commitment
	 *  - kG = sG - eP
	 *  - kJ = sJ - eP2
	 *  - sha256(kG || kJ || P || P2) == e
	 */
	struct sha256 sha;
	const secp256k1_pubkey *args[2];
	struct pubkey eP, eP2, sG, sJ, kG, kJ, * pubkeys[E_MEMBERS];
	unsigned char compressed[PUBKEY_CMPR_LEN], neg_e[32],
		      e_arr[E_LEN];
	size_t clen = sizeof(compressed), elen = sizeof(e_arr),
	       pk_len = ARRAY_SIZE(pubkeys);

	sJ = *j;
	eP = *p;
	eP2 = podle->pk2;

	/* First, we verify that the sha256 of p2 is equivalent */
	if (!secp256k1_ec_pubkey_serialize(secp256k1_ctx, compressed,
					   &clen, &podle->pk2.pubkey,
					   SECP256K1_EC_COMPRESSED))
		return false;

	sha256(&sha, compressed, clen);
	if (!sha256_eq(&sha, &podle->commitment))
		return false;

	if (!init_G(&sG))
		return false;

	/* -e */
	memcpy(neg_e, podle->e.u.u8, sizeof(podle->e.u.u8));
	if (!secp256k1_ec_privkey_negate(secp256k1_ctx, neg_e))
		return false;

	/* sG */
	if (!secp256k1_ec_pubkey_tweak_mul(secp256k1_ctx, &sG.pubkey, podle->sig))
		return false;

	/* -eP */
	if (!secp256k1_ec_pubkey_tweak_mul(secp256k1_ctx, &eP.pubkey, neg_e))
		return false;

	/* kG = sG - eP */
	args[0] = &sG.pubkey;
	args[1] = &eP.pubkey;
	if (!secp256k1_ec_pubkey_combine(secp256k1_ctx, &kG.pubkey, args, 2))
		return false;

	/* sJ */
	if (!secp256k1_ec_pubkey_tweak_mul(secp256k1_ctx, &sJ.pubkey, podle->sig))
		return false;

	/* -eP2 */
	if (!secp256k1_ec_pubkey_tweak_mul(secp256k1_ctx, &eP2.pubkey, neg_e))
		return false;

	/* kJ = sJ - eP2 */
	args[0] = &sJ.pubkey;
	args[1] = &eP2.pubkey;
	if (!secp256k1_ec_pubkey_combine(secp256k1_ctx, &kJ.pubkey, args, 2))
		return false;

	/* Find 'e' */
	pubkeys[0] = &kG;
	pubkeys[1] = &kJ;
	pubkeys[2] = p;
	pubkeys[3] = &podle->pk2;
	if (!pack_e(e_arr, elen, pubkeys, pk_len))
		return false;
	sha256(&sha, e_arr, elen);

	/* Return comparison result */
	return sha256_eq(&sha, &podle->e);
}
