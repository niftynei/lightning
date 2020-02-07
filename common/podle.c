#include <bitcoin/privkey.h>
#include <bitcoin/pubkey.h>
#include <ccan/array_size/array_size.h>
#include <ccan/crypto/sha256/sha256.h>
#include <common/podle.h>
#include <common/utils.h>
#include <stdio.h>

static bool find_NUM(unsigned char *arr, size_t arr_len, struct pubkey *nums_key)
{
	struct sha256 sha;
	u16 i;

	/* Placeholder for sha-result + compression marker */
	unsigned char cmp_key[PUBKEY_CMPR_LEN];
	size_t len = ARRAY_SIZE(cmp_key);
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
	size_t c_len = ARRAY_SIZE(seed_cmp_g), uc_len = ARRAY_SIZE(seed_uncmp_g), outlen;

	/* G seed (the first!) */
	unsigned char g_priv[32] = {0};
	g_priv[31]++;

	/* First we need to get the G point */
	if (!secp256k1_ec_pubkey_create(secp256k1_ctx, &G.pubkey, g_priv))
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
