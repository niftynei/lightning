#include <assert.h>
#include <bitcoin/address.h>
#include <bitcoin/base58.h>
#include <bitcoin/privkey.h>
#include <bitcoin/pubkey.h>
#include <ccan/str/hex/hex.h>
#include <common/type_to_string.h>
#include <common/utils.h>
#include <inttypes.h>
#include <stdio.h>
#include "../amount.c"
#define SUPERVERBOSE printf
#include "../funding_tx.c"
#undef SUPERVERBOSE
#include "../key_derive.c"
#include "../type_to_string.c"
#include "../permute_tx.c"
#include "../utxo.c"

/* AUTOGENERATED MOCKS START */
/* Generated stub for fromwire_amount_sat */
struct amount_sat fromwire_amount_sat(const u8 **cursor UNNEEDED, size_t *max UNNEEDED)
{ fprintf(stderr, "fromwire_amount_sat called!\n"); abort(); }
/* Generated stub for fromwire_bitcoin_txid */
void fromwire_bitcoin_txid(const u8 **cursor UNNEEDED, size_t *max UNNEEDED,
			   struct bitcoin_txid *txid UNNEEDED)
{ fprintf(stderr, "fromwire_bitcoin_txid called!\n"); abort(); }
/* Generated stub for fromwire_bool */
bool fromwire_bool(const u8 **cursor UNNEEDED, size_t *max UNNEEDED)
{ fprintf(stderr, "fromwire_bool called!\n"); abort(); }
/* Generated stub for fromwire_fail */
const void *fromwire_fail(const u8 **cursor UNNEEDED, size_t *max UNNEEDED)
{ fprintf(stderr, "fromwire_fail called!\n"); abort(); }
/* Generated stub for fromwire_node_id */
void fromwire_node_id(const u8 **cursor UNNEEDED, size_t *max UNNEEDED, struct node_id *id UNNEEDED)
{ fprintf(stderr, "fromwire_node_id called!\n"); abort(); }
/* Generated stub for fromwire_pubkey */
void fromwire_pubkey(const u8 **cursor UNNEEDED, size_t *max UNNEEDED, struct pubkey *pubkey UNNEEDED)
{ fprintf(stderr, "fromwire_pubkey called!\n"); abort(); }
/* Generated stub for fromwire_u16 */
u16 fromwire_u16(const u8 **cursor UNNEEDED, size_t *max UNNEEDED)
{ fprintf(stderr, "fromwire_u16 called!\n"); abort(); }
/* Generated stub for fromwire_u32 */
u32 fromwire_u32(const u8 **cursor UNNEEDED, size_t *max UNNEEDED)
{ fprintf(stderr, "fromwire_u32 called!\n"); abort(); }
/* Generated stub for fromwire_u64 */
u64 fromwire_u64(const u8 **cursor UNNEEDED, size_t *max UNNEEDED)
{ fprintf(stderr, "fromwire_u64 called!\n"); abort(); }
/* Generated stub for fromwire_u8_array */
void fromwire_u8_array(const u8 **cursor UNNEEDED, size_t *max UNNEEDED, u8 *arr UNNEEDED, size_t num UNNEEDED)
{ fprintf(stderr, "fromwire_u8_array called!\n"); abort(); }
/* Generated stub for towire_amount_sat */
void towire_amount_sat(u8 **pptr UNNEEDED, const struct amount_sat sat UNNEEDED)
{ fprintf(stderr, "towire_amount_sat called!\n"); abort(); }
/* Generated stub for towire_bitcoin_txid */
void towire_bitcoin_txid(u8 **pptr UNNEEDED, const struct bitcoin_txid *txid UNNEEDED)
{ fprintf(stderr, "towire_bitcoin_txid called!\n"); abort(); }
/* Generated stub for towire_bool */
void towire_bool(u8 **pptr UNNEEDED, bool v UNNEEDED)
{ fprintf(stderr, "towire_bool called!\n"); abort(); }
/* Generated stub for towire_node_id */
void towire_node_id(u8 **pptr UNNEEDED, const struct node_id *id UNNEEDED)
{ fprintf(stderr, "towire_node_id called!\n"); abort(); }
/* Generated stub for towire_pubkey */
void towire_pubkey(u8 **pptr UNNEEDED, const struct pubkey *pubkey UNNEEDED)
{ fprintf(stderr, "towire_pubkey called!\n"); abort(); }
/* Generated stub for towire_u16 */
void towire_u16(u8 **pptr UNNEEDED, u16 v UNNEEDED)
{ fprintf(stderr, "towire_u16 called!\n"); abort(); }
/* Generated stub for towire_u32 */
void towire_u32(u8 **pptr UNNEEDED, u32 v UNNEEDED)
{ fprintf(stderr, "towire_u32 called!\n"); abort(); }
/* Generated stub for towire_u64 */
void towire_u64(u8 **pptr UNNEEDED, u64 v UNNEEDED)
{ fprintf(stderr, "towire_u64 called!\n"); abort(); }
/* Generated stub for towire_u8_array */
void towire_u8_array(u8 **pptr UNNEEDED, const u8 *arr UNNEEDED, size_t num UNNEEDED)
{ fprintf(stderr, "towire_u8_array called!\n"); abort(); }
/* AUTOGENERATED MOCKS END */

struct test_case {
	struct input_info **opener_inputs;
	struct input_info **accepter_inputs;
	struct output_info **opener_outputs;
	struct output_info **accepter_outputs;
	struct amount_sat opener_funding;
	struct amount_sat accepter_funding;
	struct amount_sat expected_funding;
	struct bitcoin_tx *expected_tx;
	char *local_pubkey_str;
	char *remote_pubkey_str;
	u32 feerate;
};

#if EXPERIMENTAL_FEATURES
static u8 *hex_to_u8(const tal_t *ctx, char *str)
{
	return tal_hexdata(ctx, str, strlen(str));
}

/* Test case from the 03 Appendix F, in the RFC */
/* FIXME: add bolt reference for this */
static struct test_case test1(const tal_t *ctx)
{
	struct bitcoin_txid txid;
	bitcoin_txid_from_hex("4303ca8ff10c6c345b9299672a66f111c5b81ae027cc5b0d4d39d09c66b032b9",
			      strlen("4303ca8ff10c6c345b9299672a66f111c5b81ae027cc5b0d4d39d09c66b032b9"),
			      &txid);

	struct input_info **opener_inputs = tal_arr(ctx, struct input_info *, 2);
	struct input_info *input_one = tal(ctx, struct input_info);
	input_one->input_satoshis = AMOUNT_SAT(250000000);
	input_one->prevtx_txid = txid;
	input_one->prevtx_vout = 0;
	input_one->prevtx_scriptpubkey = hex_to_u8(ctx, "220020fd89acf65485df89797d9ba7ba7a33624ac4452f00db08107f34257d33e5b946");
	input_one->max_witness_len = 75;
	input_one->script = NULL;
	opener_inputs[0] = input_one;

	struct input_info *input_two = tal(ctx, struct input_info);
	input_two->input_satoshis = AMOUNT_SAT(250000000);
	input_two->prevtx_txid = txid;
	input_two->prevtx_vout = 1;
	input_two->prevtx_scriptpubkey = hex_to_u8(ctx, "a9146a235d064786b49e7043e4a042d4cc429f7eb69487");
	input_two->max_witness_len = 75;
	input_two->script = hex_to_u8(ctx, "220020fd89acf65485df89797d9ba7ba7a33624ac4452f00db08107f34257d33e5b946");
	opener_inputs[1] = input_two;

	struct input_info **accepter_inputs = tal_arr(ctx, struct input_info *, 2);
	struct input_info *input_three = tal(ctx, struct input_info);
	input_three->input_satoshis = AMOUNT_SAT(250000000);
	input_three->prevtx_txid = txid;
	input_three->prevtx_vout = 2;
	input_three->prevtx_scriptpubkey = hex_to_u8(ctx, "160014fbb4db9d85fba5e301f4399e3038928e44e37d32");
	input_three->max_witness_len = 109;
	input_three->script = NULL;
	accepter_inputs[0] = input_three;

	struct input_info *input_four = tal(ctx, struct input_info);
	input_four->input_satoshis = AMOUNT_SAT(250000000);
	input_four->prevtx_txid = txid;
	input_four->prevtx_vout = 3;
	input_four->prevtx_scriptpubkey = hex_to_u8(ctx, "a9147ecd1b519326bc13b0ec716e469b58ed02b112a087");
	input_four->max_witness_len = 109;
	input_four->script = hex_to_u8(ctx, "160014fbb4db9d85fba5e301f4399e3038928e44e37d32");
	accepter_inputs[1] = input_four;

	struct output_info **opener_outputs = tal_arr(ctx, struct output_info *, 1);
	struct output_info *output_one = tal(ctx, struct output_info);
	output_one->output_satoshis = AMOUNT_SAT(0);
	output_one->script = hex_to_u8(ctx, "00141ca1cca8855bad6bc1ea5436edd8cff10b7e448b");
	opener_outputs[0] = output_one;

	struct output_info **accepter_outputs = tal_arr(ctx, struct output_info *, 1);
	struct output_info *output_two = tal(ctx, struct output_info);
	output_two->output_satoshis = AMOUNT_SAT(200000000);
	output_two->script = hex_to_u8(ctx, "001444cb0c39f93ecc372b5851725bd29d865d333b10");
	accepter_outputs[0] = output_two;

	char *expected_tx_str = "0200000004b932b0669cd0394d0d5bcc27e01ab8c511f1662a6799925b346c0cf18fca03430000000000ffffffffb932b0669cd0394d0d5bcc27e01ab8c511f1662a6799925b346c0cf18fca03430100000023220020fd89acf65485df89797d9ba7ba7a33624ac4452f00db08107f34257d33e5b946ffffffffb932b0669cd0394d0d5bcc27e01ab8c511f1662a6799925b346c0cf18fca03430200000000ffffffffb932b0669cd0394d0d5bcc27e01ab8c511f1662a6799925b346c0cf18fca03430300000017160014fbb4db9d85fba5e301f4399e3038928e44e37d32ffffffff03ea7f0100000000001600141ca1cca8855bad6bc1ea5436edd8cff10b7e448b00c2eb0b0000000016001444cb0c39f93ecc372b5851725bd29d865d333b106081ad2f00000000220020297b92c238163e820b82486084634b4846b86a3c658d87b9384192e6bea98ec500000000";
	struct test_case test1 = {
	  .feerate = 1000,
	  .opener_inputs = opener_inputs,
	  .accepter_inputs = accepter_inputs,
	  .opener_outputs = opener_outputs,
	  .accepter_outputs = accepter_outputs,
	  .opener_funding = AMOUNT_SAT(499900000),
	  .accepter_funding = AMOUNT_SAT(300000000),
	  .expected_funding = AMOUNT_SAT(799900000),
	  .expected_tx = bitcoin_tx_from_hex(ctx, expected_tx_str, strlen(expected_tx_str)),
	  .remote_pubkey_str = "02e16172a41e928cbd78f761bd1c657c4afc7495a1244f7f30166b654fbf7661e3",
	  .local_pubkey_str = "0292edb5f7bbf9e900f7e024be1c1339c6d149c11930e613af3a983d2565f4e41e",
	};

	assert(test1.expected_tx);

	return test1;
}

/* The following inputs are build off of two prior transactions, depending
 * on how many inputs there are from the 'accepter' side */
const char* txid_str_one = "6c39988c96f100fbd1cc4ba47f73e3410922a9b41db07e80530a47fb71da053f";
const char* txid_str_two = "07f983eea2be59f6aada611475df69c11f5f95aac5a04ff769effbf24ae9e951";

static struct input_info *input_one(const tal_t *ctx, int vout, const char* txid_str)
{
	struct bitcoin_txid txid;
	bitcoin_txid_from_hex(txid_str, strlen(txid_str), &txid);
	struct input_info *input_one = tal(ctx, struct input_info);
	input_one->input_satoshis = AMOUNT_SAT(500000);
	input_one->prevtx_txid = txid;
	input_one->prevtx_vout = vout;
	input_one->prevtx_scriptpubkey = hex_to_u8(ctx, "0014ca5cc81df579bd589a428c0d29dceb81513fce8d");
	input_one->max_witness_len = 109;
	input_one->script = NULL;
	return input_one;
}

static struct input_info *input_two(const tal_t *ctx, const char *txid_str)
{
	struct bitcoin_txid txid;
	bitcoin_txid_from_hex(txid_str, strlen(txid_str), &txid);

	struct input_info *input_two = tal(ctx, struct input_info);
	input_two->input_satoshis = AMOUNT_SAT(1000000);
	input_two->prevtx_txid = txid;
	input_two->prevtx_vout = 0;
	input_two->prevtx_scriptpubkey = hex_to_u8(ctx, "001483440596268132e6c99d44dae2d151dabd9a2b23");
	input_two->max_witness_len = 109;
	input_two->script = NULL;
	return input_two;
}

static struct input_info *input_three(const tal_t *ctx, int vout, const char *txid_str)
{
	struct bitcoin_txid txid;
	bitcoin_txid_from_hex(txid_str, strlen(txid_str), &txid);

	struct input_info *input = tal(ctx, struct input_info);
	input->input_satoshis = AMOUNT_SAT(1500000);
	input->prevtx_txid = txid;
	input->prevtx_vout = vout;
	input->prevtx_scriptpubkey = hex_to_u8(ctx, "0014d1f40e954d7a792284b6fb19a2e0bf777441d83e");
	input->max_witness_len = 109;
	input->script = NULL;
	return input;
}

/* Input four only exists on the 'second' transaction */
static struct input_info *input_four(const tal_t *ctx)
{
	struct bitcoin_txid txid;
	bitcoin_txid_from_hex(txid_str_two, strlen(txid_str_two), &txid);

	struct input_info *input = tal(ctx, struct input_info);
	input->input_satoshis = AMOUNT_SAT(2000000);
	input->prevtx_txid = txid;
	input->prevtx_vout = 1;
	input->prevtx_scriptpubkey = hex_to_u8(ctx, "0014fd9658fbd476d318f3b825b152b152aafa49bc92");
	input->max_witness_len = 109;
	input->script = NULL;
	return input;
}

static struct output_info *output_one(const tal_t *ctx, u64 amount)
{
	struct output_info *output_one = tal(ctx, struct output_info);
	output_one->output_satoshis = (struct amount_sat){ amount };
	output_one->script = hex_to_u8(ctx, "00140f0963bc774334ebc14d11ce940c35cfa6986415");
	return output_one;
}

static struct output_info *output_two(const tal_t *ctx, u64 amount)
{
	struct output_info *output = tal(ctx, struct output_info);
	output->output_satoshis = (struct amount_sat){ amount };
	output->script = hex_to_u8(ctx, "0014d640ab16f347d1de5aba5a715321a5fc4ba9a5d5");
	return output;
}

static struct output_info *output_three(const tal_t *ctx, u64 amount)
{
	struct output_info *output = tal(ctx, struct output_info);
	output->output_satoshis = (struct amount_sat){ amount };
	output->script = hex_to_u8(ctx, "0014d295f76da2319791f36df5759e45b15d5e105221");
	return output;
}

/* Check that change filled in correctly */
static struct test_case test2(const tal_t *ctx)
{
	struct input_info **opener_inputs = tal_arr(ctx, struct input_info *, 1);
	struct input_info **accepter_inputs = tal_arr(ctx, struct input_info *, 1);
	opener_inputs[0] = input_one(ctx, 1, txid_str_one);
	accepter_inputs[0] = input_two(ctx, txid_str_one);

	struct output_info **opener_outputs = tal_arr(ctx, struct output_info *, 1);
	opener_outputs[0] = output_one(ctx, 0);

	struct output_info **accepter_outputs = tal_arr(ctx, struct output_info *, 1);
	accepter_outputs[0] = output_two(ctx, 10000);

	char *expected_tx_str = "02000000023f05da71fb470a53807eb01db4a9220941e3737fa44bccd1fb00f1968c98396c0000000000ffffffff3f05da71fb470a53807eb01db4a9220941e3737fa44bccd1fb00f1968c98396c0100000000ffffffff0311260000000000001600140f0963bc774334ebc14d11ce940c35cfa69864151027000000000000160014d640ab16f347d1de5aba5a715321a5fc4ba9a5d54095160000000000220020c46bf3d1686d6dbb2d9244f8f67b90370c5aa2747045f1aeccb77d818711738200000000";
	struct test_case test = {
	  .feerate = 253,
	  .opener_inputs = opener_inputs,
	  .accepter_inputs = accepter_inputs,
	  .opener_outputs = opener_outputs,
	  .accepter_outputs = accepter_outputs,
	  .opener_funding = AMOUNT_SAT(490000),
	  .accepter_funding = AMOUNT_SAT(990000),
	  .expected_funding = AMOUNT_SAT(1480000),
	  .expected_tx = bitcoin_tx_from_hex(ctx, expected_tx_str, strlen(expected_tx_str)),
	  .remote_pubkey_str = "03d30199d74fb5a22d47b6e054e2f378cedacffcb89904a61d75d0dbd407143e65",
	  .local_pubkey_str = "03e60fce93b59e9ec53011aabc21c23e97b2a31369b87a5ae9c44ee89e2a6dec0a",
	};

	assert(test.expected_tx);

	return test;
}

/* No change passed in, but output is exactly correct */
static struct test_case test3(const tal_t *ctx)
{
	struct input_info **opener_inputs = tal_arr(ctx, struct input_info *, 1);
	struct input_info **accepter_inputs = tal_arr(ctx, struct input_info *, 1);
	opener_inputs[0] = input_one(ctx, 1, txid_str_one);
	accepter_inputs[0] = input_two(ctx, txid_str_one);

	struct output_info **opener_outputs = tal_arr(ctx, struct output_info *, 1);
	opener_outputs[0] = output_one(ctx, 9745);

	struct output_info **accepter_outputs = tal_arr(ctx, struct output_info *, 1);
	accepter_outputs[0] = output_two(ctx, 10000);

	char *expected_tx_str = "02000000023f05da71fb470a53807eb01db4a9220941e3737fa44bccd1fb00f1968c98396c0000000000ffffffff3f05da71fb470a53807eb01db4a9220941e3737fa44bccd1fb00f1968c98396c0100000000ffffffff0311260000000000001600140f0963bc774334ebc14d11ce940c35cfa69864151027000000000000160014d640ab16f347d1de5aba5a715321a5fc4ba9a5d54095160000000000220020c46bf3d1686d6dbb2d9244f8f67b90370c5aa2747045f1aeccb77d818711738200000000";
	struct test_case test = {
	  .feerate = 253,
	  .opener_inputs = opener_inputs,
	  .accepter_inputs = accepter_inputs,
	  .opener_outputs = opener_outputs,
	  .accepter_outputs = accepter_outputs,
	  .opener_funding = AMOUNT_SAT(490000),
	  .accepter_funding = AMOUNT_SAT(990000),
	  .expected_funding = AMOUNT_SAT(1480000),
	  .expected_tx = bitcoin_tx_from_hex(ctx, expected_tx_str, strlen(expected_tx_str)),
	  .remote_pubkey_str = "03d30199d74fb5a22d47b6e054e2f378cedacffcb89904a61d75d0dbd407143e65",
	  .local_pubkey_str = "03e60fce93b59e9ec53011aabc21c23e97b2a31369b87a5ae9c44ee89e2a6dec0a",
	};

	assert(test.expected_tx);

	return test;
}

/* No change passed in, output is a little too big, funding impacted */
static struct test_case test_no_change(const tal_t *ctx)
{
	struct input_info **opener_inputs = tal_arr(ctx, struct input_info *, 1);
	struct input_info **accepter_inputs = tal_arr(ctx, struct input_info *, 1);
	opener_inputs[0] = input_one(ctx, 1, txid_str_one);
	accepter_inputs[0] = input_two(ctx, txid_str_one);

	struct output_info **opener_outputs = tal_arr(ctx, struct output_info *, 1);
	opener_outputs[0] = output_one(ctx, 5000);

	struct output_info **accepter_outputs = tal_arr(ctx, struct output_info *, 1);
	accepter_outputs[0] = output_two(ctx, 10000);

        char *expected_tx_str = "02000000023f05da71fb470a53807eb01db4a9220941e3737fa44bccd1fb00f1968c98396c0000000000ffffffff3f05da71fb470a53807eb01db4a9220941e3737fa44bccd1fb00f1968c98396c0100000000ffffffff0388130000000000001600140f0963bc774334ebc14d11ce940c35cfa69864151027000000000000160014d640ab16f347d1de5aba5a715321a5fc4ba9a5d5d8a4160000000000220020c46bf3d1686d6dbb2d9244f8f67b90370c5aa2747045f1aeccb77d818711738200000000";
	struct test_case test = {
	  .feerate = 1000,
	  .opener_inputs = opener_inputs,
	  .accepter_inputs = accepter_inputs,
	  .opener_outputs = opener_outputs,
	  .accepter_outputs = accepter_outputs,
	  .opener_funding = AMOUNT_SAT(493000),
	  .accepter_funding = AMOUNT_SAT(990000),
	  .expected_funding = AMOUNT_SAT(1483992.0),
	  .expected_tx = bitcoin_tx_from_hex(ctx, expected_tx_str, strlen(expected_tx_str)),
	  .remote_pubkey_str = "03d30199d74fb5a22d47b6e054e2f378cedacffcb89904a61d75d0dbd407143e65",
	  .local_pubkey_str = "03e60fce93b59e9ec53011aabc21c23e97b2a31369b87a5ae9c44ee89e2a6dec0a",
	};

	assert(test.expected_tx);

	return test;
}

/* With change */
static struct test_case test_change(const tal_t *ctx)
{
	struct input_info **opener_inputs = tal_arr(ctx, struct input_info *, 1);
	struct input_info **accepter_inputs = tal_arr(ctx, struct input_info *, 1);
	opener_inputs[0] = input_one(ctx, 1, txid_str_one);
	accepter_inputs[0] = input_two(ctx, txid_str_one);

	struct output_info **opener_outputs = tal_arr(ctx, struct output_info *, 2);
	opener_outputs[0] = output_one(ctx, 5000);
	opener_outputs[1] = output_three(ctx, 0);

	struct output_info **accepter_outputs = tal_arr(ctx, struct output_info *, 1);
	accepter_outputs[0] = output_two(ctx, 10000);

        char *expected_tx_str = "02000000023f05da71fb470a53807eb01db4a9220941e3737fa44bccd1fb00f1968c98396c0000000000ffffffff3f05da71fb470a53807eb01db4a9220941e3737fa44bccd1fb00f1968c98396c0100000000ffffffff046403000000000000160014d295f76da2319791f36df5759e45b15d5e10522188130000000000001600140f0963bc774334ebc14d11ce940c35cfa69864151027000000000000160014d640ab16f347d1de5aba5a715321a5fc4ba9a5d5f8a0160000000000220020c46bf3d1686d6dbb2d9244f8f67b90370c5aa2747045f1aeccb77d818711738200000000";
	struct test_case test = {
	  .feerate = 1000,
	  .opener_inputs = opener_inputs,
	  .accepter_inputs = accepter_inputs,
	  .opener_outputs = opener_outputs,
	  .accepter_outputs = accepter_outputs,
	  .opener_funding = AMOUNT_SAT(493000),
	  .accepter_funding = AMOUNT_SAT(990000),
	  .expected_funding = AMOUNT_SAT(1483000),
	  .expected_tx = bitcoin_tx_from_hex(ctx, expected_tx_str, strlen(expected_tx_str)),
	  .remote_pubkey_str = "03d30199d74fb5a22d47b6e054e2f378cedacffcb89904a61d75d0dbd407143e65",
	  .local_pubkey_str = "03e60fce93b59e9ec53011aabc21c23e97b2a31369b87a5ae9c44ee89e2a6dec0a",
	};

	assert(test.expected_tx);

	return test;
}

/* With change trimmed, funding decreases */
static struct test_case test_change_trimmed(const tal_t *ctx)
{
	struct input_info **opener_inputs = tal_arr(ctx, struct input_info *, 1);
	struct input_info **accepter_inputs = tal_arr(ctx, struct input_info *, 1);
	opener_inputs[0] = input_one(ctx, 1, txid_str_one);
	accepter_inputs[0] = input_two(ctx, txid_str_one);

	struct output_info **opener_outputs = tal_arr(ctx, struct output_info *, 2);
	opener_outputs[0] = output_one(ctx, 5000);
	opener_outputs[1] = output_three(ctx, 0);

	struct output_info **accepter_outputs = tal_arr(ctx, struct output_info *, 1);
	accepter_outputs[0] = output_two(ctx, 10000);

        char *expected_tx_str = "02000000023f05da71fb470a53807eb01db4a9220941e3737fa44bccd1fb00f1968c98396c0000000000ffffffff3f05da71fb470a53807eb01db4a9220941e3737fa44bccd1fb00f1968c98396c0100000000ffffffff0388130000000000001600140f0963bc774334ebc14d11ce940c35cfa69864151027000000000000160014d640ab16f347d1de5aba5a715321a5fc4ba9a5d56881160000000000220020c46bf3d1686d6dbb2d9244f8f67b90370c5aa2747045f1aeccb77d818711738200000000";
	struct test_case test = {
	  .feerate = 10000,
	  .opener_inputs = opener_inputs,
	  .accepter_inputs = accepter_inputs,
	  .opener_outputs = opener_outputs,
	  .accepter_outputs = accepter_outputs,
	  .opener_funding = AMOUNT_SAT(493000),
	  .accepter_funding = AMOUNT_SAT(990000),
	  .expected_funding = AMOUNT_SAT(1474920.0),
	  .expected_tx = bitcoin_tx_from_hex(ctx, expected_tx_str, strlen(expected_tx_str)),
	  .remote_pubkey_str = "03d30199d74fb5a22d47b6e054e2f378cedacffcb89904a61d75d0dbd407143e65",
	  .local_pubkey_str = "03e60fce93b59e9ec53011aabc21c23e97b2a31369b87a5ae9c44ee89e2a6dec0a",
	};

	assert(test.expected_tx);

	return test;
}


/* With change trimmed, funding increases */
static struct test_case test_change_trimmed_positive(const tal_t *ctx)
{
	struct input_info **opener_inputs = tal_arr(ctx, struct input_info *, 1);
	struct input_info **accepter_inputs = tal_arr(ctx, struct input_info *, 1);
	opener_inputs[0] = input_one(ctx, 1, txid_str_one);
	accepter_inputs[0] = input_two(ctx, txid_str_one);

	struct output_info **opener_outputs = tal_arr(ctx, struct output_info *, 2);
	opener_outputs[0] = output_one(ctx, 5000);
	opener_outputs[1] = output_three(ctx, 0);

	struct output_info **accepter_outputs = tal_arr(ctx, struct output_info *, 1);
	accepter_outputs[0] = output_two(ctx, 10000);


        // fee = 1310
        // change = 0
        char *expected_tx_str = "02000000023f05da71fb470a53807eb01db4a9220941e3737fa44bccd1fb00f1968c98396c0000000000ffffffff3f05da71fb470a53807eb01db4a9220941e3737fa44bccd1fb00f1968c98396c0100000000ffffffff0388130000000000001600140f0963bc774334ebc14d11ce940c35cfa69864151027000000000000160014d640ab16f347d1de5aba5a715321a5fc4ba9a5d5aaa3160000000000220020c46bf3d1686d6dbb2d9244f8f67b90370c5aa2747045f1aeccb77d818711738200000000";
	struct test_case test = {
	  .feerate = 1300,
	  .opener_inputs = opener_inputs,
	  .accepter_inputs = accepter_inputs,
	  .opener_outputs = opener_outputs,
	  .accepter_outputs = accepter_outputs,
	  .opener_funding = AMOUNT_SAT(493000),
	  .accepter_funding = AMOUNT_SAT(990000),
	  .expected_funding = AMOUNT_SAT(1483690.0),
	  .expected_tx = bitcoin_tx_from_hex(ctx, expected_tx_str, strlen(expected_tx_str)),
	  .remote_pubkey_str = "03d30199d74fb5a22d47b6e054e2f378cedacffcb89904a61d75d0dbd407143e65",
	  .local_pubkey_str = "03e60fce93b59e9ec53011aabc21c23e97b2a31369b87a5ae9c44ee89e2a6dec0a",
	};

	assert(test.expected_tx);

	return test;
}

/* Funding is less than dust_limit */
static struct test_case test_less_than_dust(const tal_t *ctx)
{
	struct input_info **opener_inputs = tal_arr(ctx, struct input_info *, 1);
	struct input_info **accepter_inputs = tal_arr(ctx, struct input_info *, 0);
	opener_inputs[0] = input_one(ctx, 1, txid_str_one);

	struct output_info **opener_outputs = tal_arr(ctx, struct output_info *, 2);
	opener_outputs[0] = output_one(ctx, 499000);
	opener_outputs[1] = output_three(ctx, 0);

	struct output_info **accepter_outputs = tal_arr(ctx, struct output_info *, 0);

        struct test_case test = {
          .feerate = 1300,
          .opener_inputs = opener_inputs,
          .accepter_inputs = accepter_inputs,
          .opener_outputs = opener_outputs,
          .accepter_outputs = accepter_outputs,
          .opener_funding = AMOUNT_SAT(1000),
          .accepter_funding = AMOUNT_SAT(0),
          .expected_funding = AMOUNT_SAT(206),
          .expected_tx = NULL,
          .remote_pubkey_str = "03d30199d74fb5a22d47b6e054e2f378cedacffcb89904a61d75d0dbd407143e65",
          .local_pubkey_str = "03e60fce93b59e9ec53011aabc21c23e97b2a31369b87a5ae9c44ee89e2a6dec0a",
        };

	return test;
}

/* Funding is less than dust_limit, with accepter inputs  */
static struct test_case test_less_than_dust_with_accepter(const tal_t *ctx)
{
	struct input_info **opener_inputs = tal_arr(ctx, struct input_info *, 1);
	struct input_info **accepter_inputs = tal_arr(ctx, struct input_info *, 1);
	opener_inputs[0] = input_one(ctx, 1, txid_str_one);
	accepter_inputs[0] = input_two(ctx, txid_str_one);

	struct output_info **opener_outputs = tal_arr(ctx, struct output_info *, 2);
	opener_outputs[0] = output_one(ctx, 499000);
	opener_outputs[1] = output_three(ctx, 0);

	struct output_info **accepter_outputs = tal_arr(ctx, struct output_info *, 0);

        struct test_case test = {
          .feerate = 1300,
          .opener_inputs = opener_inputs,
          .accepter_inputs = accepter_inputs,
          .opener_outputs = opener_outputs,
          .accepter_outputs = accepter_outputs,
          .opener_funding = AMOUNT_SAT(1000),
          .accepter_funding = AMOUNT_SAT(1000000),
          .expected_funding = AMOUNT_SAT(1000206),
          .expected_tx = NULL,
          .remote_pubkey_str = "03d30199d74fb5a22d47b6e054e2f378cedacffcb89904a61d75d0dbd407143e65",
          .local_pubkey_str = "03e60fce93b59e9ec53011aabc21c23e97b2a31369b87a5ae9c44ee89e2a6dec0a",
        };

	return test;
}

/* Opener one input, no outputs */
static struct test_case test_one_input(const tal_t *ctx)
{
	struct input_info **opener_inputs = tal_arr(ctx, struct input_info *, 1);
	struct input_info **accepter_inputs = tal_arr(ctx, struct input_info *, 0);
	struct output_info **opener_outputs = tal_arr(ctx, struct output_info *, 0);
	struct output_info **accepter_outputs = tal_arr(ctx, struct output_info *, 0);

	opener_inputs[0] = input_one(ctx, 1, txid_str_one);

        char *expected_tx_str = "02000000013f05da71fb470a53807eb01db4a9220941e3737fa44bccd1fb00f1968c98396c0100000000ffffffff01399f070000000000220020c46bf3d1686d6dbb2d9244f8f67b90370c5aa2747045f1aeccb77d818711738200000000";
	struct test_case test = {
	  .feerate = 1000,
	  .opener_inputs = opener_inputs,
	  .accepter_inputs = accepter_inputs,
	  .opener_outputs = opener_outputs,
	  .accepter_outputs = accepter_outputs,
	  .opener_funding = AMOUNT_SAT(100000),
	  .accepter_funding = AMOUNT_SAT(0),
	  .expected_funding = AMOUNT_SAT(499513),
	  .expected_tx = bitcoin_tx_from_hex(ctx, expected_tx_str, strlen(expected_tx_str)),
	  .remote_pubkey_str = "03d30199d74fb5a22d47b6e054e2f378cedacffcb89904a61d75d0dbd407143e65",
	  .local_pubkey_str = "03e60fce93b59e9ec53011aabc21c23e97b2a31369b87a5ae9c44ee89e2a6dec0a",
	};

	assert(test.expected_tx);

	return test;
}

/* Opener two inputs, no outputs */
static struct test_case test_two_input(const tal_t *ctx)
{
	struct input_info **opener_inputs = tal_arr(ctx, struct input_info *, 2);
	struct input_info **accepter_inputs = tal_arr(ctx, struct input_info *, 0);
	struct output_info **opener_outputs = tal_arr(ctx, struct output_info *, 0);
	struct output_info **accepter_outputs = tal_arr(ctx, struct output_info *, 0);

	opener_inputs[0] = input_one(ctx, 1, txid_str_one);
	opener_inputs[1] = input_three(ctx, 2, txid_str_one);

        char *expected_tx_str = "02000000023f05da71fb470a53807eb01db4a9220941e3737fa44bccd1fb00f1968c98396c0100000000ffffffff3f05da71fb470a53807eb01db4a9220941e3737fa44bccd1fb00f1968c98396c0200000000ffffffff0188811e0000000000220020c46bf3d1686d6dbb2d9244f8f67b90370c5aa2747045f1aeccb77d818711738200000000";
	struct test_case test = {
	  .feerate = 1000,
	  .opener_inputs = opener_inputs,
	  .accepter_inputs = accepter_inputs,
	  .opener_outputs = opener_outputs,
	  .accepter_outputs = accepter_outputs,
	  .opener_funding = AMOUNT_SAT(100000),
	  .accepter_funding = AMOUNT_SAT(0),
	  .expected_funding = AMOUNT_SAT(1999240),
	  .expected_tx = bitcoin_tx_from_hex(ctx, expected_tx_str, strlen(expected_tx_str)),
	  .remote_pubkey_str = "03d30199d74fb5a22d47b6e054e2f378cedacffcb89904a61d75d0dbd407143e65",
	  .local_pubkey_str = "03e60fce93b59e9ec53011aabc21c23e97b2a31369b87a5ae9c44ee89e2a6dec0a",
	};

	assert(test.expected_tx);

	return test;
}

/* Full input/output set */
static struct test_case test_full_set(const tal_t *ctx)
{
	struct input_info **opener_inputs = tal_arr(ctx, struct input_info *, 2);
	struct input_info **accepter_inputs = tal_arr(ctx, struct input_info *, 2);
	struct output_info **opener_outputs = tal_arr(ctx, struct output_info *, 2);
	struct output_info **accepter_outputs = tal_arr(ctx, struct output_info *, 1);

	opener_inputs[0] = input_one(ctx, 2, txid_str_two);
	opener_inputs[1] = input_three(ctx, 3, txid_str_two);

	accepter_inputs[0] = input_two(ctx, txid_str_two);
	accepter_inputs[1] = input_four(ctx);

	opener_outputs[0] = output_one(ctx, 5000);
	opener_outputs[1] = output_three(ctx, 0);

	accepter_outputs[0] = output_two(ctx, 10000);

        char *expected_tx_str = "020000000451e9e94af2fbef69f74fa0c5aa955f1fc169df751461daaaf659bea2ee83f9070000000000ffffffff51e9e94af2fbef69f74fa0c5aa955f1fc169df751461daaaf659bea2ee83f9070100000000ffffffff51e9e94af2fbef69f74fa0c5aa955f1fc169df751461daaaf659bea2ee83f9070200000000ffffffff51e9e94af2fbef69f74fa0c5aa955f1fc169df751461daaaf659bea2ee83f9070300000000ffffffff0488130000000000001600140f0963bc774334ebc14d11ce940c35cfa69864151027000000000000160014d640ab16f347d1de5aba5a715321a5fc4ba9a5d5cae31c0000000000160014d295f76da2319791f36df5759e45b15d5e10522150262f0000000000220020c46bf3d1686d6dbb2d9244f8f67b90370c5aa2747045f1aeccb77d818711738200000000";
	struct test_case test = {
	  .feerate = 1000,
	  .opener_inputs = opener_inputs,
	  .accepter_inputs = accepter_inputs,
	  .opener_outputs = opener_outputs,
	  .accepter_outputs = accepter_outputs,
	  .opener_funding = AMOUNT_SAT(100000),
	  .accepter_funding = AMOUNT_SAT(2990000),
	  .expected_funding = AMOUNT_SAT(3090000),
	  .expected_tx = bitcoin_tx_from_hex(ctx, expected_tx_str, strlen(expected_tx_str)),
	  .remote_pubkey_str = "03d30199d74fb5a22d47b6e054e2f378cedacffcb89904a61d75d0dbd407143e65",
	  .local_pubkey_str = "03e60fce93b59e9ec53011aabc21c23e97b2a31369b87a5ae9c44ee89e2a6dec0a",
	};

	assert(test.expected_tx);

	return test;
}

/* More funding requested than has inputs for */
static struct test_case test_more_than_input(const tal_t *ctx)
{
	struct input_info **opener_inputs = tal_arr(ctx, struct input_info *, 1);
	struct input_info **accepter_inputs = tal_arr(ctx, struct input_info *, 0);
	struct output_info **opener_outputs = tal_arr(ctx, struct output_info *, 0);
	struct output_info **accepter_outputs = tal_arr(ctx, struct output_info *, 0);

	opener_inputs[0] = input_one(ctx, 1, txid_str_one);

	struct test_case test = {
	  .feerate = 1000,
	  .opener_inputs = opener_inputs,
	  .accepter_inputs = accepter_inputs,
	  .opener_outputs = opener_outputs,
	  .accepter_outputs = accepter_outputs,
	  .opener_funding = AMOUNT_SAT(600000),
	  .accepter_funding = AMOUNT_SAT(0),
	  .expected_funding = AMOUNT_SAT(499513),
	  .expected_tx = NULL,
	  .remote_pubkey_str = "03d30199d74fb5a22d47b6e054e2f378cedacffcb89904a61d75d0dbd407143e65",
	  .local_pubkey_str = "03e60fce93b59e9ec53011aabc21c23e97b2a31369b87a5ae9c44ee89e2a6dec0a",
	};

	return test;
}

/* More funding requested (funding + outputs) than has inputs for */
static struct test_case test_culmulative_more_than_input(const tal_t *ctx)
{
	struct input_info **opener_inputs = tal_arr(ctx, struct input_info *, 1);
	struct input_info **accepter_inputs = tal_arr(ctx, struct input_info *, 0);
	struct output_info **opener_outputs = tal_arr(ctx, struct output_info *, 1);
	struct output_info **accepter_outputs = tal_arr(ctx, struct output_info *, 0);

	opener_inputs[0] = input_one(ctx, 1, txid_str_one);

	opener_outputs[0] = output_one(ctx, 100000);

	struct test_case test = {
	  .feerate = 1000,
	  .opener_inputs = opener_inputs,
	  .accepter_inputs = accepter_inputs,
	  .opener_outputs = opener_outputs,
	  .accepter_outputs = accepter_outputs,
	  .opener_funding = AMOUNT_SAT(500000),
	  .accepter_funding = AMOUNT_SAT(0),
	  .expected_funding = AMOUNT_SAT(499513),
	  .expected_tx = NULL,
	  .remote_pubkey_str = "03d30199d74fb5a22d47b6e054e2f378cedacffcb89904a61d75d0dbd407143e65",
	  .local_pubkey_str = "03e60fce93b59e9ec53011aabc21c23e97b2a31369b87a5ae9c44ee89e2a6dec0a",
	};

	return test;
}


#define num_tests 14
static struct test_case (*test_cases[num_tests])(const tal_t *ctx) = {
	test1, test2, test3, test_no_change, test_change, test_change_trimmed,
	test_change_trimmed_positive, test_less_than_dust, test_one_input,
	test_two_input, test_full_set, test_less_than_dust_with_accepter,
	test_more_than_input, test_culmulative_more_than_input,
};

static bool bitcoin_tx_eq(const struct bitcoin_tx *tx1,
			  const struct bitcoin_tx *tx2)
{
	u8 *lin1, *lin2;
	bool eq;
	lin1 = linearize_tx(NULL, tx1);
	lin2 = linearize_tx(lin1, tx2);
	eq = memeq(lin1, tal_count(lin1), lin2, tal_count(lin2));
	tal_free(lin1);
	return eq;
}

int main(void)
{
	setup_locale();

	struct bitcoin_tx *funding;

	struct pubkey local_funding_pubkey, remote_funding_pubkey;
	const struct chainparams *chainparams = chainparams_for_network("bitcoin");

	secp256k1_ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY
						 | SECP256K1_CONTEXT_SIGN);
	setup_tmpctx();

	u16 outnum;
	struct amount_sat total_funding;

	for (size_t i = 0; i < num_tests; i++) {
		struct test_case test = test_cases[i](tmpctx);

		assert(amount_sat_add(&total_funding, test.opener_funding, test.accepter_funding));

		if (!pubkey_from_hexstr(test.local_pubkey_str, strlen(test.local_pubkey_str),
				       	&local_funding_pubkey))
			abort();
		if (!pubkey_from_hexstr(test.remote_pubkey_str, strlen(test.remote_pubkey_str),
					&remote_funding_pubkey))
			abort();

		/* Note that dust_limit is set to 546, via chainparams */
		funding = dual_funding_funding_tx(tmpctx, chainparams,
						  &outnum, test.feerate,
						  &test.opener_funding,
						  test.accepter_funding,
						  test.opener_inputs,
						  test.accepter_inputs,
						  test.opener_outputs,
						  test.accepter_outputs,
						  &local_funding_pubkey,
						  &remote_funding_pubkey,
						  &total_funding, NULL);

		if (!test.expected_tx && !funding)
			continue;

		if (!test.expected_tx ^ !funding)
			abort();

		assert(amount_sat_eq(total_funding, test.expected_funding));
		assert(bitcoin_tx_eq(funding, test.expected_tx));
	}

	/* No memory leaks please */
	secp256k1_context_destroy(secp256k1_ctx);
	tal_free(tmpctx);

	return 0;
}
#else
int main(void)
{
	return 0;
}
#endif /* EXPERIMENTAL_FEATURES */
