/* This is a plugin which allows you to specify
 * your policy for accepting/dual-funding incoming
 * v2 channel-open requests.
 *
 *  "They say marriages are made in Heaven.
 *   But so is funder and lightning."
 *     - Clint Eastwood
 */
#include "config.h"
#include <bitcoin/feerate.h>
#include <bitcoin/psbt.h>
#include <ccan/array_size/array_size.h>
#include <ccan/list/list.h>
#include <ccan/tal/str/str.h>
#include <common/channel_id.h>
#include <common/json.h>
#include <common/json_helpers.h>
#include <common/json_stream.h>
#include <common/node_id.h>
#include <common/psbt_open.h>
#include <common/type_to_string.h>
#include <common/utils.h>
#include <plugins/funder_policy.h>
#include <plugins/libplugin.h>

/* In-progress channel opens */
static struct list_head pending_opens;

/* Current set policy */
static struct funder_policy current_policy;

struct pending_open {
	struct list_node list;
	struct plugin *p;

	struct node_id peer_id;
	struct channel_id channel_id;

	const struct wally_psbt *psbt;
};

static struct pending_open *
find_channel_pending_open(const struct channel_id *cid)
{
	struct pending_open *open;
	list_for_each(&pending_opens, open, list) {
		if (channel_id_eq(&open->channel_id, cid))
			return open;
	}
	return NULL;
}

static struct pending_open *
new_channel_open(const tal_t *ctx,
		 struct plugin *p,
		 const struct node_id id,
		 const struct channel_id cid,
		 const struct wally_psbt *psbt STEALS)
{
	struct pending_open *open;

	/* Make sure we haven't gotten this yet */
	assert(!find_channel_pending_open(&cid));

	open = tal(ctx, struct pending_open);
	open->p = p;
	open->peer_id = id;
	open->channel_id = cid;
	open->psbt = tal_steal(open, psbt);

	list_add_tail(&pending_opens, &open->list);

	return open;
}

static struct command_result *
unreserve_done(struct command *cmd UNUSED,
	       const char *buf,
	       const jsmntok_t *result,
	       struct pending_open *open)
{
	plugin_log(open->p, LOG_DBG,
		   "`unreserveinputs` for channel %s completed. %*.s",
		   type_to_string(tmpctx, struct channel_id, &open->channel_id),
		   json_tok_full_len(result),
		   json_tok_full(buf, result));

	return command_done();
}

static void unreserve_psbt(struct pending_open *open)
{
	struct out_req *req;

	plugin_log(open->p, LOG_DBG,
		   "Calling `unreserveinputs` for channel %s",
		   type_to_string(tmpctx, struct channel_id,
				  &open->channel_id));

	req = jsonrpc_request_start(open->p, NULL,
				    "unreserveinputs",
				    unreserve_done, unreserve_done,
				    open);
	json_add_psbt(req->js, "psbt", open->psbt);
	send_outreq(open->p, req);
}

static void cleanup_peer_pending_opens(const struct node_id *id)
{
	struct pending_open *i, *next;
	list_for_each_safe(&pending_opens, i, next, list) {
		if (node_id_eq(&i->peer_id, id)) {
			unreserve_psbt(i);
			list_del(&i->list);
		}
	}
}

static struct pending_open *
cleanup_channel_pending_open(const struct channel_id *cid)
{
	struct pending_open *open;
	open = find_channel_pending_open(cid);

	if (!open)
		return NULL;

	list_del(&open->list);
	return open;
}

static struct command_result *
command_hook_cont_psbt(struct command *cmd, struct wally_psbt *psbt)
{
	struct json_stream *response;

	response = jsonrpc_stream_success(cmd);
	json_add_string(response, "result", "continue");
	json_add_psbt(response, "psbt", psbt);
	return command_finished(cmd, response);
}

static struct command_result *
signpsbt_done(struct command *cmd,
	      const char *buf,
	      const jsmntok_t *result,
	      struct pending_open *open)
{
	struct wally_psbt *signed_psbt;
	const char *err;

	plugin_log(cmd->plugin, LOG_DBG,
		   "`signpsbt` done for channel %s",
		   type_to_string(tmpctx, struct channel_id,
				  &open->channel_id));
	err = json_scan(tmpctx, buf, result,
			"{signed_psbt:%}",
			JSON_SCAN_TAL(cmd, json_to_psbt, &signed_psbt));

	if (err)
		plugin_err(cmd->plugin,
			   "`signpsbt` payload did not scan %s: %*.s",
			   err, json_tok_full_len(result),
			   json_tok_full(buf, result));

	cleanup_channel_pending_open(&open->channel_id);
	return command_hook_cont_psbt(cmd, signed_psbt);
}

static struct command_result *
json_openchannel2_sign_call(struct command *cmd,
			    const char *buf,
			    const jsmntok_t *params)
{
	struct channel_id cid;
	struct wally_psbt *psbt;
	const char *err;
	struct out_req *req;
	struct pending_open *open;

	err = json_scan(tmpctx, buf, params,
			"{openchannel2_sign:"
			"{channel_id:%,psbt:%}}",
			JSON_SCAN(json_to_channel_id, &cid),
			JSON_SCAN_TAL(cmd, json_to_psbt, &psbt));

	if (err)
		plugin_err(cmd->plugin,
			   "`openchannel2_sign` payload did not scan %s: %.*s",
			   err, json_tok_full_len(params),
			   json_tok_full(buf, params));

	/* If we're not tracking this open, just pass through */
	open = find_channel_pending_open(&cid);
	if (!open) {
		plugin_log(cmd->plugin, LOG_DBG,
			   "nothing to sign for channel %s",
			   type_to_string(tmpctx, struct channel_id, &cid));
		return command_hook_cont_psbt(cmd, psbt);
	}

	if (!psbt_has_our_input(psbt)) {
		plugin_log(cmd->plugin, LOG_DBG,
			   "no inputs to sign for channel %s",
			   type_to_string(tmpctx, struct channel_id, &cid));
		return command_hook_cont_psbt(cmd, psbt);
	}

	plugin_log(cmd->plugin, LOG_DBG,
		   "openchannel_sign PSBT is %s",
		   type_to_string(tmpctx, struct wally_psbt, psbt));

	req = jsonrpc_request_start(cmd->plugin, cmd,
				    "signpsbt",
				    &signpsbt_done,
				    &forward_error,
				    open);
	json_add_psbt(req->js, "psbt", psbt);
	/* Use input markers to identify which inputs
	 * are ours, only sign those */
	json_array_start(req->js, "signonly");
	for (size_t i = 0; i < psbt->num_inputs; i++) {
		if (psbt_input_is_ours(&psbt->inputs[i]))
			json_add_num(req->js, NULL, i);
	}
	json_array_end(req->js);

	plugin_log(cmd->plugin, LOG_DBG,
		   "calling `signpsbt` for channel %s",
		   type_to_string(tmpctx, struct channel_id,
				  &open->channel_id));
	return send_outreq(cmd->plugin, req);
}

static struct command_result *
json_openchannel2_changed_call(struct command *cmd,
			       const char *buf,
			       const jsmntok_t *params)
{
	struct channel_id cid;
	struct wally_psbt *psbt;
	const char *err;

	err = json_scan(tmpctx, buf, params,
			"{openchannel2_changed:"
			"{channel_id:%,psbt:%}}",
			JSON_SCAN(json_to_channel_id, &cid),
			JSON_SCAN_TAL(cmd, json_to_psbt, &psbt));

	if (err)
		plugin_err(cmd->plugin,
			   "`openchannel2_changed` payload did not"
			   " scan %s: %.*s",
			   err, json_tok_full_len(params),
			   json_tok_full(buf, params));

	plugin_log(cmd->plugin, LOG_DBG,
		   "openchannel_changed PSBT is %s",
		   type_to_string(tmpctx, struct wally_psbt, psbt));

	/* FIXME: do we have any additions or updates to make based
	 * on their changes? */
	/* For now, we assume we're the same as before and continue
	 * on as planned */
	return command_hook_cont_psbt(cmd, psbt);
}

/* Tiny struct to pass info to callback for fundpsbt */
struct open_info {
	struct channel_id cid;
	struct node_id id;
	struct amount_sat our_funding;
};

static struct command_result *
psbt_funded(struct command *cmd,
	    const char *buf,
	    const jsmntok_t *result,
	    struct open_info *info)
{
	struct wally_psbt *psbt;
	struct json_stream *response;
	struct amount_msat our_funding_msat;

	const char *err;

	err = json_scan(tmpctx, buf, result,
			"{psbt:%}",
			JSON_SCAN_TAL(tmpctx, json_to_psbt, &psbt));
	if (err)
		plugin_err(cmd->plugin,
			   "`fundpsbt` response did not scan %s: %.*s",
			   err, json_tok_full_len(result),
			   json_tok_full(buf, result));

	/* We also mark all of our inputs as *ours*, so we
	 * can easily identify them for `signpsbt` later */
	for (size_t i = 0; i < psbt->num_inputs; i++)
		psbt_input_mark_ours(psbt, &psbt->inputs[i]);

	new_channel_open(cmd->plugin, cmd->plugin,
			 info->id, info->cid, psbt);

	if (!amount_sat_to_msat(&our_funding_msat, info->our_funding))
		abort();

	response = jsonrpc_stream_success(cmd);
	json_add_string(response, "result", "continue");
	json_add_psbt(response, "psbt", psbt);
	json_add_amount_msat_only(response, "our_funding_msat",
				  our_funding_msat);

	return command_finished(cmd, response);
}

static struct command_result *
psbt_fund_failed(struct command *cmd,
		 const char *buf,
		 const jsmntok_t *error,
		 struct open_info *info)
{
	/* Attempt to fund a psbt for this open failed.
	 * We probably ran out of funds (race?) */
	plugin_log(cmd->plugin, LOG_INFORM,
		   "Unable to secure %s from wallet,"
		   " continuing channel open to %s"
		   " without our participation. err %.*s",
		   type_to_string(tmpctx, struct amount_sat,
				  &info->our_funding),
		   type_to_string(tmpctx, struct node_id,
				  &info->id),
		   json_tok_full_len(error),
		   json_tok_full(buf, error));

	return command_hook_success(cmd);
}

static struct command_result *
json_openchannel2_call(struct command *cmd,
		       const char *buf,
		       const jsmntok_t *params)
{
	struct open_info *info = tal(cmd, struct open_info);
	struct amount_sat their_funding, available_funds, channel_max;
	struct amount_msat max_htlc_inflight, htlc_minimum;
	u64 funding_feerate_perkw, commitment_feerate_perkw,
	    feerate_our_max, feerate_our_min;
	u32 to_self_delay, max_accepted_htlcs, locktime;
	u16 channel_flags;
	const char *err;
	struct out_req *req;

	err = json_scan(tmpctx, buf, params,
			"{openchannel2:"
			"{id:%"
			",channel_id:%"
			",their_funding:%"
			",max_htlc_value_in_flight_msat:%"
			",htlc_minimum_msat:%"
			",funding_feerate_per_kw:%"
			",commitment_feerate_per_kw:%"
			",feerate_our_max:%"
			",feerate_our_min:%"
			",to_self_delay:%"
			",max_accepted_htlcs:%"
			",channel_flags:%"
			",locktime:%}}",
			JSON_SCAN(json_to_node_id, &info->id),
			JSON_SCAN(json_to_channel_id, &info->cid),
			JSON_SCAN(json_to_sat, &their_funding),
			JSON_SCAN(json_to_msat, &max_htlc_inflight),
			JSON_SCAN(json_to_msat, &htlc_minimum),
			JSON_SCAN(json_to_u64, &funding_feerate_perkw),
			JSON_SCAN(json_to_u64, &commitment_feerate_perkw),
			JSON_SCAN(json_to_u64, &feerate_our_max),
			JSON_SCAN(json_to_u64, &feerate_our_min),
			JSON_SCAN(json_to_u32, &to_self_delay),
			JSON_SCAN(json_to_u32, &max_accepted_htlcs),
			JSON_SCAN(json_to_u16, &channel_flags),
			JSON_SCAN(json_to_u32, &locktime));

	if (err)
		plugin_err(cmd->plugin,
			   "`openchannel2` payload did not scan %s: %.*s",
			   err, json_tok_full_len(params),
			   json_tok_full(buf, params));


	/* If there's no channel_max, it's actually infinity */
	err = json_scan(tmpctx, buf, params,
			"{openchannel2:{channel_max_msat:%}}",
			JSON_SCAN(json_to_sat, &channel_max));
	if (err)
		channel_max = AMOUNT_SAT(UINT64_MAX);

	/* We don't fund anything that's above or below our feerate */
	if (funding_feerate_perkw < feerate_our_min
	    || funding_feerate_perkw > feerate_our_max)
		return command_hook_success(cmd);

	info->our_funding = calculate_our_funding(current_policy,
						  info->id,
						  their_funding,
						  available_funds,
						  channel_max);
	plugin_log(cmd->plugin, LOG_DBG,
		   "Policy %s returned funding amount of %s",
		   funder_policy_desc(tmpctx, current_policy),
		   type_to_string(tmpctx, struct amount_sat,
				  &info->our_funding));

	if (amount_sat_eq(info->our_funding, AMOUNT_SAT(0)))
		return command_hook_success(cmd);

	plugin_log(cmd->plugin, LOG_DBG,
		   "Funding channel %s with %s (their input %s)",
		   type_to_string(tmpctx, struct channel_id, &info->cid),
		   type_to_string(tmpctx, struct amount_sat,
				  &info->our_funding),
		   type_to_string(tmpctx, struct amount_sat, &their_funding));

	req = jsonrpc_request_start(cmd->plugin, cmd,
				    "fundpsbt",
				    &psbt_funded,
				    &psbt_fund_failed,
				    info);
	json_add_bool(req->js, "reserve", true);
	json_add_string(req->js, "satoshi",
			type_to_string(tmpctx, struct amount_sat,
				       &info->our_funding));
	json_add_string(req->js, "feerate",
			tal_fmt(tmpctx, "%"PRIu64"%s", funding_feerate_perkw,
				feerate_style_name(FEERATE_PER_KSIPA)));
	/* Our startweight is zero because we're freeriding on their open
	 * transaction ! */
	json_add_num(req->js, "startweight", 0);
	json_add_num(req->js, "min_witness_weight", 110);
	json_add_bool(req->js, "excess_as_change", true);
	json_add_num(req->js, "locktime", locktime);

	return send_outreq(cmd->plugin, req);
}

static void json_disconnect(struct command *cmd,
			    const char *buf,
			    const jsmntok_t *params)
{
	struct node_id id;
	const char *err;

	err = json_scan(tmpctx, buf, params,
			"{id:%}",
			JSON_SCAN(json_to_node_id, &id));
	if (err)
		plugin_err(cmd->plugin,
			   "`disconnect` notification payload did not"
			   " scan %s: %.*s",
			   err, json_tok_full_len(params),
			   json_tok_full(buf, params));

	plugin_log(cmd->plugin, LOG_DBG,
		   "Cleaning up inflights for peer id %s",
		   type_to_string(tmpctx, struct node_id, &id));

	cleanup_peer_pending_opens(&id);
}

static void json_channel_open_failed(struct command *cmd,
				     const char *buf,
				     const jsmntok_t *params)
{
	struct channel_id cid;
	struct pending_open *open;
	const char *err;

	err = json_scan(tmpctx, buf, params,
			"{channel_open_failed:"
			"{channel_id:%}}",
			JSON_SCAN(json_to_channel_id, &cid));
	if (err)
		plugin_err(cmd->plugin,
			   "`channel_open_failed` notification payload did"
			   " not scan %s: %.*s",
			   err, json_tok_full_len(params),
			   json_tok_full(buf, params));

	plugin_log(cmd->plugin, LOG_DBG,
		   "Cleaning up inflight for channel_id %s",
		   type_to_string(tmpctx, struct channel_id, &cid));

	open = cleanup_channel_pending_open(&cid);
	if (open)
		unreserve_psbt(open);
}

static const char *init(struct plugin *p, const char *b, const jsmntok_t *t)
{
	list_head_init(&pending_opens);

	return NULL;
}

const struct plugin_hook hooks[] = {
	{
		"openchannel2",
		json_openchannel2_call,
	},
	{
		"openchannel2_changed",
		json_openchannel2_changed_call,
	},
	{
		"openchannel2_sign",
		json_openchannel2_sign_call,
	},
};

const struct plugin_notification notifs[] = {
	{
		"channel_open_failed",
		json_channel_open_failed,
	},
	{
		"disconnect",
		json_disconnect,
	},
};

static char *amount_option(const char *arg, struct amount_sat *amt)
{
	if (!parse_amount_sat(amt, arg, strlen(arg)))
		return tal_fmt(NULL, "Unable to parse amount '%s'", arg);

	return NULL;
}

static char *amount_sat_or_u64_option(const char *arg, u64 *amt)
{
	struct amount_sat sats;
	char *err;

	err = u64_option(arg, amt);
	if (err) {
		tal_free(err);
		if (!parse_amount_sat(&sats, arg, strlen(arg)))
			return tal_fmt(NULL,
				       "Unable to parse option '%s'",
				       arg);

		*amt = sats.satoshis; /* Raw: convert to u64 */
	}

	return NULL;
}

int main(int argc, char **argv)
{
	char *owner = tal(NULL, char);

	setup_locale();

	/* Our default funding policy is fixed (0msat) */
	current_policy = default_funder_policy(FIXED, 0);

	plugin_main(argv, init, PLUGIN_RESTARTABLE, true,
		    NULL,
		    NULL, 0,
		    notifs, ARRAY_SIZE(notifs),
		    hooks, ARRAY_SIZE(hooks),
		    plugin_option("funder-policy",
				  "string",
				  "Policy to use for dual-funding requests."
				  " [match, available, fixed]",
				  funding_option, &current_policy.opt),
		    plugin_option("funder-policy-mod",
				  "string",
				  "Percent to apply policy at"
				  " (match/available); or amount to fund"
				  " (fixed)",
				  amount_sat_or_u64_option,
				  &current_policy.mod),
		    plugin_option("funder-min-their-funding",
				  "string",
				  "Minimum funding peer must open with"
				  " to activate our policy",
				  amount_option,
				  &current_policy.min_their_funding),
		    plugin_option("funder-max-their-funding",
				  "string",
				  "Maximum funding peer may open with"
				  " to activate our policy",
				  amount_option,
				  &current_policy.max_their_funding),
		    plugin_option("funder-per-channel-min",
				  "string",
				  "Minimum funding we'll add to a channel."
				  " If we can't meet this, we don't fund",
				  amount_option,
				  &current_policy.per_channel_min),
		    plugin_option("funder-per-channel-max",
				  "string",
				  "Maximum funding we'll add to a channel."
				  " We cap all contributions to this",
				  amount_option,
				  &current_policy.per_channel_max),
		    plugin_option("funder-reserve-tank",
				  "string",
				  "Amount of funds we'll always leave"
				  " available.",
				  amount_option,
				  &current_policy.reserve_tank),
		    plugin_option("funder-fuzz-percent",
				  "int",
				  "Percent to fuzz the policy contribution by."
				  " Defaults to 5%. Max is 100%",
				  u32_option,
				  &current_policy.fuzz_factor),
		    plugin_option("funder-fund-probability",
				  "int",
				  "Percent of requests to consider."
				  " Defaults to 100%. Setting to 0% will"
				  " disable dual-funding",
				  u32_option,
				  &current_policy.fund_probability),
		    NULL);

	tal_free(owner);
	return 0;
}
