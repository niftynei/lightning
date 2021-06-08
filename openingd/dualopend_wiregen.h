/* This file was generated by generate-wire.py */
/* Do not modify this file! Modify the _csv file it was generated from. */
/* Original template can be found at tools/gen/header_template */

#ifndef LIGHTNING_OPENINGD_DUALOPEND_WIREGEN_H
#define LIGHTNING_OPENINGD_DUALOPEND_WIREGEN_H
#include <ccan/tal/tal.h>
#include <wire/tlvstream.h>
#include <wire/wire.h>
#include <bitcoin/chainparams.h>
#include <bitcoin/psbt.h>
#include <common/cryptomsg.h>
#include <common/channel_config.h>
#include <common/channel_id.h>
#include <common/derive_basepoints.h>
#include <common/features.h>
#include <common/fee_states.h>
#include <common/htlc_wire.h>
#include <common/penalty_base.h>
#include <common/per_peer_state.h>
#include <wire/peer_wire.h>

enum dualopend_wire {
        WIRE_DUALOPEND_INIT = 7000,
        /*  master-dualopend: peer has reconnected */
        WIRE_DUALOPEND_REINIT = 7001,
        /*  dualopend->master: they offered channel */
        WIRE_DUALOPEND_GOT_OFFER = 7005,
        /*  master->dualopend: reply back with our first funding info/contribs */
        WIRE_DUALOPEND_GOT_OFFER_REPLY = 7105,
        /*  dualopend->master: they offered a RBF */
        WIRE_DUALOPEND_GOT_RBF_OFFER = 7500,
        /*  master->dualopend: reply back with our funding info/contribs */
        WIRE_DUALOPEND_GOT_RBF_OFFER_REPLY = 7505,
        /*  dualopend->master: is this a valid RBF candidate transaction? */
        WIRE_DUALOPEND_RBF_VALIDATE = 7506,
        /*  master->dualopend: this is a valid RBF candidate transaction */
        WIRE_DUALOPEND_RBF_VALID = 7507,
        /*  master->dualopend: attempt an RBF */
        WIRE_DUALOPEND_RBF_INIT = 7509,
        /*  dualopend->master: ready to commit channel open to database and */
        /*                     get some signatures for the funding_tx. */
        WIRE_DUALOPEND_COMMIT_RCVD = 7007,
        /*  dualopend->master: peer updated the psbt */
        WIRE_DUALOPEND_PSBT_CHANGED = 7107,
        /*  master->dualopend: we updated the psbt */
        WIRE_DUALOPEND_PSBT_UPDATED = 7108,
        /*  master->dualopend: fail this channel open */
        WIRE_DUALOPEND_FAIL = 7003,
        /*  master->dualopend: hello */
        WIRE_DUALOPEND_OPENER_INIT = 7200,
        /*  dualopend->master received tx_sigs from peer */
        WIRE_DUALOPEND_FUNDING_SIGS = 7010,
        /*  master->dualopend send our tx_sigs to peer */
        WIRE_DUALOPEND_SEND_TX_SIGS = 7011,
        /*  dualopend->master tx sigs transmitted to peer */
        WIRE_DUALOPEND_TX_SIGS_SENT = 7012,
        /*  dualopend->peer peer locked channel */
        WIRE_DUALOPEND_PEER_LOCKED = 7018,
        /*  dualopend->master this channel has been locked */
        WIRE_DUALOPEND_CHANNEL_LOCKED = 7019,
        /*  master->dualopend funding reached depth; tell peer */
        WIRE_DUALOPEND_DEPTH_REACHED = 7020,
        /*  Tell peer to shut down channel. */
        WIRE_DUALOPEND_SEND_SHUTDOWN = 7023,
        /*  Peer told us that channel is shutting down */
        WIRE_DUALOPEND_GOT_SHUTDOWN = 7024,
        /*  Peer presented proof it was from the future. */
        WIRE_DUALOPEND_FAIL_FALLEN_BEHIND = 1028,
        /*  Shutdown is complete */
        WIRE_DUALOPEND_SHUTDOWN_COMPLETE = 7025,
        /*  master -> dualopend: do you have a memleak? */
        WIRE_DUALOPEND_DEV_MEMLEAK = 7033,
        WIRE_DUALOPEND_DEV_MEMLEAK_REPLY = 7133,
};

const char *dualopend_wire_name(int e);

/**
 * Determine whether a given message type is defined as a message.
 *
 * Returns true if the message type is part of the message definitions we have
 * generated parsers for, false if it is a custom message that cannot be
 * handled internally.
 */
bool dualopend_wire_is_defined(u16 type);


/* WIRE: DUALOPEND_INIT */
u8 *towire_dualopend_init(const tal_t *ctx, const struct chainparams *chainparams, const struct feature_set *our_feature_set, const u8 *their_init_features, const struct channel_config *our_config, u32 max_to_self_delay, struct amount_msat min_effective_htlc_capacity_msat, const struct per_peer_state *pps, const struct basepoints *our_basepoints, const struct pubkey *our_funding_pubkey, u32 minimum_depth);
bool fromwire_dualopend_init(const tal_t *ctx, const void *p, const struct chainparams **chainparams, struct feature_set **our_feature_set, u8 **their_init_features, struct channel_config *our_config, u32 *max_to_self_delay, struct amount_msat *min_effective_htlc_capacity_msat, struct per_peer_state **pps, struct basepoints *our_basepoints, struct pubkey *our_funding_pubkey, u32 *minimum_depth);

/* WIRE: DUALOPEND_REINIT */
/*  master-dualopend: peer has reconnected */
u8 *towire_dualopend_reinit(const tal_t *ctx, const struct chainparams *chainparams, const struct feature_set *our_feature_set, const u8 *their_init_features, const struct channel_config *our_config, const struct channel_config *their_config, const struct channel_id *channel_id, u32 max_to_self_delay, struct amount_msat min_effective_htlc_capacity_msat, const struct per_peer_state *pps, const struct basepoints *our_basepoints, const struct pubkey *our_funding_pubkey, const struct pubkey *their_funding_pubkey, u32 minimum_depth, const struct bitcoin_txid *funding_txid, u16 funding_txout, u32 most_recent_feerate_per_kw_funding, struct amount_sat funding_satoshi, struct amount_msat our_funding, const struct basepoints *their_basepoints, const struct pubkey *remote_per_commit, const struct wally_psbt *funding_psbt, enum side opener, bool local_funding_locked, bool remote_funding_locked, bool send_shutdown, bool remote_shutdown_received, const u8 *local_shutdown_scriptpubkey, const u8 *remote_shutdown_scriptpubkey, bool remote_funding_sigs_received, const struct fee_states *fee_states, u8 channel_flags);
bool fromwire_dualopend_reinit(const tal_t *ctx, const void *p, const struct chainparams **chainparams, struct feature_set **our_feature_set, u8 **their_init_features, struct channel_config *our_config, struct channel_config *their_config, struct channel_id *channel_id, u32 *max_to_self_delay, struct amount_msat *min_effective_htlc_capacity_msat, struct per_peer_state **pps, struct basepoints *our_basepoints, struct pubkey *our_funding_pubkey, struct pubkey *their_funding_pubkey, u32 *minimum_depth, struct bitcoin_txid *funding_txid, u16 *funding_txout, u32 *most_recent_feerate_per_kw_funding, struct amount_sat *funding_satoshi, struct amount_msat *our_funding, struct basepoints *their_basepoints, struct pubkey *remote_per_commit, struct wally_psbt **funding_psbt, enum side *opener, bool *local_funding_locked, bool *remote_funding_locked, bool *send_shutdown, bool *remote_shutdown_received, u8 **local_shutdown_scriptpubkey, u8 **remote_shutdown_scriptpubkey, bool *remote_funding_sigs_received, struct fee_states **fee_states, u8 *channel_flags);

/* WIRE: DUALOPEND_GOT_OFFER */
/*  dualopend->master: they offered channel */
u8 *towire_dualopend_got_offer(const tal_t *ctx, const struct channel_id *channel_id, struct amount_sat opener_funding, struct amount_sat dust_limit_satoshis, struct amount_msat max_htlc_value_in_flight_msat, struct amount_msat htlc_minimum_msat, u32 feerate_per_kw_funding, u32 feerate_per_kw_commitment, u16 to_self_delay, u16 max_accepted_htlcs, u8 channel_flags, u32 locktime, const u8 *shutdown_scriptpubkey, struct amount_sat requested_amt, u32 lease_blockheight_start);
bool fromwire_dualopend_got_offer(const tal_t *ctx, const void *p, struct channel_id *channel_id, struct amount_sat *opener_funding, struct amount_sat *dust_limit_satoshis, struct amount_msat *max_htlc_value_in_flight_msat, struct amount_msat *htlc_minimum_msat, u32 *feerate_per_kw_funding, u32 *feerate_per_kw_commitment, u16 *to_self_delay, u16 *max_accepted_htlcs, u8 *channel_flags, u32 *locktime, u8 **shutdown_scriptpubkey, struct amount_sat *requested_amt, u32 *lease_blockheight_start);

/* WIRE: DUALOPEND_GOT_OFFER_REPLY */
/*  master->dualopend: reply back with our first funding info/contribs */
u8 *towire_dualopend_got_offer_reply(const tal_t *ctx, struct amount_sat accepter_funding, const struct wally_psbt *psbt, const u8 *our_shutdown_scriptpubkey, const struct lease_rates *lease_rates);
bool fromwire_dualopend_got_offer_reply(const tal_t *ctx, const void *p, struct amount_sat *accepter_funding, struct wally_psbt **psbt, u8 **our_shutdown_scriptpubkey, struct lease_rates **lease_rates);

/* WIRE: DUALOPEND_GOT_RBF_OFFER */
/*  dualopend->master: they offered a RBF */
u8 *towire_dualopend_got_rbf_offer(const tal_t *ctx, const struct channel_id *channel_id, struct amount_sat their_funding, u32 funding_feerate_per_kw, u32 locktime);
bool fromwire_dualopend_got_rbf_offer(const void *p, struct channel_id *channel_id, struct amount_sat *their_funding, u32 *funding_feerate_per_kw, u32 *locktime);

/* WIRE: DUALOPEND_GOT_RBF_OFFER_REPLY */
/*  master->dualopend: reply back with our funding info/contribs */
u8 *towire_dualopend_got_rbf_offer_reply(const tal_t *ctx, struct amount_sat our_funding, const struct wally_psbt *psbt);
bool fromwire_dualopend_got_rbf_offer_reply(const tal_t *ctx, const void *p, struct amount_sat *our_funding, struct wally_psbt **psbt);

/* WIRE: DUALOPEND_RBF_VALIDATE */
/*  dualopend->master: is this a valid RBF candidate transaction? */
u8 *towire_dualopend_rbf_validate(const tal_t *ctx, const struct wally_psbt *proposed_funding_psbt);
bool fromwire_dualopend_rbf_validate(const tal_t *ctx, const void *p, struct wally_psbt **proposed_funding_psbt);

/* WIRE: DUALOPEND_RBF_VALID */
/*  master->dualopend: this is a valid RBF candidate transaction */
u8 *towire_dualopend_rbf_valid(const tal_t *ctx);
bool fromwire_dualopend_rbf_valid(const void *p);

/* WIRE: DUALOPEND_RBF_INIT */
/*  master->dualopend: attempt an RBF */
u8 *towire_dualopend_rbf_init(const tal_t *ctx, struct amount_sat our_funding, u32 funding_feerate_perkw, const struct wally_psbt *psbt);
bool fromwire_dualopend_rbf_init(const tal_t *ctx, const void *p, struct amount_sat *our_funding, u32 *funding_feerate_perkw, struct wally_psbt **psbt);

/* WIRE: DUALOPEND_COMMIT_RCVD */
/*  dualopend->master: ready to commit channel open to database and */
/*                     get some signatures for the funding_tx. */
u8 *towire_dualopend_commit_rcvd(const tal_t *ctx, const struct channel_config *their_config, const struct bitcoin_tx *remote_first_commit, const struct penalty_base *pbase, const struct bitcoin_signature *first_commit_sig, const struct wally_psbt *psbt, const struct pubkey *revocation_basepoint, const struct pubkey *payment_basepoint, const struct pubkey *htlc_basepoint, const struct pubkey *delayed_payment_basepoint, const struct pubkey *their_per_commit_point, const struct pubkey *remote_fundingkey, const struct bitcoin_txid *funding_txid, u16 funding_txout, struct amount_sat funding_satoshis, struct amount_sat our_funding_sats, u8 channel_flags, u32 feerate_per_kw_funding, u32 feerate_per_kw_commitment, const u8 *local_shutdown_scriptpubkey, const u8 *remote_shutdown_scriptpubkey);
bool fromwire_dualopend_commit_rcvd(const tal_t *ctx, const void *p, struct channel_config *their_config, struct bitcoin_tx **remote_first_commit, struct penalty_base **pbase, struct bitcoin_signature *first_commit_sig, struct wally_psbt **psbt, struct pubkey *revocation_basepoint, struct pubkey *payment_basepoint, struct pubkey *htlc_basepoint, struct pubkey *delayed_payment_basepoint, struct pubkey *their_per_commit_point, struct pubkey *remote_fundingkey, struct bitcoin_txid *funding_txid, u16 *funding_txout, struct amount_sat *funding_satoshis, struct amount_sat *our_funding_sats, u8 *channel_flags, u32 *feerate_per_kw_funding, u32 *feerate_per_kw_commitment, u8 **local_shutdown_scriptpubkey, u8 **remote_shutdown_scriptpubkey);

/* WIRE: DUALOPEND_PSBT_CHANGED */
/*  dualopend->master: peer updated the psbt */
u8 *towire_dualopend_psbt_changed(const tal_t *ctx, const struct channel_id *channel_id, u64 funding_serial, const struct wally_psbt *psbt);
bool fromwire_dualopend_psbt_changed(const tal_t *ctx, const void *p, struct channel_id *channel_id, u64 *funding_serial, struct wally_psbt **psbt);

/* WIRE: DUALOPEND_PSBT_UPDATED */
/*  master->dualopend: we updated the psbt */
u8 *towire_dualopend_psbt_updated(const tal_t *ctx, const struct wally_psbt *psbt);
bool fromwire_dualopend_psbt_updated(const tal_t *ctx, const void *p, struct wally_psbt **psbt);

/* WIRE: DUALOPEND_FAIL */
/*  master->dualopend: fail this channel open */
u8 *towire_dualopend_fail(const tal_t *ctx, const wirestring *reason);
bool fromwire_dualopend_fail(const tal_t *ctx, const void *p, wirestring **reason);

/* WIRE: DUALOPEND_OPENER_INIT */
/*  master->dualopend: hello */
u8 *towire_dualopend_opener_init(const tal_t *ctx, const struct wally_psbt *psbt, struct amount_sat funding_amount, const u8 *local_shutdown_scriptpubkey, u32 feerate_per_kw, u32 feerate_per_kw_funding, u8 channel_flags, struct amount_sat requested_sats, u32 blockheight);
bool fromwire_dualopend_opener_init(const tal_t *ctx, const void *p, struct wally_psbt **psbt, struct amount_sat *funding_amount, u8 **local_shutdown_scriptpubkey, u32 *feerate_per_kw, u32 *feerate_per_kw_funding, u8 *channel_flags, struct amount_sat *requested_sats, u32 *blockheight);

/* WIRE: DUALOPEND_FUNDING_SIGS */
/*  dualopend->master received tx_sigs from peer */
u8 *towire_dualopend_funding_sigs(const tal_t *ctx, const struct wally_psbt *signed_psbt);
bool fromwire_dualopend_funding_sigs(const tal_t *ctx, const void *p, struct wally_psbt **signed_psbt);

/* WIRE: DUALOPEND_SEND_TX_SIGS */
/*  master->dualopend send our tx_sigs to peer */
u8 *towire_dualopend_send_tx_sigs(const tal_t *ctx, const struct wally_psbt *signed_psbt);
bool fromwire_dualopend_send_tx_sigs(const tal_t *ctx, const void *p, struct wally_psbt **signed_psbt);

/* WIRE: DUALOPEND_TX_SIGS_SENT */
/*  dualopend->master tx sigs transmitted to peer */
u8 *towire_dualopend_tx_sigs_sent(const tal_t *ctx);
bool fromwire_dualopend_tx_sigs_sent(const void *p);

/* WIRE: DUALOPEND_PEER_LOCKED */
/*  dualopend->peer peer locked channel */
u8 *towire_dualopend_peer_locked(const tal_t *ctx, const struct pubkey *remote_per_commit);
bool fromwire_dualopend_peer_locked(const void *p, struct pubkey *remote_per_commit);

/* WIRE: DUALOPEND_CHANNEL_LOCKED */
/*  dualopend->master this channel has been locked */
u8 *towire_dualopend_channel_locked(const tal_t *ctx, const struct per_peer_state *pps);
bool fromwire_dualopend_channel_locked(const tal_t *ctx, const void *p, struct per_peer_state **pps);

/* WIRE: DUALOPEND_DEPTH_REACHED */
/*  master->dualopend funding reached depth; tell peer */
u8 *towire_dualopend_depth_reached(const tal_t *ctx, u32 depth);
bool fromwire_dualopend_depth_reached(const void *p, u32 *depth);

/* WIRE: DUALOPEND_SEND_SHUTDOWN */
/*  Tell peer to shut down channel. */
u8 *towire_dualopend_send_shutdown(const tal_t *ctx, const u8 *shutdown_scriptpubkey);
bool fromwire_dualopend_send_shutdown(const tal_t *ctx, const void *p, u8 **shutdown_scriptpubkey);

/* WIRE: DUALOPEND_GOT_SHUTDOWN */
/*  Peer told us that channel is shutting down */
u8 *towire_dualopend_got_shutdown(const tal_t *ctx, const u8 *scriptpubkey);
bool fromwire_dualopend_got_shutdown(const tal_t *ctx, const void *p, u8 **scriptpubkey);

/* WIRE: DUALOPEND_FAIL_FALLEN_BEHIND */
/*  Peer presented proof it was from the future. */
u8 *towire_dualopend_fail_fallen_behind(const tal_t *ctx);
bool fromwire_dualopend_fail_fallen_behind(const void *p);

/* WIRE: DUALOPEND_SHUTDOWN_COMPLETE */
/*  Shutdown is complete */
u8 *towire_dualopend_shutdown_complete(const tal_t *ctx, const struct per_peer_state *per_peer_state);
bool fromwire_dualopend_shutdown_complete(const tal_t *ctx, const void *p, struct per_peer_state **per_peer_state);

/* WIRE: DUALOPEND_DEV_MEMLEAK */
/*  master -> dualopend: do you have a memleak? */
u8 *towire_dualopend_dev_memleak(const tal_t *ctx);
bool fromwire_dualopend_dev_memleak(const void *p);

/* WIRE: DUALOPEND_DEV_MEMLEAK_REPLY */
u8 *towire_dualopend_dev_memleak_reply(const tal_t *ctx, bool leak);
bool fromwire_dualopend_dev_memleak_reply(const void *p, bool *leak);


#endif /* LIGHTNING_OPENINGD_DUALOPEND_WIREGEN_H */
// SHA256STAMP:d8a31a5de292561ccfb5b7050c911b590db44a50209e02469179904708328861
