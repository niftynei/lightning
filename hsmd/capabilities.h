#ifndef LIGHTNING_HSMD_CAPABILITIES_H
#define LIGHTNING_HSMD_CAPABILITIES_H

#define HSM_CAP_ECDH 1
#define HSM_CAP_SIGN_GOSSIP 2
#define HSM_CAP_SIGN_ONCHAIN_TX 4
#define HSM_CAP_COMMITMENT_POINT 8
#define HSM_CAP_SIGN_REMOTE_TX 16
#define HSM_CAP_SIGN_CLOSING_TX 32
#define HSM_CAP_SIGN_ACCEPTER_FUNDING_TX 64

#define HSM_CAP_MASTER 1024
#endif /* LIGHTNING_HSMD_CAPABILITIES_H */
