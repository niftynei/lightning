#ifndef LIGHTNING_CONNECTD_NETADDRESS_H
#define LIGHTNING_CONNECTD_NETADDRESS_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <common/wireaddr.h>

/* Helper to extract a wireaddr from a (socket) fd.  Sets errno if false. */
bool fd_local_address(int fd, struct wireaddr *wireaddr);

/* Address is a wildcard: try to guess what it looks like to outside world */
bool guess_address(struct wireaddr *wireaddr);

/* Is this address public? */
bool address_routable(const struct wireaddr *wireaddr,
		      bool allow_localhost);

#endif /* LIGHTNING_CONNECTD_NETADDRESS_H */
