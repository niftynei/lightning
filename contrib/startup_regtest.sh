#!/bin/sh

## Short script to startup two local nodes with
## bitcoind, all running on regtest
## Makes it easier to test things out, by hand.

## Should be called by source since it sets aliases
##
##  First load this file up.
##
##  $ source contrib/startup_regtest.sh
##
##  Start up the nodeset
##
##  $ start_ln
##
##  Let's connect the nodes.
##
##  $ l2-cli getinfo | jq .id
##    "02b96b03e42d9126cb5228752c575c628ad09bdb7a138ec5142bbca21e244ddceb"
##  $ l2-cli getinfo | jq .binding[0].port
##    9090
##  $ l1-cli connect 02b96b03e42d9126cb5228752c575c628ad09bdb7a138ec5142bbca21e244ddceb@localhost:9090
##    {
##      "id" : "030b02fc3d043d2d47ae25a9306d98d2abb7fc9bee824e68b8ce75d6d8f09d5eb7"
##    }
##
##  When you're finished, clean up or stop
##
##  $ stop_ln  # stops the services, keeps the aliases
##  $ cleanup_ln # stops and cleans up aliases
##

if [ -z "$PATH_TO_LIGHTNING" ]
then
	echo "\$PATH_TO_LIGHTNING not set"
	return
fi

if [ -z "$PATH_TO_BITCOIN" ]
then
	echo "\$PATH_TO_BITCOIN not set"
	return
fi

mkdir -p /tmp/l1-regtest /tmp/l2-regtest /tmp/bt-regtest

# Node one config
cat << 'EOF' > /tmp/l1-regtest/config
network=regtest
daemon
log-level=debug
log-file=/tmp/l1-regtest/log
addr=localhost:6060
bitcoin-datadir=/tmp/bt-regtest
EOF

cat << 'EOF' > /tmp/l2-regtest/config
network=regtest
daemon
log-level=debug
log-file=/tmp/l2-regtest/log
addr=localhost:9090
bitcoin-datadir=/tmp/bt-regtest
EOF

alias l1-cli='$PATH_TO_LIGHTNING/cli/lightning-cli --lightning-dir=/tmp/l1-regtest'
alias l2-cli='$PATH_TO_LIGHTNING/cli/lightning-cli --lightning-dir=/tmp/l2-regtest'
alias bt-cli='bitcoin-cli -regtest -datadir=/tmp/bt-regtest'

start_ln() {
	# Start bitcoind in the background
	test -f "/tmp/bt-regtest/regtest/bitcoind.pid" || \
		bitcoind -daemon -regtest -txindex -datadir=/tmp/bt-regtest

	# Start the lightning nodes
	test -f /tmp/l1-regtest/lightningd-regtest.pid || \
		"$PATH_TO_LIGHTNING/lightningd/lightningd" --lightning-dir=/tmp/l1-regtest
	test  -f /tmp/l2-regtest/lightningd-regtest.pid || \
		"$PATH_TO_LIGHTNING/lightningd/lightningd" --lightning-dir=/tmp/l2-regtest

}

stop_ln() {
	test ! -f /tmp/l1-regtest/lightningd-regtest.pid || \
		(kill "$(cat /tmp/l1-regtest/lightningd-regtest.pid)"; \
		rm /tmp/l1-regtest/lightningd-regtest.pid)
	test ! -f /tmp/l2-regtest/lightningd-regtest.pid || \
		(kill "$(cat /tmp/l2-regtest/lightningd-regtest.pid)"; \
		rm /tmp/l2-regtest/lightningd-regtest.pid)
	test ! -f "/tmp/bt-regtest/regtest/bitcoind.pid" || \
		(kill "$(cat "/tmp/bt-regtest/regtest/bitcoind.pid")"; \
		rm "/tmp/bt-regtest/regtest/bitcoind.pid")
}

reset_ln() {
	rm -rf /tmp/l2-regtest /tmp/l1-regtest /tmp/bt-regtest
}

cleanup_ln() {
	stop_ln
	reset_ln
	unalias l1-cli
	unalias l2-cli
	unalias bt-cli
	unset -f start_ln
	unset -f stop_ln
	unset -f cleanup_ln
	unset -f reset_ln
}
