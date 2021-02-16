#include "probe.h"
#include <assert.h>
#include <errno.h>
#include <error.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void wait_for_activity(struct net_state_t* net_state);
static int gather_read_fds(const struct net_state_t* net_state,
                           fd_set* read_set, fd_set* write_set);

int main() {
    struct net_state_t net_state;
    init_net_state_privileged(&net_state);
    init_net_state(&net_state);

    for (int times = 1; times <= 3; times++) {
        for (int ttl = 1; ttl <= 30; ttl++) {
            struct probe_param_t param;
            memset(&param, 0, sizeof(struct probe_param_t));
            param.command_token = times * 100 + ttl;
            param.protocol = IPPROTO_ICMP;
            param.ttl = ttl;
            param.packet_size = 64;
            param.timeout = 1;
            param.is_probing_byte_order = false;
            param.ip_version = 4;
            param.local_address = "100.100.57.107";
            param.remote_address = "119.188.122.239";
            param.type_of_service = 0;
            param.packet_size = 64;

            if (!is_ip_version_supported(&net_state, param.ip_version)) {
                fprintf(stderr,
                        "%d invalid-argument reason ip-version-not-supported\n",
                        param.command_token);
                return -1;
            }

            if (!is_protocol_supported(&net_state, param.protocol)) {
                fprintf(stderr,
                        "%d invalid-argument reason protocol-not-supported\n",
                        param.command_token);

                return -1;
            }
            send_probe(&net_state, &param);
        }

        while (net_state.outstanding_probe_count > 0) {
            wait_for_activity(&net_state);
            receive_replies(&net_state);
            check_probe_timeouts(&net_state);
        }
    }

    return 0;
}

void wait_for_activity(struct net_state_t* net_state) {
    int nfds;
    fd_set read_set;
    fd_set write_set;
    struct timeval probe_timeout;
    struct timeval* select_timeout;
    int ready_count;

    nfds = gather_read_fds(net_state, &read_set, &write_set);

    while (true) {
        select_timeout = NULL;

        /*  Use the soonest probe timeout time as our maximum wait time  */
        if (get_next_probe_timeout(net_state, &probe_timeout)) {
            assert(probe_timeout.tv_sec >= 0);
            select_timeout = &probe_timeout;
        }

        ready_count = select(nfds, &read_set, &write_set, NULL, select_timeout);

        /*
           If we didn't have an error, either one of our descriptors is
           readable, or we timed out.  So we can now return.
         */
        if (ready_count != -1) {
            break;
        }

        /*
           We will get EINTR if we received a signal during the select, so
           retry in that case.  We may get EAGAIN if "the kernel was
           (perhaps temporarily) unable to allocate the requested number of
           file descriptors."  I haven't seen this in practice, but selecting
           again seems like the right thing to do.
         */
        if (errno != EINTR && errno != EAGAIN) {
            /*  We don't expect other errors, so report them  */
            error(EXIT_FAILURE, errno, "unexpected select error");
        }
    }
}

int gather_read_fds(const struct net_state_t* net_state, fd_set* read_set,
                    fd_set* write_set) {
    int nfds;
    int probe_nfds;
    int ip4_socket;
    int ip6_socket;

    FD_ZERO(read_set);
    FD_ZERO(write_set);

    nfds = 0;

    if (net_state->platform.ip4_socket_raw) {
        ip4_socket = net_state->platform.ip4_recv_socket;
        FD_SET(ip4_socket, read_set);
        if (ip4_socket >= nfds) {
            nfds = ip4_socket + 1;
        }
    } else {
        ip4_socket = net_state->platform.ip4_txrx_icmp_socket;
        FD_SET(ip4_socket, read_set);
        if (ip4_socket >= nfds) {
            nfds = ip4_socket + 1;
        }
        ip4_socket = net_state->platform.ip4_txrx_udp_socket;
        FD_SET(ip4_socket, read_set);
        if (ip4_socket >= nfds) {
            nfds = ip4_socket + 1;
        }
    }

    if (net_state->platform.ip6_socket_raw) {
        ip6_socket = net_state->platform.ip6_recv_socket;
        FD_SET(ip6_socket, read_set);
        if (ip6_socket >= nfds) {
            nfds = ip6_socket + 1;
        }
    } else {
        ip6_socket = net_state->platform.ip6_txrx_icmp_socket;
        FD_SET(ip6_socket, read_set);
        if (ip6_socket >= nfds) {
            nfds = ip6_socket + 1;
        }
        ip6_socket = net_state->platform.ip6_txrx_udp_socket;
        FD_SET(ip6_socket, read_set);
        if (ip6_socket >= nfds) {
            nfds = ip6_socket + 1;
        }
    }

    probe_nfds = gather_probe_sockets(net_state, write_set);
    if (probe_nfds > nfds) {
        nfds = probe_nfds;
    }

    return nfds;
}