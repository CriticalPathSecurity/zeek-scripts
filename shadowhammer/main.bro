##! Original Author - Vlad Grigorescu
##! Identifier="2019-02-18"
##! Iteration="1.0"
##! Description="Detects ARP spoofing"
##! Protocol="ARP"
##! CreationDate="2019-02-18"
##! LastUpdate="2019-02-18"

@load base/frameworks/notice
@load shadowhammermac.bro

module ARP;

export {
    redef enum Log::ID += { LOG };

    redef enum Notice::Type += {
            Addl_MAC_Mapping,                # another MAC->addr seen beyond just one
            Bad_ARP_Packet,                        # bad arp packet received
            Cache_Inconsistency,                # MAC/addr pair seen in request/reply different
                                            # from that in the ARP_cache
            Mapping_Changed,                # reply gives different value than previously seen
            Source_MAC_Mismatch,                # source MAC doesn't match mappings
            ShadowHammer,
            Unsolicited_Reply                # could be poisoning; or just gratuitous
    };

    type Info: record {
            ts:                time                &log;
            ## The requestor's MAC address.
            src_mac:        string                &log &optional;
            ## The requestor's IP address, if known. This is populated based
            ## on ARP traffic seen to this point.
            src_addr:        addr                &log &optional;
            ## The responder's MAC address.
            dst_mac:        string                &log &optional;
            ## The responder's IP address, if known. This is populated based
            ## on ARP traffic seen to this point.
            dst_addr:        addr                &log &optional;
            ## Flag to indicate that a response was unsolicited
            unsolicited:        bool                &log &default=F;
            ## Flag to indicate that a response was never received
            no_resp:        bool                &log &default=F;
            ## The IP address that is requested in the ARP request
            who_has:        addr                &log &optional;
            ## The assocaited MAC address from the ARP response
            is_at:                string                &log &optional;
    };

    global log_arp: event(rec: Info);
}

redef capture_filters += { ["arp"] = "arp" };

global expired_request: function(t: table[string, addr, addr] of Info, idx: any): interval &redef;

type State: record {
    mac_addr:        string;
    ip_addr:        addr;
    assoc_ips:        set[addr];
    requests:        table[string, addr, addr] of Info
                        &create_expire = 1 min
                        &expire_func = expired_request;
};
global arp_states: table[string] of State;

# ARP responses we've seen: indexed by IP address, yielding MAC address.
global ARP_cache: table[addr] of string;

# A somewhat general notion of broadcast MAC/IP addresses
const broadcast_mac_addrs = { "00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff", };
const broadcast_addrs = { 0.0.0.0, 255.255.255.255, };

# Create a new arp_request record with the given src and dst fields
function new_arp_request(mac_src: string, mac_dst: string): Info
    {
    local request: Info;
    request$ts = network_time();
    request$src_mac = mac_src;
    request$dst_mac = mac_dst;

    return request;
    }

# Create a new state record for the given MAC address
function new_arp_state(mac_addr: string): State
    {
    local state: State;
    state$mac_addr = mac_addr;

    return state;
    }

# Returns the IP address associated with a MAC address, if we've seen one.
# Otherwise just returns the MAC address/
function addr_from_mac(mac_addr: string): string
    {
    return mac_addr in arp_states ?
            fmt("%s", arp_states[mac_addr]$ip_addr) : mac_addr;
    }

# Completes an Info record by populating the src and dst IP addresses, if
# known, and logs the ARP traffic via the Log framework
function log_request(rec: Info)
    {
    if ( rec$src_mac in arp_states )
            rec$src_addr = arp_states[rec$src_mac]$ip_addr;

    if ( rec$dst_mac in arp_states )
            rec$dst_addr = arp_states[rec$dst_mac]$ip_addr;

    Log::write(ARP::LOG, rec);
    }

# Expiration function which is called when a ARP request does not receive
# a valid response within the expiration timeout period.
function expired_request(t: table[string, addr, addr] of Info, idx: any): interval
    {
    local SHA: string;
    local SPA: addr;
    local TPA: addr;

    [SHA, SPA, TPA] = idx;
    local request = t[SHA, SPA, TPA];
    request$no_resp = T;

    log_request(request);

    return 0 sec;
    }

# Create association between MAC address and an IP address. This is *not* an
# association advertised in an ARP reply (those are tracked in ARP_cache), but
# instead the pairing of hardware address + protocol address as expressed in
# an ARP request or reply header.
function mac_addr_association(mac_addr: string, a: addr)
    {

    # Ignore broadcast and network addresses (IP and Ethernet)
    if ( mac_addr in broadcast_mac_addrs || a in broadcast_addrs )
            return;

    # Get state record
    if ( mac_addr !in arp_states )
            arp_states[mac_addr] = new_arp_state(mac_addr);
    local arp_state = arp_states[mac_addr];

    # Determine if MAC has more than 1 associated IP.
    if ( a !in arp_state$assoc_ips && |arp_state$assoc_ips| > 0 )
            NOTICE([$note=Addl_MAC_Mapping, $src=a,
                    $msg=fmt("Additional mapping for MAC address %s found", mac_addr)]);

    arp_state$ip_addr = a;
    add arp_state$assoc_ips[a];

    if ( a in ARP_cache && ARP_cache[a] != mac_addr )
            NOTICE([$note=Cache_Inconsistency, $src=a,
                    $msg=fmt("Mapping for %s to %s doesn't match cache of %s", mac_addr, a, ARP_cache[a])]);
    }

event bro_init() &priority=5
    {
    Log::create_stream(ARP::LOG, [$columns=Info, $ev=log_arp]);
    }

# Bad ARPs can occur when:
#         - type/size pairs are not OK for HW and L3 addresses (Ethernet=6, IP=4)
#         - opcode is neither request (1) nor reply (2)
#         - MAC src address != ARP sender MAC address
event bad_arp(SPA: addr, SHA: string, TPA: addr, THA: string, explanation: string)
    {
    NOTICE([$note=Bad_ARP_Packet, $src=SPA,
            $msg=fmt("Bad-arp %s(%s) ? %s(%s): %s", SPA, SHA, TPA, THA, explanation)]);
    }

event arp_reply(mac_src: string, mac_dst: string, SPA: addr, SHA: string, TPA: addr, THA: string)
{
    if ( shadowhammermac in mac_dst  )
    {
    NOTICE([$note=ShadowHammer, $src=SPA,
            $msg=fmt("ShadowHammer %s(%s) ? %s(%s)", SPA, SHA, TPA, THA)]);
    }
}

event arp_reply(mac_src: string, mac_dst: string, SPA: addr, SHA: string, TPA: addr, THA: string)
    {
    mac_addr_association(SHA, SPA);
    mac_addr_association(THA, TPA);

    local arp_state: State;
    arp_state = arp_states[THA];

    local msg = fmt("%s -> %s: %s is-at %s",
            addr_from_mac(mac_src), addr_from_mac(mac_dst), SPA, SHA);

    # Check for source mac mismatch
    local mismatch = SHA != mac_src;
    if ( mismatch )
            NOTICE([$note=Source_MAC_Mismatch, $src=SPA, $msg=msg]);

    # Check if reply is unsolicited and get request record
    local request: Info;
    if ( [THA, TPA, SPA] !in arp_state$requests ) {
            request = new_arp_request(THA, SHA);
            request$unsolicited = T;

            NOTICE([$note=Unsolicited_Reply, $src=SPA,
                    $msg=fmt("%s: request[%s, %s, %s]", msg, THA, TPA, SPA)]);
    } else {
            request = arp_state$requests[THA, TPA, SPA];
            delete arp_state$requests[THA, TPA, SPA];
    }
    request$is_at = SHA;

    # Check reply against current ARP_cache
    local mapping_changed = SPA in ARP_cache && ARP_cache[SPA] != SHA;
    if ( mapping_changed )
            NOTICE([$note=Mapping_Changed, $src=SPA,
                    $msg=fmt("%s: was %s", msg, ARP_cache[SPA])]);

    log_request(request);

    ARP_cache[SPA] = SHA;
    }
