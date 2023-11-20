---
###
# Internet-Draft Markdown Template
#
# Rename this file from draft-todo-yourname-protocol.md to get started.
# Draft name format is "draft-<yourname>-<workgroup>-<name>.md".
#
# For initial setup, you only need to edit the first block of fields.
# Only "title" needs to be changed; delete "abbrev" if your title is short.
# Any other content can be edited, but be careful not to introduce errors.
# Some fields will be set automatically during setup if they are unchanged.
#
# Don't include "-00" or "-latest" in the filename.
# Labels in the form draft-<yourname>-<workgroup>-<name>-latest are used by
# the tools to refer to the current version; see "docname" for example.
#
# This template uses kramdown-rfc: https://github.com/cabo/kramdown-rfc
# You can replace the entire file if you prefer a different format.
# Change the file extension to match the format (.xml for XML, etc...)
#
###
title: "Resolver DNSSEC Response Serialization"
abbrev: "Resolver DNSSEC Response Serialization"
category: info

docname: draft-singanamalla-dance-dnssec-serialization-latest
submissiontype: IETF  # also: "independent", "editorial", "IAB", or "IRTF"
number:
date:
consensus: false
v: 3
area: DANCE
workgroup: WG Working Group
keyword:
 - next generation
 - unicorn
 - sparkling distributed ledger
venue:
  group: WG
  type: Working Group
  mail: WG@example.com
  arch: https://example.com/WG
  github: USER/REPO
  latest: https://example.com/LATEST

author:
 -
    fullname: Sudheesh Singanamalla
    organization: University of Washington
    email: sudheesh@cs.washington.edu
 -
    fullname: Ben Weintraub
    organization: Northeastern University
    email: weintraub.b@northeastern.edu
 -
    fullname: Thibault Meunier
    organization: Cloudflare
    email: mail@thibaultmeunier.com

normative:
    DNSSEC:
        =: RFC4034
    RDATA:
        =: RFC1035
    EDNS0:
        =: RFC6891
    RFC1034:
        =: RFC1034
    RFC9102:
        =: RFC9102
    SERIALIZECHAIN:
        =: I-D.agl-dane-serializechain-01

informative:

--- abstract

This document introduces a DNSSEC serialization format. It is designed to enable recursive resolvers to provide
the complete DNSSEC validation chain to DNS clients in one request over any transport. It is one mechanism to share
a specific view of the DNS ecosystem and to ensure authenticity without imposing recursive resolution on clients.

--- middle

# Introduction

This document describes a use of the DNS additional record section to transit a serialized DNSSEC proof, and
introduces a new DNS Flag bit (SP)
to be used, in addition to DNSSEC OK (DO), to indicate the client's intent to obtain a serialized proof of
all RRs necessary to validate the DNSSEC chain.
A recursive resolver performs the necessary queries and
obtains the responses before responding to the client query with a direct answer. The serialization
mechanism with the complete DNSSEC verification chain enables resolvers to
share their view of the DNS ecosystem. Additionally, the transport agnostic nature allows future
DNS protocols, and applications relying on DNS infrastructure as a trust anchor to be interoperable allowing a higher
focus on the transport layer innovations than addressing DNS interoperability.
<!-- Examples for an email would be any kind of domain validation at the application layer: Certificate Authority, DNSLink, ENS, Bluesky, etc... -->

# Conventions and Definitions

{::boilerplate bcp14-tagged}

# DNSSEC Serialization

## Construction using a Recursive Resolver

A DNSSEC validating recursive resolver MAY accept DNS queries {{Section 2.4 of RFC1034}} with the SP bit set.
To process a client DNS query with SP bit set, a resolver MUST initialize an authenticated connection to
the respective name servers in the resolution process, and construct the following data structures.

The following structures comprise a single resource yet, but are also designed hold well-formed resource records within them in a nested structure.

Each resource record contains an `RR_Header` structure.
The `RR_Header` structure is a resource record header {{{{Section 3.2.1 of RFC1035}}}}, which we keep in place, to maintain backwards compatibility with clients and libraries who are expecting well-formed resource records. The structure of `RR_Header` is the following.

~~~
type RR_Header struct {
	Name     string
	Rrtype   uint16
	Class    uint16
	Ttl      uint32
	Rdlength uint16
}
~~~

`RR_Header` MAY contain values in any of the fields, but does not need to. These are not used in verification, but could be used for debugging.

The core structure of this DNSSEC chain serialization protocol is the `Zone` structure. It MUST contain the domain name of the DNS zone in `Name`, the zone name of the previously traversed zone in `PreviousName`, and the index of the zone signing key (ZSK) used to sign the enclosed records `ZSKIndex`. The remaining fields are either lists of resource records of a particular type, or an 8-bit unsigned integer representing the number of records in each list. The resource records contained in lists include `DNSKEY`, `RRSIG DNSKEY`, `DS`, and `RRSIG DS`. The `Leaves` list contains resource records that are unknown until they are received. Their type depends on the DNS configuration---the types of resource records in `Leaves` MAY be any resource record type not already listed. The final field, `LeavesSigs`, contains the list of `RRSIG`s of the resource records in `Leaves`. The `DS`, `DNSKEY`, `RRSIG`, and leaf records all MUST follow the uncompressed wire format DNS RRs described in {{DNSSEC}} and {{RDATA}}.

~~~
type Zone struct {
	Hdr           RR_Header
	Name          Name
	PreviousName  Name
	ZSKIndex      uint8
	NumKeys       uint8
	Keys          []DNSKEY
	NumKeySigs    uint8
	KeySigs       []RRSIG
	NumDS         uint8
	DSSet         []DS
	NumDSSigs     uint8
	DSSigs        []RRSIG
	NumLeaves     uint8
	Leaves        []RR
	NumLeavesSigs uint8
	LeavesSigs    []RRSIG
}
~~~


These zones are listed the topmost data structure called `Chain` (see below). In `Chain`, the field `NumZones` stores the number of `Zone`s in `Zones`. These `Zones` are traversed during verification.

~~~
type Chain struct {
	Hdr           RR_Header
	Version       uint8
	InitialKeyTag uint16
	StartingZone  uint8
	NumZones      uint8
	Zones         []Zone
}
~~~


The `Version` field of `Chain` MUST contain the version number of this DNSSEC serialization protocol. This draft describes version 1. The `InitialKeyTag` field MUST contain a short digest of the trust anchor's key signing key (KSK) or be set to zero to use the IANA root. The integer `StartingZone` indicates the starting level in the DNS hierarchy for the response data. A `KeyIndex` value being set to 0, means the entire proof chain all the way to the root (.) is included.

The resolution of the `AAAA` records for the FQDN `example.com.`, results in a response with three `Zone`s:

~~~
Zone[0]:
    - Hdr
    - Name (example.com.)
    - PreviousName (NONE)
    - ZSKIndex
    - NumKeys (1)
    - Keys
        - DNSKEY (example.com.)
    - NumKeySigs (1)
    - KeySigs
        - Signature (example.com.)
    - NumDS (1)
    - DSSet
        - DS (com.)
    - NumDSSigs (1)
    - DSSigs
        - Signature (com.)
    - NumLeaves (1)
    - Leaves
        - RR (AAAA)
    - NumLeavesSigs (1)
    - LeavesSigs
        - Signature (AAAA)
Zone[1]:
    - Hdr
    - Name (com.)
    - PreviousName (example.com.)
    - ZSKIndex
    - NumKeys (1)
    - Keys
        - DNSKEY (com.)
    - NumKeySigs (1)
    - KeySigs
        - Signature (com.)
    - NumDS (1)
    - DSSet
        - DS (.)
    - NumDSSigs (1)
    - DSSigs
        - Signature (.)
Zone[2]:
    - Hdr
    - Name (.)
    - PreviousName (com.)
    - ZSKIndex
    - NumKeys (1)
    - Keys
        - DNSKEY (.)
    - NumKeySigs (1)
    - KeySigs
        - Signature (.)
    - NumDS (1)
    - DSSet
        - DS (.)
    - NumDSSigs (1)
    - DSSigs
        - Signature (.)
~~~

## Client

Clients MAY communicate with a validating recursive resolver using the protocol of their choice and MUST set both the DO
and SP bits in the DNS query sent to the recursive resolver. The resolver performs the required resolutions, serializes
the proof and returns the serialized proof as a resource record in the ADDITIONAL section of the response as well as
the answer associated with the query in the ANSWER section.

The client uses the OPT RR {{EDNS0}} and uses flag `SP`. Both `DO` and `SP` bits MUST be true, and the
remaining flags Z set to zero by the client. They SHOULD be ignored by the receiving resolver.

                +0 (MSB)                            +1 (LSB)
       +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
    0: |         EXTENDED-RCODE        |            VERSION            |
       +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
    2: | DO| SP|                       Z                               |
       +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+

The usage of the `SP` comes with an OPTIONAL usage of a `SKIP RR` included in the additional section of the DNS Message
to the resolver by the client. SKIP RR Type contains a `uint8` indicating the KeyIndex from the root to skip:

~~~
struct {
    struct {
        string Name;
        uint8  Rrtype;
        uint32 Ttl;
        uint16 Rdlength;
    } RR_Header;
    uint8 KeyIndex;
} SKIP;
~~~

The value of `InitialKeyIndex` starting at `0` indicates that no levels of the proof chain are skipped by the resolver when
the serialized response is returned to the client. Alternatively, providing a digest of the trust anchor's key signing key (KSK) indicates where the client can stop validating as it traverses the DNS hierarchy. This is an OPTIONAL optimization a client could use to
provide hints to the resolver in an attempt to reduce the size of the serialized DNS message on the wire. The records
skipped would be the `Zone` structures for all zones beyond the purview of the provided trust anchor.

The client COULD leverage this optimization when a cache containing the validated DNSKEYs, DS records are cached
preventing repeated transmission of the response data or cryptographic verifications.

### Resolver Verification

<!-- unclear -->

Similar to DNSSEC, a validating recursive resolver MUST individually validate the signed responses obtained from the
various name servers during query resolution. All responses MUST be cryptographically valid for the serialization to be
constructed. In case of failure, the server indicates a failed resolution with the appropriate SERVFAIL response code
and return the invalid serialization to the client if the CD bit is set, in addition to the SP and DO bits.

If the query to the resolver contains the `SP` bit set in the OPT RR, it MUST check for the existence of the `SKIP`
records in the additional section of the message. The SKIP result is included in the response returned to the client
and the chain is updated accordingly.

### Client Verification

The clients obtaining the serialized responses pop `Zone`s off the . The client executes the following algorithm:

~~~
BEGIN Verification(query, chain, starting_zone):
  UpdateChain(query, &chain, starting_zone)
  for index, zone in chain.Zones:
    key_validity = Verify(zone.Keys,
                          zone.KeySigs,
                          getKSK(zone.Keys))
    assertTrue(key_validity)

    if length(zone.Leaves) == 0:
      ds_sig_validity = Verify(zone.DSSet,
                               zone.DSSigs,
                               getZSKs(zone.Keys))
      ds_hash_validity = HashCompareEqual(zone.DSSet,
                                          ToDS(
                                            getKSK(
                                              chain.Zones[index+1].Keys
                                            )
                                          )
                                         )
      assertTrue(ds_sig_validity && ds_hash_validity)
    else:
      leaves_sig_validity = Verify(zone.Leaves,
                                   zone.LeavesSigs,
                                   getZSKs(zone.Keys))
      assertTrue(leaves_sig_validity)
  return True
END
~~~

The `UpdateChain` method updates the returned serialized Chain response and includes information about the DNSKEY, DS
resource records from the validated cache by reconstructing the chain which is then validated. The `Verify()` method
takes as arguments the DNS RRs, the signature RRSIG, and a DNSKEY returning a boolean. Similarly `HashCompareEqual` takes as input two DS
records and compares them returning a boolean.

Note that it is possible to perform cryptographic validations of partial chains without updating the chain explicitly
to include skipped records if the records are already present in a trusted cache. To successfully confirm the validation
to the root trust anchors, the DNSKEYs from the cache at the domain hierarchy level are necessary to validate the
signatures associated with the Leaving section of the first element in the chain. In the example presented above:

~~~
COM_DNSKEY = getZsk(LookupCache(.com., DNSKEY))
Verify(chain.Zones[0].DSSet, chain.Zones[0].DSSigs, COM_DNSKEY)
~~~

## Resolver Cache Considerations

Validating resolvers continue to maintain their caches as is current practice.

## Modifications to Existing RFCs

TODO: Need help with this one. I've referenced a few RFCs with this draft so far which might be extended.
It looks like we are introducing new RRType and bits for which specific numbers need to be granted.

# Security Considerations

<!-- TODO how does this protocol impact existing security -->

Many public recursive resolvers today used by clients validate DNSSEC responses and protect their clients by
returning a DNS Error Code (RCODE) in the response. However, responses to queries with the client DO bit set
result in a partial response of the intended resource records and its corresponding signature. As a result,
clients using a validating recursive resolver delegate their trust to the resolver. A client stub with the
validation capabilities should be able to verify the correctness of the responses further reducing the amount
of implicit trust placed in the resolver.

Responses sent for the DNS queries include larger responses due to the existence of the serialized proof chain
potentially resulting in DDoS attacks. Existing practices to prevent DDoS attacks for larger DNSSEC responses
could continue to be considered and improved.

# Performance Considerations

The serialization of the necessary RRs and their RRSIGs by the recursive resolver does not
adversely impact resolution latency (network). The cryptographic computational overheads to verify the serialized
responses and the accompanying answer is minimal. This section provides indicational performance using an
implementation of the proposal in Go. This implementation includes the entire proof chain with no optimizations for the queries.

## Size Overheads

The following measurements are performed for 10000 queries requesting the A records from the recursive resolver. The median size of the
response is 2172 Bytes indicating a 247% increase in size compared to the client recursively performing all the queries
required to validate the DNSSEC responses. For various protocols, the sizes are the following:

~~~
| Protocol | Median N/W RX | Percent Increase |
|----------|---------------|------------------|
| Do53 UDP | 2172 Bytes    | 247.5%           |
| Do53 TCP | 2178 Bytes    | 248.5%           |
| DoH      | 2180 Bytes    | 248.8%           |
~~~

## Measured Latency Overheads

The median response times for the queries including the proof compared to the Leaf only responses from a validating
recursive resolver are as follows:

~~~
| Protocol | Median Latency (ms) | Percent Increase |
|----------|---------------------|------------------|
| Do53 UDP | 172.54              | 0.15%            |
| Do53 TCP | 192.29              | 0.45%            |
| DoH      | 173.44              | 1.10%            |
~~~

# IANA Considerations

Register SP field, SKIP resource record

--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.

{{RFC9102}}
{{SERIALIZECHAIN}}

## Test Vectors
{:numbered="false"}



# Appendix
{:numbered="false"}

## Test vectors
{:numbered="false"}

TODO
