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

informative:

--- abstract

This document introduces a DNSSEC serialization format. It is designed to enable recursive resolvers to provide
the complete DNSSEC validation chain to DNS clients in one request on any transport. It is one mechanism to share
a specific view of the DNS ecosystem and to ensure authenticity without imposing recursive resolution on clients.

--- middle

# Introduction

This document describes a use of the DNS additional record section to transit a serialized DNSSEC proof, and
introduces a new DNS Flag bit (SP)
to be used in addition to DNSSEC OK (DO) indicating the client's intent to obtain a serialized proof of
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

A DNSSEC validating recursive resolver MAY accept DNS queries {{RFC??? Section??}} with the SP bit set.
To process a client DNS query with SP bit set, a resolver MUST initialize an authenticated connection to
the respective nameservers in the resolution process, and constructs the following `ZonePair` structure.

~~~
struct {
    Entering entry;
    Leaving exit;
} ZonePair;
~~~

The `Entering` structure contains information about the `DNSKEY`s and associated (RRSIG) signatures `Signature` in
addition to an integer `KeyIndex` indicating the starting level in the DNS hierarchy for the response data.
Inclusion of the entire proof results in the `KeyIndex` value being set to 0 `root (.)`.

The `Leaving` structures contain information about the `DS` records and corresponding RRSIGs necessary to authenticate
the next level of the authentication chain. For the leaf of the query during resolution, the `Leaving` structures
include the answer for the query and return the associated signatures when available.

The `DNSKEY`, `DS`, and `RRSIG` records follow the uncompressed wire format DNS RRs described in {{DNSSEC}} and
{{RDATA}}.

~~~
struct {
    DNSKEY []RR;
    Signature RRSIG;
    KeyIndex uint8;
} Entering;

union {
    struct {
        DSRecords []RR;
        Signature RRSIG;
    } Delegations;

    struct {
        Answer []RR;
        Signature RRSIG;
    } Leaf;
} Leaving;
~~~

The resolver constructs an in-order sequence of list of `ZonePair`s containing the entire chain. For example:

The resolution of the `A` records for the FQDN `example.com.`, results in the response being the length of X `ZonePairs`:

~~~
ZonePair[0]:
    - Entering:
        - DNSKEY (.)
        - Signature
        - KeyIndex (0)
    - Leaving (Delegations):
        - DSRecords (com.)
        - Signature
ZonePair[1]:
    - Entering:
        - DNSKEY (com.)
        - Signature
        - KeyIndex (1)
    - Leaving (Delegations):
        - DSRecords (example.com.)
        - Signature
ZonePair[2]:
    - Entering:
        - DNSKEY (example.com.)
        - RRSIG
        - KeyIndex (2)
    - Leaving (Leaf):
        - []RR (*dns.A)
        - Signature
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

The value of `KeyIndex` starting at `0` indicates that no levels of the proof chain are skipped by the resolver when
the serialized response is returned to the client. Similarly, the value `1` indicates one level of the chain starting
from one level below the root i.e. TLD, in the serialized response. This is an OPTIONAL optimization a client could use to
provide hints to the resolver in an attempt to reduce the size of the serialized DNS message on the wire. The records
skipped would include the `Entering` and `Leaving` structures for all indices of the chain less than the indicated level
, and `Entering` structure for the matching level. Skip indices less than 0 and greater than the expected length of the
query SHOULD BE treated as invalid and a corresponding error response code SERVFAIL is returned to the client.

For example, a client with a SKIP RR, and KeyIndex 1 for the query provided in the example above would result in:

~~~
ZonePair[0]:
    - Entering: NULL
    - Leaving (Delegations):
        - DSRecords (example.com.)
        - Signature
ZonePair[1]:
    - Entering:
        - DNSKEY (example.com.)
        - RRSIG
        - KeyIndex (2)
    - Leaving (Leaf):
        - []RR (*dns.A)
        - Signature
~~~

The client COULD leverage this optimization when a cache containing the validated DNSKEYs, DS records are cached
preventing repeated transmission of the response data or cryptographic verifications.

## Verification

~~~
                  MATCH DS IN PARENT TO ZSK CHILD
                 ┌─────────────────────────────────┐
                 │                                 │
                 │                                 │
                 ▼                                 │
          ┌────────────────┐              ┌────────┴────────┐
          │                │              │                 │
START     │                │              │                 │   COMPLETE
─────────►│    ENTERING    ├─────────────►│    LEAVING      ├────────►
          │                │              │                 │
          │                │              │                 │
          └────────────────┘              └─────────────────┘

                 DNSKEY                       DS    │ Verified using ZSK
                   ZSK    │                   RRSIG │
                   KSK    ├── Integrity
                   RRSIG  │    of Keys
            ──────────────┘                   Answer│ Verified using ZSK
             Verified using KSK               RRSIG │
~~~

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

The clients obtaining the serialized responses follow the state machine transitions between ENTERING and LEAVING regions
of the serialized responses. The client executes the following algorithm:

~~~
BEGIN Verification(query, chain, starting_index=0):
  UpdateChain(query, &chain, starting_index)
  for index, zone_pair in chain:
    enter_validity = Verify(zone_pair.Entering.DNSKEYs,
                            zone_pair.Entering.RRSIG,
                            getKSK(zone_pair.Entering.DNSKEYs))
    if zone_pair.Leaving is not Leaf:
      leaving_validity = Verify(zone_pair.Leaving.DSs,
                                  zone_pair.Leaving.RRSIG,
                                  getZSK(zone_pair.Entering.DNSKEYs))
      next_enter = HashCompareEqual(zone_pair.Leaving.DS,
                                  ToDS(chain[index+1].Entering.DNSKEY))
      assertTrue(next_enter)
    else:
      leaving_validity = Verify(zone_pair.Leaving.Answer.TYPE,
                                  zone_pair.Leaving.Answer.RRSIG,
                                  getZSK(zone_pair.Entering.DNSKEYs)))
    assertTrue(enter_validity && leaving_validity)
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
COM_DNSKEY = LookupCache(.com., DNSKEY)
Verify(chain[0].Leaving.DS, chain[0].Leaving.RRSIG, COM_DNSKEY)
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
