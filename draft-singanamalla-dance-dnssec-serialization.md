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
    email: thibault@cloudflare.com

normative:

informative:


--- abstract

This document introduces a transport agnostic serialization format for recursive resolvers to
respond to client requests with DNSSEC OK bit and a newly introduced Serialized Proof (SP) bit
with a serialized response including the complete set of records that can be used to validate
the DNSSEC chain. This proposal obviates the need to perform additional DNS RR queries for DNSKEY
and DS records and their associated RRSIG signatures. This proposal is aimed at the communication
between the client stub resolver and a recursive resolver delegated to perform the queries and can
also be consumed by other transport mechanisms.

--- middle

# Introduction

This document introduces and describes an experimental extension and introduces a new DNS Flag bit (SP)
to be used in addition to DNSSEC OK (DO) indicating the client's intent to obtain a serialized proof of
all necessary DNSSEC RRs to validate the chain. A recursive resolver performs the necessary queries and
obtains the responses before responding to the client query with a direct answer. However, for DNSSEC aware
clients, the response obtained from the recursive resolver containing the requested resource records and
the corresponding signature RRSIG record results in additional queries to the resolver to obtain the DNSKEY
and DS resource records along with their associated signature records. This results in additional DNS queries
made by the client to the resolver which could be potentially cached by the resolver and returned immediately.
Failures in caching however result in the recursive resolver performing the necessary queries again resulting in
increased DNS response latency for DNSSEC validating stubs.

The serialization mechanism with the complete DNSSEC verification chain enables resolvers to
share their view of the DNS ecosystem. Additionally, the transport agnostic nature allows future
DNS protocols, and application relying on DNS infrastructure to be easily interoperable allowing a higher
focus on the transport layer innovations than addressing DNS interoperability.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

MAY, MUST, and others

# DNSSEC Serialization

## Construction using a Recursive Resolver

The proposed standard requires a DNSSEC validating recursive resolver accepting client queries with the SP bit set.
The resolver initializes secure connections to the respective nameservers in the resolution process of a client query
and constructs the following `ZonePair` structure.

~~~
struct ZonePair {
    Entering entry;
    Leaving exit;
}
~~~

The `Entering` structure contains information about the `DNSKEY`s and associated (RRSIG) signatures `Signature` in
addition to an integer `KeyIndex` indicating the starting level in the DNS hierarchy for the response data.
Inclusion of the entire proof results in the `KeyIndex` value being set to 0 `root (.)`.

The `Leaving` structures contain information about the `DS` records and corresponding RRSIGs necessary to authenticate
the next level of the authentication chain. For the leaf of the query during resolution, the `Leaving` structures
include the answer for the query and return the associated signatures when available.

~~~
struct Entering {
    DNSKEY []RR;
    Signature RRSIG;
    KeyIndex uint8;
}

union Leaving {
    struct Delegations {
        DSRecords []RR;
        Signature RRSIG;
    };

    struct Leaf {
        Answer []RR;
        Signature RRSIG;
    };
}
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
        - DNSKEY (.com)
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

## Verification

## Resolver Cache Considerations

## Modifications to Existing RFCs

# Security Considerations

Many public recursive resolvers today used by clients validate DNSSEC responses and protect their clients by
returning a DNS Error Code (RCODE) in the response. However, responses to queries with the client DO bit set
result in a partial response of the intended resource records and its corresponding signature. As a result,
clients using a validating recursive resolver delegate their trust to the resolver. A client stub with the
validation capabilities should be able to verify the correctness of the responses further reducing the amount
of implicit trust placed in the resolver.

# Performance Considerations

We posit that the serialization of the necessary RRs and their RRSIGs by the recursive resolver does not
adversely impact resolution latency (network). The cryptographic computational overheads to verify the serialized
responses and the accompanying answer is minimal.

## Size Overheads

## Measured Latency Overheads

# IANA Considerations

Register SP field

--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.

## Test Vectors
{:numbered="false"}



# Appendix
{:numbered="false"}

## Test vectors
{:numbered="false"}

TODO
