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


TODO
+ novelty: share view of DNS, transport agnostic DNS format
+ replace https://datatracker.ietf.org/doc/html/rfc9102 ?

# Conventions and Definitions

{::boilerplate bcp14-tagged}

MAY, MUST, and others

# DNSSEC Serialization


Construction (using a recursive resolver)
+ requirements on the dns resolver
+ state-machine
+ wireformat

verification
+ state machine
+ error messages
+ authenticated denial
+ trust anchor and root key rotation/agility

caching
+ expiration
+ pre-fetch
+ increase dns ttl?

Modification of existing RFCs

+ request over DNS-o-UDP
+ request over DNS-o-TCP
+ request over DNS-o-HTTP


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

TODO
+ overview of size overhead
+ UDP packet?

# IANA Considerations

Register SP field

--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.


# Apendix

## Test vectors

TODO