# DNSSECValTool

This is a command line Java tool for doing DNSSEC response validation against
a single authoritative DNS server.

```bash
usage: java -jar dnssecvaltool.jar [..options..]
       server:       the DNS server to query.
       query:        a name [type [flags]] string.
       query_file:   a list of queries, one query per line.
       count:        send up to'count' queries, then stop.
       dnskey_file:  a file containing DNSKEY RRs to trust.
       dnskey_query: query 'server' for DNSKEY at given name to trust,
                     may repeat
       error_file:   write DNSSEC validation failure details to this file
```

The `DNSSECValTool` needs a server to query ('`server`'), a query or list of
queries ('query' or 'query_file'), and a set of DNSKEYs to trust ('`dnskey_file`'
or '`dnskey_query`') -- these keys MUST be the ones used to sign everything in the
responses.

By default it logs everything to stdout.  DNSSEC validation errors (which is
most of the output) can be redirected to a file (which will be appended to if it
already exists).

Note that the DNSSECValTool will skip queries if the `qname` isn't a
subdomain (or matches) the names of the DNSKEYs that have been added.

## query_file

This is a file of one query per line, with a query formatted as:

```text
qname [qtype] [qclass] [flags]
```

For example:

```text
pietbarber.com ns +ad
blacka.com a IN +do
verisign.com
```

The DO bit is redundant since all queries will be made with the DO bit set.

Note: at the moment, flags are ignored.

## `dnskey_file`

The is a list of DNSKEYs in zone file format.  It will ignore zone file comments
and non-DNSKEY records, so you can just use dig output:

```bash
dig @0 edu dnskey +dnssec > keys
dig @0 net dnskey +dnssec >> keys
```

## `dnskey_query`

For each one of these, do a DNSKEY query to the server for that name, and add
the resultant keys to the set of trusted keys.

## Examples

1. Query "a.edu-servers.net", fetching the .edu keys directly from
   that server.  Use queries.txt for the queries, and log all DNSSEC
   validation failures to `dnssecvaltool_errors.log`.
```bash
java -jar dnssecvaltool.jar server=a.edu-servers.net \
     dnskey_query=edu \
     query_file=queries.txt \
     error_file=dnssecvaltool_errors.log
```
2. Query localhost with a single query for `edu/soa`, using stored keys
   in the file 'keys'.  Validation failures will be logged to stdout.
```bash
java -jar dnssecvaltool.jar server=127.0.0.1 \
     dnskey_file=keys \
     query="edu soa"
```
3. Query "a.gov-servers.net", fetching the .gov keys directly from
   that server, then query for nasa.gov/A.
```bash
java -jar dnssecvaltool.jar server=a.gov-servers.net \
     dnskey_query=gov \
     query="nasa.gov a"
```
