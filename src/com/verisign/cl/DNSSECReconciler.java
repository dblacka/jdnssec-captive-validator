package com.verisign.cl;

import java.util.*;

import org.xbill.DNS.*;

import com.verisign.tat.dnssec.CaptiveValidator;

public class DNSSECReconciler {

    /**
     * Invoke with java -jar dnssecreconciler.jar server=127.0.0.1 \
     * query_file=queries.txt dnskey_query=net dnskey_query=edu
     */
    private CaptiveValidator validator;

    // Options
    public String server;
    public String query;
    public String queryFile;
    public String dnskeyFile;
    public List<String> dnskeyNames;

    DNSSECReconciler() {
        validator = new CaptiveValidator();
    }

    /**
     * Convert a query line of the form: <qname> <qtype> <flags> to a request
     * message.
     *
     * @param query_line
     * @return A query message
     * @throws TextParseException
     * @throws NameTooLongException
     */
    private Message queryFromString(String query_line)
            throws TextParseException, NameTooLongException {

        String[] tokens = query_line.split("[ \t]+");

        Name qname = null;
        int qtype = -1;
        int qclass = -1;

        if (tokens.length < 1)
            return null;
        qname = Name.fromString(tokens[0]);
        if (!qname.isAbsolute()) {
            qname = Name.concatenate(qname, Name.root);
        }

        for (int i = 1; i < tokens.length; i++) {
            if (tokens[i].startsWith("+")) {
                // For now, we ignore flags as uninteresting
                continue;
            }

            int type = Type.value(tokens[i]);
            if (type > 0) {
                qtype = type;
                continue;
            }
            int cls = DClass.value(tokens[i]);
            if (cls > 0) {
                qclass = cls;
                continue;
            }
        }
        if (qtype < 0) {
            qtype = Type.A;
        }
        if (qclass < 0) {
            qclass = DClass.IN;
        }

        Message query = Message.newQuery(Record.newRecord(qname, qtype, qclass));

        return query;
    }

    public void execute() {
    }

    private static void usage() {
        System.err.println("usage: java -jar dnssecreconiler.jar [..options..]");
        System.err.println("       server: the DNS server to query.");
        System.err.println("       query: a name [type [flags]] string.");
        System.err.println("       query_file: a list of queries, one query per line.");
        System.err.println("       dnskey_file: a file containing DNSKEY RRs to trust.");
        System.err.println("       dnskey_query: query 'server' for DNSKEY at given name to trust, may repeat");
    }

    public static int main(String[] argv) {

        DNSSECReconciler dr = new DNSSECReconciler();

        try {
            // Parse the command line options
            for (String arg : argv) {

                if (arg.indexOf('=') < 0) {
                    System.err.println("Unrecognized option: " + arg);
                    usage();
                    return 1;
                }

                String[] split_arg = arg.split("[ \t]*=[ \t]*", 2);
                String opt = split_arg[0];
                String optarg = split_arg[1];

                if (opt.equals("server")) {
                    dr.server = optarg;
                } else if (opt.equals("query_file")) {
                    dr.queryFile = optarg;
                } else if (opt.equals("dnskey_file")) {
                    dr.dnskeyFile = optarg;
                } else if (opt.equals("dnskey_query")) {
                    if (dr.dnskeyNames == null) {
                        dr.dnskeyNames = new ArrayList<String>();
                    }
                    dr.dnskeyNames.add(optarg);
                } else {
                    System.err.println("Unrecognized option: " + opt);
                    usage();
                    return 1;
                }
            }

            // Check for minimum usage
            if (dr.server == null) {
                System.err.println("'server' must be specified");
                usage();
                return 1;
            }
            if (dr.query == null && dr.queryFile == null) {
                System.err.println("Either 'query' or 'query_file' must be specified");
                usage();
                return 1;
            }
            if (dr.dnskeyFile == null && dr.dnskeyNames == null) {
                System.err.println("Either 'dnskey_file' or 'dnskey_query' must be specified");
                usage();
                return 1;
            }

            // Execute the job
            dr.execute();

        } catch (Exception e) {
            e.printStackTrace();
            return 1;
        }

        return 0;
    }
}
