package com.verisign.cl;

import java.io.BufferedReader;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.PrintStream;
import java.net.SocketTimeoutException;
import java.text.SimpleDateFormat;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.TimeZone;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.xbill.DNS.DClass;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.NameTooLongException;
import org.xbill.DNS.Record;
import org.xbill.DNS.SimpleResolver;
import org.xbill.DNS.TextParseException;
import org.xbill.DNS.Type;

import com.verisign.dnssec.security.CaptiveValidator;
import com.verisign.dnssec.security.SecurityStatus;
import com.verisign.dnssec.security.Util;

public class DNSSECValTool {

    /**
     * Invoke with java -jar dnssecvaltool.jar server=127.0.0.1 \
     * query_file=queries.txt dnskey_query=net dnskey_query=edu
     */
    private CaptiveValidator validator;
    private SimpleResolver resolver;

    private BufferedReader queryStream;
    private Set<Name> zoneNames;

    // Options
    public String server;
    public String query;
    public String queryFile;
    public String dnskeyFile;
    public List<String> dnskeyNames;
    public String errorFile;
    public long count = 0;
    public long queryLineNum = 0;
    public boolean debug = false;
    public boolean trace = false;

    DNSSECValTool() {
        validator = new CaptiveValidator();
    }

    public void setCurrentTime(Instant time) {
        validator.setCustomTime(time);
    }
    public void setValidateAllSignatures(boolean value) {
        validator.setValidateAllSignatures(value);
    }

    /**
     * Convert a query line of the form: <qname> <qtype> <flags> to a request
     * message.
     *
     * @param queryLine
     * @return A query message
     * @throws TextParseException
     * @throws NameTooLongException
     */
    private Message queryFromString(String queryLine)
            throws TextParseException, NameTooLongException {

        String[] tokens = queryLine.split("[ \t]+");

        Name qname = null;
        int qtype = -1;
        int qclass = -1;

        if (tokens.length < 1) {
            return null;
        }
        qname = Name.fromString(tokens[0]);
        if (!qname.isAbsolute()) {
            qname = Name.concatenate(qname, Name.root);
        }

        for (int i = 1; i < tokens.length; i++) {
            if (tokens[i].startsWith("+")) {
                // For now, we ignore flags as uninteresting
                // All queries will get the DO bit anyway
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
            }
        }
        if (qtype < 0) {
            qtype = Type.A;
        }
        if (qclass < 0) {
            qclass = DClass.IN;
        }

        return Message.newQuery(Record.newRecord(qname, qtype, qclass));
    }

    /**
     * Fetch the next query from either the command line or the query file
     *
     * @return a query Message, or null if the query list is exhausted
     * @throws IOException
     */
    private Message nextQuery() throws IOException {
        if (query != null) {
            Message res = queryFromString(query);
            query = null;
            return res;
        }

        if (queryStream == null && queryFile != null) {
            queryStream = new BufferedReader(new FileReader(queryFile));
            queryLineNum = 0;
        }

        while (queryStream != null) {
            String line = queryStream.readLine();
            queryLineNum++;

            if (line == null) {
                return null;
            }

            if (line.startsWith("#")) {
                continue;
            }
            try {
                return queryFromString(line);
            } catch (TextParseException e) {
                Logger log = Logger.getLogger(this.getClass().getName());
                log.log(Level.SEVERE, e, () -> "Encountered a query file parsing issue on line: "
                        + queryLineNum);
                // otherwise, continue
            }
        }

        return null;
    }

    /**
     * Figure out the correct zone from the query by comparing the qname to the
     * list of trusted DNSKEY owner names.
     *
     * @param query
     * @return a zone name
     * @throws IOException
     */
    private Name zoneFromQuery(Message query) throws IOException {

        if (zoneNames == null) {
            zoneNames = new HashSet<>();
            for (String key : validator.listTrustedKeys()) {
                String[] components = key.split("/");
                Name keyname = Name.fromString(components[0]);
                if (!keyname.isAbsolute()) {
                    keyname = Name.concatenate(keyname, Name.root);
                }
                zoneNames.add(keyname);
            }
        }

        Name qname = query.getQuestion().getName();
        for (Name n : zoneNames) {
            if (qname.subdomain(n)) {
                return n;
            }
        }

        return null;
    }

    private Message resolve(Message query) {
        try {
            return resolver.send(query);
        } catch (SocketTimeoutException e) {
            System.err.println("Error: timed out querying " + server + " for "
                    + queryToString(query));
        } catch (IOException e) {
            System.err.println("Error: error querying " + server + " for "
                    + queryToString(query) + ":" + e.getMessage());
        }
        return null;
    }

    private String queryToString(Message query) {
        if (query == null) {
            return null;
        }
        Record question = query.getQuestion();
        return question.getName() + "/" + Type.string(question.getType()) + "/"
                + DClass.string(question.getDClass());
    }

    public void execute() throws IOException {
        PrintStream errorStream;
        // Configure our resolver
        resolver = new SimpleResolver(server);
        resolver.setEDNS(0, 4096, Flags.DO, Collections.emptyList());

        // Create our DNSSEC error stream
        if (errorFile != null) {
            errorStream = new PrintStream(new FileOutputStream(errorFile, true));
        } else {
            errorStream = System.out;
        }

        // Prime the validator
        if (dnskeyFile != null) {
            validator.addTrustedKeysFromFile(dnskeyFile);
        } else {
            for (String name : dnskeyNames) {
                Message qry = queryFromString(name + " DNSKEY");
                Message response = resolve(qry);
                validator.addTrustedKeysFromResponse(response);
            }
        }

        // Log our set of trusted keys
        List<String> trustedKeys = validator.listTrustedKeys();
        if (trustedKeys.isEmpty()) {
            System.err.println("ERROR: no trusted keys found/provided.");
            return;
        }

        for (String key : validator.listTrustedKeys()) {
            System.out.println("Trusted Key: " + key);
        }

        // Iterate over all queries
        Message q = nextQuery();
        long total = 0;
        long validCount = 0;
        long errorCount = 0;

        while (q != null) {

            Name zone = zoneFromQuery(q);
            // Skip queries in zones that we don't have keys for
            if (zone == null) {
                if (debug) {
                    System.out.println("DEBUG: skipping query "
                            + queryToString(q));
                }
                q = nextQuery();
                continue;
            }

            if (debug) {
                System.out.println("DEBUG: querying for: " + queryToString(q));
            }

            Message response = resolve(q);
            if (response == null) {
                System.out.println("ERROR: No response for query: "
                        + queryToString(q));
                continue;
            }
            byte result = validator.validateMessage(response, zone.toString());

            switch (result) {
            case SecurityStatus.BOGUS:
            case SecurityStatus.INVALID:
                errorStream.println("BOGUS Answer:");
                errorStream.println("Query: " + queryToString(q));
                errorStream.println("Response:\n" + response);
                for (String err : validator.getErrorList()) {
                    errorStream.println("Error: " + err);
                }
                errorStream.println("");
                errorCount++;
                break;
            case SecurityStatus.INSECURE:
            case SecurityStatus.INDETERMINATE:
            case SecurityStatus.UNCHECKED:
                errorStream.println("Insecure Answer:");
                errorStream.println("Query: " + queryToString(q));
                errorStream.println("Response:\n" + response);
                for (String err : validator.getErrorList()) {
                    errorStream.println("Error: " + err);
                }
                errorCount++;
                break;
            case SecurityStatus.SECURE:
                if (debug) {
                    System.out.println("DEBUG: response for " + queryToString(q)
                            + " was valid.");
                    System.out.println("Response:\n" + response);
                }
                validCount++;
                break;
            default:
                System.err.println("Unknown security status: " + result);
                break;
            }

            if (++total % 1000 == 0) {
                System.out.println("Completed " + total + " queries: "
                        + validCount + " valid, " + errorCount + " errors.");
            }

            if (count > 0 && total >= count) {
                if (debug) {
                    System.out.println("DEBUG: reached maximum number of queries, exiting");
                }
                break;
            }

            q = nextQuery();
        }

        System.out.println("Completed " + total
                + (total > 1 ? " queries" : " query") + ": " + validCount
                + " valid, " + errorCount + " errors.");
    }

    private static void usage() {
        System.err.println("usage: java -jar dnssecvaltool.jar [..options..]");
        System.err.println("       server:       the DNS server to query.");
        System.err.println("       query:        a name [type [flags]] string.");
        System.err.println("       query_file:   a list of queries, one query per line.");
        System.err.println("       count:        send up to 'count' queries, then stop.");
        System.err.println("       dnskey_file:  a file containing DNSKEY RRs to trust.");
        System.err.println("       dnskey_query: query 'server' for DNSKEY at given name to trust, may repeat.");
        System.err.println("       error_file:   write DNSSEC validation failure details to this file.");
        System.err.println("       debug:        if true, enable debug logging");
        System.err.println("       trace:        if true, enable trace logging");
        System.err.println("       time:         validate responses as if it was <time>");
        System.err.println("       validate_all: in responses with multiple RRSIGs per RRset, require all to validate");
    }

    /**
     * Calculate a date/time from a command line time/offset duration string.
     *
     * @param start
     *                     the start time to calculate offsets from.
     * @param duration
     *                     the time/offset string to parse.
     * @return the calculated time.
     */
    private static Instant convertTime(String timeStr) {

        Logger log = Logger.getLogger(DNSSECValTool.class.getName());

        // This is a heuristic to distinguish UNIX epoch times from the zone
        // file format standard (which is length == 14)
        if (timeStr.length() <= 10) {
            try {
                long epoch = Long.parseLong(timeStr);
                return Instant.ofEpochSecond(epoch);
            } catch (NumberFormatException e) {
                log.severe("Could not parse time specification: " + timeStr + "; using now");
            }
            return Instant.now();
        }

        SimpleDateFormat dateFormatter = new SimpleDateFormat("yyyyMMddHHmmss");
        dateFormatter.setTimeZone(TimeZone.getTimeZone("GMT"));
        DateTimeFormatter fmt = DateTimeFormatter.ofPattern("yyyyMMddHHmmss", Locale.getDefault());
        try {
            return LocalDateTime.parse(timeStr, fmt).atOffset(ZoneOffset.UTC).toInstant();
        } catch (DateTimeParseException e) {
            log.log(Level.SEVERE, e, () -> "Unable to parse time specification: " + timeStr + "; using now");
        }
        return Instant.now();
    }

    // Parse the command line options
    private static void parseCommandLine(DNSSECValTool dr, String[] argv) {
        Logger rootLogger = Logger.getGlobal();

        for (String arg : argv) {

            if (arg.indexOf('=') < 0) {
                System.err.println("Unrecognized option: " + arg);
                usage();
                System.exit(1);
            }

            String[] splitArg = arg.split("=", 2);
            String opt = splitArg[0];
            String optarg = splitArg[1];

            if (opt.equals("server")) {
                dr.server = optarg;
            } else if (opt.equals("query")) {
                dr.query = optarg;
            } else if (opt.equals("query_file")) {
                dr.queryFile = optarg;
            } else if (opt.equals("count")) {
                dr.count = Util.parseInt(optarg, 0);
            } else if (opt.equals("error_file")) {
                dr.errorFile = optarg;
            } else if (opt.equals("dnskey_file")) {
                dr.dnskeyFile = optarg;
            } else if (opt.equals("dnskey_query")) {
                if (dr.dnskeyNames == null) {
                    dr.dnskeyNames = new ArrayList<>();
                }
                dr.dnskeyNames.add(optarg);
            } else if (opt.equals("debug")) {
                dr.debug = Boolean.parseBoolean(optarg);
                if (dr.debug) {
                    rootLogger.setLevel(Level.FINE);
                }
            } else if (opt.equals("trace")) {
                dr.trace = Boolean.parseBoolean(optarg);
                if (dr.trace) {
                    rootLogger.setLevel(Level.FINEST);
                    dr.debug = true;
                }
            } else if (opt.equals("time")) {
                // convert optarg to an Instant
                Instant currentTime = convertTime(optarg);
                dr.setCurrentTime(currentTime);
                System.out.println("currentTime = " + currentTime);
            } else if (opt.equals("validate_all")) {
                dr.setValidateAllSignatures(true);
            } else {
                System.err.println("Unrecognized option: " + opt);
                usage();
                System.exit(1);
            }
        }

        // Check for minimum usage
        if (dr.server == null) {
            System.err.println("'server' must be specified");
            usage();
            System.exit(1);
        }
        if (dr.query == null && dr.queryFile == null) {
            System.err.println("Either 'query' or 'query_file' must be specified");
            usage();
            System.exit(1);
        }
        if (dr.dnskeyFile == null && dr.dnskeyNames == null) {
            System.err.println("Either 'dnskey_file' or 'dnskey_query' must be specified");
            usage();
            System.exit(1);
        }
    }

    public static void main(String[] argv) {

        // And raise the log level quite high
        Logger rootLogger = Logger.getGlobal();
        rootLogger.setLevel(Level.SEVERE);

        DNSSECValTool dr = new DNSSECValTool();

        try {
            parseCommandLine(dr, argv);
            // Execute the job
            dr.execute();

        } catch (Exception e) {
            e.printStackTrace();
            System.exit(1);
        }
    }
}
