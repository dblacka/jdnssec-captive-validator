/***************************** -*- Java -*- ********************************\
 *                                                                         *
 *   Copyright (c) 2009 VeriSign, Inc. All rights reserved.                *
 *                                                                         *
 * This software is provided solely in connection with the terms of the    *
 * license agreement.  Any other use without the prior express written     *
 * permission of VeriSign is completely prohibited.  The software and      *
 * documentation are "Commercial Items", as that term is defined in 48     *
 * C.F.R.  section 2.101, consisting of "Commercial Computer Software" and *
 * "Commercial Computer Software Documentation" as such terms are defined  *
 * in 48 C.F.R. section 252.227-7014(a)(5) and 48 C.F.R. section           *
 * 252.227-7014(a)(1), and used in 48 C.F.R. section 12.212 and 48 C.F.R.  *
 * section 227.7202, as applicable.  Pursuant to the above and other       *
 * relevant sections of the Code of Federal Regulations, as applicable,    *
 * VeriSign's publications, commercial computer software, and commercial   *
 * computer software documentation are distributed and licensed to United  *
 * States Government end users with only those rights as granted to all    *
 * other end users, according to the terms and conditions contained in the *
 * license agreement(s) that accompany the products and software           *
 * documentation.                                                          *
 *                                                                         *
\***************************************************************************/

package com.verisign.dnssec.security;

import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.ListIterator;
import java.util.logging.Logger;

import org.xbill.DNS.DClass;
import org.xbill.DNS.DNSKEYRecord;
import org.xbill.DNS.NSEC3PARAMRecord;
import org.xbill.DNS.NSEC3Record;
import org.xbill.DNS.Name;
import org.xbill.DNS.NameTooLongException;
import org.xbill.DNS.RRset;
import org.xbill.DNS.TextParseException;
import org.xbill.DNS.Type;
import org.xbill.DNS.utils.base32;
import org.xbill.DNS.Record;

import com.verisign.dnssec.security.SignUtils.ByteArrayComparator;

public class NSEC3ValUtils {

    private NSEC3ValUtils() {
        throw new IllegalStateException("NSEC3ValUtils class");
    }

    // FIXME: should probably refactor to handle different NSEC3
    // parameters more efficiently.
    // Given a list of NSEC3 RRs, they should be grouped according to
    // parameters. The idea is to hash and compare for each group
    // independently, instead of having to skip NSEC3 RRs with the
    // wrong parameters.
    private static Name asteriskLabel = Name.fromConstantString("*");
    private static Logger stLog = Logger.getLogger(NSEC3ValUtils.class.getName());
    private static final base32 b32 = new base32(base32.Alphabet.BASE32HEX, false, false);

    public static boolean supportsHashAlgorithm(int alg) {
        return (alg == NSEC3Record.SHA1_DIGEST_ID);
    }

    public static void stripUnknownAlgNSEC3s(List<NSEC3Record> nsec3s) {
        if (nsec3s == null) {
            return;
        }

        for (ListIterator<NSEC3Record> i = nsec3s.listIterator(); i.hasNext();) {
            NSEC3Record nsec3 = i.next();

            if (!supportsHashAlgorithm(nsec3.getHashAlgorithm())) {
                i.remove();
            }
        }
    }

    public static boolean isOptOut(NSEC3Record nsec3) {
        return (nsec3.getFlags()
                & NSEC3Record.Flags.OPT_OUT) == NSEC3Record.Flags.OPT_OUT;
    }

    /**
     * Given a list of NSEC3Records that are part of a message, determine the
     * NSEC3 parameters (hash algorithm, iterations, and salt) present. If there
     * is more than one distinct grouping, return null;
     *
     * @param nsec3s
     *                   A list of NSEC3Record object.
     * @return A set containing a number of objects (NSEC3Parameter objects)
     *         that correspond to each distinct set of parameters, or null if
     *         the nsec3s list was empty.
     */
    public static NSEC3Parameters nsec3Parameters(List<NSEC3Record> nsec3s) {
        if ((nsec3s == null) || (nsec3s.isEmpty())) {
            return null;
        }

        NSEC3Parameters params = new NSEC3Parameters(nsec3s.get(0));
        ByteArrayComparator bac = new ByteArrayComparator();

        for (NSEC3Record nsec3 : nsec3s) {
            if (!params.match(nsec3, bac)) {
                return null;
            }
        }

        return params;
    }

    /**
     * Given a hash and an a zone name, construct an NSEC3 ownername.
     *
     * @param hash
     *                     The hash of an original name.
     * @param zonename
     *                     The zone to use in constructing the NSEC3 name.
     * @return The NSEC3 name.
     */
    private static Name hashName(byte[] hash, Name zonename) {
        try {
            return new Name(b32.toString(hash).toLowerCase(), zonename);
        } catch (TextParseException e) {
            // Note, this should never happen.
            return null;
        }
    }

    /**
     * Given a set of NSEC3 parameters, hash a name.
     *
     * @param name
     *                   The name to hash.
     * @param params
     *                   The parameters to hash with.
     * @return The hash.
     */
    private static byte[] hash(Name name, NSEC3Parameters params) {
        try {
            return params.hash(name);
        } catch (NoSuchAlgorithmException e) {
            stLog.warning("Did not recognize hash algorithm: " + params.alg);
            return new byte[0];
        }
    }

    /**
     * Given the name of a closest encloser, return the name *.closest_encloser.
     *
     * @param closestEncloser
     *                            The name to start with.
     * @return The wildcard name.
     */
    private static Name ceWildcard(Name closestEncloser) {
        try {
            return Name.concatenate(asteriskLabel, closestEncloser);
        } catch (NameTooLongException e) {
            return null;
        }
    }

    /**
     * Given a qname and its proven closest encloser, calculate the "next
     * closest" name. Basically, this is the name that is one label longer than
     * the closest encloser that is still a subdomain of qname.
     *
     * @param qname
     *                            The qname.
     * @param closestEncloser
     *                            The closest encloser name.
     * @return The next closer name.
     */
    private static Name nextClosest(Name qname, Name closestEncloser) {
        int strip = qname.labels() - closestEncloser.labels() - 1;

        return (strip > 0) ? new Name(qname, strip) : qname;
    }

    /**
     * Find the NSEC3Record that matches a hash of a name.
     *
     * @param hash
     *                     The pre-calculated hash of a name.
     * @param zonename
     *                     The name of the zone that the NSEC3s are from.
     * @param nsec3s
     *                     A list of NSEC3Records from a given message.
     * @param params
     *                     The parameters used for calculating the hash.
     * @param bac
     *                     An already allocated ByteArrayComparator, for reuse.
     *                     This may be null.
     *
     * @return The matching NSEC3Record, if one is present.
     */
    private static NSEC3Record findMatchingNSEC3(byte[] hash, Name zonename,
            List<NSEC3Record> nsec3s, NSEC3Parameters params,
            ByteArrayComparator bac) {
        Name n = hashName(hash, zonename);

        for (NSEC3Record nsec3 : nsec3s) {
            // Skip nsec3 records that are using different parameters.
            if (!params.match(nsec3, bac)) {
                continue;
            }

            if (n.equals(nsec3.getName())) {
                return nsec3;
            }
        }

        return null;
    }

    /**
     * Given a hash and a candidate NSEC3Record, determine if that NSEC3Record
     * covers the hash. Covers specifically means that the hash is in between
     * the owner and next hashes and does not equal either.
     *
     * @param nsec3
     *                  The candidate NSEC3Record.
     * @param hash
     *                  The precalculated hash.
     * @param bac
     *                  An already allocated comparator. This may be null.
     * @return True if the NSEC3Record covers the hash.
     */
    private static boolean nsec3Covers(NSEC3Record nsec3, byte[] hash,
            ByteArrayComparator bac) {
        Name ownerName = nsec3.getName();
        byte[] owner = b32.fromString(ownerName.getLabelString(0));
        byte[] next = nsec3.getNext();

        // This is the "normal case: owner < next and owner < hash < next
        if ((bac.compare(owner, hash) < 0) && (bac.compare(hash, next) < 0)) {
            return true;
        }
        // this is the end of zone case: next < owner and hash > owner or hash <
        // next
        return ((bac.compare(next, owner) <= 0)
                && ((bac.compare(hash, next) < 0)
                        || (bac.compare(owner, hash) < 0)));
        // Otherwise, the NSEC3 does not cover the hash.
    }

    /**
     * Given a pre-hashed name, find a covering NSEC3 from among a list of
     * NSEC3s.
     *
     * @param hash
     *                     The hash to consider.
     * @param zonename
     *                     The name of the zone.
     * @param nsec3s
     *                     The list of NSEC3s present in a message.
     * @param params
     *                     The NSEC3 parameters used to generate the hash --
     *                     NSEC3s that do not use those parameters will be
     *                     skipped.
     *
     * @return A covering NSEC3 if one is present, null otherwise.
     */
    private static NSEC3Record findCoveringNSEC3(byte[] hash,
            List<NSEC3Record> nsec3s, NSEC3Parameters params,
            ByteArrayComparator bac) {
        ByteArrayComparator comparator = new ByteArrayComparator();

        for (NSEC3Record nsec3 : nsec3s) {
            if (!params.match(nsec3, bac)) {
                continue;
            }

            if (nsec3Covers(nsec3, hash, comparator)) {
                return nsec3;
            }
        }

        return null;
    }

    /**
     * Given a name and a list of NSEC3s, find the candidate closest encloser.
     * This will be the first ancestor of 'name' (including itself) to have a
     * matching NSEC3 RR.
     *
     * @param name
     *                        The name the start with.
     * @param zonename
     *                        The name of the zone that the NSEC3s came from.
     * @param nsec3s
     *                        The list of NSEC3s.
     * @param nsec3params
     *                        The NSEC3 parameters.
     * @param bac
     *                        A pre-allocated comparator. May be null.
     *
     * @return A CEResponse containing the closest encloser name and the NSEC3
     *         RR that matched it, or null if there wasn't one.
     */
    private static CEResponse findClosestEncloser(Name name, Name zonename,
            List<NSEC3Record> nsec3s, NSEC3Parameters params,
            ByteArrayComparator bac) {
        Name n = name;

        NSEC3Record nsec3;

        // This scans from longest name to shortest, so the first match we find
        // is the only viable candidate.
        // TODO: modify so that the NSEC3 matching the zone apex need not be
        // present.
        while (n.labels() >= zonename.labels()) {
            nsec3 = findMatchingNSEC3(hash(n, params), zonename, nsec3s, params, bac);

            if (nsec3 != null) {
                return new CEResponse(n, nsec3);
            }

            n = new Name(n, 1);
        }

        return null;
    }

    /**
     * Given a List of nsec3 RRs, find and prove the closest encloser to qname.
     *
     * @param qname
     *                              The qname in question.
     * @param zonename
     *                              The name of the zone that the NSEC3 RRs come
     *                              from.
     * @param nsec3s
     *                              The list of NSEC3s found the this response
     *                              (already verified).
     * @param params
     *                              The NSEC3 parameters found in the response.
     * @param bac
     *                              A pre-allocated comparator. May be null.
     * @param proveDoesNotExist
     *                              If true, then if the closest encloser turns
     *                              out to be qname, then null is returned.
     * @return null if the proof isn't completed. Otherwise, return a CEResponse
     *         object which contains the closest encloser name and the NSEC3
     *         that matches it.
     */
    private static CEResponse proveClosestEncloser(Name qname, Name zonename,
            List<NSEC3Record> nsec3s, NSEC3Parameters params,
            ByteArrayComparator bac, boolean proveDoesNotExist,
            List<String> errorList) {
        CEResponse candidate = findClosestEncloser(qname, zonename, nsec3s, params, bac);

        if (candidate == null) {
            errorList.add("Could not find a candidate for the closest encloser");
            stLog.fine("proveClosestEncloser: could not find a "
                    + "candidate for the closest encloser.");

            return null;
        }

        if (candidate.closestEncloser.equals(qname)) {
            if (proveDoesNotExist) {
                errorList.add("Proven closest encloser proved that the qname existed and should not have");
                stLog.fine("proveClosestEncloser: proved that qname existed!");

                return null;
            }

            // otherwise, we need to nothing else to prove that qname
            // is its own closest encloser.
            return candidate;
        }

        // If the closest encloser is actually a delegation, then the
        // response should have been a referral. If it is a DNAME,
        // then it should have been a DNAME response.
        if (candidate.ceNSEC3.hasType(Type.NS)
                && !candidate.ceNSEC3.hasType(Type.SOA)) {
            errorList.add("Proven closest encloser was a delegation");
            stLog.fine("proveClosestEncloser: closest encloser "
                    + "was a delegation!");

            return null;
        }

        if (candidate.ceNSEC3.hasType(Type.DNAME)) {
            errorList.add("Proven closest encloser was a DNAME");
            stLog.fine("proveClosestEncloser: closest encloser was a DNAME!");

            return null;
        }

        // Otherwise, we need to show that the next closer name is covered.
        Name nextClosest = nextClosest(qname, candidate.closestEncloser);

        byte[] ncHash = hash(nextClosest, params);
        candidate.ncNSEC3 = findCoveringNSEC3(ncHash, nsec3s, params, bac);

        if (candidate.ncNSEC3 == null) {
            errorList.add("Could not find proof that the closest encloser was the closest encloser");
            errorList.add("hash " + hashName(ncHash, zonename)
                    + " is not covered by any NSEC3 RRs");
            stLog.fine("Could not find proof that the "
                    + "closest encloser was the closest encloser");

            return null;
        }

        return candidate;
    }

    // Determine the maximum number of NSEC3 iterations we will tolerate This is
    // arbitrary, really.  The old way is to size it to be similar to the
    // validation speed. The new way is to just have a global max (regardless of
    // verification speed), and to ratchet this down to a very low number over
    // time.
    private static int maxIterations(int baseAlg, int keysize) {
        return 300;
    }

    private static boolean validIterations(NSEC3Parameters nsec3params,
            RRset dnskeyRRset, DnsSecVerifier verifier) {
        // for now, we return the maximum iterations based simply on
        // the key algorithms that may have been used to sign the
        // NSEC3 RRsets.
        int maxIterations = 0;

        for (Record r : dnskeyRRset.rrs()) {
            DNSKEYRecord dnskey = (DNSKEYRecord) r;
            int iters = maxIterations(dnskey.getAlgorithm(), 0);
            maxIterations = (maxIterations < iters) ? iters : maxIterations;
        }

        return nsec3params.iterations <= maxIterations;
    }

    /**
     * Determine if all of the NSEC3s in a response are legally ignoreable
     * (i.e., their presence should lead to an INSECURE result). Currently, this
     * is solely based on iterations.
     *
     * @param nsec3s
     *                         The list of NSEC3s. If there is more than one set
     *                         of NSEC3 parameters present, this test will not
     *                         be performed.
     * @param dnskeyRRset
     *                         The set of validating DNSKEYs.
     * @param verifier
     *                         The verifier used to verify the NSEC3 RRsets.
     *                         This is solely used to map algorithm aliases.
     * @return true if all of the NSEC3s can be legally ignored, false if not.
     */
    public static boolean allNSEC3sIgnoreable(List<NSEC3Record> nsec3s,
            RRset dnskeyRRset, DnsSecVerifier verifier) {
        NSEC3Parameters params = nsec3Parameters(nsec3s);

        if (params == null) {
            return false;
        }

        return !validIterations(params, dnskeyRRset, verifier);
    }

    /**
     * Determine if the set of NSEC3 records provided with a response prove NAME
     * ERROR. This means that the NSEC3s prove a) the closest encloser exists,
     * b) the direct child of the closest encloser towards qname doesn't exist,
     * and c) *.closest encloser does not exist.
     *
     * @param nsec3s
     *                     The list of NSEC3s.
     * @param qname
     *                     The query name to check against.
     * @param zonename
     *                     This is the name of the zone that the NSEC3s belong
     *                     to. This may be discovered in any number of ways. A
     *                     good one is to use the signerName from the NSEC3
     *                     record's RRSIG.
     * @return SecurityStatus.SECURE of the Name Error is proven by the NSEC3
     *         RRs, BOGUS if not, INSECURE if all of the NSEC3s could be validly
     *         ignored.
     */
    public static boolean proveNameError(List<NSEC3Record> nsec3s, Name qname,
            Name zonename, List<String> errorList) {
        if ((nsec3s == null) || (nsec3s.isEmpty())) {
            return false;
        }

        NSEC3Parameters nsec3params = nsec3Parameters(nsec3s);

        if (nsec3params == null) {
            errorList.add("Could not find a single set of NSEC3 parameters (multiple parameters present");
            stLog.fine("Could not find a single set of "
                    + "NSEC3 parameters (multiple parameters present).");

            return false;
        }

        ByteArrayComparator bac = new ByteArrayComparator();

        // First locate and prove the closest encloser to qname. We will use the
        // variant that fails if the closest encloser turns out to be qname.
        CEResponse ce = proveClosestEncloser(qname, zonename, nsec3s, nsec3params, bac, true, errorList);

        if (ce == null) {
            errorList.add("Failed to find the closest encloser as part of the NSEC3 proof");
            stLog.fine("proveNameError: failed to prove a closest encloser.");

            return false;
        }

        // At this point, we know that qname does not exist. Now we need to
        // prove
        // that the wildcard does not exist.
        Name wc = ceWildcard(ce.closestEncloser);
        byte[] wcHash = hash(wc, nsec3params);
        NSEC3Record nsec3 = findCoveringNSEC3(wcHash, nsec3s, nsec3params, bac);

        if (nsec3 == null) {
            errorList.add("Failed to prove that the applicable wildcard did not exist");
            stLog.fine("proveNameError: could not prove that the "
                    + "applicable wildcard did not exist.");

            return false;
        }

        return true;
    }

    /**
     * Determine if the NSEC3s provided in a response prove the NOERROR/NODATA
     * status. There are a number of different variants to this listed in RFC
     * 5155:
     *
     * 1) NODATA, qtype is not DS (section 8.5) 2) NODATA, qtype is DS (section
     * 8.6) 3) Wildcard NODATA (section 8.7)
     *
     * #1 assumes that you are querying an actual node, and thus have a matching
     * NSEC3. What is not accounted for are ENTs created by insecure delegations
     * while using Opt-Out.
     *
     * #2 assumes that the only way to get a NODATA out of an Opt-Out span is to
     * match an insecure delegation but have the qtype be DS.
     *
     * This missing corner case is addressed in an errata:
     * https://www.rfc-editor.org/errata/rfc5155
     *
     * Thus we split case #1 into two sub-cases: 1a) NODATA, qtype is not DS and
     * we have a matching NSEC3 1b) NODATA, qtype is not DS and we do not have a
     * matching NSEC3
     *
     * And case 2 can split into two cases: 2a) NODATA, qtype is DS and we have
     * a matching NSEC3 2b) NODATA, qtype is DS and we do not have a matching
     * NSEC3
     *
     * 1b and 2b end up having the same logic. The NSEC3 that covers the next
     * closest encloser must have the opt-out bit set.
     *
     * @param nsec3s
     *                     The NSEC3Records to consider.
     * @param qname
     *                     The qname in question.
     * @param qtype
     *                     The qtype in question.
     * @param zonename
     *                     The name of the zone that the NSEC3s came from.
     * @return true if the NSEC3s prove the proposition.
     */
    public static boolean proveNodata(List<NSEC3Record> nsec3s, Name qname,
            int qtype, Name zonename, List<String> errorList) {
        if ((nsec3s == null) || nsec3s.isEmpty()) {
            return false;
        }

        NSEC3Parameters nsec3params = nsec3Parameters(nsec3s);

        if (nsec3params == null) {
            stLog.fine("could not find a single set of "
                    + "NSEC3 parameters (multiple parameters present)");

            return false;
        }

        ByteArrayComparator bac = new ByteArrayComparator();

        NSEC3Record nsec3 = findMatchingNSEC3(hash(qname, nsec3params), zonename, nsec3s, nsec3params, bac);

        // Cases 1a & 2a.
        if (nsec3 != null) {
            if (nsec3.hasType(qtype)) {
                stLog.fine("proveNodata: Matching NSEC3 proved that type existed!");

                return false;
            }

            if (nsec3.hasType(Type.CNAME)) {
                stLog.fine("proveNodata: Matching NSEC3 proved "
                        + "that a CNAME existed!");

                return false;
            }

            return true;
        }

        // For cases 1b, 2b, and 3, we need the proven closest encloser, and it
        // can't
        // match qname. Although, at this point, we know that it won't since we
        // just checked that.
        CEResponse ce = proveClosestEncloser(qname, zonename, nsec3s, nsec3params, bac, true, errorList);

        // At this point, not finding a match or a proven closest encloser is a
        // problem.
        if (ce == null) {
            stLog.fine("proveNodata: did not match qname, "
                    + "nor found a proven closest encloser.");

            return false;
        }

        // Case 3:
        Name wc = ceWildcard(ce.closestEncloser);
        nsec3 = findMatchingNSEC3(hash(wc, nsec3params), zonename, nsec3s, nsec3params, bac);

        if (nsec3 != null) {
            if (nsec3.hasType(qtype)) {
                stLog.fine("proveNodata: matching wildcard had qtype!");

                return false;
            }

            return true;
        }

        // Cases 1b and 2b
        // We need to make sure that the covering NSEC3 is opt-in.
        if (!isOptOut(ce.ncNSEC3)) {
            stLog.fine("proveNodata: covering NSEC3 was not "
                    + "opt-in in an opt-in DS NOERROR/NODATA case.");

            return false;
        }

        return true;
    }

    /**
     * Prove that a positive wildcard match was appropriate (no direct match
     * RRset).
     *
     * @param nsec3s
     *                     The NSEC3 records to work with.
     * @param qname
     *                     The qname that was matched to the wildcard
     * @param zonename
     *                     The name of the zone that the NSEC3s come from.
     * @param wildcard
     *                     The purported wildcard that matched.
     * @return true if the NSEC3 records prove this case.
     */
    public static boolean proveWildcard(List<NSEC3Record> nsec3s, Name qname,
            Name wildcard, List<String> errorList) {
        if ((nsec3s == null) || nsec3s.isEmpty()) {
            return false;
        }

        if ((qname == null) || (wildcard == null)) {
            return false;
        }

        NSEC3Parameters nsec3params = nsec3Parameters(nsec3s);

        if (nsec3params == null) {
            errorList.add("Could not find a single set of NSEC3 parameters (multiple parameters present)");
            stLog.fine("Couldn't find a single set of NSEC3 parameters (multiple parameters present).");

            return false;
        }

        ByteArrayComparator bac = new ByteArrayComparator();

        // We know what the (purported) closest encloser is by just looking at
        // the
        // supposed generating wildcard.
        CEResponse candidate = new CEResponse(new Name(wildcard, 1), null);

        // Now we still need to prove that the original data did not exist.
        // Otherwise, we need to show that the next closer name is covered.
        Name nextClosest = nextClosest(qname, candidate.closestEncloser);
        candidate.ncNSEC3 = findCoveringNSEC3(hash(nextClosest, nsec3params), nsec3s, nsec3params, bac);

        if (candidate.ncNSEC3 == null) {
            errorList.add("Did not find a NSEC3 that covered the next closer name to '"
                    + qname + "' from '" + candidate.closestEncloser
                    + "' (derived from the wildcard: " + wildcard + ")");
            stLog.fine("proveWildcard: did not find a covering NSEC3 "
                    + "that covered the next closer name to " + qname + " from "
                    + candidate.closestEncloser + " (derived from wildcard "
                    + wildcard + ")");

            return false;
        }

        return true;
    }

    /**
     * Prove that a DS response either had no DS, or wasn't a delegation point.
     *
     * Fundamentally there are two cases here: normal NODATA and Opt-In NODATA.
     *
     * @param nsec3s
     *                     The NSEC3 RRs to examine.
     * @param qname
     *                     The name of the DS in question.
     * @param zonename
     *                     The name of the zone that the NSEC3 RRs come from.
     *
     * @return SecurityStatus.SECURE if it was proven that there is no DS in a
     *         secure (i.e., not opt-in) way, SecurityStatus.INSECURE if there
     *         was no DS in an insecure (i.e., opt-in) way,
     *         SecurityStatus.INDETERMINATE if it was clear that this wasn't a
     *         delegation point, and SecurityStatus.BOGUS if the proofs don't
     *         work out.
     */
    public static byte proveNoDS(List<NSEC3Record> nsec3s, Name qname,
            Name zonename, List<String> errorList) {
        if ((nsec3s == null) || nsec3s.isEmpty()) {
            return SecurityStatus.BOGUS;
        }

        NSEC3Parameters nsec3params = nsec3Parameters(nsec3s);

        if (nsec3params == null) {
            errorList.add("Could not find a single set of NSEC3 parameters (multiple parameters present)");
            stLog.fine("couldn't find a single set of "
                    + "NSEC3 parameters (multiple parameters present).");

            return SecurityStatus.BOGUS;
        }

        ByteArrayComparator bac = new ByteArrayComparator();

        // Look for a matching NSEC3 to qname -- this is the normal NODATA case.
        NSEC3Record nsec3 = findMatchingNSEC3(hash(qname, nsec3params), zonename, nsec3s, nsec3params, bac);

        if (nsec3 != null) {
            // If the matching NSEC3 has the SOA bit set, it is from the wrong
            // zone (the child instead of the parent). If it has the DS bit set,
            // then we were lied to.
            if (nsec3.hasType(Type.SOA) || nsec3.hasType(Type.DS)) {
                errorList.add("Matching NSEC3 is incorrectly from the child "
                        + "instead of the parent (SOA or DS bit set)");
                return SecurityStatus.BOGUS;
            }

            // If the NSEC3 RR doesn't have the NS bit set, then this wasn't a
            // delegation point.
            if (!nsec3.hasType(Type.NS)) {
                return SecurityStatus.INDETERMINATE;
            }

            // Otherwise, this proves no DS.
            return SecurityStatus.SECURE;
        }

        // Otherwise, we are probably in the opt-in case.
        CEResponse ce = proveClosestEncloser(qname, zonename, nsec3s, nsec3params, bac, true, errorList);

        if (ce == null) {
            errorList.add("Failed to prove the closest encloser as part of a 'No DS' proof");
            return SecurityStatus.BOGUS;
        }

        // If we had the closest encloser proof, then we need to check that the
        // covering NSEC3 was opt-in -- the proveClosestEncloser step already
        // checked to see if the closest encloser was a delegation or DNAME.
        if (isOptOut(ce.ncNSEC3)) {
            return SecurityStatus.SECURE;
        }

        errorList.add("Failed to find a covering NSEC3 for 'No DS' proof");
        return SecurityStatus.BOGUS;
    }

    /**
     * This is a class to encapsulate a unique set of NSEC3 parameters:
     * algorithm, iterations, and salt.
     */
    private static class NSEC3Parameters {
        public int alg;
        public byte[] salt;
        public int iterations;
        private NSEC3PARAMRecord nsec3paramrec;

        public NSEC3Parameters(NSEC3Record r) {
            alg = r.getHashAlgorithm();
            salt = r.getSalt();
            iterations = r.getIterations();

            nsec3paramrec = new NSEC3PARAMRecord(Name.root, DClass.IN, 0, alg, 0, iterations, salt);
        }

        public boolean match(NSEC3Record r, ByteArrayComparator bac) {
            if (r.getHashAlgorithm() != alg) {
                return false;
            }

            if (r.getIterations() != iterations) {
                return false;
            }

            if ((salt == null) && (r.getSalt() != null)) {
                return false;
            }

            if (salt == null) {
                return true;
            }

            if (bac == null) {
                bac = new ByteArrayComparator();
            }

            return bac.compare(r.getSalt(), salt) == 0;
        }

        public byte[] hash(Name name) throws NoSuchAlgorithmException {
            return nsec3paramrec.hashName(name);
        }
    }

    /**
     * This is just a simple class to encapsulate the response to a closest
     * encloser proof.
     */
    private static class CEResponse {
        public Name closestEncloser;
        public NSEC3Record ceNSEC3;
        public NSEC3Record ncNSEC3;

        public CEResponse(Name ce, NSEC3Record nsec3) {
            this.closestEncloser = ce;
            this.ceNSEC3 = nsec3;
        }
    }
}
