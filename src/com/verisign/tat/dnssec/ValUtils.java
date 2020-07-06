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

package com.verisign.tat.dnssec;

import org.apache.log4j.Logger;

import org.xbill.DNS.*;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import java.util.Iterator;

/**
 * This is a collection of routines encompassing the logic of validating
 * different message types.
 */
public class ValUtils {
    private static Logger st_log = Logger.getLogger(ValUtils.class);
    private Logger        log    = Logger.getLogger(this.getClass());

    /** A local copy of the verifier object. */
    private DnsSecVerifier mVerifier;

    public ValUtils(DnsSecVerifier verifier) {
        mVerifier = verifier;
    }

    /**
     * Given a response, classify ANSWER responses into a subtype.
     *
     * @param m
     *            The response to classify.
     *
     * @return A subtype ranging from UNKNOWN to NAMEERROR.
     */
    public static ResponseType classifyResponse(SMessage m, Name zone) {
        SRRset[] rrsets;

        // Normal Name Error's are easy to detect -- but don't mistake a CNAME
        // chain ending in NXDOMAIN.
        if ((m.getRcode() == Rcode.NXDOMAIN) && (m.getCount(Section.ANSWER) == 0)) {
            return ResponseType.NAMEERROR;
        }

        // If rcode isn't NXDOMAIN or NOERROR, it is a throwaway response.
        if (m.getRcode() != Rcode.NOERROR) {
            return ResponseType.THROWAWAY;
        }

        // Next is REFERRAL. These are distinguished by having:
        // 1) nothing in the ANSWER section
        // 2) an NS RRset in the AUTHORITY section that is a strict subdomain of
        // 'zone' (the presumed queried zone).
        if ((zone != null) && (m.getCount(Section.ANSWER) == 0) &&
            (m.getCount(Section.AUTHORITY) > 0)) {

            rrsets = m.getSectionRRsets(Section.AUTHORITY);

            for (int i = 0; i < rrsets.length; ++i) {
                if ((rrsets[i].getType() == Type.NS)
                        && strictSubdomain(rrsets[i].getName(), zone)) {
                    return ResponseType.REFERRAL;
                }
            }
        }

        // Next is NODATA
        if (m.getCount(Section.ANSWER) == 0) {
            return ResponseType.NODATA;
        }

        // We distinguish between CNAME response and other positive/negative
        // responses because CNAME answers require extra processing.
        int qtype = m.getQuestion().getType();

        // We distinguish between ANY and CNAME or POSITIVE because ANY
        // responses are validated differently.
        if (qtype == Type.ANY) {
            return ResponseType.ANY;
        }

        rrsets = m.getSectionRRsets(Section.ANSWER);

        // Note that DNAMEs will be ignored here, unless qtype=DNAME. Unless
        // qtype=CNAME, this will yield a CNAME response.
        for (int i = 0; i < rrsets.length; i++) {
            if (rrsets[i].getType() == qtype) {
                return ResponseType.POSITIVE;
            }

            if (rrsets[i].getType() == Type.CNAME) {
                return ResponseType.CNAME;
            }
        }

        st_log.warn("Failed to classify response message:\n" + m);

        return ResponseType.UNKNOWN;
    }

    /**
     * Given a response, determine the name of the "signer". This is
     * primarily to determine if the response is, in fact, signed at
     * all, and, if so, what is the name of the most pertinent keyset.
     *
     * @param m
     *            The response to analyze.
     * @return a signer name, if the response is signed (even partially), or
     *         null if the response isn't signed.
     */
    public Name findSigner(SMessage m) {
        // This used to classify the message, then look in the pertinent
        // section. Now we just find the first RRSIG in the ANSWER and AUTHORIY
        // sections.
        for (int section = Section.ANSWER; section < Section.ADDITIONAL; ++section) {
            SRRset[] rrsets = m.getSectionRRsets(section);

            for (int i = 0; i < rrsets.length; ++i) {
                Name signerName = rrsets[i].getSignerName();

                if (signerName != null) {
                    return signerName;
                }
            }
        }

        return null;
    }

    /**
     * Given a DNSKEY record, generate the DS record from it.
     *
     * @param keyrec
     *            the DNSKEY record in question.
     * @param ds_alg
     *            The DS digest algorithm in use.
     * @return the corresponding {@link org.xbill.DNS.DSRecord}
     */
    public static byte[] calculateDSHash(DNSKEYRecord keyrec, int ds_alg) {
        DNSOutput os = new DNSOutput();

        os.writeByteArray(keyrec.getName().toWireCanonical());
        os.writeByteArray(keyrec.rdataToWireCanonical());

        try {
            MessageDigest md = null;

            switch (ds_alg) {
            case DSRecord.SHA1_DIGEST_ID:
                md = MessageDigest.getInstance("SHA");

                return md.digest(os.toByteArray());

            case DSRecord.SHA256_DIGEST_ID:
                md = MessageDigest.getInstance("SHA256");

                return md.digest(os.toByteArray());

            default:
                st_log.warn("Unknown DS algorithm: " + ds_alg);

                return null;
            }
        } catch (NoSuchAlgorithmException e) {
            st_log.error("Error using DS algorithm: " + ds_alg, e);

            return null;
        }
    }

    public static boolean supportsDigestID(int digest_id) {
        if (digest_id == DSRecord.SHA1_DIGEST_ID) {
            return true;
        }

        if (digest_id == DSRecord.SHA256_DIGEST_ID) {
            return true;
        }

        return false;
    }

    /**
     * Check to see if a type is a special DNSSEC type.
     *
     * @param type
     *            The type.
     *
     * @return true if the type is one of the special DNSSEC types.
     */
    public static boolean isDNSSECType(int type) {
        switch (type) {
        case Type.DNSKEY:
        case Type.NSEC:
        case Type.DS:
        case Type.RRSIG:
        case Type.NSEC3:
            return true;

        default:
            return false;
        }
    }

    /**
     * Set the security status of a particular RRset. This will only
     * upgrade the security status.
     *
     * @param rrset
     *            The SRRset to update.
     * @param security
     *            The security status.
     */
    public static void setRRsetSecurity(SRRset rrset, byte security) {
        if (rrset == null) {
            return;
        }

        int cur_sec = rrset.getSecurityStatus();

        if ((cur_sec == SecurityStatus.UNCHECKED) || (security > cur_sec)) {
            rrset.setSecurityStatus(security);
        }
    }

    /**
     * Set the security status of a message and all of its
     * RRsets. This will only upgrade the status of the message (i.e.,
     * set to more secure, not less) and all of the RRsets.
     */
    public static void setMessageSecurity(SMessage m, byte security) {
        if (m == null) {
            return;
        }

        int cur_sec = m.getStatus();

        if ((cur_sec == SecurityStatus.UNCHECKED) || (security > cur_sec)) {
            m.setStatus(security);
        }

        for (int section = Section.ANSWER; section <= Section.ADDITIONAL; section++) {
            SRRset[] rrsets = m.getSectionRRsets(section);

            for (int i = 0; i < rrsets.length; i++) {
                setRRsetSecurity(rrsets[i], security);
            }
        }
    }

    /**
     * Given an SRRset that is signed by a DNSKEY found in the
     * key_rrset, verify it. This will return the status (either BOGUS
     * or SECURE) and set that status in rrset.
     *
     * @param rrset
     *            The SRRset to verify.
     * @param key_rrset
     *            The set of keys to verify against.
     * @return The status (BOGUS or SECURE).
     */
    public byte verifySRRset(SRRset rrset, SRRset key_rrset) {
        String rrset_name = rrset.getName() + "/" + Type.string(rrset.getType()) + "/" +
            DClass.string(rrset.getDClass());

        if (rrset.getSecurityStatus() == SecurityStatus.SECURE) {
            log.trace("verifySRRset: rrset <" + rrset_name +
                      "> previously found to be SECURE");

            return SecurityStatus.SECURE;
        }

        byte status = mVerifier.verify(rrset, key_rrset);

        if (status != SecurityStatus.SECURE) {
            log.debug("verifySRRset: rrset <" + rrset_name + "> found to be BAD");
            status = SecurityStatus.BOGUS;
        } else {
            log.trace("verifySRRset: rrset <" + rrset_name + "> found to be SECURE");
        }

        rrset.setSecurityStatus(status);

        return status;
    }

    /**
     * Determine if a given type map has a given type.
     *
     * @param types
     *            The type map from the NSEC record.
     * @param type
     *            The type to look for.
     * @return true if the type is present in the type map, false otherwise.
     */
    public static boolean typeMapHasType(int[] types, int type) {
        for (int i = 0; i < types.length; i++) {
            if (types[i] == type) {
                return true;
            }
        }

        return false;
    }

    @SuppressWarnings("rawtypes")
    public static RRSIGRecord rrsetFirstSig(RRset rrset) {
        for (Iterator i = rrset.sigs(); i.hasNext();) {
            return (RRSIGRecord) i.next();
        }

        return null;
    }

    /**
     * Finds the longest common name between two domain names.
     *
     * @param domain1
     * @param domain2
     * @return
     */
    public static Name longestCommonName(Name domain1, Name domain2) {
        if ((domain1 == null) || (domain2 == null)) {
            return null;
        }

        // for now, do this in a a fairly brute force way
        // FIXME: convert this to direct operations on the byte[]
        int d1_labels = domain1.labels();
        int d2_labels = domain2.labels();

        int l = (d1_labels < d2_labels) ? d1_labels : d2_labels;

        for (int i = l; i > 0; i--) {
            Name n1 = new Name(domain1, d1_labels - i);
            Name n2 = new Name(domain2, d2_labels - i);

            if (n1.equals(n2)) {
                return n1;
            }
        }

        return Name.root;
    }

    public static boolean strictSubdomain(Name child, Name parent) {
        int clabels = child.labels();
        int plabels = parent.labels();

        if (plabels >= clabels) {
            return false;
        }

        Name n = new Name(child, clabels - plabels);

        return parent.equals(n);
    }

    /**
     * Determine by looking at a signed RRset whether or not the rrset name was
     * the result of a wildcard expansion.
     *
     * @param rrset
     *            The rrset to examine.
     * @return true if the rrset is a wildcard expansion. This will return false
     *         for all unsigned rrsets.
     */
    public static boolean rrsetIsWildcardExpansion(RRset rrset) {
        if (rrset == null) {
            return false;
        }

        RRSIGRecord rrsig = rrsetFirstSig(rrset);

        if ((rrset.getName().labels() - 1) > rrsig.getLabels()) {
            return true;
        }

        return false;
    }

    /**
     * Determine by looking at a signed RRset whether or not the RRset name was
     * the result of a wildcard expansion. If so, return the name of the
     * generating wildcard.
     *
     * @param rrset
     *            The rrset to check.
     * @return the wildcard name, if the rrset was synthesized from a wildcard.
     *         null if not.
     */
    public static Name rrsetWildcard(RRset rrset) {
        if (rrset == null) {
            return null;
        }

        RRSIGRecord rrsig = rrsetFirstSig(rrset);

        // if the RRSIG label count is shorter than the number of actual labels,
        // then this rrset was synthesized from a wildcard.
        // Note that the RRSIG label count doesn't count the root label.
        int label_diff = (rrset.getName().labels() - 1) - rrsig.getLabels();

        if (label_diff > 0) {
            Name wc = rrset.getName().wild(label_diff);
            // if the name was the wildcard itself, this isn't actually a
            // wildcard expansion.
            if (wc.equals(rrset.getName())) {
                return null;
            }
            return wc;
        }

        return null;
    }

    public static Name closestEncloser(Name domain, NSECRecord nsec) {
        Name n1 = longestCommonName(domain, nsec.getName());
        Name n2 = longestCommonName(domain, nsec.getNext());

        return (n1.labels() > n2.labels()) ? n1 : n2;
    }

    public static Name nsecWildcard(Name domain, NSECRecord nsec) {
        try {
            return new Name("*", closestEncloser(domain, nsec));
        } catch (TextParseException e) {
            // this should never happen.
            return null;
        }
    }

    /**
     * Determine if the given NSEC proves a NameError (NXDOMAIN) for a
     * given qname.
     *
     * @param nsec
     *            The NSEC to check.
     * @param qname
     *            The qname to check against.
     * @param signerName
     *            The signer name of the NSEC record, which is used as the zone
     *            name, for a more precise (but perhaps more brittle) check for
     *            the last NSEC in a zone.
     * @return true if the NSEC proves the condition.
     */
    public static boolean nsecProvesNameError(NSECRecord nsec, Name qname,
            Name signerName) {
        Name owner = nsec.getName();
        Name next  = nsec.getNext();

        // If NSEC owner == qname, then this NSEC proves that qname exists.
        if (qname.equals(owner)) {
            return false;
        }

        // If NSEC is a parent of qname, we need to check the type map
        // If the parent name has a DNAME or is a delegation point, then this
        // NSEC is being misused.
        boolean hasBadType = typeMapHasType(nsec.getTypes(), Type.DNAME) ||
            (typeMapHasType(nsec.getTypes(), Type.NS) && !typeMapHasType(nsec.getTypes(), Type.SOA));

        if (qname.subdomain(owner) && hasBadType) {
            return false;
        }

        if (((qname.compareTo(owner) > 0) && (qname.compareTo(next) < 0)) || signerName.equals(next)) {
            return true;
        }

        return false;
    }

    /**
     * Determine if a NSEC record proves the non-existence of a
     * wildcard that could have produced qname.
     *
     * @param nsec
     *            The nsec to check.
     * @param qname
     *            The qname to check against.
     * @param signerName
     *            The signer name for the NSEC rrset, used as the zone name.
     * @return true if the NSEC proves the condition.
     */
    public static boolean nsecProvesNoWC(NSECRecord nsec, Name qname, Name signerName) {
        Name owner = nsec.getName();
        Name next  = nsec.getNext();

        int qname_labels  = qname.labels();
        int signer_labels = signerName.labels();

        for (int i = qname_labels - signer_labels; i > 0; i--) {
            Name wc_name = qname.wild(i);

            if ((wc_name.compareTo(owner) > 0) &&
                ((wc_name.compareTo(next) < 0) || signerName.equals(next))) {
                return true;
            }
        }

        return false;
    }

    /**
     * Determine if a NSEC proves the NOERROR/NODATA conditions. This
     * will also handle the empty non-terminal (ENT) case and
     * partially handle the wildcard case. If the ownername of 'nsec'
     * is a wildcard, the validator must still be provided proof that
     * qname did not directly exist and that the wildcard is, in fact,
     * *.closest_encloser.
     *
     * @param nsec
     *            The NSEC to check
     * @param qname
     *            The query name to check against.
     * @param qtype
     *            The query type to check against.
     * @return true if the NSEC proves the condition.
     */
    public static boolean nsecProvesNodata(NSECRecord nsec, Name qname, int qtype) {
        if (!nsec.getName().equals(qname)) {
            // wildcard checking.

            // If this is a wildcard NSEC, make sure that a) it was
            // possible to have generated qname from the wildcard and
            // b) the type map does not contain qtype. Note that this
            // does NOT prove that this wildcard was the applicable
            // wildcard.
            if (nsec.getName().isWild()) {
                // the is the purported closest encloser.
                Name ce = new Name(nsec.getName(), 1);

                // The qname must be a strict subdomain of the closest
                // encloser, and the qtype must be absent from the
                // type map.
                if (!strictSubdomain(qname, ce) || typeMapHasType(nsec.getTypes(), qtype)) {
                    return false;
                }

                return true;
            }

            // empty-non-terminal checking.

            // If the nsec is proving that qname is an ENT, the nsec
            // owner will be less than qname, and the next name will
            // be a child domain of the qname.
            if (strictSubdomain(nsec.getNext(), qname)
                    && (qname.compareTo(nsec.getName()) > 0)) {
                return true;
            }

            // Otherwise, this NSEC does not prove ENT, so it does not
            // prove NODATA.
            return false;
        }

        // If the qtype exists, then we should have gotten it.
        if (typeMapHasType(nsec.getTypes(), qtype)) {
            return false;
        }

        // if the name is a CNAME node, then we should have gotten the
        // CNAME
        if (typeMapHasType(nsec.getTypes(), Type.CNAME)) {
            return false;
        }

        // If an NS set exists at this name, and NOT a SOA (so this is
        // a zone cut, not a zone apex), then we should have gotten a
        // referral (or we just got the wrong NSEC).
        if (typeMapHasType(nsec.getTypes(), Type.NS) &&
            !typeMapHasType(nsec.getTypes(), Type.SOA)) {

            return false;
        }

        return true;
    }

    public static byte nsecProvesNoDS(NSECRecord nsec, Name qname) {
        // Could check to make sure the qname is a subdomain of nsec
        int[] types = nsec.getTypes();

        if (typeMapHasType(types, Type.SOA) || typeMapHasType(types, Type.DS)) {
            // SOA present means that this is the NSEC from the child,
            // not the parent (so it is the wrong one) DS present
            // means that there should have been a positive response
            // to the DS query, so there is something wrong.
            return SecurityStatus.BOGUS;
        }

        if (!typeMapHasType(types, Type.NS)) {
            // If there is no NS at this point at all, then this
            // doesn't prove anything one way or the other.
            return SecurityStatus.INSECURE;
        }

        // Otherwise, this proves no DS.
        return SecurityStatus.SECURE;
    }

    // These are response subtypes. They are necessary for determining
    // the validation strategy. They have no bearing on the iterative
    // resolution algorithm, so they are confined here.
    public enum ResponseType {
        UNTYPED, UNKNOWN, POSITIVE, CNAME, NODATA, NAMEERROR, ANY, REFERRAL, // a referral response
        THROWAWAY; // a throwaway response (i.e., an error)
    }
}
