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

import java.io.IOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.ListIterator;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.xbill.DNS.CNAMERecord;
import org.xbill.DNS.DNAMERecord;
import org.xbill.DNS.Master;
import org.xbill.DNS.Message;
import org.xbill.DNS.NSEC3Record;
import org.xbill.DNS.NSECRecord;
import org.xbill.DNS.Name;
import org.xbill.DNS.NameTooLongException;
import org.xbill.DNS.RRSIGRecord;
import org.xbill.DNS.RRset;
import org.xbill.DNS.Rcode;
import org.xbill.DNS.Record;
import org.xbill.DNS.Section;
import org.xbill.DNS.TextParseException;
import org.xbill.DNS.Type;
import org.xbill.DNS.utils.base64;

/**
 * This resolver module implements a "captive" DNSSEC validator. The captive
 * validator does not have direct access to the Internet and DNS system --
 * instead it attempts to validate DNS messages using only configured context.
 * This is useful for determining if responses coming from a given authoritative
 * server will validate independent of the normal chain of trust.
 */
public class CaptiveValidator {
    // A data structure holding all all of our trusted keys.
    private TrustAnchorStore mTrustedKeys;

    // The local validation utilities.
    private ValUtils mValUtils;

    // The local verification utility.
    private DnsSecVerifier mVerifier;
    private Logger log = Logger.getLogger(this.getClass().getName());

    // The list of validation errors found.
    private List<String> mErrorList;

    public CaptiveValidator() {
        mVerifier = new DnsSecVerifier();
        mValUtils = new ValUtils(mVerifier);
        mTrustedKeys = new TrustAnchorStore();
        mErrorList = new ArrayList<>();
    }

    // ---------------- Module Initialization -------------------

    /**
     * Add a set of trusted keys from a file. The file should be in DNS master
     * zone file format. Only DNSKEY records will be added.
     *
     * @param filename
     *                     The file contains the trusted keys.
     * @throws IOException
     */
    public void addTrustedKeysFromFile(String filename) throws IOException {
        ArrayList<Record> records = new ArrayList<>();

        // First read in the whole trust anchor file.
        try (Master master = new Master(filename, Name.root, 0)) {
            Record r = null;

            while ((r = master.nextRecord()) != null) {
                records.add(r);
            }
        }
        // Record.compareTo() should sort them into DNSSEC canonical
        // order. Don't care about canonical order per se, but do
        // want them to be formable into RRsets.
        Collections.sort(records);

        SRRset curRRset = new SRRset();

        for (Record rec : records) {
            // Skip RR types that cannot be used as trusted
            // keys. I.e., everything not a key :)
            if (rec.getType() != Type.DNSKEY) {
                continue;
            }

            // If our cur_rrset is empty, we can just add it.
            if (curRRset.size() == 0) {
                curRRset.addRR(rec);

                continue;
            }

            // If this record matches our current RRset, we can just
            // add it.
            if (curRRset.equals(rec)) {
                curRRset.addRR(rec);
                continue;
            }

            // Otherwise, we add the rrset to our set of trust anchors.
            mTrustedKeys.store(curRRset);
            curRRset = new SRRset();
            curRRset.addRR(rec);
        }

        // add the last rrset (if it was not empty)
        if (curRRset.size() > 0) {
            mTrustedKeys.store(curRRset);
        }
    }

    public void addTrustedKeysFromResponse(Message m) {
        List<RRset> rrsets = m.getSectionRRsets(Section.ANSWER);

        for (RRset rrs : rrsets) {
            if (rrs.getType() == Type.DNSKEY) {
                SRRset srrset = new SRRset(rrs);
                mTrustedKeys.store(srrset);
            }
        }
    }

    public void setCustomTime(Instant customTime) {
        mVerifier.setCurrentTime(customTime);
    }

    public void setValidateAllSignatures(boolean value) {
        mVerifier.setValidateAllSignatures(value);
    }

    // ----------------- Validation Support ----------------------

    /**
     * This routine normalizes a response. This includes removing "irrelevant"
     * records from the answer and additional sections and (re)synthesizing
     * CNAMEs from DNAMEs, if present.
     *
     * @param response
     */
    private SMessage normalize(SMessage m) {
        if (m == null) {
            return m;
        }

        if ((m.getRcode() != Rcode.NOERROR)
                && (m.getRcode() != Rcode.NXDOMAIN)) {
            return m;
        }

        Name qname = m.getQuestion().getName();
        int qtype = m.getQuestion().getType();

        Name sname = qname;

        // For the ANSWER section, remove all "irrelevant" records and add
        // synthesized CNAMEs from DNAMEs
        // This will strip out-of-order CNAMEs as well.
        List<SRRset> rrsetList = m.getSectionList(Section.ANSWER);
        Set<Name> additionalNames = new HashSet<>();

        for (ListIterator<SRRset> i = rrsetList.listIterator(); i.hasNext();) {
            SRRset rrset = i.next();
            int type = rrset.getType();
            Name n = rrset.getName();

            // Handle DNAME synthesis; DNAME synthesis does not occur
            // at the DNAME name itself.
            if ((type == Type.DNAME) && ValUtils.strictSubdomain(sname, n)) {
                if (rrset.size() > 1) {
                    log.fine("Found DNAME rrset with size > 1: " + rrset);
                    m.setStatus(SecurityStatus.INVALID);

                    return m;
                }

                DNAMERecord dname = (DNAMERecord) rrset.first();

                try {
                    Name cnameAlias = sname.fromDNAME(dname);

                    // Note that synthesized CNAMEs should have a TTL of zero.
                    CNAMERecord cname = new CNAMERecord(sname, dname.getDClass(), 0, cnameAlias);
                    SRRset cnameRRset = new SRRset();
                    cnameRRset.addRR(cname);
                    i.add(cnameRRset);

                    sname = cnameAlias;
                } catch (NameTooLongException e) {
                    log.fine("not adding synthesized CNAME -- "
                            + "generated name is too long: " + e.toString());
                }

                continue;
            }

            // The only records in the ANSWER section not allowed to
            if (!n.equals(sname)) {
                log.fine("normalize: removing irrelevant rrset: " + rrset);
                i.remove();

                continue;
            }

            // Follow the CNAME chain.
            if (type == Type.CNAME) {
                if (rrset.size() > 1) {
                    mErrorList.add("Found CNAME rrset with size > 1: " + rrset);
                    m.setStatus(SecurityStatus.INVALID);

                    return m;
                }

                CNAMERecord cname = (CNAMERecord) rrset.first();
                sname = cname.getTarget();

                continue;
            }

            // Otherwise, make sure that the RRset matches the qtype.
            if ((qtype != Type.ANY) && (qtype != type)) {
                log.fine("normalize: removing irrelevant rrset: " + rrset);
                i.remove();
            }

            // Otherwise, fetch the additional names from the relevant rrset.
            rrsetAdditionalNames(additionalNames, rrset);
        }

        // Get additional names from AUTHORITY
        rrsetList = m.getSectionList(Section.AUTHORITY);

        for (SRRset rrset : rrsetList) {
            rrsetAdditionalNames(additionalNames, rrset);
        }

        // For each record in the additional section, remove it if it is an
        // address record and not in the collection of additional names found in
        // ANSWER and AUTHORITY.
        rrsetList = m.getSectionList(Section.ADDITIONAL);

        for (Iterator<SRRset> i = rrsetList.iterator(); i.hasNext();) {
            SRRset rrset = i.next();
            int type = rrset.getType();

            if (((type == Type.A) || (type == Type.AAAA))
                    && !additionalNames.contains(rrset.getName())) {

                i.remove();
            }
        }

        return m;
    }

    /**
     * Extract additional names from the records in an rrset.
     *
     * @param additionalNames
     *                            The set to add the additional names to, if
     *                            any.
     * @param rrset
     *                            The rrset to extract from.
     */
    private void rrsetAdditionalNames(Set<Name> additionalNames, SRRset rrset) {
        if (rrset == null) {
            return;
        }

        for (Record r : rrset.rrs()) {
            Name addName = r.getAdditionalName();

            if (addName != null) {
                additionalNames.add(addName);
            }
        }
    }

    private SRRset findKeys(SMessage message) {
        Name qname = message.getQName();
        int qclass = message.getQClass();

        return mTrustedKeys.find(qname, qclass);
    }

    /**
     * Check to see if a given response needs to go through the validation
     * process. Typical reasons for this routine to return false are: CD bit was
     * on in the original request, the response was already validated, or the
     * response is a kind of message that is unvalidatable (i.e., SERVFAIL,
     * REFUSED, etc.)
     *
     * @param message
     *                        The message to check.
     * @param origRequest
     *                        The original request received from the client.
     *
     * @return true if the response could use validation (although this does not
     *         mean we can actually validate this response).
     */
    private boolean needsValidation(SMessage message) {
        int rcode = message.getRcode();

        if ((rcode != Rcode.NOERROR) && (rcode != Rcode.NXDOMAIN)) {
            log.fine("cannot validate non-answer.");
            log.finest("non-answer: " + message);

            return false;
        }

        return mTrustedKeys.isBelowTrustAnchor(message.getQName(), message.getQClass());
    }

    /**
     * Given a "positive" response -- a response that contains an answer to the
     * question, and no CNAME chain, validate this response. This generally
     * consists of verifying the answer RRset and the authority RRsets.
     *
     * Note that by the time this method is called, the process of finding the
     * trusted DNSKEY rrset that signs this response must already have been
     * completed.
     *
     * @param response
     *                      The response to validate.
     * @param request
     *                      The request that generated this response.
     * @param keyRRset
     *                      The trusted DNSKEY rrset that matches the signer of
     *                      the answer.
     */
    private void validatePositiveResponse(SMessage message, SRRset keyRRset) {
        Name qname = message.getQName();
        int qtype = message.getQType();

        SMessage m = message;

        // validate the ANSWER section - this will be the answer itself
        SRRset[] rrsets = m.getSectionRRsets(Section.ANSWER);

        Name wc = null;
        boolean wcNSEC_ok = false;
        boolean dname = false;
        List<NSEC3Record> nsec3s = null;

        for (int i = 0; i < rrsets.length; i++) {
            // Skip the CNAME following a (validated) DNAME.
            // Because of the normalization routines in NameserverClient, there
            // will always be an unsigned CNAME following a DNAME (unless
            // qtype=DNAME).
            if (dname && (rrsets[i].getType() == Type.CNAME)) {
                dname = false;
                continue;
            }

            // Verify the answer rrset.
            int status = mValUtils.verifySRRset(rrsets[i], keyRRset);

            // If the (answer) rrset failed to validate, then this
            // message is bogus.
            if (status != SecurityStatus.SECURE) {
                mErrorList.add("Positive response has failed ANSWER rrset: "
                        + rrsets[i]);
                m.setStatus(SecurityStatus.BOGUS);

                return;
            }

            // Check to see if the rrset is the result of a wildcard expansion.
            // If so, an additional check will need to be made in the authority
            // section.
            wc = ValUtils.rrsetWildcard(rrsets[i]);

            // Notice a DNAME that should be followed by an unsigned CNAME.
            if ((qtype != Type.DNAME) && (rrsets[i].getType() == Type.DNAME)) {
                dname = true;
            }
        }

        // validate the AUTHORITY section as well - this will
        // generally be the NS rrset (which could be missing, no
        // problem)
        rrsets = m.getSectionRRsets(Section.AUTHORITY);

        for (int i = 0; i < rrsets.length; i++) {
            int status = mValUtils.verifySRRset(rrsets[i], keyRRset);

            // If anything in the authority section fails to be
            // secure, we have a bad message.
            if (status != SecurityStatus.SECURE) {
                mErrorList.add("Positive response has failed AUTHORITY rrset: "
                        + rrsets[i]);
                m.setStatus(SecurityStatus.BOGUS);

                return;
            }

            // If this is a positive wildcard response, and we have a
            // (just verified) NSEC record, try to use it to 1) prove
            // that qname doesn't exist and 2) that the correct
            // wildcard was used.
            if ((wc != null) && (rrsets[i].getType() == Type.NSEC)) {
                NSECRecord nsec = (NSECRecord) rrsets[i].first();

                if (ValUtils.nsecProvesNameError(nsec, qname, keyRRset.getName())) {
                    Name nsec_wc = ValUtils.nsecWildcard(qname, nsec);

                    if (!wc.equals(nsec_wc)) {
                        mErrorList.add("Positive wildcard response wasn't generated by the correct wildcard");
                        m.setStatus(SecurityStatus.BOGUS);

                        return;
                    }

                    wcNSEC_ok = true;
                }
            }

            // Otherwise, if this is a positive wildcard response and we have
            // NSEC3 records, collect them.
            if ((wc != null) && (rrsets[i].getType() == Type.NSEC3)) {
                if (nsec3s == null) {
                    nsec3s = new ArrayList<>();
                }

                nsec3s.add((NSEC3Record) rrsets[i].first());
            }
        }

        // If this was a positive wildcard response that we haven't
        // already proven, and we have NSEC3 records, try to prove it
        // using the NSEC3 records.
        if ((wc != null) && !wcNSEC_ok && nsec3s != null
                && NSEC3ValUtils.proveWildcard(nsec3s, qname, keyRRset.getName(), mErrorList)) {
            wcNSEC_ok = true;
        }

        // If after all this, we still haven't proven the positive
        // wildcard response, fail.
        if ((wc != null) && !wcNSEC_ok) {
            m.setStatus(SecurityStatus.BOGUS);

            return;
        }

        log.finest("Successfully validated positive response");
        m.setStatus(SecurityStatus.SECURE);
    }

    /**
     * Given a "referral" type response (RCODE=NOERROR, ANSWER=0, AUTH=NS
     * records under the zone we thought we were talking to, etc.), validate it.
     * This consists of validating the DS or NSEC/NSEC3 RRsets and noting that
     * the response does indeed look like a referral.
     *
     *
     */
    private void validateReferral(SMessage message, SRRset keyRRset) {
        SMessage m = message;

        if (m.getCount(Section.ANSWER) > 0) {
            m.setStatus(SecurityStatus.INVALID);

            return;
        }

        // validate the AUTHORITY section.
        boolean secureDelegation = false;
        Name delegation = null;
        Name nsec3zone = null;
        NSECRecord nsec = null;
        List<NSEC3Record> nsec3s = null;

        // validate the AUTHORITY section as well - this will generally be the
        // NS rrset, plus proof of a secure delegation or not
        SRRset[] rrsets = m.getSectionRRsets(Section.AUTHORITY);

        for (int i = 0; i < rrsets.length; i++) {
            int type = rrsets[i].getType();

            // The NS RRset won't be signed, but everything else
            // should be. If we have an unexpected type here
            // with a bad signature, we will fail when we otherwise
            // might just have warned about the odd record. Consider
            // checking the types first, then validating.
            if (type != Type.NS) {
                int status = mValUtils.verifySRRset(rrsets[i], keyRRset);

                // If anything in the authority section fails to be
                // secure, we have a bad message.
                if (status != SecurityStatus.SECURE) {
                    mErrorList.add("Referral response has failed AUTHORITY rrset: "
                            + rrsets[i]);
                    m.setStatus(SecurityStatus.BOGUS);

                    return;
                }
            }

            switch (type) {
            case Type.DS:
                secureDelegation = true;
                break;

            case Type.NS:
                delegation = rrsets[i].getName();
                break;

            case Type.NSEC:
                nsec = (NSECRecord) rrsets[i].first();
                break;

            case Type.NSEC3:
                if (nsec3s == null) {
                    nsec3s = new ArrayList<>();
                }

                NSEC3Record nsec3 = (NSEC3Record) rrsets[i].first();
                nsec3s.add(nsec3);
                // this is a hack, really.
                nsec3zone = rrsets[i].getSignerName();

                break;

            default:
                log.warning("Encountered unexpected type in a REFERRAL response: "
                        + Type.string(type));

                break;
            }
        }

        // At this point, all validatable RRsets have been validated.
        // Now to check to see if we have a valid combination of
        // things.
        if (delegation == null) {
            // somehow we have a referral without an NS rrset.
            mErrorList.add("Apparent referral does not contain NS RRset");
            m.setStatus(SecurityStatus.BOGUS);

            return;
        }

        if (secureDelegation) {
            if ((nsec != null) || ((nsec3s != null) && (!nsec3s.isEmpty()))) {
                // we found both a DS rrset *and* NSEC/NSEC3 rrsets!
                mErrorList.add("Referral contains both DS and NSEC/NSEC3 RRsets");
                m.setStatus(SecurityStatus.BOGUS);

                return;
            }

            // otherwise, we are done.
            m.setStatus(SecurityStatus.SECURE);

            return;
        }

        // Note: not going to care if both NSEC and NSEC3 rrsets were present.
        if (nsec != null) {
            byte status = ValUtils.nsecProvesNoDS(nsec);

            if (status != SecurityStatus.SECURE) {
                // The NSEC *must* prove that there was no DS
                // record. The INSECURE state here is still bogus.
                mErrorList.add("Referral does not contain a NSEC record proving no DS");
                m.setStatus(SecurityStatus.BOGUS);

                return;
            }

            m.setStatus(SecurityStatus.SECURE);

            return;
        }

        if (nsec3s != null && !nsec3s.isEmpty()) {
            byte status = NSEC3ValUtils.proveNoDS(nsec3s, delegation, nsec3zone, mErrorList);

            if (status != SecurityStatus.SECURE) {
                // the NSEC3 RRs MUST prove no DS, so the INDETERMINATE state is
                // actually bogus
                mErrorList.add("Referral does not contain NSEC3 record(s) proving no DS");
                m.setStatus(SecurityStatus.BOGUS);

                return;
            }

            m.setStatus(SecurityStatus.SECURE);

            return;
        }

        // failed to find proof either way.
        mErrorList.add("Referral does not contain proof of no DS");
        m.setStatus(SecurityStatus.BOGUS);
    }

    // When processing CNAME responses, if we have wildcard-generated CNAMEs we
    // have to keep track of several bits of information per-cname. This small
    // inner class is for that.
    class CNAMEWildcardEntry {
        public Name owner;
        public Name wildcard;
        public Name signer;

        public CNAMEWildcardEntry(Name owner, Name wildcard, Name signer) {
            this.owner = owner;
            this.wildcard = wildcard;
            this.signer = signer;
        }
    }

    // When processing CNAME responses, our final step is check the end of the
    // chain if we ended up in zone. To that end, we generate a temporary
    // message that removes the CNAME/DNAME chain.
    private SMessage messageFromCNAME(SMessage source, Name sname) {

        SMessage m = new SMessage();
        m.setHeader(source.getHeader());
        Record oldQuestion = source.getQuestion();
        Record newQuestion = Record.newRecord(sname, oldQuestion.getType(), oldQuestion.getDClass());
        m.setQuestion(newQuestion);
        m.setOPT(source.getOPT());

        // Add the rrsets from the source message, stripping answers that don't
        // belong to the end of the chain
        RRset[] rrsets = source.getSectionRRsets(Section.ANSWER);
        for (int i = 0; i < rrsets.length; i++) {
            Name rname = rrsets[i].getName();

            if (rname.equals(sname)) {
                m.addRRset(rrsets[i], Section.ANSWER);
            }
        }

        // The authority and additional sections should be about the end of the
        // chain, plus some additional NSEC or NSEC3 records.
        for (int i = Section.AUTHORITY; i <= Section.ADDITIONAL; i++) {
            rrsets = source.getSectionRRsets(i);

            for (int j = 0; j < rrsets.length; j++) {
                m.addRRset(rrsets[j], i);
            }
        }
        return m;
    }

    /**
     * Given a "CNAME" response (i.e., a response that contains at least one
     * CNAME, and qtype != CNAME). This largely consists of validating each
     * CNAME RRset until the CNAME chain goes "out of zone". Note that
     * out-of-order CNAME chains will have been cleaned up via normalize(). When
     * traversing the CNAME chain, we detect if the CNAMEs were generated from a
     * wildcard, and we detect when the chain goes "out-of-zone". For each
     * in-zone wildcard generated CNAME, we check for a proof that the alias
     * (the owner of each cname) doesn't exist.
     *
     * If the end of the chain is still in zone, we then strip the CNAME/DNAME
     * chain, reclassify the response, then validate the "tail message".
     *
     * Note that once the CNAME chain goes out of zone, any further CNAMEs are
     * not DNSSEC validated (we would need more trusted keysets for that), so
     * this isn't useful in all cases (i.e., for testing a nameserver, like
     * BIND, which generates CNAME chains across zones.)
     *
     * Note that by the time this method is called, the process of finding the
     * trusted DNSKEY rrset that signs this response must already have been
     * completed.
     */
    private void validateCNAMEResponse(SMessage message, SRRset keyRRset) {
        Name qname = message.getQName();

        Name sname = qname; // this is the "current" name in the chain
        boolean dname = false; // a flag indicating that prev iteration was a
                               // dname
        boolean inZone = true; // a flag telling us if we ended up in zone.
        // The CNAMEs that were generated with wildcards.
        List<CNAMEWildcardEntry> wildcards = new ArrayList<>();

        Name zone = keyRRset.getName();

        SRRset[] rrsets = message.getSectionRRsets(Section.ANSWER);

        // Validate the ANSWER section RRsets.
        for (int i = 0; i < rrsets.length; i++) {

            int rtype = rrsets[i].getType();
            Name rname = rrsets[i].getName();

            // Follow the CNAME chain
            if (rtype == Type.CNAME) {
                // If we've gotten off track... Note: this should be
                // impossible with normalization in effect.

                if (!sname.equals(rname)) {
                    mErrorList.add("CNAME chain is broken: expected owner name of "
                            + sname + " got: " + rname);
                    message.setStatus(SecurityStatus.BOGUS);
                    return;
                }

                sname = ((CNAMERecord) rrsets[i].first()).getTarget();

                // Check to see if the CNAME was generated by a wildcard. We
                // store the generated name instead of the wildcard value, as we
                // need to prove that the wildcard wasn't blocked. For now, we
                // only want to do that for "in zone" wildcard CNAMEs
                Name wc = ValUtils.rrsetWildcard(rrsets[i]);
                if (wc != null && inZone) {
                    RRSIGRecord rrsig = rrsets[i].firstSig();
                    wildcards.add(new CNAMEWildcardEntry(sname, wc, rrsig.getSigner()));
                }
            }

            // Note when we see a DNAME.
            if (rtype == Type.DNAME) {
                dname = true;
                Name wc = ValUtils.rrsetWildcard(rrsets[i]);
                if (wc != null) {
                    mErrorList.add("Illegal wildcard DNAME found: "
                            + rrsets[i]);
                }
            }

            // Skip validation of CNAMEs following DNAMEs. The
            // normalization step will have synthesized an unsigned
            // CNAME RRset.
            if (dname && rtype == Type.CNAME) {
                dname = false;
                continue;
            }

            int status = mValUtils.verifySRRset(rrsets[i], keyRRset);

            if (status != SecurityStatus.SECURE) {
                mErrorList.add("CNAME response has a failed ANSWER rrset: "
                        + rrsets[i]);
                message.setStatus(SecurityStatus.BOGUS);

                return;
            }

            // Once we've gone off the reservation, avoid further
            // validation.
            if (!sname.subdomain(zone)) {
                inZone = false;
                break;
            }
        }

        log.finest("processed CNAME chain and ended with: " + sname
                + "; inZone = " + inZone);

        // Keep track of NSEC and NSEC3 records we find in the auth section
        // Only add verified records, though.
        List<NSECRecord> nsecs = new ArrayList<>();
        List<NSEC3Record> nsec3s = new ArrayList<>();

        // Validate the AUTHORITY section.
        rrsets = message.getSectionRRsets(Section.ANSWER);
        for (int i = 0; i < rrsets.length; i++) {
            Name rname = rrsets[i].getName();
            int rtype = rrsets[i].getType();

            if (!rname.subdomain(zone)) {
                // Skip auth records that are not in our zone
                // This is a current limitation of this method
                continue;
            }

            int status = mValUtils.verifySRRset(rrsets[i], keyRRset);

            // If anything in the authority section fails to be
            // secure, we have a bad message.
            if (status != SecurityStatus.SECURE) {
                mErrorList.add("Positive response has failed AUTHORITY rrset: "
                        + rrsets[i]);
                message.setStatus(SecurityStatus.BOGUS);

                return;
            }

            // otherwise, collect the validated NSEC and NSEC3 RRs, if any
            if (rtype == Type.NSEC) {
                nsecs.add((NSECRecord) rrsets[i].first());
            } else if (rtype == Type.NSEC3) {
                nsec3s.add((NSEC3Record) rrsets[i].first());
            }
        }

        // Regardless if whether or not we left the reservation, if some of our
        // CNAMEs were generated from wildcards we need to prove that.
        if (!wildcards.isEmpty()) {

            for (CNAMEWildcardEntry wcEntry : wildcards) {
                boolean result = false;
                if (!nsecs.isEmpty()) {
                    for (NSECRecord nsec : nsecs) {
                        result = ValUtils.nsecProvesNameError(nsec, wcEntry.owner, wcEntry.signer);
                        if (result)
                            break;
                    }
                } else if (!nsec3s.isEmpty()) {
                    result = NSEC3ValUtils.proveWildcard(nsec3s, wcEntry.owner, zone, mErrorList);
                }

                if (!result) {
                    mErrorList.add("CNAME response has a wildcard-generated CNAME '"
                            + wcEntry.owner
                            + "' but does not prove that the wildcard '"
                            + wcEntry.wildcard
                            + "' was valid via a covering NSEC or NSEC3 RR");
                    message.setStatus(SecurityStatus.BOGUS);
                    return;
                }
            }
        }

        // If our CNAME chain took us out of zone, we are done.
        if (!inZone) {
            log.finest("Successfully validated CNAME response up to the point where it left our zone.");
            message.setStatus(SecurityStatus.SECURE);
            return;
        }

        // Otherwise, we need to do some additional proofs
        SMessage tailMessage = messageFromCNAME(message, sname);
        ValUtils.ResponseType tailType = ValUtils.classifyResponse(tailMessage, zone);
        switch (tailType) {
        case POSITIVE:
            log.finest("Validating the rest of the CNAME response as a positive response");
            validatePositiveResponse(tailMessage, keyRRset);
            message.setSecurityStatus(tailMessage.getSecurityStatus());
            break;

        case REFERRAL:
            log.finest("Validating the rest of the CNAME response as a referral");
            validateReferral(tailMessage, keyRRset);
            message.setSecurityStatus(tailMessage.getSecurityStatus());
            break;

        case NODATA:
            log.finest("Validating the rest of the CNAME responses as a NODATA response");
            validateNodataResponse(tailMessage, keyRRset, mErrorList);
            message.setSecurityStatus(tailMessage.getSecurityStatus());
            break;

        case NAMEERROR:
            log.finest("Validating a the rest of the CNAME responses as NXDOMAIN response");
            validateNameErrorResponse(tailMessage, keyRRset);
            message.setSecurityStatus(tailMessage.getSecurityStatus());
            break;

        case CNAME:
            log.severe("Reclassified the tail of a CNAME response as a CNAME");
            log.severe(tailMessage.toString());
            message.setStatus(SecurityStatus.BOGUS);
            break;

        case ANY:
            log.severe("Reclassified the tail of a CNAME response as an ANY response");
            log.severe(tailMessage.toString());
            message.setStatus(SecurityStatus.BOGUS);
            break;

        default:
            log.severe("unhandled response subtype: " + tailType);
            message.setStatus(SecurityStatus.BOGUS);
            break;
        }
    }

    /**
     * Given an "ANY" response -- a response that contains an answer to a
     * qtype==ANY question, with answers. This consists of simply verifying all
     * present answer/auth RRsets, with no checking that all types are present.
     *
     * NOTE: it may be possible to get parent-side delegation point records
     * here, which won't all be signed. Right now, this routine relies on the
     * upstream iterative resolver to not return these responses -- instead
     * treating them as referrals.
     *
     * NOTE: RFC 4035 is silent on this issue, so this may change upon
     * clarification.
     *
     * Note that by the time this method is called, the process of finding the
     * trusted DNSKEY rrset that signs this response must already have been
     * completed.
     *
     * @param message
     *                      The response to validate.
     * @param keyRRset
     *                      The trusted DNSKEY rrset that matches the signer of
     *                      the answer.
     */
    private void validateAnyResponse(SMessage message, SRRset keyRRset) {
        int qtype = message.getQType();

        if (qtype != Type.ANY) {
            throw new IllegalArgumentException("ANY validation called on non-ANY response.");
        }

        SMessage m = message;

        // validate the ANSWER section.
        SRRset[] rrsets = m.getSectionRRsets(Section.ANSWER);

        for (int i = 0; i < rrsets.length; i++) {
            int status = mValUtils.verifySRRset(rrsets[i], keyRRset);

            // If the (answer) rrset failed to validate, then this message is
            // BAD.
            if (status != SecurityStatus.SECURE) {
                mErrorList.add("Positive response has failed ANSWER rrset: "
                        + rrsets[i]);
                m.setStatus(SecurityStatus.BOGUS);

                return;
            }
        }

        // validate the AUTHORITY section as well - this will be the NS rrset
        // (which could be missing, no problem)
        rrsets = m.getSectionRRsets(Section.AUTHORITY);

        for (int i = 0; i < rrsets.length; i++) {
            int status = mValUtils.verifySRRset(rrsets[i], keyRRset);

            // If anything in the authority section fails to be secure, we have
            // a bad message.
            if (status != SecurityStatus.SECURE) {
                mErrorList.add("Positive response has failed AUTHORITY rrset: "
                        + rrsets[i]);
                m.setStatus(SecurityStatus.BOGUS);

                return;
            }
        }

        log.finest("Successfully validated positive ANY response");
        m.setStatus(SecurityStatus.SECURE);
    }

    /**
     * Validate a NOERROR/NODATA signed response -- a response that has a
     * NOERROR Rcode but no ANSWER section RRsets. This consists of verifying
     * the authority section rrsets and making certain that the authority
     * section NSEC/NSEC3s proves that the qname does exist and the qtype
     * doesn't.
     *
     * Note that by the time this method is called, the process of finding the
     * trusted DNSKEY rrset that signs this response must already have been
     * completed.
     *
     * @param response
     *                      The response to validate.
     * @param request
     *                      The request that generated this response.
     * @param keyRRset
     *                      The trusted DNSKEY rrset that signs this response.
     */
    private void validateNodataResponse(SMessage message, SRRset keyRRset,
            List<String> errorList) {
        Name qname = message.getQName();
        int qtype = message.getQType();

        SMessage m = message;

        // Since we are here, there must be nothing in the ANSWER
        // section to validate.

        // validate the AUTHORITY section
        SRRset[] rrsets = m.getSectionRRsets(Section.AUTHORITY);

        // If true, then the NODATA has been proven.
        boolean hasValidNSEC = false;

        // for wildcard NODATA responses. This is the proven closest
        // encloser.
        Name ce = null;

        // for wildcard NODATA responses. This is the wildcard NSEC.
        NSECRecord wc = null;

        // A collection of NSEC3 RRs found in the authority section.
        List<NSEC3Record> nsec3s = null;

        // The RRSIG signer field for the NSEC3 RRs.
        Name nsec3Signer = null;

        for (int i = 0; i < rrsets.length; i++) {
            int status = mValUtils.verifySRRset(rrsets[i], keyRRset);

            if (status != SecurityStatus.SECURE) {
                mErrorList.add("NODATA response has failed AUTHORITY rrset: "
                        + rrsets[i]);
                m.setStatus(SecurityStatus.BOGUS);

                return;
            }

            // If we encounter an NSEC record, try to use it to prove NODATA.
            // This needs to handle the ENT NODATA case.
            if (rrsets[i].getType() == Type.NSEC) {
                NSECRecord nsec = (NSECRecord) rrsets[i].first();

                if (ValUtils.nsecProvesNodata(nsec, qname, qtype)) {
                    hasValidNSEC = true;

                    if (nsec.getName().isWild()) {
                        wc = nsec;
                    }
                } else if (ValUtils.nsecProvesNameError(nsec, qname, rrsets[i].getSignerName())) {
                    ce = ValUtils.closestEncloser(qname, nsec);
                }
            }

            // Collect any NSEC3 records present.
            if (rrsets[i].getType() == Type.NSEC3) {
                if (nsec3s == null) {
                    nsec3s = new ArrayList<>();
                }

                nsec3s.add((NSEC3Record) rrsets[i].first());
                nsec3Signer = rrsets[i].getSignerName();
            }
        }

        // check to see if we have a wildcard NODATA proof.

        // The wildcard NODATA is 1 NSEC proving that qname does not
        // exists (and also proving what the closest encloser is), and
        // 1 NSEC showing the matching wildcard, which must be
        // *.closest_encloser.
        if ((ce != null) || (wc != null)) {
            try {
                Name wcName = new Name("*", ce);

                if (!wcName.equals(wc.getName())) {
                    hasValidNSEC = false;
                }
            } catch (TextParseException e) {
                log.log(Level.SEVERE, "Error parsing name", e);
            }
        }

        NSEC3ValUtils.stripUnknownAlgNSEC3s(nsec3s);

        if (!hasValidNSEC && (nsec3s != null) && (!nsec3s.isEmpty())) {
            // try to prove NODATA with our NSEC3 record(s)
            hasValidNSEC = NSEC3ValUtils.proveNodata(nsec3s, qname, qtype, nsec3Signer, errorList);
        }

        if (!hasValidNSEC) {
            log.fine("NODATA response failed to prove NODATA "
                    + "status with NSEC/NSEC3");
            log.fine("Failed NODATA:\n" + m);
            mErrorList.add("NODATA response failed to prove NODATA status with NSEC/NSEC3");
            m.setStatus(SecurityStatus.BOGUS);

            return;
        }

        log.finest("successfully validated NODATA response.");
        m.setStatus(SecurityStatus.SECURE);
    }

    /**
     * Validate a NAMEERROR signed response -- a response that has a NXDOMAIN
     * Rcode. This consists of verifying the authority section rrsets and making
     * certain that the authority section NSEC proves that the qname doesn't
     * exist and the covering wildcard also doesn't exist..
     *
     * Note that by the time this method is called, the process of finding the
     * trusted DNSKEY rrset that signs this response must already have been
     * completed.
     *
     * @param response
     *                      The response to validate.
     * @param request
     *                      The request that generated this response.
     * @param keyRRset
     *                      The trusted DNSKEY rrset that signs this response.
     */
    private void validateNameErrorResponse(SMessage message, SRRset keyRRset) {
        Name qname = message.getQName();

        SMessage m = message;

        if (message.getCount(Section.ANSWER) > 0) {
            log.warning("NameError response contained records in the ANSWER SECTION");
            mErrorList.add("NameError response contained records in the ANSWER SECTION");
            message.setStatus(SecurityStatus.INVALID);

            return;
        }

        // Validate the authority section -- all RRsets in the authority section
        // must be signed and valid.
        // In addition, the NSEC record(s) must prove the NXDOMAIN condition.
        boolean hasValidNSEC = false;
        boolean hasValidWCNSEC = false;
        SRRset[] rrsets = m.getSectionRRsets(Section.AUTHORITY);
        List<NSEC3Record> nsec3s = null;
        Name nsec3Signer = null;

        for (int i = 0; i < rrsets.length; i++) {
            int status = mValUtils.verifySRRset(rrsets[i], keyRRset);

            if (status != SecurityStatus.SECURE) {
                mErrorList.add("NameError response has failed AUTHORITY rrset: "
                        + rrsets[i]);
                m.setStatus(SecurityStatus.BOGUS);

                return;
            }

            if (rrsets[i].getType() == Type.NSEC) {
                NSECRecord nsec = (NSECRecord) rrsets[i].first();

                if (ValUtils.nsecProvesNameError(nsec, qname, rrsets[i].getSignerName())) {
                    hasValidNSEC = true;
                }

                if (ValUtils.nsecProvesNoWC(nsec, qname, rrsets[i].getSignerName())) {
                    hasValidWCNSEC = true;
                }
            }

            if (rrsets[i].getType() == Type.NSEC3) {
                if (nsec3s == null) {
                    nsec3s = new ArrayList<>();
                }

                nsec3s.add((NSEC3Record) rrsets[i].first());
                nsec3Signer = rrsets[i].getSignerName();
            }
        }

        NSEC3ValUtils.stripUnknownAlgNSEC3s(nsec3s);

        if ((nsec3s != null) && (!nsec3s.isEmpty())) {
            log.fine("Validating nxdomain: using NSEC3 records");

            // Attempt to prove name error with nsec3 records.
            if (NSEC3ValUtils.allNSEC3sIgnoreable(nsec3s, keyRRset, mVerifier)) {
                // log.debug("all NSEC3s were validated but ignored.")
                m.setStatus(SecurityStatus.INSECURE);

                return;
            }

            hasValidNSEC = NSEC3ValUtils.proveNameError(nsec3s, qname, nsec3Signer, mErrorList);

            // Note that we assume that the NSEC3ValUtils proofs
            // encompass the wildcard part of the proof.
            hasValidWCNSEC = hasValidNSEC;
        }

        // If the message fails to prove either condition, it is bogus.
        if (!hasValidNSEC) {
            mErrorList.add("NameError response has failed to prove qname does not exist");
            m.setStatus(SecurityStatus.BOGUS);

            return;
        }

        if (!hasValidWCNSEC) {
            mErrorList.add("NameError response has failed to prove covering wildcard does not exist");
            m.setStatus(SecurityStatus.BOGUS);

            return;
        }

        // Otherwise, we consider the message secure.
        log.finest("successfully validated NAME ERROR response.");
        m.setStatus(SecurityStatus.SECURE);
    }

    public byte validateMessage(SMessage message, Name zone) {
        mErrorList.clear();
        if (!zone.isAbsolute()) {
            try {
                zone = Name.concatenate(zone, Name.root);
            } catch (NameTooLongException e) {
                log.log(Level.SEVERE, "Name was too long", e);

                return SecurityStatus.UNCHECKED;
            }
        }

        // It is unclear if we should actually normalize our
        // responses Instead, maybe we should just fail if they are
        // not normal?
        message = normalize(message);

        if (!needsValidation(message)) {
            return SecurityStatus.UNCHECKED;
        }

        SRRset keyRRset = findKeys(message);

        if (keyRRset == null) {
            mErrorList.add("Failed to find matching DNSKEYs for the response");
            return SecurityStatus.BOGUS;
        }

        ValUtils.ResponseType subtype = ValUtils.classifyResponse(message, zone);

        switch (subtype) {
        case POSITIVE:
            log.finest("Validating a positive response");
            validatePositiveResponse(message, keyRRset);
            break;

        case REFERRAL:
            validateReferral(message, keyRRset);
            break;

        case NODATA:
            log.finest("Validating a NODATA response");
            validateNodataResponse(message, keyRRset, mErrorList);
            break;

        case NAMEERROR:
            log.finest("Validating a NXDOMAIN response");
            validateNameErrorResponse(message, keyRRset);
            break;

        case CNAME:
            log.finest("Validating a CNAME response");
            validateCNAMEResponse(message, keyRRset);
            break;

        case ANY:
            log.finest("Validating a positive ANY response");
            validateAnyResponse(message, keyRRset);
            break;

        default:
            log.severe("unhandled response subtype: " + subtype);
        }

        return message.getSecurityStatus().getStatus();
    }

    public byte validateMessage(Message message, String zone)
            throws TextParseException {
        SMessage sm = new SMessage(message);
        Name z = Name.fromString(zone);

        return validateMessage(sm, z);
    }

    public byte validateMessage(byte[] messagebytes, String zone)
            throws IOException {
        Message message = new Message(messagebytes);
        return validateMessage(message, zone);
    }

    public byte validateMessage(String b64messagebytes, String zone)
            throws IOException {
        byte[] messagebytes = base64.fromString(b64messagebytes);
        return validateMessage(messagebytes, zone);
    }

    public List<String> listTrustedKeys() {
        return mTrustedKeys.listTrustAnchors();
    }

    public List<String> getErrorList() {
        return mErrorList;
    }
}
