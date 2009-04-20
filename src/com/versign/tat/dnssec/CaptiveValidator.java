/*
 * Copyright (c) 2009 VeriSign, Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

package com.versign.tat.dnssec;

import java.io.IOException;
import java.util.*;

import org.xbill.DNS.*;

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
    private ValUtils         mValUtils;

    // The local verification utility.
    private DnsSecVerifier   mVerifier;

    public CaptiveValidator() {
        mVerifier = new DnsSecVerifier();
        mValUtils = new ValUtils(mVerifier);
        mTrustedKeys = new TrustAnchorStore();
    }

    // ---------------- Module Initialization -------------------

    /**
     * Add a set of trusted keys from a file. The file should be in DNS master
     * zone file format. Only DNSKEY records will be added.
     * 
     * @param filename
     *            The file contains the trusted keys.
     * @throws IOException
     */
    @SuppressWarnings("unchecked")
    public void addTrustedKeysFromFile(String filename) throws IOException {
        // First read in the whole trust anchor file.
        Master master = new Master(filename, Name.root, 0);
        ArrayList<Record> records = new ArrayList<Record>();
        Record r = null;

        while ((r = master.nextRecord()) != null) {
            records.add(r);
        }

        // Record.compareTo() should sort them into DNSSEC canonical order.
        // Don't care about canonical order per se, but do want them to be
        // formable into RRsets.
        Collections.sort(records);

        SRRset cur_rrset = new SRRset();
        for (Record rec : records) {
            // Skip RR types that cannot be used as trusted keys. I.e.,
            // everything not a key :)
            if (rec.getType() != Type.DNSKEY) continue;

            // If our cur_rrset is empty, we can just add it.
            if (cur_rrset.size() == 0) {
                cur_rrset.addRR(rec);
                continue;
            }
            // If this record matches our current RRset, we can just add it.
            if (cur_rrset.getName().equals(rec.getName())
                && cur_rrset.getType() == rec.getType()
                && cur_rrset.getDClass() == rec.getDClass()) {
                cur_rrset.addRR(rec);
                continue;
            }

            // Otherwise, we add the rrset to our set of trust anchors.
            mTrustedKeys.store(cur_rrset);
            cur_rrset = new SRRset();
            cur_rrset.addRR(rec);
        }

        // add the last rrset (if it was not empty)
        if (cur_rrset.size() > 0) {
            mTrustedKeys.store(cur_rrset);
        }
    }
    
    public void addTrustedKeysFromResponse(Message m) {
        RRset[] rrsets = m.getSectionRRsets(Section.ANSWER);
        for (int i = 0; i < rrsets.length; ++i) {
            if (rrsets[i].getType() == Type.DNSKEY) {
                SRRset srrset = new SRRset(rrsets[i]);
                mTrustedKeys.store(srrset);
            }
        }
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
        if (m == null) return m;

        if (m.getRcode() != Rcode.NOERROR && m.getRcode() != Rcode.NXDOMAIN) {
            return m;
        }

        Name qname = m.getQuestion().getName();
        int qtype = m.getQuestion().getType();

        Name sname = qname;

        // For the ANSWER section, remove all "irrelevant" records and add
        // synthesized CNAMEs from DNAMEs
        // This will strip out-of-order CNAMEs as well.
        List<SRRset> rrset_list = m.getSectionList(Section.ANSWER);
        Set<Name> additional_names = new HashSet<Name>();

        for (ListIterator<SRRset> i = rrset_list.listIterator(); i.hasNext();) {
            SRRset rrset = i.next();
            int type = rrset.getType();
            Name n = rrset.getName();

            // Handle DNAME synthesis; DNAME synthesis does not occur at the
            // DNAME name itself.
            if (type == Type.DNAME && ValUtils.strictSubdomain(sname, n)) {
                if (rrset.size() > 1) {
                    // log.debug("Found DNAME rrset with size > 1: " + rrset);
                    // return Util.errorMessage(m, Rcode.SERVFAIL);
                    return null; // FIXME
                }
                DNAMERecord dname = (DNAMERecord) rrset.first();
                try {
                    Name cname_alias = sname.fromDNAME(dname);
                    // Note that synthesized CNAMEs should have a TTL of zero.

                    CNAMERecord cname = new CNAMERecord(sname,
                            dname.getDClass(), 0, cname_alias);
                    SRRset cname_rrset = new SRRset();
                    cname_rrset.addRR(cname);
                    i.add(cname_rrset);

                    sname = cname_alias;
                } catch (NameTooLongException e) {
//                    log.debug("not adding synthesized CNAME -- "
//                              + "generated name is too long", e);
                }
                continue;
            }

            // The only records in the ANSWER section not allowed to
            if (!n.equals(sname)) {
//                log.debug("normalize: removing irrelevant rrset: " + rrset);
                i.remove();
                continue;
            }

            // Follow the CNAME chain.
            if (type == Type.CNAME) {
                if (rrset.size() > 1) {
//                    log.debug("Found CNAME rrset with size > 1: " + rrset);
//                    return Util.errorMessage(m, Rcode.SERVFAIL);
                    return null; // FIXME
                }

                CNAMERecord cname = (CNAMERecord) rrset.first();
                sname = cname.getAlias();
                continue;
            }

            // Otherwise, make sure that the RRset matches the qtype.
            if (qtype != Type.ANY && qtype != type) {
//                log.debug("normalize: removing irrelevant rrset: " + rrset);
                i.remove();
            }

            // Otherwise, fetch the additional names from the relevant rrset.
            rrsetAdditionalNames(additional_names, rrset);
        }

        // Get additional names from AUTHORITY
        rrset_list = m.getSectionList(Section.AUTHORITY);
        for (SRRset rrset : rrset_list) {
            rrsetAdditionalNames(additional_names, rrset);
        }

        // For each record in the additional section, remove it if it is an
        // address record and not in the collection of additional names found in
        // ANSWER and AUTHORITY.
        rrset_list = m.getSectionList(Section.ADDITIONAL);
        for (Iterator<SRRset> i = rrset_list.iterator(); i.hasNext();) {
            SRRset rrset = i.next();
            int type = rrset.getType();
            if ((type == Type.A || type == Type.AAAA)
                && !additional_names.contains(rrset.getName())) {
                i.remove();
            }
            // FIXME: what about other types?
        }

        return m;
    }
    
    /**
     * Extract additional names from the records in an rrset.
     * 
     * @param additional_names
     *            The set to add the additional names to, if any.
     * @param rrset
     *            The rrset to extract from.
     */
    private void rrsetAdditionalNames(Set<Name> additional_names, SRRset rrset) {
        if (rrset == null) return;

        for (Iterator<Record> i = rrset.rrs(); i.hasNext();) {
            Record r = i.next();
            Name add_name = r.getAdditionalName();
            if (add_name != null) {
                additional_names.add(add_name);
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
     *            The message to check.
     * @param origRequest
     *            The original request received from the client.
     * 
     * @return true if the response could use validation (although this does not
     *         mean we can actually validate this response).
     */
    private boolean needsValidation(SMessage message) {
        int rcode = message.getRcode();

        if (rcode != Rcode.NOERROR && rcode != Rcode.NXDOMAIN) {
            // log.debug("cannot validate non-answer.");
            // log.trace("non-answer: " + response);
            return false;
        }
        
        if (!mTrustedKeys.isBelowTrustAnchor(message.getQName(), message.getQClass())) {
            return false;
        }
        return true;
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
     *            The response to validate.
     * @param request
     *            The request that generated this response.
     * @param key_rrset
     *            The trusted DNSKEY rrset that matches the signer of the
     *            answer.
     */
    private void validatePositiveResponse(SMessage message, SRRset key_rrset) {
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
            if (dname && rrsets[i].getType() == Type.CNAME) {
                dname = false;
                continue;
            }

            // Verify the answer rrset.
            int status = mValUtils.verifySRRset(rrsets[i], key_rrset);
            // If the (answer) rrset failed to validate, then this message is
            // BAD.
            if (status != SecurityStatus.SECURE) {
                // log.debug("Positive response has failed ANSWER rrset: "
                // + rrsets[i]);
                m.setStatus(SecurityStatus.BOGUS);
                return;
            }
            // Check to see if the rrset is the result of a wildcard expansion.
            // If so, an additional check will need to be made in the authority
            // section.
            wc = ValUtils.rrsetWildcard(rrsets[i]);

            // Notice a DNAME that should be followed by an unsigned CNAME.
            if (qtype != Type.DNAME && rrsets[i].getType() == Type.DNAME) {
                dname = true;
            }
        }

        // validate the AUTHORITY section as well - this will generally be the
        // NS rrset (which could be missing, no problem)
        rrsets = m.getSectionRRsets(Section.AUTHORITY);
        for (int i = 0; i < rrsets.length; i++) {
            int status = mValUtils.verifySRRset(rrsets[i], key_rrset);
            // If anything in the authority section fails to be secure, we have
            // a
            // bad message.
            if (status != SecurityStatus.SECURE) {
                // log.debug("Positive response has failed AUTHORITY rrset: "
                // + rrsets[i]);
                m.setStatus(SecurityStatus.BOGUS);
                return;
            }

            // If this is a positive wildcard response, and we have a (just
            // verified) NSEC record, try to use it to 1) prove that qname
            // doesn't exist and 2) that the correct wildcard was used.
            if (wc != null && rrsets[i].getType() == Type.NSEC) {
                NSECRecord nsec = (NSECRecord) rrsets[i].first();

                if (ValUtils.nsecProvesNameError(nsec, qname,
                                                 key_rrset.getName())) {
                    Name nsec_wc = ValUtils.nsecWildcard(qname, nsec);
                    if (!wc.equals(nsec_wc)) {
                        // log.debug("Positive wildcard response wasn't generated "
                        // + "by the correct wildcard");
                        m.setStatus(SecurityStatus.BOGUS);
                        return;
                    }
                    wcNSEC_ok = true;
                }
            }

            // Otherwise, if this is a positive wildcard response and we have
            // NSEC3 records, collect them.
            if (wc != null && rrsets[i].getType() == Type.NSEC3) {
                if (nsec3s == null) nsec3s = new ArrayList<NSEC3Record>();
                nsec3s.add((NSEC3Record) rrsets[i].first());
            }
        }

        // If this was a positive wildcard response that we haven't already
        // proven, and we have NSEC3 records, try to prove it using the NSEC3
        // records.
        if (wc != null && !wcNSEC_ok && nsec3s != null) {
            if (NSEC3ValUtils.proveWildcard(nsec3s, qname, key_rrset.getName(),
                                            wc)) {
                wcNSEC_ok = true;
            }
        }

        // If after all this, we still haven't proven the positive wildcard
        // response, fail.
        if (wc != null && !wcNSEC_ok) {
            // log.debug("positive response was wildcard expansion and "
            // + "did not prove original data did not exist");
            m.setStatus(SecurityStatus.BOGUS);
            return;
        }

        // log.trace("Successfully validated positive response");
        m.setStatus(SecurityStatus.SECURE);
    }

    private void validateReferral(SMessage message, SRRset key_rrset) {
        SMessage m = message;

        if (m.getCount(Section.ANSWER) > 0) {
            // FIXME: fail somehow.
        }

        // validate the AUTHORITY section.
        SRRset[] rrsets = m.getSectionRRsets(Section.AUTHORITY);

        boolean secure_delegation = false;
        Name delegation = null;
        Name nsec3zone  = null;
        NSECRecord nsec = null;
        List<NSEC3Record> nsec3s = null;

        // validate the AUTHORITY section as well - this will generally be the
        // NS rrset, plus proof of a secure delegation or not
        rrsets = m.getSectionRRsets(Section.AUTHORITY);
        for (int i = 0; i < rrsets.length; i++) {
            int status = mValUtils.verifySRRset(rrsets[i], key_rrset);
            // If anything in the authority section fails to be secure, we have
            // a bad message.
            if (status != SecurityStatus.SECURE) {
                // log.debug("Positive response has failed AUTHORITY rrset: "
                // + rrsets[i]);
                m.setStatus(SecurityStatus.BOGUS);
                return;
            }

            int type = rrsets[i].getType();
            switch (type) {
            case Type.DS:
                secure_delegation = true;
                break;
            case Type.NS:
                delegation = rrsets[i].getName();
                break;
            case Type.NSEC:
                nsec = (NSECRecord) rrsets[i].first();
                break;
            case Type.NSEC3:
                if (nsec3s == null) nsec3s = new ArrayList<NSEC3Record>();
                NSEC3Record nsec3 = (NSEC3Record) rrsets[i].first();
                nsec3s.add(nsec3);
                nsec3zone = rrsets[i].getSignerName(); // this is a hack of sorts.
                break;
            default:
                // FIXME: should probably whine if we see something else.
                break;
            }
        }
        
        // At this point, all validatable RRsets have been validated.
        // Now to check to see if we have a valid combination of things.
        if (delegation == null) {
            // somehow we have a referral without an NS rrset.
            m.setStatus(SecurityStatus.BOGUS);
            return;
        }
        
        if (secure_delegation) {
            if (nsec != null || nsec3s.size() > 0) {
                // we found both a DS rrset *and* NSEC/NSEC3 rrsets! 
                m.setStatus(SecurityStatus.BOGUS);
                return;
            }
            // otherwise, we are done.
            m.setStatus(SecurityStatus.SECURE);
            return;
        }

        // Note: not going to care if both NSEC and NSEC3 rrsets were present.
        if (nsec != null) {
            byte status = ValUtils.nsecProvesNoDS(nsec, delegation);
            if (status != SecurityStatus.SECURE) {
                // The NSEC *must* prove that there was no DS record.  The INSECURE state here is still bogus.
                m.setStatus(SecurityStatus.BOGUS);
                return;
            }
            m.setStatus(SecurityStatus.SECURE);
            return;
        }
        
        if (nsec3s.size() > 0) {
            byte status = NSEC3ValUtils.proveNoDS(nsec3s, delegation, nsec3zone);
            if (status != SecurityStatus.SECURE) {
                // the NSEC3 RRs MUST prove no DS, so the INDETERMINATE state is actually bogus
                m.setStatus(SecurityStatus.BOGUS);
                return;
            }
            m.setStatus(SecurityStatus.SECURE);
            return;            
        }

        // failed to find proof either way.
        m.setStatus(SecurityStatus.BOGUS);
    }

    private void validateCNAMEResponse(SMessage message, SRRset key_rrset) {

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
     *            The response to validate.
     * @param key_rrset
     *            The trusted DNSKEY rrset that matches the signer of the
     *            answer.
     */
    private void validateAnyResponse(SMessage message, SRRset key_rrset) {
        int qtype = message.getQType();

        if (qtype != Type.ANY)
            throw new IllegalArgumentException(
                    "ANY validation called on non-ANY response.");

        SMessage m = message;

        // validate the ANSWER section.
        SRRset[] rrsets = m.getSectionRRsets(Section.ANSWER);
        for (int i = 0; i < rrsets.length; i++) {
            int status = mValUtils.verifySRRset(rrsets[i], key_rrset);
            // If the (answer) rrset failed to validate, then this message is
            // BAD.
            if (status != SecurityStatus.SECURE) {
                // log.debug("Positive response has failed ANSWER rrset: "
                // + rrsets[i]);
                m.setStatus(SecurityStatus.BOGUS);
                return;
            }
        }

        // validate the AUTHORITY section as well - this will be the NS rrset
        // (which could be missing, no problem)
        rrsets = m.getSectionRRsets(Section.AUTHORITY);
        for (int i = 0; i < rrsets.length; i++) {
            int status = mValUtils.verifySRRset(rrsets[i], key_rrset);
            // If anything in the authority section fails to be secure, we have
            // a
            // bad message.
            if (status != SecurityStatus.SECURE) {
                // log.debug("Positive response has failed AUTHORITY rrset: "
                // + rrsets[i]);
                m.setStatus(SecurityStatus.BOGUS);
                return;
            }
        }

        // log.trace("Successfully validated positive ANY response");
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
     *            The response to validate.
     * @param request
     *            The request that generated this response.
     * @param key_rrset
     *            The trusted DNSKEY rrset that signs this response.
     */
    private void validateNodataResponse(SMessage message, SRRset key_rrset) {
        Name qname = message.getQName();
        int qtype = message.getQType();

        SMessage m = message;

        // Since we are here, there must be nothing in the ANSWER section to
        // validate. (Note: CNAME/DNAME responses will not directly get here --
        // instead they are broken down into individual CNAME/DNAME/final answer
        // responses.)

        // validate the AUTHORITY section
        SRRset[] rrsets = m.getSectionRRsets(Section.AUTHORITY);

        boolean hasValidNSEC = false; // If true, then the NODATA has been
        // proven.
        Name ce = null; // for wildcard NODATA responses. This is the proven
        // closest encloser.
        NSECRecord wc = null; // for wildcard NODATA responses. This is the
        // wildcard NSEC.
        List<NSEC3Record> nsec3s = null; // A collection of NSEC3 RRs found in the authority
        // section.
        Name nsec3Signer = null; // The RRSIG signer field for the NSEC3 RRs.

        for (int i = 0; i < rrsets.length; i++) {
            int status = mValUtils.verifySRRset(rrsets[i], key_rrset);
            if (status != SecurityStatus.SECURE) {
                // log.debug("NODATA response has failed AUTHORITY rrset: "
                // + rrsets[i]);
                m.setStatus(SecurityStatus.BOGUS);
                return;
            }

            // If we encounter an NSEC record, try to use it to prove NODATA.
            // This needs to handle the ENT NODATA case.
            if (rrsets[i].getType() == Type.NSEC) {
                NSECRecord nsec = (NSECRecord) rrsets[i].first();
                if (ValUtils.nsecProvesNodata(nsec, qname, qtype)) {
                    hasValidNSEC = true;
                    if (nsec.getName().isWild()) wc = nsec;
                } else if (ValUtils.nsecProvesNameError(
                                                        nsec,
                                                        qname,
                                                        rrsets[i].getSignerName())) {
                    ce = ValUtils.closestEncloser(qname, nsec);
                }
            }

            // Collect any NSEC3 records present.
            if (rrsets[i].getType() == Type.NSEC3) {
                if (nsec3s == null) nsec3s = new ArrayList<NSEC3Record>();
                nsec3s.add((NSEC3Record) rrsets[i].first());
                nsec3Signer = rrsets[i].getSignerName();
            }
        }

        // check to see if we have a wildcard NODATA proof.

        // The wildcard NODATA is 1 NSEC proving that qname does not exists (and
        // also proving what the closest encloser is), and 1 NSEC showing the
        // matching wildcard, which must be *.closest_encloser.
        if (ce != null || wc != null) {
            try {
                Name wc_name = new Name("*", ce);
                if (!wc_name.equals(wc.getName())) {
                    hasValidNSEC = false;
                }
            } catch (TextParseException e) {
                // log.error(e);
            }
        }

        NSEC3ValUtils.stripUnknownAlgNSEC3s(nsec3s);

        if (!hasValidNSEC && nsec3s != null && nsec3s.size() > 0) {
            // try to prove NODATA with our NSEC3 record(s)
            hasValidNSEC = NSEC3ValUtils.proveNodata(nsec3s, qname, qtype,
                                                     nsec3Signer);
        }

        if (!hasValidNSEC) {
            // log.debug("NODATA response failed to prove NODATA "
            // + "status with NSEC/NSEC3");
            // log.trace("Failed NODATA:\n" + m);
            m.setStatus(SecurityStatus.BOGUS);
            return;
        }
        // log.trace("successfully validated NODATA response.");
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
     *            The response to validate.
     * @param request
     *            The request that generated this response.
     * @param key_rrset
     *            The trusted DNSKEY rrset that signs this response.
     */
    private void validateNameErrorResponse(SMessage message, SRRset key_rrset) {
        Name qname = message.getQName();

        SMessage m = message;

        // FIXME: should we check to see if there is anything in the answer
        // section? if so, what should the result be?

        // Validate the authority section -- all RRsets in the authority section
        // must be signed and valid.
        // In addition, the NSEC record(s) must prove the NXDOMAIN condition.

        boolean hasValidNSEC = false;
        boolean hasValidWCNSEC = false;
        SRRset[] rrsets = m.getSectionRRsets(Section.AUTHORITY);
        List<NSEC3Record> nsec3s = null;
        Name nsec3Signer = null;

        for (int i = 0; i < rrsets.length; i++) {
            int status = mValUtils.verifySRRset(rrsets[i], key_rrset);
            if (status != SecurityStatus.SECURE) {
                // log.debug("NameError response has failed AUTHORITY rrset: "
                // + rrsets[i]);
                m.setStatus(SecurityStatus.BOGUS);
                return;
            }
            if (rrsets[i].getType() == Type.NSEC) {
                NSECRecord nsec = (NSECRecord) rrsets[i].first();

                if (ValUtils.nsecProvesNameError(nsec, qname,
                                                 rrsets[i].getSignerName())) {
                    hasValidNSEC = true;
                }
                if (ValUtils.nsecProvesNoWC(nsec, qname,
                                            rrsets[i].getSignerName())) {
                    hasValidWCNSEC = true;
                }
            }
            if (rrsets[i].getType() == Type.NSEC3) {
                if (nsec3s == null) nsec3s = new ArrayList<NSEC3Record>();
                nsec3s.add((NSEC3Record) rrsets[i].first());
                nsec3Signer = rrsets[i].getSignerName();
            }
        }

        NSEC3ValUtils.stripUnknownAlgNSEC3s(nsec3s);

        if (nsec3s != null && nsec3s.size() > 0) {
            // log.debug("Validating nxdomain: using NSEC3 records");
            // Attempt to prove name error with nsec3 records.

            if (NSEC3ValUtils.allNSEC3sIgnoreable(nsec3s, key_rrset, mVerifier)) {
                // log.debug("all NSEC3s were validated but ignored.");
                m.setStatus(SecurityStatus.INSECURE);
                return;
            }

            hasValidNSEC = NSEC3ValUtils.proveNameError(nsec3s, qname,
                                                        nsec3Signer);

            // Note that we assume that the NSEC3ValUtils proofs encompass the
            // wildcard part of the proof.
            hasValidWCNSEC = hasValidNSEC;
        }

        // If the message fails to prove either condition, it is bogus.
        if (!hasValidNSEC) {
            // log.debug("NameError response has failed to prove: "
            // + "qname does not exist");
            m.setStatus(SecurityStatus.BOGUS);
            return;
        }

        if (!hasValidWCNSEC) {
            // log.debug("NameError response has failed to prove: "
            // + "covering wildcard does not exist");
            m.setStatus(SecurityStatus.BOGUS);
            return;
        }

        // Otherwise, we consider the message secure.
        // log.trace("successfully validated NAME ERROR response.");
        m.setStatus(SecurityStatus.SECURE);
    }

    public byte validateMessage(SMessage message, Name zone) {

        // FIXME: it is unclear if we should actually normalize our responses
        // Instead, maybe we should just fail if they are not normal?
        message = normalize(message);
        
        if (! needsValidation(message)) {
            return SecurityStatus.UNCHECKED;
        }
        
        SRRset key_rrset = findKeys(message);
        if (key_rrset == null) {
            return SecurityStatus.BOGUS;
        }

        ValUtils.ResponseType subtype = ValUtils.classifyResponse(message, zone);

        switch (subtype) {
        case POSITIVE:
            // log.trace("Validating a positive response");
            validatePositiveResponse(message, key_rrset);
            break;
        case REFERRAL:
            validateReferral(message, key_rrset);
            break;
        case NODATA:
            // log.trace("Validating a NODATA response");
            validateNodataResponse(message, key_rrset);
            break;
        case NAMEERROR:
            // log.trace("Validating a NXDOMAIN response");
            validateNameErrorResponse(message, key_rrset);
            break;
        case CNAME:
            // log.trace("Validating a CNAME response");
            // forward on to the special CNAME state for this.
            // state.state = ValEventState.CNAME_STATE;
            validateCNAMEResponse(message, key_rrset);
            break;
        case ANY:
            // log.trace("Validating a positive ANY response");
            validateAnyResponse(message, key_rrset);
            break;
        default:
            // log.error("unhandled response subtype: " + subtype);
        }

        return message.getSecurityStatus().getStatus();

    }
}
