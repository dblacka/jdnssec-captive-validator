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

package se.rfc.unbound;

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
     * Initialize the module.
     */
    public void init(Properties config) throws Exception {
        mVerifier.init(config);

        String s = config.getProperty("dns.trust_anchor_file");
        if (s != null) {
            try {
                loadTrustAnchors(s);
            } catch (IOException e) {
                System.err.println("Error loading trust anchors: " + e);
            }
        }
    }

    /**
     * Load the trust anchor file into the trust anchor store. The trust anchors
     * are currently stored in a zone file format list of DNSKEY or DS records.
     * 
     * @param filename
     *            The trust anchor file.
     * @throws IOException
     */
    private void loadTrustAnchors(String filename) throws IOException {
        System.err.println("reading trust anchor file file: " + filename);

        // First read in the whole trust anchor file.
        Master master = new Master(filename, Name.root, 0);
        ArrayList records = new ArrayList();
        Record r = null;

        while ((r = master.nextRecord()) != null) {
            records.add(r);
        }

        // Record.compareTo() should sort them into DNSSEC canonical order.
        // Don't care about canonical order per se, but do want them to be
        // formable into RRsets.
        Collections.sort(records);

        SRRset cur_rrset = new SRRset();
        for (Iterator i = records.iterator(); i.hasNext();) {
            r = (Record) i.next();
            // Skip RR types that cannot be used as trust anchors.
            if (r.getType() != Type.DNSKEY && r.getType() != Type.DS) continue;

            // If our cur_rrset is empty, we can just add it.
            if (cur_rrset.size() == 0) {
                cur_rrset.addRR(r);
                continue;
            }
            // If this record matches our current RRset, we can just add it.
            if (cur_rrset.getName().equals(r.getName())
                && cur_rrset.getType() == r.getType()
                && cur_rrset.getDClass() == r.getDClass()) {
                cur_rrset.addRR(r);
                continue;
            }

            // Otherwise, we add the rrset to our set of trust anchors.
            mTrustedKeys.store(cur_rrset);
            cur_rrset = new SRRset();
            cur_rrset.addRR(r);
        }

        // add the last rrset (if it was not empty)
        if (cur_rrset.size() > 0) {
            mTrustedKeys.store(cur_rrset);
        }
    }

    // ----------------- Validation Support ----------------------

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

        // FIXME: add check to see if message qname is at or below any of our
        // configured trust anchors.
        
        int rcode = message.getRcode();
        
        if (rcode != Rcode.NOERROR && rcode != Rcode.NXDOMAIN) {
            // log.debug("cannot validate non-answer.");
            // log.trace("non-answer: " + response);
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

        Name wc           = null;
        boolean wcNSEC_ok = false;
        boolean dname     = false;
        List nsec3s       = null;

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
//                log.debug("Positive response has failed ANSWER rrset: "
//                          + rrsets[i]);
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
//                log.debug("Positive response has failed AUTHORITY rrset: "
//                          + rrsets[i]);
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
//                        log.debug("Postive wildcard response wasn't generated "
//                                  + "by the correct wildcard");
                        m.setStatus(SecurityStatus.BOGUS);
                        return;
                    }
                    wcNSEC_ok = true;
                }
            }

            // Otherwise, if this is a positive wildcard response and we have
            // NSEC3 records, collect them.
            if (wc != null && rrsets[i].getType() == Type.NSEC3) {
                if (nsec3s == null) nsec3s = new ArrayList();
                nsec3s.add(rrsets[i].first());
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
//            log.debug("positive response was wildcard expansion and "
//                      + "did not prove original data did not exist");
            m.setStatus(SecurityStatus.BOGUS);
            return;
        }

//        log.trace("Successfully validated postive response");
        m.setStatus(SecurityStatus.SECURE);
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
//                log.debug("Postive response has failed ANSWER rrset: "
//                          + rrsets[i]);
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
//                log.debug("Postive response has failed AUTHORITY rrset: "
//                          + rrsets[i]);
                m.setStatus(SecurityStatus.BOGUS);
                return;
            }
        }

//        log.trace("Successfully validated postive ANY response");
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
        Name ce = null; // for wildcard nodata responses. This is the proven
        // closest encloser.
        NSECRecord wc = null; // for wildcard nodata responses. This is the
        // wildcard NSEC.
        List nsec3s = null; // A collection of NSEC3 RRs found in the authority
        // section.
        Name nsec3Signer = null; // The RRSIG signer field for the NSEC3 RRs.

        for (int i = 0; i < rrsets.length; i++) {
            int status = mValUtils.verifySRRset(rrsets[i], key_rrset);
            if (status != SecurityStatus.SECURE) {
//                log.debug("NODATA response has failed AUTHORITY rrset: "
//                          + rrsets[i]);
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
                if (nsec3s == null) nsec3s = new ArrayList();
                nsec3s.add(rrsets[i].first());
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
//                log.error(e);
            }
        }

        NSEC3ValUtils.stripUnknownAlgNSEC3s(nsec3s);

        if (!hasValidNSEC && nsec3s != null && nsec3s.size() > 0) {
            // try to prove NODATA with our NSEC3 record(s)
            hasValidNSEC = NSEC3ValUtils.proveNodata(nsec3s, qname, qtype,
                                                     nsec3Signer);
        }

        if (!hasValidNSEC) {
//            log.debug("NODATA response failed to prove NODATA "
//                      + "status with NSEC/NSEC3");
//            log.trace("Failed NODATA:\n" + m);
            m.setStatus(SecurityStatus.BOGUS);
            return;
        }
//        log.trace("sucessfully validated NODATA response.");
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
        List nsec3s = null;
        Name nsec3Signer = null;

        for (int i = 0; i < rrsets.length; i++) {
            int status = mValUtils.verifySRRset(rrsets[i], key_rrset);
            if (status != SecurityStatus.SECURE) {
//                log.debug("NameError response has failed AUTHORITY rrset: "
//                          + rrsets[i]);
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
                if (nsec3s == null) nsec3s = new ArrayList();
                nsec3s.add(rrsets[i].first());
                nsec3Signer = rrsets[i].getSignerName();
            }
        }

        NSEC3ValUtils.stripUnknownAlgNSEC3s(nsec3s);

        if (nsec3s != null && nsec3s.size() > 0) {
//            log.debug("Validating nxdomain: using NSEC3 records");
            // Attempt to prove name error with nsec3 records.

            if (NSEC3ValUtils.allNSEC3sIgnoreable(nsec3s, key_rrset, mVerifier)) {
//                log.debug("all NSEC3s were validated but ignored.");
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
//            log.debug("NameError response has failed to prove: "
//                      + "qname does not exist");
            m.setStatus(SecurityStatus.BOGUS);
            return;
        }

        if (!hasValidWCNSEC) {
//            log.debug("NameError response has failed to prove: "
//                      + "covering wildcard does not exist");
            m.setStatus(SecurityStatus.BOGUS);
            return;
        }

        // Otherwise, we consider the message secure.
//        log.trace("successfully validated NAME ERROR response.");
        m.setStatus(SecurityStatus.SECURE);
    }

//    /**
//     * This state is used for validating CNAME-type responses -- i.e., responses
//     * that have CNAME chains.
//     * 
//     * It primarily is responsible for breaking down the response into a series
//     * of separately validated queries & responses.
//     * 
//     * @param event
//     * @param state
//     * @return
//     */
//    private boolean processCNAME(DNSEvent event, ValEventState state) {
//        Request req = event.getRequest();
//
//        Name qname = req.getQName();
//        int qtype = req.getQType();
//        int qclass = req.getQClass();
//
//        SMessage m = event.getResponse().getSMessage();
//
//        if (state.cnameSname == null) state.cnameSname = qname;
//
//        // We break the chain down by re-querying for the specific CNAME or
//        // DNAME
//        // (or final answer).
//        SRRset[] rrsets = m.getSectionRRsets(Section.ANSWER);
//
//        while (state.cnameIndex < rrsets.length) {
//            SRRset rrset = rrsets[state.cnameIndex++];
//            Name rname = rrset.getName();
//            int rtype = rrset.getType();
//
//            // Skip DNAMEs -- prefer to query for the generated CNAME,
//            if (rtype == Type.DNAME && qtype != Type.DNAME) continue;
//
//            // Set the SNAME if we are dealing with a CNAME
//            if (rtype == Type.CNAME) {
//                CNAMERecord cname = (CNAMERecord) rrset.first();
//                state.cnameSname = cname.getTarget();
//            }
//
//            // Note if the current rrset is the answer. In that case, we want to
//            // set
//            // the final state differently.
//            // For non-answers, the response ultimately comes back here.
//            int final_state = ValEventState.CNAME_RESP_STATE;
//            if (isAnswerRRset(rrset.getName(), rtype, state.cnameSname, qtype,
//                              Section.ANSWER)) {
//                // If this is an answer, however, break out of this loop.
//                final_state = ValEventState.CNAME_ANS_RESP_STATE;
//            }
//
//            // Generate the sub-query.
//            Request localRequest = generateLocalRequest(rname, rtype, qclass);
//            DNSEvent localEvent = generateLocalEvent(event, localRequest,
//                                                     ValEventState.INIT_STATE,
//                                                     final_state);
//
//            // ...and send it along.
//            processLocalRequest(localEvent);
//            return false;
//        }
//
//        // Something odd has happened if we get here.
//        log.warn("processCNAME: encountered unknown issue handling a CNAME chain.");
//        return false;
//    }
//
//    private boolean processCNAMEResponse(DNSEvent event, ValEventState state) {
//        DNSEvent forEvent = event.forEvent();
//        ValEventState forState = getModuleState(forEvent);
//
//        SMessage resp = event.getResponse().getSMessage();
//        if (resp.getStatus() != SecurityStatus.SECURE) {
//            forEvent.getResponse().getSMessage().setStatus(resp.getStatus());
//            forState.state = forState.finalState;
//            handleResponse(forEvent, forState);
//            return false;
//        }
//
//        forState.state = ValEventState.CNAME_STATE;
//        handleResponse(forEvent, forState);
//        return false;
//    }
//
//    private boolean processCNAMEAnswer(DNSEvent event, ValEventState state) {
//        DNSEvent forEvent = event.forEvent();
//        ValEventState forState = getModuleState(forEvent);
//
//        SMessage resp = event.getResponse().getSMessage();
//        SMessage forResp = forEvent.getResponse().getSMessage();
//
//        forResp.setStatus(resp.getStatus());
//
//        forState.state = forState.finalState;
//        handleResponse(forEvent, forState);
//        return false;
//    }


    public byte validateMessage(SMessage message) {

        SRRset key_rrset = findKeys(message);
        if (key_rrset == null) {
            return SecurityStatus.BOGUS;
        }
        
        int subtype = ValUtils.classifyResponse(message);

        switch (subtype) {
        case ValUtils.POSITIVE:
            // log.trace("Validating a positive response");
            validatePositiveResponse(message, key_rrset);
            break;
        case ValUtils.NODATA:
            // log.trace("Validating a nodata response");
            validateNodataResponse(message, key_rrset);
            break;
        case ValUtils.NAMEERROR:
            // log.trace("Validating a nxdomain response");
            validateNameErrorResponse(message, key_rrset);
            break;
        case ValUtils.CNAME:
            // log.trace("Validating a cname response");
            // forward on to the special CNAME state for this.
//            state.state = ValEventState.CNAME_STATE;
            break;
        case ValUtils.ANY:
            // log.trace("Validating a postive ANY response");
            validateAnyResponse(message, key_rrset);
            break;
        default:
            // log.error("unhandled response subtype: " + subtype);
        }
        
        return message.getSecurityStatus().getStatus();

    }
}
