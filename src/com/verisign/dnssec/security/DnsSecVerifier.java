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
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.xbill.DNS.DNSKEYRecord;
import org.xbill.DNS.RRSIGRecord;
import org.xbill.DNS.RRset;
import org.xbill.DNS.Record;

/**
 * A class for performing basic DNSSEC verification. The DNSJAVA package
 * contains a similar class. This is a re-implementation that allows us to have
 * finer control over the validation process.
 */
public class DnsSecVerifier {

    private DnsKeyConverter mKeyConverter;
    private DnsKeyAlgorithm mAlgorithmMap;

    // We have a few validation options
    private Instant mCurrentTime = null;
    private boolean mValidateAllSignatures = false;

    private Logger log = Logger.getLogger(this.getClass().getName());

    public DnsSecVerifier() {
        // get our helper objects
        mAlgorithmMap = DnsKeyAlgorithm.getInstance();
        mKeyConverter = new DnsKeyConverter();
    }

    /**
     * Find the matching DNSKEY(s) to an RRSIG within a DNSKEY rrset. Normally
     * this will only return one DNSKEY. It can return more than one, since
     * KeyID/Footprints are not guaranteed to be unique.
     *
     * @param dnskeyRRset
     *                        The DNSKEY rrset to search.
     * @param signature
     *                        The RRSIG to match against.
     * @return A List contains a one or more DNSKEYRecord objects, or null if a
     *         matching DNSKEY could not be found.
     */
    private List<DNSKEYRecord> findKey(RRset dnskeyRRset,
            RRSIGRecord signature) {
        if (!signature.getSigner().equals(dnskeyRRset.getName())) {
            log.finest("findKey: could not find appropriate key because "
                    + "incorrect keyset was supplied. Wanted: "
                    + signature.getSigner() + ", got: "
                    + dnskeyRRset.getName());

            return Collections.emptyList();
        }

        int keyid = signature.getFootprint();
        int alg = signature.getAlgorithm();

        List<DNSKEYRecord> res = new ArrayList<>(dnskeyRRset.size());

        for (Record rec : dnskeyRRset.rrs()) {
            DNSKEYRecord r = (DNSKEYRecord) rec;

            if ((r.getAlgorithm() == alg) && (r.getFootprint() == keyid)) {
                res.add(r);
            }
        }

        if (res.isEmpty()) {
            log.finest("findKey: could not find a key matching "
                    + "the algorithm and footprint in supplied keyset.");

            return Collections.emptyList();
        }

        return res;
    }

    /**
     * Check to see if a signature looks valid (i.e., matches the rrset in
     * question, in the validity period, etc.)
     *
     * @param rrset
     *                   The rrset that the signature belongs to.
     * @param sigrec
     *                   The signature record to check.
     * @return A value of SecurityStatus.SECURE if it looks OK,
     *         SecurityStatus.BOGUS if it looks bad.
     */
    private byte checkSignature(RRset rrset, RRSIGRecord sigrec) {
        if ((rrset == null) || (sigrec == null)) {
            return SecurityStatus.BOGUS;
        }

        if (!rrset.getName().equals(sigrec.getName())) {
            log.warning("Signature name does not match RRset name");

            return SecurityStatus.BOGUS;
        }

        if (rrset.getType() != sigrec.getTypeCovered()) {
            log.warning("Signature type does not match RRset type");

            return SecurityStatus.BOGUS;
        }

        Instant now;
        if (mCurrentTime != null) {
            now = mCurrentTime;
        } else {
            now = Instant.now();
        }
        Instant start = sigrec.getTimeSigned();
        Instant expire = sigrec.getExpire();

        if (now.isBefore(start)) {
            log.fine("Signature is not yet valid");

            return SecurityStatus.BOGUS;
        }

        if (now.isAfter(expire)) {
            log.fine("Signature has expired (now = " + now + ", sig expires = "
                    + expire);

            return SecurityStatus.BOGUS;
        }

        return SecurityStatus.SECURE;
    }

    /**
     * Actually cryptographically verify a signature over the rrset. The RRSIG
     * record must match the rrset being verified (see checkSignature).
     *
     * @param rrset
     *                   The rrset to verify.
     * @param sigrec
     *                   The signature to verify with.
     * @param key
     *                   The (public) key associated with the RRSIG record.
     * @return A security status code: SECURE if it worked, BOGUS if not,
     *         UNCHECKED if we just couldn't actually do the function.
     */
    public byte verifySignature(RRset rrset, RRSIGRecord sigrec,
            DNSKEYRecord key) {
        try {
            PublicKey pk = mKeyConverter.parseDNSKEYRecord(key);

            if (pk == null) {
                log.warning("Could not convert DNSKEY record to a JCA public key: "
                        + key);
                return SecurityStatus.UNCHECKED;
            }

            byte[] data = SignUtils.generateSigData(rrset, sigrec);

            Signature signer = mAlgorithmMap.getSignature(sigrec.getAlgorithm());

            if (signer == null) {
                return SecurityStatus.BOGUS;
            }

            signer.initVerify(pk);
            signer.update(data);

            byte[] sig = sigrec.getSignature();

            if (mAlgorithmMap.isDSA(sigrec.getAlgorithm())) {
                sig = SignUtils.convertDSASignature(sig);
            }
            if (mAlgorithmMap.isECDSA(sigrec.getAlgorithm())) {
                sig = SignUtils.convertECDSASignature(sig);
            }

            if (!signer.verify(sig)) {
                log.info("Signature failed to verify cryptographically");
                log.fine("Failed signature: " + sigrec);

                return SecurityStatus.BOGUS;
            }

            log.finest("Signature verified: " + sigrec);

            return SecurityStatus.SECURE;
        } catch (NoSuchAlgorithmException e) {
            log.log(Level.SEVERE, "DNSSEC key parsing error", e);
        } catch (IOException e) {
            log.log(Level.SEVERE, "I/O error", e);
        } catch (GeneralSecurityException e) {
            log.log(Level.SEVERE, "Security error", e);
        }

        // FIXME: Since I'm not sure what would cause an exception here (failure
        // to have the required crypto?)
        // We default to UNCHECKED instead of BOGUS. This could be wrong.
        return SecurityStatus.UNCHECKED;
    }

    /**
     * Verify an RRset against a particular signature.
     *
     * @return DNSSEC.Secure if the signature verfied, DNSSEC.Failed if it did
     *         not verify (for any reason), and DNSSEC.Insecure if verification
     *         could not be completed (usually because the public key was not
     *         available).
     */
    public byte verifySignature(RRset rrset, RRSIGRecord sigrec,
            RRset keyRRset) {
        byte result = checkSignature(rrset, sigrec);

        if (result != SecurityStatus.SECURE) {
            return result;
        }

        List<DNSKEYRecord> keys = findKey(keyRRset, sigrec);

        if (keys.isEmpty()) {
            log.finest("could not find appropriate key");
            return SecurityStatus.BOGUS;
        }

        byte status = SecurityStatus.UNCHECKED;

        for (DNSKEYRecord key : keys) {
            status = verifySignature(rrset, sigrec, key);

            if (status == SecurityStatus.SECURE) {
                break;
            }
        }

        return status;
    }

    /**
     * Verifies an RRset. This routine does not modify the RRset. This RRset is
     * presumed to be verifiable, and the correct DNSKEY rrset is presumed to
     * have been found.
     *
     * @return SecurityStatus.SECURE if the rrest verified positively,
     *         SecurityStatus.BOGUS otherwise.
     */
    public byte verify(RRset rrset, RRset keyRRset) {
        if (rrset.sigs().isEmpty()) {
            log.warning("RRset failed to verify due to lack of signatures");
            return SecurityStatus.BOGUS;            
        }
        byte status = SecurityStatus.UNCHECKED;

        for (RRSIGRecord sig : rrset.sigs()) {
            byte result = verifySignature(rrset, sig, keyRRset);
            switch (result) {
                case SecurityStatus.BOGUS:
                    log.warning("Signature was BOGUS: " + sig);
                    status = result;
                break;
                case SecurityStatus.SECURE:
                    log.fine("Signature was SECURE: " + sig);
                    if (status != SecurityStatus.BOGUS) {
                        status = result;
                    }
                break;
                default:
                    status = result;
                    break;
            }
            if (!mValidateAllSignatures && result == SecurityStatus.SECURE) {
                return result;
            }
        }

        return status;
    }

    /**
     * Verify an RRset against a single DNSKEY. Use this when you must be
     * certain that an RRset signed and verifies with a particular DNSKEY (as
     * opposed to a particular DNSKEY rrset).
     *
     * @param rrset
     *                   The rrset to verify.
     * @param dnskey
     *                   The DNSKEY to verify with.
     * @return SecurityStatus.SECURE if the rrset verified, BOGUS otherwise.
     */
    @SuppressWarnings("rawtypes")
    public byte verify(RRset rrset, DNSKEYRecord dnskey) {
        // Iterate over RRSIGS
        Iterator i = rrset.sigs().iterator();

        if (!i.hasNext()) {
            log.info("RRset failed to verify due to lack of signatures");

            return SecurityStatus.BOGUS;
        }

        while (i.hasNext()) {
            RRSIGRecord sigrec = (RRSIGRecord) i.next();

            // Skip RRSIGs that do not match our given key's footprint.
            if (sigrec.getFootprint() != dnskey.getFootprint()) {
                continue;
            }

            byte res = verifySignature(rrset, sigrec, dnskey);

            if (res == SecurityStatus.SECURE) {
                return res;
            }
        }

        log.info("RRset failed to verify: all signatures were BOGUS");

        return SecurityStatus.BOGUS;
    }

    public boolean supportsAlgorithm(int algorithm) {
        return mAlgorithmMap.supportedAlgorithm(algorithm);
    }

    public void setCurrentTime(Instant customTime) {
        mCurrentTime = customTime;
    }

    public void setValidateAllSignatures(boolean value) {
        mValidateAllSignatures = value;
    }
}
