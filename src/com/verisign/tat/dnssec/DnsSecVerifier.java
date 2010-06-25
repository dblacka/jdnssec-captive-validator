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
import org.xbill.DNS.security.*;

import java.io.*;

import java.security.*;

import java.util.*;

/**
 * A class for performing basic DNSSEC verification. The DNSJAVA package
 * contains a similar class. This is a re-implementation that allows us to have
 * finer control over the validation process.
 */
public class DnsSecVerifier {
    public static final int UNKNOWN = 0;
    public static final int RSA = 1;
    public static final int DSA = 2;
    private Logger log = Logger.getLogger(this.getClass());

    /**
     * This is a mapping of DNSSEC algorithm numbers to JCA algorithm
     * identifiers.
     */
    private HashMap<Integer, AlgEntry> mAlgorithmMap;

    /**
     * This is a mapping of DNSSEC private (DNS name) identifiers to JCA
     * algorithm identifiers.
     */
    private HashMap<Name, AlgEntry> mPrivateAlgorithmMap;

    public DnsSecVerifier() {
        mAlgorithmMap = new HashMap<Integer, AlgEntry>();
        mPrivateAlgorithmMap = new HashMap<Name, AlgEntry>();

        // set the default algorithm map.
        mAlgorithmMap.put(Integer.valueOf(DNSSEC.RSAMD5), new AlgEntry(
                "MD5withRSA", DNSSEC.RSAMD5, false));
        mAlgorithmMap.put(Integer.valueOf(DNSSEC.DSA), new AlgEntry("SHA1withDSA",
                DNSSEC.DSA, true));
        mAlgorithmMap.put(Integer.valueOf(DNSSEC.RSASHA1), new AlgEntry(
                "SHA1withRSA", DNSSEC.RSASHA1, false));
        mAlgorithmMap.put(Integer.valueOf(DNSSEC.DSA_NSEC3_SHA1), new AlgEntry(
                "SHA1withDSA", DNSSEC.DSA, true));
        mAlgorithmMap.put(Integer.valueOf(DNSSEC.RSA_NSEC3_SHA1), new AlgEntry(
                "SHA1withRSA", DNSSEC.RSASHA1, false));
        mAlgorithmMap.put(Integer.valueOf(DNSSEC.RSASHA256), new AlgEntry(
                "SHA256withRSA", DNSSEC.RSASHA256, false));
        mAlgorithmMap.put(Integer.valueOf(DNSSEC.RSASHA512), new AlgEntry(
                "SHA512withRSA", DNSSEC.RSASHA512, false));
    }

    private boolean isDSA(int algorithm) {
        // shortcut the standard algorithms
        if (algorithm == DNSSEC.DSA) {
            return true;
        }

        if (algorithm == DNSSEC.RSASHA1) {
            return false;
        }

        if (algorithm == DNSSEC.RSAMD5) {
            return false;
        }

        AlgEntry entry = (AlgEntry) mAlgorithmMap.get(Integer.valueOf(algorithm));

        if (entry != null) {
            return entry.isDSA;
        }

        return false;
    }

    public void init(Properties config) {
        if (config == null) {
            return;
        }

        // Algorithm configuration

        // For now, we just accept new identifiers for existing algorithms.
        // FIXME: handle private identifiers.
        List<Util.ConfigEntry> aliases = Util.parseConfigPrefix(config,
                "dns.algorithm.");

        for (Util.ConfigEntry entry : aliases) {
            Integer alg_alias = Integer.valueOf(Util.parseInt(entry.key, -1));
            Integer alg_orig = Integer.valueOf(Util.parseInt(entry.value, -1));

            if (!mAlgorithmMap.containsKey(alg_orig)) {
                log.warn("Unable to alias " + alg_alias
                        + " to unknown algorithm " + alg_orig);

                continue;
            }

            if (mAlgorithmMap.containsKey(alg_alias)) {
                log.warn("Algorithm alias " + alg_alias
                        + " is already defined and cannot be redefined");

                continue;
            }

            mAlgorithmMap.put(alg_alias, mAlgorithmMap.get(alg_orig));
        }

        // for debugging purposes, log the entire algorithm map table.
        for (Integer alg : mAlgorithmMap.keySet()) {
            AlgEntry entry = mAlgorithmMap.get(alg);

            if (entry == null) {
                log.warn("DNSSEC alg " + alg + " has a null entry!");
            } else {
                log.debug("DNSSEC alg " + alg + " maps to " + entry.jcaName
                        + " (" + entry.dnssecAlg + ")");
            }
        }
    }

    /**
     * Find the matching DNSKEY(s) to an RRSIG within a DNSKEY rrset. Normally
     * this will only return one DNSKEY. It can return more than one, since
     * KeyID/Footprints are not guaranteed to be unique.
     * 
     * @param dnskey_rrset
     *            The DNSKEY rrset to search.
     * @param signature
     *            The RRSIG to match against.
     * @return A List contains a one or more DNSKEYRecord objects, or null if a
     *         matching DNSKEY could not be found.
     */
    @SuppressWarnings("rawtypes")
    private List<DNSKEYRecord> findKey(RRset dnskey_rrset, RRSIGRecord signature) {
        if (!signature.getSigner().equals(dnskey_rrset.getName())) {
            log.trace("findKey: could not find appropriate key because "
                    + "incorrect keyset was supplied. Wanted: "
                    + signature.getSigner() + ", got: "
                    + dnskey_rrset.getName());

            return null;
        }

        int keyid = signature.getFootprint();
        int alg = signature.getAlgorithm();

        List<DNSKEYRecord> res = new ArrayList<DNSKEYRecord>(dnskey_rrset
                .size());

        for (Iterator i = dnskey_rrset.rrs(); i.hasNext();) {
            DNSKEYRecord r = (DNSKEYRecord) i.next();

            if ((r.getAlgorithm() == alg) && (r.getFootprint() == keyid)) {
                res.add(r);
            }
        }

        if (res.size() == 0) {
            log.trace("findKey: could not find a key matching "
                    + "the algorithm and footprint in supplied keyset. ");

            return null;
        }

        return res;
    }

    /**
     * Check to see if a signature looks valid (i.e., matches the rrset in
     * question, in the validity period, etc.)
     * 
     * @param rrset
     *            The rrset that the signature belongs to.
     * @param sigrec
     *            The signature record to check.
     * @return A value of DNSSEC.Secure if it looks OK, DNSSEC.Faile if it looks
     *         bad.
     */
    private byte checkSignature(RRset rrset, RRSIGRecord sigrec) {
        if ((rrset == null) || (sigrec == null)) {
            return DNSSEC.Failed;
        }

        if (!rrset.getName().equals(sigrec.getName())) {
            log.debug("Signature name does not match RRset name");

            return SecurityStatus.BOGUS;
        }

        if (rrset.getType() != sigrec.getTypeCovered()) {
            log.debug("Signature type does not match RRset type");

            return SecurityStatus.BOGUS;
        }

        Date now = new Date();
        Date start = sigrec.getTimeSigned();
        Date expire = sigrec.getExpire();

        if (now.before(start)) {
            log.debug("Signature is not yet valid");

            return SecurityStatus.BOGUS;
        }

        if (now.after(expire)) {
            log.debug("Signature has expired (now = " + now
                    + ", sig expires = " + expire);

            return SecurityStatus.BOGUS;
        }

        return SecurityStatus.SECURE;
    }

    public PublicKey parseDNSKEY(DNSKEYRecord key) {
        AlgEntry ae = (AlgEntry) mAlgorithmMap.get(Integer.valueOf(key
                .getAlgorithm()));

        if (key.getAlgorithm() != ae.dnssecAlg) {
            // Recast the DNSKEYRecord in question as one using the offical
            // algorithm, to work around the lack of alias support in the
            // underlying
            // KEYConverter class from DNSjava
            key = new DNSKEYRecord(key.getName(), key.getDClass(),
                    key.getTTL(), key.getFlags(), key.getProtocol(),
                    ae.dnssecAlg, key.getKey());
        }

        return KEYConverter.parseRecord(key);
    }

    /**
     * Actually cryptographically verify a signature over the rrset. The RRSIG
     * record must match the rrset being verified (see checkSignature).
     * 
     * @param rrset
     *            The rrset to verify.
     * @param sigrec
     *            The signature to verify with.
     * @param key
     *            The (public) key associated with the RRSIG record.
     * @return A security status code: SECURE if it worked, BOGUS if not,
     *         UNCHECKED if we just couldn't actually do the function.
     */
    public byte verifySignature(RRset rrset, RRSIGRecord sigrec,
            DNSKEYRecord key) {
        try {
            PublicKey pk = parseDNSKEY(key);

            if (pk == null) {
                log
                        .warn("Could not convert DNSKEY record to a JCA public key: "
                                + key);

                return SecurityStatus.UNCHECKED;
            }

            byte[] data = SignUtils.generateSigData(rrset, sigrec);

            Signature signer = getSignature(sigrec.getAlgorithm());

            if (signer == null) {
                return SecurityStatus.BOGUS;
            }

            signer.initVerify(pk);
            signer.update(data);

            byte[] sig = sigrec.getSignature();

            if (isDSA(sigrec.getAlgorithm())) {
                sig = SignUtils.convertDSASignature(sig);
            }

            if (!signer.verify(sig)) {
                log.info("Signature failed to verify cryptographically");
                log.debug("Failed signature: " + sigrec);

                return SecurityStatus.BOGUS;
            }

            log.trace("Signature verified: " + sigrec);

            return SecurityStatus.SECURE;
        } catch (IOException e) {
            log.error("I/O error", e);
        } catch (GeneralSecurityException e) {
            log.error("Security error", e);
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
    public byte verifySignature(RRset rrset, RRSIGRecord sigrec, RRset key_rrset) {
        byte result = checkSignature(rrset, sigrec);

        if (result != SecurityStatus.SECURE) {
            return result;
        }

        List<DNSKEYRecord> keys = findKey(key_rrset, sigrec);

        if (keys == null) {
            log.trace("could not find appropriate key");

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
    @SuppressWarnings("rawtypes")
    public byte verify(RRset rrset, RRset key_rrset) {
        Iterator i = rrset.sigs();

        if (!i.hasNext()) {
            log.info("RRset failed to verify due to lack of signatures");

            return SecurityStatus.BOGUS;
        }

        while (i.hasNext()) {
            RRSIGRecord sigrec = (RRSIGRecord) i.next();

            byte res = verifySignature(rrset, sigrec, key_rrset);

            if (res == SecurityStatus.SECURE) {
                return res;
            }
        }

        log.info("RRset failed to verify: all signatures were BOGUS");

        return SecurityStatus.BOGUS;
    }

    /**
     * Verify an RRset against a single DNSKEY. Use this when you must be
     * certain that an RRset signed and verifies with a particular DNSKEY (as
     * opposed to a particular DNSKEY rrset).
     * 
     * @param rrset
     *            The rrset to verify.
     * @param dnskey
     *            The DNSKEY to verify with.
     * @return SecurityStatus.SECURE if the rrset verified, BOGUS otherwise.
     */
    @SuppressWarnings("rawtypes")
    public byte verify(RRset rrset, DNSKEYRecord dnskey) {
        // Iterate over RRSIGS
        Iterator i = rrset.sigs();

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
        return mAlgorithmMap.containsKey(Integer.valueOf(algorithm));
    }

    public boolean supportsAlgorithm(Name private_id) {
        return mPrivateAlgorithmMap.containsKey(private_id);
    }

    public int baseAlgorithm(int algorithm) {
        switch (algorithm) {
        case DNSSEC.RSAMD5:
        case DNSSEC.RSASHA1:
            return RSA;

        case DNSSEC.DSA:
            return DSA;
        }

        AlgEntry entry = (AlgEntry) mAlgorithmMap.get(Integer.valueOf(algorithm));

        if (entry == null) {
            return UNKNOWN;
        }

        if (entry.isDSA) {
            return DSA;
        }

        return RSA;
    }

    /** @return the appropriate Signature object for this keypair. */
    private Signature getSignature(int algorithm) {
        Signature s = null;

        try {
            AlgEntry entry = (AlgEntry) mAlgorithmMap
                    .get(Integer.valueOf(algorithm));

            if (entry == null) {
                log.info("DNSSEC algorithm " + algorithm + " not recognized.");

                return null;
            }

            // TODO: should we cache the instance?
            s = Signature.getInstance(entry.jcaName);
        } catch (NoSuchAlgorithmException e) {
            log.error("error getting Signature object", e);
        }

        return s;
    }

    private static class AlgEntry {
        public String jcaName;
        public boolean isDSA;
        public int dnssecAlg;

        public AlgEntry(String name, int dnssecAlg, boolean isDSA) {
            jcaName = name;
            this.dnssecAlg = dnssecAlg;
            this.isDSA = isDSA;
        }
    }

    // TODO: enable private algorithm support in dnsjava.
    // Right now, this cannot be used because the DNSKEYRecord object doesn't
    // give us
    // the private key name.
    // private Signature getSignature(Name private_alg)
    // {
    // Signature s = null;
    //
    // try
    // {
    // String alg_id = (String) mAlgorithmMap.get(private_alg);
    // if (alg_id == null)
    // {
    // log.debug("DNSSEC private algorithm '" + private_alg
    // + "' not recognized.");
    // return null;
    // }
    //
    // s = Signature.getInstance(alg_id);
    // }
    // catch (NoSuchAlgorithmException e)
    // {
    // log.error("error getting Signature object", e);
    // }
    //
    // return s;
    // }
}
