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

import java.util.logging.Logger;

import org.xbill.DNS.DNSKEYRecord;
import org.xbill.DNS.DNSOutput;
import org.xbill.DNS.DNSSEC;
import org.xbill.DNS.Name;
import org.xbill.DNS.RRSIGRecord;
import org.xbill.DNS.RRset;
import org.xbill.DNS.Record;
import org.xbill.DNS.utils.base64;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.Serializable;

import java.security.SignatureException;
import java.security.interfaces.DSAParams;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.Iterator;

/**
 * This class contains a bunch of utility methods that are generally useful in
 * signing and verifying rrsets.
 */
public class SignUtils {

    private SignUtils() {
        throw new IllegalStateException("SignUtils class");
    }

    private static final int ASN1_INT = 0x02;
    private static final int ASN1_SEQ = 0x30;
    public static final int RR_NORMAL = 0;
    public static final int RR_DELEGATION = 1;
    public static final int RR_GLUE = 2;
    public static final int RR_INVALID = 3;

    private static Logger log = Logger.getLogger(SignUtils.class.getName());

    /**
     * Generate from some basic information a prototype SIG RR containing
     * everything but the actual signature itself.
     *
     * @param rrset
     *                   the RRset being signed.
     * @param signer
     *                   the name of the signing key
     * @param alg
     *                   the algorithm of the signing key
     * @param keyid
     *                   the keyid (or footprint) of the signing key
     * @param start
     *                   the SIG inception time.
     * @param expire
     *                   the SIG expiration time.
     * @param sigTTL
     *                   the TTL of the resulting SIG record.
     * @return a prototype signature based on the RRset and key information.
     */
    public static RRSIGRecord generatePreRRSIG(RRset rrset, Name signer,
            int alg, int keyid, Instant start, Instant expire, long sigTTL) {
        return new RRSIGRecord(rrset.getName(), rrset.getDClass(), sigTTL, rrset.getType(), alg, rrset.getTTL(), expire, start, keyid, signer, null);
    }

    /**
     * Generate from some basic information a prototype SIG RR containing
     * everything but the actual signature itself.
     *
     * @param rrset
     *                   the RRset being signed.
     * @param key
     *                   the public KEY RR counterpart to the key being used to
     *                   sign the RRset
     * @param start
     *                   the SIG inception time.
     * @param expire
     *                   the SIG expiration time.
     * @param sigTTL
     *                   the TTL of the resulting SIG record.
     * @return a prototype signature based on the RRset and key information.
     */
    public static RRSIGRecord generatePreRRSIG(RRset rrset, DNSKEYRecord key,
            Instant start, Instant expire, long sigTTL) {
        return generatePreRRSIG(rrset, key.getName(), key.getAlgorithm(), key.getFootprint(), start, expire, sigTTL);
    }

    /**
     * Generate from some basic information a prototype SIG RR containing
     * everything but the actual signature itself.
     *
     * @param rec
     *                   the DNS record being signed (forming an entire RRset).
     * @param key
     *                   the public KEY RR counterpart to the key signing the
     *                   record.
     * @param start
     *                   the SIG inception time.
     * @param expire
     *                   the SIG expiration time.
     * @param sigTTL
     *                   the TTL of the result SIG record.
     * @return a prototype signature based on the Record and key information.
     */
    public static RRSIGRecord generatePreRRSIG(Record rec, DNSKEYRecord key,
            Instant start, Instant expire, long sigTTL) {
        return new RRSIGRecord(rec.getName(), rec.getDClass(), sigTTL, rec.getType(), key.getAlgorithm(), rec.getTTL(), expire, start, key.getFootprint(), key.getName(), null);
    }

    /**
     * Generate the binary image of the prototype SIG RR.
     *
     * @param presig
     *                   the SIG RR prototype.
     * @return the RDATA portion of the prototype SIG record. This forms the
     *         first part of the data to be signed.
     */
    private static byte[] generatePreSigRdata(RRSIGRecord presig) {

        // Generate the binary image
        DNSOutput image = new DNSOutput();

        // precalculate some things
        long startTime = presig.getTimeSigned().getEpochSecond();
        long expireTime = presig.getExpire().getEpochSecond();
        Name signer = presig.getSigner();

        // first write out the partial SIG record (this is the SIG RDATA
        // minus the actual signature.
        image.writeU16(presig.getTypeCovered());
        image.writeU8(presig.getAlgorithm());
        image.writeU8(presig.getLabels());
        image.writeU32((int) presig.getOrigTTL());
        image.writeU32(expireTime);
        image.writeU32(startTime);
        image.writeU16(presig.getFootprint());
        image.writeByteArray(signer.toWireCanonical());

        return image.toByteArray();
    }

    /**
     * Calculate the canonical wire line format of the RRset.
     *
     * @param rrset
     *                   the RRset to convert.
     * @param ttl
     *                   the TTL to use when canonicalizing -- this is generally
     *                   the TTL of the signature if there is a pre-existing
     *                   signature. If not it is just the ttl of the rrset
     *                   itself.
     * @param labels
     *                   the labels field of the signature, or 0.
     * @return the canonical wire line format of the rrset. This is the second
     *         part of data to be signed.
     */
    public static byte[] generateCanonicalRRsetData(RRset rrset, long ttl,
            int labels) {
        DNSOutput image = new DNSOutput();

        if (ttl == 0) {
            ttl = rrset.getTTL();
        }

        Name n = rrset.getName();

        if (labels == 0) {
            labels = n.labels();
        } else {
            // correct for Name()'s conception of label count.
            labels++;
        }

        boolean wildcardName = false;

        if (n.labels() != labels) {
            n = n.wild(n.labels() - labels);
            wildcardName = true;
            log.finest("Detected wildcard expansion: " + rrset.getName()
                    + " changed to " + n);
        }

        // now convert the wire format records in the RRset into a
        // list of byte arrays.
        ArrayList<byte[]> canonicalRRs = new ArrayList<>();

        for (Record r : rrset.rrs()) {
            if ((r.getTTL() != ttl) || wildcardName) {
                // If necessary, we need to create a new record with a new ttl
                // or ownername.
                // In the TTL case, this avoids changing the ttl in the
                // response.
                r = Record.newRecord(n, r.getType(), r.getDClass(), ttl, r.rdataToWireCanonical());
            }

            byte[] wirefmt = r.toWireCanonical();
            canonicalRRs.add(wirefmt);
        }

        // put the records into the correct ordering.
        // Calculate the offset where the RDATA begins (we have to skip
        // past the length byte)
        int offset = rrset.getName().toWireCanonical().length + 10;
        ByteArrayComparator bac = new ByteArrayComparator(offset, false);

        Collections.sort(canonicalRRs, bac);

        for (Iterator<byte[]> i = canonicalRRs.iterator(); i.hasNext();) {
            byte[] wirefmtRec = i.next();
            image.writeByteArray(wirefmtRec);
        }

        return image.toByteArray();
    }

    /**
     * Given an RRset and the prototype signature, generate the canonical data
     * that is to be signed.
     *
     * @param rrset
     *                   the RRset to be signed.
     * @param presig
     *                   a prototype SIG RR created using the same RRset.
     * @return a block of data ready to be signed.
     */
    public static byte[] generateSigData(RRset rrset, RRSIGRecord presig)
            throws IOException {
        byte[] rrsetData = generateCanonicalRRsetData(rrset, presig.getOrigTTL(), presig.getLabels());

        return generateSigData(rrsetData, presig);
    }

    /**
     * Given an RRset and the prototype signature, generate the canonical data
     * that is to be signed.
     *
     * @param rrsetData
     *                      the RRset converted into canonical wire line format
     *                      (as per the canonicalization rules in RFC 2535).
     * @param presig
     *                      the prototype signature based on the same RRset
     *                      represented in <code>rrset_data</code>.
     * @return a block of data ready to be signed.
     */
    public static byte[] generateSigData(byte[] rrsetData, RRSIGRecord presig)
            throws IOException {
        byte[] sigRdata = generatePreSigRdata(presig);

        ByteArrayOutputStream image = new ByteArrayOutputStream(sigRdata.length
                + rrsetData.length);

        image.write(sigRdata);
        image.write(rrsetData);

        return image.toByteArray();
    }

    /**
     * Given the actual signature and the prototype signature, combine them and
     * return the fully formed RRSIGRecord.
     *
     * @param signature
     *                      the cryptographic signature, in DNSSEC format.
     * @param presig
     *                      the prototype RRSIG RR to add the signature to.
     * @return the fully formed RRSIG RR.
     */
    public static RRSIGRecord generateRRSIG(byte[] signature,
            RRSIGRecord presig) {
        return new RRSIGRecord(presig.getName(), presig.getDClass(), presig.getTTL(), presig.getTypeCovered(), presig.getAlgorithm(), presig.getOrigTTL(), presig.getExpire(), presig.getTimeSigned(), presig.getFootprint(), presig.getSigner(), signature);
    }

    /**
     * Converts from a RFC 2536 formatted DSA signature to a JCE (ASN.1)
     * formatted signature.
     *
     * <p>
     * ASN.1 format = ASN1_SEQ . seq_length . ASN1_INT . Rlength . R . ANS1_INT
     * . Slength . S
     * </p>
     *
     * The integers R and S may have a leading null byte to force the integer
     * positive.
     *
     * @param signature
     *                      the RFC 2536 formatted DSA signature.
     * @return The ASN.1 formatted DSA signature.
     * @throws SignatureException
     *                                if there was something wrong with the RFC
     *                                2536 formatted signature.
     */
    public static byte[] convertDSASignature(byte[] signature)
            throws SignatureException {
        if (signature.length != 41) {
            throw new SignatureException("RFC 2536 signature not expected length.");
        }

        byte rPad = 0;
        byte sPad = 0;

        // handle initial null byte padding.
        if (signature[1] < 0) {
            rPad++;
        }

        if (signature[21] < 0) {
            sPad++;
        }

        // ASN.1 length = R length + S length + (2 + 2 + 2), where each 2
        // is for a ASN.1 type-length byte pair of which there are three
        // (SEQ, INT, INT).
        byte sigLength = (byte) (40 + rPad + sPad + 6);

        byte[] sig = new byte[sigLength];
        byte pos = 0;

        sig[pos++] = ASN1_SEQ;
        sig[pos++] = (byte) (sigLength - 2); // all but the SEQ type+length.
        sig[pos++] = ASN1_INT;
        sig[pos++] = (byte) (20 + rPad);

        // copy the value of R, leaving a null byte if necessary
        if (rPad == 1) {
            sig[pos++] = 0;
        }

        System.arraycopy(signature, 1, sig, pos, 20);
        pos += 20;

        sig[pos++] = ASN1_INT;
        sig[pos++] = (byte) (20 + sPad);

        // copy the value of S, leaving a null byte if necessary
        if (sPad == 1) {
            sig[pos++] = 0;
        }

        System.arraycopy(signature, 21, sig, pos, 20);

        return sig;
    }

    /**
     * Converts from a JCE (ASN.1) formatted DSA signature to a RFC 2536
     * compliant signature.
     *
     * <p>
     * rfc2536 format = T . R . S
     * </p>
     *
     * where T is a number between 0 and 8, which is based on the DSA key
     * length, and R & S are formatted to be exactly 20 bytes each (no leading
     * null bytes).
     *
     * @param params
     *                      the DSA parameters associated with the DSA key used
     *                      to generate the signature.
     * @param signature
     *                      the ASN.1 formatted DSA signature.
     * @return a RFC 2536 formatted DSA signature.
     * @throws SignatureException
     *                                if something is wrong with the ASN.1
     *                                format.
     */
    public static byte[] convertDSASignature(DSAParams params, byte[] signature)
            throws SignatureException {
        if ((signature[0] != ASN1_SEQ) || (signature[2] != ASN1_INT)) {
            throw new SignatureException("Invalid ASN.1 signature format: expected SEQ, INT");
        }

        byte rPad = (byte) (signature[3] - 20);

        if (signature[24 + rPad] != ASN1_INT) {
            throw new SignatureException("Invalid ASN.1 signature format: expected SEQ, INT, INT");
        }

        log.finest("(start) ASN.1 DSA Sig:\n" + base64.toString(signature));

        byte sPad = (byte) (signature[25 + rPad] - 20);

        byte[] sig = new byte[41]; // all rfc2536 signatures are 41 bytes.

        // Calculate T:
        sig[0] = (byte) ((params.getP().bitLength() - 512) / 64);

        // copy R value
        if (rPad >= 0) {
            System.arraycopy(signature, 4 + rPad, sig, 1, 20);
        } else {
            // R is shorter than 20 bytes, so right justify the number
            // (r_pad is negative here, remember?).
            Arrays.fill(sig, 1, 1 - rPad, (byte) 0);
            System.arraycopy(signature, 4, sig, 1 - rPad, 20 + rPad);
        }

        // copy S value
        if (sPad >= 0) {
            System.arraycopy(signature, 26 + rPad + sPad, sig, 21, 20);
        } else {
            // S is shorter than 20 bytes, so right justify the number
            // (s_pad is negative here).
            Arrays.fill(sig, 21, 21 - sPad, (byte) 0);
            System.arraycopy(signature, 26 + rPad, sig, 21 - sPad, 20 + sPad);
        }

        if ((rPad < 0) || (sPad < 0)) {
            log.finest("(finish ***) RFC 2536 DSA Sig:\n"
                    + base64.toString(sig));
        } else {
            log.finest("(finish) RFC 2536 DSA Sig:\n" + base64.toString(sig));
        }

        return sig;
    }

    // Given one of the ECDSA algorithms determine the "length", which is the
    // length, in bytes, of both 'r' and 's' in the ECDSA signature.
    private static int ecdsaLength(int algorithm) throws SignatureException {
        switch (algorithm) {
        case DNSSEC.Algorithm.ECDSAP256SHA256:
            return 32;
        case DNSSEC.Algorithm.ECDSAP384SHA384:
            return 48;
        default:
            throw new SignatureException("Algorithm " + algorithm
                    + " is not a supported ECDSA signature algorithm.");
        }
    }

    /**
     * Convert a JCE standard ECDSA signature (which is a ASN.1 encoding) into a
     * standard DNS signature.
     * 
     * The format of the ASN.1 signature is
     * 
     * ASN1_SEQ . seq_length . ASN1_INT . r_length . R . ANS1_INT . s_length . S
     * 
     * where R and S may have a leading zero byte if without it the values would
     * be negative.
     *
     * The format of the DNSSEC signature is just R . S where R and S are both
     * exactly "length" bytes.
     * 
     * @param signature
     *                      The output of a ECDSA signature object.
     * @return signature data formatted for use in DNSSEC.
     * @throws SignatureException
     *                                if the ASN.1 encoding appears to be
     *                                corrupt.
     */
    public static byte[] convertECDSASignature(int algorithm, byte[] signature)
            throws SignatureException {
        int expLength = ecdsaLength(algorithm);
        byte[] sig = new byte[expLength * 2];

        if (signature[0] != ASN1_SEQ || signature[2] != ASN1_INT) {
            throw new SignatureException("Invalid ASN.1 signature format: expected SEQ, INT");
        }
        int rLen = signature[3];
        int rPos = 4;

        if (signature[rPos + rLen] != ASN1_INT) {
            throw new SignatureException("Invalid ASN.1 signature format: expected SEQ, INT, INT");
        }
        int sPos = rPos + rLen + 2;
        int sLen = signature[rPos + rLen + 1];

        // Adjust for leading zeros on both R and S
        if (signature[rPos] == 0) {
            rPos++;
            rLen--;
        }
        if (signature[sPos] == 0) {
            sPos++;
            sLen--;
        }

        System.arraycopy(signature, rPos, sig, 0
                + (expLength - rLen), rLen);
        System.arraycopy(signature, sPos, sig, expLength
                + (expLength - sLen), sLen);

        return sig;
    }

    /**
     * Convert a DNS standard ECDSA signature (defined in RFC 6605) into a JCE
     * standard ECDSA signature, which is encoded in ASN.1.
     * 
     * The format of the ASN.1 signature is
     * 
     * ASN1_SEQ . seq_length . ASN1_INT . r_length . R . ANS1_INT . s_length . S
     * 
     * where R and S may have a leading zero byte if without it the values would
     * be negative.
     *
     * The format of the DNSSEC signature is just R . S where R and S are both
     * exactly "length" bytes.
     * 
     * @param signature
     *                      The binary signature data from an RRSIG record.
     * @return signature data that may be used in a JCE Signature object for
     *         verification purposes.
     */
    public static byte[] convertECDSASignature(byte[] signature) {
        byte rSrcPos;
        byte rSrcLen;
        byte rPad;
        byte sSrcPos;
        byte sSrcLen;
        byte sPad;
        byte len;

        rSrcLen = sSrcLen = (byte) (signature.length / 2);
        rSrcPos = 0;
        rPad = 0;
        sSrcPos = (byte) (rSrcPos + rSrcLen);
        sPad = 0;
        len = (byte) (6 + rSrcLen + sSrcLen);

        // leading zeroes are forbidden
        while (signature[rSrcPos] == 0 && rSrcLen > 0) {
            rSrcPos++;
            rSrcLen--;
            len--;
        }
        while (signature[sSrcPos] == 0 && sSrcLen > 0) {
            sSrcPos++;
            sSrcLen--;
            len--;
        }

        // except when they are mandatory
        if (rSrcLen > 0 && signature[rSrcPos] < 0) {
            rPad = 1;
            len++;
        }
        if (sSrcLen > 0 && signature[sSrcPos] < 0) {
            sPad = 1;
            len++;
        }
        byte[] sig = new byte[len];
        byte pos = 0;

        sig[pos++] = ASN1_SEQ;
        sig[pos++] = (byte) (len - 2);
        sig[pos++] = ASN1_INT;
        sig[pos++] = (byte) (rSrcLen + rPad);
        pos += rPad;
        System.arraycopy(signature, rSrcPos, sig, pos, rSrcLen);
        pos += rSrcLen;

        sig[pos++] = ASN1_INT;
        sig[pos++] = (byte) (sSrcLen + sPad);
        pos += sPad;
        System.arraycopy(signature, sSrcPos, sig, pos, sSrcLen);

        return sig;
    }

    /**
     * This class implements a basic comparator for byte arrays. It is primarily
     * useful for comparing RDATA portions of DNS records in doing DNSSEC
     * canonical ordering.
     */
    public static class ByteArrayComparator
            implements Comparator<byte[]>, Serializable {
        private static final long serialVersionUID = 1L;
        private int mOffset = 0;
        private boolean mDebug = false;

        public ByteArrayComparator() {
        }

        public ByteArrayComparator(int offset, boolean debug) {
            mOffset = offset;
            mDebug = debug;
        }

        public int compare(byte[] b1, byte[] b2) throws ClassCastException {
            for (int i = mOffset; (i < b1.length) && (i < b2.length); i++) {
                if (b1[i] != b2[i]) {
                    if (mDebug) {
                        System.out.println("offset " + i + " differs (this is "
                                + (i - mOffset)
                                + " bytes in from our offset.)");
                    }

                    return (b1[i] & 0xFF) - (b2[i] & 0xFF);
                }
            }

            return b1.length - b2.length;
        }
    }
}
