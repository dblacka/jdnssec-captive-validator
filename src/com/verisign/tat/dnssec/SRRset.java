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

import org.xbill.DNS.*;

import java.util.*;

/**
 * A version of the RRset class overrides the standard security status.
 */
public class SRRset extends RRset {
    private static final long serialVersionUID = 1L;
    private SecurityStatus    mSecurityStatus;

    /** Create a new, blank SRRset. */
    public SRRset() {
        super();
        mSecurityStatus = new SecurityStatus();
    }

    /**
     * Create a new SRRset from an existing RRset. This SRRset will contain that
     * same internal Record objects as the original RRset.
     */
    @SuppressWarnings("rawtypes")
    public SRRset(RRset r) {
        this();

        for (Iterator i = r.rrs(); i.hasNext();) {
            addRR((Record) i.next());
        }

        for (Iterator i = r.sigs(); i.hasNext();) {
            addRR((Record) i.next());
        }
    }

    /**
     * Return the current security status (generally: UNCHECKED, BOGUS, or
     * SECURE).
     */
    public int getSecurity() {
        return getSecurityStatus();
    }

    /**
     * Return the current security status (generally: UNCHECKED, BOGUS, or
     * SECURE).
     */
    public byte getSecurityStatus() {
        return mSecurityStatus.getStatus();
    }

    /**
     * Set the current security status for this SRRset. This status will be
     * shared amongst all copies of this SRRset (created with cloneSRRset())
     */
    public void setSecurityStatus(byte status) {
        mSecurityStatus.setStatus(status);
    }

    @SuppressWarnings("unchecked")
    public Iterator<Record> rrs() {
        return (Iterator<Record>) super.rrs();
    }

    @SuppressWarnings("unchecked")
    public Iterator<RRSIGRecord> sigs() {
        return (Iterator<RRSIGRecord>) super.sigs();
    }

    public int totalSize() {
        int num_sigs = 0;

        for (Iterator<RRSIGRecord> i = sigs(); i.hasNext();) {
            num_sigs++;
            i.next();
        }

        return size() + num_sigs;
    }

    /**
     * @return The total number of records (data + sigs) in the SRRset.
     */
    public int getNumRecords() {
        return totalSize();
    }

    public RRSIGRecord firstSig() {
        for (Iterator<RRSIGRecord> i = sigs(); i.hasNext();) {
            return i.next();
        }

        return null;
    }

    /**
     * @return true if this RRset has RRSIG records that cover data records.
     *         (i.e., RRSIG SRRsets return false)
     */
    public boolean isSigned() {
        if (getType() == Type.RRSIG) {
            return false;
        }

        return firstSig() != null;
    }

    /**
     * @return The "signer" name for this SRRset, if signed, or null if not.
     */
    public Name getSignerName() {
        RRSIGRecord sig = (RRSIGRecord) firstSig();

        if (sig == null) {
            return null;
        }

        return sig.getSigner();
    }
}
