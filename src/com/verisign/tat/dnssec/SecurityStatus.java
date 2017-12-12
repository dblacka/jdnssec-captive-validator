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

import java.io.Serializable;

/**
 * Codes for DNSSEC security statuses.
 *
 * @author davidb
 */
public class SecurityStatus implements Serializable {
    private static final long serialVersionUID = 1L;
    public static final byte  INVALID          = -1;

    /**
     * UNCHECKED means that object has yet to be validated.
     */
    public static final byte UNCHECKED = 0;

    /**
     * BOGUS means that the object (RRset or message) failed to validate
     * (according to local policy), but should have validated.
     */
    public static final byte BOGUS = 1;

    /**
     * BAD is a synonym for BOGUS.
     */
    public static final byte BAD = BOGUS;

    /**
     * INDTERMINATE means that the object is insecure, but not authoritatively
     * so. Generally this means that the RRset is not below a configured trust
     * anchor.
     */
    public static final byte INDETERMINATE = 2;

    /**
     * INSECURE means that the object is authoritatively known to be insecure.
     * Generally this means that this RRset is below a trust anchor, but also
     * below a verified, insecure delegation.
     */
    public static final byte INSECURE = 3;

    /**
     * SECURE means that the object (RRset or message) validated according to
     * local policy.
     */
    public static final byte SECURE = 4;
    private byte status;

    public SecurityStatus() {
        status = UNCHECKED;
    }

    public SecurityStatus(byte status) {
        setStatus(status);
    }

    public static String string(int status) {
        switch (status) {
        case INVALID:
            return "Invalid";

        case BOGUS:
            return "Bogus";

        case SECURE:
            return "Secure";

        case INSECURE:
            return "Insecure";

        case INDETERMINATE:
            return "Indeterminate";

        case UNCHECKED:
            return "Unchecked";

        default:
            return "UNKNOWN";
        }
    }

    public byte getStatus() {
        return status;
    }

    public void setStatus(byte status) {
        this.status = status;
    }
}
