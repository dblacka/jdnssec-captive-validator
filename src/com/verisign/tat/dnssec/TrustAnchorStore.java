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
 *
 */
public class TrustAnchorStore {
    private Map<String, SRRset> mMap;

    public TrustAnchorStore() {
        mMap = null;
    }

    private String key(Name n, int dclass) {
        return "T" + dclass + "/" + Util.nameToString(n);
    }

    public void store(SRRset rrset) {
        if (mMap == null) {
            mMap = new HashMap<String, SRRset>();
        }

        String k = key(rrset.getName(), rrset.getDClass());
        rrset.setSecurityStatus(SecurityStatus.SECURE);

        mMap.put(k, rrset);
    }

    private SRRset lookup(String key) {
        if (mMap == null) {
            return null;
        }

        return mMap.get(key);
    }

    public SRRset find(Name n, int dclass) {
        if (mMap == null) {
            return null;
        }

        while (n.labels() > 0) {
            String k = key(n, dclass);
            SRRset r = lookup(k);

            if (r != null) {
                return r;
            }

            n = new Name(n, 1);
        }

        return null;
    }

    public boolean isBelowTrustAnchor(Name n, int dclass) {
        return find(n, dclass) != null;
    }

    public List<String> listTrustAnchors() {
        List<String> res = new ArrayList<String>();

        for (Map.Entry<String, SRRset> entry : mMap.entrySet()) {
            for (Iterator<Record> i = entry.getValue().rrs(); i.hasNext();) {
                DNSKEYRecord r = (DNSKEYRecord) i.next();
                String key_desc = r.getName().toString() + "/"
                        + DNSSEC.Algorithm.string(r.getAlgorithm()) + "/"
                        + r.getFootprint();
                res.add(key_desc);
            }
        }

        return res;
    }
}
