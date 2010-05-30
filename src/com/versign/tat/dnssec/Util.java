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

import org.xbill.DNS.Name;

import java.util.*;


/**
 * Some basic utility functions.
 */
public class Util {
    /**
     * Convert a DNS name into a string suitable for use as a cache key.
     *
     * @param name The name to convert.
     * @return A string representing the name. This isn't ever meant to be
     *         converted back into a DNS name.
     */
    public static String nameToString(Name name) {
        if (name.equals(Name.root)) {
            return ".";
        }

        String n = name.toString().toLowerCase();

        if (n.endsWith(".")) {
            n = n.substring(0, n.length() - 1);
        }

        return n;
    }

    public static int parseInt(String s, int def) {
        if (s == null) {
            return def;
        }

        try {
            return Integer.parseInt(s);
        } catch (NumberFormatException e) {
            return def;
        }
    }

    public static long parseLong(String s, long def) {
        if (s == null) {
            return def;
        }

        try {
            return Long.parseLong(s);
        } catch (NumberFormatException e) {
            return def;
        }
    }

    public static List<ConfigEntry> parseConfigPrefix(Properties config,
        String prefix) {
        if (!prefix.endsWith(".")) {
            prefix = prefix + ".";
        }

        List<ConfigEntry> res = new ArrayList<ConfigEntry>();

        for (Map.Entry<Object, Object> entry : config.entrySet()) {
            String key = (String) entry.getKey();

            if (key.startsWith(prefix)) {
                key = key.substring(prefix.length());
                res.add(new ConfigEntry(key, (String) entry.getValue()));
            }
        }

        return res;
    }

    public static class ConfigEntry {
        public String key;
        public String value;

        public ConfigEntry(String key, String value) {
            this.key       = key;
            this.value     = value;
        }
    }
}
