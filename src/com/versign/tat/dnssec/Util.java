/*
 * $Id$
 * 
 * Copyright (c) 2005 VeriSign. All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer. 2. Redistributions in
 * binary form must reproduce the above copyright notice, this list of
 * conditions and the following disclaimer in the documentation and/or other
 * materials provided with the distribution. 3. The name of the author may not
 * be used to endorse or promote products derived from this software without
 * specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN
 * NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *  
 */

package com.versign.tat.dnssec;

import java.util.*;

import org.xbill.DNS.Flags;
import org.xbill.DNS.Header;
import org.xbill.DNS.Name;

/**
 * Some basic utility functions.
 * 
 * @author davidb
 * @version $Revision$
 */
public class Util
{

  /**
   * Convert a DNS name into a string suitable for use as a cache key.
   * 
   * @param name The name to convert.
   * @return A string representing the name. This isn't ever meant to be
   *         converted back into a DNS name.
   */
  public static String nameToString(Name name)
  {
    if (name.equals(Name.root)) return ".";

    String n = name.toString().toLowerCase();
    if (n.endsWith(".")) n = n.substring(0, n.length() - 1);

    return n;
  }

//  public static SMessage errorMessage(Request request, int rcode)
//  {
//    SMessage m = new SMessage(request.getID());
//    Header h = m.getHeader();
//    h.setRcode(rcode);
//    h.setFlag(Flags.QR);
//    m.setQuestion(request.getQuestion());
//    m.setOPT(request.getOPT());
//
//    return m;
//  }
//
//  public static SMessage errorMessage(SMessage message, int rcode)
//  {
//    Header h = message.getHeader();
//    SMessage m = new SMessage(h.getID());
//    h = m.getHeader();
//    h.setRcode(rcode);
//    h.setFlag(Flags.QR);
//    m.setQuestion(message.getQuestion());
//    m.setOPT(message.getOPT());
//
//    return m;
//  }

  public static int parseInt(String s, int def)
  {
    if (s == null) return def;
    try
    {
      return Integer.parseInt(s);
    }
    catch (NumberFormatException e)
    {
      return def;
    }
  }

  public static long parseLong(String s, long def)
  {
    if (s == null) return def;
    try
    {
      return Long.parseLong(s);
    }
    catch (NumberFormatException e)
    {
      return def;
    }
  }
  
  public static class ConfigEntry
  {
    public String key;
    public String value;
    
    public ConfigEntry(String key, String value)
    {
      this.key = key; this.value = value;
    }
  }
  
  public static List parseConfigPrefix(Properties config, String prefix)
  {
    if (! prefix.endsWith("."))
    {
      prefix = prefix + ".";
    }
    
    List res = new ArrayList();
    
    for (Iterator i = config.entrySet().iterator(); i.hasNext(); )
    {
      Map.Entry entry = (Map.Entry) i.next();
      String key = (String) entry.getKey();
      if (key.startsWith(prefix))
      {
        key = key.substring(prefix.length());
        
        res.add(new ConfigEntry(key, (String) entry.getValue()));
      }
    }
    
    return res;
  }
}
