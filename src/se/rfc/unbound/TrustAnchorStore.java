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

import java.util.HashMap;
import java.util.Map;

import org.xbill.DNS.Name;

import se.rfc.unbound.SRRset;
import se.rfc.unbound.SecurityStatus;

/**
 *
 */
public class TrustAnchorStore
{
  private Map mMap;
  
  public TrustAnchorStore()
  {
    mMap = null;
  }
  
  private String key(Name n, int dclass)
  {
    return "T" + dclass + "/" + Util.nameToString(n);
  }
  
  
  public void store(SRRset rrset)
  {
    if (mMap == null)
    {
      mMap = new HashMap();
    }
    String k = key(rrset.getName(), rrset.getDClass());
    rrset.setSecurityStatus(SecurityStatus.SECURE);
    
    mMap.put(k, rrset);
  }
  
  private SRRset lookup(String key)
  {
    if (mMap == null) return null;
    return (SRRset) mMap.get(key);
  }
  
  public SRRset find(Name n, int dclass)
  {
    if (mMap == null) return null;
    
    while (n.labels() > 0)
    {
      String k = key(n, dclass);
      SRRset r = lookup(k);
      if (r != null) return r;
      n = new Name(n, 1);
    }
    
    return null;
  }
  
}
