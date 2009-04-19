/*
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

import org.xbill.DNS.*;

/**
 * A version of the RRset class overrides the standard security status.
 */
public class SRRset extends RRset
{
  private SecurityStatus mSecurityStatus;
  
  /** Create a new, blank SRRset. */
  public SRRset()
  {
    super();
    mSecurityStatus = new SecurityStatus();
  }

  /**
   * Create a new SRRset from an existing RRset. This SRRset will contain that
   * same internal Record objects as the original RRset.
   */
  @SuppressWarnings("unchecked") // org.xbill.DNS.RRset isn't typesafe-aware.
public SRRset(RRset r)
  {
    this();

    for (Iterator i = r.rrs(); i.hasNext();)
    {
      addRR((Record) i.next());
    }

    for (Iterator i = r.sigs(); i.hasNext();)
    {
      addRR((Record) i.next());
    }
  }

  /**
   * Clone this SRRset, giving the copy a new TTL. The copy is independent
   * from the original except for the security status.
   * 
   * @param withNewTTL The new TTL to apply to the RRset. This applies to
   *          contained RRsig records as well.
   * @return The cloned SRRset.
   */
//  public SRRset cloneSRRset(long withNewTTL)
//  {
//    SRRset nr = new SRRset();
//
//    for (Iterator i = rrs(); i.hasNext();)
//    {
//      nr.addRR(((Record) i.next()).withTTL(withNewTTL));
//    }
//    for (Iterator i = sigs(); i.hasNext();)
//    {
//      nr.addRR(((Record) i.next()).withTTL(withNewTTL));
//    }
//
//    nr.mSecurityStatus = mSecurityStatus;
//
//    return nr;
//  }

  public SRRset cloneSRRsetNoSigs()
  {
    SRRset nr = new SRRset();
    for (Iterator i = rrs(); i.hasNext();)
    {
      // NOTE: should this clone the records as well?
      nr.addRR((Record) i.next());
    }
    // Do not copy the SecurityStatus reference
    
    return nr;
  }
  
  
  /**
   * Return the current security status (generally: UNCHECKED, BOGUS, or
   * SECURE).
   */
  public int getSecurity()
  {
    return getSecurityStatus();
  }

  /**
   * Return the current security status (generally: UNCHECKED, BOGUS, or
   * SECURE).
   */
  public int getSecurityStatus()
  {
    return mSecurityStatus.getStatus();
  }

  /**
   * Set the current security status for this SRRset. This status will be
   * shared amongst all copies of this SRRset (created with cloneSRRset())
   */
  public void setSecurityStatus(byte status)
  {
    mSecurityStatus.setStatus(status);
  }

  public int totalSize() {
      int num_sigs = 0;
      for (Iterator i = sigs(); i.hasNext(); ) {
          num_sigs++;
      }
      return size() + num_sigs;
  }
  
  /**
   * @return The total number of records (data + sigs) in the SRRset.
   */
  public int getNumRecords()
  {
    return totalSize();
  }

  public RRSIGRecord firstSig() {
      for (Iterator i = sigs(); i.hasNext(); ) {
          return (RRSIGRecord) i.next();
      }
      return null;
  }
  /**
   * @return true if this RRset has RRSIG records that cover data records.
   *         (i.e., RRSIG SRRsets return false)
   */
  public boolean isSigned()
  {
    if (getType() == Type.RRSIG) return false;
    return firstSig() != null;
  }

  /**
   * @return The "signer" name for this SRRset, if signed, or null if not.
   */
  public Name getSignerName()
  {
    RRSIGRecord sig = (RRSIGRecord) firstSig();
    if (sig == null) return null;
    return sig.getSigner();
  }
  
//  public void setTTL(long ttl)
//  {
//    if (ttl < 0)
//    {
//      throw new IllegalArgumentException("ttl can't be less than zero, stupid! was " + ttl);
//    }
//    super.setTTL(ttl);
//  }
}
