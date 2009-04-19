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

package se.rfc.unbound;

/**
 * Codes for DNSSEC security statuses.
 * 
 * @author davidb
 */
public class SecurityStatus
{

  /**
   * UNCHECKED means that object has yet to be validated.
   */
  public static final byte UNCHECKED     = 0;
  /**
   * BOGUS means that the object (RRset or message) failed to validate
   * (according to local policy), but should have validated.
   */
  public static final byte BOGUS         = 1;
  /**
   * BAD is a synonym for BOGUS.
   */
  public static final byte BAD           = BOGUS;
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
  public static final byte INSECURE      = 3;
  /**
   * SECURE means that the object (RRset or message) validated according to
   * local policy.
   */
  public static final byte SECURE        = 4;

  private byte              status;

  public static String string(int status)
  {
    switch (status)
    {
      case BOGUS :
        return "Bogus";
      case SECURE :
        return "Secure";
      case INSECURE :
        return "Insecure";
      case INDETERMINATE :
        return "Indeterminate";
      case UNCHECKED :
        return "Unchecked";
      default :
        return "UNKNOWN";
    }
  }

  public SecurityStatus() 
  {
    status = UNCHECKED;
  }
  
  public SecurityStatus(byte status)
  {
    setStatus(status);
  }
  
  public byte getStatus()
  {
    return status;
  }

  public void setStatus(byte status)
  {
    this.status = status;
  }

}
