/*
 * $Id$
 * 
 * Copyright (c) 2006 VeriSign. All rights reserved.
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

import java.security.NoSuchAlgorithmException;
import java.util.*;

import org.xbill.DNS.*;
import org.xbill.DNS.utils.base32;

import se.rfc.unbound.SignUtils.ByteArrayComparator;


public class NSEC3ValUtils
{

  // FIXME: should probably refactor to handle different NSEC3 parameters more
  // efficiently.
  // Given a list of NSEC3 RRs, they should be grouped according to
  // parameters. The idea is to hash and compare for each group independently,
  // instead of having to skip NSEC3 RRs with the wrong parameters.


  private static Name   asterisk_label = Name.fromConstantString("*");

  /**
   * This is a class to encapsulate a unique set of NSEC3 parameters:
   * algorithm, iterations, and salt.
   */
  private static class NSEC3Parameters
  {
    public byte   alg;
    public byte[] salt;
    public int    iterations;

    public NSEC3Parameters(NSEC3Record r)
    {
      alg = r.getHashAlgorithm();
      salt = r.getSalt();
      iterations = r.getIterations();
    }

    public boolean match(NSEC3Record r, ByteArrayComparator bac)
    {
      if (r.getHashAlgorithm() != alg) return false;
      if (r.getIterations() != iterations) return false;

      if (salt == null && r.getSalt() != null) return false;

      if (bac == null) bac = new ByteArrayComparator();
      return bac.compare(r.getSalt(), salt) == 0;
    }
  }

  /**
   * This is just a simple class to enapsulate the response to a closest
   * encloser proof.
   */
  private static class CEResponse
  {
    public Name        closestEncloser;
    public NSEC3Record ce_nsec3;
    public NSEC3Record nc_nsec3;

    public CEResponse(Name ce, NSEC3Record nsec3)
    {
      this.closestEncloser = ce;
      this.ce_nsec3 = nsec3;
    }
  }

  public static boolean supportsHashAlgorithm(int alg)
  {
    if (alg == NSEC3Record.SHA1_DIGEST_ID) return true;
    return false;
  }
  
  public static void stripUnknownAlgNSEC3s(List nsec3s)
  {
    if (nsec3s == null) return;
    for (ListIterator i = nsec3s.listIterator(); i.hasNext(); )
    {
      NSEC3Record nsec3 = (NSEC3Record) i.next();
      if (!supportsHashAlgorithm(nsec3.getHashAlgorithm()))
      {
        i.remove();
      }
    }
  }
  
  /**
   * Given a list of NSEC3Records that are part of a message, determine the
   * NSEC3 parameters (hash algorithm, iterations, and salt) present. If there
   * is more than one distinct grouping, return null;
   * 
   * @param nsec3s A list of NSEC3Record object.
   * @return A set containing a number of objects (NSEC3Parameter objects)
   *         that correspond to each distinct set of parameters, or null if
   *         the nsec3s list was empty.
   */
  public static NSEC3Parameters nsec3Parameters(List nsec3s)
  {
    if (nsec3s == null || nsec3s.size() == 0) return null;

    NSEC3Parameters params = new NSEC3Parameters((NSEC3Record) nsec3s.get(0));
    ByteArrayComparator bac = new ByteArrayComparator();
    
    for (Iterator i = nsec3s.iterator(); i.hasNext();)
    {
      if (! params.match((NSEC3Record) i.next(), bac))
      {
        return null;
      }
    }  
    return params;
  }

  /**
   * In a list of NSEC3Record object pulled from a given message, find the
   * NSEC3 that directly matches a given name, without hashing.
   * 
   * @param n The name in question.
   * @param nsec3s A list of NSEC3Records from a given message.
   * @return The matching NSEC3Record, or null if there wasn't one.
   */
  // private static NSEC3Record findDirectMatchingNSEC3(Name n, List nsec3s)
  // {
  // if (n == null || nsec3s == null) return null;
  //
  // for (Iterator i = nsec3s.iterator(); i.hasNext();)
  // {
  // NSEC3Record nsec3 = (NSEC3Record) i.next();
  // if (n.equals(nsec3.getName())) return nsec3;
  // }
  //
  // return null;
  // }
  /**
   * Given a hash and an a zone name, construct an NSEC3 ownername.
   * 
   * @param hash The hash of an original name.
   * @param zonename The zone to use in constructing the NSEC3 name.
   * @return The NSEC3 name.
   */
  private static Name hashName(byte[] hash, Name zonename)
  {
    try
    {
      return new Name(base32.toString(hash).toLowerCase(), zonename);
    }
    catch (TextParseException e)
    {
      // Note, this should never happen.
      return null;
    }
  }

  /**
   * Given a set of NSEC3 parameters, hash a name.
   * 
   * @param name The name to hash.
   * @param params The parameters to hash with.
   * @return The hash.
   */
  private static byte[] hash(Name name, NSEC3Parameters params)
  {
    try
    {
      return NSEC3Record.hash(name,
          params.alg,
          params.iterations,
          params.salt);
    }
    catch (NoSuchAlgorithmException e)
    {
//      st_log.debug("Did not recognize hash algorithm: " + params.alg);
      return null;
    }
  }

  /**
   * Given the name of a closest encloser, return the name *.closest_encloser.
   * 
   * @param closestEncloser The name to start with.
   * @return The wildcard name.
   */
  private static Name ceWildcard(Name closestEncloser)
  {
    try
    {
      Name wc = Name.concatenate(asterisk_label, closestEncloser);
      return wc;
    }
    catch (NameTooLongException e)
    {
      return null;
    }
  }

  /**
   * Given a qname and its proven closest encloser, calculate the "next
   * closest" name. Basically, this is the name that is one label longer than
   * the closest encloser that is still a subdomain of qname.
   * 
   * @param qname The qname.
   * @param closestEncloser The closest encloser name.
   * @return The next closer name.
   */
  private static Name nextClosest(Name qname, Name closestEncloser)
  {
    int strip = qname.labels() - closestEncloser.labels() - 1;
    return (strip > 0) ? new Name(qname, strip) : qname;
  }

  /**
   * Find the NSEC3Record that matches a hash of a name.
   * 
   * @param hash The pre-calculated hash of a name.
   * @param zonename The name of the zone that the NSEC3s are from.
   * @param nsec3s A list of NSEC3Records from a given message.
   * @param params The parameters used for calculating the hash.
   * @param bac An already allocated ByteArrayComparator, for reuse. This may
   *          be null.
   * 
   * @return The matching NSEC3Record, if one is present.
   */
  private static NSEC3Record findMatchingNSEC3(byte[] hash, Name zonename,
      List nsec3s, NSEC3Parameters params, ByteArrayComparator bac)
  {
    Name n = hashName(hash, zonename);

    for (Iterator i = nsec3s.iterator(); i.hasNext();)
    {
      NSEC3Record nsec3 = (NSEC3Record) i.next();
      // Skip nsec3 records that are using different parameters.
      if (!params.match(nsec3, bac)) continue;
      if (n.equals(nsec3.getName())) return nsec3;
    }
    return null;
  }

  /**
   * Given a hash and a candidate NSEC3Record, determine if that NSEC3Record
   * covers the hash. Covers specifically means that the hash is in between
   * the owner and next hashes and does not equal either.
   * 
   * @param nsec3 The candidate NSEC3Record.
   * @param hash The precalculated hash.
   * @param bac An already allocated comparator. This may be null.
   * @return True if the NSEC3Record covers the hash.
   */
  private static boolean nsec3Covers(NSEC3Record nsec3, byte[] hash,
      ByteArrayComparator bac)
  {
    byte[] owner = nsec3.getOwner();
    byte[] next = nsec3.getNext();

    // This is the "normal case: owner < next and owner < hash < next
    if (bac.compare(owner, hash) < 0 && bac.compare(hash, next) < 0)
      return true;

    // this is the end of zone case: next < owner && hash > owner || hash <
    // next
    if (bac.compare(next, owner) <= 0
        && (bac.compare(hash, next) < 0 || bac.compare(owner, hash) < 0))
      return true;
     
    // Otherwise, the NSEC3 does not cover the hash.
    return false;
  }

  /**
   * Given a pre-hashed name, find a covering NSEC3 from among a list of
   * NSEC3s.
   * 
   * @param hash The hash to consider.
   * @param zonename The name of the zone.
   * @param nsec3s The list of NSEC3s present in a message.
   * @param params The NSEC3 parameters used to generate the hash -- NSEC3s
   *          that do not use those parameters will be skipped.
   * 
   * @return A covering NSEC3 if one is present, null otherwise.
   */
  private static NSEC3Record findCoveringNSEC3(byte[] hash, Name zonename,
      List nsec3s, NSEC3Parameters params, ByteArrayComparator bac)
  {
    ByteArrayComparator comparator = new ByteArrayComparator();

    for (Iterator i = nsec3s.iterator(); i.hasNext();)
    {
      NSEC3Record nsec3 = (NSEC3Record) i.next();
      if (!params.match(nsec3, bac)) continue;

      if (nsec3Covers(nsec3, hash, comparator)) return nsec3;
    }

    return null;
  }


  /**
   * Given a name and a list of NSEC3s, find the candidate closest encloser.
   * This will be the first ancestor of 'name' (including itself) to have a
   * matching NSEC3 RR.
   * 
   * @param name The name the start with.
   * @param zonename The name of the zone that the NSEC3s came from.
   * @param nsec3s The list of NSEC3s.
   * @param nsec3params The NSEC3 parameters.
   * @param bac A pre-allocated comparator. May be null.
   * 
   * @return A CEResponse containing the closest encloser name and the NSEC3
   *         RR that matched it, or null if there wasn't one.
   */
  private static CEResponse findClosestEncloser(Name name, Name zonename,
      List nsec3s, NSEC3Parameters params, ByteArrayComparator bac)
  {
    Name n = name;

    NSEC3Record nsec3;

    // This scans from longest name to shortest, so the first match we find is
    // the only viable candidate.
    // FIXME: modify so that the NSEC3 matching the zone apex need not be
    // present.
    while (n.labels() >= zonename.labels())
    {
      nsec3 = findMatchingNSEC3(hash(n, params), zonename, nsec3s, params, bac);
      if (nsec3 != null) return new CEResponse(n, nsec3);
      n = new Name(n, 1);
    }

    return null;
  }

  /**
   * Given a List of nsec3 RRs, find and prove the closest encloser to qname.
   * 
   * @param qname The qname in question.
   * @param zonename The name of the zone that the NSEC3 RRs come from.
   * @param nsec3s The list of NSEC3s found the this response (already
   *          verified).
   * @param params The NSEC3 parameters found in the response.
   * @param bac A pre-allocated comparator. May be null.
   * @param proveDoesNotExist If true, then if the closest encloser turns out
   *          to be qname, then null is returned.
   * @return null if the proof isn't completed. Otherwise, return a CEResponse
   *         object which contains the closest encloser name and the NSEC3
   *         that matches it.
   */
  private static CEResponse proveClosestEncloser(Name qname, Name zonename,
      List nsec3s, NSEC3Parameters params, ByteArrayComparator bac,
      boolean proveDoesNotExist)
  {
    CEResponse candidate = findClosestEncloser(qname,
        zonename,
        nsec3s,
        params,
        bac);

    if (candidate == null)
    {
//      st_log.debug("proveClosestEncloser: could not find a "
//          + "candidate for the closest encloser.");
      return null;
    }

    if (candidate.closestEncloser.equals(qname))
    {
      if (proveDoesNotExist)
      {
//        st_log.debug("proveClosestEncloser: proved that qname existed!");
        return null;
      }
      // otherwise, we need to nothing else to prove that qname is its own
      // closest encloser.
      return candidate;
    }

    // If the closest encloser is actually a delegation, then the response
    // should have been a referral. If it is a DNAME, then it should have been
    // a DNAME response.
    if (candidate.ce_nsec3.hasType(Type.NS)
        && !candidate.ce_nsec3.hasType(Type.SOA))
    {
//      st_log.debug("proveClosestEncloser: closest encloser "
//          + "was a delegation!");
      return null;
    }
    if (candidate.ce_nsec3.hasType(Type.DNAME))
    {
//      st_log.debug("proveClosestEncloser: closest encloser was a DNAME!");
      return null;
    }

    // Otherwise, we need to show that the next closer name is covered.
    Name nextClosest = nextClosest(qname, candidate.closestEncloser);
    
    byte[] nc_hash = hash(nextClosest, params);
    candidate.nc_nsec3 = findCoveringNSEC3(nc_hash,
        zonename,
        nsec3s,
        params,
        bac);
    if (candidate.nc_nsec3 == null)
    {
//      st_log.debug("Could not find proof that the "
//          + "closest encloser was the closest encloser");
      return null;
    }

    return candidate;
  }

  private static int maxIterations(int baseAlg, int keysize)
  {
    switch (baseAlg)
    {
      case DnsSecVerifier.RSA:
        if (keysize == 0) return 2500; // the max at 4096
        if (keysize > 2048) return 2500;
        if (keysize > 1024) return 500;
        if (keysize > 0) return 150;
        break;
      case DnsSecVerifier.DSA:
        if (keysize == 0) return 5000; // the max at 2048;
        if (keysize > 1024) return 5000;
        if (keysize > 0) return 1500;
        break;
    }
    return -1;
  }
  
  private static boolean validIterations(NSEC3Parameters nsec3params, 
      RRset dnskey_rrset, DnsSecVerifier verifier)
  {
    // for now, we return the maximum iterations based simply on the key
    // algorithms that may have been used to sign the NSEC3 RRsets.
    
    int max_iterations = 0;
    for (Iterator i = dnskey_rrset.rrs(); i.hasNext();)
    {
      DNSKEYRecord dnskey = (DNSKEYRecord) i.next();
      int baseAlg = verifier.baseAlgorithm(dnskey.getAlgorithm());
      int iters = maxIterations(baseAlg, 0);
      max_iterations = max_iterations < iters ? iters : max_iterations;
    }
    
    if (nsec3params.iterations > max_iterations) return false;
    
   return true; 
  }
  
  /**
   * Determine if all of the NSEC3s in a response are legally ignoreable
   * (i.e., their presence should lead to an INSECURE result). Currently, this
   * is solely based on iterations.
   * 
   * @param nsec3s The list of NSEC3s. If there is more than one set of NSEC3
   *          parameters present, this test will not be performed.
   * @param dnskey_rrset The set of validating DNSKEYs.
   * @param verifier The verifier used to verify the NSEC3 RRsets. This is
   *          solely used to map algorithm aliases.
   * @return true if all of the NSEC3s can be legally ignored, false if not.
   */
  public static boolean allNSEC3sIgnoreable(List nsec3s, RRset dnskey_rrset, DnsSecVerifier verifier)
  {
    NSEC3Parameters params = nsec3Parameters(nsec3s);
    if (params == null) return false;
    
    return !validIterations(params, dnskey_rrset, verifier);
  }
  
  /**
   * Determine if the set of NSEC3 records provided with a response prove NAME
   * ERROR. This means that the NSEC3s prove a) the closest encloser exists,
   * b) the direct child of the closest encloser towards qname doesn't exist,
   * and c) *.closest encloser does not exist.
   * 
   * @param nsec3s The list of NSEC3s.
   * @param qname The query name to check against.
   * @param zonename This is the name of the zone that the NSEC3s belong to.
   *          This may be discovered in any number of ways. A good one is to
   *          use the signerName from the NSEC3 record's RRSIG.
   * @return SecurityStatus.SECURE of the Name Error is proven by the NSEC3
   *         RRs, BOGUS if not, INSECURE if all of the NSEC3s could be validly
   *         ignored.
   */
  public static boolean proveNameError(List nsec3s, Name qname, Name zonename)
  {
    if (nsec3s == null || nsec3s.size() == 0) return false;

    NSEC3Parameters nsec3params = nsec3Parameters(nsec3s);
    if (nsec3params == null)
    {
//      st_log.debug("Could not find a single set of " +
//          "NSEC3 parameters (multiple parameters present).");
      return false;
    }
    
    ByteArrayComparator bac = new ByteArrayComparator();

    // First locate and prove the closest encloser to qname. We will use the
    // variant that fails if the closest encloser turns out to be qname.
    CEResponse ce = proveClosestEncloser(qname,
        zonename,
        nsec3s,
        nsec3params,
        bac,
        true);

    if (ce == null)
    {
//      st_log.debug("proveNameError: failed to prove a closest encloser.");
      return false;
    }

    // At this point, we know that qname does not exist. Now we need to prove
    // that the wildcard does not exist.
    Name wc = ceWildcard(ce.closestEncloser);
    byte[] wc_hash = hash(wc, nsec3params);
    NSEC3Record nsec3 = findCoveringNSEC3(wc_hash,
        zonename,
        nsec3s,
        nsec3params,
        bac);
    if (nsec3 == null)
    {
//      st_log.debug("proveNameError: could not prove that the "
//          + "applicable wildcard did not exist.");
      return false;
    }

    return true;
  }

  /**
   * Determine if the set of NSEC3 records provided with a response prove NAME
   * ERROR when qtype = NSEC3. This is a special case, and (currently anyway)
   * it suffices to simply prove that the NSEC3 RRset itself does not exist,
   * without proving that no wildcard could have generated it, etc..
   * 
   * @param nsec3s The list of NSEC3s.
   * @param qname The query name to check against.
   * @param zonename This is the name of the zone that the NSEC3s belong to.
   *          This may be discovered in any number of ways. A good one is to
   *          use the signerName from the NSEC3 record's RRSIG.
   * @return true of the Name Error is proven by the NSEC3 RRs, false if not.
   */
  // public static boolean proveNSEC3NameError(List nsec3s, Name qname,
  // Name zonename)
  // {
  // if (nsec3s == null || nsec3s.size() == 0) return false;
  //
  // for (Iterator i = nsec3s.iterator(); i.hasNext(); )
  // {
  // NSEC3Record nsec3 = (NSEC3Record) i.next();
  //      
  // // Convert owner and next into Names.
  // Name owner = nsec3.getName();
  // Name next = null;
  // try
  // {
  // next = new Name(base32.toString(nsec3.getNext()), zonename);
  // }
  // catch (TextParseException e)
  // {
  // continue;
  // }
  //      
  // // Now see if qname is covered by the NSEC3.
  //      
  // // normal case, owner < qname < next.
  // if (owner.compareTo(next) < 0 && owner.compareTo(qname) < 0 &&
  // next.compareTo(qname) > 0)
  // {
  // st_log.debug("proveNSEC3NameError: found a covering NSEC3: " + nsec3);
  // return true;
  // }
  // // end-of-zone case: next < owner and qname > owner || qname < next.
  // if (owner.compareTo(next) > 0 && (owner.compareTo(qname) < 0 ||
  // next.compareTo(qname) > 0))
  // {
  // st_log.debug("proveNSEC3NameError: found a covering NSEC3: " + nsec3);
  // return true;
  // }
  // }
  //    
  // st_log.debug("proveNSEC3NameError: did not find a covering NSEC3");
  // return false;
  // }
  /**
   * Determine if the NSEC3s provided in a response prove the NOERROR/NODATA
   * status. There are a number of different variants to this:
   * 
   * 1) Normal NODATA -- qname is matched to an NSEC3 record, type is not
   * present.
   * 
   * 2) ENT NODATA -- because there must be NSEC3 record for
   * empty-non-terminals, this is the same as #1.
   * 
   * 3) NSEC3 ownername NODATA -- qname matched an existing, lone NSEC3
   * ownername, but qtype was not NSEC3. NOTE: as of nsec-05, this case no
   * longer exists.
   * 
   * 4) Wildcard NODATA -- A wildcard matched the name, but not the type.
   * 
   * 5) Opt-In DS NODATA -- the qname is covered by an opt-in span and qtype ==
   * DS. (or maybe some future record with the same parent-side-only property)
   * 
   * @param nsec3s The NSEC3Records to consider.
   * @param qname The qname in question.
   * @param qtype The qtype in question.
   * @param zonename The name of the zone that the NSEC3s came from.
   * @return true if the NSEC3s prove the proposition.
   */
  public static boolean proveNodata(List nsec3s, Name qname, int qtype,
      Name zonename)
  {
    if (nsec3s == null || nsec3s.size() == 0) return false;

    NSEC3Parameters nsec3params = nsec3Parameters(nsec3s);
    if (nsec3params == null)
    {
//      st_log.debug("could not find a single set of "
//          + "NSEC3 parameters (multiple parameters present)");
      return false;
    }
    ByteArrayComparator bac = new ByteArrayComparator();

    NSEC3Record nsec3 = findMatchingNSEC3(hash(qname, nsec3params),
        zonename,
        nsec3s,
        nsec3params,
        bac);
    // Cases 1 & 2.
    if (nsec3 != null)
    {
      if (nsec3.hasType(qtype))
      {
//        st_log.debug("proveNodata: Matching NSEC3 proved that type existed!");
        return false;
      }
      if (nsec3.hasType(Type.CNAME))
      {
//        st_log.debug("proveNodata: Matching NSEC3 proved "
//            + "that a CNAME existed!");
        return false;
      }
      return true;
    }

    // For cases 3 - 5, we need the proven closest encloser, and it can't
    // match qname. Although, at this point, we know that it won't since we
    // just checked that.
    CEResponse ce = proveClosestEncloser(qname,
        zonename,
        nsec3s,
        nsec3params,
        bac,
        true);

    // At this point, not finding a match or a proven closest encloser is a
    // problem.
    if (ce == null)
    {
//      st_log.debug("proveNodata: did not match qname, "
//          + "nor found a proven closest encloser.");
      return false;
    }

    // Case 3: REMOVED

    // Case 4:
    Name wc = ceWildcard(ce.closestEncloser);
    nsec3 = findMatchingNSEC3(hash(wc, nsec3params),
        zonename,
        nsec3s,
        nsec3params,
        bac);

    if (nsec3 != null)
    {
      if (nsec3.hasType(qtype))
      {
//        st_log.debug("proveNodata: matching wildcard had qtype!");
        return false;
      }
      return true;
    }

    // Case 5.
    if (qtype != Type.DS)
    {
//      st_log.debug("proveNodata: could not find matching NSEC3, "
//          + "nor matching wildcard, and qtype is not DS -- no more options.");
      return false;
    }

    // We need to make sure that the covering NSEC3 is opt-in.
    if (!ce.nc_nsec3.getOptInFlag())
    {
//      st_log.debug("proveNodata: covering NSEC3 was not "
//          + "opt-in in an opt-in DS NOERROR/NODATA case.");
      return false;
    }

    return true;
  }

  /**
   * Prove that a positive wildcard match was appropriate (no direct match
   * RRset).
   * 
   * @param nsec3s The NSEC3 records to work with.
   * @param qname The qname that was matched to the wildard
   * @param zonename The name of the zone that the NSEC3s come from.
   * @param wildcard The purported wildcard that matched.
   * @return true if the NSEC3 records prove this case.
   */
  public static boolean proveWildcard(List nsec3s, Name qname, Name zonename,
      Name wildcard)
  {
    if (nsec3s == null || nsec3s.size() == 0) return false;
    if (qname == null || wildcard == null) return false;

    NSEC3Parameters nsec3params = nsec3Parameters(nsec3s);
    if (nsec3params == null) 
    {
//      st_log.debug("couldn't find a single set of NSEC3 parameters (multiple parameters present).");
      return false;
    }
    
    ByteArrayComparator bac = new ByteArrayComparator();

    // We know what the (purported) closest encloser is by just looking at the
    // supposed generating wildcard.
    CEResponse candidate = new CEResponse(new Name(wildcard, 1), null);

    // Now we still need to prove that the original data did not exist.
    // Otherwise, we need to show that the next closer name is covered.
    Name nextClosest = nextClosest(qname, candidate.closestEncloser);
    candidate.nc_nsec3 = findCoveringNSEC3(hash(nextClosest, nsec3params),
        zonename,
        nsec3s,
        nsec3params,
        bac);

    if (candidate.nc_nsec3 == null)
    {
//      st_log.debug("proveWildcard: did not find a covering NSEC3 "
//          + "that covered the next closer name to " + qname + " from "
//          + candidate.closestEncloser + " (derived from wildcard " + wildcard
//          + ")");
      return false;
    }

    return true;
  }

  /**
   * Prove that a DS response either had no DS, or wasn't a delegation point.
   * 
   * Fundamentally there are two cases here: normal NODATA and Opt-In NODATA.
   * 
   * @param nsec3s The NSEC3 RRs to examine.
   * @param qname The name of the DS in question.
   * @param zonename The name of the zone that the NSEC3 RRs come from.
   * 
   * @return SecurityStatus.SECURE if it was proven that there is no DS in a
   *         secure (i.e., not opt-in) way, SecurityStatus.INSECURE if there
   *         was no DS in an insecure (i.e., opt-in) way,
   *         SecurityStatus.INDETERMINATE if it was clear that this wasn't a
   *         delegation point, and SecurityStatus.BOGUS if the proofs don't
   *         work out.
   */
  public static int proveNoDS(List nsec3s, Name qname, Name zonename)
  {
    if (nsec3s == null || nsec3s.size() == 0) return SecurityStatus.BOGUS;

    NSEC3Parameters nsec3params = nsec3Parameters(nsec3s);
    if (nsec3params == null)
    {
//      st_log.debug("couldn't find a single set of " +
//          "NSEC3 parameters (multiple parameters present).");
      return SecurityStatus.BOGUS;      
    }
    ByteArrayComparator bac = new ByteArrayComparator();

    // Look for a matching NSEC3 to qname -- this is the normal NODATA case.
    NSEC3Record nsec3 = findMatchingNSEC3(hash(qname, nsec3params),
        zonename,
        nsec3s,
        nsec3params,
        bac);

    if (nsec3 != null)
    {
      // If the matching NSEC3 has the SOA bit set, it is from the wrong zone
      // (the child instead of the parent). If it has the DS bit set, then we
      // were lied to.
      if (nsec3.hasType(Type.SOA) || nsec3.hasType(Type.DS))
      {
        return SecurityStatus.BOGUS;
      }
      // If the NSEC3 RR doesn't have the NS bit set, then this wasn't a
      // delegation point.
      if (!nsec3.hasType(Type.NS)) return SecurityStatus.INDETERMINATE;

      // Otherwise, this proves no DS.
      return SecurityStatus.SECURE;
    }

    // Otherwise, we are probably in the opt-in case.
    CEResponse ce = proveClosestEncloser(qname,
        zonename,
        nsec3s,
        nsec3params,
        bac,
        true);
    if (ce == null)
    {
      return SecurityStatus.BOGUS;
    }

    // If we had the closest encloser proof, then we need to check that the
    // covering NSEC3 was opt-in -- the proveClosestEncloser step already
    // checked to see if the closest encloser was a delegation or DNAME.
    if (ce.nc_nsec3.getOptInFlag())
    {
      return SecurityStatus.SECURE;
    }

    return SecurityStatus.BOGUS;
  }

}