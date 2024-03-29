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

import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

import org.xbill.DNS.CNAMERecord;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Header;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.OPTRecord;
import org.xbill.DNS.RRSIGRecord;
import org.xbill.DNS.RRset;
import org.xbill.DNS.Record;
import org.xbill.DNS.Section;
import org.xbill.DNS.Type;

/**
 * This class represents a DNS message with resolver/validator state.
 */
public class SMessage {
    private static         SRRset[] emptySRRsetArray = new SRRset[0];
    private Header         mHeader;
    private Record         mQuestion;
    private OPTRecord      mOPTRecord;
    private List<SRRset>[] mSection;
    private SecurityStatus mSecurityStatus;

    @SuppressWarnings("unchecked")
    public SMessage(Header h) {
        mSection        = new List[3];
        mHeader         = h;
        mSecurityStatus = new SecurityStatus();
    }

    public SMessage(int id) {
        this(new Header(id));
    }

    public SMessage() {
        this(new Header(0));
    }

    public SMessage(Message m) {
        this(m.getHeader());
        mQuestion  = m.getQuestion();
        mOPTRecord = m.getOPT();

        for (int i = Section.ANSWER; i <= Section.ADDITIONAL; i++) {
            List<RRset> rrsets = m.getSectionRRsets(i);

            for (RRset rrs : rrsets) {
                addRRset(rrs, i);
            }
        }
    }

    public Header getHeader() {
        return mHeader;
    }

    public void setHeader(Header h) {
        mHeader = h;
    }

    public void setQuestion(Record r) {
        mQuestion = r;
    }

    public Record getQuestion() {
        return mQuestion;
    }

    public Name getQName() {
        return getQuestion().getName();
    }

    public int getQType() {
        return getQuestion().getType();
    }

    public int getQClass() {
        return getQuestion().getDClass();
    }

    public void setOPT(OPTRecord r) {
        mOPTRecord = r;
    }

    public OPTRecord getOPT() {
        return mOPTRecord;
    }

    public List<SRRset> getSectionList(int section) {
        if ((section <= Section.QUESTION) || (section > Section.ADDITIONAL)) {
            throw new IllegalArgumentException("Invalid section.");
        }

        if (mSection[section - 1] == null) {
            mSection[section - 1] = new LinkedList<>();
        }

        return mSection[section - 1];
    }

    public void addRRset(SRRset srrset, int section) {
        if ((section <= Section.QUESTION) || (section > Section.ADDITIONAL)) {
            throw new IllegalArgumentException("Invalid section");
        }

        if (srrset.getType() == Type.OPT) {
            mOPTRecord = (OPTRecord) srrset.first();

            return;
        }

        List<SRRset> sectionList = getSectionList(section);
        sectionList.add(srrset);
    }

    public void addRRset(RRset rrset, int section) {
        if (rrset instanceof SRRset) {
            addRRset((SRRset) rrset, section);

            return;
        }

        SRRset srrset = new SRRset(rrset);
        addRRset(srrset, section);
    }

    public void prependRRsets(List<SRRset> rrsets, int section) {
        if ((section <= Section.QUESTION) || (section > Section.ADDITIONAL)) {
            throw new IllegalArgumentException("Invalid section");
        }

        List<SRRset> sectionList = getSectionList(section);
        sectionList.addAll(0, rrsets);
    }

    public SRRset[] getSectionRRsets(int section) {
        List<SRRset> slist = getSectionList(section);

        return slist.toArray(emptySRRsetArray);
    }

    public SRRset[] getSectionRRsets(int section, int qtype) {
        List<SRRset> slist = getSectionList(section);

        if (slist.isEmpty()) {
            return new SRRset[0];
        }

        ArrayList<SRRset> result = new ArrayList<>(slist.size());

        for (SRRset rrset : slist) {
            if (rrset.getType() == qtype) {
                result.add(rrset);
            }
        }

        return result.toArray(emptySRRsetArray);
    }

    public void deleteRRset(SRRset rrset, int section) {
        List<SRRset> slist = getSectionList(section);

        if (slist.isEmpty()) {
            return;
        }

        slist.remove(rrset);
    }

    public void clear(int section) {
        if ((section < Section.QUESTION) || (section > Section.ADDITIONAL)) {
            throw new IllegalArgumentException("Invalid section.");
        }

        if (section == Section.QUESTION) {
            mQuestion = null;

            return;
        }

        if (section == Section.ADDITIONAL) {
            mOPTRecord = null;
        }

        mSection[section - 1] = null;
    }

    public void clear() {
        for (int s = Section.QUESTION; s <= Section.ADDITIONAL; s++) {
            clear(s);
        }
    }

    public int getRcode() {
        // FIXME: might want to do what Message does and handle extended rcodes.
        return mHeader.getRcode();
    }

    public int getStatus() {
        return mSecurityStatus.getStatus();
    }

    public void setStatus(byte status) {
        mSecurityStatus.setStatus(status);
    }

    public SecurityStatus getSecurityStatus() {
        return mSecurityStatus;
    }

    public void setSecurityStatus(SecurityStatus s) {
        if (s == null) {
            return;
        }

        mSecurityStatus = s;
    }

    public Message getMessage() {
        // Generate our new message.
        Message m = new Message(mHeader.getID());

        // Convert the header
        // We do this for two reasons: 1) setCount() is package scope, so we
        // can't do that, and 2) setting the header on a message after creating
        // the message frequently gets stuff out of sync, leading to malformed
        // wire format messages.
        Header h = m.getHeader();
        h.setOpcode(mHeader.getOpcode());
        h.setRcode(mHeader.getRcode());

        for (int i = 0; i < 16; i++) {
            if (Flags.isFlag(i)) {
                if (mHeader.getFlag(i)) {
                    h.setFlag(i);
                } else {
                    h.unsetFlag(i);
                }
            }
        }

        // Add all the records. -- this will set the counts correctly in the
        // message header.
        if (mQuestion != null) {
            m.addRecord(mQuestion, Section.QUESTION);
        }

        for (int sec = Section.ANSWER; sec <= Section.ADDITIONAL; sec++) {
            List<SRRset> slist = getSectionList(sec);

            for (SRRset rrset : slist) {
                for (Record rr : rrset.rrs()) {
                    m.addRecord(rr, sec);
                }

                for (RRSIGRecord sig : rrset.sigs()) {
                    m.addRecord(sig, sec);
                }
            }
        }

        if (mOPTRecord != null) {
            m.addRecord(mOPTRecord, Section.ADDITIONAL);
        }

        return m;
    }

    public int getCount(int section) {
        if (section == Section.QUESTION) {
            return (mQuestion == null) ? 0 : 1;
        }

        List<SRRset> sectionList = getSectionList(section);

        if (sectionList == null) {
            return 0;
        }

        if (sectionList.isEmpty()) {
            return 0;
        }

        int count = 0;

        for (SRRset sr : sectionList) {
            count += sr.totalSize();
        }

        return count;
    }

    public String toString() {
        return getMessage().toString();
    }

    /**
     * Find a specific (S)RRset in a given section.
     *
     * @param name
     *            the name of the RRset.
     * @param type
     *            the type of the RRset.
     * @param dclass
     *            the class of the RRset.
     * @param section
     *            the section to look in (ANSWER -> ADDITIONAL)
     *
     * @return The SRRset if found, null otherwise.
     */
    public SRRset findRRset(Name name, int type, int dclass, int section) {
        if ((section <= Section.QUESTION) || (section > Section.ADDITIONAL)) {
            throw new IllegalArgumentException("Invalid section.");
        }

        SRRset[] rrsets = getSectionRRsets(section);

        for (int i = 0; i < rrsets.length; i++) {
            if (rrsets[i].getName().equals(name) &&
                (rrsets[i].getType() == type) &&
                (rrsets[i].getDClass() == dclass)) {

                return rrsets[i];
            }
        }

        return null;
    }

    /**
     * Find an "answer" RRset. This will look for RRsets in the ANSWER section
     * that match the qname/qtype/qclass, taking into consideration CNAMEs.
     *
     * @param qname
     *            The starting search name.
     * @param qtype
     *            The search type.
     * @param qclass
     *            The search class.
     *
     * @return a SRRset matching the query. This SRRset may have a different
     *         name from qname, due to following a CNAME chain.
     */
    public SRRset findAnswerRRset(Name qname, int qtype, int qclass) {
        SRRset[] srrsets = getSectionRRsets(Section.ANSWER);

        for (int i = 0; i < srrsets.length; i++) {
            if (srrsets[i].getName().equals(qname) && (srrsets[i].getType() == Type.CNAME)) {
                CNAMERecord cname = (CNAMERecord) srrsets[i].first();
                qname = cname.getTarget();

                continue;
            }

            if (srrsets[i].getName().equals(qname) &&
                (srrsets[i].getType() == qtype) &&
                (srrsets[i].getDClass() == qclass)) {

                return srrsets[i];
            }
        }

        return null;
    }
}
