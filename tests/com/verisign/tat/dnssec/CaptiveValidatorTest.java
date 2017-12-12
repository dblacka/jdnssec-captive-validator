package com.verisign.tat.dnssec;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;


public class CaptiveValidatorTest
{

    public static class Test_init extends TestCase
    {
        protected void setUp() {
            // Nothing to do yet.
        }

        public void test_0arg()
        {
            CaptiveValidator v = new CaptiveValidator();
            assertNotNull(v);
        }
    }

    public static class Test_Validate extends TestCase
    {
        Message baseMessage;

        // Set up a base Response message
        protected void setUp() {
            baseMessage = new Message();

            // set up our response header; note that the captive
            // validator code doesn't actually look at anything in the
            // header but the RCODE, really, so the flag values
            // probably don't matter.  But make them realistic anyway.
            Header hdr = new Header();
            hdr.setOpcode(DNS.Opcode.QUERY);
            hdr.setRcode(DNS.Rcode.NOERROR);
            hdr.setFlag(DNS.Flags.QR);
            hdr.setFlag(DNS.Flags.AA);
            hdr.setFlag(DNS.Flags.RD);
            baseMessage.setHeader(hdr);


        }

        public void test_positive()
        {
            Message m = new Message();
        }

        public void test_referral()
        {
        }

        public void test_nodata()
        {
        }

        public void test_nameerror()
        {
        }

        public void test_cname()
        {
        }

        public void test_any()
        {
        }
    }


    public static Test suite()
    {
        TestSuite s = new TestSuite();
        s.addTestSuite(Test_init.class);
        s.addTestSuite(Test_Validate.class);
        return s;
    }

}
