using System;
using System.Linq;
using NUnit.Framework;

namespace librtmp.Tests
{
    [TestFixture]
    public class AMFTests
    {
        [Test]
        public void AMF_EncodeStringTest()
        {
            AVal app = AVal.AVC("app");
            byte[] buf = new byte[50];
            int output = 0, pend = buf.Length;
            output = AMF.AMF_EncodeString(buf, output, pend, app);
            Assert.AreEqual(6, output);
            Assert.AreEqual((byte)AMFDataType.AMF_STRING, buf[0]);
            Assert.AreEqual(0, buf[1]);
            Assert.AreEqual(3, buf[2]);
            Assert.AreEqual('a', buf[3]);
            Assert.AreEqual('p', buf[4]);
            Assert.AreEqual('p', buf[5]);
        }

        [Test]
        public void AMF_EncodeStringTest2()
        {
            AVal app = AVal.AVC("appp");
            byte[] buf = new byte[4];
            int enc = 0, pend = buf.Length;
            enc = AMF.AMF_EncodeString(buf, enc, pend, app);
            Assert.AreEqual(0, enc);
        }

        [Test]
        public void AMF_EncodeNumberTest()
        {
            double val = -2.3456; // 0xC0 02 C3 C9 EE CB FB 16
            byte[] buf = new byte[100];
            int enc = 0, pend = buf.Length;
            enc = AMF.AMF_EncodeNumber(buf, enc, pend, val);
            Assert.AreEqual(9, enc);
            Assert.AreEqual((byte)AMFDataType.AMF_NUMBER, buf[0]);
            Assert.AreEqual(0xC0, buf[1]);
            Assert.AreEqual(0x02, buf[2]);
            Assert.AreEqual(0xC3, buf[3]);
            Assert.AreEqual(0xC9, buf[4]);
            Assert.AreEqual(0xEE, buf[5]);
            Assert.AreEqual(0xCB, buf[6]);
            Assert.AreEqual(0xFB, buf[7]);
            Assert.AreEqual(0x16, buf[8]);
        }

        [Test]
        public void AMF_EncodeInt16Test()
        {
            short sval = 0x1234;
            byte[] buf = new byte[100];
            int enc = 0, pend = buf.Length;
            enc = AMF.AMF_EncodeInt16(buf, enc, pend, sval);
            Assert.AreEqual(2, enc);
            Assert.AreEqual(0x12, buf[0]);
            Assert.AreEqual(0x34, buf[1]);
        }

        [Test]
        public void AMF_EncodeInt24Test()
        {
            int val = 0x123456;
            byte[] buf = new byte[100];
            int enc = 0, pend = buf.Length;
            enc = AMF.AMF_EncodeInt24(buf, enc, pend, val);
            Assert.AreEqual(3, enc, "result");
            Assert.AreEqual(0x12, buf[0], "0");
            Assert.AreEqual(0x34, buf[1], "1");
            Assert.AreEqual(0x56, buf[2], "2");
        }

        [Test]
        public void AMF_EncodeInt32Test()
        {
            int val = 0x12345678;
            byte[] buf = new byte[100];
            int enc = 0, pend = buf.Length;
            enc = AMF.AMF_EncodeInt32(buf, enc, pend, val);
            Assert.AreEqual(4, enc);
            Assert.AreEqual(0x12, buf[0]);
            Assert.AreEqual(0x34, buf[1]);
            Assert.AreEqual(0x56, buf[2]);
            Assert.AreEqual(0x78, buf[3]);
        }

        [Test]
        public void AMF_EncodeBooleanTest()
        {
            byte[] buf = new byte[100];
            int enc = 0, pend = buf.Length;

            enc = AMF.AMF_EncodeBoolean(buf, enc, pend, false);
            Assert.AreEqual(2, enc);
            Assert.AreEqual((byte)AMFDataType.AMF_BOOLEAN, buf[0]);
            Assert.AreEqual(0x00, buf[1]);

            enc = 0;
            pend = buf.Length;
            enc = AMF.AMF_EncodeBoolean(buf, enc, pend, true);
            Assert.AreEqual(2, enc);
            Assert.AreEqual((byte)AMFDataType.AMF_BOOLEAN, buf[0]);
            Assert.AreEqual(0x01, buf[1]);
        }

        [Test]
        public void AMF_EncodeNamedStringTest()
        {
            AVal name = AVal.AVC("name"), val = AVal.AVC("val");
            byte[] buf = new byte[100];
            int enc = 0, pend = buf.Length;
            int len = 2 + 4 + 1 + 2 + 3; // "name".len + "name" + AMF_STRING + "val".len + "val"
            enc = AMF.AMF_EncodeNamedString(buf, enc, pend, name, val);
            Assert.AreEqual(len, enc);
            Assert.AreEqual(0x00, buf[0]);
            Assert.AreEqual(0x04, buf[1]);
            Assert.AreEqual('n', buf[2]);
            Assert.AreEqual('a', buf[3]);
            Assert.AreEqual('m', buf[4]);
            Assert.AreEqual('e', buf[5]);
            Assert.AreEqual((byte)AMFDataType.AMF_STRING, buf[6]);
            Assert.AreEqual(0x00, buf[7]);
            Assert.AreEqual(0x03, buf[8]);
            Assert.AreEqual('v', buf[9]);
            Assert.AreEqual('a', buf[10]);
            Assert.AreEqual('l', buf[11]);
            Assert.AreEqual(0x00, buf[12]);
        }

        [Test]
        public void AMF_EncodeNamedStringTest2()
        {
            AVal name = AVal.AVC("name"), val = AVal.AVC("val");
            byte[] buf = new byte[100];
            int offset = 20;
            int enc = offset, pend = buf.Length;
            int len = 2 + 4 + 1 + 2 + 3; // "name".len + "name" + AMF_STRING + "val".len + "val"
            enc = AMF.AMF_EncodeNamedString(buf, enc, pend, name, val);
            Assert.AreEqual(len + offset, enc);
            Assert.AreEqual(0x00, buf[0 + offset]);
            Assert.AreEqual(0x04, buf[1 + offset]);
            Assert.AreEqual('n', buf[2 + offset]);
            Assert.AreEqual('a', buf[3 + offset]);
            Assert.AreEqual('m', buf[4 + offset]);
            Assert.AreEqual('e', buf[5 + offset]);
            Assert.AreEqual((byte)AMFDataType.AMF_STRING, buf[6 + offset]);
            Assert.AreEqual(0x00, buf[7 + offset]);
            Assert.AreEqual(0x03, buf[8 + offset]);
            Assert.AreEqual('v', buf[9 + offset]);
            Assert.AreEqual('a', buf[10 + offset]);
            Assert.AreEqual('l', buf[11 + offset]);
            Assert.AreEqual(0x00, buf[12 + offset]);
        }

        [Test]
        public void AMF_EncodeNamedNumberTest()
        {
            AVal name = AVal.AVC("name");
            double val = -2.3456; // 0xC0 02 C3 C9 EE CB FB 16
            byte[] buf = new byte[100];
            int enc = 0, pend = buf.Length;
            int len = 2 + 4 + 1 + 8; // "name".len + "name" + AMF_NUMBER + 8
            enc = AMF.AMF_EncodeNamedNumber(buf, enc, pend, name, val);
            Assert.AreEqual(len, enc);
            Assert.AreEqual(0x00, buf[0]);
            Assert.AreEqual(0x04, buf[1]);
            Assert.AreEqual('n', buf[2]);
            Assert.AreEqual('a', buf[3]);
            Assert.AreEqual('m', buf[4]);
            Assert.AreEqual('e', buf[5]);
            Assert.AreEqual((byte)AMFDataType.AMF_NUMBER, buf[6]);
            Assert.AreEqual(0xC0, buf[7]);
            Assert.AreEqual(0x02, buf[8]);
            Assert.AreEqual(0xC3, buf[9]);
            Assert.AreEqual(0xC9, buf[10]);
            Assert.AreEqual(0xEE, buf[11]);
            Assert.AreEqual(0xCB, buf[12]);
            Assert.AreEqual(0xFB, buf[13]);
            Assert.AreEqual(0x16, buf[14]);
        }

        [Test]
        public void AMF_EncodeNamedBooleanTest()
        {
            AVal name = AVal.AVC("name");
            byte[] buf = new byte[100];
            int enc = 0, pend = buf.Length;
            int len = 2 + 4 + 1 + 1; // "name".len + "name" + AMF_NUMBER + 8
            enc = AMF.AMF_EncodeNamedBoolean(buf, enc, pend, name, true);
            Assert.AreEqual(len, enc);
            Assert.AreEqual(0x00, buf[0]);
            Assert.AreEqual(0x04, buf[1]);
            Assert.AreEqual('n', buf[2]);
            Assert.AreEqual('a', buf[3]);
            Assert.AreEqual('m', buf[4]);
            Assert.AreEqual('e', buf[5]);
            Assert.AreEqual((byte)AMFDataType.AMF_BOOLEAN, buf[6]);
            Assert.AreEqual(0x01, buf[7]);
        }

        [Test]
        public void AMF_DecodeInt16Test()
        {
            Assert.Inconclusive();
        }

        [Test]
        public void AMF_DecodeInt24Test()
        {
            Assert.Inconclusive();
        }

        [Test]
        public void AMF_DecodeInt32Test()
        {
            Assert.Inconclusive();
        }

        [Test]
        public void AMF_DecodeStringTest()
        {
            Assert.Inconclusive();
        }

        [Test]
        public void AMF_DecodeNumberTest()
        {
            Assert.Inconclusive();
        }

        [Test]
        public void memcpyTest()
        {
            var src = new byte[] { 0x01, 0x23, 0x45, 0x67, 0x89 };
            var dst = new byte[src.Length];
            AMF.memcpy(dst, 0, src, 3);
            Assert.AreEqual(src[0], dst[0]);
            Assert.AreEqual(src[1], dst[1]);
            Assert.AreEqual(src[2], dst[2]);
            Assert.AreEqual(0x00, dst[3]);
        }
    }
}