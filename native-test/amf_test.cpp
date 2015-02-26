#include <CppUTest/TestHarness.h>
#include <string.h>

extern "C" {
  #include "rtmp.h"
  #include "log.h"
}

TEST_GROUP(AMFTestGroup)
{
  void setup() {
    RTMP_LogSetLevel( RTMP_LOGALL );
    // RTMP_LogSetLevel( RTMP_LOGCRIT );
  }
  void teardown() {}
};

TEST(AMFTestGroup, EncodeStringTest)
{
  AVal app = AVC("app");
  char buf[50]= {0}, *enc, *pend;
  enc = buf;
  pend = buf + sizeof(buf); 
  enc = AMF_EncodeString(enc, pend, &app );
  
  CHECK_EQUAL( 6,          enc - buf );
  CHECK_EQUAL( AMF_STRING, buf[0] );
  CHECK_EQUAL( 0,          buf[1] );
  CHECK_EQUAL( 3,          buf[2] );
  CHECK_EQUAL( 'a',        buf[3] );
  CHECK_EQUAL( 'p',        buf[4] );
  CHECK_EQUAL( 'p',        buf[5] );
  CHECK_EQUAL( '\0',       buf[6] );
}

TEST(AMFTestGroup, EncodeStringTest2)
{
  AVal app = AVC("appp");
  char buf[4]= {0}, *enc, *pend;
  enc = buf;
  pend = buf + sizeof(buf); 
  enc = AMF_EncodeString(enc, pend, &app );
  CHECK_EQUAL( NULL, enc );
}

TEST(AMFTestGroup, EncodeNumberTest1)
{
  double val = -2.3456; // 0xC0 02 C3 C9 EE CB FB 16
  char buf[100] = {0}, *enc, *pend;
  enc = buf;
  pend = buf + sizeof(buf);
  enc = AMF_EncodeNumber(enc, pend, val);
  CHECK_EQUAL( 9,          enc - buf );
  CHECK_EQUAL( AMF_NUMBER, buf[0] );
  CHECK_EQUAL( (unsigned char)0xC0, (unsigned char)buf[1] );
  CHECK_EQUAL( (unsigned char)0x02, (unsigned char)buf[2] );
  CHECK_EQUAL( (unsigned char)0xC3, (unsigned char)buf[3] );
  CHECK_EQUAL( (unsigned char)0xC9, (unsigned char)buf[4] );
  CHECK_EQUAL( (unsigned char)0xEE, (unsigned char)buf[5] );
  CHECK_EQUAL( (unsigned char)0xCB, (unsigned char)buf[6] );
  CHECK_EQUAL( (unsigned char)0xFB, (unsigned char)buf[7] );
  CHECK_EQUAL( (unsigned char)0x16, (unsigned char)buf[8] );
}

TEST(AMFTestGroup, EncodeBooleanTest1)
{
  char buf[100] = {0}, *enc, *pend;
  enc = buf;
  pend = buf + sizeof(buf);
  enc = AMF_EncodeBoolean(enc, pend, 0);
  CHECK_EQUAL( 2,          enc - buf );
  CHECK_EQUAL( AMF_BOOLEAN, buf[0] );
  CHECK_EQUAL( (unsigned char)0x00, (unsigned char)buf[1] );
  enc = buf;
  pend = buf + sizeof(buf);
  enc = AMF_EncodeBoolean(enc, pend, 1);
  CHECK_EQUAL( 2,          enc - buf );
  CHECK_EQUAL( AMF_BOOLEAN, buf[0] );
  CHECK_EQUAL( (unsigned char)0x01, (unsigned char)buf[1] );
}

TEST(AMFTestGroup, EncodeInt16Test1)
{
  short sval = 0x1234;
  char buf[100] = {0}, *enc, *pend;
  enc = buf;
  pend = buf + sizeof(buf);
  enc = AMF_EncodeInt16(enc, pend, sval);
  CHECK_EQUAL( 2,          enc - buf );
  CHECK_EQUAL( (unsigned char)0x12, (unsigned char)buf[0] );
  CHECK_EQUAL( (unsigned char)0x34, (unsigned char)buf[1] );
}

TEST(AMFTestGroup, EncodeInt24Test1)
{
  int val = 0x123456;
  char buf[100] = {0}, *enc, *pend;
  enc = buf;
  pend = buf + sizeof(buf);
  enc = AMF_EncodeInt24(enc, pend, val);
  CHECK_EQUAL( 3,          enc - buf );
  CHECK_EQUAL( (unsigned char)0x12, (unsigned char)buf[0] );
  CHECK_EQUAL( (unsigned char)0x34, (unsigned char)buf[1] );
  CHECK_EQUAL( (unsigned char)0x56, (unsigned char)buf[2] );
}

TEST(AMFTestGroup, EncodeInt32Test1)
{
  int val = 0x12345678;
  char buf[100] = {0}, *enc, *pend;
  enc = buf;
  pend = buf + sizeof(buf);
  enc = AMF_EncodeInt32(enc, pend, val);
  CHECK_EQUAL( 4,          enc - buf );
  CHECK_EQUAL( (unsigned char)0x12, (unsigned char)buf[0] );
  CHECK_EQUAL( (unsigned char)0x34, (unsigned char)buf[1] );
  CHECK_EQUAL( (unsigned char)0x56, (unsigned char)buf[2] );
  CHECK_EQUAL( (unsigned char)0x78, (unsigned char)buf[3] );
}

TEST(AMFTestGroup, EncodeNamedStringTest1)
{
  AVal name = AVC("name"), val = AVC("val");
  char buf[100] = {0}, *enc, *pend;
  int len = 2 + 4 + 1 + 2 + 3;  // "name".len + "name" + AMF_STRING + "val".len + "val"
  enc = buf;
  pend = buf + sizeof(buf);
  enc = AMF_EncodeNamedString(enc, pend, &name, &val);
  CHECK_EQUAL( len,                 enc - buf );
  CHECK_EQUAL( (unsigned char)0x00, (unsigned char)buf[0] );
  CHECK_EQUAL( (unsigned char)0x04, (unsigned char)buf[1] );
  CHECK_EQUAL( (unsigned char)'n',  (unsigned char)buf[2] );
  CHECK_EQUAL( (unsigned char)'a',  (unsigned char)buf[3] );
  CHECK_EQUAL( (unsigned char)'m',  (unsigned char)buf[4] );
  CHECK_EQUAL( (unsigned char)'e',  (unsigned char)buf[5] );
  CHECK_EQUAL( (unsigned char)AMF_STRING, (unsigned char)buf[6] );
  CHECK_EQUAL( (unsigned char)0x00, (unsigned char)buf[7] );
  CHECK_EQUAL( (unsigned char)0x03, (unsigned char)buf[8] );
  CHECK_EQUAL( (unsigned char)'v',  (unsigned char)buf[9] );
  CHECK_EQUAL( (unsigned char)'a',  (unsigned char)buf[10] );
  CHECK_EQUAL( (unsigned char)'l',  (unsigned char)buf[11] );
  CHECK_EQUAL( (unsigned char)0x00, (unsigned char)buf[12] );
}

