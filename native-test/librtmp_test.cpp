#include <CppUTest/TestHarness.h>
#include <string.h>

extern "C" {
  #include "rtmp.h"
  #include "log.h"
}

TEST_GROUP(FirstTestGroup)
{
  void setup() {
    // RTMP_LogSetLevel( RTMP_LOGALL );
    RTMP_LogSetLevel( RTMP_LOGCRIT );
  }
  void teardown() {}
};

TEST(FirstTestGroup, CallParseURLTest)
{
  // int RTMP_ParseURL(const char *url, int *protocol, AVal *host, unsigned int *port, AVal *playpath, AVal *app);
  AVal host, playpath, app;
  int protocol;
  unsigned int port;
  int res = RTMP_ParseURL("", &protocol, &host, &port, &playpath, &app);
  CHECK( res == 0 );
}

TEST(FirstTestGroup, ParseTestAAndG)
{
  AVal host, playpath, app;
  int protocol;
  unsigned int port;
  int res = RTMP_ParseURL("rtmp://fms-base1.mitene.ad.jp/agqr/aandg22", &protocol, &host, &port, &playpath, &app);
  CHECK_EQUAL( 1, res );
  CHECK_EQUAL( RTMP_PROTOCOL_RTMP, protocol );
  CHECK_EQUAL( strlen( "fms-base1.mitene.ad.jp" ), host.av_len )
  CHECK( strncmp( "fms-base1.mitene.ad.jp", host.av_val, host.av_len ) == 0 );
  CHECK_EQUAL( 0, port );
  CHECK_EQUAL( strlen( "aandg22" ), playpath.av_len );
  CHECK( strncmp( "aandg22", playpath.av_val, playpath.av_len ) == 0 );
}

TEST(FirstTestGroup, ParseTest)
{
  // rtmp://example.com:41935/app/appinst
  AVal host, playpath, app;
  int protocol;
  unsigned int port;
  int res = RTMP_ParseURL("rtmp://example.com:41935/app/playpath", &protocol, &host, &port, &playpath, &app);
  CHECK_EQUAL( 1, res );
  CHECK_EQUAL( RTMP_PROTOCOL_RTMP, protocol );
  CHECK_EQUAL( strlen( "example.com" ), host.av_len )
  CHECK( strncmp( "example.com", host.av_val, host.av_len ) == 0 );
  CHECK_EQUAL( 41935, port );
  CHECK_EQUAL( strlen( "app" ), app.av_len );
  CHECK( strncmp( "app", app.av_val, app.av_len ) == 0 );
  CHECK_EQUAL( strlen( "playpath" ), playpath.av_len );
  CHECK( strncmp( "playpath", playpath.av_val, playpath.av_len ) == 0 );
}
