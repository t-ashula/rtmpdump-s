using System;
using System.Linq;
using NUnit.Framework;

namespace librtmp.Tests
{
    [TestFixture]
    public class RTMPTests
    {
        private const string EXAMPLE_URL = "rtmp://example.com:41935/app/plypath";

        [TestFixtureSetUp]
        public void Init()
        {
            Log.RTMP_LogSetLevel(Log.RTMP_LogLevel.RTMP_LOGALL);
            Log.RTMP_LogSetCallback((_, f, p) => Console.WriteLine(f, p));
        }

        [Test]
        public void RTMP_ParseURLTest_example()
        {
            AVal host, app, playpath;
            int protocol, port;
            var res = RTMP.RTMP_ParseURL(EXAMPLE_URL, out protocol, out host, out port, out playpath, out app);
            Assert.IsTrue(res);
            Assert.AreEqual(RTMP.RTMP_PROTOCOL_RTMP, protocol);
            Assert.IsTrue(AVal.Match(AVal.AVC("example.com"), host), "actual:" + host.to_s());
            Assert.AreEqual(41935, port);
            Assert.IsTrue(AVal.Match(AVal.AVC("plypath"), playpath), "actual:" + playpath);
            Assert.IsTrue(AVal.Match(AVal.AVC("app"), app), "actual:" + app);
        }
    }
}