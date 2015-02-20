using System;
using System.Linq;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace librtmp.Tests
{
    [TestClass]
    public class RTMPTests
    {
        private const string EXAMPLE_URL = "rtmp://example.com:41935/app/appinst";

        [TestMethod]
        public void RTMP_ParseURLTest_protocol()
        {
            AVal host, app, playpath;
            int protocol, port;
            var res = RTMP.RTMP_ParseURL(EXAMPLE_URL, out protocol, out host, out port, out playpath, out app);
            Assert.IsTrue(res);
            Assert.AreEqual(RTMP.RTMP_PROTOCOL_RTMP, protocol);
        }

        [TestMethod]
        public void RTMP_ParseURLTest_host()
        {
            AVal host, app, playpath;
            int protocol, port;
            var res = RTMP.RTMP_ParseURL(EXAMPLE_URL, out protocol, out host, out port, out playpath, out app);
            Assert.IsTrue(res);
            Assert.IsTrue(AVal.Match(AVal.AVC("example.com"), host), "actual:" + host.to_s());
        }

        [TestMethod]
        public void RTMP_ParseURLTest_port()
        {
            AVal host, app, playpath;
            int protocol, port;
            var res = RTMP.RTMP_ParseURL(EXAMPLE_URL, out protocol, out host, out port, out playpath, out app);
            Assert.IsTrue(res);
            Assert.AreEqual(41935, port);
        }

        [TestMethod]
        public void RTMP_ParseURLTest_playpath()
        {
            AVal host, app, playpath;
            int protocol, port;
            var res = RTMP.RTMP_ParseURL(EXAMPLE_URL, out protocol, out host, out port, out playpath, out app);
            Assert.IsTrue(res);
            Assert.IsTrue(AVal.Match(AVal.AVC("appinst"), playpath), "actual:" + playpath.to_s());
        }

        [TestMethod]
        public void RTMP_ParseURLTest_app()
        {
            AVal host, app, playpath;
            int protocol, port;
            var res = RTMP.RTMP_ParseURL(EXAMPLE_URL, out protocol, out host, out port, out playpath, out app);
            Assert.IsTrue(res);
            Assert.IsTrue(AVal.Match(AVal.AVC("app/appinst"), app), "actual:" + app.to_s());
        }
    }
}