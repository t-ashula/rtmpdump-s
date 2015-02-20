using System;
using System.Linq;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace librtmp.Tests
{
    [TestClass]
    public class AValTests
    {
        [TestMethod]
        public void MatchTest_Match()
        {
            var a = AVal.AVC("string1");
            var b = AVal.AVC("string1");
            Assert.IsTrue(AVal.Match(a, b));
        }

        [TestMethod]
        public void MatchTest_Unmatch()
        {
            var a = AVal.AVC("string1");
            var b = AVal.AVC("string2");
            Assert.IsFalse(AVal.Match(a, b));
        }

        [TestMethod]
        public void MatchTest_Empty()
        {
            AVal a = AVal.AVC(string.Empty), b = AVal.AVC(string.Empty);
            Assert.IsTrue(AVal.Match(a, b));
        }
    }
}