using System;
using System.Linq;
using NUnit;
using NUnit.Framework;

namespace librtmp.Tests
{
    [TestFixture]
    public class AValTests
    {
        [Test]
        public void MatchTest_Match()
        {
            var a = AVal.AVC("string1");
            var b = AVal.AVC("string1");
            Assert.IsTrue(AVal.Match(a, b));
        }

        [Test]
        public void MatchTest_Unmatch()
        {
            var a = AVal.AVC("string1");
            var b = AVal.AVC("string2");
            Assert.IsFalse(AVal.Match(a, b));
        }

        [Test]
        public void MatchTest_Empty()
        {
            AVal a = AVal.AVC(string.Empty), b = AVal.AVC(string.Empty);
            Assert.IsTrue(AVal.Match(a, b));
        }
    }
}