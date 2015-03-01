/*
 *      Copyright (C) 2005-2008 Team XBMC
 *      http://www.xbmc.org
 *      Copyright (C) 2008-2009 Andrej Stepanchuk
 *      Copyright (C) 2009-2010 Howard Chu
 *
 *  This file is part of librtmp.
 *
 *  librtmp is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as
 *  published by the Free Software Foundation; either version 2.1,
 *  or (at your option) any later version.
 *
 *  librtmp is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with librtmp see the file COPYING.  If not, write to
 *  the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 *  Boston, MA  02110-1301, USA.
 *  http://www.gnu.org/copyleft/lgpl.html
 */

using System;
using System.Linq;

namespace librtmp
{
    /// <summary> struct AVal; </summary>
    public class AVal
    {
        /// <summary> char* av_val </summary>
        public byte[] av_val { get; set; }

        /// <summary> int av_len </summary>
        public int av_len { get; set; }

        /// <summary> AVMATCH(a1,a2) </summary>
        public static bool Match(AVal a1, AVal a2)
        {
            return a1.av_len == a2.av_len
                   && a1.av_val.SequenceEqual(a2.av_val);
        }

        /// <summary> #define AVC(str) {str,sizeof(str)-1} </summary>
        /// <param name="str"></param>
        /// <returns></returns>
        public static AVal AVC(string str)
        {
            return new AVal
            {
                av_len = str.Length,
                av_val = str.ToCharArray().Select(c => (byte)c).ToArray()
            };
        }

        public AVal()
            : this(new byte[0])
        {
        }

        public AVal(byte[] val)
        {
            av_val = val;
            av_len = val.Length;
        }

        /// <summary> toString </summary>
        /// <param name="len"></param>
        /// <returns></returns>
        public string to_s(int len = 0)
        {
            if (len == 0 || len > av_len)
            {
                len = av_len;
            }

            if (len > av_val.Length)
            {
                len = av_val.Length;
            }

            return new string(av_val.Select(b => (char)b).Take(len).ToArray());
        }

        /// <inheritdoc/>
        public override string ToString()
        {
            return string.Format("len:{0}, val({1}):[{2}]", av_len, av_val.Length, string.Join(",", av_val.Select(b => b.ToString("x02"))));
        }
    }
}