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
    /// <summary> for amf.c global functions </summary>
    public static class AMF
    {
        /// <summary> char *AMF_EncodeString(char *output, char *outend, const AVal * str);</summary>
        public static int AMF_EncodeString(byte[] buf, int output, int outend, AVal str)
        {
            if ((str.av_len < 65536 && output + 1 + 2 + str.av_len > outend) ||
                output + 1 + 4 + str.av_len > outend)
            {
                return 0;
            }

            if (str.av_len < 65536)
            {
                // *output++ = AMF_STRING;
                buf[output++] = (byte)AMFDataType.AMF_STRING;
                output = AMF_EncodeInt16(buf, output, outend, (ushort)str.av_len);
            }
            else
            {
                buf[output++] = (byte)AMFDataType.AMF_LONG_STRING;
                output = AMF_EncodeInt32(buf, output, outend, (uint)str.av_len);
            }

            memcpy(buf, output, str.av_val, str.av_len);

            output += str.av_len;
            return output;
        }

        /// <summary> char *AMF_EncodeNumber(char *output, char *outend, double dVal);</summary>
        public static int AMF_EncodeNumber(byte[] buf, int output, int outend, double val)
        {
            if (output + 1 + 8 > outend)
            {
                return 0;
            }

            buf[output++] = (byte)AMFDataType.AMF_NUMBER;
            var ci = BitConverter.GetBytes(val);
            for (var i = 0; i < 8; ++i)
            {
                buf[output + i] = ci[7 - i];
            }

            return output + 8;
        }

        /// <summary> char *AMF_EncodeInt16(char *output, char *outend, short nVal);</summary>
        public static int AMF_EncodeInt16(byte[] buf, int output, int outend, ushort nval)
        {
            if (output + 2 > outend)
            {
                return 0;
            }

            var ci = BitConverter.GetBytes(nval);
            buf[output + 1] = ci[0];
            buf[output + 0] = ci[1];
            return output + 2;
        }

        /// <summary>  char *AMF_EncodeInt24(char *output, char *outend, int nVal);</summary>
        public static int AMF_EncodeInt24(byte[] buf, int output, int outend, uint val)
        {
            if (output + 3 > outend)
            {
                return 0;
            }

            var ci = BitConverter.GetBytes(val);
            buf[output + 2] = ci[0];
            buf[output + 1] = ci[1];
            buf[output + 0] = ci[2];
            return output + 3;
        }

        /// <summary> char* AMF_EncodeInt32(char* output, char* outend, int nVal); </summary>
        public static int AMF_EncodeInt32(byte[] buf, int output, int outend, uint val)
        {
            if (output + 4 > outend)
            {
                return 0;
            }

            var ci = BitConverter.GetBytes(val);
            buf[output + 3] = ci[0];
            buf[output + 2] = ci[1];
            buf[output + 1] = ci[2];
            buf[output + 0] = ci[3];
            return output + 4;
        }

        // char *AMF_EncodeBoolean(char *output, char *outend, int bVal);
        public static int AMF_EncodeBoolean(byte[] buf, int output, int outend, bool val)
        {
            if (output + 2 > outend)
            {
                return 0;
            }

            buf[output + 0] = (byte)(AMFDataType.AMF_BOOLEAN);
            buf[output + 1] = (byte)(val ? 0x01 : 0x00);
            return output + 2;
        }

        /* Shortcuts for AMFProp_Encode */

        /// <summary> char *AMF_EncodeNamedString(char *output, char *outend, const AVal * name, const AVal * value);</summary>
        public static int AMF_EncodeNamedString(byte[] buf, int output, int outend, AVal name, AVal value)
        {
            if (output + 2 + name.av_len > outend)
            {
                return 0;
            }

            output = AMF_EncodeInt16(buf, output, outend, (ushort)name.av_len);
            memcpy(buf, output, name.av_val, name.av_len);
            output += name.av_len;

            return AMF_EncodeString(buf, output, outend, value);
        }

        /// <summary> char *AMF_EncodeNamedNumber(char *output, char *outend, const AVal * name, double dVal);</summary>
        public static int AMF_EncodeNamedNumber(byte[] buf, int output, int outend, AVal name, double val)
        {
            if (output + 2 + name.av_len > outend)
            {
                return 0;
            }

            output = AMF_EncodeInt16(buf, output, outend, (ushort)name.av_len);

            memcpy(buf, output, name.av_val, name.av_len);
            output += name.av_len;

            return AMF_EncodeNumber(buf, output, outend, val);
        }

        /// <summary> char *AMF_EncodeNamedBoolean(char *output, char *outend, const AVal * name, int bVal);</summary>
        public static int AMF_EncodeNamedBoolean(byte[] buf, int output, int outend, AVal name, bool val)
        {
            if (output + 2 + name.av_len > outend)
            {
                return 0;
            }

            output = AMF_EncodeInt16(buf, output, outend, (ushort)name.av_len);

            memcpy(buf, output, name.av_val, name.av_len);
            output += name.av_len;

            return AMF_EncodeBoolean(buf, output, outend, val);
        }

        /// <summary> unsigned short AMF_DecodeInt16(const char *data);</summary>
        public static ushort AMF_DecodeInt16(byte[] data, int offset = 0)
        {
            return (ushort)((data[offset] << 8) | data[offset + 1]);
        }

        /// <summary> unsigned int AMF_DecodeInt24(const char *data);</summary>
        public static uint AMF_DecodeInt24(byte[] data, int offset = 0)
        {
            return (uint)((data[offset] << 16) | (data[offset + 1] << 8) | data[offset + 2]);
        }

        /// <summary> unsigned int AMF_DecodeInt32(const char *data);</summary>
        public static uint AMF_DecodeInt32(byte[] data, int offset = 0)
        {
            return (uint)((data[offset] << 24) | (data[offset + 1] << 16) | (data[offset + 2] << 8) | data[offset + 3]);
        }

        /// <summary> void AMF_DecodeString(const char *data, AVal * str);</summary>
        public static void AMF_DecodeString(byte[] buf, int offset, out AVal str)
        {
            var len = AMF_DecodeInt16(buf, offset);
            var data = new byte[len];
            Array.Copy(buf, offset + 2, data, 0, len);
            str = new AVal(data);
        }

        /// <summary> void AMF_DecodeLongString(const char *data, AVal * str);</summary>
        public static void AMF_DecodeLongString(byte[] buf, int offset, out AVal str)
        {
            var len = AMF_DecodeInt32(buf, offset);
            var data = new byte[len];
            Array.Copy(buf, offset + 4, data, 0, len);
            str = new AVal(data);
        }

        /// <summary> int AMF_DecodeBoolean(const char *data); </summary>
        public static bool AMF_DecodeBoolean(byte[] buf, int data)
        {
            return buf[data] != 0;
        }

        /// <summary> double AMF_DecodeNumber(const char *data);</summary>
        public static double AMF_DecodeNumber(byte[] buf, int offset = 0)
        {
            var d = buf.Skip(offset).Take(8).Reverse().ToArray();
            return BitConverter.ToDouble(d, 0);
        }

        /// <summary>
        /// memcpy; copy (src[0], src[len-1]) to (buf[output],buf[output+len-1])
        /// </summary>
        /// <param name="buf">destination</param>
        /// <param name="output">destination</param>
        /// <param name="src">source</param>
        /// <param name="len">length</param>
        public static void memcpy(byte[] buf, int output, byte[] src, int len)
        {
            // Array.ConstrainedCopy(src, 0, buf, output, len);
            Array.Copy(src, 0, buf, output, len);
        }
    }
}