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
using System.Security.Policy;

namespace librtmp
{
    /// <summary> typedef enum {} AMFDataType </summary>
    public enum AMFDataType
    {
        AMF_NUMBER = 0,
        AMF_BOOLEAN,
        AMF_STRING,
        AMF_OBJECT,
        AMF_MOVIECLIP, /* reserved, not used */
        AMF_NULL,
        AMF_UNDEFINED,
        AMF_REFERENCE,
        AMF_ECMA_ARRAY,
        AMF_OBJECT_END,
        AMF_STRICT_ARRAY,
        AMF_DATE,
        AMF_LONG_STRING,
        AMF_UNSUPPORTED,
        AMF_RECORDSET, /* reserved, not used */
        AMF_XML_DOC,
        AMF_TYPED_OBJECT,
        AMF_AVMPLUS, /* switch to AMF3 */
        AMF_INVALID = 0xff
    }

    /// <summary> typedef enum {} AMF3DataType </summary>
    public enum AMF3DataType
    {
        AMF3_UNDEFINED = 0,
        AMF3_NULL,
        AMF3_FALSE,
        AMF3_TRUE,
        AMF3_INTEGER,
        AMF3_DOUBLE,
        AMF3_STRING,
        AMF3_XML_DOC,
        AMF3_DATE,
        AMF3_ARRAY,
        AMF3_OBJECT,
        AMF3_XML,
        AMF3_BYTE_ARRAY
    }

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
                output = AMF_EncodeInt16(buf, output, outend, (short)str.av_len);
            }
            else
            {
                buf[output++] = (byte)AMFDataType.AMF_LONG_STRING;
                output = AMF_EncodeInt32(buf, output, outend, str.av_len);
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
        public static int AMF_EncodeInt16(byte[] buf, int output, int outend, short nval)
        {
            if (output + 2 > outend)
            {
                return 0;
            }

            buf[output + 1] = (byte)(nval & 0xff);
            buf[output + 0] = (byte)(nval >> 8);
            return output + 2;
        }

        /// <summary>  char *AMF_EncodeInt24(char *output, char *outend, int nVal);</summary>
        public static int AMF_EncodeInt24(byte[] buf, int output, int outend, int val)
        {
            if (output + 3 > outend)
            {
                return 0;
            }

            var ci = BitConverter.GetBytes(val);
            buf[output + 2] = ci[3];
            buf[output + 1] = ci[2];
            buf[output + 0] = ci[1];
            return output + 3;
        }

        /// <summary> char* AMF_EncodeInt32(char* output, char* outend, int nVal); </summary>
        public static int AMF_EncodeInt32(byte[] buf, int output, int outend, int val)
        {
            if (output + 4 > outend)
            {
                return 0;
            }

            var ci = BitConverter.GetBytes(val);
            buf[output + 3] = ci[3];
            buf[output + 2] = ci[2];
            buf[output + 1] = ci[1];
            buf[output + 0] = ci[0];
            return output + 4;
        }

        // char *AMF_EncodeBoolean(char *output, char *outend, int bVal);
        public static int AMF_EncodeBoolean(byte[] buf, int output, int outend, bool val)
        {
            if (output + 2 > outend)
            {
                return 0;
            }

            buf[output++] = (byte)(AMFDataType.AMF_BOOLEAN);
            buf[output++] = (byte)(val ? 0x01 : 0x00);
            return output;
        }

        /* Shortcuts for AMFProp_Encode */

        /// <summary> char *AMF_EncodeNamedString(char *output, char *outend, const AVal * name, const AVal * value);</summary>
        public static int AMF_EncodeNamedString(byte[] buf, int output, int outend, AVal name, AVal value)
        {
            if (output + 2 + name.av_len > outend)
            {
                return 0;
            }

            var ret = AMF_EncodeInt16(buf, output, outend, (short)name.av_len);
            output += ret;
            // memcpy(output, name.av_val, name.av_len);
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

            output = AMF_EncodeInt16(buf, output, outend, (short)name.av_len);

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

            output = AMF_EncodeInt16(buf, output, outend, (short)name.av_len);

            memcpy(buf, output, name.av_val, name.av_len);
            output += name.av_len;

            return AMF_EncodeBoolean(buf, output, outend, val);
        }

        /// <summary> unsigned short AMF_DecodeInt16(const char *data);</summary>
        public static ushort AMF_DecodeInt16(byte[] data, int offset = 0)
        {
            throw new NotImplementedException();
        }

        /// <summary> unsigned int AMF_DecodeInt24(const char *data);</summary>
        public static int AMF_DecodeInt24(byte[] data, int offset = 0)
        {
            throw new NotImplementedException();
        }

        /// <summary> unsigned int AMF_DecodeInt32(const char *data);</summary>
        public static uint AMF_DecodeInt32(byte[] data, int offset = 0)
        {
            throw new NotImplementedException();
        }

        // void AMF_DecodeString(const char *data, AVal * str);
        // void AMF_DecodeLongString(const char *data, AVal * str);
        // int AMF_DecodeBoolean(const char *data);
        // double AMF_DecodeNumber(const char *data);

        private static void memcpy(byte[] buf, int output, byte[] src, int len)
        {
            for (var i = 0; i < len; ++i)
            {
                buf[output + i] = src[i];
            }
        }
    }

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

    /// <summary> struct AMFObject </summary>
    public class AMFObject
    {
        /// <summary> int o_num </summary>
        public int o_num { get; set; }

        /// <summary> AMFObjectProperty o_props </summary>
        public AMFObjectProperty[] o_props { get; set; }

        // char* AMF_Encode(AMFObject* obj, char* pBuffer, char* pBufEnd);
        // char* AMF_EncodeEcmaArray(AMFObject* obj, char* pBuffer, char* pBufEnd);
        // char* AMF_EncodeArray(AMFObject* obj, char* pBuffer, char* pBufEnd);

        /// <summary> int AMF_Decode(AMFObject * obj, const char *pBuffer, int nSize, int bDecodeName); </summary>
        public static int AMF_Decode(AMFObject obj, byte[] buf, int nSize, bool bDecodeName)
        {
            throw new NotImplementedException();
        }

        /// <summary> int AMF_DecodeArray(AMFObject * obj, const char *pBuffer, int nSize,int nArrayLen, int bDecodeName); </summary>
        public static int AMF_DecodeArray(AMFObject obj, byte[] buffer, int nSize, int nArrayLen, int bDecodeName)
        {
            throw new NotImplementedException();
        }

        /// <summary> int AMF3_Decode(AMFObject * obj, const char *pBuffer, int nSize, int bDecodeName); </summary>
        public static int AMF3_Decode(AMFObject obj, byte[] buffer, int nSize, int bDecodeName)
        {
            throw new NotImplementedException();
        }

        /// <summary> void AMF_Dump(AMFObject* obj); </summary>
        public static void AMF_Dump(AMFObject obj)
        {
            throw new NotImplementedException();
        }

        /// <summary> void AMF_Reset(AMFObject * obj); </summary>
        public static void AMF_Reset(AMFObject obj)
        {
            throw new NotImplementedException();
        }

        /// <summary> void AMF_AddProp(AMFObject * obj, const AMFObjectProperty * prop); </summary>
        public static void AMF_AddProp(AMFObject obj, AMFObjectProperty prrop)
        {
            throw new NotImplementedException();
        }

        /// <summary> int AMF_CountProp(AMFObject * obj); </summary>
        public static int AMF_CountProp(AMFObject o)
        {
            throw new NotImplementedException();
        }

        /// <summary> AMFObjectProperty *AMF_GetProp(AMFObject * obj, const AVal * name, int nIndex); </summary>
        public static AMFObjectProperty AMF_GetProp(AMFObject obj, AVal name, int nIndex)
        {
            throw new NotImplementedException();
        }
    }

    /// <summary> struct AMFObjectProperty </summary>
    public class AMFObjectProperty
    {
        /// <summary> AVal p_name </summary>
        public AVal p_name { get; set; }

        /// <summary> AMFDataType p_type </summary>
        public AMFDataType p_type { get; set; }

        /// <summary> p_vu.p_number </summary>
        public double p_number { get; set; }

        /// <summary> p_vu.p_aval </summary>
        public AVal p_aval { get; set; }

        /// <summary> p_vu.p_object </summary>
        public AMFObject p_object { get; set; }

        /// <summary> int16_t p_UTCoffset </summary>
        public short p_UTCoffset { get; set; }

        /// <summary> AMFDataType AMFProp_GetType(AMFObjectProperty* prop); </summary>
        public static AMFDataType AFMProp_GetType(AMFObjectProperty p)
        {
            throw new NotImplementedException();
        }

        /// <summary> void AMFProp_SetNumber(AMFObjectProperty* prop, double dval); </summary>
        public static void AMFProp_SetNumber(AMFObjectProperty prop, double dval)
        {
            throw new NotImplementedException();
        }

        /// <summary> void AMFProp_SetBoolean(AMFObjectProperty* prop, int bflag); </summary>
        public static void AMFProp_SetBoolean(AMFObjectProperty prop, int bflag)
        {
            throw new NotImplementedException();
        }

        /// <summary> void AMFProp_SetString(AMFObjectProperty* prop, AVal* str); </summary>
        public static void AMFProp_SetString(AMFObjectProperty prop, AVal str)
        {
            throw new NotImplementedException();
        }

        // void AMFProp_SetObject(AMFObjectProperty* prop, AMFObject* obj); </summary>
        public static void AMFProp_SetObject(AMFObjectProperty prop, AMFObject obj)
        {
            throw new NotImplementedException();
        }

        /// <summary> void AMFProp_GetName(AMFObjectProperty* prop, AVal* name); </summary>
        public static void AMFProp_GetName(AMFObjectProperty prop, AVal name)
        {
            throw new NotImplementedException();
        }

        /// <summary> void AMFProp_SetName(AMFObjectProperty* prop, AVal* name); </summary>
        public static void AMFProp_SetName(AMFObjectProperty prop, AVal name)
        {
            throw new NotImplementedException();
        }

        /// <summary> double AMFProp_GetNumber(AMFObjectProperty* prop); </summary>
        public static double AMFProp_GetNumber(AMFObjectProperty prop)
        {
            throw new NotImplementedException();
        }

        /// <summary> int AMFProp_GetBoolean(AMFObjectProperty* prop); </summary>
        public static bool AMFProp_GetBoolean(AMFObjectProperty prop)
        {
            throw new NotImplementedException();
        }

        /// <summary> void AMFProp_GetString(AMFObjectProperty* prop, AVal* str); </summary>
        public static void AMFProp_GetString(AMFObjectProperty prop, out AVal str)
        {
            throw new NotImplementedException();
        }

        /// <summary> void AMFProp_GetObject(AMFObjectProperty* prop, AMFObject* obj); </summary>
        public static void AMFProp_GetObject(AMFObjectProperty prop, out AMFObject obj)
        {
            throw new NotImplementedException();
        }

        /// <summary> int AMFProp_IsValid(AMFObjectProperty* prop); </summary>
        public static int AMFProp_IsValid(AMFObjectProperty prop)
        {
            throw new NotImplementedException();
        }

        /// <summary>char * AMFProp_Encode(AMFObjectProperty *prop, char *pBuffer, char *pBufEnd)</summary>
        public static int AMFProp_Encode(AMFObjectProperty prop, byte[] buf, int offset, int pend)
        {
            throw new NotImplementedException();
        }
    }
}