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
using System.Collections.Generic;
using System.Linq;

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
        public List<AMFObjectProperty> o_props { get; set; }

        // char* AMF_Encode(AMFObject* obj, char* pBuffer, char* pBufEnd);
        // char* AMF_EncodeEcmaArray(AMFObject* obj, char* pBuffer, char* pBufEnd);
        // char* AMF_EncodeArray(AMFObject* obj, char* pBuffer, char* pBufEnd);

        /// <summary> int AMF_Decode(AMFObject * obj, const char *pBuffer, int nSize, int bDecodeName); </summary>
        public static int AMF_Decode(AMFObject obj, byte[] buf, int pbuf, int nSize, bool bDecodeName)
        {
            int nOriginalSize = nSize;
            bool bError = false; /* if there is an error while decoding - try to at least find the end mark AMF_OBJECT_END */

            obj.o_num = 0;
            obj.o_props = null;
            while (nSize > 0)
            {
                if (nSize >= 3)
                {
                    if (AMF.AMF_DecodeInt24(buf, pbuf) == (uint)AMFDataType.AMF_OBJECT_END)
                    {
                        nSize -= 3;
                        bError = false;
                        break;
                    }
                }

                if (bError)
                {
                    Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGERROR, "DECODING ERROR, IGNORING BYTES UNTIL NEXT KNOWN PATTERN!");
                    nSize--;
                    pbuf++;
                    continue;
                }

                AMFObjectProperty prop = new AMFObjectProperty();
                int nRes = AMFObjectProperty.AMFProp_Decode(prop, buf, pbuf, nSize, bDecodeName);
                if (nRes == -1)
                {
                    bError = true;
                }
                else
                {
                    nSize -= nRes;
                    pbuf += nRes;
                    AMF_AddProp(obj, prop);
                }
            }

            if (bError)
            {
                return -1;
            }

            return nOriginalSize - nSize;
        }

        /// <summary> int AMF_DecodeArray(AMFObject * obj, const char *pBuffer, int nSize,int nArrayLen, int bDecodeName); </summary>
        public static int AMF_DecodeArray(AMFObject obj, byte[] buf, int pBuffer, int nSize, int nArrayLen, bool bDecodeName)
        {
            throw new NotImplementedException();
        }

        /// <summary> int AMF3_Decode(AMFObject * obj, const char *pBuffer, int nSize, int bDecodeName); </summary>
        public static int AMF3_Decode(AMFObject obj, byte[] buffer, int pBuffer, int nSize, bool bDecodeName)
        {
            throw new NotImplementedException();
        }

        /// <summary> void AMF_Dump(AMFObject* obj); </summary>
        public static void AMF_Dump(AMFObject obj)
        {
            Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "(object begin)");
            for (var n = 0; n < obj.o_num; n++)
            {
                AMFObjectProperty.AMFProp_Dump(obj.o_props[n]);
            }

            Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "(object end)");
        }

        /// <summary> void AMF_Reset(AMFObject * obj); </summary>
        public static void AMF_Reset(AMFObject obj)
        {
            for (var n = 0; n < obj.o_num; n++)
            {
                AMFObjectProperty.AMFProp_Reset(obj.o_props[n]);
            }

            // free(obj.o_props);
            obj.o_props = new List<AMFObjectProperty>();
            obj.o_num = 0;
        }

        /// <summary> void AMF_AddProp(AMFObject * obj, const AMFObjectProperty * prop); </summary>
        public static void AMF_AddProp(AMFObject obj, AMFObjectProperty prop)
        {
            if (obj.o_props == null)
            {
                obj.o_props = new List<AMFObjectProperty>();
            }

            obj.o_props.Add(prop);
            obj.o_num++;
        }

        /// <summary> int AMF_CountProp(AMFObject * obj); </summary>
        public static int AMF_CountProp(AMFObject o)
        {
            throw new NotImplementedException();
        }

        /// <summary> AMFObjectProperty *AMF_GetProp(AMFObject * obj, const AVal * name, int nIndex); </summary>
        public static AMFObjectProperty AMF_GetProp(AMFObject obj, AVal name, int nIndex)
        {
            if (nIndex >= 0)
            {
                if (nIndex < obj.o_num)
                {
                    return obj.o_props[nIndex];
                }
            }
            else
            {
                for (var n = 0; n < obj.o_num; n++)
                {
                    if (AVal.Match(obj.o_props[n].p_name, name))
                    {
                        return obj.o_props[n];
                    }
                }
            }

            // return (AMFObjectProperty*)&AMFProp_Invalid;
            return AMFObjectProperty.AMFProp_Invalid;
        }
    }

    /// <summary> struct AMFObjectProperty </summary>
    public class AMFObjectProperty
    {
        public static readonly AMFObjectProperty AMFProp_Invalid = new AMFObjectProperty { p_type = AMFDataType.AMF_INVALID };

        public AMFObjectProperty()
        {
            p_name = new AVal();
            p_aval = new AVal();
            p_object = new AMFObject();
        }

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

        /// <summary> void AMFProp_SetObject(AMFObjectProperty* prop, AMFObject* obj); </summary>
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
            return prop.p_number;
        }

        /// <summary> int AMFProp_GetBoolean(AMFObjectProperty* prop); </summary>
        public static bool AMFProp_GetBoolean(AMFObjectProperty prop)
        {
            return prop.p_number > 0 || prop.p_number < 0;
        }

        /// <summary> void AMFProp_GetString(AMFObjectProperty* prop, AVal* str); </summary>
        public static void AMFProp_GetString(AMFObjectProperty prop, out AVal str)
        {
            str = prop.p_aval;
        }

        /// <summary> void AMFProp_GetObject(AMFObjectProperty* prop, AMFObject* obj); </summary>
        public static void AMFProp_GetObject(AMFObjectProperty prop, out AMFObject obj)
        {
            obj = prop.p_object;
        }

        /// <summary> int AMFProp_IsValid(AMFObjectProperty* prop); </summary>
        public static bool AMFProp_IsValid(AMFObjectProperty prop)
        {
            return prop.p_type != AMFDataType.AMF_INVALID;
        }

        /// <summary> char * AMFProp_Encode(AMFObjectProperty *prop, char *pBuffer, char *pBufEnd)</summary>
        public static int AMFProp_Encode(AMFObjectProperty prop, byte[] buf, int offset, int pend)
        {
            throw new NotImplementedException();
        }

        /// <summary> int AMFProp_Decode(AMFObjectProperty *prop, const char *pBuffer, int nSize, int bDecodeName)</summary>
        public static int AMFProp_Decode(AMFObjectProperty prop, byte[] buf, int pBuffer, int nSize, bool bDecodeName)
        {
            const string __FUNCTION__ = "AMFProp_Decode";
            int nOriginalSize = nSize;

            prop.p_name = new AVal();

            if (nSize == 0 || pBuffer > buf.Length)
            {
                Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "{0}: Empty buffer/no buffer pointer!", __FUNCTION__);
                return -1;
            }

            if (bDecodeName && nSize < 4)
            {
                /* at least name (length + at least 1 byte) and 1 byte of data */
                Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "{0}: Not enough data for decoding with name, less than 4 bytes!", __FUNCTION__);
                return -1;
            }

            if (bDecodeName)
            {
                var nNameSize = AMF.AMF_DecodeInt16(buf, pBuffer);
                if (nNameSize > nSize - 2)
                {
                    Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG,
                        "{0}: Name size out of range: namesize ({1}) > len ({2}) - 2",
                        __FUNCTION__, nNameSize, nSize);
                    return -1;
                }

                AVal name;
                AMF.AMF_DecodeString(buf, pBuffer, out name);
                prop.p_name = name;
                nSize -= 2 + nNameSize;
                pBuffer += 2 + nNameSize;
            }

            if (nSize == 0)
            {
                return -1;
            }

            nSize--;

            prop.p_type = (AMFDataType)buf[pBuffer++]; // *pBuffer++;
            switch (prop.p_type)
            {
                case AMFDataType.AMF_NUMBER:
                    if (nSize < 8)
                    {
                        return -1;
                    }

                    prop.p_number = AMF.AMF_DecodeNumber(buf, pBuffer);
                    nSize -= 8;
                    break;

                case AMFDataType.AMF_BOOLEAN:
                    if (nSize < 1)
                    {
                        return -1;
                    }

                    prop.p_number = AMF.AMF_DecodeBoolean(buf, pBuffer) ? 1 : 0;
                    nSize--;
                    break;

                case AMFDataType.AMF_STRING:
                    {
                        var nStringSize = AMF.AMF_DecodeInt16(buf, pBuffer);

                        if (nSize < (long)nStringSize + 2)
                        {
                            return -1;
                        }

                        AVal v;
                        AMF.AMF_DecodeString(buf, pBuffer, out v);
                        prop.p_aval = v;
                        nSize -= (2 + nStringSize);
                        break;
                    }
                case AMFDataType.AMF_OBJECT:
                    {
                        int nRes = AMFObject.AMF_Decode(prop.p_object, buf, pBuffer, nSize, true);
                        if (nRes == -1)
                        {
                            return -1;
                        }

                        nSize -= nRes;
                        break;
                    }
                case AMFDataType.AMF_MOVIECLIP:
                    {
                        Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGERROR, "AMF_MOVIECLIP reserved!");
                        return -1;
                        break;
                    }

                case AMFDataType.AMF_NULL:
                case AMFDataType.AMF_UNDEFINED:
                case AMFDataType.AMF_UNSUPPORTED:
                    prop.p_type = AMFDataType.AMF_NULL;
                    break;

                case AMFDataType.AMF_REFERENCE:
                    {
                        Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGERROR, "AMF_REFERENCE not supported!");
                        return -1;
                    }
                case AMFDataType.AMF_ECMA_ARRAY:
                    {
                        nSize -= 4;

                        /* next comes the rest, mixed array has a final 0x000009 mark and names, so its an object */
                        var nRes = AMFObject.AMF_Decode(prop.p_object, buf, pBuffer + 4, nSize, true);
                        if (nRes == -1)
                        {
                            return -1;
                        }

                        nSize -= nRes;
                    }
                    break;

                case AMFDataType.AMF_OBJECT_END:
                    return -1;

                case AMFDataType.AMF_STRICT_ARRAY:
                    {
                        var nArrayLen = AMF.AMF_DecodeInt32(buf, pBuffer);
                        nSize -= 4;

                        var nRes = AMFObject.AMF_DecodeArray(prop.p_object, buf, pBuffer + 4, nSize, (int)nArrayLen, false);
                        if (nRes == -1)
                        {
                            return -1;
                        }

                        nSize -= nRes;
                    }
                    break;

                case AMFDataType.AMF_DATE:
                    {
                        Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "AMF_DATE");

                        if (nSize < 10)
                        {
                            return -1;
                        }

                        prop.p_number = AMF.AMF_DecodeNumber(buf, pBuffer);
                        prop.p_UTCoffset = (short)AMF.AMF_DecodeInt16(buf, pBuffer + 8);

                        nSize -= 10;
                        break;
                    }

                case AMFDataType.AMF_LONG_STRING:
                case AMFDataType.AMF_XML_DOC:
                    {
                        var nStringSize = AMF.AMF_DecodeInt32(buf, pBuffer);
                        if (nSize < (long)nStringSize + 4)
                        {
                            return -1;
                        }

                        AVal v;
                        AMF.AMF_DecodeLongString(buf, pBuffer, out v);
                        prop.p_aval = v;
                        nSize -= (int)(4 + nStringSize);
                        if (prop.p_type == AMFDataType.AMF_LONG_STRING)
                        {
                            prop.p_type = AMFDataType.AMF_STRING;
                        }

                        break;
                    }
                case AMFDataType.AMF_RECORDSET:
                    Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGERROR, "AMF_RECORDSET reserved!");
                    return -1;

                case AMFDataType.AMF_TYPED_OBJECT:
                    Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGERROR, "AMF_TYPED_OBJECT not supported!");
                    return -1;

                case AMFDataType.AMF_AVMPLUS:
                    {
                        var nRes = AMFObject.AMF3_Decode(prop.p_object, buf, pBuffer, nSize, true);
                        if (nRes == -1)
                        {
                            return -1;
                        }
                        nSize -= nRes;
                        prop.p_type = AMFDataType.AMF_OBJECT;
                        break;
                    }
                default:
                    Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "{0} - unknown datatype 0x{1:x2}, @{2}", __FUNCTION__, prop.p_type, pBuffer - 1);
                    return -1;
            }

            return nOriginalSize - nSize;
        }

        /// <summary> void AMFProp_Dump(AMFObjectProperty *prop) </summary>
        public static void AMFProp_Dump(AMFObjectProperty prop)
        {
            if (prop.p_type == AMFDataType.AMF_INVALID)
            {
                Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "Property: INVALID");
                return;
            }

            if (prop.p_type == AMFDataType.AMF_NULL)
            {
                Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "Property: NULL");
                return;
            }

            var name = prop.p_name.av_len != 0 ? prop.p_name : AVal.AVC("no-name.");

            if (name.av_len > 18)
            {
                name.av_len = 18;
            }

            // snprintf(strRes, 255, "Name: %18.*s, ", name.av_len, name.av_val);
            var strRes = string.Format("Name: {0,-18}, ", name.to_s(18));

            if (prop.p_type == AMFDataType.AMF_OBJECT)
            {
                Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "Property: <{0}OBJECT>", strRes);
                AMFObject.AMF_Dump(prop.p_object);
                return;
            }

            if (prop.p_type == AMFDataType.AMF_ECMA_ARRAY)
            {
                Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "Property: <{0}ECMA_ARRAY>", strRes);
                AMFObject.AMF_Dump(prop.p_object);
                return;
            }

            if (prop.p_type == AMFDataType.AMF_STRICT_ARRAY)
            {
                Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "Property: <{0}STRICT_ARRAY>", strRes);
                AMFObject.AMF_Dump(prop.p_object);
                return;
            }

            string str;
            switch (prop.p_type)
            {
                case AMFDataType.AMF_NUMBER:
                    // snprintf(str, 255, "NUMBER:\t%.2f", prop.p_vu.p_number);
                    str = string.Format("NUMBER:\t{0:F2}", prop.p_number);
                    break;

                case AMFDataType.AMF_BOOLEAN:
                    // snprintf(str, 255, "BOOLEAN:\t%s", prop.p_vu.p_number != 0.0 ? "TRUE" : "FALSE");
                    str = string.Format("BOOLEAN:\t{0}", prop.p_number != 0.0 ? "TRUE" : "FALSE");
                    break;

                case AMFDataType.AMF_STRING:
                    // snprintf(str, 255, "STRING:\t%.*s", prop.p_vu.p_aval.av_len, prop.p_vu.p_aval.av_val);
                    str = string.Format("STRING:\t{0}", prop.p_aval.to_s());
                    break;

                case AMFDataType.AMF_DATE:
                    // snprintf(str, 255, "DATE:\ttimestamp: %.2f, UTC offset: %d", prop.p_vu.p_number, prop.p_UTCoffset);
                    str = string.Format("DATE:\ttimestamp: {0:F2}, UTC offset: {1}", prop.p_number, prop.p_UTCoffset);
                    break;

                default:
                    // snprintf(str, 255, "INVALID TYPE 0x%02x", (unsigned char )prop.p_type);
                    str = string.Format("INVALID TYPE 0x{0:x2}", prop.p_type);
                    break;
            }

            Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "Property: <{0}{1}>", strRes, str);
        }

        /// <summary> void AMFProp_Reset(AMFObjectProperty* prop) </summary>
        public static void AMFProp_Reset(AMFObjectProperty prop)
        {
            if (prop.p_type == AMFDataType.AMF_OBJECT
                || prop.p_type == AMFDataType.AMF_ECMA_ARRAY
                || prop.p_type == AMFDataType.AMF_STRICT_ARRAY)
            {
                AMFObject.AMF_Reset(prop.p_object);
            }
            else
            {
                prop.p_aval = null;
            }

            prop.p_type = AMFDataType.AMF_INVALID;
        }
    }
}