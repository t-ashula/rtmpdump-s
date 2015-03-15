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
                    Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGERROR, "AMF_MOVIECLIP reserved!");
                    return -1;

                case AMFDataType.AMF_NULL:
                case AMFDataType.AMF_UNDEFINED:
                case AMFDataType.AMF_UNSUPPORTED:
                    prop.p_type = AMFDataType.AMF_NULL;
                    break;

                case AMFDataType.AMF_REFERENCE:
                    Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGERROR, "AMF_REFERENCE not supported!");
                    return -1;

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
            var strRes = string.Format("Name: {0,18}, ", name.to_s(18));

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