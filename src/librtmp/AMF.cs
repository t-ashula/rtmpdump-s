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
    }
}