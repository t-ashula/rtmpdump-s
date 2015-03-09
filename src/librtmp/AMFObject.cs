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
using System.Collections.Generic;

namespace librtmp
{
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
            int nOriginalSize = nSize;
            bool bError = false;

            obj.o_num = 0;
            obj.o_props = null;
            while (nArrayLen > 0)
            {
                AMFObjectProperty prop = new AMFObjectProperty();

                nArrayLen--;

                int nRes = AMFObjectProperty.AMFProp_Decode(prop, buf, pBuffer, nSize, bDecodeName);
                if (nRes == -1)
                {
                    bError = true;
                }
                else
                {
                    nSize -= nRes;
                    pBuffer += nRes;
                    AMF_AddProp(obj, prop);
                }
            }

            if (bError)
                return -1;

            return nOriginalSize - nSize;
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
}