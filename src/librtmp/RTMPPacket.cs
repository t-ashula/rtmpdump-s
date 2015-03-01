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

namespace librtmp
{
    /// <summary> struct RTMPPacket </summary>
    public class RTMPPacket
    {
        /// <summary> #define RTMPPacket_IsReady(a)  ((a).m_nBytesRead == (a).m_nBodySize) </summary>
        public bool IsReady()
        {
            return BytesRead == BodySize;
        }

        /// <summary> void RTMPPacket_Free(RTMPPacket *p); </summary>
        public void Free()
        {
            throw new NotImplementedException();
        }

        /// <summary> uint8_t m_headerType </summary>
        public byte HeaderType { get; set; }

        /// <summary> uint8_t PacketType </summary>
        public byte PacketType { get; set; }

        /// <summary> uint8_t m_hasAbsTimestamp </summary>
        public bool HasAbsTimestamp { get; set; }

        /// <summary> int m_nChannnel </summary>
        public int ChannelNum { get; set; }

        /// <summary> uint32_t m_nTimeStamp </summary>
        public uint TimeStamp { get; set; }

        /// <summary> int32_t m_nInfoField2 </summary>
        public int InfoField2 { get; set; }

        /// <summary> uint32_t m_nBodySize </summary>
        public uint BodySize { get; set; }

        /// <summary> uint32_t m_nBytesRead </summary>
        public uint BytesRead { get; set; }

        /// <summary> RTMPChunk *m_chunk </summary>
        public RTMPChunk Chunk { get; set; }

        /// <summary> char *m_body </summary>
        public byte[] Body { get; set; }

        /*      RTMP_PACKET_TYPE_...                0x00 */
        public const byte RTMP_PACKET_TYPE_CHUNK_SIZE = 0x01;
        /*      RTMP_PACKET_TYPE_...                0x02 */
        public const byte RTMP_PACKET_TYPE_BYTES_READ_REPORT = 0x03;
        public const byte RTMP_PACKET_TYPE_CONTROL = 0x04;
        public const byte RTMP_PACKET_TYPE_SERVER_BW = 0x05;
        public const byte RTMP_PACKET_TYPE_CLIENT_BW = 0x06;
        /*      RTMP_PACKET_TYPE_...                0x07 */
        public const byte RTMP_PACKET_TYPE_AUDIO = 0x08;
        public const byte RTMP_PACKET_TYPE_VIDEO = 0x09;
        /*      RTMP_PACKET_TYPE_...                0x0A */
        /*      RTMP_PACKET_TYPE_...                0x0B */
        /*      RTMP_PACKET_TYPE_...                0x0C */
        /*      RTMP_PACKET_TYPE_...                0x0D */
        /*      RTMP_PACKET_TYPE_...                0x0E */
        public const byte RTMP_PACKET_TYPE_FLEX_STREAM_SEND = 0x0F;
        public const byte RTMP_PACKET_TYPE_FLEX_SHARED_OBJECT = 0x10;
        public const byte RTMP_PACKET_TYPE_FLEX_MESSAGE = 0x11;
        public const byte RTMP_PACKET_TYPE_INFO = 0x12;
        public const byte RTMP_PACKET_TYPE_SHARED_OBJECT = 0x13;
        public const byte RTMP_PACKET_TYPE_INVOKE = 0x14;
        /*      RTMP_PACKET_TYPE_...                0x15 */
        public const byte RTMP_PACKET_TYPE_FLASH_VIDEO = 0x16;

        // void RTMPPacket_Free(RTMPPacket *p)
        public static void RTMPPacket_Free(RTMPPacket p)
        {
            if (p.Body != null)
            {
                // free(p.m_body - RTMP_MAX_HEADER_SIZE);
                p.Body = null;
            }
        }

        public static bool RTMPPacket_Alloc(RTMPPacket p, int nsize)
        {
            p.Body = new byte[nsize + RTMP.RTMP_MAX_HEADER_SIZE];
            p.BytesRead = 0;
            return true;
        }
    }
}