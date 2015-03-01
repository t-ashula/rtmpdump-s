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
    /// <summary>
    /// struct RTMP_LNK
    /// </summary>
    public class RTMP_LNK
    {
        /// <summary> AVal hostname </summary>
        public AVal hostname { get; set; }

        /// <summary> AVal sockshost </summary>
        public AVal sockshost { get; set; }

        /// <summary> AVal playpath0 </summary>
        public AVal playpath0 { get; set; } /* parsed from URL */

        /// <summary> AVal playpath </summary>
        public AVal playpath { get; set; } /* passed in explicitly */

        /// <summary> Aval tcUrl </summary>
        public AVal tcUrl { get; set; }

        /// <summary> AVal swfUrl </summary>
        public AVal swfUrl { get; set; }

        /// <summary> AVal pageUrl </summary>
        public AVal pageUrl { get; set; }

        /// <summary> AVal app </summary>
        public AVal app { get; set; }

        /// <summary> AVal auth </summary>
        public AVal auth { get; set; }

        /// <summary> AVal flashVer </summary>
        public AVal flashVer { get; set; }

        /// <summary> AVal subscribepath </summary>
        public AVal subscribepath { get; set; }

        /// <summary> AVal usherToken </summary>
        public AVal usherToken { get; set; }

        /// <summary> AVal token </summary>
        public AVal token { get; set; }

        /// <summary> AVal pubUser </summary>
        public AVal pubUser { get; set; }

        /// <summary> AVal pubPasswd </summary>
        public AVal pubPasswd { get; set; }

        /// <summary> AMFObject extras </summary>
        public AMFObject extras { get; set; }

        /// <summary> int edepth </summary>
        public int edepth { get; set; }

        /// <summary> int seekTime </summary>
        public int seekTime { get; set; }

        /// <summary> int stopTime </summary>
        public int stopTime { get; set; }

        /// <summary> RTMP_LF_XXXX </summary>
        [Flags]
        public enum RTMP_LNK_FLAG
        {
            RTMP_LF_AUTH = 0x0001, /* using auth param */
            RTMP_LF_LIVE = 0x0002, /* stream is live */
            RTMP_LF_SWFV = 0x0004, /* do SWF verification */
            RTMP_LF_PLST = 0x0008, /* send playlist before play */
            RTMP_LF_BUFX = 0x0010, /* toggle stream on BufferEmpty msg */
            RTMP_LF_FTCU = 0x0020, /* free tcUrl on close */
            RTMP_LF_FAPU = 0x0040 /* free app on close */
        }

        /// <summary> int lFlags </summary>
        public RTMP_LNK_FLAG lFlags { get; set; }

        /// <summary> int swfAge </summary>
        public int swfAge { get; set; }

        /// <summary> int protocol </summary>
        public int protocol { get; set; }

        /// <summary> int timeout </summary>
        public int timeout { get; set; } /* connection timeout in seconds */

        /// <summary> int pFlags </summary>
        public int pFlags { get; set; } /* unused, but kept to avoid breaking ABI */

        /// <summary> unsigned short socksport; </summary>
        public ushort socksport { get; set; }

        /// <summary> unsigned short port; </summary>
        public ushort port { get; set; }

        #region CRYPTO

        // #ifdef CRYPTO

        /// <summary> #define RTMP_SWF_HASHLEN	32 </summary>
        public const int RTMP_SWF_HASHLEN = 32;

        /// <summary> void *dh;			/* for encryption */ </summary>
        public object dh { get; set; }

        /// <summary> void *rc4keyIn; </summary>
        public object rc4KeyIn { get; set; }

        /// <summary> void *rc4keyOut; </summary>
        public object rc4KeyOut { get; set; }

        /// <summary> uint32_t SWFSize; </summary>
        public uint SWFSize { get; set; }

        /// <summary> uint8_t SWFHash[RTMP_SWF_HASHLEN]; </summary>
        public byte[] SWFHash { get; set; }

        /// <summary> char SWFVerificationResponse[RTMP_SWF_HASHLEN+10]; </summary>
        public byte[] SWFVerificationResponse { get; set; }

        // #endif

        #endregion
    }
}