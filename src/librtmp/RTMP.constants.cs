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

// rtmp.c constants

using System;
using System.Collections.Generic;
using System.Linq;

namespace librtmp
{
    public partial class RTMP
    {
        public const int RTMP_FEATURE_HTTP = 0x01;
        public const int RTMP_FEATURE_ENC = 0x02;
        public const int RTMP_FEATURE_SSL = 0x04;
        public const int RTMP_FEATURE_MFP = 0x08; /* not yet supported */
        public const int RTMP_FEATURE_WRITE = 0x10; /* publish, not play */
        public const int RTMP_FEATURE_HTTP2 = 0x20; /* server-side rtmpt */

        public const int RTMP_PROTOCOL_UNDEFINED = -1;
        public const int RTMP_PROTOCOL_RTMP = 0;
        public const int RTMP_PROTOCOL_RTMPE = RTMP_FEATURE_ENC;
        public const int RTMP_PROTOCOL_RTMPT = RTMP_FEATURE_HTTP;
        public const int RTMP_PROTOCOL_RTMPS = RTMP_FEATURE_SSL;
        public const int RTMP_PROTOCOL_RTMPTE = (RTMP_FEATURE_HTTP | RTMP_FEATURE_ENC);
        public const int RTMP_PROTOCOL_RTMPTS = (RTMP_FEATURE_HTTP | RTMP_FEATURE_SSL);
        public const int RTMP_PROTOCOL_RTMFP = RTMP_FEATURE_MFP;

        public const int RTMP_DEFAULT_CHUNKSIZE = 128;

        public const int RTMP_BUFFER_CACHE_SIZE = 16 * 1024;

        public const int RTMP_CHANNELS = 65600;

        /// <summary> #define RTMP_SIG_SIZE 1536 </summary>
        private const int RTMP_SIG_SIZE = 1536;

        /*      RTMP_PACKET_TYPE_...                0x00 */
        public const int RTMP_PACKET_TYPE_CHUNK_SIZE = 0x01;
        /*      RTMP_PACKET_TYPE_...                0x02 */
        public const int RTMP_PACKET_TYPE_BYTES_READ_REPORT = 0x03;
        public const int RTMP_PACKET_TYPE_CONTROL = 0x04;
        public const int RTMP_PACKET_TYPE_SERVER_BW = 0x05;
        public const int RTMP_PACKET_TYPE_CLIENT_BW = 0x06;
        /*      RTMP_PACKET_TYPE_...                0x07 */
        public const int RTMP_PACKET_TYPE_AUDIO = 0x08;
        public const int RTMP_PACKET_TYPE_VIDEO = 0x09;
        /*      RTMP_PACKET_TYPE_...                0x0A */
        /*      RTMP_PACKET_TYPE_...                0x0B */
        /*      RTMP_PACKET_TYPE_...                0x0C */
        /*      RTMP_PACKET_TYPE_...                0x0D */
        /*      RTMP_PACKET_TYPE_...                0x0E */
        public const int RTMP_PACKET_TYPE_FLEX_STREAM_SEND = 0x0F;
        public const int RTMP_PACKET_TYPE_FLEX_SHARED_OBJECT = 0x10;
        public const int RTMP_PACKET_TYPE_FLEX_MESSAGE = 0x11;
        public const int RTMP_PACKET_TYPE_INFO = 0x12;
        public const int RTMP_PACKET_TYPE_SHARED_OBJECT = 0x13;
        public const int RTMP_PACKET_TYPE_INVOKE = 0x14;
        /*      RTMP_PACKET_TYPE_...                0x15 */
        public const int RTMP_PACKET_TYPE_FLASH_VIDEO = 0x16;

        /// <summary> #define RTMP_LARGE_HEADER_SIZE 12 </summary>
        private const int RTMP_LARGE_HEADER_SIZE = 12;

        /// <summary> #define RTMP_MAX_HEADER_SIZE 18</summary>
        public const int RTMP_MAX_HEADER_SIZE = 18;

        /// <summary> #define RTMP_PACKET_SIZE_LARGE    0</summary>
        public const int RTMP_PACKET_SIZE_LARGE = 0;

        /// <summary> #define RTMP_PACKET_SIZE_MEDIUM   1</summary>
        public const int RTMP_PACKET_SIZE_MEDIUM = 1;

        /// <summary> #define RTMP_PACKET_SIZE_SMALL    2</summary>
        public const int RTMP_PACKET_SIZE_SMALL = 2;

        /// <summary> #define RTMP_PACKET_SIZE_MINIMUM  3</summary>
        public const int RTMP_PACKET_SIZE_MINIMUM = 3;

        /// <summary> const char RTMPProtocolStrings[][7]  </summary>
        private static readonly string[] RTMPProtocolStrings =
        {
            "RTMP", "RTMPT", "RTMPE", "RTMPTE", "RTMPS", "RTMPTS", "", "", "RTMFP"
        };

        /// <summary> const char RTMPProtocolStrings[][7]  </summary>
        public static readonly string[] RTMPProtocolStringsLower =
        {
            "rtmp", "rtmpt", "rtmpe", "rtmpte", "rtmps", "rtmpts", "", "", "rtmfp"
        };

        /// <summary>packetSize = { 12, 8, 4, 1 } </summary>
        private static readonly int[] packetSize = { 12, 8, 4, 1 };

        /// <summary> const AVal RTMP_DefaultFlashVer </summary>
        /// <remarks>TODO: OSS( WIN/SOL/MAC/LNX/GNU) </remarks>
        public static readonly AVal RTMP_DefaultFlashVer = AVal.AVC("WIN 10,0,32,18");

        private static readonly AVal av_app = AVal.AVC("app");
        private static readonly AVal av_connect = AVal.AVC("connect");
        private static readonly AVal av_flashVer = AVal.AVC("flashVer");
        private static readonly AVal av_swfUrl = AVal.AVC("swfUrl)");
        private static readonly AVal av_pageUrl = AVal.AVC("pageUrl");
        private static readonly AVal av_tcUrl = AVal.AVC("tcUrl");
        private static readonly AVal av_fpad = AVal.AVC("fpad");
        private static readonly AVal av_capabilities = AVal.AVC("capabilities");
        private static readonly AVal av_audioCodecs = AVal.AVC("audioCodecs");
        private static readonly AVal av_videoCodecs = AVal.AVC("videoCodecs");
        private static readonly AVal av_videoFunction = AVal.AVC("videoFunction");
        private static readonly AVal av_objectEncoding = AVal.AVC("objectEncoding");
        private static readonly AVal av_secureToken = AVal.AVC("secureToken");
        private static readonly AVal av_secureTokenResponse = AVal.AVC("secureTokenResponse");
        private static readonly AVal av_type = AVal.AVC("type");
        private static readonly AVal av_nonprivate = AVal.AVC("nonprivate");
        private static readonly AVal av_FCUnpublish = AVal.AVC("FCUnpublish");
        private static readonly AVal av_deleteStream = AVal.AVC("deleteStream");
        private static readonly AVal av__result = AVal.AVC("_result");
        private static readonly AVal av_createStream = AVal.AVC("createStream");
        private static readonly AVal av_releaseStream = AVal.AVC("releaseStream");
        private static readonly AVal av_play = AVal.AVC("play");
        private static readonly AVal av_live = AVal.AVC("live");
        private static readonly AVal av_pause = AVal.AVC("pause");

        private static readonly AVal av_0 = AVal.AVC("0");
        private static readonly AVal av_publish = AVal.AVC("publish");
        private static readonly AVal av_onBWDone = AVal.AVC("onBWDone");
        private static readonly AVal av_onFCSubscribe = AVal.AVC("onFCSubscribe");
        private static readonly AVal av_onFCUnsubscribe = AVal.AVC("onFCUnsubscribe");

        private static readonly AVal av_FCPublish = AVal.AVC("FCPublish");
        private static readonly AVal av_FCSubscribe = AVal.AVC("FCSubscribe");

        private static readonly AVal av_ping = AVal.AVC("ping");
        private static readonly AVal av_pong = AVal.AVC("pong");
        private static readonly AVal av__onbwcheck = AVal.AVC("_onbwcheck");
        private static readonly AVal av__onbwdone = AVal.AVC("_onbwdone");
        private static readonly AVal av__error = AVal.AVC("_error");
        private static readonly AVal av_close = AVal.AVC("close");
        private static readonly AVal av_onStatus = AVal.AVC("onStatus");
        private static readonly AVal av_code = AVal.AVC("code");
        private static readonly AVal av_level = AVal.AVC("level");
        private static readonly AVal av_set_playlist = AVal.AVC("set_playlist");

        private static readonly AVal av_description = AVal.AVC("description");
        private static readonly AVal av_playlist_ready = AVal.AVC("playlist_ready");
        private static readonly AVal av_NetStream_Failed = AVal.AVC("NetStream.Failed");
        private static readonly AVal av_NetStream_Play_Failed = AVal.AVC("NetStream.Play.Failed");
        private static readonly AVal av_NetStream_Play_StreamNotFound = AVal.AVC("NetStream.Play.StreamNotFound");
        private static readonly AVal av_NetConnection_Connect_InvalidApp = AVal.AVC("NetConnection.Connect.InvalidApp");
        private static readonly AVal av_NetStream_Play_Start = AVal.AVC("NetStream.Play.Start");
        private static readonly AVal av_NetStream_Play_Complete = AVal.AVC("NetStream.Play.Complete");
        private static readonly AVal av_NetStream_Play_Stop = AVal.AVC("NetStream.Play.Stop");
        private static readonly AVal av_NetStream_Seek_Notify = AVal.AVC("NetStream.Seek.Notify");
        private static readonly AVal av_NetStream_Pause_Notify = AVal.AVC("NetStream.Pause.Notify");
        private static readonly AVal av_NetStream_Play_PublishNotify = AVal.AVC("NetStream.Play.PublishNotify");
        private static readonly AVal av_NetStream_Play_UnpublishNotify = AVal.AVC("NetStream.Play.UnpublishNotify");
        private static readonly AVal av_NetStream_Publish_Start = AVal.AVC("NetStream.Publish.Start");
        private static readonly AVal av_NetConnection_Connect_Rejected = AVal.AVC("NetConnection.Connect.Rejected");

        /* Justin.tv specific authentication */
        private static readonly AVal av_NetStream_Authenticate_UsherToken = AVal.AVC("NetStream.Authenticate.UsherToken");

        private static readonly AVal av_onMetaData = AVal.AVC("onMetaData");
        private static readonly AVal av_duration = AVal.AVC("duration");
        private static readonly AVal av_video = AVal.AVC("video");
        private static readonly AVal av_audio = AVal.AVC("audio");
        private static readonly AVal av__checkbw = AVal.AVC("_checkbw");

        /// <summary> #define HEADRBUF (128*1024) </summary>
        private const int HEADERBUF = 128 * 1024;

        // static const char flvHeader[]
        private static readonly byte[] FlvHeader =
        {
            (byte)'F', (byte)'L', (byte)'V', 0x01,
            0x00, /* 0x04 == audio, 0x01 == video */
            0x00, 0x00, 0x00, 0x09,
            0x00, 0x00, 0x00, 0x00
        };

        ///<summary> static int add_addr_info(struct sockaddr_in *service, AVal *host, int port) </summary>
        private enum RTMPTCmd
        {
            RTMPT_OPEN = 0,
            RTMPT_SEND,
            RTMPT_IDLE,
            RTMPT_CLOSE
        };

        /// <summary> static const char* RTMPT_cmds[]  </summary>
        private static readonly Dictionary<RTMPTCmd, string> RTMPT_cmds = new Dictionary<RTMPTCmd, string>
        {
            { RTMPTCmd.RTMPT_OPEN, "open" },
            { RTMPTCmd.RTMPT_SEND, "send" },
            { RTMPTCmd.RTMPT_IDLE, "idle" },
            { RTMPTCmd.RTMPT_CLOSE, "close" }
        };

        private const int MAX_IGNORED_FRAMES = 50;
    }
}