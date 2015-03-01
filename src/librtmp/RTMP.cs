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
using System.Net;
using System.Net.Sockets;

namespace librtmp
{
    public class RTMP
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
        private const int RTMP_PACKET_TYPE_CHUNK_SIZE = 0x01;
        /*      RTMP_PACKET_TYPE_...                0x02 */
        private const int RTMP_PACKET_TYPE_BYTES_READ_REPORT = 0x03;
        private const int RTMP_PACKET_TYPE_CONTROL = 0x04;
        private const int RTMP_PACKET_TYPE_SERVER_BW = 0x05;
        private const int RTMP_PACKET_TYPE_CLIENT_BW = 0x06;
        /*      RTMP_PACKET_TYPE_...                0x07 */
        private const int RTMP_PACKET_TYPE_AUDIO = 0x08;
        private const int RTMP_PACKET_TYPE_VIDEO = 0x09;
        /*      RTMP_PACKET_TYPE_...                0x0A */
        /*      RTMP_PACKET_TYPE_...                0x0B */
        /*      RTMP_PACKET_TYPE_...                0x0C */
        /*      RTMP_PACKET_TYPE_...                0x0D */
        /*      RTMP_PACKET_TYPE_...                0x0E */
        private const int RTMP_PACKET_TYPE_FLEX_STREAM_SEND = 0x0F;
        private const int RTMP_PACKET_TYPE_FLEX_SHARED_OBJECT = 0x10;
        private const int RTMP_PACKET_TYPE_FLEX_MESSAGE = 0x11;
        private const int RTMP_PACKET_TYPE_INFO = 0x12;
        private const int RTMP_PACKET_TYPE_SHARED_OBJECT = 0x13;
        private const int RTMP_PACKET_TYPE_INVOKE = 0x14;
        /*      RTMP_PACKET_TYPE_...                0x15 */
        private const int RTMP_PACKET_TYPE_FLASH_VIDEO = 0x16;

        /// <summary> #define RTMP_LARGE_HEADER_SIZE 12 </summary>
        private const int RTMP_LARGE_HEADER_SIZE = 12;

        /// <summary> #define RTMP_MAX_HEADER_SIZE 18</summary>
        public const int RTMP_MAX_HEADER_SIZE = 18;

        /// <summary> #define RTMP_PACKET_SIZE_LARGE    0</summary>
        private const int RTMP_PACKET_SIZE_LARGE = 0;

        /// <summary> #define RTMP_PACKET_SIZE_MEDIUM   1</summary>
        private const int RTMP_PACKET_SIZE_MEDIUM = 1;

        /// <summary> #define RTMP_PACKET_SIZE_SMALL    2</summary>
        private const int RTMP_PACKET_SIZE_SMALL = 2;

        /// <summary> #define RTMP_PACKET_SIZE_MINIMUM  3</summary>
        private const int RTMP_PACKET_SIZE_MINIMUM = 3;

        public static readonly string[] RTMPProtocolStrings =
        {
            "RTMP", "RTMPT", "RTMPE", "RTMPTE", "RTMPS", "RTMPTS", "", "", "RTMFP"
        };

        public static readonly string[] RTMPProtocolStringsLower =
        {
            "rtmp", "rtmpt", "rtmpe", "rtmpte", "rtmps", "rtmpts", "", "", "rtmfp"
        };

        private static readonly int[] packetSize = { 12, 8, 4, 1 };

        /// <summary> const AVal RTMP_DefaultFlashVer </summary>
        /// <remarks>TODO: OSS( WIN/SOL/MAC/LNX/GNU) </remarks>
        public static readonly AVal RTMP_DefaultFlashVer = AVal.AVC("WIN 10,0,32,18");

        public static bool RTMP_ctrlC { get; set; } // rtmp.c global, not struct RTMP member

        /// <summary> int m_inChunkSize; </summary>
        public int m_inChunkSize { get; set; }

        /// <summary> int m_outChunkSize; </summary>
        public int m_outChunkSize { get; set; }

        /// <summary> int m_nBWCheckCounter; </summary>
        public int m_nBWCheckCounter { get; set; }

        /// <summary> int m_nBytesIn; </summary>
        public int m_nBytesIn { get; set; }

        /// <summary> int m_nBytesInSent; </summary>
        public int m_nBytesInSent { get; set; }

        /// <summary> int m_nBufferMS; </summary>
        public int m_nBufferMS { get; set; }

        /// <summary> int m_stream_id; </summary>
        public int m_stream_id { get; set; } /* returned in _result from createStream */

        /// <summary> int m_mediaChannel </summary>
        public int m_mediaChannel { get; set; }

        /// <summary> uint32_t m_mediaStamp </summary>
        public uint m_mediaStamp { get; set; }

        /// <summary> uint32_t m_pauseStamp </summary>
        public uint m_pauseStamp { get; set; }

        /// <summary> int m_pausing </summary>
        public int m_pausing { get; set; }

        /// <summary> int m_nServerBW </summary>
        public int m_nServerBW { get; set; }

        /// <summary> int m_nClientBW </summary>
        public int m_nClientBW { get; set; }

        /// <summary> uint8_t m_nClientBW2 </summary>
        public byte m_nClientBW2 { get; set; }

        /// <summary> uint8_t m_bPlaying </summary>
        public bool m_bPlaying { get; set; }

        /// <summary> uint8_t m_bSendEncoding </summary>
        public byte m_bSendEncoding { get; set; }

        /// <summary> uint8_t m_bSendCounter </summary>
        public bool m_bSendCounter { get; set; }

        /// <summary> int m_numInvokes </summary>
        public int m_numInvokes { get; set; }

        /// <summary> int m_numCalls </summary>
        public int m_numCalls { get; set; }

        /// <summary> RTMP_METHOD* m_methodCalls </summary>
        public List<RTMP_METHOD> m_methodCalls { get; set; } /* remote method calls queue */

        /// <summary> int m_channelsAllocatedIn </summary>
        public int m_channelsAllocatedIn { get; set; }

        /// <summary> int m_channelsAllocatedOut </summary>
        public int m_channelsAllocatedOut { get; set; }

        /// <summary> RTMPPacket** m_vecChannelsIn </summary>
        public RTMPPacket[] m_vecChannelsIn { get; set; }

        /// <summary> RTMPPacket** m_vecChannelsOut </summary>
        public RTMPPacket[] m_vecChannelsOut { get; set; }

        /// <summary> int* m_channelTimestamp </summary>
        public uint[] m_channelTimestamp { get; set; } /* abs timestamp of last packet */

        /// <summary> double m_fAudioCodecs </summary>
        public double m_fAudioCodecs { get; set; } /* audioCodecs for the connect packet */

        /// <summary> double m_fVideoCodecs </summary>
        public double m_fVideoCodecs { get; set; } /* videoCodecs for the connect packet */

        /// <summary> double m_fEncoding </summary>
        public double m_fEncoding { get; set; } /* AMF0 or AMF3 */

        /// <summary> double m_fDuration </summary>
        public double m_fDuration { get; set; } /* duration of stream in seconds */

        /// <summary> int m_msgCounter </summary>
        public int m_msgCounter { get; set; } /* RTMPT stuff */

        /// <summary> int m_polling </summary>
        public int m_polling { get; set; }

        /// <summary> int m_resplen </summary>
        public int m_resplen { get; set; }

        /// <summary> int m_unackd </summary>
        public int m_unackd { get; set; }

        /// <summary> AVal m_clientID </summary>
        public AVal m_clientID { get; set; }

        /// <summary> RTMP_READ m_read </summary>
        public RTMP_READ m_read { get; set; }

        /// <summary> RTMPPacket m_write </summary>
        public RTMPPacket m_write { get; set; }

        /// <summary> RTMPSockBuf m_sb </summary>
        public RTMPSockBuf m_sb { get; set; }

        /// <summary> RTMP_LNK Link </summary>
        public RTMP_LNK Link { get; set; }

        /// <summary>R
        /// uint32_t RTMP_GetTime()
        /// </summary>
        /// <returns></returns>
        public static uint RTMP_GetTime()
        {
#if DEBUG
            return 0;
#else
            return (uint)DateTime.Now.Ticks;
#endif
        }

        /// <summary>
        /// int RTMP_ParseURL(const char *url, int *protocol, AVal *host, unsigned int *port, AVal *playpath, AVal *app);
        /// parseurl.c
        /// </summary>
        public static bool RTMP_ParseURL(string url, out int protocol, out AVal host, out int port, out AVal playpath, out AVal app)
        {
            // TODO: use Uri
            Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "Parsing...");
            protocol = RTMP_PROTOCOL_RTMP;
            host = AVal.AVC(string.Empty);
            port = 0;
            playpath = AVal.AVC(string.Empty);
            app = AVal.AVC(string.Empty);

            var p = url.IndexOf("://", StringComparison.CurrentCulture);
            if (string.IsNullOrEmpty(url) || p == -1)
            {
                // str.IndexOf return 0 when str is emtpy
                Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGERROR, "RTMP URL: No :// in url!");
                return false;
            }

            {
                var scheme = url.Substring(0, p).ToLower();
                switch (scheme)
                {
                    case "rtmp":
                        protocol = RTMP_PROTOCOL_RTMP;
                        break;

                    case "rtmpt":
                        protocol = RTMP_PROTOCOL_RTMPT;
                        break;

                    case "rtmps":
                        protocol = RTMP_PROTOCOL_RTMPTS;
                        break;

                    case "rtmpe":
                        protocol = RTMP_PROTOCOL_RTMPE;
                        break;

                    case "rtmfp":
                        protocol = RTMP_PROTOCOL_RTMFP;
                        break;

                    case "rtmpte":
                        protocol = RTMP_PROTOCOL_RTMPTE;
                        break;

                    case "rtmpts":
                        protocol = RTMP_PROTOCOL_RTMPTS;
                        break;

                    default:
                        Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGWARNING, "Unknown protocol!\n");
                        break;
                }
            }

            Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "Parsed protocol: {0}", protocol);

            p += 3;
            if (p >= url.Length)
            {
                Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGWARNING, "No hostname in URL!");
                return false;
            }

            var end = url.Length;
            var col = url.IndexOf(':', p);
            var ques = url.IndexOf('?', p);
            var slash = url.IndexOf('/', p);
            {
                var hostlen = slash != -1 ? slash - p : end - p;
                if (col != -1 && col - p < hostlen)
                {
                    hostlen = col - p;
                }

                if (hostlen < 256)
                {
                    host = AVal.AVC(url.Substring(p, hostlen));
                    Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "Parsed host    : {0}", host.to_s());
                }
                else
                {
                    Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGWARNING, "Hostname exceeds 255 characters!");
                }

                p += hostlen;
            }

            if (url[p] == ':')
            {
                p++;
                var t = new string(url.Substring(p).ToCharArray().TakeWhile(char.IsNumber).ToArray());
                int p2;
                if (!int.TryParse(t, out p2))
                {
                    p2 = 65536;
                }

                if (p2 > 65536)
                {
                    Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGWARNING, "Invalid port number!");
                }
                else
                {
                    port = p2;
                }
            }

            if (slash == -1)
            {
                Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGWARNING, "No application or playpath in URL!");
                return true;
            }

            p = slash + 1;
            {
                var s2 = url.IndexOf('/', p);
                var s3 = s2 != -1 ? url.IndexOf('/', s2 + 1) : -1;
                var s4 = s3 != -1 ? url.IndexOf('/', s3 + 1) : -1;
                var applen = end - p;
                var appnamelen = applen;
                if (ques != -1 && url.IndexOf("slist=", p, StringComparison.CurrentCulture) != -1)
                {
                    appnamelen = ques - p;
                }
                else if (url.Substring(p, 9) == "ondemand/")
                {
                    applen = 8;
                    appnamelen = 8;
                }
                else
                {
                    if (s4 != -1)
                    {
                        appnamelen = s4 - p;
                    }
                    else if (s3 != -1)
                    {
                        appnamelen = s3 - p;
                    }
                    else if (s2 != -1)
                    {
                        appnamelen = s2 - p;
                    }

                    applen = appnamelen;
                }

                app = AVal.AVC(url.Substring(p, applen));
                Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "Parsed app     : {0}", app.to_s());
                p += appnamelen;
            }

            if (url[p] == '/')
            {
                p++;
            }

            if (end > p)
            {
                var av = AVal.AVC(url.Substring(p));
                RTMP_ParsePlaypath(av, out playpath);
            }

            return true;
        }

        /// <summary> void RTMP_ParsePlaypath(AVal *in, AVal *out);
        /// Extracts playpath from RTMP URL. playpath is the file part of the
        /// URL, i.e. the part that comes after rtmp://host:port/app/
        /// Returns the stream name in a format understood by FMS. The name is
        /// the playpath part of the URL with formatting depending on the stream
        /// type:
        ///  mp4 streams: prepend "mp4:", remove extension
        ///  mp3 streams: prepend "mp3:", remove extension
        ///  flv streams: remove extension
        /// </summary>
        public static void RTMP_ParsePlaypath(AVal raw, out AVal cooked)
        {
            var pplen = raw.av_len;
            var ppstart = 0;
            var rawStr = new string(raw.av_val.Select(b => (char)b).ToArray());

            if (rawStr[ppstart] == '?')
            {
                var t = rawStr.IndexOf("slist=", StringComparison.CurrentCulture);
                if (t != -1)
                {
                    ppstart = t + 6;
                    pplen -= ppstart;
                }

                t = rawStr.IndexOf('&', ppstart);
                if (t != -1)
                {
                    pplen = t - ppstart;
                }
            }

            bool mp3 = false, mp4 = false, subExt = false;
            var q = rawStr.IndexOf('?', ppstart);
            var extp = 0;
            if (pplen >= 4)
            {
                var t = q != -1 ? q - 4 : ppstart + pplen - 4;
                extp = t;
                var ext = rawStr.Substring(t, 4);
                if (ext == ".f4v" || ext == ".mp4")
                {
                    //
                    mp4 = true;
                    subExt = true;
                    /* Only remove .flv from rtmp URL, not slist params */
                }
                else if (ppstart == 0 && ext == ".flv")
                {
                    subExt = true;
                }
                else if (ext == ".mp3")
                {
                    mp3 = true;
                    subExt = true;
                }
            }

            var streamName = string.Empty;
            if (mp4)
            {
                if (rawStr.Substring(ppstart, 4) != "mp4:")
                {
                    streamName = "mp4:";
                }
                else
                {
                    subExt = false;
                }
            }
            else if (mp3)
            {
                if (rawStr.Substring(ppstart, 4) != "mp3:")
                {
                    streamName = "mp3:";
                }
                else
                {
                    subExt = false;
                }
            }

            for (var p = ppstart; pplen > 0; )
            {
                if (subExt && p == extp)
                {
                    p += 4;
                    pplen -= 4;
                    continue;
                }
                if (rawStr[p] == '%')
                {
                    var enc = rawStr.Substring(p + 1, 2);
                    char s;
                    if (char.TryParse(enc, out s))
                    {
                        streamName += s;
                    }

                    pplen -= 3;
                    p += 3;
                }
                else
                {
                    streamName += rawStr[p];
                    p++;
                    pplen--;
                }
            }

            cooked = AVal.AVC(streamName);
        }

        /// <summary> void RTMP_SetBufferMS(RTMP *r, int size);</summary>
        public static void RTMP_SetBufferMS(RTMP r, int size)
        {
            r.m_nBufferMS = size;
        }

        /// <summary>
        /// void RTMP_UpdateBufferMS(RTMP *r);
        /// </summary>
        public static void RTMP_UpdateBufferMS(RTMP r)
        {
            throw new NotImplementedException();
        }

        // int RTMP_SetOpt(RTMP *r, const AVal *opt, AVal *arg);
        public static bool RTMP_SetOpt(RTMP r, AVal opt, AVal arg)
        {
            throw new NotImplementedException();
        }

        /// <summary> int RTMP_SetupURL(RTMP *r, char *url); </summary>
        public static bool RTMP_SetupURL(RTMP r, string url)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// void RTMP_SetupStream(RTMP *r, int protocol,AVal *hostname,unsigned int port,
        /// AVal *sockshost,AVal *playpath,AVal *tcUrl,AVal *swfUrl,AVal *pageUrl,
        /// AVal *app,AVal *auth,AVal *swfSHA256Hash,uint32_t swfSize,AVal *flashVer,
        /// AVal *subscribepath,AVal *usherToken,int dStart,int dStop, int bLiveStream, long int timeout);
        /// </summary>
        public static void RTMP_SetupStream(RTMP r,
            int protocol, AVal host, int port, AVal sockshost,
            AVal playpath, AVal tcUrl, AVal swfUrl, AVal pageUrl, AVal app,
            AVal auth, AVal swfSha256Hash, int swfSize, AVal flashVer,
            AVal subscribepath, AVal usherToken, int dStart, int dStop, bool bLiveStream, int timeout)
        {
            #region dump-args

            Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "Protocol : {0}", RTMPProtocolStrings[protocol & 7]);
            Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "Hostname : {0}", host.to_s());
            Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "Port     : {0}", port);
            Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "Playpath : {0}", playpath.to_s());

            if (tcUrl.av_val.Length > 0)
            {
                Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "tcUrl    : {0}", tcUrl.to_s());
            }

            if (swfUrl.av_val.Length > 0)
            {
                Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "swfUrl   : {0}", swfUrl.to_s());
            }

            if (pageUrl.av_val.Length > 0)
            {
                Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "pageUrl  : {0}", pageUrl.to_s());
            }

            if (app.av_val.Length > 0)
            {
                Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "app      : {0}", app.to_s());
            }

            if (auth.av_val.Length > 0)
            {
                Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "auth     : {0}", auth.to_s());
            }

            if (subscribepath.av_val.Length > 0)
            {
                Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "subscribepath : {0}", subscribepath.to_s());
            }

            if (usherToken.av_val.Length > 0)
            {
                Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "NetStream.Authenticate.UsherToken : {0}", usherToken.to_s());
            }

            if (flashVer.av_val.Length > 0)
            {
                Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "flashVer : {0}", flashVer.to_s());
            }

            if (dStart > 0)
            {
                Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "StartTime     : {0} msec", dStart);
            }

            if (dStop > 0)
            {
                Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "StopTime      : {0} msec", dStop);
            }

            Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "live     : {0}", bLiveStream ? "yes" : "no");
            Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "timeout  : {0} sec", timeout);

            #endregion

#if CRYPTO
    if (swfSHA256Hash != NULL && swfSize > 0)
    {
        memcpy(r.Link.SWFHash, swfSHA256Hash.av_val, sizeof(r.Link.SWFHash));
        r.Link.SWFSize = swfSize;
        Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "SWFSHA256:");
        RTMP_LogHex(RTMP_LOGDEBUG, r.Link.SWFHash, sizeof(r.Link.SWFHash));
        Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "SWFSize  : %u", r.Link.SWFSize);
    }
    else
    {
        r.Link.SWFSize = 0;
    }
#endif

            SocksSetup(r, sockshost);

            if (tcUrl.av_len > 0)
            {
                r.Link.tcUrl = tcUrl;
            }

            if (swfUrl.av_len > 0)
            {
                r.Link.swfUrl = swfUrl;
            }

            if (pageUrl.av_len > 0)
            {
                r.Link.pageUrl = pageUrl;
            }

            if (app.av_len > 0)
            {
                r.Link.app = app;
            }

            if (auth.av_len > 0)
            {
                r.Link.auth = auth;
                r.Link.lFlags |= RTMP_LNK.RTMP_LNK_FLAG.RTMP_LF_AUTH;
            }

            r.Link.flashVer = flashVer.av_len > 0 ? flashVer : RTMP_DefaultFlashVer;

            if (subscribepath.av_len > 0)
            {
                r.Link.subscribepath = subscribepath;
            }

            if (usherToken.av_len > 0)
            {
                r.Link.usherToken = usherToken;
            }

            r.Link.seekTime = dStart;
            r.Link.stopTime = dStop;
            if (bLiveStream)
            {
                r.Link.lFlags |= RTMP_LNK.RTMP_LNK_FLAG.RTMP_LF_LIVE;
            }

            r.Link.timeout = timeout;
            r.Link.protocol = protocol;
            r.Link.hostname = host;
            r.Link.port = (ushort)port;
            r.Link.playpath = playpath;

            if (r.Link.port == 0)
            {
                if ((protocol & RTMP_FEATURE_SSL) != 0x00)
                {
                    r.Link.port = 443;
                }
                else if ((protocol & RTMP_FEATURE_HTTP) != 0x00)
                {
                    r.Link.port = 80;
                }
                else
                {
                    r.Link.port = 1935;
                }
            }
        }

        /// <summary> int RTMP_Connect(RTMP *r, RTMPPacket *cp); </summary>
        public static bool RTMP_Connect(RTMP r, RTMPPacket cp)
        {
            if (r.Link.hostname == null || r.Link.hostname.av_len == 0)
            {
                return false;
            }

            var remote = r.Link.socksport != 0
                ? new DnsEndPoint(r.Link.sockshost.to_s(), r.Link.socksport)
                : new DnsEndPoint(r.Link.hostname.to_s(), r.Link.port);

            if (!RTMP_Connect0(r, remote))
            {
                return false;
            }

            r.m_bSendCounter = true;

            return RTMP_Connect1(r, cp);
        }

        /// <summary> int RTMP_Connect0(RTMP *r, struct sockaddr *svc); </summary>
        public static bool RTMP_Connect0(RTMP r, EndPoint remote)
        {
            const string __FUNCTION__ = "RTMP_Connect0";

            r.m_sb.sb_timedout = false;
            r.m_pausing = 0;
            r.m_fDuration = 0.0;
            try
            {
                r.m_sb.sb_socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            }
            catch (SocketException se)
            {
                // TODO:  GetSockError()
                Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGERROR, "{0}, failed to create socket. Error: {1}", __FUNCTION__, se.Message);
                return false;
            }

            try
            {
                r.m_sb.sb_socket.Connect(remote);
            }
            catch (Exception ee)
            {
                Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGERROR, "{0}, failed to connect socket. ({1}) ", __FUNCTION__, ee.Message);
                RTMP_Close(r);
                return false;
            }

            if (r.Link.socksport != 0)
            {
                Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "{0} ... SOCKS negotiation", __FUNCTION__);
                if (!SocksNegotiate(r))
                {
                    Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGERROR, "{0}, SOCKS negotiation failed.", __FUNCTION__);
                    RTMP_Close(r);
                    return false;
                }
            }

            // TODO: Socket.ReceiveTimeOut?
            try
            {
                r.m_sb.sb_socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReceiveTimeout, r.Link.timeout * 1000);
            }
            catch (SocketException)
            {
                Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGERROR, "{0}, Setting socket timeout to {1}s failed!", __FUNCTION__, r.Link.timeout);
            }

            try
            {
                r.m_sb.sb_socket.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.NoDelay, true);
            }
            catch
            {
                // nothing;
            }

            return true;
        }

        /// <summary> int RTMP_Connect1(RTMP *r, RTMPPacket *cp); </summary>
        public static bool RTMP_Connect1(RTMP r, RTMPPacket cp)
        {
            const string __FUNCTION__ = "RTMP_Connect1";

            if ((r.Link.protocol & RTMP_FEATURE_SSL) != 0x00)
            {
#if CRYPTO_SSL // defined(CRYPTO) && !defined(NO_SSL)
                TLS_client(RTMP_TLS_ctx, r.m_sb.sb_ssl);
                TLS_setfd(r.m_sb.sb_ssl, r.m_sb.sb_socket);
                if (TLS_connect(r.m_sb.sb_ssl) < 0)
                {
                    Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGERROR, "{0}, TLS_Connect failed", __FUNCTION__);
                    RTMP_Close(r);
                    return false;
                }
#else
                Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGERROR, "{0}, no SSL/TLS support", __FUNCTION__);
                RTMP_Close(r);
                return false;

#endif
            }

            if ((r.Link.protocol & RTMP_FEATURE_HTTP) != 0x00)
            {
                r.m_msgCounter = 1;
                r.m_clientID.av_val = null;
                r.m_clientID.av_len = 0;
                HTTP_Post(r, RTMPTCmd.RTMPT_OPEN, new byte[1], 1);
                if (HTTP_read(r, true) != 0)
                {
                    r.m_msgCounter = 0;
                    Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "{0}, Could not connect for handshake", __FUNCTION__);
                    RTMP_Close(r);
                    return false;
                }

                r.m_msgCounter = 0;
            }

            Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "{0}, ... connected, handshaking", __FUNCTION__);
            if (!HandShake(r, 1))
            {
                Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGERROR, "{0}, handshake failed.", __FUNCTION__);
                RTMP_Close(r);
                return false;
            }

            Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "{0}, handshaked", __FUNCTION__);

            if (!SendConnectPacket(r, cp))
            {
                Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGERROR, "{0}, RTMP connect failed.", __FUNCTION__);
                RTMP_Close(r);
                return false;
            }

            return true;
        }

        /// <summary> int RTMP_Serve(RTMP *r); </summary>
        public static bool RTMP_Serve(RTMP r)
        {
            return SHandShake(r);
        }

        // int RTMP_TLS_Accept(RTMP *r, void *ctx);

        /// <summary> int RTMP_ReadPacket(RTMP *r, RTMPPacket *packet); </summary>
        public static bool RTMP_ReadPacket(RTMP r, RTMPPacket packet)
        {
            const string __FUNCTION__ = "RTMP_ReadPaceket";
            byte[] hbuf = new byte[RTMP_MAX_HEADER_SIZE];
            int header = 0; // hbuf
            bool didAlloc = false; // int didAlloc = false;

            Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG2, "{0}: fd={1}", __FUNCTION__, r.m_sb.sb_socket.LocalEndPoint);

            if (ReadN(r, hbuf, 1) == 0)
            {
                Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGERROR, "{0}, failed to read RTMP packet header", __FUNCTION__);
                return false;
            }

            packet.HeaderType = (byte)((hbuf[0] & 0xc0) >> 6);
            packet.ChannelNum = (hbuf[0] & 0x3f);
            header++;
            byte[] rbuf;
            if (packet.ChannelNum == 0)
            {
                rbuf = new byte[1];
                if (ReadN(r, rbuf, 1) != 1)
                {
                    Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGERROR, "{0}, failed to read RTMP packet header 2nd byte", __FUNCTION__);
                    return false;
                }

                hbuf[1] = rbuf[0];
                packet.ChannelNum = hbuf[1];
                packet.ChannelNum += 64;
                header++;
            }
            else if (packet.ChannelNum == 1)
            {
                rbuf = new byte[2];
                if (ReadN(r, rbuf, 2) != 2)
                {
                    Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGERROR, "{0}, failed to read RTMP packet header 3nd byte", __FUNCTION__);
                    return false;
                }

                hbuf[1] = rbuf[0];
                hbuf[2] = rbuf[1];
                packet.ChannelNum = (hbuf[2] << 8) + hbuf[1] + 64;
                Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "{0}, ChannelNum: {1:x}", __FUNCTION__, packet.ChannelNum);
                header += 2;
            }

            var nSize = packetSize[packet.HeaderType];

            // TODO: resize array.
            if (packet.ChannelNum >= r.m_channelsAllocatedIn)
            {
                int n = packet.ChannelNum + 10;
                var timestamp = new uint[n];
                var packets = new RTMPPacket[n];
                for (var i = 0; i < r.m_channelsAllocatedIn; ++i)
                {
                    timestamp[i] = r.m_channelTimestamp[i];
                    packets[i] = r.m_vecChannelsIn[i];
                }

                r.m_channelTimestamp = timestamp;
                r.m_vecChannelsIn = packets;
                r.m_channelsAllocatedIn = n;
            }

            if (nSize == RTMP_LARGE_HEADER_SIZE) /* if we get a full header the timestamp is absolute */
            {
                packet.HasAbsTimestamp = true;
            }
            else if (nSize < RTMP_LARGE_HEADER_SIZE)
            {
                Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "nSize < RTMP_LARGE_HEADER_SIZE");
                /* using values from the last message of this channel */
                if (r.m_vecChannelsIn[packet.ChannelNum] == null)
                {
                    //memcpy(packet, r.m_vecChannelsIn[packet.ChannelNum], sizeof (RTMPPacket));
                    r.m_vecChannelsIn[packet.ChannelNum] = new RTMPPacket
                    {
                        Body = packet.Body,
                        BodySize = packet.BodySize,
                        BytesRead = packet.BytesRead,
                        ChannelNum = packet.ChannelNum,
                        HasAbsTimestamp = packet.HasAbsTimestamp,
                        HeaderType = packet.HeaderType,
                        InfoField2 = packet.InfoField2,
                        PacketType = packet.PacketType,
                        Chunk = packet.Chunk,
                        TimeStamp = packet.TimeStamp
                    };
                }
            }

            nSize--;

            rbuf = new byte[nSize];
            if (nSize > 0 && ReadN(r, rbuf, nSize) != nSize)
            {
                Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGERROR, "{0}, failed to read RTMP packet header. type: {1:x}", __FUNCTION__, hbuf[0]);
                return false;
            }

            Array.Copy(rbuf, 0, hbuf, header, nSize); // TODO:
            var hSize = nSize + (header);

            if (nSize >= 3)
            {
                packet.TimeStamp = AMF.AMF_DecodeInt24(hbuf, header);

                /*Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "{0}, reading RTMP packet chunk on channel %x, headersz %i, timestamp %i, abs timestamp %i", __FUNCTION__, packet.ChannelNum, nSize, packet.TimeStamp, packet.HasAbsTimestamp); */

                if (nSize >= 6)
                {
                    packet.BodySize = AMF.AMF_DecodeInt24(hbuf, header + 3);
                    packet.BytesRead = 0;
                    RTMPPacket.RTMPPacket_Free(packet);

                    if (nSize > 6)
                    {
                        packet.PacketType = hbuf[header + 6]; // header[6];
                        if (nSize == 11)
                        {
                            packet.InfoField2 = DecodeInt32LE(hbuf, header + 7);
                        }
                    }
                }
            }

            var extendedTimestamp = packet.TimeStamp == 0xffffff;
            if (extendedTimestamp)
            {
                rbuf = new byte[4];
                if (ReadN(r, rbuf, 4) != 4) /* header + nSize */
                {
                    Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGERROR, "{0}, failed to read extended timestamp", __FUNCTION__);
                    return false;
                }
                Array.Copy(rbuf, 0, hbuf, header + nSize, 4);
                packet.TimeStamp = AMF.AMF_DecodeInt32(rbuf);
                hSize += 4;
            }

            Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG2, "{0}:", __FUNCTION__);
            Log.RTMP_LogHexString(Log.RTMP_LogLevel.RTMP_LOGDEBUG2, hbuf, (ulong)hSize);

            if (packet.BodySize > 0 && packet.Body == null)
            {
                if (!RTMPPacket.RTMPPacket_Alloc(packet, (int)packet.BodySize))
                {
                    Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "{0}, failed to allocate packet", __FUNCTION__);
                    return false;
                }

                didAlloc = true;
                packet.HeaderType = (byte)((hbuf[0] & 0xc0) >> 6);
            }

            var nToRead = (int)(packet.BodySize - packet.BytesRead);
            var nChunk = r.m_inChunkSize;
            if (nToRead < nChunk)
            {
                nChunk = nToRead;
            }

            /* Does the caller want the raw chunk? */
            if (packet.Chunk != null)
            {
                packet.Chunk.c_headerSize = hSize;
                // memcpy(packet.Chunk.c_header, hbuf, hSize);
                packet.Chunk.c_header = new byte[hSize];
                Array.Copy(hbuf, packet.Chunk.c_header, hSize);
                // packet.Chunk.c_chunk =  packet.Body + packet.BytesRead;
                packet.Chunk.c_chunk = new byte[nChunk];
                Array.Copy(packet.Body, packet.BytesRead, packet.Chunk.c_chunk, 0, nChunk);
                packet.Chunk.c_chunkSize = nChunk;
            }

            rbuf = new byte[nChunk]; // packet.Body + packet.BytesRead
            if (ReadN(r, rbuf, nChunk) != nChunk)
            {
                Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGERROR, "{0}, failed to read RTMP packet body. len: {1}",
                    __FUNCTION__, packet.BodySize);
                return false;
            }

            Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG2, "{0}:", __FUNCTION__);
            Log.RTMP_LogHexString(Log.RTMP_LogLevel.RTMP_LOGDEBUG2, rbuf, (ulong)nChunk);
            Array.Copy(rbuf, 0, packet.Body, packet.BytesRead, nChunk);
            packet.BytesRead += (uint)nChunk;

            /* keep the packet as ref for other packets on this channel */
            //if (!r.m_vecChannelsIn[packet.ChannelNum])
            //{
            //    r.m_vecChannelsIn[packet.ChannelNum] = malloc(sizeof (RTMPPacket));
            //}
            //memcpy(r.m_vecChannelsIn[packet.ChannelNum], packet, sizeof (RTMPPacket));
            if (r.m_vecChannelsIn[packet.ChannelNum] == null)
            {
                r.m_vecChannelsIn[packet.ChannelNum] = new RTMPPacket();
            }

            // TODO:
            r.m_vecChannelsIn[packet.ChannelNum].Body = (byte[])packet.Body.Clone();
            r.m_vecChannelsIn[packet.ChannelNum].BodySize = packet.BodySize;
            r.m_vecChannelsIn[packet.ChannelNum].BytesRead = packet.BytesRead;
            r.m_vecChannelsIn[packet.ChannelNum].ChannelNum = packet.ChannelNum;
            r.m_vecChannelsIn[packet.ChannelNum].HasAbsTimestamp = packet.HasAbsTimestamp;
            r.m_vecChannelsIn[packet.ChannelNum].HeaderType = packet.HeaderType;
            r.m_vecChannelsIn[packet.ChannelNum].InfoField2 = packet.InfoField2;
            r.m_vecChannelsIn[packet.ChannelNum].PacketType = packet.PacketType;
            r.m_vecChannelsIn[packet.ChannelNum].TimeStamp = packet.TimeStamp;
            r.m_vecChannelsIn[packet.ChannelNum].Chunk = packet.Chunk == null
                ? null
                : new RTMPChunk
                {
                    c_header = packet.Chunk.c_header,
                    c_chunk = (byte[])packet.Chunk.c_chunk.Clone(), // TODO:
                    c_chunkSize = packet.Chunk.c_chunkSize,
                    c_headerSize = packet.Chunk.c_headerSize
                };

            if (extendedTimestamp)
            {
                r.m_vecChannelsIn[packet.ChannelNum].TimeStamp = 0xffffff;
            }

            if (packet.IsReady())
            {
                /* make packet's timestamp absolute */
                if (!packet.HasAbsTimestamp)
                {
                    packet.TimeStamp += r.m_channelTimestamp[packet.ChannelNum]; /* timestamps seem to be always relative!! */
                }

                r.m_channelTimestamp[packet.ChannelNum] = packet.TimeStamp;

                /* reset the data from the stored packet. we keep the header since we may use it later if a new packet for this channel */
                /* arrives and requests to re-use some info (small packet header) */
                r.m_vecChannelsIn[packet.ChannelNum].Body = null;
                r.m_vecChannelsIn[packet.ChannelNum].BytesRead = 0;
                r.m_vecChannelsIn[packet.ChannelNum].HasAbsTimestamp = false; /* can only be false if we reuse header */
            }
            else
            {
                packet.Body = null; /* so it won't be erased on free */
            }

            return true;
        }

        // static int DecodeInt32LE(const char *data)
        private static int DecodeInt32LE(byte[] buf, int data)
        {
            return (buf[data + 3] << 24) | (buf[data + 2] << 16) | (buf[data + 1] << 8) | (buf[data + 0]);
        }

        // static int EncodeInt32LE(char* output, int nVal)
        private static int EncodeInt32LE(byte[] buf, int output, int nVal)
        {
            var ci = BitConverter.GetBytes(nVal);
            buf[output + 0] = ci[0];
            buf[output + 1] = ci[1];
            buf[output + 2] = ci[2];
            buf[output + 3] = ci[3];
            return 4;
        }

        /// <summary> int RTMP_SendPacket(RTMP *r, RTMPPacket *packet, int queue);</summary>
        public static bool RTMP_SendPacket(RTMP r, RTMPPacket packet, bool queue)
        {
            const string __FUNCTION__ = "RTMP_SendPacket";
            uint last = 0;

            if (packet.ChannelNum >= r.m_channelsAllocatedOut)
            {
                int n = packet.ChannelNum + 10;
                var packets = new RTMPPacket[n];
                for (var i = 0; i < r.m_channelsAllocatedOut; ++i)
                {
                    packets[i] = r.m_vecChannelsOut[i];
                }

                r.m_vecChannelsOut = packets;
                r.m_channelsAllocatedOut = n;
            }

            var prevPacket = r.m_vecChannelsOut[packet.ChannelNum];
            if (prevPacket != null && packet.HeaderType != RTMP_PACKET_SIZE_LARGE)
            {
                /* compress a bit by using the prev packet's attributes */
                if (prevPacket.BodySize == packet.BodySize
                    && prevPacket.PacketType == packet.PacketType
                    && packet.HeaderType == RTMP_PACKET_SIZE_MEDIUM)
                {
                    packet.HeaderType = RTMP_PACKET_SIZE_SMALL;
                }

                if (prevPacket.TimeStamp == packet.TimeStamp
                    && packet.HeaderType == RTMP_PACKET_SIZE_SMALL)
                {
                    packet.HeaderType = RTMP_PACKET_SIZE_MINIMUM;
                }

                last = prevPacket.TimeStamp;
            }

            if (packet.HeaderType > 3) /* sanity */
            {
                Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGERROR, "sanity failed!! trying to send header of type: 0x{0:x2}.", packet.HeaderType);
                return false;
            }

            var nSize = packetSize[packet.HeaderType];
            var hSize = nSize;
            var cSize = 0;
            var t = packet.TimeStamp - last;

            // char *header, *hptr, *hend, hbuf[RTMP_MAX_HEADER_SIZE], c;
            byte[] hbuf = new byte[RTMP_MAX_HEADER_SIZE];
            int header, hend;
            // TODO: packet.Body
            if (packet.Body != null)
            {
                header = 0; // packet.Body - nSize;
                hend = nSize; // packet.Body;
                hbuf = new byte[nSize + packet.BodySize];
                Array.Copy(packet.Body, 0, hbuf, nSize, packet.BodySize);
            }
            else
            {
                header = 6; // hbuf + 6;
                hend = hbuf.Length; // hbuf + sizeof(hbuf);
            }

            if (packet.ChannelNum > 319)
            {
                cSize = 2;
            }
            else if (packet.ChannelNum > 63)
            {
                cSize = 1;
            }

            if (cSize != 0)
            {
                header -= cSize;
                hSize += cSize;
            }

            if (t >= 0xffffff)
            {
                header -= 4;
                hSize += 4;
                Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGWARNING, "Larger timestamp than 24-bit: 0x{0:x}", t);
            }

            var hptr = header;
            var c = packet.HeaderType << 6;
            switch (cSize)
            {
                case 0:
                    c |= packet.ChannelNum;
                    break;

                case 1:
                    break;

                case 2:
                    c |= 1;
                    break;
            }

            hbuf[hptr++] = (byte)c; // *hptr++ = c;
            if (cSize != 0)
            {
                int tmp = packet.ChannelNum - 64;
                // *hptr++ = tmp & 0xff;
                hbuf[hptr++] = (byte)(tmp & 0xff);
                if (cSize == 2)
                {
                    // *hptr++ = tmp >> 8;
                    hbuf[hptr++] = (byte)(tmp >> 8);
                }
            }

            if (nSize > 1)
            {
                hptr = AMF.AMF_EncodeInt24(hbuf, hptr, hend, t > 0xffffff ? 0xffffff : t);
            }

            if (nSize > 4)
            {
                hptr = AMF.AMF_EncodeInt24(hbuf, hptr, hend, packet.BodySize);
                // *hptr++ = packet.PacketType;
                hbuf[hptr++] = packet.PacketType;
            }

            if (nSize > 8)
            {
                hptr += EncodeInt32LE(hbuf, hptr, packet.InfoField2);
            }

            if (t >= 0xffffff)
            {
                hptr = AMF.AMF_EncodeInt32(hbuf, hptr, hend, t);
            }

            nSize = (int)packet.BodySize; // TODO: uint
            var buffer = 0; // var buffer = packet.Body;
            var nChunkSize = r.m_outChunkSize;
            byte[] tbuf = null;
            int toff = 0;
            Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG2, "{0}: fd={1}, size={2}", __FUNCTION__, r.m_sb.sb_socket.LocalEndPoint, nSize);
            /* send all chunks in one HTTP request */
            if ((r.Link.protocol & RTMP_FEATURE_HTTP) != 0x00)
            {
                int chunks = (nSize + nChunkSize - 1) / nChunkSize;
                if (chunks > 1)
                {
                    var tlen = chunks * (cSize + 1) + nSize + hSize;
                    // tbuf = malloc(tlen);
                    tbuf = new byte[tlen];
                    toff = 0;
                }
            }

            while (nSize + hSize != 0)
            {
                if (nSize < nChunkSize)
                {
                    nChunkSize = nSize;
                }
                Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG2, "{0}:", __FUNCTION__);
                Log.RTMP_LogHexString(Log.RTMP_LogLevel.RTMP_LOGDEBUG2, hbuf.Skip(header).ToArray(), (ulong)hSize);
                Log.RTMP_LogHexString(Log.RTMP_LogLevel.RTMP_LOGDEBUG2, packet.Body.Skip(buffer).ToArray(), (ulong)nChunkSize);
                if (tbuf != null)
                {
                    // memcpy(toff, header, nChunkSize + hSize);
                    AMF.memcpy(tbuf, toff, hbuf, nChunkSize + hSize);
                    toff += nChunkSize + hSize;
                }
                else
                {
                    // int wrote = WriteN(r, header, nChunkSize + hSize);
                    var wrote = WriteN(r, hbuf.Skip(header).ToArray(), nChunkSize + hSize);
                    if (!wrote)
                    {
                        return false;
                    }
                }

                nSize -= nChunkSize;
                buffer += nChunkSize;
                hSize = 0;

                if (nSize > 0)
                {
                    header = buffer - 1;
                    hSize = 1;
                    if (cSize != 0)
                    {
                        header -= cSize;
                        hSize += cSize;
                    }

                    if (t >= 0xffffff)
                    {
                        header -= 4;
                        hSize += 4;
                    }

                    hbuf[header] = (byte)(0xc0 | c); // *header = (0xc0 | c);
                    if (cSize != 0)
                    {
                        int tmp = packet.ChannelNum - 64;
                        // header[1] = tmp & 0xff;
                        hbuf[header + 1] = (byte)(tmp & 0xff);
                        if (cSize == 2)
                        {
                            // header[2] = tmp >> 8;
                            hbuf[header + 2] = (byte)(tmp >> 8);
                        }
                    }

                    if (t >= 0xffffff)
                    {
                        var extendedTimestamp = header + 1 + cSize;
                        AMF.AMF_EncodeInt32(hbuf, extendedTimestamp, extendedTimestamp + 4, t);
                    }
                }
            }

            if (tbuf != null)
            {
                var wrote = WriteN(r, tbuf, toff); // toff - tbuf);
                // free(tbuf);tbuf = null;
                if (!wrote)
                {
                    return false;
                }
            }

            /* we invoked a remote method */
            if (packet.PacketType == RTMP_PACKET_TYPE_INVOKE)
            {
                AVal method;
                // char* ptr = packet.Body + 1;
                var ptr = 1;
                AMF.AMF_DecodeString(packet.Body, ptr, out method);
                Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "Invoking {0}", method.to_s());
                /* keep it in call queue till result arrives */
                if (queue)
                {
                    ptr += 3 + method.av_len;
                    var txn = (int)AMF.AMF_DecodeNumber(packet.Body, ptr);
                    r.m_methodCalls.Add(new RTMP_METHOD
                    {
                        name = method,
                        num = txn
                    });

                    r.m_numCalls++;
                }
            }

            if (r.m_vecChannelsOut[packet.ChannelNum] == null)
            {
                // r.m_vecChannelsOut[packet.ChannelNum] = malloc(sizeof(RTMPPacket));
                r.m_vecChannelsOut[packet.ChannelNum] = new RTMPPacket();
            }

            // TODO:
            // memcpy(r.m_vecChannelsOut[packet.ChanelNum], packet, sizeof(RTMPPacket));
            r.m_vecChannelsOut[packet.ChannelNum].BodySize = packet.BodySize;
            r.m_vecChannelsOut[packet.ChannelNum].BytesRead = packet.BytesRead;
            r.m_vecChannelsOut[packet.ChannelNum].ChannelNum = packet.ChannelNum;
            r.m_vecChannelsOut[packet.ChannelNum].Chunk = packet.Chunk == null
                ? null
                : new RTMPChunk
                {
                    c_chunk = packet.Chunk.c_chunk,
                    c_chunkSize = packet.Chunk.c_chunkSize,
                    c_header = packet.Chunk.c_header,
                    c_headerSize = packet.Chunk.c_headerSize
                };
            r.m_vecChannelsOut[packet.ChannelNum].HasAbsTimestamp = packet.HasAbsTimestamp;
            r.m_vecChannelsOut[packet.ChannelNum].HeaderType = packet.HeaderType;
            r.m_vecChannelsOut[packet.ChannelNum].InfoField2 = packet.InfoField2;
            r.m_vecChannelsOut[packet.ChannelNum].PacketType = packet.PacketType;
            r.m_vecChannelsOut[packet.ChannelNum].TimeStamp = packet.TimeStamp;
            r.m_vecChannelsOut[packet.ChannelNum].Body = (byte[])packet.Body.Clone();

            return true;
        }

        /// <summary> int RTMP_SendChunk(RTMP *r, RTMPChunk *chunk); </summary>
        public static bool RTMP_SendChunk(RTMP r, RTMPChunk c)
        {
            throw new NotImplementedException();
        }

        /// <summary> int RTMP_IsConnected(RTMP *r); </summary>
        public static bool RTMP_IsConnected(RTMP r)
        {
            return r.m_sb.sb_socket != null && r.m_sb.sb_socket.Connected;
        }

        // int RTMP_Socket(RTMP *r);

        /// <summary> int RTMP_IsTimedout(RTMP *r);</summary>
        public static bool RTMP_IsTimedout(RTMP r)
        {
            throw new NotImplementedException();
        }

        /// <summary> double RTMP_GetDuration(RTMP *r); </summary>
        public static double RTMP_GetDuration(RTMP r)
        {
            throw new NotImplementedException();
        }

        /// <summary> int RTMP_ToggleStream(RTMP* r); </summary>
        public static bool RTMP_ToggleStream(RTMP r)
        {
            throw new NotImplementedException();
        }

        /// <summary> int RTMP_ConnectStream(RTMP* r, int seekTime); </summary>
        public static bool RTMP_ConnectStream(RTMP r, int seekTime)
        {
            RTMPPacket packet = new RTMPPacket();

            /* seekTime was already set by SetupStream / SetupURL.
             * This is only needed by ReconnectStream.
             */
            if (seekTime > 0)
            {
                r.Link.seekTime = seekTime;
            }

            r.m_mediaChannel = 0;

            while (!r.m_bPlaying && RTMP_IsConnected(r) && RTMP_ReadPacket(r, packet))
            {
                if (packet.IsReady())
                {
                    if (packet.BodySize == 0)
                    {
                        continue;
                    }

                    if ((packet.PacketType == RTMP_PACKET_TYPE_AUDIO) ||
                        (packet.PacketType == RTMP_PACKET_TYPE_VIDEO) ||
                        (packet.PacketType == RTMP_PACKET_TYPE_INFO))
                    {
                        Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGWARNING, "Received FLV packet before play()! Ignoring.");
                        RTMPPacket.RTMPPacket_Free(packet);
                        continue;
                    }

                    RTMP_ClientPacket(r, packet);
                    RTMPPacket.RTMPPacket_Free(packet);
                }
            }

            return r.m_bPlaying;
        }

        /// <summary> int RTMP_ReconnectStream(RTMP *r, int seekTime); </summary>
        public static bool RTMP_ReconnectStream(RTMP r, int seekTime)
        {
            throw new NotImplementedException();
        }

        // void RTMP_DeleteStream(RTMP *r);
        // int RTMP_GetNextMediaPacket(RTMP *r, RTMPPacket *packet);
        public static int RTMP_GetNextMediaPacket(RTMP r, RTMPPacket packet)
        {
            {
                int bHasMediaPacket = 0;

                while (bHasMediaPacket == 0 && RTMP_IsConnected(r) && RTMP_ReadPacket(r, packet))
                {
                    if (!packet.IsReady())
                    {
                        continue;
                    }

                    bHasMediaPacket = RTMP_ClientPacket(r, packet);

                    if (bHasMediaPacket == 0)
                    {
                        RTMPPacket.RTMPPacket_Free(packet);
                    }
                    else if (r.m_pausing == 3)
                    {
                        if (packet.TimeStamp <= r.m_mediaStamp)
                        {
                            bHasMediaPacket = 0;
#if DEBUG
                            Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG,
                                "Skipped type: {0:X02}, size: {1}, TS: {2} ms, abs TS: {3}, pause: {4} ms",
                                packet.PacketType, packet.BodySize,
                                packet.TimeStamp, packet.HasAbsTimestamp,
                                r.m_mediaStamp);
#endif
                            RTMPPacket.RTMPPacket_Free(packet);
                            continue;
                        }

                        r.m_pausing = 0;
                    }
                }

                if (bHasMediaPacket != 0)
                {
                    r.m_bPlaying = true;
                }
                else if (r.m_sb.sb_timedout && r.m_pausing == 0)
                {
                    r.m_pauseStamp = r.m_mediaChannel < r.m_channelsAllocatedIn ?
                        r.m_channelTimestamp[r.m_mediaChannel] : 0;
                }

                return bHasMediaPacket;
            }
        }

        /// <summary> int RTMP_ClientPacket(RTMP *r, RTMPPacket *packet);</summary>
        public static int RTMP_ClientPacket(RTMP r, RTMPPacket packet)
        {
            const string __FUNCTION__ = "RTMP_ClientPacket";
            {
                int bHasMediaPacket = 0;
                switch (packet.PacketType)
                {
                    case RTMP_PACKET_TYPE_CHUNK_SIZE:
                        /* chunk size */
                        HandleChangeChunkSize(r, packet);
                        break;

                    case RTMP_PACKET_TYPE_BYTES_READ_REPORT:
                        /* bytes read report */
                        Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "{0}, received: bytes read report", __FUNCTION__);
                        break;

                    case RTMP_PACKET_TYPE_CONTROL:
                        /* ctrl */
                        HandleCtrl(r, packet);
                        break;

                    case RTMP_PACKET_TYPE_SERVER_BW:
                        /* server bw */
                        HandleServerBW(r, packet);
                        break;

                    case RTMP_PACKET_TYPE_CLIENT_BW:
                        /* client bw */
                        HandleClientBW(r, packet);
                        break;

                    case RTMP_PACKET_TYPE_AUDIO:
                        /* audio data */
                        /*Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "{0}, received: audio %lu bytes", __FUNCTION__, packet.BodySize); */
                        HandleAudio(r, packet);
                        bHasMediaPacket = 1;
                        if (r.m_mediaChannel != 0)
                        {
                            r.m_mediaChannel = packet.ChannelNum;
                        }

                        if (r.m_pausing != 0)
                        {
                            r.m_mediaStamp = packet.TimeStamp;
                        }

                        break;

                    case RTMP_PACKET_TYPE_VIDEO:
                        /* video data */
                        /*Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "{0}, received: video %lu bytes", __FUNCTION__, packet.BodySize); */
                        HandleVideo(r, packet);
                        bHasMediaPacket = 1;
                        if (r.m_mediaChannel != 0)
                        {
                            r.m_mediaChannel = packet.ChannelNum;
                        }

                        if (r.m_pausing != 0)
                        {
                            r.m_mediaStamp = packet.TimeStamp;
                        }

                        break;

                    case RTMP_PACKET_TYPE_FLEX_STREAM_SEND:
                        /* flex stream send */
                        Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG,
                            "{0}, flex stream send, size {1} bytes, not supported, ignoring",
                            __FUNCTION__, packet.BodySize);
                        break;

                    case RTMP_PACKET_TYPE_FLEX_SHARED_OBJECT:
                        /* flex shared object */
                        Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG,
                            "{0}, flex shared object, size {1} bytes, not supported, ignoring",
                            __FUNCTION__, packet.BodySize);
                        break;

                    case RTMP_PACKET_TYPE_FLEX_MESSAGE:
                        /* flex message */
                        {
                            Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG,
                                "{0}, flex message, size {1} bytes, not fully supported",
                                __FUNCTION__, packet.BodySize);
                            /*RTMP_LogHex(packet.Body, packet.BodySize); */

                            /* some DEBUG code */
#if UNUSE
        RTMP_LIB_AMFObject obj;
        int nRes = obj.Decode(packet.Body + 1, packet.BodySize - 1);
        if (nRes < 0) {
            Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGERROR, "{0}, error decoding AMF3 packet", __FUNCTION__);
            /*return; */
        }

        obj.Dump();
#endif

                            if (HandleInvoke(r, packet.Body, 1, packet.BodySize - 1) == 1)
                            {
                                bHasMediaPacket = 2;
                            }

                            break;
                        }
                    case RTMP_PACKET_TYPE_INFO:
                        /* metadata (notify) */
                        Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "{0}, received: notify {1} bytes", __FUNCTION__,
                            packet.BodySize);
                        if (HandleMetadata(r, packet.Body, 0, packet.BodySize))
                        {
                            bHasMediaPacket = 1;
                        }
                        break;

                    case RTMP_PACKET_TYPE_SHARED_OBJECT:
                        Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "{0}, shared object, not supported, ignoring",
                            __FUNCTION__);
                        break;

                    case RTMP_PACKET_TYPE_INVOKE:
                        /* invoke */
                        Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "{0}, received: invoke {1} bytes", __FUNCTION__,
                            packet.BodySize);
                        /*RTMP_LogHex(packet.Body, packet.BodySize); */

                        if (HandleInvoke(r, packet.Body, 0, packet.BodySize) == 1)
                        {
                            bHasMediaPacket = 2;
                        }
                        break;

                    case RTMP_PACKET_TYPE_FLASH_VIDEO:
                        {
                            /* go through FLV packets and handle metadata packets */
                            int pos = 0;
                            var nTimeStamp = packet.TimeStamp;

                            while (pos + 11 < packet.BodySize)
                            {
                                var dataSize = AMF.AMF_DecodeInt24(packet.Body, pos + 1); /* size without header (11) and prevTagSize (4) */

                                if (pos + 11 + dataSize + 4 > packet.BodySize)
                                {
                                    Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGWARNING, "Stream corrupt?!");
                                    break;
                                }
                                if (packet.Body[pos] == 0x12)
                                {
                                    HandleMetadata(r, packet.Body, pos + 11, dataSize);
                                }
                                else if (packet.Body[pos] == 8 || packet.Body[pos] == 9)
                                {
                                    nTimeStamp = AMF.AMF_DecodeInt24(packet.Body, pos + 4);
                                    nTimeStamp |= (uint)(packet.Body[pos + 7] << 24); // TODO:
                                }

                                pos += (int)(11 + dataSize + 4); // TODO:
                            }

                            if (r.m_pausing != 0)
                            {
                                r.m_mediaStamp = nTimeStamp;
                            }

                            /* FLV tag(s) */
                            /*Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "{0}, received: FLV tag(s) %lu bytes", __FUNCTION__, packet.BodySize); */
                            bHasMediaPacket = 1;
                        }
                        break;

                    default:
                        Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "{0}, unknown packet type received: 0x{1:x02}", __FUNCTION__,
                            packet.PacketType);
#if  DEBUG
                        Log.RTMP_LogHex(Log.RTMP_LogLevel.RTMP_LOGDEBUG, packet.Body, packet.BodySize);
#endif
                        break;
                }

                return bHasMediaPacket;
            }
        }

#if CRYPTO
        private class TLS_CTX { }

        private static TLS_CTX RTMP_TLS_ctx;
#endif

        /// <summary> void RTMP_Init(RTMP *r); </summary>
        public static void RTMP_Init(RTMP r)
        {
#if CRYPTO
            if (RTMP_TLS_ctx == null)
            {
                RTMP_TLS_Init();
            }
#endif
            r.m_sb = new RTMPSockBuf();
            r.m_inChunkSize = RTMP_DEFAULT_CHUNKSIZE;
            r.m_outChunkSize = RTMP_DEFAULT_CHUNKSIZE;
            r.m_nBufferMS = 30000;
            r.m_nClientBW = 2500000;
            r.m_nClientBW2 = 2;
            r.m_nServerBW = 2500000;
            r.m_fAudioCodecs = 3191.0;
            r.m_fVideoCodecs = 252.0;
            r.Link = new RTMP_LNK { timeout = 30, swfAge = 30 };
            r.m_read = new RTMP_READ();
            r.m_write = new RTMPPacket();
            r.m_methodCalls = new List<RTMP_METHOD>();
        }

        /// <summary> void RTMP_Close(RTMP *r); </summary>
        public static void RTMP_Close(RTMP r)
        {
            CloseInternal(r, false);
        }

        //RTMP *RTMP_Alloc(void);
        // void RTMP_Free(RTMP *r);
        // void RTMP_EnableWrite(RTMP *r);

        // void *RTMP_TLS_AllocServerContext(const char* cert, const char* key);
        // void RTMP_TLS_FreeServerContext(void *ctx);

        // int RTMP_LibVersion(void);
        // void RTMP_UserInterrupt(void);	/* user typed Ctrl-C */
        /*
        from http://jira.red5.org/confluence/display/docs/Ping:

        Ping is the most mysterious message in RTMP and till now we haven't fully interpreted it yet. In summary, Ping message is used as a special command that are exchanged between client and server. This page aims to document all known Ping messages. Expect the list to grow.

        The type of Ping packet is 0x4 and contains two mandatory parameters and two optional parameters. The first parameter is the type of Ping and in short integer. The second parameter is the target of the ping. As Ping is always sent in Channel 2 (control channel) and the target object in RTMP header is always 0 which means the Connection object, it's necessary to put an extra parameter to indicate the exact target object the Ping is sent to. The second parameter takes this responsibility. The value has the same meaning as the target object field in RTMP header. (The second value could also be used as other purposes, like RTT Ping/Pong. It is used as the timestamp.) The third and fourth parameters are optional and could be looked upon as the parameter of the Ping packet. Below is an unexhausted list of Ping messages.

        * type 0: Clear the stream. No third and fourth parameters. The second parameter could be 0. After the connection is established, a Ping 0,0 will be sent from server to client. The message will also be sent to client on the start of Play and in response of a Seek or Pause/Resume request. This Ping tells client to re-calibrate the clock with the timestamp of the next packet server sends.
        * type 1: Tell the stream to clear the playing buffer.
        * type 3: Buffer time of the client. The third parameter is the buffer time in millisecond.
        * type 4: Reset a stream. Used together with type 0 in the case of VOD. Often sent before type 0.
        * type 6: Ping the client from server. The second parameter is the current time.
        * type 7: Pong reply from client. The second parameter is the time the server sent with his ping request.
        * type 26: SWFVerification request
        * type 27: SWFVerification response
        */

        /// <summary> int RTMP_SendCtrl(RTMP *r, short nType, unsigned int nObject,unsigned int nTime);</summary>
        public static bool RTMP_SendCtrl(RTMP r, short nType, uint nObject, uint nTime)
        {
            {
                byte[] pbuf = new byte[256];
                var pend = pbuf.Length;

                Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "sending ctrl. type: 0x{0:x4}", nType);

                uint nSize;
                switch (nType)
                {
                    case 0x03:
                        nSize = 10;
                        break; /* buffer time */
                    case 0x1A:
                        nSize = 3;
                        break; /* SWF verify request */
                    case 0x1B:
                        nSize = 44;
                        break; /* SWF verify response */
                    default:
                        nSize = 6;
                        break;
                }

                var buf = 0;
                buf = AMF.AMF_EncodeInt16(pbuf, buf, pend, (ushort)nType);

                if (nType == 0x1B)
                {
#if CRYPTO
    // memcpy(buf, r.Link.SWFVerificationResponse, 42);
                    Array.Copy(r.Link.SWFVerificationResponse, 0, pbuf, buf, 42);
                    Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "Sending SWFVerification response: ");
                    Log.RTMP_LogHex(Log.RTMP_LogLevel.RTMP_LOGDEBUG, packet.Body, packet.BodySize);
#endif
                }
                else if (nType == 0x1A)
                {
                    pbuf[buf] = (byte)(nObject & 0xFF); // *buf = nObject & 0xff;
                }
                else
                {
                    if (nSize > 2)
                    {
                        buf = AMF.AMF_EncodeInt32(pbuf, buf, pend, nObject);
                    }

                    if (nSize > 6)
                    {
                        buf = AMF.AMF_EncodeInt32(pbuf, buf, pend, nTime);
                    }
                }

                var packet = new RTMPPacket
                {
                    ChannelNum = 0x02, /* control channel (ping) */
                    HeaderType = RTMP_PACKET_SIZE_MEDIUM,
                    PacketType = RTMP_PACKET_TYPE_CONTROL,
                    TimeStamp = 0, /* RTMP_GetTime(); */
                    InfoField2 = 0,
                    HasAbsTimestamp = false,
                    Body = pbuf,
                    BodySize = nSize
                };

                return RTMP_SendPacket(r, packet, false);
            }
        }

        /* caller probably doesn't know current timestamp, should just use RTMP_Pause instead */

        /// <summary> int RTMP_SendPause(RTMP *r, int doPause, int iTime)</summary>
        public static bool RTMP_SendPause(RTMP r, bool doPause, int iTime)
        {
            const string __FUNCTION__ = "RTMP_SendPause";
            var pbuf = new byte[256];
            var pend = pbuf.Length;

            var enc = 0;
            enc = AMF.AMF_EncodeString(pbuf, enc, pend, av_pause);
            enc = AMF.AMF_EncodeNumber(pbuf, enc, pend, ++r.m_numInvokes);
            pbuf[enc++] = (byte)AMFDataType.AMF_NULL;
            enc = AMF.AMF_EncodeBoolean(pbuf, enc, pend, doPause);
            enc = AMF.AMF_EncodeNumber(pbuf, enc, pend, iTime);
            var packet = new RTMPPacket
            {
                ChannelNum = 0x08, /* video channel */
                HeaderType = RTMP_PACKET_SIZE_MEDIUM,
                PacketType = RTMP_PACKET_TYPE_INVOKE,
                TimeStamp = 0,
                InfoField2 = 0,
                HasAbsTimestamp = false,
                Body = pbuf,
                BodySize = (uint)enc
            };

            Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "{0}, {1}, pauseTime={2}", __FUNCTION__, doPause, iTime);
            return RTMP_SendPacket(r, packet, true);
        }

        // int RTMP_Pause(RTMP *r, int doPause);

        /// <summary> int RTMP_FindFirstMatchingProperty(AMFObject *obj, const AVal *name,AMFObjectProperty * p); </summary>
        public static bool RTMP_FindFirstMatchingProperty(AMFObject obj, AVal name, out AMFObjectProperty p)
        {
            /* this is a small object search to locate the "duration" property */
            for (var n = 0; n < obj.o_num; n++)
            {
                AMFObjectProperty prop = AMFObject.AMF_GetProp(obj, null, n);

                if (AVal.Match(prop.p_name, name))
                {
                    // memcpy(p, prop, sizeof ( * prop));
                    p = prop;
                    return true;
                }

                if (prop.p_type == AMFDataType.AMF_OBJECT || prop.p_type == AMFDataType.AMF_ECMA_ARRAY)
                {
                    if (RTMP_FindFirstMatchingProperty(prop.p_object, name, out p))
                    {
                        return true;
                    }
                }
            }

            p = null;
            return false;
        }

        /// <summary>
        /// int RTMP_FindPrefixProperty(AMFObject *obj, const AVal *name, AMFObjectProperty * p)
        /// /* Like above, but only check if name is a prefix of property */
        /// </summary>
        public static bool RTMP_FindPrefixProperty(AMFObject obj, AVal name, out AMFObjectProperty p)
        {
            for (var n = 0; n < obj.o_num; n++)
            {
                AMFObjectProperty prop = AMFObject.AMF_GetProp(obj, null, n);

                if (prop.p_name.av_len > name.av_len &&
                    !memcmp(prop.p_name.av_val, 0, name.av_val, 0, name.av_len))
                {
                    // memcpy(p, prop, sizeof(*prop));
                    p = prop;
                    return true;
                }

                if (prop.p_type == AMFDataType.AMF_OBJECT)
                {
                    if (RTMP_FindPrefixProperty(prop.p_object, name, out p))
                    {
                        return true;
                    }
                }
            }

            p = null;
            return false;
        }

        /// <summary> int RTMP_SendCreateStream(RTMP *r)</summary>
        public static bool RTMP_SendCreateStream(RTMP r)
        {
            var pbuf = new byte[256];
            var pend = pbuf.Length;
            var enc = 0;
            enc = AMF.AMF_EncodeString(pbuf, enc, pend, av_createStream);
            enc = AMF.AMF_EncodeNumber(pbuf, enc, pend, ++r.m_numInvokes);
            pbuf[enc++] = (byte)AMFDataType.AMF_NULL; /* NULL */
            var packet = new RTMPPacket
            {
                ChannelNum = 0x03, /* control channel (invoke) */
                HeaderType = RTMP_PACKET_SIZE_MEDIUM,
                PacketType = RTMP_PACKET_TYPE_INVOKE,
                TimeStamp = 0,
                InfoField2 = 0,
                HasAbsTimestamp = false,
                Body = pbuf,
                BodySize = (uint)enc
            };

            return RTMP_SendPacket(r, packet, true);
        }

        // int RTMP_SendSeek(RTMP *r, int dTime);

        /// <summary> int RTMP_SendServerBW(RTMP *r);</summary>
        public static bool RTMP_SendServerBW(RTMP r)
        {
            byte[] pbuf = new byte[256];
            var pend = pbuf.Length;
            AMF.AMF_EncodeInt32(pbuf, 0, pend, (uint)r.m_nServerBW); //

            var packet = new RTMPPacket
            {
                ChannelNum = 0x02, /* control channel (invoke) */
                HeaderType = RTMP_PACKET_SIZE_LARGE,
                PacketType = RTMP_PACKET_TYPE_SERVER_BW,
                TimeStamp = 0,
                InfoField2 = 0,
                HasAbsTimestamp = false,
                Body = pbuf,
                BodySize = 4
            };

            return RTMP_SendPacket(r, packet, false);
        }

        // int RTMP_SendClientBW(RTMP *r);
        // void RTMP_DropRequest(RTMP *r, int i, int freeit);

        /// <summary> #define HEADRBUF (128*1024) </summary>
        private const int HEADERBUF = 128 * 1024;

        // static const char flvHeader[]
        private static readonly byte[] flvHeader =
        {
            (byte)'F', (byte)'L', (byte)'V', 0x01,
            0x00, /* 0x04 == audio, 0x01 == video */
            0x00, 0x00, 0x00, 0x09,
            0x00, 0x00, 0x00, 0x00
        };

        /// <summary> int RTMP_Read(RTMP *r, char *buf, int size); </summary>
        public static int RTMP_Read(RTMP r, byte[] buf, int size)
        {
            int nRead = 0, total = 0;

            /* can't continue */
        fail:
            // TODO: remove goto
            switch (r.m_read.status)
            {
                case RTMP_READ.RTMP_READ_EOF:
                case RTMP_READ.RTMP_READ_COMPLETE:
                    return 0;

                case RTMP_READ.RTMP_READ_ERROR: /* corrupted stream, resume failed */
                    // TODO: SetSockError(EINVAL);
                    return -1;
            }

            /* first time thru */
            if ((r.m_read.flags & RTMP_READ.RTMP_READ_HEADER) == 0x00)
            {
                if ((r.m_read.flags & RTMP_READ.RTMP_READ_RESUME) == 0x00)
                {
                    // char* mybuf = malloc(HEADERBUF),
                    var mybuf = new byte[HEADERBUF];
                    var end = HEADERBUF;
                    int cnt = 0;
                    var pmybuf = 0;
                    r.m_read.buf = mybuf;
                    r.m_read.buflen = HEADERBUF;

                    // memcpy(mybuf, flvHeader, sizeof (flvHeader));
                    Array.Copy(flvHeader, mybuf, flvHeader.Length);
                    pmybuf += flvHeader.Length; // r.m_read.buf += sizeof (flvHeader);
                    r.m_read.buflen -= flvHeader.Length;
                    cnt += flvHeader.Length;

                    while (r.m_read.timestamp == 0)
                    {
                        nRead = Read_1_Packet(r, r.m_read.buf, pmybuf, r.m_read.buflen);
                        if (nRead < 0)
                        {
                            // free(mybuf);
                            r.m_read.buf = null;
                            r.m_read.buflen = 0;
                            r.m_read.status = (sbyte)nRead;
                            goto fail;
                        }

                        /* buffer overflow, fix buffer and give up */
                        if (pmybuf < 0 || pmybuf > end)
                        {
                            var tbuf = new byte[cnt + nRead];
                            Array.Copy(mybuf, tbuf, cnt + nRead); // mybuf = realloc(mybuf, cnt + nRead);
                            Array.Copy(r.m_read.buf, pmybuf, tbuf, cnt, nRead); // TODO: // memcpy(mybuf + cnt, r.m_read.buf, nRead);
                            pmybuf = cnt + nRead; // r.m_read.buf = mybuf + cnt + nRead;
                            break;
                        }

                        cnt += nRead;
                        pmybuf += nRead; // r.m_read.buf += nRead;
                        r.m_read.buflen -= nRead;
                        if (r.m_read.dataType == 5)
                        {
                            break;
                        }
                    }

                    mybuf[4] = r.m_read.dataType;
                    r.m_read.buflen = pmybuf; // r.m_read.buf - mybuf;
                    r.m_read.buf = mybuf;
                    r.m_read.bufpos = 0; // mybuf;
                }

                r.m_read.flags |= RTMP_READ.RTMP_READ_HEADER;
            }

            if (((r.m_read.flags & RTMP_READ.RTMP_READ_SEEKING) != 0x00) && r.m_read.buf != null)
            {
                /* drop whatever's here */
                // free(r.m_read.buf);
                r.m_read.buf = null;
                r.m_read.bufpos = 0;
                r.m_read.buflen = 0;
            }

            var bufoffset = 0;
            /* If there's leftover data buffered, use it up */
            if (r.m_read.buf != null)
            {
                nRead = r.m_read.buflen;
                if (nRead > size)
                {
                    nRead = size;
                }

                Array.Copy(r.m_read.buf, r.m_read.bufpos, buf, bufoffset, nRead); // memcpy(buf, r.m_read.bufpos, nRead);
                r.m_read.buflen -= nRead;
                if (r.m_read.buflen != 0)
                {
                    // free(r.m_read.buf);
                    r.m_read.buf = null;
                    r.m_read.bufpos = 0;
                }
                else
                {
                    r.m_read.bufpos += nRead;
                }

                bufoffset += nRead; // buf += nRead;
                total += nRead;
                size -= nRead;
            }

            while (size > 0 && (nRead = Read_1_Packet(r, buf, bufoffset, size)) >= 0)
            {
                if (nRead == 0)
                {
                    continue;
                }

                bufoffset += nRead; // buf += nRead;
                total += nRead;
                size -= nRead;
                break;
            }

            if (nRead < 0)
            {
                r.m_read.status = (sbyte)nRead;
            }

            if (size < 0)
            {
                total += size;
            }

            return total;
        }

        // int RTMP_Write(RTMP *r, const char *buf, int size);

        /// <summary> static void SocksSetup</summary>
        private static void SocksSetup(RTMP r, AVal sockshost)
        {
            if (sockshost.av_len > 0)
            {
                var hostname = sockshost.av_val.TakeWhile(b => b != (byte)':').ToArray();
                r.Link.sockshost = new AVal(hostname);

                var socksport = sockshost.av_val.Contains((byte)':');
                if (socksport)
                {
                    var t = new string(sockshost.av_val.Select(b => (char)b).SkipWhile(c => c != ':').Skip(1).ToArray());
                    ushort port;
                    if (!ushort.TryParse(t, out port))
                    {
                        port = 1080;
                    }

                    r.Link.socksport = port;
                }

                Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "Connecting via SOCKS proxy: {0}:{1}", r.Link.sockshost.to_s(), r.Link.socksport);
            }
            else
            {
                r.Link.sockshost = new AVal(new byte[0]);
                r.Link.socksport = 0;
            }
        }

        /// <summary> static int SocksNegotiate(RTMP *r) </summary>
        /// <remarks> SOCKS proxy does not support </remarks>
        private static bool SocksNegotiate(RTMP r)
        {
            throw new NotImplementedException();
        }

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

        ///<summary> static int HTTP_Post(RTMP *r, RTMPTCmd cmd, const char *buf, int len) </summary>
        private static int HTTP_Post(RTMP r, RTMPTCmd cmd, byte[] data, int len)
        {
            var req = string.Join("\r\n",
                string.Format("POST /{0}{1}/{2} HTTP/1.1", RTMPT_cmds[cmd], r.m_clientID.to_s(), r.m_msgCounter),
                string.Format("Host: {0}:{1}", r.Link.hostname.to_s(), r.Link.port),
                "Accept: */*", "User-Agent: Shockwave Flash",
                "Connection: Keep-Alive",
                "Cache-Control: no-cache",
                "Content-type: application/x-fcs",
                string.Format("Content-length: {0}", len),
                string.Empty);
            var hbuf = req.ToCharArray().Select(c => (byte)c).ToArray();
            var hlen = hbuf.Length;
            RTMPSockBuf.RTMPSockBuf_Send(r.m_sb, hbuf, hlen);
            hlen = RTMPSockBuf.RTMPSockBuf_Send(r.m_sb, data, len);
            r.m_msgCounter++;
            r.m_unackd++;
            return hlen;
        }

        /// <summary> static int HTTP_read(RTMP *r, int fill)</summary>
        /// <remarks> TODO: rewrite by WebClient(?)</remarks>
        private static int HTTP_read(RTMP r, bool fill)
        {
            throw new NotImplementedException();
        }

#if CRYPTO
#else

        // static int HandShake(RTMP *r, int FP9HandShake)
        private static bool HandShake(RTMP r, int FP9HandShake)
        {
            const string __FUNCTION__ = "HandShake";

            byte[] clientbuf = new byte[RTMP_SIG_SIZE + 1];
            byte[] serversig = new byte[RTMP_SIG_SIZE];

            clientbuf[0] = 0x03; /* not encrypted */

            var uptime = (int)IPAddress.HostToNetworkOrder(RTMP_GetTime()); // htonl(RTMP_GetTime());
            var tmp = BitConverter.GetBytes(uptime);
            // memcpy(clientsig, &uptime, 4);
            for (var i = 0; i < 4; ++i)
            {
                clientbuf[1 + i] = tmp[i];
            }
            // memset(&clientsig[4], 0, 4);
            for (var i = 0; i < 4; ++i)
            {
                clientbuf[1 + 4 + i] = 0;
            }

#if DEBUG
            for (var i = 8; i < RTMP_SIG_SIZE; i++)
            {
                clientbuf[1 + i] = 0xff;
            }
#else
            var rand = new Random();
            tmp = new byte[RTMP_SIG_SIZE];
            rand.NextBytes(tmp);
            for (var i = 8; i < RTMP_SIG_SIZE - 1; i++)
            {
                // clientsig[i] = (char)(rand() % 256);
                clientbuf[1 + i] = tmp[i];
            }
#endif

            if (!WriteN(r, clientbuf, RTMP_SIG_SIZE + 1))
            {
                return false;
            }

            if (ReadN(r, tmp, 1) != 1) /* 0x03 or 0x06 */
            {
                return false;
            }

            var type = tmp[0];
            Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "{0}: Type Answer   : {1:X2}", __FUNCTION__, type);

            if (type != clientbuf[0])
            {
                Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGWARNING, "{0}: Type mismatch: client sent {1}, server answered {2}", __FUNCTION__, clientbuf[0], type);
            }

            if (ReadN(r, serversig, RTMP_SIG_SIZE) != RTMP_SIG_SIZE)
            {
                return false;
            }

            /* decode server response */
            int suptime = BitConverter.ToInt32(serversig, 0);
            // memcpy(&suptime, serversig, 4);
            // suptime = ntohl(suptime);
            suptime = IPAddress.NetworkToHostOrder(suptime);

            Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "{0}: Server Uptime : {1}", __FUNCTION__, suptime);
            Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "{0}: FMS Version   : {1}.{2}.{3}.{4}", __FUNCTION__, serversig[4], serversig[5], serversig[6], serversig[7]);

            /* 2nd part of handshake */
            if (!WriteN(r, serversig, RTMP_SIG_SIZE))
            {
                return false;
            }

            if (ReadN(r, serversig, RTMP_SIG_SIZE) != RTMP_SIG_SIZE)
            {
                return false;
            }

            var clientSig = clientbuf.Skip(1).Take(RTMP_SIG_SIZE).ToArray();

            var bMatch = clientSig.SequenceEqual(serversig); // (memcmp(serversig, clientsig, RTMP_SIG_SIZE) == 0);
            if (!bMatch)
            {
                Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGWARNING, "{0}, client signature does not match!", __FUNCTION__);
                Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "{0}, client signature = {1}\n", __FUNCTION__, clientSig[0]);
                Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "{0}, server signature = {1}\n", __FUNCTION__, serversig[0]);
            }

            return true;
        }

        /// <summary> static int SHandShake(RTMP *r) </summary>
        private static bool SHandShake(RTMP r)
        {
            const string __FUNCTION__ = "SHandShake";

            // char serverbuf[RTMP_SIG_SIZE + 1], *serversig = serverbuf + 1;
            byte[] serverbuf = new byte[RTMP_SIG_SIZE + 1];

            if (ReadN(r, serverbuf, 1) != 1) /* 0x03 or 0x06 */
            {
                return false;
            }

            Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "{0}: Type Request  : {1:X02}", __FUNCTION__, serverbuf[0]);

            if (serverbuf[0] != 3)
            {
                Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGERROR, "{0}: Type unknown: client sent {1:X02}", __FUNCTION__, serverbuf[0]);
                return false;
            }

            // uptime = htonl(RTMP_GetTime());
            var uptime = RTMP_GetTime();
            var tmp = BitConverter.GetBytes(uptime);
            // memcpy(serversig, &uptime, 4)
            AMF.memcpy(serverbuf, 1, tmp, 4);

            // memset(&serversig[4], 0, 4);
            AMF.memcpy(serverbuf, 1 + 4, new byte[4], 4);
#if DEBUG
            for (var i = 8; i < RTMP_SIG_SIZE; i++)
            {
                serverbuf[1 + i] = 0xff;
            }
#else
            var rand = new Random();
            tmp = new byte[RTMP_SIG_SIZE];
            rand.NextBytes(tmp);
            for (var i = 8; i < RTMP_SIG_SIZE; i++)
            {
                serverbuf[1 + i] = tmp[i];
            }
#endif

            if (!WriteN(r, serverbuf, RTMP_SIG_SIZE + 1))
            {
                return false;
            }

            // char clientsig[RTMP_SIG_SIZE];
            byte[] clientsig = new byte[RTMP_SIG_SIZE];
            if (ReadN(r, clientsig, RTMP_SIG_SIZE) != RTMP_SIG_SIZE)
            {
                return false;
            }

            /* decode client response */

            // memcpy(&uptime, clientsig, 4);
            uptime = BitConverter.ToUInt32(clientsig, 0);
            // uptime = IPAddress.NetworkToHostOrder(uptime);

            Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "{0}: Client Uptime : {1}", __FUNCTION__, uptime);
            Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "{0}: Player Version: {1}.{2}.{3}.{4}", __FUNCTION__,
                clientsig[4], clientsig[5], clientsig[6], clientsig[7]);

            /* 2nd part of handshake */
            if (!WriteN(r, clientsig, RTMP_SIG_SIZE))
            {
                return false;
            }

            if (ReadN(r, clientsig, RTMP_SIG_SIZE) != RTMP_SIG_SIZE)
            {
                return false;
            }

            var serversig = serverbuf.Skip(1).Take(RTMP_SIG_SIZE);
            var bMatch = serversig.SequenceEqual(clientsig); // (memcmp(serversig, clientsig, RTMP_SIG_SIZE) == 0);
            if (!bMatch)
            {
                Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGWARNING, "{0}, client signature does not match!", __FUNCTION__);
            }

            return true;
        }

#endif

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

        /// <summary> static int SendConnectPacket(RTMP *r, RTMPPacket* cp);</summary>
        private static bool SendConnectPacket(RTMP r, RTMPPacket cp)
        {
            const string __FUNCTION__ = "SendConnectPacket";
            const int PBUF_SIZE = 4096;

            if (cp != null)
            {
                return RTMP_SendPacket(r, cp, true);
            }

            var packet = new RTMPPacket
            {
                ChannelNum = 0x03,
                HeaderType = RTMP_PACKET_SIZE_LARGE,
                PacketType = RTMP_PACKET_TYPE_INVOKE,
                TimeStamp = 0,
                InfoField2 = 0,
                HasAbsTimestamp = false,
                Body = new byte[PBUF_SIZE - RTMP_MAX_HEADER_SIZE]
            };
            /* control channel (invoke) */

            var enc = 0;
            enc = AMF.AMF_EncodeString(packet.Body, enc, PBUF_SIZE, av_connect);
            enc = AMF.AMF_EncodeNumber(packet.Body, enc, PBUF_SIZE, ++r.m_numInvokes);
            packet.Body[enc++] = (byte)AMFDataType.AMF_OBJECT; // *enc++ = AMFDataType. AMF_OBJECT;

            enc = AMF.AMF_EncodeNamedString(packet.Body, enc, PBUF_SIZE, av_app, r.Link.app);
            if (enc == 0)
            {
                return false;
            }

            if ((r.Link.protocol & RTMP_FEATURE_WRITE) != 0x00)
            {
                enc = AMF.AMF_EncodeNamedString(packet.Body, enc, PBUF_SIZE, av_type, av_nonprivate);
                if (enc == 0)
                {
                    return false;
                }
            }

            if (r.Link.flashVer != null && r.Link.flashVer.av_len > 0)
            {
                enc = AMF.AMF_EncodeNamedString(packet.Body, enc, PBUF_SIZE, av_flashVer, r.Link.flashVer);
                if (enc == 0)
                {
                    return false;
                }
            }

            if (r.Link.swfUrl != null && r.Link.swfUrl.av_len > 0)
            {
                enc = AMF.AMF_EncodeNamedString(packet.Body, enc, PBUF_SIZE, av_swfUrl, r.Link.swfUrl);
                if (enc == 0)
                {
                    return false;
                }
            }

            if (r.Link.tcUrl != null && r.Link.tcUrl.av_len > 0)
            {
                enc = AMF.AMF_EncodeNamedString(packet.Body, enc, PBUF_SIZE, av_tcUrl, r.Link.tcUrl);
                if (enc == 0)
                {
                    return false;
                }
            }

            if ((r.Link.protocol & RTMP_FEATURE_WRITE) == 0x00)
            {
                enc = AMF.AMF_EncodeNamedBoolean(packet.Body, enc, PBUF_SIZE, av_fpad, false);
                if (enc == 0)
                {
                    return false;
                }

                enc = AMF.AMF_EncodeNamedNumber(packet.Body, enc, PBUF_SIZE, av_capabilities, 15.0);
                if (enc == 0)
                {
                    return false;
                }

                enc = AMF.AMF_EncodeNamedNumber(packet.Body, enc, PBUF_SIZE, av_audioCodecs, r.m_fAudioCodecs);
                if (enc == 0)
                {
                    return false;
                }

                enc = AMF.AMF_EncodeNamedNumber(packet.Body, enc, PBUF_SIZE, av_videoCodecs, r.m_fVideoCodecs);
                if (enc == 0)
                {
                    return false;
                }

                enc = AMF.AMF_EncodeNamedNumber(packet.Body, enc, PBUF_SIZE, av_videoFunction, 1.0);
                if (enc == 0)
                {
                    return false;
                }

                if (r.Link.pageUrl != null && r.Link.pageUrl.av_len > 0)
                {
                    enc = AMF.AMF_EncodeNamedString(packet.Body, enc, PBUF_SIZE, av_pageUrl, r.Link.pageUrl);
                    if (enc == 0)
                    {
                        return false;
                    }
                }
            }

            if (r.m_fEncoding != 0.0 || r.m_bSendEncoding != 0x00)
            {
                /* AMF0, AMF3 not fully supported yet */
                enc = AMF.AMF_EncodeNamedNumber(packet.Body, enc, PBUF_SIZE, av_objectEncoding, r.m_fEncoding);
                if (enc == 0)
                {
                    return false;
                }
            }

            if (enc + 3 >= PBUF_SIZE)
            {
                return false;
            }

            packet.Body[enc++] = 0;
            packet.Body[enc++] = 0; /* end of object - 0x00 0x00 0x09 */
            packet.Body[enc++] = (byte)AMFDataType.AMF_OBJECT_END;

            /* add auth string */
            if (r.Link.auth != null && r.Link.auth.av_len > 0)
            {
                enc = AMF.AMF_EncodeBoolean(packet.Body, enc, PBUF_SIZE, (r.Link.lFlags & RTMP_LNK.RTMP_LNK_FLAG.RTMP_LF_AUTH) != 0x00);
                if (enc == 0)
                {
                    return false;
                }

                enc = AMF.AMF_EncodeString(packet.Body, enc, PBUF_SIZE, r.Link.auth);
                if (enc == 0)
                {
                    return false;
                }
            }

            if (r.Link.extras != null && r.Link.extras.o_num > 0)
            {
                for (var i = 0; i < r.Link.extras.o_num; i++)
                {
                    enc = AMFObjectProperty.AMFProp_Encode(r.Link.extras.o_props[i], packet.Body, enc, PBUF_SIZE);
                    if (enc == 0)
                    {
                        return false;
                    }
                }
            }

            packet.BodySize = (uint)enc;

            return RTMP_SendPacket(r, packet, true);
        }

        /// <summary> static int WriteN(RTMP *r, const char *buffer, int n)</summary>
        private static bool WriteN(RTMP r, byte[] buffer, int n)
        {
            const string __FUNCTION__ = "WriteN";
#if CRYPTO
    char *encrypted = 0;
    char buf[RTMP_BUFFER_CACHE_SIZE];

    if (r.Link.rc4keyOut)
    {
        if (n > sizeof(buf))
            encrypted = (char *)malloc(n);
        else
            encrypted = (char *)buf;
        ptr = encrypted;
        RC4_encrypt2(r.Link.rc4keyOut, n, buffer, ptr);
    }
#endif
            // Log.RTMP_LogHexString(Log.RTMP_LogLevel.RTMP_LOGDEBUG2, buffer, (ulong)n);
            var ptr = 0;
            var userHttp = (r.Link.protocol & RTMP_FEATURE_HTTP) != 0x00;
            while (n > 0)
            {
                int nBytes = userHttp
                    ? HTTP_Post(r, RTMPTCmd.RTMPT_SEND, buffer.Skip(ptr).ToArray(), n)
                    : RTMPSockBuf.RTMPSockBuf_Send(r.m_sb, buffer.Skip(ptr).ToArray(), n);

                // Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "{0}: {1}\n", __FUNCTION__, nBytes);

                if (nBytes < 0)
                {
                    int sockerr = 0; // TODO: GetSockError();
                    Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGERROR, "{0}, RTMP send error {1} ({2} bytes)", __FUNCTION__, sockerr, n);

                    if (sockerr == 1 /*EINTR */&& !RTMP_ctrlC)
                    {
                        continue;
                    }

                    RTMP_Close(r);
                    n = 1;
                    break;
                }

                if (nBytes == 0)
                {
                    break;
                }

                n -= nBytes;
                ptr += nBytes;
            }

#if CRYPTO
    if (encrypted && encrypted != buf)
        free(encrypted);
#endif

            return n == 0;
        }

        /// <summary> static int ReadN(RTMP *r, char* buffer, int n)</summary>
        private static int ReadN(RTMP r, byte[] buffer, int n)
        {
            const string __FUNCTION__ = "ReadN";
            int nOriginalSize = n;

            r.m_sb.sb_timedout = false;

#if DEBUG
            // memset(buffer, 0, n);
            for (var i = 0; i < n; ++i)
            {
                buffer[i] = 0x00;
            }
#endif

            var ptr = 0;
            var useHttp = (r.Link.protocol & RTMP_FEATURE_HTTP) != 0x00;
            while (n > 0)
            {
                int nBytes = 0;
                int avail;
                if (useHttp)
                {
                    bool refill = false;
                    while (r.m_resplen != 0)
                    {
                        int ret;
                        if (r.m_sb.sb_size < 13 || refill)
                        {
                            if (r.m_unackd == 0)
                            {
                                HTTP_Post(r, RTMPTCmd.RTMPT_IDLE, new byte[1], 1);
                            }

                            if (RTMPSockBuf.RTMPSockBuf_Fill(r.m_sb) < 1)
                            {
                                if (!r.m_sb.sb_timedout)
                                {
                                    RTMP_Close(r);
                                }

                                return 0;
                            }
                        }

                        if ((ret = HTTP_read(r, false)) == -1)
                        {
                            Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "{0}, No valid HTTP response found", __FUNCTION__);
                            RTMP_Close(r);
                            return 0;
                        }
                        else if (ret == -2)
                        {
                            refill = true;
                        }
                        else
                        {
                            refill = false;
                        }
                    }

                    if (r.m_resplen != 0 && r.m_sb.sb_size == 0)
                    {
                        RTMPSockBuf.RTMPSockBuf_Fill(r.m_sb);
                    }

                    avail = r.m_sb.sb_size;
                    if (avail > r.m_resplen)
                    {
                        avail = r.m_resplen;
                    }
                }
                else
                {
                    avail = r.m_sb.sb_size;
                    if (avail == 0)
                    {
                        if (RTMPSockBuf.RTMPSockBuf_Fill(r.m_sb) < 1)
                        {
                            if (!r.m_sb.sb_timedout)
                            {
                                RTMP_Close(r);
                            }

                            return 0;
                        }

                        avail = r.m_sb.sb_size;
                    }
                }

                var nRead = ((n < avail) ? n : avail);
                if (nRead > 0)
                {
                    // memcpy(ptr, r.m_sb.sb_start, nRead);
                    Array.Copy(r.m_sb.sb_buf, r.m_sb.sb_start, buffer, ptr, nRead);
                    r.m_sb.sb_start += nRead;
                    r.m_sb.sb_size -= nRead;
                    nBytes = nRead;
                    r.m_nBytesIn += nRead;
                    if (r.m_bSendCounter && r.m_nBytesIn > (r.m_nBytesInSent + r.m_nClientBW / 10))
                    {
                        if (!SendBytesReceived(r))
                        {
                            return 0;
                        }
                    }
                }

                /*Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "%s: %d bytes\n", __FUNCTION__, nBytes); */
#if _DEBUG
                fwrite(ptr, 1, nBytes, netstackdump_read);
#endif

                if (nBytes == 0)
                {
                    Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "{0}, RTMP socket closed by peer", __FUNCTION__);
                    /*goto again; */
                    RTMP_Close(r);
                    break;
                }

                if (useHttp)
                {
                    r.m_resplen -= nBytes;
                }

#if CRYPTO
                if (r.Link.rc4keyIn)
                {
                    RC4_encrypt(r.Link.rc4keyIn, nBytes, ptr);
                }
#endif

                n -= nBytes;
                ptr += nBytes;
            }

            return nOriginalSize - n;
        }

        /// <summary> static int SendBytesReceived(RTMP *r)</summary>
        private static bool SendBytesReceived(RTMP r)
        {
            var packet = new RTMPPacket
            {
                ChannelNum = 0x02,
                HeaderType = RTMP_PACKET_SIZE_MEDIUM,
                PacketType = RTMP_PACKET_TYPE_BYTES_READ_REPORT,
                TimeStamp = 0,
                InfoField2 = 0,
                HasAbsTimestamp = false,
                Body = new byte[256],
                BodySize = 4
            };

            /* control channel (invoke) */
            var pend = packet.Body.Length;
            AMF.AMF_EncodeInt32(packet.Body, 0, pend, (uint)r.m_nBytesIn); /* hard coded for now */
            r.m_nBytesInSent = r.m_nBytesIn;

            /*Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "Send bytes report. 0x%x (%d bytes)", (unsigned int)m_nBytesIn, m_nBytesIn); */
            return RTMP_SendPacket(r, packet, false);
        }

#if UNUSE
    /// <summary> static void AV_queue(RTMP_METHOD** vals, int* num, AVal* av, int txn)</summary>
        private static void AV_queue(RTMP_METHOD[] vals, ref int num, AVal av, int txn)
        {
            // char* tmp;
            if ((num & 0x0f) == 0x00)
            {
                // *vals = realloc(*vals, (*num + 16) * sizeof(RTMP_METHOD));
                var ms = new RTMP_METHOD[num + 16];
                for (var i = 0; i < num; ++i)
                {
                    ms[i] = vals[i];
                }

                vals = ms;
            }

            // tmp = malloc(av.av_len + 1);
            var tmp = new byte[av.av_len + 1];

            // memcpy(tmp, av.av_val, av.av_len);
            for (var i = 0; i < av.av_len; ++i)
            {
                tmp[i] = av.av_val[i];
            }

            tmp[av.av_len] = 0; // '\0'
            var m = new RTMP_METHOD
            {
                num = txn,
                name = new AVal(tmp)
                {
                    av_len = av.av_len
                }
            };
            // (*vals)[num].num = txn;
            // (*vals)[num].name.av_len = av.av_len;
            // (*vals)[(*num)++].name.av_val = tmp;
            vals[num] = m;
            num += 1;
        }

        /// <summary> static void AV_clear(RTMP_METHOD* vals, int num)</summary>
        private static void AV_clear(RTMP_METHOD[] vals, int num)
        {
            // for (var i = 0; i < num; i++) free(vals[i].name.av_val);
            // free(vals);
        }

        /// <summary> static void AV_erase(RTMP_METHOD *vals, int *num, int i, int freeit)</summary>
        private static void AV_erase(RTMP_METHOD[] vals, ref int num, int i, bool freeit)
        {
            if (freeit)
            {
                vals[i].name.av_val = null; // free(vals[i].name.av_val);
            }

            num--;
            for (; i < num; i++)
            {
                vals[i] = vals[i + 1];
            }

            vals[i].name.av_val = null;
            vals[i].name.av_len = 0;
            vals[i].num = 0;
        }
#endif

        /// <summary> static void CloseInternal(RTMP *r, int reconnect)</summary>
        private static void CloseInternal(RTMP r, bool reconnect)
        {
            if (RTMP_IsConnected(r))
            {
                if (r.m_stream_id > 0)
                {
                    var i = r.m_stream_id;
                    r.m_stream_id = 0;
                    if ((r.Link.protocol & RTMP_FEATURE_WRITE) != 0x00)
                    {
                        SendFCUnpublish(r);
                    }

                    SendDeleteStream(r, i);
                }

                if (r.m_clientID != null)
                {
                    HTTP_Post(r, RTMPTCmd.RTMPT_CLOSE, new byte[1], 1);
                    // free(r.m_clientID.av_val);
                    r.m_clientID.av_val = null;
                    r.m_clientID.av_len = 0;
                }

                RTMPSockBuf.RTMPSockBuf_Close(r.m_sb);
            }

            r.m_stream_id = -1;
            r.m_sb.sb_socket = null;
            r.m_nBWCheckCounter = 0;
            r.m_nBytesIn = 0;
            r.m_nBytesInSent = 0;

            if ((r.m_read.flags & RTMP_READ.RTMP_READ_HEADER) != 0x00)
            {
                // free(r.m_read.buf);
                r.m_read.buf = null;
            }
            r.m_read.dataType = 0;
            r.m_read.flags = 0;
            r.m_read.status = 0;
            r.m_read.nResumeTS = 0;
            r.m_read.nIgnoredFrameCounter = 0;
            r.m_read.nIgnoredFlvFrameCounter = 0;

            r.m_write.BytesRead = 0;
            RTMPPacket.RTMPPacket_Free(r.m_write);

            for (var i = 0; i < r.m_channelsAllocatedIn; i++)
            {
                if (r.m_vecChannelsIn[i] != null)
                {
                    RTMPPacket.RTMPPacket_Free(r.m_vecChannelsIn[i]);
                    // free(r.m_vecChannelsIn[i]);
                    r.m_vecChannelsIn[i] = null;
                }
            }
            // free(r.m_vecChannelsIn);
            r.m_vecChannelsIn = null;
            // free(r.m_channelTimestamp);
            r.m_channelTimestamp = null;
            r.m_channelsAllocatedIn = 0;
            for (var i = 0; i < r.m_channelsAllocatedOut; i++)
            {
                if (r.m_vecChannelsOut[i] != null)
                {
                    // free(r.m_vecChannelsOut[i]);
                    r.m_vecChannelsOut[i] = null;
                }
            }
            // free(r.m_vecChannelsOut);
            r.m_vecChannelsOut = null;
            r.m_channelsAllocatedOut = 0;
            // AV_clear(r.m_methodCalls, r.m_numCalls);
            r.m_methodCalls.Clear();
            r.m_methodCalls = null;
            r.m_numCalls = 0;
            r.m_numInvokes = 0;

            r.m_bPlaying = false;
            r.m_sb.sb_size = 0;

            r.m_msgCounter = 0;
            r.m_resplen = 0;
            r.m_unackd = 0;

            if ((r.Link.lFlags & RTMP_LNK.RTMP_LNK_FLAG.RTMP_LF_FTCU) != 0x00 && !reconnect)
            {
                r.Link.tcUrl.av_val = null;
                r.Link.lFlags ^= RTMP_LNK.RTMP_LNK_FLAG.RTMP_LF_FTCU;
            }

            if ((r.Link.lFlags & RTMP_LNK.RTMP_LNK_FLAG.RTMP_LF_FAPU) != 0x00 && !reconnect)
            {
                r.Link.app.av_val = null;
                r.Link.lFlags ^= RTMP_LNK.RTMP_LNK_FLAG.RTMP_LF_FAPU;
            }

            if (!reconnect)
            {
                r.Link.playpath0 = null;
            }
#if CRYPTO
            if (r.Link.dh)
            {
                MDH_free(r.Link.dh);
                r.Link.dh = null;
            }

            if (r.Link.rc4keyIn)
            {
                RC4_free(r.Link.rc4keyIn);
                r.Link.rc4keyIn = null;
            }

            if (r.Link.rc4keyOut)
            {
                RC4_free(r.Link.rc4keyOut);
                r.Link.rc4keyOut = null;
            }
#endif
        }

        /// <summary> static int SendFCUnpublish(RTMP *r)</summary>
        private static bool SendFCUnpublish(RTMP r)
        {
            var pbuf = new Byte[1024];
            int pend = pbuf.Length;

            var enc = 0; // char* enc;
            enc = AMF.AMF_EncodeString(pbuf, enc, pend, av_FCUnpublish);
            enc = AMF.AMF_EncodeNumber(pbuf, enc, pend, ++r.m_numInvokes);
            pbuf[enc++] = (byte)AMFDataType.AMF_NULL;
            enc = AMF.AMF_EncodeString(pbuf, enc, pend, r.Link.playpath);
            if (enc == 0)
            {
                return false;
            }

            var packet = new RTMPPacket
            {
                ChannelNum = 0x03, /* control channel (invoke) */
                HeaderType = RTMP_PACKET_SIZE_MEDIUM,
                PacketType = RTMP_PACKET_TYPE_INVOKE,
                TimeStamp = 0,
                InfoField2 = 0,
                HasAbsTimestamp = false,
                Body = pbuf,
                BodySize = (uint)enc
            };

            // - packet.Body;

            return RTMP_SendPacket(r, packet, false);
        }

        /// <summary> static int SendDeleteStream(RTMP *r, double dStreamId)</summary>
        private static bool SendDeleteStream(RTMP r, double streamId)
        {
            var pbuf = new byte[256];
            var pend = pbuf.Length;
            var enc = 0; // packet.Body;
            enc = AMF.AMF_EncodeString(pbuf, enc, pend, av_deleteStream);
            enc = AMF.AMF_EncodeNumber(pbuf, enc, pend, ++r.m_numInvokes);
            pbuf[enc++] = (byte)AMFDataType.AMF_NULL;
            enc = AMF.AMF_EncodeNumber(pbuf, enc, pend, streamId);

            var packet = new RTMPPacket
            {
                ChannelNum = 0x03, /* control channel (invoke) */
                HeaderType = RTMP_PACKET_SIZE_MEDIUM,
                PacketType = RTMP_PACKET_TYPE_INVOKE,
                TimeStamp = 0,
                InfoField2 = 0,
                HasAbsTimestamp = false,
                Body = pbuf,
                BodySize = (uint)enc
            };

            /* no response expected */
            return RTMP_SendPacket(r, packet, false);
        }

        /// <summary>
        /// static int HandleInvoke(RTMP *r, const char *body, unsigned int nBodySize)
        /// /* Returns 0 for OK/Failed/error, 1 for 'Stop or Complete' */
        /// </summary>
        private static int HandleInvoke(RTMP r, byte[] body, int offset, uint nBodySize)
        {
            const string __FUNCTION__ = "HandleInvoke";
            if (body[0] != 0x02) /* make sure it is a string method name we start with */
            {
                Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGWARNING, "{0}, Sanity failed. no string method in invoke packet",
                    __FUNCTION__);
                return 0;
            }

            AMFObject obj = new AMFObject();
            int ret = 0;
            var nRes = AMFObject.AMF_Decode(obj, body, offset, (int)nBodySize, false);
            if (nRes < 0)
            {
                Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGERROR, "{0}, error decoding invoke packet", __FUNCTION__);
                return 0;
            }

            AMFObject.AMF_Dump(obj);
            AVal method;
            AMFObjectProperty.AMFProp_GetString(AMFObject.AMF_GetProp(obj, null, 0), out method);
            var txn = AMFObjectProperty.AMFProp_GetNumber(AMFObject.AMF_GetProp(obj, null, 1));
            Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "{0}, server invoking <{1}>", __FUNCTION__, method.to_s());

            if (AVal.Match(method, av__result))
            {
                AVal methodInvoked = null; // = { 0 };

                for (var i = 0; i < r.m_numCalls; i++)
                {
                    if (r.m_methodCalls[i].num == (int)txn)
                    {
                        methodInvoked = r.m_methodCalls[i].name;
                        // AV_erase(r.m_methodCalls, ref n, i, false);
                        r.m_methodCalls.RemoveAt(i);
                        r.m_numCalls--;
                        break;
                    }
                }

                if (methodInvoked == null)
                {
                    Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "{0}, received result id {1} without matching request", __FUNCTION__, txn);
                    goto leave;
                }

                Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "{0}, received result for method call <{1}>", __FUNCTION__, methodInvoked.to_s());

                if (AVal.Match(methodInvoked, av_connect))
                {
                    if (r.Link.token != null && r.Link.token.av_len != 0)
                    {
                        AMFObjectProperty p;
                        if (RTMP_FindFirstMatchingProperty(obj, av_secureToken, out p))
                        {
                            DecodeTEA(r.Link.token, p.p_aval);
                            SendSecureTokenResponse(r, p.p_aval);
                        }
                    }

                    if ((r.Link.protocol & RTMP_FEATURE_WRITE) != 0x00)
                    {
                        SendReleaseStream(r);
                        SendFCPublish(r);
                    }
                    else
                    {
                        RTMP_SendServerBW(r);
                        RTMP_SendCtrl(r, 3, 0, 300);
                    }

                    RTMP_SendCreateStream(r);

                    if ((r.Link.protocol & RTMP_FEATURE_WRITE) == 0x00)
                    {
                        /* Authenticate on Justin.tv legacy servers before sending FCSubscribe */
                        if (r.Link.usherToken != null && r.Link.usherToken.av_len != 0)
                        {
                            SendUsherToken(r, r.Link.usherToken);
                        }

                        /* Send the FCSubscribe if live stream or if subscribepath is set */
                        if (r.Link.subscribepath != null && r.Link.subscribepath.av_len != 0)
                        {
                            SendFCSubscribe(r, r.Link.subscribepath);
                        }
                        else if ((r.Link.lFlags & RTMP_LNK.RTMP_LNK_FLAG.RTMP_LF_LIVE) != 0x00)
                        {
                            SendFCSubscribe(r, r.Link.playpath);
                        }
                    }
                }
                else if (AVal.Match(methodInvoked, av_createStream))
                {
                    r.m_stream_id = (int)AMFObjectProperty.AMFProp_GetNumber(AMFObject.AMF_GetProp(obj, null, 3));

                    if ((r.Link.protocol & RTMP_FEATURE_WRITE) != 0x00)
                    {
                        SendPublish(r);
                    }
                    else
                    {
                        if ((r.Link.lFlags & RTMP_LNK.RTMP_LNK_FLAG.RTMP_LF_PLST) != 0x00)
                        {
                            SendPlaylist(r);
                        }

                        SendPlay(r);
                        RTMP_SendCtrl(r, 3, (uint)r.m_stream_id, (uint)r.m_nBufferMS);
                    }
                }
                else if (AVal.Match(methodInvoked, av_play)
                         || AVal.Match(methodInvoked, av_publish))
                {
                    r.m_bPlaying = true;
                }

                // free(methodInvoked.av_val);
                methodInvoked.av_val = null;
            }
            else if (AVal.Match(method, av_onBWDone))
            {
                if (r.m_nBWCheckCounter == 0)
                {
                    SendCheckBW(r);
                }
            }
            else if (AVal.Match(method, av_onFCSubscribe))
            {
                /* SendOnFCSubscribe(); */
            }
            else if (AVal.Match(method, av_onFCUnsubscribe))
            {
                RTMP_Close(r);
                ret = 1;
            }
            else if (AVal.Match(method, av_ping))
            {
                SendPong(r, txn);
            }
            else if (AVal.Match(method, av__onbwcheck))
            {
                SendCheckBWResult(r, txn);
            }
            else if (AVal.Match(method, av__onbwdone))
            {
                for (var i = 0; i < r.m_numCalls; i++)
                {
                    if (AVal.Match(r.m_methodCalls[i].name, av__checkbw))
                    {
                        // AV_erase(r.m_methodCalls, ref n, i, true);
                        r.m_methodCalls.RemoveAt(i);
                        r.m_numCalls--;
                        break;
                    }
                }
            }
            else if (AVal.Match(method, av__error))
            {
#if CRYPTO
                AVal methodInvoked = { 0 };
                int i;

                if (r.Link.protocol & RTMP_FEATURE_WRITE)
                {
                    for (i = 0; i < r.m_numCalls; i++)
                    {
                        if (r.m_methodCalls[i].num == txn)
                        {
                            methodInvoked = r.m_methodCalls[i].name;
                            AV_erase(r.m_methodCalls, &r.m_numCalls, i, false);
                            break;
                        }
                    }
                    if (!methodInvoked.av_val)
                    {
                        Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "{0}, received result id %f without matching request",
                            __FUNCTION__, txn);
                        goto leave;
                    }

                    Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "{0}, received error for method call <%s>", __FUNCTION__,
                        methodInvoked.av_val);

                    if (AVal.Match(&methodInvoked, &av_connect))
                    {
                        AMFObject obj2;
                        AVal code, level, description;
                        AMFProp_GetObject(AMFObject.AMF_GetProp(obj, null, 3), obj2);
                        AMFProp_GetString(AMFObject.AMF_GetProp(obj2, &av_code, -1), &code);
                        AMFProp_GetString(AMFObject.AMF_GetProp(obj2, &av_level, -1), &level);
                        AMFProp_GetString(AMFObject.AMF_GetProp(obj2, &av_description, -1), &description);
                        Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "{0}, error description: %s", __FUNCTION__, description.av_val);
                        /* if PublisherAuth returns 1, then reconnect */
                        if (PublisherAuth(r, &description) == 1)
                        {
                            CloseInternal(r, 1);
                            if (!RTMP_Connect(r, null) || !RTMP_ConnectStream(r, 0))
                                goto leave;
                        }
                    }
                }
                else
                {
                    Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGERROR, "rtmp server sent error");
                }
                free(methodInvoked.av_val);
#else
                Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGERROR, "rtmp server sent error");
#endif
            }
            else if (AVal.Match(method, av_close))
            {
                Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGERROR, "rtmp server requested close");
                RTMP_Close(r);
            }
            else if (AVal.Match(method, av_onStatus))
            {
                AMFObject obj2;
                AVal code, level;
                AMFObjectProperty.AMFProp_GetObject(AMFObject.AMF_GetProp(obj, null, 3), out obj2);
                AMFObjectProperty.AMFProp_GetString(AMFObject.AMF_GetProp(obj2, av_code, -1), out code);
                AMFObjectProperty.AMFProp_GetString(AMFObject.AMF_GetProp(obj2, av_level, -1), out level);

                Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "{0}, onStatus: {1}", __FUNCTION__, code.to_s());
                if (AVal.Match(code, av_NetStream_Failed)
                    || AVal.Match(code, av_NetStream_Play_Failed)
                    || AVal.Match(code, av_NetStream_Play_StreamNotFound)
                    || AVal.Match(code, av_NetConnection_Connect_InvalidApp))
                {
                    r.m_stream_id = -1;
                    RTMP_Close(r);
                    Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGERROR, "Closing connection: {0}", code.to_s());
                }
                else if (AVal.Match(code, av_NetStream_Play_Start)
                         || AVal.Match(code, av_NetStream_Play_PublishNotify))
                {
                    r.m_bPlaying = true;
                    for (var i = 0; i < r.m_numCalls; i++)
                    {
                        if (AVal.Match(r.m_methodCalls[i].name, av_play))
                        {
                            // AV_erase(r.m_methodCalls, ref n, i, true);
                            r.m_methodCalls.RemoveAt(i);
                            r.m_numCalls--;
                            break;
                        }
                    }
                }
                else if (AVal.Match(code, av_NetStream_Publish_Start))
                {
                    r.m_bPlaying = true;
                    for (var i = 0; i < r.m_numCalls; i++)
                    {
                        if (AVal.Match(r.m_methodCalls[i].name, av_publish))
                        {
                            // var n = r.m_numCalls;
                            // AV_erase(r.m_methodCalls, ref n, i, true);
                            r.m_methodCalls.RemoveAt(i);
                            r.m_numCalls--;
                            break;
                        }
                    }
                }

                /* Return 1 if this is a Play.Complete or Play.Stop */
                else if (AVal.Match(code, av_NetStream_Play_Complete)
                         || AVal.Match(code, av_NetStream_Play_Stop)
                         || AVal.Match(code, av_NetStream_Play_UnpublishNotify))
                {
                    RTMP_Close(r);
                    ret = 1;
                }
                else if (AVal.Match(code, av_NetStream_Seek_Notify))
                {
                    r.m_read.flags &= ((~RTMP_READ.RTMP_READ_SEEKING) & 0xFF); // (~RTMP_READ.RTMP_READ_SEEKING);
                }
                else if (AVal.Match(code, av_NetStream_Pause_Notify))
                {
                    if (r.m_pausing == 1 || r.m_pausing == 2)
                    {
                        RTMP_SendPause(r, false, (int)r.m_pauseStamp); // TODO:
                        r.m_pausing = 3;
                    }
                }
            }
            else if (AVal.Match(method, av_playlist_ready))
            {
                for (var i = 0; i < r.m_numCalls; i++)
                {
                    if (AVal.Match(r.m_methodCalls[i].name, av_set_playlist))
                    {
                        // var n = r.m_numCalls;
                        // AV_erase(r.m_methodCalls, ref n, i, true);
                        r.m_methodCalls.RemoveAt(i);
                        r.m_numCalls--;
                        break;
                    }
                }
            }
            else
            {
            }
        leave:
            AMFObject.AMF_Reset(obj);
            return ret;
        }

        /// <summary> static int HandleMetadata(RTMP *r, char *body, unsigned int len)</summary>
        private static bool HandleMetadata(RTMP r, byte[] body, int offset, uint len)
        {
            const string __FUNCTION__ = "HandleMetadata";
            /* allright we get some info here, so parse it and print it */
            /* also keep duration or filesize to make a nice progress bar */

            AMFObject obj = new AMFObject();
            AVal metastring;
            bool ret = false;

            int nRes = AMFObject.AMF_Decode(obj, body, offset, (int)len, false); // TODO:uint
            if (nRes < 0)
            {
                Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGERROR, "{0}, error decoding meta data packet", __FUNCTION__);
                return false;
            }

            AMFObject.AMF_Dump(obj);
            AMFObjectProperty.AMFProp_GetString(AMFObject.AMF_GetProp(obj, null, 0), out metastring);

            if (AVal.Match(metastring, av_onMetaData))
            {
                AMFObjectProperty prop;
                /* Show metadata */
                Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGINFO, "Metadata:");
                DumpMetaData(obj);
                if (RTMP_FindFirstMatchingProperty(obj, av_duration, out prop))
                {
                    r.m_fDuration = prop.p_number;
                    /*Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "Set duration: %.2f", m_fDuration); */
                }

                /* Search for audio or video tags */
                if (RTMP_FindPrefixProperty(obj, av_video, out prop))
                {
                    r.m_read.dataType |= 1;
                }

                if (RTMP_FindPrefixProperty(obj, av_audio, out prop))
                {
                    r.m_read.dataType |= 4;
                }

                ret = true;
            }

            AMFObject.AMF_Reset(obj);
            return ret;
        }

        /// <summary> static void HandleChangeChunkSize(RTMP *r, const RTMPPacket *packet)</summary>
        private static void HandleChangeChunkSize(RTMP r, RTMPPacket packet)
        {
            const string __FUNCTION__ = "HandleChangeChunkSize";
            if (packet.BodySize >= 4)
            {
                r.m_inChunkSize = (int)AMF.AMF_DecodeInt32(packet.Body);
                Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "{0}, received: chunk size change to {1}", __FUNCTION__, r.m_inChunkSize);
            }
        }

        /// <summary> static void HandleAudio(RTMP *r, const RTMPPacket *packet)</summary>
        private static void HandleAudio(RTMP r, RTMPPacket packet)
        {
        }

        /// <summary> static void HandleVideo(RTMP *r, const RTMPPacket *packet)</summary>
        private static void HandleVideo(RTMP r, RTMPPacket packet)
        {
        }

        /// <summary> static void HandleCtrl(RTMP *r, const RTMPPacket *packet)</summary>
        private static void HandleCtrl(RTMP r, RTMPPacket packet)
        {
            const string __FUNCTION__ = "HandleCtrl";
            short nType = -1;
            if (packet.Body != null && packet.BodySize >= 2)
            {
                nType = (short)AMF.AMF_DecodeInt16(packet.Body);
            }

            Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "{0}, received ctrl. type: {1}, len: {2}", __FUNCTION__, nType,
                packet.BodySize);
            /*RTMP_LogHex(packet.Body, packet.BodySize); */

            if (packet.BodySize >= 6)
            {
                uint tmp;
                switch (nType)
                {
                    case 0:
                        tmp = AMF.AMF_DecodeInt32(packet.Body, 2);
                        Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "{0}, Stream Begin {1}", __FUNCTION__, tmp);
                        break;

                    case 1:
                        tmp = AMF.AMF_DecodeInt32(packet.Body, 2);
                        Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "{0}, Stream EOF {1}", __FUNCTION__, tmp);
                        if (r.m_pausing == 1)
                        {
                            r.m_pausing = 2;
                        }

                        break;

                    case 2:
                        tmp = AMF.AMF_DecodeInt32(packet.Body, 2);
                        Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "{0}, Stream Dry {1}", __FUNCTION__, tmp);
                        break;

                    case 4:
                        tmp = AMF.AMF_DecodeInt32(packet.Body, 2);
                        Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "{0}, Stream IsRecorded {1}", __FUNCTION__, tmp);
                        break;

                    case 6: /* server ping. reply with pong. */
                        tmp = AMF.AMF_DecodeInt32(packet.Body, 2);
                        Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "{0}, Ping {1}", __FUNCTION__, tmp);
                        RTMP_SendCtrl(r, 0x07, tmp, 0);
                        break;

                    /*
                     * FMS 3.5 servers send the following two controls to let the client
                     * know when the server has sent a complete buffer. I.e., when the
                     * server has sent an amount of data equal to m_nBufferMS in duration.
                     * The server meters its output so that data arrives at the client
                     * in realtime and no faster.
                     *
                     * The rtmpdump program tries to set m_nBufferMS as large as
                     * possible, to force the server to send data as fast as possible.
                     * In practice, the server appears to cap this at about 1 hour's
                     * worth of data. After the server has sent a complete buffer, and
                     * sends this BufferEmpty message, it will wait until the play
                     * duration of that buffer has passed before sending a new buffer.
                     * The BufferReady message will be sent when the new buffer starts.
                     * (There is no BufferReady message for the very first buffer;
                     * presumably the Stream Begin message is sufficient for that
                     * purpose.)
                     *
                     * If the network speed is much faster than the data bitrate, then
                     * there may be long delays between the end of one buffer and the
                     * start of the next.
                     *
                     * Since usually the network allows data to be sent at
                     * faster than realtime, and rtmpdump wants to download the data
                     * as fast as possible, we use this RTMP_LF_BUFX hack: when we
                     * get the BufferEmpty message, we send a Pause followed by an
                     * Unpause. This causes the server to send the next buffer immediately
                     * instead of waiting for the full duration to elapse. (That's
                     * also the purpose of the ToggleStream function, which rtmpdump
                     * calls if we get a read timeout.)
                     *
                     * Media player apps don't need this hack since they are just
                     * going to play the data in realtime anyway. It also doesn't work
                     * for live streams since they obviously can only be sent in
                     * realtime. And it's all moot if the network speed is actually
                     * slower than the media bitrate.
                     */
                    case 31:
                        tmp = AMF.AMF_DecodeInt32(packet.Body, 2);
                        Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "{0}, Stream BufferEmpty {1}", __FUNCTION__, tmp);
                        if ((r.Link.lFlags & RTMP_LNK.RTMP_LNK_FLAG.RTMP_LF_BUFX) != 0x00)
                        {
                            break;
                        }

                        if (r.m_pausing != 0)
                        {
                            r.m_pauseStamp = (uint)(r.m_mediaChannel < r.m_channelsAllocatedIn ? r.m_channelTimestamp[r.m_mediaChannel] : 0); // TODO:
                            RTMP_SendPause(r, true, (int)r.m_pauseStamp); // TODO:
                            r.m_pausing = 1;
                        }
                        else if (r.m_pausing == 2)
                        {
                            RTMP_SendPause(r, false, (int)r.m_pauseStamp); // TODO:
                            r.m_pausing = 3;
                        }
                        break;

                    case 32:
                        tmp = AMF.AMF_DecodeInt32(packet.Body, 2);
                        Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "{0}, Stream BufferReady {1}", __FUNCTION__, tmp);
                        break;

                    default:
                        tmp = AMF.AMF_DecodeInt32(packet.Body, 2);
                        Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "{0}, Stream xx {1}", __FUNCTION__, tmp);
                        break;
                }
            }

            if (nType == 0x1A)
            {
                Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "{0}, SWFVerification ping received: ", __FUNCTION__);
                if (packet.BodySize > 2 && packet.Body[2] > 0x01)
                {
                    Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGERROR,
                        "{0}: SWFVerification Type {1} request not supported! Patches welcome...",
                        __FUNCTION__, packet.Body[2]);
                }
#if CRYPTO
    /*RTMP_LogHex(packet.Body, packet.BodySize); */

    /* respond with HMAC SHA256 of decompressed SWF, key is the 30byte player key, also the last 30 bytes of the server handshake are applied */
                else if (r.Link.SWFSize != 0x00)
                {
                    RTMP_SendCtrl(r, 0x1B, 0, 0);
                }
                else
                {
                    Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGERROR, "{0}: Ignoring SWFVerification request, use --swfVfy!", __FUNCTION__);
                }
#else
                Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGERROR, "{0}: Ignoring SWFVerification request, no CRYPTO support!", __FUNCTION__);
#endif
            }
        }

        /// <summary> static void HandleServerBW(RTMP *r, const RTMPPacket *packet)</summary>
        private static void HandleServerBW(RTMP r, RTMPPacket packet)
        {
            const string __FUNCTION__ = "HandleServerBW";
            r.m_nServerBW = (int)AMF.AMF_DecodeInt32(packet.Body); // TODO:
            Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "{0}: server BW = {1}", __FUNCTION__, r.m_nServerBW);
        }

        /// <summary> static void HandleClientBW(RTMP *r, const RTMPPacket *packet)</summary>
        private static void HandleClientBW(RTMP r, RTMPPacket packet)
        {
            const string __FUNCTION__ = "HandleClientBW";
            r.m_nClientBW = (int)AMF.AMF_DecodeInt32(packet.Body); // TODO:
            if (packet.BodySize > 4)
            {
                r.m_nClientBW2 = packet.Body[4];
            }
            else
            {
                r.m_nClientBW2 = 0xFF; //-1;
            }

            Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "{0}: client BW = {1} {2}", __FUNCTION__, r.m_nClientBW, r.m_nClientBW2);
        }

        /// <summary> #define HEX2BIN(a)	(((a)&0x40)?((a)&0xf)+9:((a)&0xf))</summary>
        private static byte HEX2BIN(byte a)
        {
            return (byte)((a & 0x40) != 0x00 ? ((a & 0x0f) + 9) : (a & 0x0f));
        }

        /// <summary> static void DecodeTEA(AVal *key, AVal *test)</summary>
        private static void DecodeTEA(AVal key, AVal text)
        {
            throw new NotImplementedException();
        }

        /// <summary> static int SendSecureTokenResponse(RTMP *r, AVal *resp)</summary>
        private static bool SendSecureTokenResponse(RTMP r, AVal resp)
        {
            var pbuf = new byte[1024];
            var pend = pbuf.Length;
            var enc = 0;
            enc = AMF.AMF_EncodeString(pbuf, enc, pend, av_secureTokenResponse);
            enc = AMF.AMF_EncodeNumber(pbuf, enc, pend, 0.0);
            pbuf[enc++] = (byte)AMFDataType.AMF_NULL;
            enc = AMF.AMF_EncodeString(pbuf, enc, pend, resp);
            if (enc == 0)
            {
                return false;
            }

            var packet = new RTMPPacket
            {
                ChannelNum = 0x03, /* control channel (invoke) */
                HeaderType = RTMP_PACKET_SIZE_MEDIUM,
                PacketType = RTMP_PACKET_TYPE_INVOKE,
                TimeStamp = 0,
                InfoField2 = 0,
                HasAbsTimestamp = false,
                Body = pbuf,
                BodySize = (uint)enc
            };

            return RTMP_SendPacket(r, packet, false);
        }

        /// <summary> static int SendReleaseStream(RTMP *r)</summary>
        private static bool SendReleaseStream(RTMP r)
        {
            var pbuf = new byte[1024];
            var pend = pbuf.Length;
            var enc = 0;
            enc = AMF.AMF_EncodeString(pbuf, enc, pend, av_releaseStream);
            enc = AMF.AMF_EncodeNumber(pbuf, enc, pend, ++r.m_numInvokes);
            pbuf[enc++] = (byte)AMFDataType.AMF_NULL;
            enc = AMF.AMF_EncodeString(pbuf, enc, pend, r.Link.playpath);
            if (enc == 0)
            {
                return false;
            }

            var packet = new RTMPPacket
            {
                ChannelNum = 0x03, /* control channel (invoke) */
                HeaderType = RTMP_PACKET_SIZE_MEDIUM,
                PacketType = RTMP_PACKET_TYPE_INVOKE,
                TimeStamp = 0,
                InfoField2 = 0,
                HasAbsTimestamp = false,
                Body = pbuf,
                BodySize = (uint)enc
            };

            return RTMP_SendPacket(r, packet, false);
        }

        /// <summary> static int SendFCPublish(RTMP *r)
        private static bool SendFCPublish(RTMP r)
        {
            byte[] pbuf = new byte[1024];
            var pend = pbuf.Length;
            var enc = 0;
            enc = AMF.AMF_EncodeString(pbuf, enc, pend, av_FCPublish);
            enc = AMF.AMF_EncodeNumber(pbuf, enc, pend, ++r.m_numInvokes);
            pbuf[enc++] = (byte)AMFDataType.AMF_NULL;
            enc = AMF.AMF_EncodeString(pbuf, enc, pend, r.Link.playpath);
            if (enc == 0)
            {
                return false;
            }

            var packet = new RTMPPacket
            {
                ChannelNum = 0x03, /* control channel (invoke) */
                HeaderType = RTMP_PACKET_SIZE_MEDIUM,
                PacketType = RTMP_PACKET_TYPE_INVOKE,
                TimeStamp = 0,
                InfoField2 = 0,
                HasAbsTimestamp = false,
                Body = pbuf,
                BodySize = (uint)enc
            };

            return RTMP_SendPacket(r, packet, false);
        }

        /// <summary> static int SendFCSubscribe(RTMP *r, AVal *subscribepath)</summary>
        private static bool SendFCSubscribe(RTMP r, AVal subscribepath)
        {
            Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "FCSubscribe: {0}", subscribepath.to_s());
            var pbuf = new byte[512];
            var pend = pbuf.Length;
            var enc = 0;

            enc = AMF.AMF_EncodeString(pbuf, enc, pend, av_FCSubscribe);
            enc = AMF.AMF_EncodeNumber(pbuf, enc, pend, ++r.m_numInvokes);
            pbuf[enc++] = (byte)AMFDataType.AMF_NULL;
            enc = AMF.AMF_EncodeString(pbuf, enc, pend, subscribepath);

            if (enc == 0)
            {
                return false;
            }

            var packet = new RTMPPacket
            {
                ChannelNum = 0x03, /* control channel (invoke) */
                HeaderType = RTMP_PACKET_SIZE_MEDIUM,
                PacketType = RTMP_PACKET_TYPE_INVOKE,
                TimeStamp = 0,
                InfoField2 = 0,
                HasAbsTimestamp = false,
                Body = pbuf,
                BodySize = (uint)enc
            };

            return RTMP_SendPacket(r, packet, true);
        }

        /// <summary> static int SendUsherToken(RTMP *r, AVal *usherToken)</summary>
        private static bool SendUsherToken(RTMP r, AVal usherToken)
        {
            Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "UsherToken: {0}", usherToken.to_s());
            var pbuf = new byte[1024];
            var pend = pbuf.Length;
            var enc = 0;
            enc = AMF.AMF_EncodeString(pbuf, enc, pend, av_NetStream_Authenticate_UsherToken);
            enc = AMF.AMF_EncodeNumber(pbuf, enc, pend, ++r.m_numInvokes);
            pbuf[enc++] = (byte)AMFDataType.AMF_NULL;
            enc = AMF.AMF_EncodeString(pbuf, enc, pend, usherToken);

            if (enc == 0)
            {
                return false;
            }

            var packet = new RTMPPacket
            {
                ChannelNum = 0x03, /* control channel (invoke) */
                HeaderType = RTMP_PACKET_SIZE_MEDIUM,
                PacketType = RTMP_PACKET_TYPE_INVOKE,
                TimeStamp = 0,
                InfoField2 = 0,
                HasAbsTimestamp = false,
                Body = pbuf,
                BodySize = (uint)enc
            };

            return RTMP_SendPacket(r, packet, false);
        }

        /// <summary> static int SendPublish(RTMP *r)</summary>
        private static bool SendPublish(RTMP r)
        {
            var pbuf = new byte[1024];
            var pend = pbuf.Length;
            var enc = 0;
            enc = AMF.AMF_EncodeString(pbuf, enc, pend, av_publish);
            enc = AMF.AMF_EncodeNumber(pbuf, enc, pend, ++r.m_numInvokes);
            pbuf[enc++] = (byte)AMFDataType.AMF_NULL;
            enc = AMF.AMF_EncodeString(pbuf, enc, pend, r.Link.playpath);
            if (enc == 0)
            {
                return false;
            }

            /* FIXME: should we choose live based on Link.lFlags & RTMP_LF_LIVE? */
            enc = AMF.AMF_EncodeString(pbuf, enc, pend, av_live);
            if (enc == 0)
            {
                return false;
            }

            var packet = new RTMPPacket
            {
                ChannelNum = 0x04, /* source channel (invoke) */
                HeaderType = RTMP_PACKET_SIZE_LARGE,
                PacketType = RTMP_PACKET_TYPE_INVOKE,
                TimeStamp = 0,
                InfoField2 = r.m_stream_id,
                HasAbsTimestamp = false,
                Body = pbuf,
                BodySize = (uint)enc
            };

            return RTMP_SendPacket(r, packet, true);
        }

        /// <summary> static int SendPlaylist(RTMP *r)</summary>
        private static bool SendPlaylist(RTMP r)
        {
            var pbuf = new byte[1024];
            var pend = pbuf.Length;
            var enc = 0;
            enc = AMF.AMF_EncodeString(pbuf, enc, pend, av_set_playlist);
            enc = AMF.AMF_EncodeNumber(pbuf, enc, pend, 0);
            pbuf[enc++] = (byte)AMFDataType.AMF_NULL;
            pbuf[enc++] = (byte)AMFDataType.AMF_ECMA_ARRAY;
            pbuf[enc++] = 0;
            pbuf[enc++] = 0;
            pbuf[enc++] = 0;
            pbuf[enc++] = (byte)AMFDataType.AMF_OBJECT;
            enc = AMF.AMF_EncodeNamedString(pbuf, enc, pend, av_0, r.Link.playpath);
            if ((enc == 0) || (enc + 3 >= pend))
            {
                return false;
            }

            pbuf[enc++] = 0;
            pbuf[enc++] = 0;
            pbuf[enc++] = (byte)AMFDataType.AMF_OBJECT_END;

            var packet = new RTMPPacket
            {
                ChannelNum = 0x08, /* we make 8 our stream channel */
                HeaderType = RTMP_PACKET_SIZE_LARGE,
                PacketType = RTMP_PACKET_TYPE_INVOKE,
                TimeStamp = 0, /* 0x01000000; */
                InfoField2 = r.m_stream_id,
                HasAbsTimestamp = false,
                Body = pbuf,
                BodySize = (uint)enc
            };

            return RTMP_SendPacket(r, packet, true);
        }

        /// <summary> static int SendPlay(RTMP *r) </summary>
        private static bool SendPlay(RTMP r)
        {
            const string __FUNCTION__ = "SendPlay";

            var pbuf = new byte[1024];
            var pend = pbuf.Length;
            var enc = 0;
            enc = AMF.AMF_EncodeString(pbuf, enc, pend, av_play);
            enc = AMF.AMF_EncodeNumber(pbuf, enc, pend, ++r.m_numInvokes);
            pbuf[enc++] = (byte)AMFDataType.AMF_NULL;
            Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "{0}, seekTime={1}, stopTime={2}, sending play: {3}",
                __FUNCTION__, r.Link.seekTime, r.Link.stopTime, r.Link.playpath.to_s());
            enc = AMF.AMF_EncodeString(pbuf, enc, pend, r.Link.playpath);
            if (enc == 0)
            {
                return false;
            }

            /* Optional parameters start and len.
             *
             * start: -2, -1, 0, positive number
             *  -2: looks for a live stream, then a recorded stream,
             *      if not found any open a live stream
             *  -1: plays a live stream
             * >=0: plays a recorded streams from 'start' milliseconds
             */
            if ((r.Link.lFlags & RTMP_LNK.RTMP_LNK_FLAG.RTMP_LF_LIVE) != 0x00)
            {
                enc = AMF.AMF_EncodeNumber(pbuf, enc, pend, -1000.0);
            }
            else
            {
                if (r.Link.seekTime > 0.0)
                {
                    enc = AMF.AMF_EncodeNumber(pbuf, enc, pend, r.Link.seekTime); /* resume from here */
                }
                else
                {
                    enc = AMF.AMF_EncodeNumber(pbuf, enc, pend, 0.0); /*-2000.0);*/
                }
                /* recorded as default, -2000.0 is not reliable since that freezes the player if the stream is not found */
            }

            if (enc == 0)
            {
                return false;
            }

            /* len: -1, 0, positive number
             *  -1: plays live or recorded stream to the end (default)
             *   0: plays a frame 'start' ms away from the beginning
             *  >0: plays a live or recoded stream for 'len' milliseconds
             */
            /*enc += EncodeNumber(enc, -1.0); */
            /* len */
            if (r.Link.stopTime != 0)
            {
                enc = AMF.AMF_EncodeNumber(pbuf, enc, pend, r.Link.stopTime - r.Link.seekTime);
                if (enc == 0)
                {
                    return false;
                }
            }

            var packet = new RTMPPacket
            {
                ChannelNum = 0x08, /* we make 8 our stream channel */
                HeaderType = RTMP_PACKET_SIZE_LARGE,
                PacketType = RTMP_PACKET_TYPE_INVOKE,
                TimeStamp = 0, /* 0x01000000; */
                InfoField2 = r.m_stream_id,
                HasAbsTimestamp = false,
                Body = pbuf,
                BodySize = (uint)enc
            };

            return RTMP_SendPacket(r, packet, true);
        }

        /// <summary> static int SendCheckBW(RTMP *r)</summary>
        private static bool SendCheckBW(RTMP r)
        {
            var pbuf = new byte[256];
            var pend = pbuf.Length;
            var enc = 0;

            enc = AMF.AMF_EncodeString(pbuf, enc, pend, av__checkbw);
            enc = AMF.AMF_EncodeNumber(pbuf, enc, pend, ++r.m_numInvokes);
            pbuf[enc++] = (byte)AMFDataType.AMF_NULL;

            var packet = new RTMPPacket
            {
                ChannelNum = 0x03, /* control channel (invoke) */
                HeaderType = RTMP_PACKET_SIZE_LARGE,
                PacketType = RTMP_PACKET_TYPE_INVOKE,
                TimeStamp = 0, /* RTMP_GetTime(); */
                InfoField2 = 0,
                HasAbsTimestamp = false,
                Body = pbuf,
                BodySize = (uint)enc
            };

            /* triggers _onbwcheck and eventually results in _onbwdone */
            return RTMP_SendPacket(r, packet, false);
        }

        /// <summary> static int SendPong(RTMP *r, double txn) </summary>
        private static bool SendPong(RTMP r, double txn)
        {
            var pbuf = new byte[256];
            var pend = pbuf.Length;
            var enc = 0;

            enc = AMF.AMF_EncodeString(pbuf, enc, pend, av_pong);
            enc = AMF.AMF_EncodeNumber(pbuf, enc, pend, txn);
            pbuf[enc++] = (byte)AMFDataType.AMF_NULL;

            var packet = new RTMPPacket
            {
                ChannelNum = 0x03, /* control channel (invoke) */
                HeaderType = RTMP_PACKET_SIZE_MEDIUM,
                PacketType = RTMP_PACKET_TYPE_INVOKE,
                TimeStamp = (uint)(0x16 * r.m_nBWCheckCounter), /* temp inc value. till we figure it out. */
                InfoField2 = 0,
                HasAbsTimestamp = false,
                Body = pbuf,
                BodySize = (uint)enc
            };

            return RTMP_SendPacket(r, packet, false);
        }

        /// <summary> static int SendCheckBWResult(RTMP *r, double txn)</summary>
        private static bool SendCheckBWResult(RTMP r, double txn)
        {
            var pbuf = new byte[256];
            var pend = pbuf.Length;
            var enc = 0;
            enc = AMF.AMF_EncodeString(pbuf, enc, pend, av__result);
            enc = AMF.AMF_EncodeNumber(pbuf, enc, pend, txn);
            pbuf[enc++] = (byte)AMFDataType.AMF_NULL;
            enc = AMF.AMF_EncodeNumber(pbuf, enc, pend, (double)r.m_nBWCheckCounter++);

            var packet = new RTMPPacket
            {
                ChannelNum = 0x03, /* control channel (invoke) */
                HeaderType = RTMP_PACKET_SIZE_MEDIUM,
                PacketType = RTMP_PACKET_TYPE_INVOKE,
                TimeStamp = (uint)(0x16 * r.m_nBWCheckCounter), /* temp inc value. till we figure it out. */
                InfoField2 = 0,
                HasAbsTimestamp = false,
                Body = pbuf,
                BodySize = (uint)enc
            };

            return RTMP_SendPacket(r, packet, false);
        }

        /// <summary> static int DumpMetaData(AMFObject *obj)</summary>
        private static bool DumpMetaData(AMFObject obj)
        {
            for (var n = 0; n < obj.o_num; n++)
            {
                // char str [256] = "";
                var str = string.Empty;
                var prop = AMFObject.AMF_GetProp(obj, null, n);
                switch (prop.p_type)
                {
                    case AMFDataType.AMF_OBJECT:
                    case AMFDataType.AMF_ECMA_ARRAY:
                    case AMFDataType.AMF_STRICT_ARRAY:
                        if (prop.p_name.av_len != 0)
                        {
                            Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGINFO, "{0}:", prop.p_name.to_s());
                        }
                        DumpMetaData(prop.p_object);
                        break;

                    case AMFDataType.AMF_NUMBER:
                        // snprintf(str, 255, "%.2f", prop.p_vu.p_number);
                        str = string.Format("{0:f2}", prop.p_number);
                        break;

                    case AMFDataType.AMF_BOOLEAN:
                        // snprintf(str, 255, "%s", prop.p_vu.p_number != 0. ? "TRUE" : "FALSE");
                        str = string.Format("{0}", (prop.p_number < 0 || prop.p_number > 0) ? "TRUE" : "FALSE");
                        break;

                    case AMFDataType.AMF_STRING:
                        // len = snprintf(str, 255, "%.*s", prop.p_vu.p_aval.av_len, prop.p_vu.p_aval.av_val);
                        str = string.Format("{0}", prop.p_aval.to_s());
                        if (str.Length >= 1 && str[str.Length - 1] == '\n')
                        {
                            // str[len - 1] = '\0';
                            str = str.Substring(0, str.Length - 1);
                        }

                        break;

                    case AMFDataType.AMF_DATE:
                        // snprintf(str, 255, "timestamp:%.2f", prop.p_vu.p_number);
                        str = string.Format("timestamp:{0:f2}", prop.p_number);
                        break;

                    default:
                        // snprintf(str, 255, "INVALID TYPE 0x%02x",(unsigned char )prop.p_type);
                        str = string.Format("INVALID TYPE 0x{0:x02}", prop.p_type);
                        break;
                }

                if (!string.IsNullOrEmpty(str) && prop.p_name != null && prop.p_name.av_len > 0)
                {
                    Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGINFO, "  {0,-22}{1}", prop.p_name.to_s(), str);
                }
            }

            return false;
        }

        private static bool memcmp(byte[] v1, int o1, byte[] v2, int o2, int len)
        {
            for (var i = 0; i < len; ++i)
            {
                if (v1[o1 + i] != v2[o2 + i])
                {
                    return true;
                }
            }

            return false;
        }

        private const int MAX_IGNORED_FRAMES = 50;

        // static int Read_1_Packet(RTMP *r, char *buf, unsigned int buflen)
        private static int Read_1_Packet(RTMP r, byte[] buf, int offset, int buflen)
        {
            var prevTagSize = 0;
            int rtnGetNextMediaPacket = 0, ret = RTMP_READ.RTMP_READ_EOF;
            RTMPPacket packet = new RTMPPacket();
            var recopy = false;
            uint nTimeStamp = 0;
            int len;

            rtnGetNextMediaPacket = RTMP_GetNextMediaPacket(r, packet);
            while (rtnGetNextMediaPacket != 0)
            {
                // char* packetBody = packet.m_body;
                int packetBody = 0; // packet.Body
                var nPacketLen = (int)packet.BodySize;

                /* Return RTMP_READ_COMPLETE if this was completed nicely with
                     * invoke message Play.Stop or Play.Complete
                     */
                if (rtnGetNextMediaPacket == 2)
                {
                    Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "Got Play.Complete or Play.Stop from server. Assuming stream is complete");
                    ret = RTMP_READ.RTMP_READ_COMPLETE;
                    break;
                }

                {
                    var isAudio = (byte)((packet.PacketType == RTMP_PACKET_TYPE_AUDIO) ? 1 : 0);
                    var isVideo = (byte)((packet.PacketType == RTMP_PACKET_TYPE_VIDEO) ? 1 : 0);
                    r.m_read.dataType |= (byte)((isAudio << 2) | isVideo);
                }

                if (packet.PacketType == RTMP_PACKET_TYPE_VIDEO && nPacketLen <= 5)
                {
                    Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "ignoring too small video packet: size: {0}", nPacketLen);
                    ret = RTMP_READ.RTMP_READ_IGNORE;
                    break;
                }

                if (packet.PacketType == RTMP_PACKET_TYPE_AUDIO && nPacketLen <= 1)
                {
                    Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "ignoring too small audio packet: size: {0}", nPacketLen);
                    ret = RTMP_READ.RTMP_READ_IGNORE;
                    break;
                }

                if ((r.m_read.flags & RTMP_READ.RTMP_READ_SEEKING) != 0x00)
                {
                    ret = RTMP_READ.RTMP_READ_IGNORE;
                    break;
                }
#if  DEBUG
                Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG,
                    "type: {0:X02}, size: {1}, TS: {2} ms, abs TS: {3}",
                    packet.PacketType, nPacketLen, packet.TimeStamp, packet.HasAbsTimestamp);
                if (packet.PacketType == RTMP_PACKET_TYPE_VIDEO)
                {
                    Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "frametype: {0:X02}", (packet.Body[packetBody] & 0xf0));
                }
#endif

                if ((r.m_read.flags & RTMP_READ.RTMP_READ_RESUME) != 0x00)
                {
                    /* check the header if we get one */
                    if (packet.TimeStamp == 0)
                    {
                        if (r.m_read.nMetaHeaderSize > 0
                            && packet.PacketType == RTMP_PACKET_TYPE_INFO)
                        {
                            AMFObject metaObj = new AMFObject();
                            int nRes = AMFObject.AMF_Decode(metaObj, packet.Body, packetBody, (int)nPacketLen, false);
                            if (nRes >= 0)
                            {
                                AVal metastring;
                                AMFObjectProperty.AMFProp_GetString(AMFObject.AMF_GetProp(metaObj, null, 0), out metastring);

                                if (AVal.Match(metastring, av_onMetaData))
                                {
                                    /* compare */
                                    var unmatch = false; // memcmp(r.m_read.metaHeader, packetBody, r.m_read.nMetaHeaderSize);
                                    for (var i = 0; i < r.m_read.nMetaHeaderSize; ++i)
                                    {
                                        unmatch = packet.Body[packetBody + i] != r.m_read.metaHeader[i];
                                        if (unmatch)
                                        {
                                            break;
                                        }
                                    }

                                    if ((r.m_read.nMetaHeaderSize != nPacketLen) || unmatch)
                                    {
                                        ret = RTMP_READ.RTMP_READ_ERROR;
                                    }
                                }

                                AMFObject.AMF_Reset(metaObj);
                                if (ret == RTMP_READ.RTMP_READ_ERROR)
                                {
                                    break;
                                }
                            }
                        }

                        /* check first keyframe to make sure we got the right position
                             * in the stream! (the first non ignored frame)
                             */
                        if (r.m_read.nInitialFrameSize > 0)
                        {
                            /* video or audio data */
                            if (packet.PacketType == r.m_read.initialFrameType
                                && r.m_read.nInitialFrameSize == nPacketLen)
                            {
                                /* we don't compare the sizes since the packet can
                                     * contain several FLV packets, just make sure the
                                     * first frame is our keyframe (which we are going
                                     * to rewrite)
                                     */
                                var unmatch = false;
                                for (var i = 0; i < r.m_read.nInitialFrameSize; ++i)
                                {
                                    unmatch = r.m_read.initialFrame[i] != packet.Body[packetBody + i];
                                    if (unmatch)
                                    {
                                        break;
                                    }
                                }

                                if (!unmatch)
                                {
                                    Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "Checked keyframe successfully!");
                                    r.m_read.flags |= RTMP_READ.RTMP_READ_GOTKF;
                                    /* ignore it! (what about audio data after it? it is
                                         * handled by ignoring all 0ms frames, see below)
                                         */
                                    ret = RTMP_READ.RTMP_READ_IGNORE;
                                    break;
                                }
                            }

                            /* hande FLV streams, even though the server resends the
                                 * keyframe as an extra video packet it is also included
                                 * in the first FLV stream chunk and we have to compare
                                 * it and filter it out !!
                                 */
                            if (packet.PacketType == RTMP_PACKET_TYPE_FLASH_VIDEO)
                            {
                                /* basically we have to find the keyframe with the
                                     * correct TS being nResumeTS
                                     */
                                int pos = 0;
                                uint ts = 0;

                                while (pos + 11 < nPacketLen)
                                {
                                    /* size without header (11) and prevTagSize (4) */
                                    var dataSize = AMF.AMF_DecodeInt24(packet.Body, packetBody + pos + 1);
                                    ts = AMF.AMF_DecodeInt24(packet.Body, packetBody + pos + 4);
                                    ts |= (uint)(packet.Body[packetBody + pos + 7] << 24);

#if DEBUG
                                    Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG,
                                        "keyframe search: FLV Packet: type {0:X02}, dataSize: {1}, timeStamp: {2} ms",
                                        packet.Body[packetBody + pos], dataSize, ts);
#endif
                                    /* ok, is it a keyframe?: well doesn't work for audio! */
                                    /*6928, test 0 */
                                    /* && (packetBody[11]&0xf0) == 0x10 */
                                    if (packet.Body[packetBody + pos] == r.m_read.initialFrameType)
                                    {
                                        if (ts == r.m_read.nResumeTS)
                                        {
                                            Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "Found keyframe with resume-keyframe timestamp!");
                                            var unmatch = memcmp(r.m_read.initialFrame, 0, packet.Body, packetBody + pos + 11, (int)r.m_read.nInitialFrameSize);
                                            if (r.m_read.nInitialFrameSize != dataSize || unmatch)
                                            {
                                                Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGERROR,
                                                    "FLV Stream: Keyframe doesn't match!");
                                                ret = RTMP_READ.RTMP_READ_ERROR;
                                                break;
                                            }
                                            r.m_read.flags |= RTMP_READ.RTMP_READ_GOTFLVK;

                                            /* skip this packet? check whether skippable: */
                                            if (pos + 11 + dataSize + 4 > nPacketLen)
                                            {
                                                Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGWARNING,
                                                    "Non skipable packet since it doesn't end with chunk, stream corrupt!");
                                                ret = RTMP_READ.RTMP_READ_ERROR;
                                                break;
                                            }

                                            packetBody += (int)(pos + 11 + dataSize + 4); // TODO:
                                            nPacketLen -= (int)(pos + 11 + dataSize + 4); // TODO:

                                            goto stopKeyframeSearch;
                                        }
                                        else if (r.m_read.nResumeTS < ts)
                                        {
                                            /* the timestamp ts will only increase with
                                                 * further packets, wait for seek
                                                 */
                                            goto stopKeyframeSearch;
                                        }
                                    }

                                    pos += (int)(11 + dataSize + 4);
                                }

                                if (ts < r.m_read.nResumeTS)
                                {
                                    Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGERROR, "First packet does not contain keyframe, all timestamps are smaller than the keyframe timestamp; probably the resume seek failed?");
                                }

                            stopKeyframeSearch:

                                if ((r.m_read.flags & RTMP_READ.RTMP_READ_GOTFLVK) != 0x00)
                                {
                                    Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGERROR, "Couldn't find the seeked keyframe in this chunk!");
                                    ret = RTMP_READ.RTMP_READ_IGNORE;
                                    break;
                                }
                            }
                        }
                    }

                    if (packet.TimeStamp > 0
                        && (r.m_read.flags & (RTMP_READ.RTMP_READ_GOTKF | RTMP_READ.RTMP_READ_GOTFLVK)) != 0x0)
                    {
                        /* another problem is that the server can actually change from
                             * 09/08 video/audio packets to an FLV stream or vice versa and
                             * our keyframe check will prevent us from going along with the
                             * new stream if we resumed.
                             *
                             * in this case set the 'found keyframe' variables to true.
                             * We assume that if we found one keyframe somewhere and were
                             * already beyond TS > 0 we have written data to the output
                             * which means we can accept all forthcoming data including the
                             * change between 08/09 <. FLV packets
                             */
                        r.m_read.flags |= (RTMP_READ.RTMP_READ_GOTKF | RTMP_READ.RTMP_READ_GOTFLVK);
                    }

                    /* skip till we find our keyframe
                         * (seeking might put us somewhere before it)
                         */
                    if ((r.m_read.flags & RTMP_READ.RTMP_READ_GOTKF) != 0
                        && packet.PacketType != RTMP_PACKET_TYPE_FLASH_VIDEO)
                    {
                        Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGWARNING,
                            "Stream does not start with requested frame, ignoring data... ");
                        r.m_read.nIgnoredFrameCounter++;

                        /* fatal error, couldn't continue stream */
                        ret = r.m_read.nIgnoredFrameCounter > MAX_IGNORED_FRAMES
                            ? RTMP_READ.RTMP_READ_ERROR
                            : RTMP_READ.RTMP_READ_IGNORE;
                        break;
                    }

                    /* ok, do the same for FLV streams */
                    if ((r.m_read.flags & RTMP_READ.RTMP_READ_GOTFLVK) != 0
                        && packet.PacketType == RTMP_PACKET_TYPE_FLASH_VIDEO)
                    {
                        Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGWARNING,
                            "Stream does not start with requested FLV frame, ignoring data... ");
                        r.m_read.nIgnoredFlvFrameCounter++;
                        ret = r.m_read.nIgnoredFlvFrameCounter > MAX_IGNORED_FRAMES
                            ? RTMP_READ.RTMP_READ_ERROR
                            : RTMP_READ.RTMP_READ_IGNORE;
                        break;
                    }

                    /* we have to ignore the 0ms frames since these are the first
                         * keyframes; we've got these so don't mess around with multiple
                         * copies sent by the server to us! (if the keyframe is found at a
                         * later position there is only one copy and it will be ignored by
                         * the preceding if clause)
                         */
                    if ((r.m_read.flags & RTMP_READ.RTMP_READ_NO_IGNORE) != 0
                        && packet.PacketType != RTMP_PACKET_TYPE_FLASH_VIDEO)
                    {
                        /* exclude type RTMP_PACKET_TYPE_FLASH_VIDEO since it can
                             * contain several FLV packets
                             */
                        if (packet.TimeStamp == 0)
                        {
                            ret = RTMP_READ.RTMP_READ_IGNORE;
                            break;
                        }
                        else
                        {
                            /* stop ignoring packets */
                            r.m_read.flags |= RTMP_READ.RTMP_READ_NO_IGNORE;
                        }
                    }
                }

                /* calculate packet size and allocate slop buffer if necessary */
                var size = (int)(nPacketLen +
                                 ((packet.PacketType == RTMP_PACKET_TYPE_AUDIO
                                   || packet.PacketType == RTMP_PACKET_TYPE_VIDEO
                                   || packet.PacketType == RTMP_PACKET_TYPE_INFO) ? 11 : 0)
                                 + (packet.PacketType != RTMP_PACKET_TYPE_FLASH_VIDEO ? 4 : 0));

                int ptr;
                byte[] ptrBuf;
                if (size + 4 > buflen)
                {
                    /* the extra 4 is for the case of an FLV stream without a last
                         * prevTagSize (we need extra 4 bytes to append it) */
                    // r.m_read.buf = malloc(size + 4);
                    // if (r.m_read.buf == 0)
                    // {
                    //     Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGERROR, "Couldn't allocate memory!");
                    //     ret = RTMP_READ.RTMP_READ_ERROR; /* fatal error */
                    //     break;
                    // }
                    r.m_read.buf = new byte[size + 4];
                    recopy = true;
                    ptr = 0; // r.m_read.buf;
                    ptrBuf = r.m_read.buf;
                }
                else
                {
                    // ptr = buf;
                    ptr = offset;
                    ptrBuf = buf;
                }

                var pend = size + 4;

                /* use to return timestamp of last processed packet */

                /* audio (0x08), video (0x09) or metadata (0x12) packets :
                     * construct 11 byte header then add rtmp packet's data */
                if (packet.PacketType == RTMP_PACKET_TYPE_AUDIO
                    || packet.PacketType == RTMP_PACKET_TYPE_VIDEO
                    || packet.PacketType == RTMP_PACKET_TYPE_INFO)
                {
                    nTimeStamp = r.m_read.nResumeTS + packet.TimeStamp;
                    prevTagSize = 11 + nPacketLen;

                    ptrBuf[ptr] = packet.PacketType;
                    ptr++;
                    ptr = AMF.AMF_EncodeInt24(ptrBuf, ptr, pend, (uint)nPacketLen);

#if UNUSE
            if (packet.PacketType == RTMP_PACKET_TYPE_VIDEO) {
                /* H264 fix: */
                if ((packetBody[0] & 0x0f) == 7) { /* CodecId = H264 */
                    uint8_t packetType = *(packetBody + 1);

                    uint32_t ts = AMF_DecodeInt24(packetBody + 2); /* composition time */
                    int32_t cts = (ts + 0xff800000) ^ 0xff800000;
                    RTMP_Log(RTMP_LOGDEBUG, "cts  : %d\n", cts);

                    nTimeStamp -= cts;
                    /* get rid of the composition time */
                    CRTMP::EncodeInt24(packetBody + 2, 0);
                }
                RTMP_Log(RTMP_LOGDEBUG, "VIDEO: nTimeStamp: 0x%08X (%d)\n", nTimeStamp, nTimeStamp);
            }
#endif

                    ptr = AMF.AMF_EncodeInt24(ptrBuf, ptr, pend, nTimeStamp);
                    ptrBuf[ptr] = (byte)((nTimeStamp & 0xFF000000) >> 24);
                    ptr++;

                    /* stream id */
                    ptr = AMF.AMF_EncodeInt24(ptrBuf, ptr, pend, 0);
                }

                // memcpy(ptr, packetBody, nPacketLen);
                Array.Copy(packet.Body, packetBody, ptrBuf, ptr, nPacketLen);
                len = nPacketLen;

                /* correct tagSize and obtain timestamp if we have an FLV stream */
                if (packet.PacketType == RTMP_PACKET_TYPE_FLASH_VIDEO)
                {
                    int pos = 0;

                    /* grab first timestamp and see if it needs fixing */
                    nTimeStamp = AMF.AMF_DecodeInt24(packet.Body, packetBody + 4);
                    nTimeStamp |= (uint)(packet.Body[packetBody + 7] << 24);
                    int delta = (int)(packet.TimeStamp - nTimeStamp);
                    delta += (int)r.m_read.nResumeTS;

                    while (pos + 11 < nPacketLen)
                    {
                        /* size without header (11) and without prevTagSize (4) */
                        var dataSize = AMF.AMF_DecodeInt24(packet.Body, packetBody + pos + 1);
                        nTimeStamp = AMF.AMF_DecodeInt24(packet.Body, packetBody + pos + 4);
                        nTimeStamp |= (uint)(packet.Body[packetBody + pos + 7] << 24);

                        if (delta != 0)
                        {
                            nTimeStamp += (uint)delta;
                            AMF.AMF_EncodeInt24(ptrBuf, ptr + pos + 4, pend, nTimeStamp);
                            ptrBuf[ptr + pos + 7] = (byte)(nTimeStamp >> 24);
                        }

                        /* set data type */
                        r.m_read.dataType |= (byte)((packet.Body[packetBody + pos] == 0x08 ? 4 : 0)
                                                    + (packet.Body[packetBody + pos] == 0x09 ? 1 : 0));

                        if (pos + 11 + dataSize + 4 > nPacketLen)
                        {
                            if (pos + 11 + dataSize > nPacketLen)
                            {
                                Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGERROR,
                                    "Wrong data size ({0}), stream corrupted, aborting!",
                                    dataSize);
                                ret = RTMP_READ.RTMP_READ_ERROR;
                                break;
                            }

                            Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGWARNING, "No tagSize found, appending!");

                            /* we have to append a last tagSize! */
                            prevTagSize = (int)(dataSize + 11);
                            AMF.AMF_EncodeInt32(ptrBuf, (int)(ptr + pos + 11 + dataSize), pend, (uint)prevTagSize);
                            size += 4;
                            len += 4;
                        }
                        else
                        {
                            prevTagSize = (int)AMF.AMF_DecodeInt32(packet.Body, (int)(packetBody + pos + 11 + dataSize));

#if DEBUG
                            Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG,
                                "FLV Packet: type {0:X2}, dataSize: {1}, tagSize: {2}, timeStamp: {3} ms",
                                packet.Body[packetBody + pos], dataSize, prevTagSize, nTimeStamp);
#endif

                            if (prevTagSize != (dataSize + 11))
                            {
#if DEBUG
                                Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGWARNING,
                                    "Tag and data size are not consitent, writing tag size according to dataSize+11: {0}",
                                    dataSize + 11);
#endif

                                prevTagSize = (int)(dataSize + 11);
                                AMF.AMF_EncodeInt32(ptrBuf, (int)(ptr + pos + 11 + dataSize), pend, (uint)prevTagSize);
                            }
                        }

                        pos += prevTagSize + 4; /*(11+dataSize+4); */
                    }
                }

                ptr += len;

                if (packet.PacketType != RTMP_PACKET_TYPE_FLASH_VIDEO)
                {
                    /* FLV tag packets contain their own prevTagSize */
                    AMF.AMF_EncodeInt32(ptrBuf, ptr, pend, (uint)prevTagSize);
                }

                /* In non-live this nTimeStamp can contain an absolute TS.
                     * Update ext timestamp with this absolute offset in non-live mode
                     * otherwise report the relative one
                     */
                /* RTMP_Log(RTMP_LOGDEBUG, "type: %02X, size: %d, pktTS: %dms, TS: %dms, bLiveStream: %d", packet.PacketType, nPacketLen, packet.m_nTimeStamp, nTimeStamp, r.Link.lFlags & RTMP_LF_LIVE); */
                r.m_read.timestamp = (r.Link.lFlags & RTMP_LNK.RTMP_LNK_FLAG.RTMP_LF_LIVE) != 0
                    ? packet.TimeStamp : nTimeStamp;

                ret = size;
                break;
            }

            if (rtnGetNextMediaPacket != 0)
            {
                RTMPPacket.RTMPPacket_Free(packet);
            }

            if (recopy)
            {
                len = ret > buflen ? buflen : ret;
                // memcpy(buf, r.m_read.buf, len);
                Array.Copy(r.m_read.buf, buf, len);
                r.m_read.bufpos = len; // r.m_read.buf + len;
                r.m_read.buflen = ret - len;
            }

            return ret;
        }

        /* hashswf.c */

        /// <summary> int RTMP_HashSWF(const char *url, unsigned int *size, unsigned char *hash, int age); </summary>
        public static int RTMP_HashSWF(byte[] url, ref int size, byte[] hash, int age)
        {
            throw new NotImplementedException();
        }

        /// <summary> void RTMP_TLS_Init() </summary>
        private static void RTMP_TLS_Init()
        {
            //
        }
    }
}