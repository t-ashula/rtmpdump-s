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
        public const int RTMP_FEATURE_MFP = 0x08;/* not yet supported */
        public const int RTMP_FEATURE_WRITE = 0x10;	/* publish, not play */
        public const int RTMP_FEATURE_HTTP2 = 0x20;	/* server-side rtmpt */

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
        private const int RTMP_MAX_HEADER_SIZE = 18;

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
        public int m_stream_id { get; set; }		/* returned in _result from createStream */

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
        public byte m_bPlaying { get; set; }

        /// <summary> uint8_t m_bSendEncoding </summary>
        public byte m_bSendEncoding { get; set; }

        /// <summary> uint8_t m_bSendCounter </summary>
        public bool m_bSendCounter { get; set; }

        /// <summary> int m_numInvokes </summary>
        public int m_numInvokes { get; set; }

        /// <summary> int m_numCalls </summary>
        public int m_numCalls { get; set; }

        /// <summary> RTMP_METHOD* m_methodCalls </summary>
        public RTMP_METHOD m_methodCalls { get; set; }	/* remote method calls queue */

        /// <summary> int m_channelsAllocatedIn </summary>
        public int m_channelsAllocatedIn { get; set; }

        /// <summary> int m_channelsAllocatedOut </summary>
        public int m_channelsAllocatedOut { get; set; }

        /// <summary> RTMPPacket** m_vecChannelsIn </summary>
        public RTMPPacket[] m_vecChannelsIn { get; set; }

        /// <summary> RTMPPacket** m_vecChannelsOut </summary>
        public RTMPPacket[] m_vecChannelsOut { get; set; }

        /// <summary> int* m_channelTimestamp </summary>
        public int[] m_channelTimestamp { get; set; }	/* abs timestamp of last packet */

        /// <summary> double m_fAudioCodecs </summary>
        public double m_fAudioCodecs { get; set; }	/* audioCodecs for the connect packet */

        /// <summary> double m_fVideoCodecs </summary>
        public double m_fVideoCodecs { get; set; }	/* videoCodecs for the connect packet */

        /// <summary> double m_fEncoding </summary>
        public double m_fEncoding { get; set; }	/* AMF0 or AMF3 */

        /// <summary> double m_fDuration </summary>
        public double m_fDuration { get; set; }		/* duration of stream in seconds */

        /// <summary> int m_msgCounter </summary>
        public int m_msgCounter { get; set; }	/* RTMPT stuff */

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
            if (flashVer.av_len > 0)
            {
                r.Link.flashVer = flashVer;
            }
            else
            {
                r.Link.flashVer = RTMP_DefaultFlashVer;
            }

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
            if (r.Link.hostname.av_len == 0)
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
            throw new NotImplementedException();
        }

        // int RTMP_TLS_Accept(RTMP *r, void *ctx);

        /// <summary> int RTMP_ReadPacket(RTMP *r, RTMPPacket *packet); </summary>
        public static bool RTMP_ReadPacket(RTMP r, out RTMPPacket packet)
        {
            throw new NotImplementedException();
        }

        /// <summary> int RTMP_SendPacket(RTMP *r, RTMPPacket *packet, int queue);</summary>
        public static bool RTMP_SendPacket(RTMP r, RTMPPacket p, bool queue)
        {
            throw new NotImplementedException();
        }

        /// <summary> int RTMP_SendChunk(RTMP *r, RTMPChunk *chunk); </summary>
        public static bool RTMP_SendChunk(RTMP r, RTMPChunk c)
        {
            throw new NotImplementedException();
        }

        /// <summary> int RTMP_IsConnected(RTMP *r); </summary>
        public static bool RTMP_IsConnected(RTMP r)
        {
            throw new NotImplementedException();
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
            throw new NotImplementedException();
        }

        /// <summary> int RTMP_ReconnectStream(RTMP *r, int seekTime); </summary>
        public static bool RTMP_ReconnectStream(RTMP r, int seekTime)
        {
            throw new NotImplementedException();
        }

        // void RTMP_DeleteStream(RTMP *r);
        // int RTMP_GetNextMediaPacket(RTMP *r, RTMPPacket *packet);
        /// <summary> int RTMP_ClientPacket(RTMP *r, RTMPPacket *packet);</summary>
        public static int RTMP_ClientPacket(RTMP r, RTMPPacket p)
        {
            throw new NotImplementedException();
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
        }

        /// <summary> void RTMP_Close(RTMP *r); </summary>
        public static void RTMP_Close(RTMP r)
        {
            throw new NotImplementedException();
        }

        //RTMP *RTMP_Alloc(void);
        // void RTMP_Free(RTMP *r);
        // void RTMP_EnableWrite(RTMP *r);

        // void *RTMP_TLS_AllocServerContext(const char* cert, const char* key);
        // void RTMP_TLS_FreeServerContext(void *ctx);

        // int RTMP_LibVersion(void);
        // void RTMP_UserInterrupt(void);	/* user typed Ctrl-C */

        /// <summary> int RTMP_SendCtrl(RTMP *r, short nType, unsigned int nObject,unsigned int nTime);</summary>
        public static int RTMP_SendCtrl(RTMP r, short type, uint objCnt, uint times)
        {
            throw new NotImplementedException();
        }

        /* caller probably doesn't know current timestamp, should just use RTMP_Pause instead */
        // int RTMP_SendPause(RTMP *r, int DoPause, int dTime);
        // int RTMP_Pause(RTMP *r, int DoPause);

        /// <summary> int RTMP_FindFirstMatchingProperty(AMFObject *obj, const AVal *name,AMFObjectProperty * p); </summary>
        public static bool RTMP_FindFirstMatchingProperty(AMFObject obj, AVal name, out AMFObjectProperty p)
        {
            throw new NotImplementedException();
        }

        // int RTMPSockBuf_Fill(RTMPSockBuf *sb);
        // int RTMPSockBuf_Send(RTMPSockBuf *sb, const char *buf, int len);
        // int RTMPSockBuf_Close(RTMPSockBuf *sb);

        // int RTMP_SendCreateStream(RTMP *r);
        // int RTMP_SendSeek(RTMP *r, int dTime);
        // int RTMP_SendServerBW(RTMP *r);
        // int RTMP_SendClientBW(RTMP *r);
        // void RTMP_DropRequest(RTMP *r, int i, int freeit);

        /// <summary>
        /// int RTMP_Read(RTMP *r, char *buf, int size);
        /// </summary>
        public static int RTMP_Read(RTMP r, byte[] buf, int size)
        {
            throw new NotImplementedException();
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

#if _DEBUG
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

#endif

        // static int SendConnectPacket(RTMP *r, RTMPPacket* cp);
        private static bool SendConnectPacket(RTMP r, RTMPPacket cp)
        {
            throw new NotImplementedException();
        }

        // static int WriteN(RTMP *r, const char *buffer, int n)
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

            var ptr = 0;
            var userHttp = (r.Link.protocol & RTMP_FEATURE_HTTP) != 0x00;
            while (n > 0)
            {
                int nBytes = userHttp
                    ? HTTP_Post(r, RTMPTCmd.RTMPT_SEND, buffer.Skip(ptr).ToArray(), n)
                    : RTMPSockBuf.RTMPSockBuf_Send(r.m_sb, buffer.Skip(ptr).ToArray(), n);

                Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "{0}: {1}\n", __FUNCTION__, nBytes);

                if (nBytes < 0)
                {
                    int sockerr = 0; // TODO: GetSockError();
                    Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGERROR, "%s, RTMP send error %d (%d bytes)", __FUNCTION__, sockerr, n);

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

        // static int ReadN(RTMP *r, char* buffer, int n)
        private static int ReadN(RTMP r, byte[] buffer, int n)
        {
            const string __FUNCTION__ = "ReadN";
            int nOriginalSize = n;
            int avail;
            // char* ptr;

            r.m_sb.sb_timedout = false;

#if _DEBUG
            memset(buffer, 0, n);
#endif

            var ptr = 0; // buffer;
            var useHttp = (r.Link.protocol & RTMP_FEATURE_HTTP) != 0x00;
            while (n > 0)
            {
                int nBytes = 0, nRead;
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
                            Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "%s, No valid HTTP response found", __FUNCTION__);
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

                nRead = ((n < avail) ? n : avail);
                if (nRead > 0)
                {
                    // memcpy(ptr, r.m_sb.sb_start, nRead);
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
                /*RTMP_Log(RTMP_LOGDEBUG, "%s: %d bytes\n", __FUNCTION__, nBytes); */
#if _DEBUG
                fwrite(ptr, 1, nBytes, netstackdump_read);
#endif

                if (nBytes == 0)
                {
                    Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "%s, RTMP socket closed by peer", __FUNCTION__);
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

        // static int SendBytesReceived(RTMP *r)
        private static bool SendBytesReceived(RTMP r)
        {
            RTMPPacket packet = new RTMPPacket
            {
                ChannnelNum = 0x02,
                HeaderType = RTMP_PACKET_SIZE_MEDIUM,
                PacketType = RTMP_PACKET_TYPE_BYTES_READ_REPORT,
                TimeStamp = 0,
                InfoField2 = 0,
                HasAbsTimestamp = 0,
                Body = new byte[256],
                BodySize = 4
            };

            /* control channel (invoke) */
            var buf = new byte[256];
            AMF.AMF_EncodeInt32(buf, r.m_nBytesIn); /* hard coded for now */
            for (var i = 0; i < 256 - RTMP_MAX_HEADER_SIZE; ++i)
            {
                packet.Body[i + RTMP_MAX_HEADER_SIZE] = buf[i];
            }
            r.m_nBytesInSent = r.m_nBytesIn;

            /*RTMP_Log(RTMP_LOGDEBUG, "Send bytes report. 0x%x (%d bytes)", (unsigned int)m_nBytesIn, m_nBytesIn); */
            return RTMP_SendPacket(r, packet, false);
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

    /// <summary> struct RTMPChunk </summary>
    public class RTMPChunk
    {
    }

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

        /// <summary> uint8_t m_packetType </summary>
        public byte PacketType { get; set; }

        /// <summary> uint8_t m_hasAbsTimestamp </summary>
        public byte HasAbsTimestamp { get; set; }

        /// <summary> int m_nChannnel </summary>
        public int ChannnelNum { get; set; }

        /// <summary> uint32_t m_nTimeStamp </summary>
        public uint TimeStamp { get; set; }

        /// <summary> int32_t m_nInfoField2 </summary>
        public int InfoField2 { get; set; }

        /// <summary> uint32_t m_nBodySize </summary>
        public uint BodySize { get; set; }

        /// <summary> uint32_t m_nBytesRead </summary>
        public uint BytesRead { get; set; }

        /// <summary> RTMPChunk *m_chunk </summary>
        public List<RTMPChunk> Chunk { get; set; }

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
    }

    /// <summary>
    /// struct RTMPSockBuf
    /// </summary>
    public class RTMPSockBuf
    {
        /// <summary> int sb_socket </summary>
        public Socket sb_socket { get; set; }

        // int sb_size;		/* number of unprocessed bytes in buffer */
        public int sb_size { get; set; }

        /// <summary> char *sb_start;		/* pointer into sb_pBuffer of next byte to process */ </summary>
        public int sb_start { get; set; }

        /// <summary> char sb_buf[RTMP_BUFFER_CACHE_SIZE];	/* data read from socket */ </summary>
        public byte[] sb_buf { get; set; }

        /// <summary> int sb_timedout; </summary>
        public bool sb_timedout { get; set; }

        /// <summary> void *sb_ssl; </summary>
        public object sb_ssl { get; set; }

        public RTMPSockBuf()
        {
            sb_socket = null;
            sb_size = 0;
            sb_start = 0;
            sb_timedout = false;
            sb_buf = new byte[RTMP.RTMP_BUFFER_CACHE_SIZE];
        }

        /// <summary> int RTMPSockBuf_Fill(RTMPSockBuf *sb)</summary>
        public static int RTMPSockBuf_Fill(RTMPSockBuf sb)
        {
            const string __FUNCTION__ = "RTMPSockBuf_Fill";
            int nBytes;

            if (sb.sb_size == 0)
            {
                sb.sb_start = 0; // = sb.sb_buf;
            }

            while (true)
            {
                // nBytes = sizeof (sb.sb_buf) - 1 - sb.sb_size - (sb.sb_start - sb.sb_buf);
                nBytes = RTMP.RTMP_BUFFER_CACHE_SIZE - 1 - sb.sb_size - sb.sb_start;
#if CRYPTO_SSL // defined(CRYPTO) && !defined(NO_SSL)
        if (sb.sb_ssl)
        {
            nBytes = TLS_read(sb.sb_ssl, sb.sb_start + sb.sb_size, nBytes);
        }
        else
#endif
                {
                    //  nBytes = recv(sb.sb_socket, sb.sb_start + sb.sb_size, nBytes, 0);

                    nBytes = sb.sb_socket.Receive(sb.sb_buf, sb.sb_start + sb.sb_size, nBytes, SocketFlags.None);
                }

                if (nBytes != -1)
                {
                    sb.sb_size += nBytes;
                }
                else
                {
                    int sockerr = 0; // TODO: GetSockError();
                    const int EINTR = 2;
                    const int EWOULDBLOCK = 3;
                    const int EAGAIN = 4;
                    Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "{0}, recv returned {1}. GetSockError(): {2} ({3})", __FUNCTION__, nBytes, sockerr, string.Empty); // strerror(sockerr)
                    if (sockerr == EINTR && !RTMP.RTMP_ctrlC)
                    {
                        continue;
                    }

                    if (sockerr == EWOULDBLOCK || sockerr == EAGAIN)
                    {
                        sb.sb_timedout = true;
                        nBytes = 0;
                    }
                }

                break;
            }

            return nBytes;
        }

        /// <summary> int RTMPSockBuf_Send(RTMPSockBuf *sb, const char *buf, int len) </summary>
        public static int RTMPSockBuf_Send(RTMPSockBuf sb, byte[] buf, int len)
        {
            int rc;

#if _DEBUG
            fwrite(buf, 1, len, netstackdump);
#endif

#if CRYPTO_SSL // defined(CRYPTO) && !defined(NO_SSL)
    if (sb.sb_ssl)
    {
        rc = TLS_write(sb.sb_ssl, buf, len);
    }
    else
#endif
            {
                // rc = send(sb.sb_socket, buf, len, 0);
                rc = sb.sb_socket.Send(buf);
            }

            return rc;
        }
    }

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

    /// <summary> struct RTMP_METHOD </summary>
    public class RTMP_METHOD
    {
        /// <summary> Aval name </summary>
        public AVal name { get; set; }

        /// <summary> int num </summary>
        public int num { get; set; }
    }

    /// <summary> struct RTMP_READ </summary>
    public class RTMP_READ
    {
        /// <summary> char *buf; </summary>
        public byte[] buf { get; set; }

        /// <summary> char *bufpos; </summary>
        public int bufpos { get; set; }

        /// <summary> unsigned int buflen; </summary>
        public int buflen { get; set; }

        /// <summary> uint32_t timestamp </summary>
        public uint timestamp { get; set; }

        /// <summary> uint8_t dataType </summary>
        public byte dataType { get; set; }

        /// <summary> uint8_t flags </summary>
        public byte flags { get; set; }

        public const byte RTMP_READ_HEADER = 0x01;
        public const byte RTMP_READ_RESUME = 0x02;
        public const byte RTMP_READ_NO_IGNORE = 0x04;
        public const byte RTMP_READ_GOTKF = 0x08;
        public const byte RTMP_READ_GOTFLVK = 0x10;
        public const byte RTMP_READ_SEEKING = 0x20;

        // int8_t status </summary>
        public sbyte status { get; set; }

        public const int RTMP_READ_COMPLETE = -3;
        public const int RTMP_READ_ERROR = -2;
        public const int RTMP_READ_EOF = -1;
        public const int RTMP_READ_IGNORE = 0;

        /* if bResume == TRUE */

        /// <summary> uint8_t initialFrameType </summary>
        public byte initialFrameType { get; set; }

        /// <summary> uint32_t nResumeTS </summary>
        public uint nResumeTS { get; set; }

        /// <summary> char* metaHeader </summary>
        public byte[] metaHeader { get; set; }

        /// <summary> char* initialFrame </summary>
        public byte[] initialFrame { get; set; }

        /// <summary> uint32_t nMetaHeaderSize </summary>
        public uint nMetaHeaderSize { get; set; }

        /// <summary> uint32_t nInitialFrameSize </summary>
        public uint nInitialFrameSize { get; set; }

        /// <summary> uint32_t nIgnoredFrameCounter </summary>
        public uint nIgnoredFrameCounter { get; set; }

        /// <summary> uint32_t nIgnoredFlvFrameCounter </summary>
        public uint nIgnoredFlvFrameCounter { get; set; }
    }
}