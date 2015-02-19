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
using System.Linq.Expressions;
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

        public const int RTMP_BUFFER_CACHE_SIZE = 16 * 2048;

        public const int RTMP_CHANNELS = 65600;

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
        public byte m_bSendCounter { get; set; }

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
        public static long RTMP_GetTime()
        {
#if _DEBUG
            return 0
#else
            return DateTime.Now.Ticks;
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

            var end = url.Length - p;
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

            if (slash != -1)
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
            throw new NotImplementedException();
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
            int protocol, AVal hostname, int port, AVal sockshost,
            AVal playpath, AVal tcUrl, AVal swfUrl, AVal pageUrl, AVal app,
            AVal auth, AVal swfSha256Hash, int swfSize, AVal flashVer,
            AVal subscribepath, AVal usherToken, int dStart, int dStop, bool bLiveStream, int timeout)
        {
            throw new NotImplementedException();
        }

        /// <summary> int RTMP_Connect(RTMP *r, RTMPPacket *cp); </summary>
        public static bool RTMP_Connect(RTMP r, RTMPPacket cp)
        {
            throw new NotImplementedException();
        }

        // int RTMP_Connect0(RTMP *r, struct sockaddr *svc);
        // int RTMP_Connect1(RTMP *r, RTMPPacket *cp);
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
            r.m_sb = new RTMPSockBuf { sb_socket = null };
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
        /// <summary> #define RTMPPacket_IsReady(a)  ((a)->m_nBytesRead == (a)->m_nBodySize) </summary>
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
        public int sb_timedout { get; set; }

        /// <summary> void *sb_ssl; </summary>
        public object sb_ssl { get; set; }
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