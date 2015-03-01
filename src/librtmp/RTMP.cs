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
    public partial class RTMP
    {
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

        /// <summary> uint32_t RTMP_GetTime() </summary>
        public static uint RTMP_GetTime()
        {
#if DEBUG
            return 0;
#else
            return (uint)DateTime.Now.Ticks;
#endif
        }

        /// <summary>void RTMP_UserInterrupt(void);</summary>
        /// <remarks>/* user typed Ctrl-C */</remarks>
        public static void RTMP_UserInterrupt()
        {
            RTMP_ctrlC = true;
        }

        /// <summary> int RTMP_LibVersion(void);</summary>
        public static int RTMP_LibVersion()
        {
            throw new NotImplementedException();
        }

        /// <summary> void RTMP_TLS_Init() </summary>
        public static void RTMP_TLS_init()
        {
            throw new NotImplementedException();
        }

        /// <summary> void *RTMP_TLS_AllocServerContext(const char* cert, const char* key);</summary>
        public static object RTMP_TLS_AllocServerContext(byte[] cert, byte[] key)
        {
            throw new NotImplementedException();
        }

        /// <summary> void RTMP_TLS_FreeServerContext(void *ctx);</summary>
        public static void RTMP_TLS_FreeServerContext(object ctx)
        {
            throw new NotImplementedException();
        }

        /// <summary> RTMP *RTMP_Alloc(void);</summary>
        public static RTMP RTMP_Alloc()
        {
            throw new NotImplementedException();
        }

        /// <summary> void RTMP_Free(RTMP *r);</summary>
        public static void RTMP_Free(RTMP r)
        {
            throw new NotImplementedException();
        }

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

        /// <summary> void RTMP_EnableWrite(RTMP *r);</summary>
        public static void MP_EnableWrite(RTMP r)
        {
            throw new NotImplementedException();
        }

        /// <summary> double RTMP_GetDuration(RTMP *r); </summary>
        public static double RTMP_GetDuration(RTMP r)
        {
            return r.m_fDuration;
        }

        /// <summary> int RTMP_IsConnected(RTMP *r); </summary>
        public static bool RTMP_IsConnected(RTMP r)
        {
            return r.m_sb.sb_socket != null && r.m_sb.sb_socket.Connected;
        }

        /// <summary> int RTMP_Socket(RTMP *r);</summary>
        public static Socket RTMP_Socket(RTMP r)
        {
            throw new NotImplementedException();
        }

        /// <summary> int RTMP_IsTimedout(RTMP *r);</summary>
        public static bool RTMP_IsTimedout(RTMP r)
        {
            throw new NotImplementedException();
        }

        /// <summary> void RTMP_SetBufferMS(RTMP *r, int size);</summary>
        public static void RTMP_SetBufferMS(RTMP r, int size)
        {
            r.m_nBufferMS = size;
        }

        /// <summary> void RTMP_UpdateBufferMS(RTMP *r);</summary>
        public static void RTMP_UpdateBufferMS(RTMP r)
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

        /// <summary> int RTMP_SetOpt(RTMP *r, const AVal *opt, AVal *arg)</summary>
        public static bool RTMP_SetOpt(RTMP r, AVal opt, AVal arg)
        {
            throw new NotImplementedException();
        }

        /// <summary> int RTMP_SetupURL(RTMP *r, char *url); </summary>
        public static bool RTMP_SetupURL(RTMP r, string url)
        {
            throw new NotImplementedException();
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

        /// <summary> int RTMP_TLS_Accept(RTMP *r, void *ctx);</summary>
        public static int RTMP_TLS_Accept(RTMP r, object ctx)
        {
            throw new NotImplementedException();
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

        /// <summary> int RTMP_ToggleStream(RTMP* r); </summary>
        public static bool RTMP_ToggleStream(RTMP r)
        {
            throw new NotImplementedException();
        }

        /// <summary> void RTMP_DeleteStream(RTMP *r);</summary>
        public static void RTMP_DeleteStream(RTMP r)
        {
            throw new NotImplementedException();
        }

        /// <summary> int RTMP_GetNextMediaPacket(RTMP *r, RTMPPacket *packet);</summary>
        public static int RTMP_GetNextMediaPacket(RTMP r, RTMPPacket packet)
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

        /// <summary> int RTMP_ClientPacket(RTMP *r, RTMPPacket *packet);</summary>
        public static int RTMP_ClientPacket(RTMP r, RTMPPacket packet)
        {
            const string __FUNCTION__ = "RTMP_ClientPacket";
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
                    Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "{0}, flex stream send, size {1} bytes, not supported, ignoring", __FUNCTION__, packet.BodySize);
                    break;

                case RTMP_PACKET_TYPE_FLEX_SHARED_OBJECT:
                    /* flex shared object */
                    Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "{0}, flex shared object, size {1} bytes, not supported, ignoring", __FUNCTION__, packet.BodySize);
                    break;

                case RTMP_PACKET_TYPE_FLEX_MESSAGE:
                    /* flex message */
                    {
                        Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "{0}, flex message, size {1} bytes, not fully supported", __FUNCTION__, packet.BodySize);
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
                    Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "{0}, unknown packet type received: 0x{1:x02}", __FUNCTION__, packet.PacketType);
#if  DEBUG
                    Log.RTMP_LogHex(Log.RTMP_LogLevel.RTMP_LOGDEBUG, packet.Body, packet.BodySize);
#endif
                    break;
            }

            return bHasMediaPacket;
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

        /// <summary>
        ///  int RTMP_SendPause(RTMP *r, int doPause, int iTime)
        /// /* caller probably doesn't know current timestamp, should just use RTMP_Pause instead */
        /// </summary>
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

        /// <summary> int RTMP_Pause(RTMP *r, int doPause);</summary>
        public static int RTMP_Pause(RTMP r, bool doPause)
        {
            throw new NotImplementedException();
        }

        /// <summary> int RTMP_SendSeek(RTMP *r, int dTime);</summary>
        public static int RTMP_SendSeek(RTMP r, int dtime)
        {
            throw new NotImplementedException();
        }

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

        /// <summary> int RTMP_SendClientBW(RTMP *r); </summary>
        public static int RTMP_SendClientBW(RTMP r)
        {
            throw new NotImplementedException();
        }

        /// <summary> int RTMP_SendCtrl(RTMP *r, short nType, unsigned int nObject,unsigned int nTime);</summary>
        /// <remarks>
        /// from http://jira.red5.org/confluence/display/docs/Ping:
        /// Ping is the most mysterious message in RTMP and till now we haven't fully interpreted it yet. In summary, Ping message is used as a special command that are exchanged between client and server. This page aims to document all known Ping messages. Expect the list to grow.
        /// The type of Ping packet is 0x4 and contains two mandatory parameters and two optional parameters. The first parameter is the type of Ping and in short integer. The second parameter is the target of the ping. As Ping is always sent in Channel 2 (control channel) and the target object in RTMP header is always 0 which means the Connection object, it's necessary to put an extra parameter to indicate the exact target object the Ping is sent to. The second parameter takes this responsibility. The value has the same meaning as the target object field in RTMP header. (The second value could also be used as other purposes, like RTT Ping/Pong. It is used as the timestamp.) The third and fourth parameters are optional and could be looked upon as the parameter of the Ping packet. Below is an unexhausted list of Ping messages.
        /// * type 0: Clear the stream. No third and fourth parameters. The second parameter could be 0. After the connection is established, a Ping 0,0 will be sent from server to client. The message will also be sent to client on the start of Play and in response of a Seek or Pause/Resume request. This Ping tells client to re-calibrate the clock with the timestamp of the next packet server sends.
        /// * type 1: Tell the stream to clear the playing buffer.
        /// * type 3: Buffer time of the client. The third parameter is the buffer time in millisecond.
        /// * type 4: Reset a stream. Used together with type 0 in the case of VOD. Often sent before type 0.
        /// * type 6: Ping the client from server. The second parameter is the current time.
        /// * type 7: Pong reply from client. The second parameter is the time the server sent with his ping request.
        /// * type 26: SWFVerification request
        /// * type 27: SWFVerification response
        /// </remarks>
        public static bool RTMP_SendCtrl(RTMP r, short nType, uint nObject, uint nTime)
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

        /// <summary> void RTMP_DropRequest(RTMP *r, int i, int freeit); </summary>
        public static void RTMP_DropRequest(RTMP r, int i, bool freeit)
        {
            throw new NotImplementedException();
        }

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
                /* using values from the last message of this channel */
                if (r.m_vecChannelsIn[packet.ChannelNum] != null)
                {
                    // Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "nSize < RTMP_LARGE_HEADER_SIZE : {0}", packet.ChannelNum);
                    //memcpy(packet, r.m_vecChannelsIn[packet.ChannelNum], sizeof (RTMPPacket));
                    packet = r.m_vecChannelsIn[packet.ChannelNum];
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

                // Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "{0}, reading RTMP packet chunk on channel {1:x}, headersz {2}, timestamp {3}, abs timestamp {4}", __FUNCTION__, packet.ChannelNum, nSize, packet.TimeStamp, packet.HasAbsTimestamp);

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
            if (nChunk != 0)
            {
                Array.Copy(rbuf, 0, packet.Body, packet.BytesRead, nChunk);
            }
            packet.BytesRead += (uint)nChunk;

            /* keep the packet as ref for other packets on this channel */
            //if (!r.m_vecChannelsIn[packet.ChannelNum])
            //{
            //    r.m_vecChannelsIn[packet.ChannelNum] = malloc(sizeof (RTMPPacket));
            //}
            //memcpy(r.m_vecChannelsIn[packet.ChannelNum], packet, sizeof (RTMPPacket));
            var clonePacket = new RTMPPacket
            {
                Body = (byte[])(packet.Body != null ? packet.Body.Clone() : null),
                BodySize = packet.BodySize,
                BytesRead = packet.BytesRead,
                ChannelNum = packet.ChannelNum,
                HasAbsTimestamp = packet.HasAbsTimestamp,
                HeaderType = packet.HeaderType,
                InfoField2 = packet.InfoField2,
                PacketType = packet.PacketType,
                TimeStamp = packet.TimeStamp,
                Chunk = packet.Chunk == null
                    ? null
                    : new RTMPChunk
                    {
                        c_header = packet.Chunk.c_header,
                        c_chunk = (byte[])packet.Chunk.c_chunk.Clone(), // TODO:
                        c_chunkSize = packet.Chunk.c_chunkSize,
                        c_headerSize = packet.Chunk.c_headerSize
                    }
            };

            r.m_vecChannelsIn[packet.ChannelNum] = clonePacket;

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

        /// <summary> int RTMP_SendChunk(RTMP *r, RTMPChunk *chunk); </summary>
        public static bool RTMP_SendChunk(RTMP r, RTMPChunk c)
        {
            throw new NotImplementedException();
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

        /// <summary> int RTMP_Serve(RTMP *r); </summary>
        public static bool RTMP_Serve(RTMP r)
        {
            return SHandShake(r);
        }

        /// <summary> void RTMP_Close(RTMP *r); </summary>
        public static void RTMP_Close(RTMP r)
        {
            CloseInternal(r, false);
        }

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

        /// <summary> int RTMP_Write(RTMP *r, const char *buf, int size);</summary>
        public static int RTMP_Write(RTMP r, byte[] buf, int size)
        {
            throw new NotImplementedException();
        }

        #region hashswf.c

        /// <summary> int RTMP_HashSWF(const char *url, unsigned int *size, unsigned char *hash, int age); </summary>
        public static int RTMP_HashSWF(byte[] url, ref int size, byte[] hash, int age)
        {
            throw new NotImplementedException();
        }

        #endregion

        #region parseurl.c

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

        /// <summary> void RTMP_ParsePlaypath(AVal *in, AVal *out);</summary>
        /// <remarks>
        /// Extracts playpath from RTMP URL. playpath is the file part of the
        /// URL, i.e. the part that comes after rtmp://host:port/app/
        /// Returns the stream name in a format understood by FMS. The name is
        /// the playpath part of the URL with formatting depending on the stream
        /// type:
        ///  mp4 streams: prepend "mp4:", remove extension
        ///  mp3 streams: prepend "mp3:", remove extension
        ///  flv streams: remove extension
        /// </remarks>
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

        #endregion
    }
}