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
using System.Net;

namespace librtmp
{
    public partial class RTMP
    {
#if CRYPTO
#else

        #region handshake.h

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

        #endregion

#endif

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

        // static void RTMP_OptUsage()
        // static int parseAMF(AMFObject *obj, AVal *av, int *depth)
        // static int add_addr_info(struct sockaddr_in *service, AVal *host, int port)

        /// <summary> static int SocksNegotiate(RTMP *r) </summary>
        /// <remarks> SOCKS proxy does not support </remarks>
        private static bool SocksNegotiate(RTMP r)
        {
            throw new NotImplementedException();
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

                        var ret = HTTP_read(r, false);
                        if (ret == -1)
                        {
                            Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "{0}, No valid HTTP response found", __FUNCTION__);
                            RTMP_Close(r);
                            return 0;
                        }

                        refill = ret == -2;
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

        /// <summary> static int SendFCPublish(RTMP *r) </summary>
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

        /// <summary> static int SendCheckBWResult(RTMP *r, double txn)</summary>
        private static bool SendCheckBWResult(RTMP r, double txn)
        {
            var pbuf = new byte[256];
            var pend = pbuf.Length;
            var enc = 0;
            enc = AMF.AMF_EncodeString(pbuf, enc, pend, av__result);
            enc = AMF.AMF_EncodeNumber(pbuf, enc, pend, txn);
            pbuf[enc++] = (byte)AMFDataType.AMF_NULL;
            enc = AMF.AMF_EncodeNumber(pbuf, enc, pend, r.m_nBWCheckCounter++);

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

        /// <summary> static int DecodeInt32LE(const char *data) </summary>
        private static int DecodeInt32LE(byte[] buf, int data)
        {
            return (buf[data + 3] << 24) | (buf[data + 2] << 16) | (buf[data + 1] << 8) | (buf[data + 0]);
        }

        /// <summary> static int EncodeInt32LE(char* output, int nVal)</summary>
        private static int EncodeInt32LE(byte[] buf, int output, int nVal)
        {
            var ci = BitConverter.GetBytes(nVal);
            buf[output + 0] = ci[0];
            buf[output + 1] = ci[1];
            buf[output + 2] = ci[2];
            buf[output + 3] = ci[3];
            return 4;
        }

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

            if (r.m_vecChannelsIn != null)
            {
                foreach (var p in r.m_vecChannelsIn)
                {
                    RTMPPacket.RTMPPacket_Free(p.Value);
                }

                r.m_vecChannelsIn = null;
            }

            if (r.m_vecChannelsOut != null)
            {
                foreach (var p in r.m_vecChannelsOut)
                {
                    RTMPPacket.RTMPPacket_Free(p.Value);
                }

                r.m_vecChannelsOut = null;
            }

            r.m_channelTimestamp = null;
            r.m_channelsAllocatedIn = 0;
            r.m_channelsAllocatedOut = 0;
            // AV_clear(r.m_methodCalls, r.m_numCalls);
            if (r.m_numCalls > 0)
            {
                if (r.m_methodCalls != null)
                {
                    r.m_methodCalls.Clear();
                    r.m_methodCalls = null;
                }
            }

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

        // static int Read_1_Packet(RTMP *r, char *buf, unsigned int buflen)
        private static int Read_1_Packet(RTMP r, byte[] buf, int offset, int buflen)
        {
            var prevTagSize = 0;
            var ret = RTMP_READ.RTMP_READ_EOF;
            var packet = new RTMPPacket();
            var recopy = false;
            uint nTimeStamp = 0;
            int len;

            var rtnGetNextMediaPacket = RTMP_GetNextMediaPacket(r, ref packet);
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
#if _DEBUG
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
                            int nRes = AMFObject.AMF_Decode(metaObj, packet.Body, packetBody, nPacketLen, false);
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
                                    /* 6928, test 0 */
                                    /* && (packetBody[11]&0xf0) == 0x10 */
                                    if (packet.Body[packetBody + pos] == r.m_read.initialFrameType)
                                    {
                                        if (ts == r.m_read.nResumeTS)
                                        {
                                            Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "Found keyframe with resume-keyframe timestamp!");
                                            var unmatch = memcmp(r.m_read.initialFrame, 0, packet.Body, packetBody + pos + 11, (int)r.m_read.nInitialFrameSize);
                                            if (r.m_read.nInitialFrameSize != dataSize || unmatch)
                                            {
                                                Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGERROR, "FLV Stream: Keyframe doesn't match!");
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

                                        if (r.m_read.nResumeTS < ts)
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

                                if ((r.m_read.flags & RTMP_READ.RTMP_READ_GOTFLVK) == 0x00)
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
                    if ((r.m_read.flags & RTMP_READ.RTMP_READ_GOTKF) == 0x00
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
                    if ((r.m_read.flags & RTMP_READ.RTMP_READ_GOTFLVK) == 0x00
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
                    if ((r.m_read.flags & RTMP_READ.RTMP_READ_NO_IGNORE) == 0x00
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

                        /* stop ignoring packets */
                        r.m_read.flags |= RTMP_READ.RTMP_READ_NO_IGNORE;
                    }
                }

                /* calculate packet size and allocate slop buffer if necessary */
                var size = nPacketLen +
                           ((packet.PacketType == RTMP_PACKET_TYPE_AUDIO
                             || packet.PacketType == RTMP_PACKET_TYPE_VIDEO
                             || packet.PacketType == RTMP_PACKET_TYPE_INFO) ? 11 : 0)
                           + (packet.PacketType != RTMP_PACKET_TYPE_FLASH_VIDEO ? 4 : 0);

                int ptr;
                byte[] ptrBuf;
                if (size + 4 > buflen)
                {
                    /* the extra 4 is for the case of an FLV stream without a last
                     * prevTagSize (we need extra 4 bytes to append it) */
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

                var pend = ptr + size + 4;

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
                    /* grab first timestamp and see if it needs fixing */
                    nTimeStamp = AMF.AMF_DecodeInt24(packet.Body, packetBody + 4);
                    nTimeStamp |= (uint)(packet.Body[packetBody + 7] << 24);
                    int delta = (int)(packet.TimeStamp - nTimeStamp + r.m_read.nResumeTS);

                    int pos = 0;
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

#if _DEBUG
                            Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG,
                                "FLV Packet: type {0:X2}, dataSize: {1}, tagSize: {2}, timeStamp: {3} ms",
                                packet.Body[packetBody + pos], dataSize, prevTagSize, nTimeStamp);
#endif

                            if (prevTagSize != (dataSize + 11))
                            {
#if _DEBUG
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
    }
}