/*  RTMP Proxy Server
 *  Copyright (C) 2009 Andrej Stepanchuk
 *  Copyright (C) 2009 Howard Chu
 *
 *  This Program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2, or (at your option)
 *  any later version.
 *
 *  This Program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with RTMPDump; see the file COPYING.  If not, write to
 *  the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 *  Boston, MA  02110-1301, USA.
 *  http://www.gnu.org/copyleft/gpl.html
 *
 */

/* This is a Proxy Server that displays the connection parameters from a
 * client and then saves any data streamed to the client.
 */

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security;
using System.Threading;
using librtmp;

namespace rtmpsuck
{
    public enum RD_STATUS
    {
        RD_SUCCESS = 0,
        RD_FAILED = 1,
        RD_INCOMPLETE = 2
    };

    public class Program
    {
        private static void Main(string[] args)
        {
            var app = new App();
            app.Run(args);
        }
    }

    public class App
    {
        public RD_STATUS Run(string[] args)
        {
            var nStatus = RD_STATUS.RD_SUCCESS;
            const string DEFAULT_RTMP_STREAMING_DEVICE = "0.0.0.0";
            var rtmpStreamingDevice = DEFAULT_RTMP_STREAMING_DEVICE;
            var nRtmpStreamingPort = 1935;

            const string RTMPDUMP_VERSION = "v2.4"; // TODO:
            Log.RTMP_LogPrintf("RTMP Proxy Server {0}\n", RTMPDUMP_VERSION);
            Log.RTMP_LogPrintf("(c) 2010 Andrej Stepanchuk, Howard Chu; license: GPL\n\n");
            Log.RTMP_LogSetLevel(Log.RTMP_LogLevel.RTMP_LOGINFO);

            if (args.Length > 0 && args[0] == "-z")
            {
                Log.RTMP_LogSetLevel(Log.RTMP_LogLevel.RTMP_LOGALL);
            }

            Console.CancelKeyPress += sigIntHandler;
            // TODO: signal(SIGPIPE, SIG_IGN);

            open_dump_file();

            // InitSocket();

            ThreadCreate(controlServerThread);
            rtmpServer = startStreaming(rtmpStreamingDevice, nRtmpStreamingPort);
            if (rtmpServer == null)
            {
                Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGERROR, "Failed to start RTMP server, exiting!");
                return RD_STATUS.RD_FAILED;
            }

            Log.RTMP_LogPrintf("Streaming on rtmp://{0}:{1}\n", rtmpStreamingDevice, nRtmpStreamingPort);
            while (rtmpServer.state != STREAMING_STATUS.STREAMING_STOPPED)
            {
                Thread.Sleep(1000);
            }

            Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "Done, extiting...");

            // CleanupSockets();

            close_dump_file();

            return nStatus;
        }

        private void ThreadCreate(Action func)
        {
            var start = new ThreadStart(func);
            var th = new Thread(start);
            th.Start();
        }

        private void ThreadCreate<T>(Action<T> func, T arg)
        {
            var start = new ThreadStart(() => func(arg));
            var th = new Thread(start);
            th.Start();
        }

        private void controlServerThread()
        {
            while (true)
            {
                var ich = Console.ReadKey();
                switch (ich.KeyChar)
                {
                    case 'q':
                        Log.RTMP_LogPrintf("Exiting\n");
                        stopStreaming(rtmpServer);
                        Environment.Exit(0); // FIXME: more portable.
                        break;

                    default:
                        Log.RTMP_LogPrintf("Unknown command '{0}', ignoring\n", ich.KeyChar);
                        break;
                }
            }
        }

        // TODO: C#-style resource handling

        private BinaryWriter _netStackDump;

        private BinaryWriter _netStackDumpRead;

        [Conditional("DEBUG")]
        private void open_dump_file()
        {
            _netStackDump = new BinaryWriter(new FileStream("netstackdump", FileMode.CreateNew, FileAccess.Write));
            _netStackDumpRead = new BinaryWriter(new FileStream("netstackdump_read", FileMode.CreateNew, FileAccess.Write));
        }

        [Conditional("DEBUG")]
        private void close_dump_file()
        {
            if (_netStackDump != null)
            {
                _netStackDump.Close();
            }

            if (_netStackDumpRead != null)
            {
                _netStackDumpRead.Close();
            }
        }

        private void sigIntHandler(object sender, ConsoleCancelEventArgs e)
        {
            RTMP.RTMP_ctrlC = true;
            var sig = 2; // SIGINT = 2; man 7 signal, POSIX.1-1990 ?
            Log.RTMP_LogPrintf("Caught signal: {0}, cleaning up, just a second...\n", sig);
            if (rtmpServer != null)
            {
                stopStreaming(rtmpServer);
            }
        }

        private enum STREAMING_STATUS
        {
            STREAMING_ACCEPTING,
            STREAMING_IN_PROGRESS,
            STREAMING_STOPPING,
            STREAMING_STOPPED
        };

        private STREAMING_SERVER rtmpServer;

        private class STREAMING_SERVER
        {
            /// <summary> int state </summary>
            public STREAMING_STATUS state { get; set; }

            /// <summary> int socket </summary>
            public Socket socket { get; set; }

            /// <summary> uint32_t stamp </summary>
            public uint stamp { get; set; }

            /// <summary> RTMP rs </summary>
            public RTMP rs { get; set; }

            /// <summary> RTMP rc </summary>
            public RTMP rc { get; set; }

            /// <summary> Plist* rs_pkt[2] </summary>
            public List<RTMPPacket> rs_pkt;

            /// <summary> Plist* rs_pkt[2] </summary>
            public List<RTMPPacket> rc_pkt;

            /// <summary> Flist* f_head </summary>
            public List<Flist> f_head;

            /// <summary> Flist* f_cur </summary>
            public int f_cur { get; set; }

            public STREAMING_SERVER()
            {
                state = STREAMING_STATUS.STREAMING_STOPPED;
                socket = null;
                f_cur = 0;
            }
        }

        /// <summary>
        /// struct Flist
        /// </summary>
        private class Flist
        {
            /// <summary> FILE *f_file; </summary>
            public object f_file;

            /// <summary> AVal f_path; </summary>
            public AVal f_path;
        }

        private void doServe(STREAMING_SERVER server)
        {
            uint buflen = 131072;
            bool paused = false;
            var sock = server.socket;

            server.state = STREAMING_STATUS.STREAMING_IN_PROGRESS;
            if (sock.Poll(5000, SelectMode.SelectRead))
            {
                Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGERROR, "Request timeout/select failed, ignoring request");
                // goto quit;
            }
            else
            {
                RTMP.RTMP_Init(server.rs);
                RTMP.RTMP_Init(server.rc);
                server.rs.m_sb.sb_socket = sock;
                if (!RTMP.RTMP_Serve(server.rs))
                {
                    Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGERROR, "Handshake failed.");
                    // goto cleanup;
                }
                else
                {
                    var ps = new RTMPPacket();
                    while (RTMP.RTMP_IsConnected(server.rs)
                           && RTMP.RTMP_ReadPacket(server.rs, out ps))
                    {
                        if (!ps.IsReady())
                        {
                            continue;
                        }

                        ServePacket(server, 0, ps);
                        ps.Free();
                        if (RTMP.RTMP_IsConnected(server.rc))
                        {
                            break;
                        }
                    }
                }
            }
        }

        private string[] cst = { "client", "server" };

        private int ServePacket(STREAMING_SERVER server, int which, RTMPPacket packet)
        {
            var __FUNCTION__ = "ServePacket";
            int ret = 0;
            Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG,
                "{0}, {1} sent packet type {2:2x}, size {3} bytes",
                __FUNCTION__, cst[which], packet.PacketType, packet.BodySize);
            switch (packet.PacketType)
            {
                case RTMPPacket.RTMP_PACKET_TYPE_CHUNK_SIZE:
                    // chunk size
                    //      HandleChangeChunkSize(r, packet);
                    break;

                case RTMPPacket.RTMP_PACKET_TYPE_BYTES_READ_REPORT:
                    // bytes read report
                    break;

                case RTMPPacket.RTMP_PACKET_TYPE_CONTROL:
                    // ctrl
                    //      HandleCtrl(r, packet);
                    break;

                case RTMPPacket.RTMP_PACKET_TYPE_SERVER_BW:
                    // server bw
                    //      HandleServerBW(r, packet);
                    break;

                case RTMPPacket.RTMP_PACKET_TYPE_CLIENT_BW:
                    // client bw
                    //     HandleClientBW(r, packet);
                    break;

                case RTMPPacket.RTMP_PACKET_TYPE_AUDIO:
                    // audio data
                    //RTMP_Log(RTMP_LOGDEBUG, "%s, received: audio %lu bytes", __FUNCTION__, packet.m_nBodySize);
                    break;

                case RTMPPacket.RTMP_PACKET_TYPE_VIDEO:
                    // video data
                    //RTMP_Log(RTMP_LOGDEBUG, "%s, received: video %lu bytes", __FUNCTION__, packet.m_nBodySize);
                    break;

                case RTMPPacket.RTMP_PACKET_TYPE_FLEX_STREAM_SEND:
                    // flex stream send
                    break;

                case RTMPPacket.RTMP_PACKET_TYPE_FLEX_SHARED_OBJECT:
                    // flex shared object
                    break;

                case RTMPPacket.RTMP_PACKET_TYPE_FLEX_MESSAGE:
                    // flex message
                    {
                        ret = ServeInvoke(server, which, packet, packet.Body.Skip(1).ToArray());
                        break;
                    }
                case RTMPPacket.RTMP_PACKET_TYPE_INFO:
                    // metadata (notify)
                    break;

                case RTMPPacket.RTMP_PACKET_TYPE_SHARED_OBJECT:
                    /* shared object */
                    break;

                case RTMPPacket.RTMP_PACKET_TYPE_INVOKE:
                    // invoke
                    ret = ServeInvoke(server, which, packet, packet.Body);
                    break;

                case RTMPPacket.RTMP_PACKET_TYPE_FLASH_VIDEO:
                    /* flv */
                    break;

                default:
                    Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "{0}, unknown packet type received: 0x{1:02x}", __FUNCTION__, packet.PacketType);
                    serverPacket_Dump(packet);
                    break;
            }

            return ret;
        }

        [Conditional("DEBUG")]
        private void serverPacket_Dump(RTMPPacket packet)
        {
            Log.RTMP_LogHex(Log.RTMP_LogLevel.RTMP_LOGDEBUG, packet.Body, packet.BodySize);
        }

        // Returns 0 for OK/Failed/error, 1 for 'Stop or Complete'
        // int ServeInvoke(STREAMING_SERVER *server, int which, RTMPPacket *pack, const char *body)
        private int ServeInvoke(STREAMING_SERVER server, int which, RTMPPacket pack, byte[] body)
        {
            var __FUNCTION__ = "ServeInvoke";

            int bodySize = (int)pack.BodySize;
            if (body.Length < pack.Body.Length)
            {
                bodySize--;
            }

            if (body[0] != 0x02)
            {
                Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGWARNING, "{0}, Sanity failed. no string method in invoke packet", __FUNCTION__);
                return 0;
            }

            AMFObject obj = new AMFObject(); // TODO:
            var nRes = AMFObject.AMF_Decode(obj, body, bodySize, false);
            if (nRes < 0)
            {
                Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGERROR, "{0}, error decoding invoke packet", __FUNCTION__);
                return 0;
            }

            AMFObject.AMF_Dump(obj);
            AVal method;
            AMFObjectProperty.AMFProp_GetString(AMFObject.AMF_GetProp(obj, null, 0), out method);
            Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "{0}, {1} invoking <{2}>", __FUNCTION__, cst[which], method.av_val);
            int ret = 0;
            if (AVal.Match(method, av_connect))
            {
                AMFObject cobj;
                AMFObjectProperty.AMFProp_GetObject(AMFObject.AMF_GetProp(obj, null, 2), out cobj);
                Log.RTMP_LogPrintf("Processing connect\n");
                for (var i = 0; i < cobj.o_num; ++i)
                {
                    var pname = cobj.o_props[i].p_name;
                    var pval = new AVal { av_len = 0, av_val = new byte[] { } };
                    if (cobj.o_props[i].p_type == AMFDataType.AMF_STRING)
                    {
                        pval = cobj.o_props[i].p_aval;
                        // RTMP_LogPrintf("%.*s: %.*s\n", pname.av_len, pname.av_val, pval.av_len, pval.av_val);
                        Log.RTMP_LogPrintf("{0}: {1}\n",
                            new string(pname.av_val.Select(b => (char)b).ToArray()),
                            new string(pval.av_val.Select(b => (char)b).ToArray()));
                    }

                    if (AVal.Match(pname, av_app))
                    {
                        server.rc.Link.app = pval;
                        pval.av_val = new byte[0];
                    }
                    else if (AVal.Match(pname, av_flashVer))
                    {
                        server.rc.Link.flashVer = pval;
                        pval.av_val = new byte[0];
                    }
                    else if (AVal.Match(pname, av_swfUrl))
                    {
                        #region CRYPTO

                        // if (pval.av_val)
                        if (pval.av_val.Any())
                        {
                            var size = (int)server.rc.Link.SWFSize;
                            RTMP.RTMP_HashSWF(pval.av_val, ref size, server.rc.Link.SWFHash, 30);
                            server.rc.Link.SWFSize = (uint)size;
                        }

                        #endregion

                        server.rc.Link.swfUrl = pval;
                        pval.av_val = new byte[0];
                    }
                    else if (AVal.Match(pname, av_tcUrl))
                    {
                        int r1 = 0;
                        server.rc.Link.tcUrl = pval;
                        var head = pval.av_val.Take(4).Select(b => b | 0x40).Select(b => (char)b).ToArray();
                        if (head.SequenceEqual("rtmp".ToCharArray()))
                        {
                            // r1 = 'rtmp://' . <- here ?
                            if (pval.av_val[4] == ':')
                            {
                                server.rc.Link.protocol = RTMP.RTMP_PROTOCOL_RTMP;
                                r1 = 7;
                            }
                            else if ((pval.av_val[4] | 0x40) == 'e' && pval.av_val[5] == ':')
                            {
                                server.rc.Link.protocol = RTMP.RTMP_PROTOCOL_RTMPE;
                                r1 = 8;
                            }

                            var host = pval.av_val.Skip(r1).TakeWhile(b => b != '/').ToArray();
                            if (host.Any(p => p == ':'))
                            {
                                server.rc.Link.hostname.av_val = host.TakeWhile(p => p != ':').ToArray();
                                server.rc.Link.hostname.av_len = server.rc.Link.hostname.av_val.Length;
                                var portStr = host.SkipWhile(p => p != ':').Skip(1).ToArray();
                                server.rc.Link.port = ushort.Parse(new string(portStr.Select(b => (char)b).ToArray()));
                            }
                            else
                            {
                                server.rc.Link.hostname.av_val = host;
                                server.rc.Link.hostname.av_len = host.Length;
                                server.rc.Link.port = 1935;
                            }
                        }

                        pval.av_val = new byte[0];
                    }
                    else if (AVal.Match(pname, av_pageUrl))
                    {
                        server.rc.Link.pageUrl = pval;
                        pval.av_val = new byte[0];
                    }
                    else if (AVal.Match(pname, av_audioCodecs))
                    {
                        server.rc.m_fAudioCodecs = cobj.o_props[i].p_number;
                    }
                    else if (AVal.Match(pname, av_videoCodecs))
                    {
                        server.rc.m_fVideoCodecs = cobj.o_props[i].p_number;
                    }
                    else if (AVal.Match(pname, av_objectEncoding))
                    {
                        server.rc.m_fEncoding = cobj.o_props[i].p_number;
                        server.rc.m_bSendEncoding = 1; // TRUE
                    }

                    /* Dup'd a string we didn't recognize? */
                    // if (pval.av_val) free(pval.av_val);
                }

                if (obj.o_num > 3)
                {
                    if (AMFObjectProperty.AMFProp_GetBoolean(obj.o_props[3]))
                    {
                        server.rc.Link.lFlags |= RTMP_LNK.RTMP_LNK_FLAG.RTMP_LF_AUTH;
                    }

                    if (obj.o_num > 4)
                    {
                        AVal auth;
                        AMFObjectProperty.AMFProp_GetString(obj.o_props[4], out auth);
                        server.rc.Link.auth = auth;
                    }
                }

                if (!RTMP.RTMP_Connect(server.rc, pack))
                {
                    return 1;
                }

                server.rc.m_bSendCounter = 0; // FALSE
            }
            else if (AVal.Match(method, av_play))
            {
                /*
                 * Flist *fl;
                 * AVal av;
                 * FILE *out;
                 * char *file, *p, *q;
                 * int count = 0, flen;
                 */
                var flvHeader = new byte[]
                {
                    0x46, 0x4C, 0x56, 0x01, // 'F', 'L', 'V',
                    0x05, // video + audio, we finalize later if the value is different
                    0x00, 0x00, 0x00, 0x09, //
                    0x00, 0x00, 0x00, 0x00 // first prevTagSize=0
                };

                server.rc.m_stream_id = pack.InfoField2;
                AVal av;
                AMFObjectProperty.AMFProp_GetString(AMFObject.AMF_GetProp(obj, null, 3), out av);
                server.rc.Link.playpath = av;
                if (!av.av_val.Any())
                {
                    // goto out
                    AMFObject.AMF_Reset(obj);
                    return ret;
                }

                /* check for duplicates */
                var count = server.f_head.Count(fl => AVal.Match(av, fl.f_path));
                /* strip trailing URL parameters */
                if (av.av_val.Any(b => b == '?'))
                {
                    if (av.av_val[0] == '?')
                    {
                        av.av_val = av.av_val.Skip(1).ToArray();
                        av.av_len--;
                    }
                    else
                    {
                        av.av_len = av.av_val.TakeWhile(b => b != '?').Count();
                    }
                }

                /* strip leading slash components */
                for (var p = av.av_len - 1; p >= 0; --p)
                {
                    if (av.av_val[p] == '/')
                    {
                        av.av_len -= p;
                        av.av_val = av.av_val.Reverse().Take(p).Reverse().ToArray();
                        break;
                    }
                }

                if (av.av_val[0] == '.')
                {
                    av.av_len--;
                    av.av_val = av.av_val.Skip(1).ToArray();
                }

                var file = new string(av.av_val.Take(av.av_len).Select(b => (char)b).ToArray());
                if (count != 0)
                {
                    file += count.ToString("x2");
                }

                file = file.Replace(':', '_');
                Log.RTMP_LogPrintf("Playpath: {0}\nSaving as: {1}\n", server.rc.Link.playpath.av_val, file);
                try
                {
                    var fs = new FileStream(file, FileMode.Create, FileAccess.Write);
                    fs.Write(flvHeader, 0, flvHeader.Length);
                    server.f_head.Add(new Flist
                    {
                        f_file = fs,
                        f_path = server.rc.Link.playpath
                    });
                }
                catch (Exception)
                {
                    ret = 1;
                }
            }
            else if (AVal.Match(method, av_onStatus))
            {
                AMFObject obj2;
                AVal code, level;
                AMFObjectProperty.AMFProp_GetObject(AMFObject.AMF_GetProp(obj, null, 3), out obj2);
                AMFObjectProperty.AMFProp_GetString(AMFObject.AMF_GetProp(obj2, av_code, -1), out code);
                AMFObjectProperty.AMFProp_GetString(AMFObject.AMF_GetProp(obj2, av_level, -1), out level);

                Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "{0}, onStatus: {1}", __FUNCTION__, code.av_val);
                if (AVal.Match(code, av_NetStream_Failed)
                    || AVal.Match(code, av_NetStream_Play_Failed)
                    || AVal.Match(code, av_NetStream_Play_StreamNotFound)
                    || AVal.Match(code, av_NetConnection_Connect_InvalidApp))
                {
                    ret = 1;
                }

                if (AVal.Match(code, av_NetStream_Play_Start))
                {
                    /* set up the next stream */
                    if (server.f_cur != 0)
                    {
                        server.f_cur++;
                    }
                    else
                    {
                        for (var i = 0; i < server.f_head.Count; ++i)
                        {
                            if (server.f_head[i].f_file != null)
                            {
                                server.f_cur = i;
                                break;
                            }
                        }
                    }

                    server.rc.m_bPlaying = 1; // TRUE
                }

                // Return 1 if this is a Play.Complete or Play.Stop
                if (AVal.Match(code, av_NetStream_Play_Complete)
                    || AVal.Match(code, av_NetStream_Play_Stop))
                {
                    ret = 1;
                }
            }
            else if (AVal.Match(method, av_closeStream))
            {
                ret = 1;
            }
            else if (AVal.Match(method, av_close))
            {
                RTMP.RTMP_Close(server.rc);
                ret = 1;
            }

            // out:
            AMFObject.AMF_Reset(obj);
            return ret;
        }

        private void serverThread(STREAMING_SERVER server)
        {
            var __FUNCTION__ = "serverThread";
            server.state = STREAMING_STATUS.STREAMING_ACCEPTING;
            while (server.state == STREAMING_STATUS.STREAMING_ACCEPTING)
            {
                try
                {
                    var client = server.socket.Accept();
                    Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG,
                        "{0}: accepted connection from {1}\n", __FUNCTION__, client.RemoteEndPoint);
                    var srv2 = new STREAMING_SERVER { socket = client };
                    ThreadCreate(doServe, srv2);
                }
                catch (Exception ee)
                {
                    Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGERROR, "{0}: accept failed. {1}", __FUNCTION__, ee);
                }
            }

            server.state = STREAMING_STATUS.STREAMING_STOPPED;
        }

        private STREAMING_SERVER startStreaming(string address, int port)
        {
            var __FUNCTION__ = "startStreaming";
            Socket socket;
            try
            {
                socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            }
            catch (SocketException)
            {
                Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGERROR, "{0}, couldn't create socket", "startStreamingServer");
                return null;
            }

            socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
            try
            {
                var ipaddr = IPAddress.Parse(address);
                var localEndPoint = new IPEndPoint(ipaddr, port);
                socket.Bind(localEndPoint);
            }
            catch (Exception ee)
            {
                // catch only Socket.Bind()'s exception
                if (ee is SocketException
                    || ee is ObjectDisposedException
                    || ee is SecurityException
                    || ee is ArgumentNullException)
                {
                    Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGERROR,
                        "{0}, TCP bind failed for port number: {1}", __FUNCTION__, port);
                }
                else
                {
                    throw;
                }
            }

            try
            {
                socket.Listen(10);
            }
            catch (Exception ee)
            {
                if (ee is SocketException || ee is ObjectDisposedException)
                {
                    Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGERROR, "{0}, listen failed", __FUNCTION__);
                }
                else
                {
                    throw;
                }
            }

            var server = new STREAMING_SERVER { socket = socket };
            ThreadCreate(serverThread, server);
            return server;
        }

        private void stopStreaming(STREAMING_SERVER server)
        {
            Debug.Assert(server != null);
            if (server.state != STREAMING_STATUS.STREAMING_STOPPED)
            {
                var s = server.socket;
                if (server.state == STREAMING_STATUS.STREAMING_IN_PROGRESS)
                {
                    server.state = STREAMING_STATUS.STREAMING_STOPPING;
                    while (server.state != STREAMING_STATUS.STREAMING_STOPPED)
                    {
                        Thread.Sleep(1);
                    }
                }

                if (s != null)
                {
                    // s.Shutdown(SocketShutdown.Both); // XXX: need this?
                    s.Close();
                    // socket close error ???
                    // Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGERROR, "{0}: Failed to close listening socket, error {1}", "stopStreaming", GetSockError());
                }

                server.state = STREAMING_STATUS.STREAMING_STOPPED;
            }
        }

        private readonly AVal av_app = AVC("app");
        private readonly AVal av_connect = AVC("connect");
        private readonly AVal av_flashVer = AVC("flashVer");
        private readonly AVal av_swfUrl = AVC("swfUrl");
        private readonly AVal av_pageUrl = AVC("pageUrl");
        private readonly AVal av_tcUrl = AVC("tcUrl");
        private readonly AVal av_fpad = AVC("fpad");
        private readonly AVal av_capabilities = AVC("capabilities");
        private readonly AVal av_audioCodecs = AVC("audioCodecs");
        private readonly AVal av_videoCodecs = AVC("videoCodecs");
        private readonly AVal av_videoFunction = AVC("videoFunction");
        private readonly AVal av_objectEncoding = AVC("objectEncoding");
        private readonly AVal av__result = AVC("_result");
        private readonly AVal av_createStream = AVC("createStream");
        private readonly AVal av_play = AVC("play");
        private readonly AVal av_closeStream = AVC("closeStream");
        private readonly AVal av_fmsVer = AVC("fmsVer");
        private readonly AVal av_mode = AVC("mode");
        private readonly AVal av_level = AVC("level");
        private readonly AVal av_code = AVC("code");
        private readonly AVal av_secureToken = AVC("secureToken");
        private readonly AVal av_onStatus = AVC("onStatus");
        private readonly AVal av_close = AVC("close");
        private readonly AVal av_NetStream_Failed = AVC("NetStream.Failed");
        private readonly AVal av_NetStream_Play_Failed = AVC("NetStream.Play.Failed");
        private readonly AVal av_NetStream_Play_StreamNotFound = AVC("NetStream.Play.StreamNotFound");
        private readonly AVal av_NetConnection_Connect_InvalidApp = AVC("NetConnection.Connect.InvalidApp");
        private readonly AVal av_NetStream_Play_Start = AVC("NetStream.Play.Start");
        private readonly AVal av_NetStream_Play_Complete = AVC("NetStream.Play.Complete");
        private readonly AVal av_NetStream_Play_Stop = AVC("NetStream.Play.Stop");

        private static AVal AVC(string str)
        {
            return new AVal
            {
                av_len = str.Length,
                av_val = str.ToCharArray().Select(c => (byte)c).ToArray()
            };
        }
    }
}