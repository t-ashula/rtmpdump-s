/*  RTMPDump
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

#define CRYPTO

using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using librtmp;

namespace rtmpdump
{
    internal class Program
    {
        private static void Main(string[] args)
        {
            var app = new App();
            app.Run(args);
        }
    }

    /// <summary>
    ///
    /// </summary>
    public enum RD_STATUS
    {
        RD_SUCCESS = 0,
        RD_FAILED = 1,
        RD_INCOMPLETE = 2,
        RD_NO_CONNECT = 3
    }

    public class App
    {
        private const int DEF_TIMEOUT = 30; // secconds
        private const int DEF_BUFTIME = 10 * 60 * 60 * 1000; // 10 hours default
        private const int DEF_SKIPFRM = 0;

        /// <summary> int main(int argc, char**argv) </summary>
        /// <param name="args"></param>
        /// <returns></returns>
        public RD_STATUS Run(string[] args)
        {
            var nStatus = RD_STATUS.RD_SUCCESS;
            double percent = 0;
            double duration = 0.0;

            int nSkipKeyFrames = DEF_SKIPFRM; // skip this number of keyframes when resuming

            // int bOverrideBufferTime = FALSE; // if the user specifies a buffer time override this is true
            bool bOverrideBufferTime = false;
            // int bStdoutMode = TRUE; // if true print the stream directly to stdout, messages go to stderr
            bool bStdoutMode = true;
            // int bResume = FALSE; // true in resume mode
            bool bResume = false;

            int dSeek = 0; // uint32_t dSeek = 0; // seek position in resume mode, 0 otherwise
            int bufferTime = DEF_BUFTIME; // uint32_t bufferTime = DEF_BUFTIME;

            // meta header and initial frame for the resume mode (they are read from the file and compared with
            // the stream we are trying to continue
            // char* metaHeader = 0;
            byte[] metaHeader = new byte[0];
            uint nMetaHeaderSize = 0;

            // video keyframe for matching
            // char* initialFrame = 0;
            byte[] initialFrame = new byte[0];

            uint nInitialFrameSize = 0;
            int initialFrameType = 0; // tye: audio or video

            AVal hostname = new AVal();
            AVal playpath = new AVal();
            AVal subscribepath = new AVal();
            AVal usherToken = new AVal(); //Justin.tv auth token
            int port = -1;
            int protocol = RTMP.RTMP_PROTOCOL_UNDEFINED;
            int retries = 0;
            // int bLiveStream = FALSE; // is it a live stream? then we can't seek/resume
            bool bLiveStream = false;
            // int bRealtimeStream = FALSE; // If true, disable the BUFX hack (be patient)
            bool bRealtimeStream = false;
            // int bHashes = FALSE; // display byte counters not hashes by default
            bool bHashes = false;

            int timeout = DEF_TIMEOUT; // timeout connection after 120 seconds
            int dStartOffset = 0; // uint32_t dStartOffset = 0; // seek position in non-live mode
            int dStopOffset = 0; // uint32_t dStopOffset = 0;
            RTMP rtmp = new RTMP();

            AVal fullUrl = new AVal();
            AVal swfUrl = new AVal();
            AVal tcUrl = new AVal();
            AVal pageUrl = new AVal();
            AVal app = new AVal();
            AVal auth = new AVal();
            AVal swfHash = new AVal();
            int swfSize = 0; // uint32_t swfSize = 0;
            AVal flashVer = new AVal();
            AVal sockshost = new AVal();

#if CRYPTO
            int swfAge = 30; /* 30 days for SWF cache by default */
            bool swfVfy = false; // int swfVfy = 0;
            byte[] hash = new byte[RTMP_LNK.RTMP_SWF_HASHLEN]; // [RTMP_SWF_HASHLEN];
#endif

            //  char* flvFile = 0;
            var flvFile = string.Empty;

            Console.CancelKeyPress += sigIntHandler; // signal(SIGINT, sigIntHandler);
            // signal(SIGTERM, sigIntHandler);
#if WIN32
#else
            // TODO: Signal
            // signal(SIGHUP, sigIntHandler);
            // signal(SIGPIPE, sigIntHandler);
            // signal(SIGQUIT, sigIntHandler);
#endif

            Log.RTMP_LogSetLevel(Log.RTMP_LogLevel.RTMP_LOGINFO);
            // Check for --quiet option before printing any output
            int index = 0;
            int argc = args.Length;
            while (index < argc)
            {
                if (args[index] == "--quiet" || args[index] == "-q")
                {
                    Log.RTMP_LogSetLevel(Log.RTMP_LogLevel.RTMP_LOGCRIT);
                }

                index++;
            }

            Log.RTMP_LogPrintf("RTMPDump {0}\n", "2.4"); // TODO: RTMPDUMP_VERSION
            Log.RTMP_LogPrintf("(c) 2010 Andrej Stepanchuk, Howard Chu, The Flvstreamer Team; license: GPL\n");

            if (!InitSockets())
            {
                Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGERROR, "Couldn't load sockets support on your platform, exiting!");
                return RD_STATUS.RD_FAILED;
            }

            rtmp = new RTMP();
            RTMP.RTMP_Init(rtmp);

            for (var i = 0; i < argc; ++i)
            {
                var arg = args[i];
                var optarg = (i < argc - 1) ? args[i + 1] : string.Empty;
                if (arg == "-h" || arg == "--help")
                {
                    usage();
                    return RD_STATUS.RD_SUCCESS;
                }

#if CRYPTO
                else if (arg == "-w" || arg == "--swfhash")
                {
                    swfHash.av_val = Hex2Bin(optarg);
                    if (swfHash.av_val.Length != RTMP_LNK.RTMP_SWF_HASHLEN)
                    {
                        Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGWARNING,
                            "Couldn't parse swf hash hex string, not hexstring or not {0} bytes, ignoring!",
                            RTMP_LNK.RTMP_SWF_HASHLEN);
                    }

                    swfHash.av_len = RTMP_LNK.RTMP_SWF_HASHLEN;
                    ++i;
                }
                else if (arg == "-x" || arg == "--swfsize")
                {
                    int n;
                    if (int.TryParse(optarg, out n) && n > 0)
                    {
                        swfSize = n;
                    }
                    else
                    {
                        Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGERROR, "SWF Size must be at least 1, ignoring\n");
                    }

                    ++i;
                }
                else if (arg == "-W" || arg == "--swfVfy")
                {
                    swfUrl = Str2Aval(optarg);
                    swfVfy = true;
                    ++i;
                }
                else if (arg == "-X" || arg == "--swfAge")
                {
                    int num;
                    if (int.TryParse(optarg, out num) && num >= 0)
                    {
                        swfAge = num;
                    }
                    else
                    {
                        Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGERROR, "SWF Age must be non-negative, ignoring\n");
                    }

                    ++i;
                }
#endif
                else if (arg == "-k" || arg == "--skip")
                {
                    int n;
                    if (int.TryParse(optarg, out n) && n > 0)
                    {
                        Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "Number of skipped key frames for resume: {0}", nSkipKeyFrames);
                    }
                    else
                    {
                        Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGERROR, "Number of keyframes skipped must be greater or equal zero, using zero!");
                        nSkipKeyFrames = 0;
                    }
                    i++;
                }
                else if (arg == "-b" || arg == "--buffer")
                {
                    int bt;
                    if (int.TryParse(optarg, out bt) && bt >= 0)
                    {
                        bufferTime = bt;
                        bOverrideBufferTime = true;
                    }
                    else
                    {
                        Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGERROR, "Buffer time must be greater than zero, ignoring the specified value {0}!", bt);
                    }

                    i++;
                }
                else if (arg == "-v" || arg == "--live")
                {
                    bLiveStream = true;
                }
                else if (arg == "-R" || arg == "--realtime")
                {
                    bRealtimeStream = true;
                }
                else if (arg == "-d" || arg == "--subscribe")
                {
                    subscribepath = Str2Aval(optarg);
                    i++;
                }
                else if (arg == "-n" || arg == "--host")
                {
                    hostname = Str2Aval(optarg);
                    i++;
                }
                else if (arg == "-c" || arg == "--port")
                {
                    int n;
                    if (int.TryParse(optarg, out n))
                    {
                        port = n;
                    }

                    i++;
                }
                else if (arg == "-l" || arg == "--protocol")
                {
                    if (!int.TryParse(optarg, out protocol)
                        || (protocol < RTMP.RTMP_PROTOCOL_RTMP || protocol > RTMP.RTMP_PROTOCOL_RTMPTS))
                    {
                        Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGERROR, "Unknown protocol specified: {0}", protocol);
                        return RD_STATUS.RD_FAILED;
                    }
                    i++;
                }
                else if (arg == "-y" || arg == "--playpath")
                {
                    playpath = Str2Aval(optarg);
                    i++;
                }
                else if (arg == "-Y" || arg == "--playlist")
                {
                    RTMP.RTMP_SetOpt(rtmp, av_playlist, av_true);
                }
                else if (arg == "-r" || arg == "--rtmp")
                {
                    i++;
                    AVal parsedHost, parsedApp, parsedPlaypath;
                    int parsedPort, parsedProtocol; // = RTMP.RTMP_PROTOCOL_UNDEFINED;
                    var parse = RTMP.RTMP_ParseURL(optarg, out parsedProtocol, out parsedHost, out parsedPort, out parsedPlaypath, out parsedApp);
                    if (!parse)
                    {
                        Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGWARNING, "Couldn't parse the specified url ({0})!", optarg);
                    }
                    else
                    {
                        if (hostname.av_len == 0)
                        {
                            hostname = parsedHost;
                        }

                        if (port == -1)
                        {
                            port = parsedPort;
                        }

                        if (playpath.av_len == 0 && parsedPlaypath.av_len != 0)
                        {
                            playpath = parsedPlaypath;
                        }

                        if (protocol == RTMP.RTMP_PROTOCOL_UNDEFINED)
                        {
                            protocol = parsedProtocol;
                        }

                        if (app.av_len == 0 && parsedApp.av_len != 0)
                        {
                            app = parsedApp;
                        }
                    }
                }
                else if (arg == "-i" || arg == "--url")
                {
                    fullUrl = Str2Aval(optarg);
                    ++i;
                }
                else if (arg == "-s" || arg == "--swfUrl")
                {
                    swfUrl = Str2Aval(optarg);
                    ++i;
                }
                else if (arg == "-t" || arg == "--tcUrl")
                {
                    tcUrl = Str2Aval(optarg);
                    ++i;
                }
                else if (arg == "-p" || arg == "--pageUrl")
                {
                    pageUrl = Str2Aval(optarg);
                    ++i;
                }
                else if (arg == "-a" || arg == "--app")
                {
                    app = Str2Aval(optarg);
                    ++i;
                }
                else if (arg == "-f" || arg == "--flashVer")
                {
                    flashVer = Str2Aval(optarg);
                    ++i;
                }
                else if (arg == "-o" || arg == "--flv")
                {
                    flvFile = optarg;
                    if (flvFile != "-")
                    {
                        bStdoutMode = false;
                    }

                    ++i;
                }
                else if (arg == "-e" || arg == "--resume")
                {
                    bResume = true;
                }
                else if (arg == "-u" || arg == "--auth")
                {
                    auth = Str2Aval(optarg);
                    ++i;
                }
                else if (arg == "-C" || arg == "--conn")
                {
                    AVal av = Str2Aval(optarg);
                    if (!RTMP.RTMP_SetOpt(rtmp, av_conn, av))
                    {
                        Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGERROR, "Invalid AMF parameter: {0}", optarg);
                        return RD_STATUS.RD_FAILED;
                    }

                    ++i;
                }
                else if (arg == "-m" || arg == "--timeout")
                {
                    int.TryParse(optarg, out timeout);
                    ++i;
                }
                else if (arg == "-A" || arg == "--start")
                {
                    double offset;
                    if (double.TryParse(optarg, out offset))
                    {
                        dStartOffset = (int)(offset * 1000.0);
                    }
                    ++i;
                }
                else if (arg == "-B" || arg == "--stop")
                {
                    double offset;
                    if (double.TryParse(optarg, out offset))
                    {
                        dStopOffset = (int)(offset * 1000.0);
                    }
                    ++i;
                }
                else if (arg == "-T" || arg == "--token")
                {
                    AVal token = Str2Aval(optarg);
                    RTMP.RTMP_SetOpt(rtmp, av_token, token);
                    ++i;
                }
                else if (arg == "-#" || arg == "--hashes")
                {
                    bHashes = true;
                }
                else if (arg == "-q" || arg == "--quiet")
                {
                    Log.RTMP_LogSetLevel(Log.RTMP_LogLevel.RTMP_LOGCRIT);
                }
                else if (arg == "-V" || arg == "--verbose")
                {
                    Log.RTMP_LogSetLevel(Log.RTMP_LogLevel.RTMP_LOGDEBUG);
                }
                else if (arg == "-z" || arg == "--debug")
                {
                    Log.RTMP_LogSetLevel(Log.RTMP_LogLevel.RTMP_LOGALL);
                }
                else if (arg == "-S" || arg == "--socks")
                {
                    sockshost = Str2Aval(optarg);
                    ++i;
                }
                else if (arg == "-j" || arg == "--jtv")
                {
                    usherToken = Str2Aval(optarg);
                    ++i;
                }
                else
                {
                    Log.RTMP_LogPrintf("unknown option: {0}", arg);
                    usage();
                    return RD_STATUS.RD_FAILED;
                }
            }

            if (hostname.av_len == 0 && fullUrl.av_len == 0)
            {
                Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGERROR,
                    "You must specify a hostname (--host) or url (-r \"rtmp://host[:port]/playpath\") containing a hostname");
                return RD_STATUS.RD_FAILED;
            }

            if (playpath.av_len == 0 && fullUrl.av_len == 0)
            {
                Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGERROR,
                    "You must specify a playpath (--playpath) or url (-r \"rtmp://host[:port]/playpath\") containing a playpath");
                return RD_STATUS.RD_FAILED;
            }

            if (protocol == RTMP.RTMP_PROTOCOL_UNDEFINED && fullUrl.av_len == 0)
            {
                Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGWARNING,
                    "You haven't specified a protocol (--protocol) or rtmp url (-r), using default protocol RTMP");
                protocol = RTMP.RTMP_PROTOCOL_RTMP;
            }

            if (port == -1 && fullUrl.av_len == 0)
            {
                Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGWARNING,
                    "You haven't specified a port (--port) or rtmp url (-r), using default port 1935");
                port = 0;
            }

            if (port == 0 && fullUrl.av_len == 0)
            {
                if ((protocol & RTMP.RTMP_FEATURE_SSL) != 0)
                {
                    port = 443;
                }
                else if ((protocol & RTMP.RTMP_FEATURE_HTTP) != 0)
                {
                    port = 80;
                }
                else
                {
                    port = 1935;
                }
            }

            if (string.IsNullOrEmpty(flvFile))
            {
                Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGWARNING,
                    "You haven't specified an output file (-o filename), using stdout");
                bStdoutMode = true;
            }

            if (bStdoutMode && bResume)
            {
                Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGWARNING,
                    "Can't resume in stdout mode, ignoring --resume option");
                bResume = false;
            }

            if (bLiveStream && bResume)
            {
                Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGWARNING, "Can't resume live stream, ignoring --resume option");
                bResume = false;
            }

#if CRYPTO
            if (swfVfy)
            {
                if (RTMP.RTMP_HashSWF(swfUrl.av_val, ref swfSize, hash, swfAge) == 0)
                {
                    swfHash.av_val = hash;
                    swfHash.av_len = RTMP_LNK.RTMP_SWF_HASHLEN;
                }
            }

            if (swfHash.av_len == 0 && swfSize > 0)
            {
                Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGWARNING, "Ignoring SWF size, supply also the hash with --swfhash");
                swfSize = 0;
            }

            if (swfHash.av_len != 0 && swfSize == 0)
            {
                Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGWARNING, "Ignoring SWF hash, supply also the swf size  with --swfsize");
                swfHash.av_len = 0;
                swfHash.av_val = null;
            }
#endif

            if (tcUrl.av_len == 0)
            {
                var str = string.Format("{0}://{1}:{2}/{3}", RTMP.RTMPProtocolStringsLower[protocol], hostname.to_s(hostname.av_len), port, app.to_s(app.av_len));
                tcUrl = AVal.AVC(str);
            }

            bool first = true;

            // User defined seek offset
            if (dStartOffset > 0)
            {
                // Live stream
                if (bLiveStream)
                {
                    Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGWARNING, "Can't seek in a live stream, ignoring --start option");
                    dStartOffset = 0;
                }
            }

            if (fullUrl.av_len == 0)
            {
                RTMP.RTMP_SetupStream(
                    rtmp, protocol, hostname, port, sockshost, playpath,
                    tcUrl, swfUrl, pageUrl, app, auth, swfHash, swfSize,
                    flashVer, subscribepath, usherToken, dSeek, dStopOffset, bLiveStream, timeout);
            }
            else
            {
                if (!RTMP.RTMP_SetupURL(rtmp, fullUrl.to_s()))
                {
                    Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGERROR, "Couldn't parse URL: {0}", fullUrl.to_s());
                    return RD_STATUS.RD_FAILED;
                }
            }

            /* Try to keep the stream moving if it pauses on us */
            if (!bLiveStream && !bRealtimeStream && (protocol & RTMP.RTMP_FEATURE_HTTP) == 0)
            {
                rtmp.Link.lFlags |= RTMP_LNK.RTMP_LNK_FLAG.RTMP_LF_BUFX;
            }

            // off_t size = 0;
            uint size = 0;

            // ok, we have to get the timestamp of the last keyframe (only keyframes are seekable) / last audio frame (audio only streams)
            if (bResume)
            {
                nStatus = OpenResumeFile(flvFile, out file, out size, out metaHeader, ref nMetaHeaderSize, ref duration);
                if (nStatus == RD_STATUS.RD_FAILED)
                {
                    goto clean;
                }

                if (file == null)
                {
                    bResume = false;
                }
                else
                {
                    nStatus = GetLastKeyframe(file, nSkipKeyFrames, out dSeek, out initialFrame, out initialFrameType, out nInitialFrameSize);
                    if (nStatus == RD_STATUS.RD_FAILED)
                    {
                        Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "Failed to get last keyframe.");
                        goto clean;
                    }

                    if (dSeek == 0)
                    {
                        Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG,
                            "Last keyframe is first frame in stream, switching from resume to normal mode!");
                        bResume = false;
                    }
                }
            }

            if (file == null)
            {
                if (bStdoutMode)
                {
                    // TODO: stdout as file
                    // file = Console.Out;
                }
                else
                {
                    try
                    {
                        file = new FileStream(flvFile, FileMode.Append, FileAccess.Write);
                    }
                    catch (Exception)
                    {
                        Log.RTMP_LogPrintf("Failed to open file! {0}", flvFile);
                        return RD_STATUS.RD_FAILED;
                    }
                }
            }

            open_dump_file();

            while (!RTMP.RTMP_ctrlC)
            {
                Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "Setting buffer time to: {0}ms", bufferTime);
                RTMP.RTMP_SetBufferMS(rtmp, bufferTime);
                if (first)
                {
                    first = false;
                    Log.RTMP_LogPrintf("Connecting ...\n");
                    if (!RTMP.RTMP_Connect(rtmp, null))
                    {
                        nStatus = RD_STATUS.RD_NO_CONNECT;
                        break;
                    }

                    Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGINFO, "Connected...");

                    // User defined seek offset
                    if (dStartOffset > 0)
                    {
                        // Don't need the start offset if resuming an existing file
                        if (bResume)
                        {
                            Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGWARNING, "Can't seek a resumed stream, ignoring --start option");
                            dStartOffset = 0;
                        }
                        else
                        {
                            dSeek = dStartOffset;
                        }
                    }
                    // Calculate the length of the stream to still play
                    if (dStopOffset > 0)
                    {
                        // Quit if start seek is past required stop offset
                        if (dStopOffset <= dSeek)
                        {
                            Log.RTMP_LogPrintf("Already Completed\n");
                            nStatus = RD_STATUS.RD_SUCCESS;
                            break;
                        }
                    }

                    if (!RTMP.RTMP_ConnectStream(rtmp, dSeek))
                    {
                        nStatus = RD_STATUS.RD_FAILED;
                        break;
                    }
                }
                else
                {
                    nInitialFrameSize = 0;

                    if (retries != 0)
                    {
                        Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGERROR, "Failed to resume the stream\n\n");
                        if (!RTMP.RTMP_IsTimedout(rtmp))
                        {
                            nStatus = RD_STATUS.RD_FAILED;
                        }
                        else
                        {
                            nStatus = RD_STATUS.RD_INCOMPLETE;
                        }
                        break;
                    }

                    Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGINFO, "Connection timed out, trying to resume.\n\n");
                    /* Did we already try pausing, and it still didn't work? */
                    if (rtmp.m_pausing == 3)
                    {
                        /* Only one try at reconnecting... */
                        retries = 1;
                        dSeek = (int)rtmp.m_pauseStamp; // TODO:
                        if (dStopOffset > 0)
                        {
                            if (dStopOffset <= dSeek)
                            {
                                Log.RTMP_LogPrintf("Already Completed\n");
                                nStatus = RD_STATUS.RD_SUCCESS;
                                break;
                            }
                        }

                        if (!RTMP.RTMP_ReconnectStream(rtmp, dSeek))
                        {
                            Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGERROR, "Failed to resume the stream\n\n");
                            if (!RTMP.RTMP_IsTimedout(rtmp))
                            {
                                nStatus = RD_STATUS.RD_FAILED;
                            }
                            else
                            {
                                nStatus = RD_STATUS.RD_INCOMPLETE;
                            }

                            break;
                        }
                    }
                    else if (!RTMP.RTMP_ToggleStream(rtmp))
                    {
                        Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGERROR, "Failed to resume the stream\n\n");
                        if (!RTMP.RTMP_IsTimedout(rtmp))
                        {
                            nStatus = RD_STATUS.RD_FAILED;
                        }
                        else
                        {
                            nStatus = RD_STATUS.RD_INCOMPLETE;
                        }

                        break;
                    }

                    bResume = true;
                }

                nStatus = Download(rtmp, file,
                    (uint)dSeek, (uint)dStopOffset, duration, bResume,
                    metaHeader, nMetaHeaderSize, initialFrame,
                    initialFrameType, nInitialFrameSize, nSkipKeyFrames,
                    bStdoutMode, bLiveStream, bRealtimeStream, bHashes,
                    bOverrideBufferTime, (uint)bufferTime, out percent);
                // free(initialFrame);
                initialFrame = null;

                /* If we succeeded, we're done. */
                if (nStatus != RD_STATUS.RD_INCOMPLETE || !RTMP.RTMP_IsTimedout(rtmp) || bLiveStream)
                {
                    break;
                }
            }

            if (nStatus == RD_STATUS.RD_SUCCESS)
            {
                Log.RTMP_LogPrintf("Download complete\n");
            }
            else if (nStatus == RD_STATUS.RD_INCOMPLETE)
            {
                Log.RTMP_LogPrintf("Download may be incomplete (downloaded about %.2f%%), try resuming\n", percent);
            }

        clean:
            Log.RTMP_Log(Log.RTMP_LogLevel.RTMP_LOGDEBUG, "Closing connection.\n");
            RTMP.RTMP_Close(rtmp);

            // if (file != 0) fclose(file);
            // CleanupSockets();

            close_dump_file();

            return nStatus;
        }

        /// <summary>
        /// int OpenResumeFile(const char *flvFile,
        ///   FILE ** file,off_t * size,
        ///   char **metaHeader, uint32_t * nMetaHeaderSize, double *duration)
        /// </summary>
        /// <param name="flvFile">file name[in]</param>
        /// <param name="file">opened file[out]</param>
        /// <param name="size">size of the file[out]</param>
        /// <param name="metaHeader">meta data read from the file [out]</param>
        /// <param name="nMetaHeaderSize">// length of metaHeader [out]</param>
        /// <param name="duration">duration of the stream in ms [out]</param>
        private RD_STATUS OpenResumeFile(string flvFile,
            out FileStream file,
            out uint size,
            out byte[] metaHeader,
            ref uint nMetaHeaderSize,
            ref double duration)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// int GetLastKeyframe(FILE* file, int nSkipKeyFrames,
        ///   uint32_t * dSeek, char **initialFrame, int *initialFrameType, uint32_t * nInitialFrameSize)
        /// </summary>
        /// <param name="file">output file [in]</param>
        /// <param name="nSkipKeyFrames">max number of frames to skip when searching for key frame [in]</param>
        /// <param name="dSeek">offset of the last key frame [out]</param>
        /// <param name="initialFrame">content of the last keyframe [out]</param>
        /// <param name="initialFrameType">initial frame type (audio/video) [out]</param>
        /// <param name="nInitialFrameSize">length of initialFrame [out]</param>
        /// <returns></returns>
        private RD_STATUS GetLastKeyframe(FileStream file, int nSkipKeyFrames,
            out int dSeek, out byte[] initialFrame, out int initialFrameType, out uint nInitialFrameSize)
        {
            throw new NotImplementedException();
        }

        //
        /// <summary>
        /// int Download(RTMP * rtmp, FILE * file, uint32_t dSeek, uint32_t dStopOffset, double duration, int bResume, char *metaHeader, uint32_t nMetaHeaderSize, char *initialFrame, int initialFrameType, uint32_t nInitialFrameSize, int nSkipKeyFrames, int bStdoutMode, int bLiveStream, int bRealtimeStream, int bHashes, int bOverrideBufferTime, uint32_t bufferTime, double *percent)
        /// </summary>
        /// <param name="rtmp">connected RTMP object</param>
        /// <param name="file"></param>
        /// <param name="dSeek"></param>
        /// <param name="dStopOffset"></param>
        /// <param name="duration"></param>
        /// <param name="bResume"></param>
        /// <param name="metaHeader"></param>
        /// <param name="nMetaHeaderSize"></param>
        /// <param name="initialFrame"></param>
        /// <param name="initialFrameType"></param>
        /// <param name="nInitialFrameSize"></param>
        /// <param name="nSkipKeyFrames"></param>
        /// <param name="bStdoutMode"></param>
        /// <param name="bLiveStream"></param>
        /// <param name="bRealtimeStream"></param>
        /// <param name="bHashes"></param>
        /// <param name="bOverrideBufferTime"></param>
        /// <param name="bufferTime"></param>
        /// <param name="percent"> percentage downloaded [out]</param>
        /// <returns></returns>
        private RD_STATUS Download(
            RTMP rtmp, FileStream file,
            uint dSeek, uint dStopOffset, double duration, bool bResume, byte[] metaHeader, uint nMetaHeaderSize, byte[] initialFrame,
            int initialFrameType, uint nInitialFrameSize, int nSkipKeyFrames,
            bool bStdoutMode, bool bLiveStream, bool bRealtimeStream,
            bool bHashes, bool bOverrideBufferTime, uint bufferTime,
            out double percent)
        {
            throw new NotImplementedException();
        }

        private FileStream file;

        /// <summary> #define HEX2BIN(a)      (((a)&0x40)?((a)&0xf)+9:((a)&0xf)) </summary>
        private byte Hex2Bin(char a)
        {
            return ((a & 0x40) != 0x00) ? (byte)((a & 0x0f) + 9) : (byte)(a & 0x0f);
        }

        /// <summary> int hex2bin(char *str, char **hex) </summary>
        /// <param name="str">hex string</param>
        /// <returns>byte array</returns>
        private byte[] Hex2Bin(string str)
        {
            var l = str.Length;
            if (l % 2 == 1)
            {
                return new byte[0];
            }

            var ret = new byte[l / 2];

            for (var i = 0; i < l; i += 2)
            {
                ret[i / 2] = (byte)((Hex2Bin(str[i]) << 4) | Hex2Bin(str[i + 1]));
            }

            return ret;
        }

        private static readonly AVal av_onMetaData = AVal.AVC("onMetaData");
        private static readonly AVal av_duration = AVal.AVC("duration");
        private static readonly AVal av_conn = AVal.AVC("conn");
        private static readonly AVal av_token = AVal.AVC("token");
        private static readonly AVal av_playlist = AVal.AVC("playlist");
        private static readonly AVal av_true = AVal.AVC("true");

        /// <summary> #define STR2AVAL(av,str)	av.av_val = str; av.av_len = strlen(av.av_val) </summary>
        private AVal Str2Aval(string str)
        {
            return AVal.AVC(str);
        }

        // void usage(char *prog)
        private void usage(string prog = "")
        {
            if (string.IsNullOrEmpty(prog))
            {
                prog = Path.GetFileName(Environment.GetCommandLineArgs()[0]);
            }

            Log.RTMP_LogPrintf("\n{0}: This program dumps the media content streamed over RTMP.\n\n", prog);
            Log.RTMP_LogPrintf("--help|-h               Prints this help screen.\n");
            Log.RTMP_LogPrintf("--url|-i url            URL with options included (e.g. rtmp://host[:port]/path swfUrl=url tcUrl=url)\n");
            Log.RTMP_LogPrintf("--rtmp|-r url           URL (e.g. rtmp://host[:port]/path)\n");
            Log.RTMP_LogPrintf("--host|-n hostname      Overrides the hostname in the rtmp url\n");
            Log.RTMP_LogPrintf("--port|-c port          Overrides the port in the rtmp url\n");
            Log.RTMP_LogPrintf("--socks|-S host:port    Use the specified SOCKS proxy\n");
            Log.RTMP_LogPrintf("--protocol|-l num       Overrides the protocol in the rtmp url (0 - RTMP, 2 - RTMPE)\n");
            Log.RTMP_LogPrintf("--playpath|-y path      Overrides the playpath parsed from rtmp url\n");
            Log.RTMP_LogPrintf("--playlist|-Y           Set playlist before playing\n");
            Log.RTMP_LogPrintf("--swfUrl|-s url         URL to player swf file\n");
            Log.RTMP_LogPrintf("--tcUrl|-t url          URL to played stream (default: \"rtmp://host[:port]/app\")\n");
            Log.RTMP_LogPrintf("--pageUrl|-p url        Web URL of played programme\n");
            Log.RTMP_LogPrintf("--app|-a app            Name of target app on server\n");
#if CRYPTO
            Log.RTMP_LogPrintf("--swfhash|-w hexstring  SHA256 hash of the decompressed SWF file (32 bytes)\n");
            Log.RTMP_LogPrintf("--swfsize|-x num        Size of the decompressed SWF file, required for SWFVerification\n");
            Log.RTMP_LogPrintf("--swfVfy|-W url         URL to player swf file, compute hash/size automatically\n");
            Log.RTMP_LogPrintf("--swfAge|-X days        Number of days to use cached SWF hash before refreshing\n");
#endif
            Log.RTMP_LogPrintf("--auth|-u string        Authentication string to be appended to the connect string\n");
            Log.RTMP_LogPrintf("--conn|-C type:data     Arbitrary AMF data to be appended to the connect string\n");
            Log.RTMP_LogPrintf("                        B:boolean(0|1), S:string, N:number, O:object-flag(0|1),\n");
            Log.RTMP_LogPrintf("                        Z:(null), NB:name:boolean, NS:name:string, NN:name:number\n");
            Log.RTMP_LogPrintf("--flashVer|-f string    Flash version string (default: \"{0}\")\n", RTMP.RTMP_DefaultFlashVer.av_val);
            Log.RTMP_LogPrintf("--live|-v               Save a live stream, no --resume (seeking) of live streams possible\n");
            Log.RTMP_LogPrintf("--subscribe|-d string   Stream name to subscribe to (otherwise defaults to playpath if live is specifed)\n");
            Log.RTMP_LogPrintf("--realtime|-R           Don't attempt to speed up download via the Pause/Unpause BUFX hack\n");
            Log.RTMP_LogPrintf("--flv|-o string         FLV output file name, if the file name is - print stream to stdout\n");
            Log.RTMP_LogPrintf("--resume|-e             Resume a partial RTMP download\n");
            Log.RTMP_LogPrintf("--timeout|-m num        Timeout connection num seconds (default: {0})\n", DEF_TIMEOUT);
            Log.RTMP_LogPrintf("--start|-A num          Start at num seconds into stream (not valid when using --live)\n");
            Log.RTMP_LogPrintf("--stop|-B num           Stop at num seconds into stream\n");
            Log.RTMP_LogPrintf("--token|-T key          Key for SecureToken response\n");
            Log.RTMP_LogPrintf("--jtv|-j JSON           Authentication token for Justin.tv legacy servers\n");
            Log.RTMP_LogPrintf("--hashes|-#             Display progress with hashes, not with the byte counter\n");
            Log.RTMP_LogPrintf("--buffer|-b             Buffer time in milliseconds (default: %u)\n", DEF_BUFTIME);
            Log.RTMP_LogPrintf("--skip|-k num           Skip num keyframes when looking for last keyframe to resume from. Useful if resume fails (default: {0})\n\n", DEF_SKIPFRM);
            Log.RTMP_LogPrintf("--quiet|-q              Suppresses all command output.\n");
            Log.RTMP_LogPrintf("--verbose|-V            Verbose command output.\n");
            Log.RTMP_LogPrintf("--debug|-z              Debug level command output.\n");
            Log.RTMP_LogPrintf("If you don't pass parameters for swfUrl, pageUrl, or auth these properties will not be included in the connect ");
            Log.RTMP_LogPrintf("packet.\n\n");
        }

        /// <summary>
        /// // starts sockets
        /// int InitSockets()
        /// </summary>
        /// <remarks>for winsock2 code. </remarks>
        /// <returns></returns>
        private bool InitSockets()
        {
            return true;
        }

        /// <summary>
        /// void sigIntHandler(int sig)
        /// </summary>
        private void sigIntHandler(object sender, ConsoleCancelEventArgs e)
        {
            RTMP.RTMP_ctrlC = true;
            var sig = 2; // sigint = 2
            Log.RTMP_LogPrintf("Caught signal: {0}, cleaning up, just a second...\n", sig);
            // ignore all these signals now and let the connection close
            // signal(SIGINT, SIG_IGN);
            // signal(SIGTERM, SIG_IGN);
#if WIN32
#else
            // signal(SIGHUP, SIG_IGN);
            // signal(SIGPIPE, SIG_IGN);
            // signal(SIGQUIT, SIG_IGN);
#endif
        }

        #region netstackdump

        // TODO: C#-style resource handling
        // TODO: change architecture. add debug dump file setter api in librtmp

        private BinaryWriter _netStackDump;

        private BinaryWriter _netStackDumpRead;

        [Conditional("DEBUG")]
        private void open_dump_file()
        {
            _netStackDump = new BinaryWriter(new FileStream("netstackdump", FileMode.Create, FileAccess.Write));
            _netStackDumpRead = new BinaryWriter(new FileStream("netstackdump_read", FileMode.Create, FileAccess.Write));
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

        #endregion
    }
}