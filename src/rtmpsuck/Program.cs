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
using System.Linq;
using librtmp;

namespace rtmpsuck
{
    internal enum RD_STATUS
    {
        RD_SUCCESS = 0,
        RD_FAILED = 1,
        RD_INCOMPLETE = 2
    };

    internal class Program
    {
        private static void Main(string[] args)
        {
            var nStatus = RD_STATUS.RD_SUCCESS;
            const string DEFAULT_RTMP_STREAMING_DEVICE = "0.0.0.0";
            var rtmpSetreamingDevice = DEFAULT_RTMP_STREAMING_DEVICE;
            var nRtmpStreamingPort = 1935;

            const string RTMPDUMP_VERSION = "v2.4"; // TODO:
            Log.RTMP_LogPrintf("RTMP Proxy Server {0}\n", RTMPDUMP_VERSION);
            Log.RTMP_LogPrintf("(c) 2010 Andrej Stepanchuk, Howard Chu; license: GPL\n\n");
        }
    }
}