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
using System.Net.Sockets;

namespace librtmp
{
    /// <summary>
    /// struct RTMPSockBuf
    /// </summary>
    public class RTMPSockBuf
    {
        /// <summary> int sb_socket </summary>
        public Socket sb_socket { get; set; }

        /// <summary> int sb_size;		/* number of unprocessed bytes in buffer */ </summary>
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
                rc = sb.sb_socket.Send(buf, 0, len, SocketFlags.None);
            }

            return rc;
        }

        // int RTMPSockBuf_Close(RTMPSockBuf *sb)
        public static int RTMPSockBuf_Close(RTMPSockBuf sb)
        {
#if CRYPTO_SSL
  if (sb.sb_ssl)
    {
      TLS_shutdown(sb.sb_ssl);
      TLS_close(sb.sb_ssl);
      sb.sb_ssl = NULL;
    }
#endif
            if (sb.sb_socket != null)
            {
                // return closesocket(sb.sb_socket);
                sb.sb_socket.Close();
                return 0;
            }

            return 0;
        }
    }
}