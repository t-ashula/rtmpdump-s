/*
 *  Copyright (C) 2008-2009 Andrej Stepanchuk
 *  Copyright (C) 2009-2010 Howard Chu
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
using System.IO;

namespace librtmp
{
    public class Log
    {
        public enum RTMP_LogLevel
        {
            RTMP_LOGCRIT = 0,
            RTMP_LOGERROR,
            RTMP_LOGWARNING,
            RTMP_LOGINFO,
            RTMP_LOGDEBUG,
            RTMP_LOGDEBUG2,
            RTMP_LOGALL
        }

        private static string loglevel_to_string(RTMP_LogLevel e)
        {
            switch (e)
            {
                case RTMP_LogLevel.RTMP_LOGCRIT:
                    return "CRIT";

                case RTMP_LogLevel.RTMP_LOGERROR:
                    return "ERROR";

                case RTMP_LogLevel.RTMP_LOGWARNING:
                    return "WARNING";

                case RTMP_LogLevel.RTMP_LOGINFO:
                    return "INFO";

                case RTMP_LogLevel.RTMP_LOGDEBUG:
                    return "DEBUG";

                case RTMP_LogLevel.RTMP_LOGDEBUG2:
                    return "DEBUG2";

                default:
                    return string.Empty;
            }
        }

        /*
         * extern RTMP_LogLevel RTMP_debuglevel;
         * typedef void (RTMP_LogCallback)(int level, const char *fmt, va_list);
         * void RTMP_LogSetCallback(RTMP_LogCallback *callback);
         * void RTMP_LogSetOutput(FILE *file);
         * void RTMP_LogPrintf(const char *format, ...);
         * void RTMP_LogStatus(const char *format, ...);
         * void RTMP_Log(int level, const char *format, ...);
         * void RTMP_LogHex(int level, const uint8_t *data, unsigned long len);
         * void RTMP_LogHexString(int level, const uint8_t *data, unsigned long len);
         * void RTMP_LogSetLevel(RTMP_LogLevel lvl);
         * RTMP_LogLevel RTMP_LogGetLevel(void);
         */

        public delegate void RTMP_LogCallback(RTMP_LogLevel l, string fmr, params object[] v);

        private static RTMP_LogCallback cb = rtmp_log_default;

        private static RTMP_LogLevel RTMP_debuglevel = RTMP_LogLevel.RTMP_LOGERROR;

        public static void RTMP_LogSetCallback(RTMP_LogCallback callback)
        {
            cb = callback;
        }

        private static TextWriter tw;

        public static void RTMP_LogSetOutput(TextWriter w)
        {
            tw = w;
        }

        private const int MAX_PRINT_LEN = 2048;
        private static bool needNewLine;

        public static void RTMP_LogPrintf(string fmt, params object[] vals)
        {
            if (RTMP_debuglevel == RTMP_LogLevel.RTMP_LOGCRIT)
            {
                return;
            }

            if (tw == null)
            {
                tw = Console.Error;
            }

            if (needNewLine)
            {
                tw.WriteLine();
                needNewLine = false;
            }

            var msg = string.Format(fmt, vals);
            if (msg.Length > MAX_PRINT_LEN - 1)
            {
                msg = msg.Substring(MAX_PRINT_LEN - 1);
            }

            tw.Write(msg);
            if (msg.EndsWith("\n"))
            {
                tw.Flush();
            }
        }

        public static void RTMP_LogStatus(string fmt, params object[] vals)
        {
            if (RTMP_debuglevel == RTMP_LogLevel.RTMP_LOGCRIT)
            {
                return;
            }

            if (tw == null)
            {
                tw = Console.Error;
            }

            tw.Write(fmt, vals);
            needNewLine = true;
        }

        public static void RTMP_Log(RTMP_LogLevel level, string fmt, params object[] vals)
        {
            cb(level, fmt, vals);
        }

        public static void RTMP_LogHex(RTMP_LogLevel level, byte[] data, ulong len)
        {
            if (level > RTMP_debuglevel)
            {
                return;
            }

            var line = string.Empty;
            var i = 0ul;
            for (; i < len; ++i)
            {
                line += string.Format("{0:x2}", data[i]);
                if (i != 0 && i % 16 == 0)
                {
                    RTMP_Log(level, "{0}", line);
                    line = string.Empty;
                }
                else
                {
                    line += " ";
                }
            }

            if (i % 16 != 0)
            {
                RTMP_Log(level, "{0}", line);
            }
        }

        public static void RTMP_LogHexString(RTMP_LogLevel level, byte[] data, ulong len)
        {
            if (data.Length == 0 || level > RTMP_debuglevel)
            {
                return;
            }

            /*
             * data = {'a','b','c',' ','1','2','3','4',' ','1','2','3','4',' ','1','2','3','4',' ','1','2','3','4','\r', '\n' };
             * INFO:   0000:  61 62 63 20 31 32 33 34  20 31 32 33 34 20 31 32   abc 1234 1234 12
             * INFO:   0010:  33 34 20 31 32 33 34 0a  0d                        34 1234..
             */
            for (var off = 0ul; off < len; off += 16)
            {
                var end = false;
                var dump1 = string.Empty;
                for (var i = 0u; i < 8; ++i)
                {
                    if (off + i >= len)
                    {
                        end = true;
                        break;
                    }

                    dump1 += string.Format("{0:x2} ", data[off + i]);
                }

                var dump2 = string.Empty;
                if (!end)
                {
                    for (var i = 0u; i < 8; ++i)
                    {
                        if (off + i + 8 >= len)
                        {
                            break;
                        }

                        dump2 += string.Format("{0:x2} ", data[off + i + 8]);
                    }
                }

                var printable = string.Empty;
                for (var i = 0u; i < 16; ++i)
                {
                    if (off + i >= len)
                    {
                        break;
                    }

                    var c = (char)data[off + i];
                    if (char.IsLetterOrDigit(c) || char.IsSymbol(c) || c == ' ')
                    {
                        printable += c;
                    }
                    else
                    {
                        printable += '.';
                    }
                }

                // const int BP_OFFSET = 9, BP_GRAPH = 60, BP_LEN = 80;
                RTMP_Log(level, "  {0:x4}: {1, -24} {2, -24}  {3}", off, dump1, dump2, printable);
            }
        }

        public static void RTMP_LogSetLevel(RTMP_LogLevel level)
        {
            RTMP_debuglevel = level;
        }

        public static RTMP_LogLevel RTMP_LogGetLevel()
        {
            return RTMP_debuglevel;
        }

        private static void rtmp_log_default(RTMP_LogLevel level, string fmt, params object[] vals)
        {
            var msg = string.Format(fmt, vals);
            if (RTMP_debuglevel < RTMP_LogLevel.RTMP_LOGALL && msg.Contains("no-name"))
            {
                return;
            }

            if (tw == null)
            {
                tw = Console.Error;
            }

            if (level <= RTMP_debuglevel)
            {
                if (needNewLine)
                {
                    tw.WriteLine();
                    needNewLine = false;
                }

                tw.WriteLine("{0}: {1}", loglevel_to_string(level), msg);
            }
        }
    }
}