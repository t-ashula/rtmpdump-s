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

namespace librtmp
{
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

        /* if bResume == true */

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