/* $Id: pcap.h,v 1.1.4.1 2011/10/18 03:26:57 bew Exp $ */
/* $Source: /nfs/cscbz/gdoi/gdoicvs/gdoi/src/pcap.h,v $ */

/* 
 * The license applies to all software incorporated in the "Cisco GDOI reference
 * implementation" except for those portions incorporating third party software 
 * specifically identified as being licensed under separate license. 
 *  
 *  
 * The Cisco Systems Public Software License, Version 1.0 
 * Copyright (c) 2001-2011 Cisco Systems, Inc. All rights reserved.
 * Subject to the following terms and conditions, Cisco Systems, Inc., 
 * hereby grants you a worldwide, royalty-free, nonexclusive, license, 
 * subject to third party intellectual property claims, to create 
 * derivative works of the Licensed Code and to reproduce, display, 
 * perform, sublicense, distribute such Licensed Code and derivative works. 
 * All rights not expressly granted herein are reserved. 
 * 1.      Redistributions of source code must retain the above 
 * copyright notice, this list of conditions and the following 
 * disclaimer.
 * 2.      Redistributions in binary form must reproduce the above 
 * copyright notice, this list of conditions and the following 
 * disclaimer in the documentation and/or other materials 
 * provided with the distribution.
 * 3.      The names Cisco and "Cisco GDOI reference implementation" must not 
 * be used to endorse or promote products derived from this software without 
 * prior written permission. For written permission, please contact 
 * opensource@cisco.com.
 * 4.      Products derived from this software may not be called 
 * "Cisco" or "Cisco GDOI reference implementation", nor may "Cisco" or 
 * "Cisco GDOI reference implementation" appear in 
 * their name, without prior written permission of Cisco Systems, Inc.
 * THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESSED OR IMPLIED 
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED 
 * WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR 
 * PURPOSE, TITLE AND NON-INFRINGEMENT ARE DISCLAIMED. IN NO EVENT 
 * SHALL CISCO SYSTEMS, INC. OR ITS CONTRIBUTORS BE LIABLE FOR ANY 
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL 
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF 
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR 
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF 
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT 
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF 
 * THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF 
 * SUCH DAMAGE. THIS LIMITATION OF LIABILITY SHALL NOT APPLY TO 
 * LIABILITY FOR DEATH OR PERSONAL INJURY RESULTING FROM SUCH 
 * PARTY'S NEGLIGENCE TO THE EXTENT APPLICABLE LAW PROHIBITS SUCH 
 * LIMITATION. SOME JURISDICTIONS DO NOT ALLOW THE EXCLUSION OR 
 * LIMITATION OF INCIDENTAL OR CONSEQUENTIAL DAMAGES, SO THAT 
 * EXCLUSION AND LIMITATION MAY NOT APPLY TO YOU. FURTHER, YOU 
 * AGREE THAT IN NO EVENT WILL CISCO'S LIABILITY UNDER OR RELATED TO 
 * THIS AGREEMENT EXCEED AMOUNT FIVE THOUSAND DOLLARS (US) 
 * (US$5,000). 
 *  
 * ====================================================================
 * This software consists of voluntary contributions made by Cisco Systems, 
 * Inc. and many individuals on behalf of Cisco Systems, Inc. For more 
 * information on Cisco Systems, Inc., please see <http://www.cisco.com/>.
 *
 * This product includes software developed by Ericsson Radio Systems.
 */ 

/*	$OpenBSD: pcap.h,v 1.1 2001/04/09 21:21:58 ho Exp $	*/

/*
 * Copyright (c) 1993, 1994, 1995, 1996, 1997
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the Computer Systems
 *	Engineering Group at Lawrence Berkeley Laboratory.
 * 4. Neither the name of the University nor of the Laboratory may be used
 *    to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * @(#) $Header: /nfs/cscbz/gdoi/gdoicvs/gdoi/src/pcap.h,v 1.1.4.1 2011/10/18 03:26:57 bew Exp $ (LBL)
 */

#ifndef lib_pcap_h
#define lib_pcap_h

#include <sys/types.h>
#include <sys/time.h>

#define PCAP_VERSION_MAJOR	2
#define PCAP_VERSION_MINOR	4
#define DLT_NULL		0

struct pcap_file_header {
	u_int32_t magic;
	u_int16_t version_major;
	u_int16_t version_minor;
	int32_t	thiszone;	/* gmt to local correction */
	u_int32_t sigfigs;	/* accuracy of timestamps */
	u_int32_t snaplen;	/* max length saved portion of each pkt */
	u_int32_t linktype;	/* data link type (DLT_*) */
};

struct pcap_pkthdr {
	struct timeval ts;	/* time stamp */
	u_int32_t caplen;	/* length of portion present */
	u_int32_t len;		/* length this packet (off wire) */
};

#endif /* lib_pcap_h */
