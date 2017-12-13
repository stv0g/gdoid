# $Id: Makefile.am,v 1.3.4.3 2011/12/12 23:15:28 bew Exp $
# $Source: /nfs/cscbz/gdoi/gdoicvs/gdoi/src/Makefile.am,v $

#  
#  The license applies to all software incorporated in the "Cisco GDOI reference
#  implementation" except for those portions incorporating third party software 
#  specifically identified as being licensed under separate license. 
#   
#   
#  The Cisco Systems Public Software License, Version 1.0 
#  Copyright (c) 2001-2002 Cisco Systems, Inc. All rights reserved.
#  Subject to the following terms and conditions, Cisco Systems, Inc., 
#  hereby grants you a worldwide, royalty-free, nonexclusive, license, 
#  subject to third party intellectual property claims, to create 
#  derivative works of the Licensed Code and to reproduce, display, 
#  perform, sublicense, distribute such Licensed Code and derivative works. 
#  All rights not expressly granted herein are reserved. 
#  1.      Redistributions of source code must retain the above 
#  copyright notice, this list of conditions and the following 
#  disclaimer.
#  2.      Redistributions in binary form must reproduce the above 
#  copyright notice, this list of conditions and the following 
#  disclaimer in the documentation and/or other materials 
#  provided with the distribution.
#  3.      The names Cisco and "Cisco GDOI reference implementation" must not 
#  be used to endorse or promote products derived from this software without 
#  prior written permission. For written permission, please contact 
#  opensource@cisco.com.
#  4.      Products derived from this software may not be called 
#  "Cisco" or "Cisco GDOI reference implementation", nor may "Cisco" or 
#  "Cisco GDOI reference implementation" appear in 
#  their name, without prior written permission of Cisco Systems, Inc.
#  THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESSED OR IMPLIED 
#  WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED 
#  WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR 
#  PURPOSE, TITLE AND NON-INFRINGEMENT ARE DISCLAIMED. IN NO EVENT 
#  SHALL CISCO SYSTEMS, INC. OR ITS CONTRIBUTORS BE LIABLE FOR ANY 
#  INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL 
#  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF 
#  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR 
#  BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF 
#  LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT 
#  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF 
#  THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF 
#  SUCH DAMAGE. THIS LIMITATION OF LIABILITY SHALL NOT APPLY TO 
#  LIABILITY FOR DEATH OR PERSONAL INJURY RESULTING FROM SUCH 
#  PARTY'S NEGLIGENCE TO THE EXTENT APPLICABLE LAW PROHIBITS SUCH 
#  LIMITATION. SOME JURISDICTIONS DO NOT ALLOW THE EXCLUSION OR 
#  LIMITATION OF INCIDENTAL OR CONSEQUENTIAL DAMAGES, SO THAT 
#  EXCLUSION AND LIMITATION MAY NOT APPLY TO YOU. FURTHER, YOU 
#  AGREE THAT IN NO EVENT WILL CISCO'S LIABILITY UNDER OR RELATED TO 
#  THIS AGREEMENT EXCEED AMOUNT FIVE THOUSAND DOLLARS (US) 
#  (US$5,000). 
#   
#  ====================================================================
#  This software consists of voluntary contributions made by Cisco Systems, 
#  Inc. and many individuals on behalf of Cisco Systems, Inc. For more 
#  information on Cisco Systems, Inc., please see <http://www.cisco.com/>.
# 
#  This product includes software developed by Ericsson Radio Systems.
# 


#
# Makefile.am for gdoid.
#

bin_PROGRAMS = gdoid

BUILT_C_FILES = exchange_num.c ipsec_num.c isakmp_num.c gdoi_num.c \
		ipsec_fld.c isakmp_fld.c gdoi_fld.c 

BUILT_H_FILES = exchange_num.h ipsec_num.h isakmp_num.h gdoi_num.h \
		ipsec_fld.h isakmp_fld.h gdoi_fld.h 

BUILT_SOURCES = ${BUILT_C_FILES} ${BUILT_H_FILES}

noinst_HEADERS = app.h attribute.h cert.h conf.h connection.h \
		constants.h cookie.h crypto.h dh.h doi.h dyn.h \
		exchange.h field.h gdoi.h gdoi_phase2.h gmp_util.h hash.h \
		if.h ike_aggressive.h ike_auth.h ike_main_mode.h \
		ike_phase_1.h init.h ipsec.h ipsec_doi.h isakmp.h \
		isakmp_doi.h libcrypto.h log.h math_2n.h math_ec2n.h \
		math_group.h math_mp.h message.h pcap.h pf_encap.h \
		pf_key_v2.h prf.h sa.h sysdep.h timer.h transport.h udp.h \
		ui.h util.h x509.h

gdoid_SOURCES = ${BUILT_C_FILES}\
		udp.c app.c attribute.c cert.c connection.c \
		constants.c conf.c cookie.c crypto.c dh.c doi.c exchange.c \
		field.c gmp_util.c hash.c if.c ike_auth.c \
		ike_aggressive.c ike_main_mode.c ike_phase_1.c \
		init.c ipsec.c \
		isakmpd.c isakmp_doi.c libcrypto.c \
		log.c message.c math_2n.c math_ec2n.c math_group.c \
		prf.c sa.c timer.c transport.c ui.c util.c \
		gdoi_phase2.c gdoi_doi.c gdoi_rekey.c

man_MANS=	gdoid.8 gdoid.conf.5

CLEANFILES=	exchange_num.c exchange_num.h ipsec_num.c ipsec_num.h \
		isakmp_num.c isakmp_num.h ipsec_fld.c ipsec_fld.h \
		isakmp_fld.c isakmp_fld.h \
		gdoi_fld.c gdoi_fld.h gdoi_num.c gdoi_num.h

DISTCLEANFILES=	cscope.files cscope.out

EXTRA_DIST=	${man_MANS} genconstants.sh  genfields.sh \
		exchange_num.cst ipsec_num.cst isakmp_num.cst gdoi_num.cst \
		ipsec_fld.fld isakmp_fld.fld gdoi_fld.fld gdoi_app_num.cst

#
# Compilation variables
#

CFLAGS+=	-O2 ${DEBUG} -Wall -DNEED_SYSDEP_APP -D_BSD_SOURCE

#
# Generated targets
#
exchange_num.c exchange_num.h: genconstants.sh exchange_num.cst
	/bin/sh ${srcdir}/genconstants.sh ${srcdir}/exchange_num

ipsec_fld.c ipsec_fld.h: genfields.sh ipsec_fld.fld
	/bin/sh ${srcdir}/genfields.sh ${srcdir}/ipsec_fld

ipsec_num.c ipsec_num.h: genconstants.sh ipsec_num.cst
	/bin/sh ${srcdir}/genconstants.sh ${srcdir}/ipsec_num

isakmp_fld.c isakmp_fld.h: genfields.sh isakmp_fld.fld
	/bin/sh ${srcdir}/genfields.sh ${srcdir}/isakmp_fld

isakmp_num.c isakmp_num.h: genconstants.sh isakmp_num.cst
	/bin/sh ${srcdir}/genconstants.sh ${srcdir}/isakmp_num

gdoi_fld.c gdoi_fld.h: genfields.sh gdoi_fld.fld
	/bin/sh ${srcdir}/genfields.sh ${srcdir}/gdoi_fld
gdoi_num.c gdoi_num.h: genconstants.sh gdoi_num.cst
	/bin/sh ${srcdir}/genconstants.sh ${srcdir}/gdoi_num

#
# Extra sources to add based on the results of running "configure".
#

if USE_AGGRESSIVE
gdoid_SOURCES+=	ike_aggressive.c
endif

if USE_LIBCRYPTO
gdoid_SOURCES+= x509.c
CFLAGS+=	-DUSE_LIBCRYPTO -DUSE_X509
CFLAGS+=	-DMP_FLAVOUR=MP_FLAVOUR_OPENSSL
endif

if HAVE_PF_KEY_V2
gdoid_SOURCES+= pf_key_v2.c key_api.c
CFLAGS+=	-DUSE_PF_KEY_V2
endif

if GDOI_APP_SUPPORT
noinst_HEADERS+= gdoi_app_client.h
gdoid_SOURCES+= gdoi_app_client.c
BUILT_C_FILES+= gdoi_app_num.c
BUILT_H_FILES+= gdoi_app_num.h
CFLAGS+=	-DGDOI_APP_SUPPORT
CLEANFILES+=    gdoi_app_num.c gdoi_app_num.h
EXTRA_DIST+=    gdoi_app_num.cst

gdoi_app_num.c gdoi_app_num.h: genconstants.sh gdoi_app_num.cst
	/bin/sh ${srcdir}/genconstants.sh ${srcdir}/gdoi_app_num
endif

if SRTP_SUPPORT
noinst_HEADERS+= gdoi_srtp_attr.h gdoi_srtp_protos.h gdoi_srtp.h
BUILT_C_FILES+= srtp_num.c
BUILT_H_FILES+= srtp_num.h
gdoid_SOURCES+= gdoi_srtp.c
CFLAGS+=	-DSRTP_SUPPORT
CLEANFILES+=    srtp_num.c srtp_num.h
EXTRA_DIST+=    srtp_num.cst

srtp_num.c srtp_num.h: genconstants.sh srtp_num.cst
	/bin/sh ${srcdir}/genconstants.sh ${srcdir}/srtp_num
endif

if IEC90_5_SUPPORT
noinst_HEADERS+= gdoi_iec90_5.h gdoi_iec90_5_protos.h gdoi_app_iec90_5_attr.h
BUILT_C_FILES+= iec90_5_num.c iec90_5_fld.c
BUILT_H_FILES+= iec90_5_num.h iec90_5_fld.h
gdoid_SOURCES+= gdoi_iec90_5.c
CFLAGS+=	-DIEC90_5_SUPPORT
CLEANFILES+=	iec90_5_num.c iec90_5_fld.c iec90_5_num.h iec90_5_fld.h
EXTRA_DIST+=    iec90_5_num.cst iec90_5_fld.fld

iec90_5_num.c iec90_5_num.h: genconstants.sh iec90_5_num.cst
	/bin/sh ${srcdir}/genconstants.sh ${srcdir}/iec90_5_num

iec90_5_fld.c iec90_5_fld.h: genfields.sh iec90_5_fld.fld
	/bin/sh ${srcdir}/genfields.sh ${srcdir}/iec90_5_fld
endif

#
# Extra rules
#

install-data-local:
	${mkinstalldirs} /etc/gdoid
	${mkinstalldirs} /etc/gdoid/ca

#
# Remove generated .h and .c files from the distribution.
#
dist-hook:
	(cd ${distdir}; rm -f ${BUILT_SOURCES})
