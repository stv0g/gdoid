/* $Id: isakmpd.c,v 1.8.2.1 2011/10/18 03:26:56 bew Exp $ */
/* $Source: /nfs/cscbz/gdoi/gdoicvs/gdoi/src/isakmpd.c,v $ */

/*	$OpenBSD: isakmpd.c,v 1.30 2001/04/09 22:09:52 ho Exp $	*/
/*	$EOM: isakmpd.c,v 1.54 2000/10/05 09:28:22 niklas Exp $	*/

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


/*
 * Copyright (c) 1998, 1999, 2000, 2001 Niklas Hallqvist.  All rights reserved.
 * Copyright (c) 1999, 2000 Angelos D. Keromytis.  All rights reserved.
 * Copyright (c) 1999, 2000 Håkan Olsson.  All rights reserved.
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
 *	This product includes software developed by Ericsson Radio Systems.
 * 4. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * This code was written under funding by Ericsson Radio Systems.
 */

#include <errno.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include "sysdep.h"

#include "app.h"
#include "conf.h"
#include "sa.h"
#include "connection.h"
#include "init.h"
#include "libcrypto.h"
#include "log.h"
#include "timer.h"
#include "transport.h"
#include "udp.h"
#include "ui.h"
#include "util.h"
#include "cert.h"
#include <openssl/rand.h>

/*
 * Set if -d is given, currently just for running in the foreground and log
 * to stderr instead of syslog.
 */
int debug = 0;

/*
 * If we receive a SIGHUP signal, this flag gets set to show we need to
 * reconfigure ASAP.
 */
static int sighupped = 0;

/*
 * If we receive a USR1 signal, this flag gets set to show we need to dump
 * a report over our internal state ASAP.  The file to report to is settable
 * via the -R parameter.
 */
static int sigusr1ed = 0;
static char *report_file = "/var/run/gdoid.report";

/* The default path of the PID file.  */
static char *pid_file = "/var/run/gdoid.pid";

#ifdef USE_DEBUG
/* The path of the IKE packet capture log file.  */
static char *pcap_file = 0;
#endif

/*
 * If we receive a TERM signal, perform a "clean shutdown" of the daemon.
 * This includes to send DELETE notifications for all our active SAs.
 * Also on recv of an INT signal (Ctrl-C out of an '-d' session, typically).
 */
volatile sig_atomic_t sigtermed = 0;
void daemon_shutdown_now(int);

/*
 * If we receive a USR2 signal, this flag gets set to show we need to
 * rehash our SA soft expiration timers to a uniform distribution.
 * XXX Perhaps this is a really bad idea?
 */
static int sigusr2ed = 0;

static void
usage ()
{
  fprintf (stderr,
	   "usage: %s [-c config-file] [-d] [-D class=level] [-f fifo]\n"
	   "          [-i pid-file] [-n] [-p listen-port] [-P local-port]\n"
	   "          [-L] [-l packetlog-file] [-R report-file]\n",
	   sysdep_progname ());
  exit (1);
}

static void
parse_args (int argc, char *argv[])
{
  int ch;
#ifdef USE_DEBUG
  int cls, level;
  int do_packetlog = 0;
#endif

  while ((ch = getopt (argc, argv, "c:dD:f:i:np:P:Ll:R:")) != -1) {
    switch (ch) {
    case 'c':
      conf_path = optarg;
      break;

    case 'd':
      debug++;
      break;

#ifdef USE_DEBUG
    case 'D':
      if (sscanf (optarg, "%d=%d", &cls, &level) != 2)
	{
	    if (sscanf (optarg, "A=%d", &level) == 1)
	      {
		  for (cls = 0; cls < LOG_ENDCLASS; cls++)
		    log_debug_cmd (cls, level);
	      }  
	    else
	      log_print ("parse_args: -D argument unparseable: %s", optarg);
	}
      else
	log_debug_cmd (cls, level);
      break;
#endif /* USE_DEBUG */

    case 'f':
      ui_fifo = optarg;
      break;

    case 'i':
      pid_file = optarg;
      break;

    case 'n':
      app_none++;
      break;

    case 'p':
      udp_default_port = udp_decode_port (optarg);
      if (!udp_default_port)
	exit (1);
      break;

    case 'P':
      udp_bind_port = udp_decode_port (optarg);
      if (!udp_bind_port)
	exit (1);
      break;

#ifdef USE_DEBUG
    case 'l':
      pcap_file = optarg;
      /* Fallthrough intended.  */

    case 'L':
      do_packetlog++;
      break;
#endif /* USE_DEBUG */

    case 'R':
      report_file = optarg;
      break;

    case '?':
    default:
      usage ();
    }
  }
  argc -= optind;
  argv += optind;

#ifdef USE_DEBUG
  if (do_packetlog && !pcap_file)
    pcap_file = PCAP_FILE_DEFAULT;
#endif
}

/* Reinitialize after a SIGHUP reception.  */
static void
reinit (void)
{
  log_print ("SIGHUP recieved, reinitializing daemon.");

  /* 
   * XXX Remove all(/some?) pending exchange timers? - they may not be 
   *     possible to complete after we've re-read the config file.
   *     User-initiated SIGHUP's maybe "authorizes" a wait until
   *     next connection-check.
   * XXX This means we discard exchange->last_msg, is this really ok?
   */

  /* Reread config file.  */
  conf_reinit ();

  /* Try again to link in libcrypto (good if we started without /usr).  */
  libcrypto_init ();

  /* Set timezone */
  tzset ();

  /* Reinitialize certificates */
  cert_init ();

  /* Reinitialize our connection list.  */
  connection_reinit ();

  /*
   * XXX Rescan interfaces.
   *   transport_reinit (); 
   *   udp_reinit ();
   */

  /*
   * XXX "These" (non-existant) reinitializations should not be done.
   *   cookie_reinit ();
   *   ui_reinit ();
   *   sa_reinit ();
   */

  sighupped = 0;
}

static void
sighup (int sig)
{
  sighupped = 1;
}

/* Report internal state on SIGUSR1.  */
static void
report (void)
{
  FILE *report, *old;
  mode_t old_umask;
	
  old_umask = umask (S_IRWXG | S_IRWXO);
  report = fopen (report_file, "w");
  umask (old_umask);

  if (!report)
    {
      log_error ("fopen (\"%s\", \"w\") failed", report_file);
      return;
    }

  /* Divert the log channel to the report file during the report.  */
  old = log_current ();
  log_to (report);
  ui_report ("r");
  log_to (old);
  fclose (report);

  sigusr1ed = 0;
}

static void
sigusr1 (int sig)
{
  sigusr1ed = 1;
}

/* Rehash soft expiration timers on SIGUSR2.  */
static void
rehash_timers (void)
{
#if 0
  /* XXX - not yet */
  log_print ("SIGUSR2 received, rehasing soft expiration timers.");
  
  timer_rehash_timers ();
#endif

  sigusr2ed = 0;
}

static void
sigusr2 (int sig)
{
  sigusr2ed = 1;
}

static int
phase2_sa_check(struct sa *sa, void *arg)
{
	return sa->phase == 2;
}

extern void gdoi_rekey_delete_sas (fd_set *wfds);

static void
daemon_shutdown(fd_set *wfds)
{
  /* Perform a (protocol-wise) clean shutdown of the daemon.  */
  struct sa	*sa;

  if (sigtermed == 1) {
   	log_print("gdoid: shutting down...");

	/* Delete all active phase 2 SAs.  */
	while ((sa = sa_find(phase2_sa_check, NULL))) {
		/* Each DELETE is another (outgoing) message.  */
		sa_delete(sa, 1);
	}
	/* Delete GDOI SAs */
	gdoi_rekey_delete_sas(wfds);
	sigtermed++;
  }
}

/* Called on SIGTERM, SIGINT or by ui_shutdown_daemon().  */
void
daemon_shutdown_now(int sig)
{
	sigtermed = 1;
}

/* Write pid file.  */
static void
write_pid_file (void)
{
  FILE *fp;

  /* Ignore errors.  */
  unlink (pid_file);

  fp = fopen (pid_file, "w");
  if (fp != NULL)
    {
      /* XXX Error checking!  */
      fprintf (fp, "%d\n", getpid ());
      fclose (fp);
    }
  else
    log_fatal ("main: fopen (\"%s\", \"w\") failed", pid_file);
}

int
main (int argc, char *argv[])
{
  fd_set *rfds, *wfds;
  int n, m;
  size_t mask_size;
  struct timeval tv, *timeout;
  static const char rnd_seed[] = "this is a seed";

  log_to (stderr);

  RAND_seed(rnd_seed, sizeof rnd_seed);

  parse_args (argc, argv);
  init ();
  if (!debug)
    {
      if (daemon (0, 0))
	log_fatal ("main: daemon (0, 0) failed");
      /* Switch to syslog.  */
      log_to (0);
    }

  write_pid_file ();

  /* Do a clean daemon shutdown */
  signal(SIGTERM, daemon_shutdown_now);
	if (debug == 1)		/* i.e '-dd' will skip this.  */
		signal(SIGINT, daemon_shutdown_now);
  
  /* Reinitialize on HUP reception.  */
  signal (SIGHUP, sighup);

  /* Report state on USR1 reception.  */
  signal (SIGUSR1, sigusr1);

  /* Rehash soft expiration timers on USR2 reception.  */
  signal (SIGUSR2, sigusr2);

#ifdef USE_DEBUG
  /* If we wanted IKE packet capture to file, initialize it now.  */
  if (pcap_file != 0)
    log_packet_init (pcap_file);
#endif
  
  /* Allocate the file descriptor sets just big enough.  */
  n = getdtablesize ();
  mask_size = howmany (n, NFDBITS) * sizeof (fd_mask);
  rfds = (fd_set *)malloc (mask_size);
  if (!rfds)
    log_fatal ("main: malloc (%d) failed", mask_size);
  wfds = (fd_set *)malloc (mask_size);
  if (!wfds)
    log_fatal ("main: malloc (%d) failed", mask_size);

  while (1)
    {
      /* If someone has sent SIGHUP to us, reconfigure.  */
      if (sighupped)
        reinit ();

      /* and if someone sent SIGUSR1, do a state report.  */
      if (sigusr1ed)
        report ();

      /* and if someone sent SIGUSR2, do a timer rehash.  */
      if (sigusr2ed)
        rehash_timers ();

      /* Do a clean shutdown on SIGINT or SIGTERM */
      if (sigtermed)
        {
          daemon_shutdown(wfds);
      	  transport_send_messages (wfds);
  		  exit(0);	
		}
      
      /* Setup the descriptors to look for incoming messages at.  */
      memset (rfds, 0, mask_size);
      n = transport_fd_set (rfds);
      FD_SET (ui_socket, rfds);
      if (ui_socket + 1 > n)
	n = ui_socket + 1;

      /*
       * XXX Some day we might want to deal with an abstract application
       * class instead, with many instantiations possible.
       */
      if (!app_none && app_socket >= 0)
	{
	  FD_SET (app_socket, rfds);
	  if (app_socket + 1 > n)
	    n = app_socket + 1;
	}

      /* Setup the descriptors that have pending messages to send.  */
      memset (wfds, 0, mask_size);
      m = transport_pending_wfd_set (wfds);
      if (m > n)
	n = m;

      /* Find out when the next timed event is.  */
      timeout = &tv;
      timer_next_event (&timeout);

      n = select (n, rfds, wfds, 0, timeout);
      if (n == -1)
	{
	  if (errno != EINTR)
	    {
	      log_error ("select");

	      /*
	       * In order to give the unexpected error condition time to
	       * resolve without letting this process eat up all available CPU
	       * we sleep for a short while.
	       */
	      sleep (1);
	    }
	}
      else if (n)
	{
	  transport_handle_messages (rfds);
	  transport_send_messages (wfds);
	  if (FD_ISSET (ui_socket, rfds))
	    ui_handler ();
	  if (!app_none && app_socket >= 0 && FD_ISSET (app_socket, rfds))
	    app_handler ();
	}
      timer_handle_expirations ();
    }
}
