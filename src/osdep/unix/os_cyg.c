/* ========================================================================
 * Copyright 1988-2006 University of Washington
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * 
 * ========================================================================
 */

/*
 * Program:	Operating-system dependent routines -- Cygwin version
 *
 * Author:	Mark Crispin
 *		Networks and Distributed Computing
 *		Computing & Communications
 *		University of Washington
 *		Administration Building, AG-44
 *		Seattle, WA  98195
 *		Internet: MRC@CAC.Washington.EDU
 *
 * Date:	1 August 1988
 * Last Edited:	30 August 2006
 */
 
#include "tcp_unix.h"		/* must be before osdep includes tcp.h */
#include "mail.h"
#include "osdep.h"
#include <stdio.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <ctype.h>
#include <errno.h>
extern int errno;		/* just in case */
#include <pwd.h>
#include <grp.h>
#include <crypt.h>
#include "misc.h"


#define isodigit(c)    (((unsigned)(c)>=060)&((unsigned)(c)<=067))
#define toint(c)       ((c)-'0')

#include "fs_unix.c"
#include "ftl_unix.c"
#include "nl_unix.c"
#include "env_unix.c"
#include "tcp_unix.c"
#include "gr_wait.c"
#include "tz_nul.c"
#include "flockcyg.c"
#include "gethstid.c"


/* Emulator for geteuid() call
 * Returns: effective UID
 */

#undef geteuid

#define GIDS_FOR_SEARCH_SIZE 12

uid_t Geteuid (void)
{
  struct passwd *pwent = NULL;
  struct group *grent = NULL;
  /* compromise (for sake of a reasonable stack frame and avoiding calling
     malloc. if we can't find the Administrators gid within the bounds, be
     prudent and return 0 uid */
  gid_t my_gids[GIDS_FOR_SEARCH_SIZE];
  int num_gids;
  uid_t ret = geteuid ();

  /* find the real uid for SYSTEM */
  for (pwent = getpwent();
       (pwent != NULL) && (strcmp (SYSTEMUSERSID, pwent->pw_passwd) != 0);
       pwent = getpwent());

  /* if we find the real uid for SYSTEM and our effective uid is the same
     then we return the uid of the root user */
  if ((pwent != NULL) && (ret == pwent->pw_uid))
    return 0;

  /* find the real gid for Administrators */
  for (grent = getgrent();
       (grent != NULL) && (strcmp (ADMINISTRATORSGROUPSID, grent->gr_gid) != 0);
       grent = getgrent());

  /* if we cannot find the real gid for Administrators, take the most
     prudent approach and indicate this is a privileged account (that
     cannot be preauth'ed) */
  if (grent == NULL)
    return 0;

  num_gids = getgroups(GIDS_FOR_SEARCH_SIZE, my_gids);
  for (int idx = 0;
       (ifx < num_gids) && (my_gids[idx] != grent->gr_gid);
       idx++);
  
  return (idx < num_gids) ? 0 : ret;
}
