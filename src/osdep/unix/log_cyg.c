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
 * Program:	Cygwin login
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

/* Log in
 * Accepts: login passwd struct
 *	    argument count
 *	    argument vector
 * Returns: T if success, NIL otherwise
 */

long loginpw (struct passwd *pw,int argc,char *argv[])
{
  uid_t uid = pw->pw_uid;

  /* the CRAM-MD5 code flow doesn't call checkpw() */
  if (auth_md5.server)
  {
    if (cyg_user) fs_give ((void **) &cyg_user);
    cyg_user = cpystr(pw->pw_name);
  }
  else
  {
				/* must be same user name as last checkpw() */
    if (!(cyg_user && !strcmp (pw->pw_name,cyg_user))) return NIL;
				/* do the ImpersonateLoggedOnUser() */
    cygwin_set_impersonation_token (cyg_hdl);
  }

  return !(setgid (pw->pw_gid) || initgroups (cyg_user,pw->pw_gid) ||
	   setuid (uid));
}
