/*-
 * Copyright (c) 1999, 2000, 2001, 2002 Andrew J. Korty
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $Id: pam_ssh.c,v 1.33 2002/08/09 15:32:06 akorty Exp $
 */


#include <sys/cdefs.h>
#include <sys/param.h>
#include <sys/stat.h>
#if HAVE_SYS_WAIT_H
# include <sys/wait.h>
#endif
#ifndef WEXITSTATUS
# define WEXITSTATUS(x)	((unsigned)(x) >> 8)
#endif
#ifndef WTERMSIG
# define WTERMSIG(x)	((x) & 0177)
#endif
#ifndef WIFSIGNALED
# define WIFSIGNALED(x)	(WTERMSIG(x) != _WSTOPPED && WTERMSIG(x) != 0)
#endif

#include <fcntl.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define PAM_SM_SESSION
#define PAM_SM_PASSWORD

#include <security/pam_modules.h>
#if HAVE_PAM_GET_PASS
# include <security/pam_mod_misc.h>
#else
# include <pam_mod_misc.h>
#endif

#include <openssl/dsa.h>
#include <openssl/evp.h>

#include "key.h"
#include "authfd.h"
#include "authfile.h"
#include "log.h"
#include "pam_ssh.h"

#if !defined(__unused)
# define __unused
#endif

#if HAVE_OPENPAM
# define pam_ssh_log openpam_log
#else
# define pam_ssh_log syslog
#endif

enum {
	PAM_OPT_KEYFILES = PAM_OPT_STD_MAX
};

static struct opttab other_options[] = {
	{ "keyfiles",	PAM_OPT_KEYFILES },
	{ NULL, 0 }
};

static void key_cleanup(pam_handle_t *, void *, int);
static void ssh_cleanup(pam_handle_t *, void *, int);

/*
 * Generic cleanup function for OpenSSH "Key" type.
 */

static void
key_cleanup(pam_handle_t *pamh __unused, void *data, int err __unused)
{
	if (data)
		key_free(data);
}


/*
 * Generic PAM cleanup function for this module.
 */

static void
ssh_cleanup(pam_handle_t *pamh __unused, void *data, int err __unused)
{
	if (data)
		free(data);
}


/*
 * Authenticate a user's key by trying to decrypt it with the password
 * provided.  The key and its comment are then stored for later
 * retrieval by the session phase.  An increasing index is embedded in
 * the PAM variable names so this function may be called multiple times
 * for multiple keys.
 */

static int
auth_via_key(pam_handle_t *pamh, const char *file, const char *dir,
    const struct passwd *user, const char *pass)
{
	char *comment;		/* private key comment */
	char *data_name;	/* PAM state */
	static int index = 0;	/* for saved keys */
	Key *key;		/* user's key */
	char *path;		/* to key files */
	int retval;		/* from calls */
	uid_t saved_uid;	/* caller's uid */

	/* locate the user's private key file */

	if (!asprintf(&path, "%s/%s", dir, file)) {
		pam_ssh_log(LOG_CRIT, "%s: %m", MODULE_NAME);
		return PAM_SERVICE_ERR;
	}

	/* Try to decrypt the private key with the passphrase provided.  If
	   success, the user is authenticated. */

	comment = NULL;
	if ((retval = openpam_borrow_cred(pamh, user)) != PAM_SUCCESS)
		return retval;
	key = key_load_private(path, pass, &comment);
	openpam_restore_cred(pamh);
	free(path);
	if (!comment)
		comment = strdup(file);
	if (!key) {
		free(comment);
		return PAM_AUTH_ERR;
	}

	/* save the key and comment to pass to ssh-agent in the session
           phase */

	if (!asprintf(&data_name, "ssh_private_key_%d", index)) {
		pam_ssh_log(LOG_CRIT, "%s: %m", MODULE_NAME);
		free(comment);
		return PAM_SERVICE_ERR;
	}
	retval = pam_set_data(pamh, data_name, key, key_cleanup);
	free(data_name);
	if (retval != PAM_SUCCESS) {
		key_free(key);
		free(comment);
		return retval;
	}
	if (!asprintf(&data_name, "ssh_key_comment_%d", index)) {
		pam_ssh_log(LOG_CRIT, "%s: %m", MODULE_NAME);
		free(comment);
		return PAM_SERVICE_ERR;
	}
	retval = pam_set_data(pamh, data_name, comment, ssh_cleanup);
	free(data_name);
	if (retval != PAM_SUCCESS) {
		free(comment);
		return retval;
	}

	++index;
	return PAM_SUCCESS;
}


/*
 * Add the keys stored by auth_via_key() to the agent connected to the
 * socket provided.
 */

static int
add_keys(pam_handle_t *pamh, char *socket)
{
	AuthenticationConnection *ac;	/* connection to ssh-agent */
	char *comment;			/* private key comment */
	char *data_name;		/* PAM state */
	int final;			/* final return value */
	int index;			/* for saved keys */
	Key *key;			/* user's private key */
	int retval;			/* from calls */

	/* connect to the agent */

	if (!(ac = ssh_get_authentication_connection(socket))) {
		pam_ssh_log(LOG_ERR, "%s: %s: %m", MODULE_NAME, socket);
		return PAM_SESSION_ERR;
	}

	/* hand off each private key to the agent */

	final = 0;
	for (index = 0; ; index++) {
		if (!asprintf(&data_name, "ssh_private_key_%d", index)) {
			pam_ssh_log(LOG_CRIT, "%s: %m", MODULE_NAME);
			ssh_close_authentication_connection(ac);
			return PAM_SERVICE_ERR;
		}
		retval = pam_get_data(pamh, data_name, (const void **)&key);
		free(data_name);
		if (retval != PAM_SUCCESS)
			break;
		if (!asprintf(&data_name, "ssh_key_comment_%d", index)) {
			pam_ssh_log(LOG_CRIT, "%s: %m", MODULE_NAME);
			ssh_close_authentication_connection(ac);
			return PAM_SERVICE_ERR;
		}
		retval = pam_get_data(pamh, data_name,
		    (const void **)&comment);
		free(data_name);
		if (retval != PAM_SUCCESS)
			break;
		retval = ssh_add_identity(ac, key, comment);
		if (!final)
			final = retval;
	}
	ssh_close_authentication_connection(ac);

	return final ? PAM_SUCCESS : PAM_SESSION_ERR;
}


PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags __unused, int argc,
    const char **argv)
{
	int authenticated;		/* user authenticated? */
	char *dotdir;			/* .ssh dir name */
	char *file;			/* current key file */
	char *keyfiles;			/* list of key files to add */
#if HAVE_OPENPAM
	const char *kfspec;		/* list of key files to add */
#else
	char *kfspec;			/* list of key files to add */
#endif
	struct options options;		/* options for pam_get_pass() */
	const char *pass;		/* passphrase */
	const struct passwd *pwent;	/* user's passwd entry */
	struct passwd *pwent_keep;	/* our own copy */
	int retval;			/* from calls */
	const char *user;		/* username */

	log_init(MODULE_NAME, SYSLOG_LEVEL_ERROR, SYSLOG_FACILITY_AUTHPRIV,
	    0);

	keyfiles = NULL;
#if HAVE_OPENPAM
	if ((kfspec = openpam_get_option(pamh, OPT_KEYFILES)) != NULL) {
		if ((kfspec = strchr(kfspec, '=')) == NULL) {
			openpam_log(PAM_LOG_ERROR, "invalid keyfile list");
			return PAM_SERVICE_ERR;
		}
		++kfspec;
	} else {
		kfspec = DEF_KEYFILES;
	}
#else
	pam_std_option(&options, other_options, argc, argv);
	if (!pam_test_option(&options, PAM_OPT_KEYFILES, &kfspec))
		kfspec = DEF_KEYFILES;
#endif

	if ((retval = pam_get_user(pamh, &user, NULL)) != PAM_SUCCESS)
		return retval;
	if (!(user && (pwent = getpwnam(user)) && pwent->pw_dir &&
	    *pwent->pw_dir))
		return PAM_AUTH_ERR;

	/* pass prompt message to application and receive passphrase */

#if HAVE_OPENPAM
	if ((retval = pam_get_authtok(pamh, PAM_AUTHTOK, &pass,
	    NEED_PASSPHRASE)) != PAM_SUCCESS)
#else
	if ((retval = pam_get_pass(pamh, &pass, NEED_PASSPHRASE, &options))
	    != PAM_SUCCESS)
#endif
		return retval;

	OpenSSL_add_all_algorithms(); /* required for DSA */

	/* any key will authenticate us, but if we can decrypt all of the
           specified keys, we'll do so here so we can cache them in the
           session phase */

	if (!asprintf(&dotdir, "%s/%s", pwent->pw_dir, SSH_CLIENT_DIR)) {
		pam_ssh_log(LOG_CRIT, "%s: %m", MODULE_NAME);
		return PAM_SERVICE_ERR;
	}
	authenticated = 0;
	keyfiles = strdup(kfspec);
	for (file = strtok(keyfiles, SEP_KEYFILES); file;
	     file = strtok(NULL, SEP_KEYFILES))
		if (auth_via_key(pamh, file, dotdir, pwent, pass) ==
		    PAM_SUCCESS)
			authenticated++;
	free(dotdir);
	free(keyfiles);
	if (!authenticated)
		return PAM_AUTH_ERR;

	/* copy the passwd entry (in case successive calls are made) and
           save it for the session phase */

	if (!(pwent_keep = malloc(sizeof *pwent))) {
		pam_ssh_log(LOG_CRIT, "%m");
		return PAM_SERVICE_ERR;
	}
	(void) memcpy(pwent_keep, pwent, sizeof *pwent_keep);
	if ((retval = pam_set_data(pamh, "ssh_passwd_entry", pwent_keep,
	    ssh_cleanup)) != PAM_SUCCESS) {
		free(pwent_keep);
		return retval;
	}

	return PAM_SUCCESS;
}


PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh __unused, int flags __unused,
    int argc __unused, const char **argv __unused)
{
	return PAM_SUCCESS;
}


PAM_EXTERN int
pam_sm_open_session(pam_handle_t *pamh, int flags __unused,
    int argc __unused, const char **argv __unused)
{
	char *agent_pid;		/* copy of agent PID */
	char *agent_socket;		/* agent socket */
	char *env_end;			/* end of env */
	FILE *env_read;			/* env data source */
	char env_string[BUFSIZ];	/* environment string */
	char *env_value;		/* envariable value */
	int env_write;			/* env file descriptor */
	char hname[MAXHOSTNAMELEN];	/* local hostname */
	int no_link;			/* link per-agent file? */
	char *per_agent;		/* to store env */
	char *per_session;		/* per-session filename */
	const struct passwd *pwent;	/* user's passwd entry */
	int retval;			/* from calls */
	uid_t saved_uid;		/* caller's uid */
	int start_agent;		/* start agent? */
	const char *tty;		/* tty or display name */

	log_init(MODULE_NAME, SYSLOG_LEVEL_ERROR, SYSLOG_FACILITY_AUTHPRIV,
	    0);

	/* dump output of ssh-agent in ~/.ssh */
	if ((retval = pam_get_data(pamh, "ssh_passwd_entry",
	    (const void **)&pwent)) != PAM_SUCCESS)
		return retval;

	/*
	 * Use reference counts to limit agents to one per user per host.
	 *
	 * Technique: Create an environment file containing
	 * information about the agent.  Only one file is created, but
	 * it may be given many names.  One name is given for the
	 * agent itself, agent-<host>.  Another name is given for each
	 * session, agent-<host>-<display> or agent-<host>-<tty>.  We
	 * delete the per-session filename on session close, and when
	 * the link count goes to unity on the per-agent file, we
	 * delete the file and kill the agent.
	 */

	/* the per-agent file contains just the hostname */

	(void) gethostname(hname, sizeof hname);
	if (asprintf(&per_agent, "%s/.ssh/agent-%s", pwent->pw_dir, hname)
	    == -1) {
		pam_ssh_log(LOG_CRIT, "%s: %m", MODULE_NAME);
		return PAM_SERVICE_ERR;
	}

	/* save the per-agent filename in case we want to delete it on
           session close */

	if ((retval = pam_set_data(pamh, "ssh_agent_env_agent", per_agent,
	    ssh_cleanup)) != PAM_SUCCESS) {
		free(per_agent);
		return retval;
	}

	/* take on the user's privileges for writing files and starting the
           agent */

	if ((retval = openpam_borrow_cred(pamh, pwent)) != PAM_SUCCESS)
		return retval;

	/* Try to create the per-agent file or open it for reading if it
           exists.  If we can't do either, we won't try to link a
           per-session filename later.  Start the agent if we can't open
	   the file for reading. */

	env_write = no_link = 0;
	env_read = NULL;
	if ((env_write = open(per_agent, O_CREAT | O_EXCL | O_WRONLY,
	    S_IRUSR)) < 0 && !(env_read = fopen(per_agent, "r")))
		no_link = 1;
	if (env_read) {
		start_agent = 0;
		openpam_restore_cred(pamh);
	} else {
		start_agent = 1;
		env_read = popen(SSH_AGENT, "r");
		openpam_restore_cred(pamh);
		if (!env_read) {
			pam_ssh_log(LOG_ERR, "%s: %s: %m", MODULE_NAME,
			    SSH_AGENT);
			if (env_write >= 0)
				(void) close(env_write);
			return PAM_SESSION_ERR;
		}
	}

	/* save environment for application with pam_putenv() */

	agent_socket = NULL;
	while (fgets(env_string, sizeof env_string, env_read)) {

		/* parse environment definitions */

		if (env_write >= 0)
			(void) write(env_write, env_string,
			    strlen(env_string));
		if (!(env_value = strchr(env_string, '=')) ||
		    !(env_end = strchr(env_value, ';')))
			continue;
		*env_end = '\0';

		/* pass to the application */

		if (!((retval = pam_putenv(pamh, env_string)) ==
		    PAM_SUCCESS)) {
			if (start_agent)
				(void) pclose(env_read);
			else
				(void) fclose(env_read);
			if (env_write >= 0)
				(void) close(env_write);
			if (agent_socket)
				free(agent_socket);
			return PAM_SERVICE_ERR;
		}

		*env_value++ = '\0';

		/* save the agent socket so we can connect to it and add
                   the keys as well as the PID so we can kill the agent on
                   session close. */

		if (strcmp(&env_string[strlen(env_string) -
		    strlen(ENV_SOCKET_SUFFIX)], ENV_SOCKET_SUFFIX) == 0 &&
		    !(agent_socket = strdup(env_value))) {
			pam_ssh_log(LOG_CRIT, "%s: %m", MODULE_NAME);
			if (start_agent)
				(void) pclose(env_read);
			else
				(void) fclose(env_read);
			if (env_write >= 0)
				(void) close(env_write);
			if (agent_socket)
				free(agent_socket);
			return PAM_SERVICE_ERR;
		} else if (strcmp(&env_string[strlen(env_string) -
		    strlen(ENV_PID_SUFFIX)], ENV_PID_SUFFIX) == 0 &&
		    ((agent_pid = strdup(env_value)) == NULL ||
		    (retval = pam_set_data(pamh, "ssh_agent_pid",
		    agent_pid, ssh_cleanup)) != PAM_SUCCESS)) {
			if (start_agent)
				(void) pclose(env_read);
			else
				(void) fclose(env_read);
			if (env_write >= 0)
				(void) close(env_write);
			if (agent_pid)
				free(agent_pid);
			if (agent_socket)
				free(agent_socket);
			return retval;
		}

	}
	if (env_write >= 0)
		(void) close(env_write);

	if (start_agent) {
		switch (retval = pclose(env_read)) {
		case -1:
			pam_ssh_log(LOG_ERR, "%s: %s: %m", MODULE_NAME,
			    SSH_AGENT);
			if (agent_socket)
				free(agent_socket);
			return PAM_SESSION_ERR;
		case 0:
			break;
		case 127:
			pam_ssh_log(LOG_ERR, "%s: cannot execute %s",
			    MODULE_NAME, SSH_AGENT);
			if (agent_socket)
				free(agent_socket);
			return PAM_SESSION_ERR;
		default:
			pam_ssh_log(LOG_ERR, "%s: %s exited %s %d",
			    MODULE_NAME, SSH_AGENT, WIFSIGNALED(retval) ?
			    "on signal" : "with status",
			    WIFSIGNALED(retval) ? WTERMSIG(retval) :
			    WEXITSTATUS(retval));
			if (agent_socket)
				free(agent_socket);
			return PAM_SESSION_ERR;
		}
	} else
		(void) fclose(env_read);

	if (!agent_socket)
		return PAM_SESSION_ERR;

	if (start_agent && (retval = add_keys(pamh, agent_socket))
	    != PAM_SUCCESS)
		return retval;
	free(agent_socket);

	/* if we couldn't access the per-agent file, don't link a
           per-session filename to it */

	if (no_link)
		return PAM_SUCCESS;

	/* the per-session file contains the display name or tty name as
           well as the hostname */

	if ((retval = pam_get_item(pamh, PAM_TTY, (const void **)&tty))
	    != PAM_SUCCESS)
		return retval;
	if (asprintf(&per_session, "%s/.ssh/agent-%s-%s", pwent->pw_dir,
	    hname, tty) == -1) {
		pam_ssh_log(LOG_CRIT, "%s: %m", MODULE_NAME);
		return PAM_SERVICE_ERR;
	}

	/* save the per-session filename so we can delete it on session
           close */

	if ((retval = pam_set_data(pamh, "ssh_agent_env_session",
	    per_session, ssh_cleanup)) != PAM_SUCCESS) {
		free(per_session);
		return retval;
	}

	(void) unlink(per_session);		/* remove cruft */
	(void) link(per_agent, per_session);

	return PAM_SUCCESS;
}


PAM_EXTERN int
pam_sm_close_session(pam_handle_t *pamh, int flags __unused,
    int argc __unused, const char **argv __unused)
{
	const char *env_file;		/* ssh-agent environment */
	pid_t pid;			/* ssh-agent process id */
	int retval;			/* from calls */
	const char *ssh_agent_pid;	/* ssh-agent pid string */
	struct stat sb;			/* to check st_nlink */

	if ((retval = pam_get_data(pamh, "ssh_agent_env_session",
	    (const void **)&env_file)) == PAM_SUCCESS && env_file)
		(void) unlink(env_file);

	/* Retrieve per-agent filename and check link count.  If it's
           greater than unity, other sessions are still using this
           agent. */

	if ((retval = pam_get_data(pamh, "ssh_agent_env_agent",
	    (const void **)&env_file)) == PAM_SUCCESS && env_file &&
	    stat(env_file, &sb) == 0) {
		if (sb.st_nlink > 1)
			return PAM_SUCCESS;
		(void) unlink(env_file);
	}

	/* retrieve the agent's process id */

	if ((retval = pam_get_data(pamh, "ssh_agent_pid",
	    (const void **)&ssh_agent_pid)) != PAM_SUCCESS)
		return retval;

	/* Kill the agent.  SSH's ssh-agent does not have a -k option, so
           just call kill(). */

	pid = atoi(ssh_agent_pid);
	if (pid <= 0)
		return PAM_SESSION_ERR;
	if (kill(pid, SIGTERM) != 0) {
		pam_ssh_log(LOG_ERR, "%s: %s: %m", MODULE_NAME,
		    ssh_agent_pid);
		return PAM_SESSION_ERR;
	}

	return PAM_SUCCESS;
}


#if !HAVE_OPENPAM
PAM_EXTERN int
pam_sm_acct_mgmt(pam_handle_t *pamh __unused, int flags __unused,
    int argc __unused, const char **argv __unused)
{
	return PAM_IGNORE;
}


PAM_EXTERN int
pam_sm_chauthtok(pam_handle_t *pamh __unused, int flags __unused,
    int argc __unused, const char **argv __unused)
{
	return PAM_IGNORE;
}
#endif


#ifdef PAM_MODULE_ENTRY
PAM_MODULE_ENTRY(MODULE_NAME);
#else /* PAM_MODULE_ENTRY */
#ifdef PAM_STATIC
struct pam_module _modstruct = {
	MODULE_NAME,
	pam_sm_authenticate,
	pam_sm_acct_mgmt,
	pam_sm_chauthtok,
	pam_sm_open_session, pam_sm_close_session,
	NULL
};
#endif /* PAM_STATIC */
#endif /* PAM_MODULE_ENTRY */
