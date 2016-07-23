/* Author: Mark Goldman	  <mgoldman@tresys.com>
 * 	   Paul Rosenfeld <prosenfeld@tresys.com>
 * 	   Todd C. Miller <tmiller@tresys.com>
 *
 * Copyright (C) 2007 Tresys Technology, LLC
 *
 *  This library is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as
 *  published by the Free Software Foundation; either version 2.1 of the
 *  License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful, but
 *  WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 *  02110-1301  USA
 */

#include "debug.h"
#include "semanage_store.h"
#include "seuser_internal.h"
#include <selinux/context.h>
#include <semanage/fcontext_record.h>
#include <semanage/fcontexts_policy.h>
#include <semanage/handle.h>
#include <semanage/seusers_policy.h>
#include <semanage/user_record.h>
#include <semanage/users_policy.h>
#include <sepol/context.h>
#include <sepol/context_record.h>

#include "genhomedircon.h"
#include "utilities.h"
#include <ustr.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <math.h>
#include <pwd.h>
#include <regex.h>
#include <search.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/* paths used in get_home_dirs() */
#define PATH_ETC_USERADD "/etc/default/useradd"
#define PATH_ETC_LIBUSER "/etc/libuser.conf"
#define PATH_DEFAULT_HOME "/home"
#define PATH_EXPORT_HOME "/export/home"
#define PATH_ETC_LOGIN_DEFS "/etc/login.defs"

/* other paths */
#define PATH_SHELLS_FILE "/etc/shells"
#define PATH_NOLOGIN_SHELL "/sbin/nologin"

/* comments written to context file */
#define COMMENT_FILE_CONTEXT_HEADER                                            \
	"#\n#\n# "                                                             \
	"User-specific file contexts, generated via libsemanage\n"             \
	"# use semanage command to manage system users to change"              \
	" the file_context\n#\n#\n"

#define COMMENT_USER_HOME_CONTEXT                                              \
	"\n\n#\n# Home Context for user %s"                                    \
	"\n#\n\n"

#define CONTEXT_NONE "<<none>>"

/* placeholders used in the template file
   which are searched for and replaced */
#define TEMPLATE_HOME_ROOT "HOME_ROOT"
#define TEMPLATE_HOME_DIR "HOME_DIR"
/* these are legacy */
#define TEMPLATE_USER "USER"
#define TEMPLATE_ROLE "ROLE"

/* new names */
#define TEMPLATE_USERNAME "%{USERNAME}"
#define TEMPLATE_USERID "%{USERID}"

#define FALLBACK_NAME "[^/]+"
#define FALLBACK_UIDGID "[0-9]+"
#define DEFAULT_LOGIN "__default__"

struct replacement_pair {
	const char *search_for;
	const char *replace_with;
};

/*
 Represents a mapping of a Linux login
 to a SELinux user (not necessarily a 1-1
 mapping with seusers since groups are expanded)
*/
struct selogin_list {
	char *name;
	char *sename;
	char *level;
	char *prefix;

	char *uid;
	char *gid;
	char *homedir;

	struct selogin_list *next;
};

static int strcomparator(const void *a, const void *b) { return strcmp(a, b); }

/*
  Predicate for file context specifications which
  are to be written for each home directory root
  (e.g., /home).
 */
static int ROOT_PRED(const char *string)
{
	return semanage_is_prefix(string, TEMPLATE_HOME_ROOT);
}

/*
  Predicate for file context specifications which
  are to be written for each home directory.
 */
static int HOMEDIR_PRED(const char *string)
{
	return semanage_is_prefix(string, TEMPLATE_HOME_DIR);
}

/*
  Predicate for file context specifications which
  are to be written once per SELinux login.
 */
static int USER_PRED(const char *string)
{
	return strstr(string, TEMPLATE_USER) != NULL ||
	       strstr(string, TEMPLATE_USERNAME) != NULL ||
	       strstr(string, TEMPLATE_USERID) != NULL;
}

static int genhomedircon_get_home_dirs(semanage_list_t **out, int usepasswd)
{
	(void) usepasswd;
	// @todo - pull the relevant parts of code back into the original
	// genhomedircon to avoid re-implementing parts like this

	if (semanage_list_push(out, PATH_DEFAULT_HOME) != STATUS_SUCCESS) {
		return STATUS_ERR;
	}

	return STATUS_SUCCESS;
}

static struct selogin_list *genhomedircon_user_free(struct selogin_list *user)
{
	struct selogin_list *next = user->next;

	free(user->name);
	free(user->sename);
	free(user->prefix);
	free(user->uid);
	free(user->gid);
	free(user->level);
	free(user->homedir);
	free(user);

	return next;
}

static int genhomedircon_user_find(struct selogin_list *list, const char *name)
{
	struct selogin_list *curr = list;

	while (curr != NULL) {
		if (strcmp(curr->name, name) == 0) {
			return 1;
		}

		curr = curr->next;
	}

	return 0;
}

static int genhomedircon_user_read_pwent(struct selogin_list *user,
					 const char *name)
{
	int retval = STATUS_ERR;
	struct passwd *pwent = getpwnam(name);

	if (pwent == NULL) {
		return -ENOENT;
	}

	if (!pwent->pw_dir) {
		return -ENOENT;
	}

	int len = -1;
	int expected_len = -1;
	char *uid = NULL;
	char *gid = NULL;

	expected_len = sizeof(char) * (log10(pwent->pw_uid) + 2);
	uid = malloc(expected_len);
	if (!uid) {
		goto done;
	}

	len = snprintf(uid, expected_len, "%u", pwent->pw_uid);

	if (len < 0 || len > expected_len) {
		goto done;
	}

	expected_len = sizeof(char) * (log10(pwent->pw_gid) + 2);
	gid = malloc(expected_len);
	if (!gid) {
		goto done;
	}

	len = snprintf(gid, expected_len, "%u", pwent->pw_gid);

	if (len < 0 || len > expected_len) {
		goto done;
	}

	user->uid = uid;
	user->gid = gid;
	user->homedir = strdup(pwent->pw_dir);

	if (!user->homedir) {
		goto done;
	}

	retval = STATUS_SUCCESS;
done:
	if (retval < 0) {
		free(user->uid);
		free(user->gid);
		free(user->homedir);
		user->uid = NULL;
		user->gid = NULL;
		user->homedir = NULL;
	}

	return retval;
}

static int genhomedircon_user_add(semanage_handle_t *sh,
				  struct selogin_list **entry_list,
				  const char *name, const char *sename,
				  int is_default_login)
{
	int retval = STATUS_ERR;

	struct selogin_list *user = NULL;
	semanage_user_key_t *key = NULL;
	semanage_user_t *seuser = NULL;

	if (genhomedircon_user_find(*entry_list, name)) {
		ERR(sh, "Found more than 1 entry for %s", name);
		goto done;
	}

	user = calloc(1, sizeof *user);
	if (!user) {
		goto done;
	}

	if (semanage_user_key_create(sh, sename, &key) < 0) {
		goto done;
	}

	if (semanage_user_query(sh, key, &seuser) < 0) {
		ERR(sh, "No SELinux user found named \"%s\"", sename);
		goto done;
	}

	const char *prefix = semanage_user_get_prefix(seuser);
	if (prefix) {
		user->prefix = strdup(prefix);
	} else {
		user->prefix = strdup(name);
	}

	if (!user->prefix) {
		goto done;
	}

	const char *level = semanage_user_get_mlslevel(seuser);
	if (!level) {
		goto done;
	}

	user->sename = strdup(sename);
	user->level = strdup(level);

	if (!user->sename || !user->level) {
		goto done;
	}

	if (!is_default_login) {
		user->name = strdup(name);

		if (!user->name) {
			goto done;
		}

		retval = genhomedircon_user_read_pwent(user, name);
		if (retval < 0) {
			goto done;
		}
	}

	user->next = *entry_list;
	*entry_list = user;

	retval = STATUS_SUCCESS;
done:
	if (retval < 0 && user) {
		genhomedircon_user_free(user);
	}

	semanage_user_key_free(key);
	semanage_user_free(seuser);

	return retval;
}

static int genhomedircon_get_group_users(semanage_handle_t *sh,
					 struct selogin_list **entry_list,
					 const char *name, const char *sename)
{
	int retval = STATUS_ERR;
	struct group *group = getgrnam(name);

	if (group == NULL) {
		ERR(sh, "Can't find group named %s\n", name);
		goto exit;
	}

	size_t nmembers = 0;
	char **members = group->gr_mem;

	while (*members != NULL) {
		nmembers++;
		members++;
	}

	for (unsigned int i = 0; i < nmembers; i++) {
		const char *uname = group->gr_mem[i];

		if (genhomedircon_user_add(sh, entry_list, uname, sename, 0) ==
		    STATUS_ERR) {
			return STATUS_ERR;
		}
	}

	setpwent();

	struct passwd *pwent = NULL;
	while ((pwent = getpwent()) != NULL) {
		// skip users who also have this group as their
		// primary group
		if (lfind(pwent->pw_name, group->gr_mem, &nmembers,
			  sizeof(char *), strcomparator)) {
			continue;
		}

		if (group->gr_gid == pwent->pw_gid) {
			if (genhomedircon_user_add(
				sh, entry_list, pwent->pw_name, sename, 0)) {
				goto exit;
			}
		}
	}

	retval = STATUS_SUCCESS;
exit:
	endpwent();
	return retval;
}

static int genhomedircon_get_users(semanage_handle_t *sh,
				   struct selogin_list **login_list,
				   struct selogin_list **default_login)
{
	int retval = STATUS_ERR;

	semanage_seuser_t **seusers = NULL;
	unsigned int nseusers;

	retval = semanage_seuser_list(sh, &seusers, &nseusers);
	if (retval < 0) {
		goto clean;
	}

	unsigned int i;
	for (i = 0; i < nseusers; i++) {
		const char *name = semanage_seuser_get_name(seusers[i]);
		const char *sename = semanage_seuser_get_sename(seusers[i]);

		if (name[0] == '%') {
			retval = genhomedircon_get_group_users(
			    sh, login_list, name + 1, sename);
		} else {
			if (strcmp(name, "root") == 0) {
				continue;
			} else if (strcmp(name, DEFAULT_LOGIN) == 0) {
				retval = genhomedircon_user_add(
				    sh, default_login, name, sename, 1);
			} else {
				retval = genhomedircon_user_add(
				    sh, login_list, name, sename, 0);
			}
		}

		if (retval == -ENOENT) {
			WARN(sh, "couldn't find login for %s", name);
		} else if (retval < 0) {
			goto clean;
		}
	}

	retval = STATUS_SUCCESS;
clean:
	if (seusers) {
		for (i = 0; i < nseusers; i++) {
			semanage_seuser_free(seusers[i]);
		}

		free(seusers);
	}

	if (retval < 0) {
		while (*login_list) {
			*login_list = genhomedircon_user_free(*login_list);
		}

		if (*default_login) {
			genhomedircon_user_free(*default_login);
		}
	}

	return retval;
}

static int genhomedircon_get_ignore_list(semanage_list_t **ignore_list,
					 char *ignoredirs)
{
	char *tok = strtok(ignoredirs, ";");
	while (tok) {
		if (semanage_list_push(ignore_list, tok)) {
			return STATUS_ERR;
		}

		tok = strtok(NULL, ";");
	}

	return STATUS_SUCCESS;
}

static int genhomedircon_replace(struct replacement_pair *repl,
				 const char *line, Ustr **out)
{
	Ustr *replacement = ustr_dup_cstr(line);

	if (!replacement) {
		return STATUS_ERR;
	}

	for (; repl->search_for != NULL && repl->replace_with != NULL; repl++) {
		ustr_replace_cstr(&replacement, repl->search_for,
				  repl->replace_with, 0);
	}

	if (ustr_enomem(replacement)) {
		ustr_sc_free(&replacement);
		return STATUS_ERR;
	}

	*out = replacement;
	return STATUS_SUCCESS;
}

static int genhomedircon_write_root_contexts(FILE *out, const char *homedir,
					     semanage_list_t *root_ctx_list)
{
	struct replacement_pair repl[] = {
	    {.search_for = TEMPLATE_HOME_ROOT, .replace_with = homedir},
	    {NULL, NULL}};

	for (; root_ctx_list; root_ctx_list = root_ctx_list->next) {
		Ustr *replacement = NULL;

		if (genhomedircon_replace(repl, root_ctx_list->data,
					  &replacement) < 0) {
			return STATUS_ERR;
		}

		if (!ustr_io_putfileline(&replacement, out)) {
			ustr_sc_free(&replacement);
			return STATUS_ERR;
		}

		ustr_sc_free(&replacement);
	}

	return STATUS_SUCCESS;
}

static int genhomedircon_fix_context(struct selogin_list *user, Ustr **line,
				     int fixrole)
{
	int retval = STATUS_ERR;

	const char whitespace[] = " \t\n";
	size_t off, len, pos;

	/* check for trailing whitespace */
	off = ustr_spn_chrs_rev(*line, 0, whitespace, strlen(whitespace));

	/* find the length of the last field in line */
	len = ustr_cspn_chrs_rev(*line, off, whitespace, strlen(whitespace));

	if (len == 0) {
		return STATUS_ERR;
	}

	context_t context = NULL;
	Ustr* new_context_ustr = NULL;

	pos = ustr_len(*line) - (len + off);
	const char *old_context = ustr_cstr(*line) + pos;

	if (strcmp(old_context, CONTEXT_NONE) == 0) {
		retval = STATUS_SUCCESS;
		goto done;
	}

	context = context_new(old_context);

	if (context_user_set(context, user->sename) != 0 ||
	    context_range_set(context, user->level) != 0) {
		goto done;
	}

	if (fixrole && context_role_set(context, user->prefix) != 0) {
		goto done;
	}

	if (!ustr_del_subustr(line, pos + 1, len)) {
		goto done;
	}

	const char *new_context = context_str(context);
	
	if (!new_context) {
		goto done;
	}

	new_context_ustr = ustr_dup_cstr(new_context);
	if (!ustr_add(line, new_context_ustr)) {
		goto done;
	}

	retval = STATUS_SUCCESS;
done:
	ustr_sc_free(&new_context_ustr);
	context_free(context);

	return retval;
}

static int genhomedircon_replace_and_fix_context(struct replacement_pair *repl,
						 const char *line,
						 struct selogin_list *login,
						 int fixrole,
						 Ustr **replacement)
{
	if (genhomedircon_replace(repl, line, replacement) < 0) {
		return STATUS_ERR;
	}

	if (genhomedircon_fix_context(login, replacement, fixrole) < 0) {
		return STATUS_ERR;
	}

	return STATUS_SUCCESS;
}

static int genhomedircon_write_homedir_contexts(
    semanage_handle_t *sh, FILE *out, struct selogin_list *login,
    const char *homedir, semanage_list_t *homedir_ctx_list)
{
	int fixrole = sh->conf->enable_genhomedircon_rbac;

	const char *comment_uname = strcmp(login->name, FALLBACK_NAME) == 0
					? DEFAULT_LOGIN
					: login->name;

	if (!fprintf(out, COMMENT_USER_HOME_CONTEXT, comment_uname)) {
		return STATUS_ERR;
	}

	struct replacement_pair repl[] = {
	    {.search_for = TEMPLATE_ROLE, .replace_with = login->prefix},
	    {.search_for = TEMPLATE_HOME_DIR, .replace_with = homedir},
	    {.search_for = NULL, .replace_with = NULL}};

	for (; homedir_ctx_list; homedir_ctx_list = homedir_ctx_list->next) {
		Ustr *replacement = NULL;

		if (genhomedircon_replace_and_fix_context(
			repl, homedir_ctx_list->data, login, fixrole,
			&replacement) == STATUS_ERR) {
			return STATUS_ERR;
		}

		if (!ustr_io_putfileline(&replacement, out)) {
			ustr_sc_free(&replacement);
			return STATUS_ERR;
		}

		ustr_sc_free(&replacement);
	}

	return 1;
}

static int genhomedircon_write_user_contexts(semanage_handle_t *sh, FILE *out,
					     struct selogin_list *entry,
					     semanage_list_t *user_ctx_list)
{
	int fixrole = sh->conf->enable_genhomedircon_rbac;

	struct replacement_pair repl[] = {
	    {.search_for = TEMPLATE_USERNAME, .replace_with = entry->name},
	    {.search_for = TEMPLATE_USER, .replace_with = entry->name},
	    {.search_for = TEMPLATE_USERID, .replace_with = entry->uid},
	    {.search_for = TEMPLATE_ROLE, .replace_with = entry->prefix},
	    {.search_for = NULL, .replace_with = NULL}};

	for (; user_ctx_list; user_ctx_list = user_ctx_list->next) {
		Ustr *replacement = NULL;

		if (genhomedircon_replace_and_fix_context(
			repl, user_ctx_list->data, entry, fixrole,
			&replacement) == STATUS_ERR) {
			return -1;
		}

		if (!ustr_io_putfileline(&replacement, out)) {
			ustr_sc_free(&replacement);
			return -1;
		}

		ustr_sc_free(&replacement);
	}

	return 1;
}

semanage_list_t *genhomedircon_read_lines(const char *path,
					  int (*pred)(const char *))
{
	FILE *template_file = NULL;
	semanage_list_t *template_data = NULL;

	template_file = fopen(path, "r");
	if (!template_file)
		return NULL;
	template_data = semanage_slurp_file_filter(template_file, pred);
	fclose(template_file);

	return template_data;
}

int semanage_genhomedircon(semanage_handle_t *sh, sepol_policydb_t *policydb,
			   int usepasswd, char *ignoredirs)
{
	(void) policydb;
	int retval = STATUS_ERR;

	FILE *out = NULL;
	struct selogin_list *login_list = NULL;
	struct selogin_list *default_login = NULL;
	semanage_list_t *ignore_list = NULL;
	semanage_list_t *root_ctx_list = NULL;
	semanage_list_t *user_ctx_list = NULL;
	semanage_list_t *homedir_ctx_list = NULL;

	if (ignoredirs &&
	    genhomedircon_get_ignore_list(&ignore_list, ignoredirs) ==
		STATUS_ERR) {
		ERR(sh, "Error encountered building ignore list");
		goto done;
	}

	semanage_list_t *homedir_list = NULL;

	if (genhomedircon_get_home_dirs(&homedir_list, usepasswd) ==
	    STATUS_ERR) {
		ERR(sh, "Unable to list home directories");
		goto done;
	}

	if (genhomedircon_get_users(sh, &login_list, &default_login) ==
	    STATUS_ERR) {
		ERR(sh, "Could not get seuser login entries");
		goto done;
	}

	if (default_login) {
		default_login->name = FALLBACK_NAME;
		default_login->uid = FALLBACK_UIDGID;
		default_login->gid = FALLBACK_UIDGID;
	} else {
		WARN(sh, "No default seuser login found");
	}

	const char *fc_path =
	    semanage_final_path(SEMANAGE_FINAL_TMP, SEMANAGE_FC_HOMEDIRS);
	out = fopen(fc_path, "w");

	if (!out) {
		ERR(sh, "Could not open the file_context file for writing");
		goto done;
	}

	if (!fprintf(out, COMMENT_FILE_CONTEXT_HEADER)) {
		ERR(sh, "Could not write to file_contexts file");
		goto done;
	}

	const char *homedir_tmpl_path =
	    semanage_path(SEMANAGE_TMP, SEMANAGE_HOMEDIR_TMPL);

	homedir_ctx_list =
	    genhomedircon_read_lines(homedir_tmpl_path, HOMEDIR_PRED);
	user_ctx_list = genhomedircon_read_lines(homedir_tmpl_path, USER_PRED);
	root_ctx_list = genhomedircon_read_lines(homedir_tmpl_path, ROOT_PRED);

	if (default_login &&
	    genhomedircon_write_user_contexts(sh, out, default_login,
					      user_ctx_list) < 0) {
		goto done;
	}

	semanage_list_t *homedir = homedir_list;

	for (; homedir; homedir = homedir->next) {
		if (semanage_list_find(ignore_list, homedir->data)) {
			continue;
		}

		if (genhomedircon_write_root_contexts(out, homedir->data,
						      root_ctx_list) < 0) {
			ERR(sh, "Couldn't write HOMEROOT replacement contexts");
			goto done;
		}

		if (!default_login) {
			continue;
		}

		Ustr *fallback_homedir = ustr_dup_cstr(homedir->data);
		if (!fallback_homedir ||
		    !ustr_add_cstr(&fallback_homedir, "/" FALLBACK_NAME)) {
			ustr_sc_free(&fallback_homedir);
			goto done;
		}

		if (genhomedircon_write_homedir_contexts(
			sh, out, default_login, ustr_cstr(fallback_homedir),
			homedir_ctx_list) < 0) {
			ustr_sc_free(&fallback_homedir);
			goto done;
		}

		ustr_sc_free(&fallback_homedir);
	}

	struct selogin_list *seuser = login_list;
	for (; seuser; seuser = seuser->next) {
		if (semanage_list_find(ignore_list, seuser->homedir)) {
			continue;
		}

		if (genhomedircon_write_user_contexts(sh, out, seuser,
						      user_ctx_list) < 0) {
			ERR(sh, "Couldn't write user contexts for %s",
			    seuser->name);
			goto done;
		}

		if (genhomedircon_write_homedir_contexts(
			sh, out, seuser, seuser->homedir, homedir_ctx_list) < 0) {
			ERR(sh, "Couldn't write homedir contexts for %s",
			    seuser->name);
			goto done;
		}
	}

	retval = STATUS_SUCCESS;
done:
	if (out != NULL) {
		fclose(out);
	}

	if (default_login) {
		// hack to prevent the FALLBACK_NAME and FALLBACK_UIDGID
		// constants from being passed to free()
		default_login->name = NULL;
		default_login->uid = NULL;
		default_login->gid = NULL;
		genhomedircon_user_free(default_login);
	}

	while (login_list) {
		login_list = genhomedircon_user_free(login_list);
	}

	semanage_list_destroy(&homedir_list);
	semanage_list_destroy(&ignore_list);
	semanage_list_destroy(&root_ctx_list);
	semanage_list_destroy(&user_ctx_list);
	semanage_list_destroy(&homedir_ctx_list);

	return retval;
}
