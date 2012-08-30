/*
 * ProFTPD: mod_rename -- a module for automatically renaming uploaded files
 *
 * Copyright (c) 2001-2006 TJ Saunders
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307, USA.
 *
 * As a special exemption, TJ Saunders gives permission to link this program
 * with OpenSSL, and distribute the resulting executable, without including
 * the source code for OpenSSL in the source distribution.
 *
 * This is mod_rename, contrib software for proftpd 1.2.2 and above.
 * For more information contact TJ Saunders <tj@castaglia.org>.
 *
 * $Id: mod_rename.c,v 1.31 2006/05/05 02:39:24 tj Exp tj $
 */

#include "conf.h"
#include "privs.h"

#define MOD_RENAME_VERSION "mod_rename/0.17"

/* Make sure the version of proftpd is as necessary. */
#if PROFTPD_VERSION_NUMBER < 0x0001021001
# error "ProFTPD 1.2.10rc1 or later required"
#endif

#ifdef HAVE_REGEX_H
#include <regex.h>
#endif

module rename_module;

/* for logging */
static char *rename_logfile = NULL;
static int rename_logfd = -1;

/* Module variables */
static unsigned char rename_engine = FALSE;

/* Necessary prototypes
 */
static int rename_alphasort(const void *, const void *);
static void rename_closelog(void);
static unsigned char rename_isdup(char *, char *, char *);
static int rename_openlog(void);
static int rename_scandir(const char *, struct dirent ***,
  int (*)(const struct dirent *), int (*)(const void *, const void *));

/* Support functions
 */

static int rename_alphasort(const void *a, const void *b) {
  const struct dirent **denta = (const struct dirent **) a;
  const struct dirent **dentb = (const struct dirent **) b;

  return strcmp((*denta)->d_name, (*dentb)->d_name);
}

static const char *rename_fixup_path(pool *tmp_pool, const char *dir,
    const char *file, char *prefix, char *suffix) {
  const char *rename_path = NULL;

  /* Handle ~s in the prefix/suffix strings */
  if (prefix &&
      strchr(prefix, '~')) {
    char *tmp = prefix;
    (void) pr_log_writefile(rename_logfd, MOD_RENAME_VERSION,
      "[fixup] replacing ~ in RenamePrefix with '%s'", session.user);
    prefix = sreplace(tmp_pool, tmp, "~", session.user, NULL);
  }

  if (suffix &&
      strchr(suffix, '~')) {
    char *tmp = suffix;
    (void) pr_log_writefile(rename_logfd, MOD_RENAME_VERSION,
      "[fixup] replacing ~ in RenameSuffix with '%s'", session.user);
    suffix = sreplace(tmp_pool, tmp, "~", session.user, NULL);
  }

  if (prefix || suffix) {
    unsigned char prefix_hasnumtok =
      ((prefix && strchr(prefix, '#')) ? TRUE : FALSE);
    unsigned char suffix_hasnumtok =
      ((suffix && strchr(suffix, '#')) ? TRUE : FALSE);

    /* Do we have any magic # tokens to process? */
    if (prefix_hasnumtok || suffix_hasnumtok) {
      struct stat st;
      register unsigned int i = 0;
      char prefixbuf[80] = {'\0'}, suffixbuf[80] = {'\0'};
      char *tmp_path = NULL, *tmp_prefix = NULL, *tmp_suffix = NULL;

      /* If the file does not already exist as is, we don't need to
       * use the prefix/suffix.
       */
      tmp_path = pdircat(tmp_pool, dir, file, NULL);
      if (pr_fsio_lstat(tmp_path, &st) != 0) {
        rename_path = tmp_path;
        (void) pr_log_writefile(rename_logfd, MOD_RENAME_VERSION,
          "[fixup]: no need for prefix/suffix, using '%s'", rename_path);
        return rename_path;
      }

      (void) pr_log_writefile(rename_logfd, MOD_RENAME_VERSION,
        "[fixup] checking for usable number token");

      /* Yuck.  Popular among users, but...yuck. */
      for (i = 1; i < UINT_MAX; i++) {
        if (prefix_hasnumtok) {
          memset(prefixbuf, '\0', sizeof(prefixbuf));
          sprintf(prefixbuf, "%u", i);
          tmp_prefix = sreplace(tmp_pool, prefix, "#", prefixbuf, NULL);

        } else
          tmp_prefix = prefix;

        if (suffix_hasnumtok) {
          memset(suffixbuf, '\0', sizeof(suffixbuf));
          sprintf(suffixbuf, "%u", i);
          tmp_suffix = sreplace(tmp_pool, suffix, "#", suffixbuf, NULL);

        } else
          tmp_suffix = suffix;

        if (prefix && suffix)
          tmp_path = pstrcat(tmp_pool, dir, "/", tmp_prefix, file, tmp_suffix,
            NULL);
 
        else if (prefix && !suffix)
          tmp_path = pstrcat(tmp_pool, dir, "/", tmp_prefix, file, NULL);

        else if (!prefix && suffix)
          tmp_path = pstrcat(tmp_pool, dir, "/", file, tmp_suffix, NULL);

        /* Path exists...continue looking */
        (void) pr_log_writefile(rename_logfd, MOD_RENAME_VERSION,
          "[fixup] checking existence of rename path '%s'", tmp_path);

        pr_fs_clear_cache();
        if (pr_fsio_lstat(tmp_path, &st) == 0)
          continue;

        /* Path does not exist -- done looking */
        if (errno == ENOENT) {
          (void) pr_log_writefile(rename_logfd, MOD_RENAME_VERSION,
            "[fixup] final path: '%s'", tmp_path);
          return tmp_path;

        } else {

          (void) pr_log_writefile(rename_logfd, MOD_RENAME_VERSION,
            "error stat'ing '%s': %s", tmp_path, strerror(errno));
          rename_path = file;
          (void) pr_log_writefile(rename_logfd, MOD_RENAME_VERSION,
            "[fixup] final path: '%s'", rename_path);
          return rename_path;
        }
      }

      /* End of for loop reached (UINT_MAX) with no luck.  Bummer. */
      (void) pr_log_writefile(rename_logfd, MOD_RENAME_VERSION,
        "error: exhausted number token space");
      rename_path = file;

    } else {

      /* Simply affix the prefix/suffix as is */
      if (prefix &&
          suffix) {
        rename_path = pstrcat(tmp_pool, dir, "/", prefix, file, suffix, NULL);

      } else if (prefix &&
                 !suffix) {
        rename_path = pstrcat(tmp_pool, dir, "/", prefix, file, NULL);

      } else if (!prefix &&
                 suffix) {
        rename_path = pstrcat(tmp_pool, dir, "/", file, suffix, NULL);
      }
    }

  } else
    rename_path = pdircat(tmp_pool, dir, file, NULL);

  (void) pr_log_writefile(rename_logfd, MOD_RENAME_VERSION,
    "[fixup] final path: '%s'", rename_path);
  return rename_path;
}

static const char *rename_get_new_path(pool *tmp_pool, char *path,
    char *full_path) {
  config_rec *c = NULL;
  const char *rename_path = NULL;
  char *dir = NULL, *file = NULL, *rename_prefix = NULL, *rename_suffix = NULL,
    *rename_opts = NULL, *tmp = NULL;
  int res;

#if defined(HAVE_REGEX_H) && defined(HAVE_REGCOMP)
  static regex_t *rename_regex = NULL;
  static char *rename_filter = NULL;
#endif

  /* Given the full path, find out the file name. */
  tmp = rindex(full_path, '/');
  if (tmp)
    file = ++tmp;
 
  (void) pr_log_writefile(rename_logfd, MOD_RENAME_VERSION,
    "testing file '%s' for rename eligibility", full_path);

#if defined(HAVE_REGEX_H) && defined(HAVE_REGCOMP)
  c = find_config(CURRENT_CONF, CONF_PARAM, "RenameFilter", FALSE);
  if (c != NULL) {
    rename_filter = (char *) c->argv[1];
    rename_opts = (char *) c->argv[2];
    (void) pr_log_writefile(rename_logfd, MOD_RENAME_VERSION,
      "using RenameFilter %s", rename_filter);

    /* Test the filter string: is it "none" or "duplicate"? */
    if (strcmp(rename_filter, "none") == 0) {
      (void) pr_log_writefile(rename_logfd, MOD_RENAME_VERSION,
        "RenameFilter none: all files are eligible for renaming");

    } else if (strcmp(rename_filter, "duplicate") == 0) {

      if (!rename_isdup(full_path, path, rename_opts)) {
        (void) pr_log_writefile(rename_logfd, MOD_RENAME_VERSION,
          "RenameFilter duplicate: path '%s' is not a duplicate",
          session.chroot_path ? path : full_path);
        (void) pr_log_writefile(rename_logfd, MOD_RENAME_VERSION,
          "RenameFilter duplicate: not renaming file");
        return NULL;

      } else {
        (void) pr_log_writefile(rename_logfd, MOD_RENAME_VERSION,
          "RenameFilter duplicate: path '%s' is a duplicate",
          session.chroot_path ? path : full_path);
        (void) pr_log_writefile(rename_logfd, MOD_RENAME_VERSION,
          "RenameFilter duplicate: renaming file");
      }

    } else {
      rename_regex = (regex_t *) c->argv[0];

      /* Do not rename the file if it does not match the filter.  Use only
       * the file name (file), not the full path (path), for the
       * regex comparison.
       */
      if (rename_regex && file) {
        res = regexec(rename_regex, file, 0, NULL, 0);
        if (res != 0) {
          (void) pr_log_writefile(rename_logfd, MOD_RENAME_VERSION,
            "RenameFilter %s: filename '%s' does not match",
            rename_filter, file);
          (void) pr_log_writefile(rename_logfd, MOD_RENAME_VERSION,
            "RenameFilter %s: not renaming file", rename_filter);
          return NULL;

        } else {
          (void) pr_log_writefile(rename_logfd, MOD_RENAME_VERSION,
            "RenameFilter %s: file '%s' matches",
            rename_filter, file);
          (void) pr_log_writefile(rename_logfd, MOD_RENAME_VERSION,
            "RenameFilter %s: renaming file", rename_filter);
        }
      }
    }

  } else
     (void) pr_log_writefile(rename_logfd, MOD_RENAME_VERSION,
       "no RenameFilter set: all files are eligible for renaming");
#endif

  c = find_config(CURRENT_CONF, CONF_PARAM, "RenameTarget", FALSE);
  if (c != NULL) {

    if (strcmp(c->argv[0], "user") == 0) {
      if (pr_expr_eval_user_or((char **) &c->argv[1]))
        (void) pr_log_writefile(rename_logfd, MOD_RENAME_VERSION,
          "current user '%s' matches RenameTarget", session.user);

      else {
        (void) pr_log_writefile(rename_logfd, MOD_RENAME_VERSION,
          "current user '%s' does not match RenameTarget", session.user);
        return NULL;
      }

    } else if (strcmp(c->argv[0], "group") == 0) {
      if (pr_expr_eval_group_and((char **) &c->argv[1]))
        (void) pr_log_writefile(rename_logfd, MOD_RENAME_VERSION,
          "current group(s) match RenameTarget");

      else {
        (void) pr_log_writefile(rename_logfd, MOD_RENAME_VERSION, 
          "current group(s) do not match RenameTarget");
        return NULL; 
      }

    } else if (strcmp(c->argv[0], "class") == 0) {
      if (pr_expr_eval_class_or((char **) &c->argv[1]))
        (void) pr_log_writefile(rename_logfd, MOD_RENAME_VERSION,
          "current class '%s' matches RenameTarget", session.class->cls_name);

      else {
        (void) pr_log_writefile(rename_logfd, MOD_RENAME_VERSION,
          "current class '%s' does not match RenameTarget",
          session.class->cls_name);
        return NULL;
      }
    }
  }

  rename_prefix = get_param_ptr(CURRENT_CONF, "RenamePrefix", FALSE);
  if (rename_prefix)
    (void) pr_log_writefile(rename_logfd, MOD_RENAME_VERSION,
      "using RenamePrefix '%s'", rename_prefix);

  rename_suffix = get_param_ptr(CURRENT_CONF, "RenameSuffix", FALSE);
  if (rename_suffix)
    (void) pr_log_writefile(rename_logfd, MOD_RENAME_VERSION,
      "using RenameSuffix '%s'", rename_suffix);

  /* Build the filename to which the file is to be renamed.  This function
   * handles all the special characters in prefix/suffix strings.
   */

  if (session.chroot_path) {
    dir = path;

  } else {
    dir = full_path;
  }

  tmp = rindex(dir, '/');
  if (tmp) {
    *tmp = '\0';

  } else {
    dir = (char *) pr_fs_getvwd();
    (void) pr_log_writefile(rename_logfd, MOD_RENAME_VERSION,
      "assuming '%s' is in directory '%s'", path, dir);
  }

  rename_path = rename_fixup_path(tmp_pool, dir, file, rename_prefix,
    rename_suffix);

  if (tmp)
    *tmp = '/';

  return rename_path;
}

/* For use by rename_isdup() */
static char *rename_dup_file = NULL;
static unsigned char rename_dup_ignorecase = FALSE;

static int rename_dup_scan(const struct dirent *d) {
  if (strcmp(d->d_name, ".") != 0 &&
      strcmp(d->d_name, "..") != 0) {
     if (rename_dup_ignorecase &&
         strcasecmp(d->d_name, rename_dup_file) == 0) {
       (void) pr_log_writefile(rename_logfd, MOD_RENAME_VERSION,
         "[dup scan] '%s' matches '%s'", d->d_name, rename_dup_file);
       return 1;
     }

     if (!rename_dup_ignorecase &&
         strcmp(d->d_name, rename_dup_file) == 0)
       return 1;
  }

  return 0;
}

static unsigned char rename_isdup(char *full_path, char *rel_path, char *opts) {
  char *tmp = NULL;
  char *dir = session.chroot_path ? rel_path : full_path;
  struct dirent **matches = NULL;
  int nmatches = 0;

  if (opts && strcmp(opts, "IgnoreCase") == 0)
    rename_dup_ignorecase = TRUE;
  else
    rename_dup_ignorecase = FALSE;

  /* Split the path to be used into directory and file components. */
  tmp = strrchr(dir, '/');
  if (tmp == NULL) {
    rename_dup_file = dir;
    dir = ".";

  } else {
    *tmp = '\0';
    rename_dup_file = tmp + 1;
  }

  nmatches = rename_scandir(dir, &matches, rename_dup_scan, rename_alphasort);
  if (nmatches <= 0) {
    if (nmatches < 0 &&
        errno != 0) {
      (void) pr_log_writefile(rename_logfd, MOD_RENAME_VERSION,
        "[dup check] error while scanning of '%s': %s", dir,
        strerror(errno));
    }

    if (tmp)
      *tmp = '/';

    return FALSE;

  } else {

    /* We don't really care about the matches found, just that matches _were_
     * found.
     */
    while (nmatches--)
      free((void *) matches[nmatches]);
    free((void *) matches);

    if (tmp)
      *tmp = '/';

    return TRUE;
  }

  return FALSE;
}

static int rename_openlog(void) {
  int res = 0;

  /* Sanity checks */
  if (rename_logfile)
    return 0;

  rename_logfile = get_param_ptr(main_server->conf, "RenameLog", FALSE);
  if (rename_logfile == NULL)
    return 0;

  if (strcasecmp(rename_logfile, "none") != 0) {
    rename_logfile = NULL;
    return 0;
  }

  pr_signals_block();
  PRIVS_ROOT
  res = pr_log_openfile(rename_logfile, &rename_logfd, 0640);
  PRIVS_RELINQUISH
  pr_signals_unblock();

  return res;
}

static void rename_closelog(void) {

  /* sanity check */
  if (rename_logfd < 0)
    return;

  if (close(rename_logfd) < 0) {
    pr_log_pri(PR_LOG_ERR, MOD_RENAME_VERSION
      ": error closing RenameLog '%s': %s", rename_logfile, strerror(errno));
    return;
  }

  rename_logfile = NULL;
  rename_logfd = -1;

  return;
}

/* Note: this implementation of scandir(3) is made necessary because of
 * Solaris, which decided to provide the code for this function, and
 * for alphasort(3), only in their Berkeley compatibility libraries.  And,
 * even better, Solaris does _not_ support binaries that link against
 * both the Solaris standard libraries and the Berkeley compatibility
 * libraries.  So, to avoid all that, this module will use an internal
 * implementation of alphasort() and scandir() on all platforms.  Yay
 * portability. =P
 *
 * This code take from:
 *
 *  http://archives.seul.org/gdis/gdiscuss/Apr-2001/msg00002.html
 *
 * as graciously suggested by Kirk Baucom.
 */

static int rename_scandir(const char *dir, struct dirent ***namelist,
    int (*select)(const struct dirent *),
    int (*compar)(const void *, const void *)) {

  DIR *d = NULL;
  struct dirent *dent = NULL;
  register int i = 0;
  size_t dentlen;

  if ((d = opendir(dir)) == NULL)
     return -1;

  *namelist = NULL;

  /* Note: this loop's use of malloc(3) and realloc(3) is deemed acceptable,
   * in light of proftpd's use of memory pools, in order to preserve full
   * compatibility (and expectations) of use with the corresponding "normal"
   * scandir(3) function.
   */
  while ((dent = readdir(d)) != NULL) {
    if (select == NULL || (select != NULL && (*select)(dent))) {
      if ((*namelist = (struct dirent **) realloc((void *) (*namelist),
          ((i+1) * sizeof(struct dirent *)))) == NULL)
        return -1;

      dentlen = sizeof(struct dirent) -
        sizeof(dent->d_name) + strlen(dent->d_name) + 1;

      if (((*namelist)[i] = (struct dirent *) malloc(dentlen)) == NULL)
        return -1;

      memcpy((*namelist)[i], dent, dentlen);
      i++;
    }
  }

  if (closedir(d))
    return -1;

  if (i == 0)
    return -1;

  if (compar != NULL)
    qsort((void *) (*namelist), i, sizeof(struct dirent *), compar);
    
  return i;
}

/* Configuration directive handlers
 */

MODRET set_renameengine(cmd_rec *cmd) {
  int bool = 0;
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  bool = get_boolean(cmd, 1);
  if (bool == -1)
    CONF_ERROR(cmd, "expecting boolean argument");

  /* Check for duplicates */
  if (get_param_ptr(cmd->server->conf, cmd->argv[0], FALSE) != NULL)
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, cmd->argv[0], ": multiple "     
     "instances not allowed for same server", NULL));

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(unsigned char));
  *((unsigned char *) c->argv[0]) = bool;

  return HANDLED(cmd);
}

MODRET set_renamefilter(cmd_rec *cmd) {
#if defined(HAVE_REGEX_H) && defined(HAVE_REGCOMP)
  config_rec *c = NULL;
  regex_t *preg = NULL;
  int reg_cflags = REG_EXTENDED|REG_NOSUB;
  int res;

  if (cmd->argc-1 < 1 || cmd->argc-1 > 2)
    CONF_ERROR(cmd, "wrong number of parameters");
  CHECK_CONF(cmd, CONF_DIR|CONF_DYNDIR);

  preg = pr_regexp_alloc();

  if (strcmp(cmd->argv[1], "duplicate") != 0&&
      strcmp(cmd->argv[1], "none") != 0) {
   
    if (cmd->argc-1 == 2 && !strcmp(cmd->argv[2], "IgnoreCase"))
      reg_cflags |= REG_ICASE;
 
    if ((res = regcomp(preg, cmd->argv[1], reg_cflags)) != 0) {
      char errstr[200] = {'\0'};

      regerror(res, preg, errstr, sizeof(errstr));
      pr_regexp_free(preg);

      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "unable to compile '",
        cmd->argv[1], "' regex: ", errstr, NULL));
    }
  }

  c = add_config_param(cmd->argv[0], 3, NULL, NULL, NULL);
  c->argv[0] = (void *) preg;
  c->argv[1] = pstrdup(c->pool, cmd->argv[1]);

  if (cmd->argc-1 == 2)
    c->argv[2] = pstrdup(c->pool, cmd->argv[2]);

  c->flags |= CF_MERGEDOWN;
  return HANDLED(cmd);
#else /* no regex support */
  CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "The ", cmd->argv[0], " directive "
    "cannot be used on this system, as you do not have POSIX-compliant "
    "regex support.", NULL));
#endif
}

MODRET set_renamelog(cmd_rec *cmd) {
  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  /* Check for non-absolute paths */
  if (strcasecmp(cmd->argv[1], "none") != 0 && *(cmd->argv[1]) != '/')
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, cmd->argv[0], ": absolute path "
      "required", NULL));

  add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);

  return HANDLED(cmd);
}

MODRET set_renameprefix(cmd_rec *cmd) {
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_DIR|CONF_DYNDIR);

  if (strcmp(cmd->argv[1], "none") != 0)
    c = add_config_param_str(cmd->argv[0], 1, (void *) cmd->argv[1]);
  else
    c = add_config_param(cmd->argv[0], 1, NULL);

  c->flags |= CF_MERGEDOWN;
  return HANDLED(cmd);
}

MODRET set_renamesuffix(cmd_rec *cmd) {
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_DIR|CONF_DYNDIR);

  if (strcmp(cmd->argv[1], "none") != 0)
    c = add_config_param_str(cmd->argv[0], 1, (void *) cmd->argv[1]);
  else
    c = add_config_param(cmd->argv[1], 1, NULL);

  c->flags |= CF_MERGEDOWN;
  return HANDLED(cmd);
}

MODRET set_renametarget(cmd_rec *cmd) {
  config_rec *c = NULL;
  array_header *acl = NULL;
  int argc = cmd->argc - 2;
  char **argv = cmd->argv + 1;

  CHECK_ARGS(cmd, 2);
  CHECK_CONF(cmd, CONF_DIR|CONF_DYNDIR);

  if (strcmp(cmd->argv[1], "user") != 0 &&
      strcmp(cmd->argv[1], "group") != 0 &&
      strcmp(cmd->argv[1], "class") != 0)
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, ": unknown classifier used: '",
      cmd->argv[1], "'", NULL));

  acl = pr_parse_expression(cmd->tmp_pool, &argc, argv);

  c = add_config_param(cmd->argv[0], 0);
  c->argc = argc + 2;

  /* Add 2 to argc for the argv of the config_rec: one for the classifier,
   * and one for the terminating NULL
   */
  c->argv = pcalloc(c->pool, ((argc + 3) * sizeof(char *)));

  /* Capture the config_rec's argv pointer for doing the by-hand population
   */
  argv = (char **) c->argv;

  /* Copy in the classifier */
  *argv++ = pstrdup(c->pool, cmd->argv[1]);

  /* Now, copy in the expression arguments */
  if (argc && acl) {
    while (argc--) {
      *argv++ = pstrdup(c->pool, *((char **) acl->elts));
      acl->elts = ((char **) acl->elts) + 1;
    }
  }

  /* Don't forget the terminating NULL */
  *argv = NULL;

  c->flags |= CF_MERGEDOWN;
  return HANDLED(cmd);
}

/* Command handlers
 */

MODRET rename_pre_stor(cmd_rec *cmd) {
  const char *rename_path = NULL;
  char *full_path = NULL;
  config_rec *prev_dir_config = session.dir_config;

  /* Is RenameEngine on? */
  if (!rename_engine)
    return DECLINED(cmd);

  full_path = dir_abs_path(cmd->tmp_pool, cmd->arg, FALSE);

  /* Make sure the appropriate dir_config is set for this path */
  session.dir_config = dir_match_path(cmd->tmp_pool, full_path);

  /* Determine what filename _should have been used_ for the file being
   * uploaded, and adjust the STOR command behind the client's back
   */
  rename_path = rename_get_new_path(cmd->tmp_pool, cmd->arg, full_path);
  if (rename_path) {

    /* Is the renamed path different from the original?  It's possible that
     * they are the same (as when no RenamePrefix or RenameSuffix are used).
     */
    if (strcmp(rename_path, full_path) != 0) {
      (void) pr_log_writefile(rename_logfd, MOD_RENAME_VERSION,
        "renamed original path '%s' to '%s%s'%s", full_path,
        *rename_path != '/' ? "/" : "", rename_path,
        session.chroot_path ? " (DefaultRoot in effect)" : "");
      cmd->arg = pstrdup(cmd->pool, rename_path);

    } else {
      (void) pr_log_writefile(rename_logfd, MOD_RENAME_VERSION,
        "no renaming of path '%s'", full_path);
    }

  } else {
    (void) pr_log_writefile(rename_logfd, MOD_RENAME_VERSION,
      "no renaming of path '%s'", full_path);
  }

  session.dir_config = prev_dir_config;
  return DECLINED(cmd);
}

/* Event handlers
 */

static void rename_exit_ev(const void *event_data, void *user_data) {
  rename_closelog();
}

/* Initialization functions
 */

static int rename_sess_init(void) {
  unsigned char *tmp = NULL;

  /* Is RenameEngine on? */
  tmp = get_param_ptr(main_server->conf, "RenameEngine", FALSE);
  if (tmp != NULL &&
      *tmp == TRUE) {
    rename_engine = TRUE;

  } else {
    rename_engine = FALSE;
    return 0;
  }

  /* Open the RenameLog, if present */
  rename_openlog();

  /* Register an exit handler to close the RenameLog */
  pr_event_register(&rename_module, "core.exit", rename_exit_ev, NULL);

  return 0;
}

/* Module API Tables
 */

static conftable rename_conftab[] = {
  { "RenameEngine",	set_renameengine,	NULL },
  { "RenameFilter",	set_renamefilter,	NULL },
  { "RenameLog",	set_renamelog,		NULL },
  { "RenamePrefix",	set_renameprefix,	NULL },
  { "RenameSuffix",	set_renamesuffix,	NULL },
  { "RenameTarget",	set_renametarget,	NULL },
  { NULL }
};

static cmdtable rename_cmdtab[] = {
  { PRE_CMD, C_STOR, G_NONE, rename_pre_stor, FALSE, FALSE },
  { 0, NULL }
};

module rename_module = {

  /* Always NULL */
  NULL, NULL,

  /* Module API version 2.0 */
  0x20,

  /* Module name */
  "rename",

  /* Module configuration handler table */
  rename_conftab,

  /* Module command handler table */
  rename_cmdtab,

  /* Module authentication handler table */
  NULL,

  /* Module initialization function */
  NULL,

  /* Session initialization function */
  rename_sess_init,

  /* Module version */
  MOD_RENAME_VERSION
};
