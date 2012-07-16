// PAM module for two-factor authentication.
//
// Copyright 2010 Google Inc.
// Author: Markus Gutschke
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#define _GNU_SOURCE
#include <fcntl.h>
#include <limits.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#ifdef linux
// We much rather prefer to use setfsuid(), but this function is unfortunately
// not available on all systems.
#include <sys/fsuid.h>
#define HAS_SETFSUID
#endif

#ifndef PAM_EXTERN
#define PAM_EXTERN
#endif

#if !defined(LOG_AUTHPRIV) && defined(LOG_AUTH)
#define LOG_AUTHPRIV LOG_AUTH
#endif

#define PAM_SM_AUTH
#define PAM_SM_SESSION
#include <security/pam_appl.h>
#include <security/pam_modules.h>

#include "base32.h"
#include "hmac.h"
#include "sha1.h"

#include "libgoogleauthenticator.h"

#define MODULE_NAME "pam_google_authenticator"

typedef void (*log_wrapper)(pam_handle_t *pamh);

static void log_message(int priority, pam_handle_t *pamh, const char *format, va_list args);

logger pam_logger_wrapper(pam_handle_t *pamh) {
    int pam_logger(int level, char *format, ...) {
        va_list args;
        va_start(args, format);

        log_message(level, pamh, format, args);

        va_end(args);

        return 0;
    }

    return &pam_logger;
}

#if defined(DEMO) || defined(TESTING)
static char error_msg[128];

const char *get_error_msg(void) __attribute__((visibility("default")));
const char *get_error_msg(void) {
  return error_msg;
}
#endif

static void log_message(int priority, pam_handle_t *pamh,
                        const char *format, va_list args) {
  char *service = NULL;
  if (pamh)
    pam_get_item(pamh, PAM_SERVICE, (void *)&service);
  if (!service)
    service = "";

  char logname[80];
  snprintf(logname, sizeof(logname), "%s(" MODULE_NAME ")", service);

#if !defined(DEMO) && !defined(TESTING)
  openlog(logname, LOG_CONS | LOG_PID, LOG_AUTHPRIV);
  vsyslog(priority, format, args);
  closelog();
#else
  if (!*error_msg) {
    vsnprintf(error_msg, sizeof(error_msg), format, args);
  }
#endif

  if (priority == LOG_EMERG) {
    // Something really bad happened. There is no way we can proceed safely.
    _exit(1);
  }
}

static int converse(pam_handle_t *pamh, int nargs,
                    const struct pam_message **message,
                    struct pam_response **response) {
  struct pam_conv *conv;
  int retval = pam_get_item(pamh, PAM_CONV, (void *)&conv);
  if (retval != PAM_SUCCESS) {
    return retval;
  }
  return conv->conv(nargs, message, response, conv->appdata_ptr);
}

static const char *get_user_name(logger *log, pam_handle_t *pamh) {
  // Obtain the user's name
  const char *username;
  if (pam_get_item(pamh, PAM_USER, (void *)&username) != PAM_SUCCESS ||
      !username || !*username) {
    (*log)(LOG_ERR, "No user name available when checking verification code");
    return NULL;
  }
  return username;
}

static int setuser(int uid) {
#ifdef HAS_SETFSUID
  // The semantics for setfsuid() are a little unusual. On success, the
  // previous user id is returned. On failure, the current user id is returned.
  int old_uid = setfsuid(uid);
  if (uid != setfsuid(uid)) {
    setfsuid(old_uid);
    return -1;
  }
#else
  int old_uid = geteuid();
  if (old_uid != uid && seteuid(uid)) {
    return -1;
  }
#endif
  return old_uid;
}

static int setgroup(int gid) {
#ifdef HAS_SETFSUID
  // The semantics of setfsgid() are a little unusual. On success, the
  // previous group id is returned. On failure, the current groupd id is
  // returned.
  int old_gid = setfsgid(gid);
  if (gid != setfsgid(gid)) {
    setfsgid(old_gid);
    return -1;
  }
#else
  int old_gid = getegid();
  if (old_gid != gid && setegid(gid)) {
    return -1;
  }
#endif
  return old_gid;
}

static int drop_privileges(logger *log, const char *username, int uid,
                           int *old_uid, int *old_gid) {
  // Try to become the new user. This might be necessary for NFS mounted home
  // directories.

  // First, look up the user's default group
  #ifdef _SC_GETPW_R_SIZE_MAX
  int len = sysconf(_SC_GETPW_R_SIZE_MAX);
  if (len <= 0) {
    len = 4096;
  }
  #else
  int len = 4096;
  #endif
  char *buf = malloc(len);
  if (!buf) {
    (*log)(LOG_ERR, "Out of memory");
    return -1;
  }
  struct passwd pwbuf, *pw;
  if (getpwuid_r(uid, &pwbuf, buf, len, &pw) || !pw) {
    (*log)(LOG_ERR, "Cannot look up user id %d", uid);
    free(buf);
    return -1;
  }
  gid_t gid = pw->pw_gid;
  free(buf);

  int gid_o = setgroup(gid);
  int uid_o = setuser(uid);
  if (uid_o < 0) {
    if (gid_o >= 0) {
      if (setgroup(gid_o) < 0 || setgroup(gid_o) != gid_o) {
        // Inform the caller that we were unsuccessful in resetting the group.
        *old_gid = gid_o;
      }
    }
    (*log)(LOG_ERR, "Failed to change user id to \"%s\"",
                username);
    return -1;
  }
  if (gid_o < 0 && (gid_o = setgroup(gid)) < 0) {
    // In most typical use cases, the PAM module will end up being called
    // while uid=0. This allows the module to change to an arbitrary group
    // prior to changing the uid. But there are many ways that PAM modules
    // can be invoked and in some scenarios this might not work. So, we also
    // try changing the group _after_ changing the uid. It might just work.
    if (setuser(uid_o) < 0 || setuser(uid_o) != uid_o) {
      // Inform the caller that we were unsuccessful in resetting the uid.
      *old_uid = uid_o;
    }
    (*log)(LOG_ERR, "Failed to change group id for user \"%s\" to %d", username,
                (int)gid);
    return -1;
  }

  *old_uid = uid_o;
  *old_gid = gid_o;
  return 0;
}

static char *get_first_pass(pam_handle_t *pamh) {
  const void *password = NULL;
  if (pam_get_item(pamh, PAM_AUTHTOK, &password) == PAM_SUCCESS &&
      password) {
    return strdup((const char *)password);
  }
  return NULL;
}

static char *request_pass(pam_handle_t *pamh, logger *log, int echocode,
                          const char *prompt) {
  // Query user for verification code
  const struct pam_message msg = { .msg_style = echocode,
                                   .msg       = prompt };
  const struct pam_message *msgs = &msg;
  struct pam_response *resp = NULL;
  int retval = converse(pamh, 1, &msgs, &resp);
  char *ret = NULL;
  if (retval != PAM_SUCCESS || resp == NULL || resp->resp == NULL ||
      *resp->resp == '\000') {
    (*log)(LOG_ERR, "Did not receive verification code from user");
  } else {
    ret = resp->resp;
  }

  // Deallocate temporary storage
  if (resp) {
    if (!ret) {
      free(resp->resp);
    }
    free(resp);
  }

  return ret;
}

static int parse_user(logger *log, const char *name, uid_t *uid) {
  char *endptr;
  errno = 0;
  long l = strtol(name, &endptr, 10);
  if (!errno && endptr != name && l >= 0 && l <= INT_MAX) {
    *uid = (uid_t)l;
    return 0;
  }
  #ifdef _SC_GETPW_R_SIZE_MAX
  int len   = sysconf(_SC_GETPW_R_SIZE_MAX);
  if (len <= 0) {
    len = 4096;
  }
  #else
  int len   = 4096;
  #endif
  char *buf = malloc(len);
  if (!buf) {
    (*log)(LOG_ERR, "Out of memory");
    return -1;
  }
  struct passwd pwbuf, *pw;
  if (getpwnam_r(name, &pwbuf, buf, len, &pw) || !pw) {
    free(buf);
    (*log)(LOG_ERR, "Failed to look up user \"%s\"", name);
    return -1;
  }
  *uid = pw->pw_uid;
  free(buf);
  return 0;
}

static int parse_args(logger *log, int argc, const char **argv,
                      Params *params) {
  params->echocode = PAM_PROMPT_ECHO_OFF;
  for (int i = 0; i < argc; ++i) {
    if (!memcmp(argv[i], "secret=", 7)) {
      free((void *)params->secret_filename_spec);
      params->secret_filename_spec = argv[i] + 7;
    } else if (!memcmp(argv[i], "user=", 5)) {
      uid_t uid;
      if (parse_user(log, argv[i] + 5, &uid) < 0) {
        return -1;
      }
      params->fixed_uid = 1;
      params->uid = uid;
    } else if (!strcmp(argv[i], "try_first_pass")) {
      params->pass_mode = TRY_FIRST_PASS;
    } else if (!strcmp(argv[i], "use_first_pass")) {
      params->pass_mode = USE_FIRST_PASS;
    } else if (!strcmp(argv[i], "forward_pass")) {
      params->forward_pass = 1;
    } else if (!strcmp(argv[i], "noskewadj")) {
      params->noskewadj = 1;
    } else if (!strcmp(argv[i], "nullok")) {
      params->nullok = NULLOK;
    } else if (!strcmp(argv[i], "echo-verification-code") ||
               !strcmp(argv[i], "echo_verification_code")) {
      params->echocode = PAM_PROMPT_ECHO_ON;
    } else {
      (*log)(LOG_ERR, "Unrecognized option \"%s\"", argv[i]);
      return -1;
    }
  }
  return 0;
}

static int google_authenticator(pam_handle_t *pamh, int flags,
                                int argc, const char **argv) {
  int        rc = PAM_SESSION_ERR;
  const char *username;
  char       *secret_filename = NULL;
  int        uid = -1, old_uid = -1, old_gid = -1, fd = -1;
  off_t      filesize = 0;
  time_t     mtime = 0;
  char       *buf = NULL;
  uint8_t    *secret = NULL;
  int        secretLen = 0;

  logger pam_logger = pam_logger_wrapper(pamh);

#if defined(DEMO) || defined(TESTING)
  *error_msg = '\000';
#endif

  // Handle optional arguments that configure our PAM module
  Params params = { 0 };
  if (parse_args(&pam_logger, argc, argv, &params) < 0) {
    return rc;
  }

  // Read and process status file, then ask the user for the verification code.
  int early_updated = 0, updated = 0;
  if ((username = get_user_name(&pam_logger, pamh)) &&
      (secret_filename = get_secret_filename(&pam_logger, username, &uid)) &&
      !drop_privileges(&pam_logger, username, uid, &old_uid, &old_gid) &&
      (fd = open_secret_file(&pam_logger, secret_filename, &params, username, uid,
                             &filesize, &mtime)) >= 0 &&
      (buf = read_file_contents(&pam_logger, secret_filename, &fd, filesize)) &&
      (secret = get_shared_secret(&pam_logger, secret_filename, buf, &secretLen)) &&
       rate_limit(&pam_logger, secret_filename, &early_updated, &buf) >= 0) {
    long hotp_counter = get_hotp_counter(&pam_logger, buf);
    int must_advance_counter = 0;
    char *pw = NULL, *saved_pw = NULL;
    for (int mode = 0; mode < 4; ++mode) {
      // In the case of TRY_FIRST_PASS, we don't actually know whether we
      // get the verification code from the system password or from prompting
      // the user. We need to attempt both.
      // This only works correctly, if all failed attempts leave the global
      // state unchanged.
      if (updated || pw) {
        // Oops. There is something wrong with the internal logic of our
        // code. This error should never trigger. The unittest checks for
        // this.
        if (pw) {
          memset(pw, 0, strlen(pw));
          free(pw);
          pw = NULL;
        }
        rc = PAM_SESSION_ERR;
        break;
      }
      switch (mode) {
      case 0: // Extract possible verification code
      case 1: // Extract possible scratch code
        if (params.pass_mode == USE_FIRST_PASS ||
            params.pass_mode == TRY_FIRST_PASS) {
          pw = get_first_pass(pamh);
        }
        break;
      default:
        if (mode != 2 && // Prompt for pw and possible verification code
            mode != 3) { // Prompt for pw and possible scratch code
          rc = PAM_SESSION_ERR;
          continue;
        }
        if (params.pass_mode == PROMPT ||
            params.pass_mode == TRY_FIRST_PASS) {
          if (!saved_pw) {
            // If forwarding the password to the next stacked PAM module,
            // we cannot tell the difference between an eight digit scratch
            // code or a two digit password immediately followed by a six
            // digit verification code. We have to loop and try both
            // options.
            saved_pw = request_pass(pamh, &pam_logger, params.echocode,
                                    params.forward_pass ?
                                    "Password & verification code: " :
                                    "Verification code: ");
          }
          if (saved_pw) {
            pw = strdup(saved_pw);
          }
        }
        break;
      }
      if (!pw) {
        continue;
      }

      // We are often dealing with a combined password and verification
      // code. Separate them now.
      int pw_len = strlen(pw);
      int expected_len = mode & 1 ? 8 : 6;
      char ch;
      if (pw_len < expected_len ||
          // Verification are six digits starting with '0'..'9',
          // scratch codes are eight digits starting with '1'..'9'
          (ch = pw[pw_len - expected_len]) > '9' ||
          ch < (expected_len == 8 ? '1' : '0')) {
      invalid:
        memset(pw, 0, pw_len);
        free(pw);
        pw = NULL;
        continue;
      }
      char *endptr;
      errno = 0;
      long l = strtol(pw + pw_len - expected_len, &endptr, 10);
      if (errno || l < 0 || *endptr) {
        goto invalid;
      }
      int code = (int)l;
      memset(pw + pw_len - expected_len, 0, expected_len);

      if ((mode == 2 || mode == 3) && !params.forward_pass) {
        // We are explicitly configured so that we don't try to share
        // the password with any other stacked PAM module. We must
        // therefore verify that the user entered just the verification
        // code, but no password.
        if (*pw) {
          goto invalid;
        }
      }

      // Check all possible types of verification codes.
      switch (check_scratch_codes(secret_filename, &updated, buf, code)){
      case 1:
        if (hotp_counter > 0) {
          switch (check_counterbased_code(&pam_logger, secret_filename, &updated,
                                          &buf, secret, secretLen, code,
                                          &params, hotp_counter,
                                          &must_advance_counter)) {
          case 0:
            rc = PAM_SUCCESS;
            break;
          case 1:
            goto invalid;
          default:
            break;
          }
        } else {
          switch (check_timebased_code(&pam_logger, secret_filename, &updated, &buf,
                                       secret, secretLen, code, &params)) {
          case 0:
            rc = PAM_SUCCESS;
            break;
          case 1:
            goto invalid;
          default:
            break;
          }
        }
        break;
      case 0:
        rc = PAM_SUCCESS;
        break;
      default:
        break;
      }

      break;
    }

    // Update the system password, if we were asked to forward
    // the system password. We already removed the verification
    // code from the end of the password.
    if (rc == PAM_SUCCESS && params.forward_pass) {
      if (!pw || pam_set_item(pamh, PAM_AUTHTOK, pw) != PAM_SUCCESS) {
        rc = PAM_SESSION_ERR;
      }
    }

    // Clear out password and deallocate memory
    if (pw) {
      memset(pw, 0, strlen(pw));
      free(pw);
    }
    if (saved_pw) {
      memset(saved_pw, 0, strlen(saved_pw));
      free(saved_pw);
    }

    // If an hotp login attempt has been made, the counter must always be
    // advanced by at least one.
    if (must_advance_counter) {
      char counter_str[40];
      sprintf(counter_str, "%ld", hotp_counter + 1);
      if (set_cfg_value(&pam_logger, "HOTP_COUNTER", counter_str, &buf) < 0) {
        rc = PAM_SESSION_ERR;
      }
      updated = 1;
    }

    // If nothing matched, display an error message
    if (rc != PAM_SUCCESS) {
      pam_logger(LOG_ERR, "Invalid verification code");
    }
  }

  // If the user has not created a state file with a shared secret, and if
  // the administrator set the "nullok" option, this PAM module completes
  // successfully, without ever prompting the user.
  if (params.nullok == SECRETNOTFOUND) {
    rc = PAM_SUCCESS;
  }

  // Persist the new state.
  if (early_updated || updated) {
    if (write_file_contents(&pam_logger, secret_filename, filesize,
                            mtime, buf) < 0) {
      // Could not persist new state. Deny access.
      rc = PAM_SESSION_ERR;
    }
  }
  if (fd >= 0) {
    close(fd);
  }
  if (old_gid >= 0) {
    if (setgroup(old_gid) >= 0 && setgroup(old_gid) == old_gid) {
      old_gid = -1;
    }
  }
  if (old_uid >= 0) {
    if (setuser(old_uid) < 0 || setuser(old_uid) != old_uid) {
      pam_logger(LOG_EMERG, "We switched users from %d to %d, "
                  "but can't switch back", old_uid, uid);
    }
  }
  free(secret_filename);

  // Clean up
  if (buf) {
    memset(buf, 0, strlen(buf));
    free(buf);
  }
  if (secret) {
    memset(secret, 0, secretLen);
    free(secret);
  }
  return rc;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags,
                                   int argc, const char **argv)
  __attribute__((visibility("default")));
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags,
                                   int argc, const char **argv) {
  return google_authenticator(pamh, flags, argc, argv);
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc,
                                     const char **argv)
  __attribute__((visibility("default")));
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc,
                                     const char **argv) {
  return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags,
                                   int argc, const char **argv)
  __attribute__((visibility("default")));
PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags,
                                   int argc, const char **argv) {
  return google_authenticator(pamh, flags, argc, argv);
}

#ifdef PAM_STATIC
struct pam_module _pam_listfile_modstruct = {
  MODULE_NAME,
  pam_sm_authenticate,
  pam_sm_setcred,
  NULL,
  pam_sm_open_session,
  NULL,
  NULL
};
#endif
