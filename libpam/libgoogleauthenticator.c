#include "libgoogleauthenticator.h"

/* Given an input value, this function computes the hash code that forms the
 * expected authentication token.
 */
#ifdef TESTING
int compute_code(const uint8_t *secret, int secretLen, unsigned long value)
    __attribute__((visibility("default")));
#else
    int compute_code(const uint8_t *secret, int secretLen, unsigned long value) {
        uint8_t val[8];
        for (int i = 8; i--; value >>= 8) {
            val[i] = value;
        }
        uint8_t hash[SHA1_DIGEST_LENGTH];
        hmac_sha1(secret, secretLen, val, 8, hash, SHA1_DIGEST_LENGTH);
        memset(val, 0, sizeof(val));
        int offset = hash[SHA1_DIGEST_LENGTH - 1] & 0xF;
        unsigned int truncatedHash = 0;
        for (int i = 0; i < 4; ++i) {
            truncatedHash <<= 8;
            truncatedHash  |= hash[offset + i];
        }
        memset(hash, 0, sizeof(hash));
        truncatedHash &= 0x7FFFFFFF;
        truncatedHash %= 1000000;
        return truncatedHash;
    }
#endif

char *get_secret_filename(logger *log, const char *username, int *uid) {
    const char *spec = SECRET;

    // Obtain the user's id and home directory
    struct passwd pwbuf, *pw = NULL;
    char *buf = NULL;
    char *secret_filename = NULL;
    if (1) {
#ifdef _SC_GETPW_R_SIZE_MAX
        int len = sysconf(_SC_GETPW_R_SIZE_MAX);
        if (len <= 0) {
            len = 4096;
        }
#else
        int len = 4096;
#endif
        buf = malloc(len);
        buf[0] = '\0';
        *uid = -1;
        if (buf == NULL ||
                getpwnam_r(username, &pwbuf, buf, len, &pw) ||
                !pw ||
                !pw->pw_dir ||
                *pw->pw_dir != '/') {
err:
            (*log)(LOG_ERR, "Failed to compute location of secret file: %s", buf);
            free(buf);
            free(secret_filename);
            return NULL;
        }
    }

    // Expand filename specification to an actual filename.
    if ((secret_filename = strdup(spec)) == NULL) {
        goto err;
    }
    int allow_tilde = 1;
    for (int offset = 0; secret_filename[offset];) {
        char *cur = secret_filename + offset;
        char *var = NULL;
        size_t var_len = 0;
        const char *subst = NULL;
        if (allow_tilde && *cur == '~') {
            var_len = 1;
            if (!pw) {
                goto err;
            }
            subst = pw->pw_dir;
            var = cur;
        } else if (secret_filename[offset] == '$') {
            if (!memcmp(cur, "${HOME}", 7)) {
                var_len = 7;
                if (!pw) {
                    goto err;
                }
                subst = pw->pw_dir;
                var = cur;
            } else if (!memcmp(cur, "${USER}", 7)) {
                var_len = 7;
                subst = username;
                var = cur;
            }
        }
        if (var) {
            size_t subst_len = strlen(subst);
            char *resized = realloc(secret_filename,
                    strlen(secret_filename) + subst_len);
            if (!resized) {
                goto err;
            }
            var += resized - secret_filename;
            secret_filename = resized;
            memmove(var + subst_len, var + var_len, strlen(var + var_len) + 1);
            memmove(var, subst, subst_len);
            offset = var + subst_len - resized;
            allow_tilde = 0;
        } else {
            allow_tilde = *cur == '/';
            ++offset;
        }
    }

  *uid = pw->pw_uid;
  free(buf);
  return secret_filename;
}

uint8_t *get_shared_secret(logger *log, const char *secret_filename,
                                  const char *buf, int *secretLen) {
  // Decode secret key
  int base32Len = strcspn(buf, "\n");
  *secretLen = (base32Len*5 + 7)/8;
  uint8_t *secret = malloc(base32Len + 1);
  if (secret == NULL) {
    *secretLen = 0;
    return NULL;
  }
  memcpy(secret, buf, base32Len);
  secret[base32Len] = '\000';
  if ((*secretLen = base32_decode(secret, secret, base32Len)) < 1) {
    (*log)(LOG_ERR,
            "Could not find a valid BASE32 encoded secret in \"%s\"",
            secret_filename);
    memset(secret, 0, base32Len);
    free(secret);
    return NULL;
  }
  memset(secret + *secretLen, 0, base32Len + 1 - *secretLen);
  return secret;
}

int is_totp(const char *buf) {
  return !!strstr(buf, "\" TOTP_AUTH");
}

int write_file_contents(logger *log, const char *secret_filename,
                               off_t old_size, time_t old_mtime,
                               const char *buf) {
  // Safely overwrite the old secret file.
  char *tmp_filename = malloc(strlen(secret_filename) + 2);
  if (tmp_filename == NULL) {
 removal_failure:
    (*log)(LOG_ERR, "Failed to update secret file \"%s\"",
                secret_filename);
    return -1;
  }

  strcat(strcpy(tmp_filename, secret_filename), "~");
  int fd = open(tmp_filename,
                O_WRONLY|O_CREAT|O_NOFOLLOW|O_TRUNC|O_EXCL, 0400);
  if (fd < 0) {
    goto removal_failure;
  }

  // Make sure the secret file is still the same. This prevents attackers
  // from opening a lot of pending sessions and then reusing the same
  // scratch code multiple times.
  struct stat sb;
  if (stat(secret_filename, &sb) != 0 ||
      sb.st_size != old_size ||
      sb.st_mtime != old_mtime) {
    (*log)(LOG_ERR,
                "Secret file \"%s\" changed while trying to use "
                "scratch code\n", secret_filename);
    unlink(tmp_filename);
    free(tmp_filename);
    close(fd);
    return -1;
  }

  // Write the new file contents
  if (write(fd, buf, strlen(buf)) != (ssize_t)strlen(buf) ||
      rename(tmp_filename, secret_filename) != 0) {
    unlink(tmp_filename);
    free(tmp_filename);
    close(fd);
    goto removal_failure;
  }

  free(tmp_filename);
  close(fd);

  return 0;
}

char *get_cfg_value(logger *log, const char *key,
                           const char *buf) {
  size_t key_len = strlen(key);
  for (const char *line = buf; *line; ) {
    const char *ptr;
    if (line[0] == '"' && line[1] == ' ' && !memcmp(line+2, key, key_len) &&
        (!*(ptr = line+2+key_len) || *ptr == ' ' || *ptr == '\t' ||
         *ptr == '\r' || *ptr == '\n')) {
      ptr += strspn(ptr, " \t");
      size_t val_len = strcspn(ptr, "\r\n");
      char *val = malloc(val_len + 1);
      if (!val) {
        (*log)(LOG_ERR, "Out of memory");
        return &oom;
      } else {
        memcpy(val, ptr, val_len);
        val[val_len] = '\000';
        return val;
      }
    } else {
      line += strcspn(line, "\r\n");
      line += strspn(line, "\r\n");
    }
  }
  return NULL;
}

int set_cfg_value(logger *log, const char *key, const char *val,
                         char **buf) {
  size_t key_len = strlen(key);
  char *start = NULL;
  char *stop = NULL;

  // Find an existing line, if any.
  for (char *line = *buf; *line; ) {
    char *ptr;
    if (line[0] == '"' && line[1] == ' ' && !memcmp(line+2, key, key_len) &&
        (!*(ptr = line+2+key_len) || *ptr == ' ' || *ptr == '\t' ||
         *ptr == '\r' || *ptr == '\n')) {
      start = line;
      stop  = start + strcspn(start, "\r\n");
      stop += strspn(stop, "\r\n");
      break;
    } else {
      line += strcspn(line, "\r\n");
      line += strspn(line, "\r\n");
    }
  }

  // If no existing line, insert immediately after the first line.
  if (!start) {
    start  = *buf + strcspn(*buf, "\r\n");
    start += strspn(start, "\r\n");
    stop   = start;
  }

  // Replace [start..stop] with the new contents.
  size_t val_len = strlen(val);
  size_t total_len = key_len + val_len + 4;
  if (total_len <= stop - start) {
    // We are decreasing out space requirements. Shrink the buffer and pad with
    // NUL characters.
    size_t tail_len = strlen(stop);
    memmove(start + total_len, stop, tail_len + 1);
    memset(start + total_len + tail_len, 0, stop - start - total_len + 1);
  } else {
    // Must resize existing buffer. We cannot call realloc(), as it could
    // leave parts of the buffer content in unused parts of the heap.
    size_t buf_len = strlen(*buf);
    size_t tail_len = buf_len - (stop - *buf);
    char *resized = malloc(buf_len - (stop - start) + total_len + 1);
    if (!resized) {
      (*log)(LOG_ERR, "Out of memory");
      return -1;
    }
    memcpy(resized, *buf, start - *buf);
    memcpy(resized + (start - *buf) + total_len, stop, tail_len + 1);
    memset(*buf, 0, buf_len);
    free(*buf);
    start = start - *buf + resized;
    *buf = resized;
  }

  // Fill in new contents.
  start[0] = '"';
  start[1] = ' ';
  memcpy(start + 2, key, key_len);
  start[2+key_len] = ' ';
  memcpy(start+3+key_len, val, val_len);
  start[3+key_len+val_len] = '\n';

  // Check if there are any other occurrences of "value". If so, delete them.
  for (char *line = start + 4 + key_len + val_len; *line; ) {
    char *ptr;
    if (line[0] == '"' && line[1] == ' ' && !memcmp(line+2, key, key_len) &&
        (!*(ptr = line+2+key_len) || *ptr == ' ' || *ptr == '\t' ||
         *ptr == '\r' || *ptr == '\n')) {
      start = line;
      stop = start + strcspn(start, "\r\n");
      stop += strspn(stop, "\r\n");
      size_t tail_len = strlen(stop);
      memmove(start, stop, tail_len + 1);
      memset(start + tail_len, 0, stop - start);
      line = start;
    } else {
      line += strcspn(line, "\r\n");
      line += strspn(line, "\r\n");
    }
  }

  return 0;
}

long get_hotp_counter(logger *log, const char *buf) {
  const char *counter_str = get_cfg_value(log, "HOTP_COUNTER", buf);
  if (counter_str == &oom) {
    // Out of memory. This is a fatal error
    return -1;
  }

  long counter = 0;
  if (counter_str) {
    counter = strtol(counter_str, NULL, 10);
  }
  free((void *)counter_str);

  return counter;
}

int rate_limit(logger *log, const char *secret_filename,
                      int *updated, char **buf) {
  const char *value = get_cfg_value(log, "RATE_LIMIT", *buf);
  if (!value) {
    // Rate limiting is not enabled for this account
    return 0;
  } else if (value == &oom) {
    // Out of memory. This is a fatal error.
    return -1;
  }

  // Parse both the maximum number of login attempts and the time interval
  // that we are looking at.
  const char *endptr = value, *ptr;
  int attempts, interval;
  errno = 0;
  if (((attempts = (int)strtoul(ptr = endptr, (char **)&endptr, 10)) < 1) ||
      ptr == endptr ||
      attempts > 100 ||
      errno ||
      (*endptr != ' ' && *endptr != '\t') ||
      ((interval = (int)strtoul(ptr = endptr, (char **)&endptr, 10)) < 1) ||
      ptr == endptr ||
      interval > 3600 ||
      errno) {
    free((void *)value);
    (*log)(LOG_ERR, "Invalid RATE_LIMIT option. Check \"%s\".",
                secret_filename);
    return -1;
  }

  // Parse the time stamps of all previous login attempts.
  unsigned int now = get_time();
  unsigned int *timestamps = malloc(sizeof(int));
  if (!timestamps) {
  oom:
    free((void *)value);
    (*log)(LOG_ERR, "Out of memory");
    return -1;
  }
  timestamps[0] = now;
  int num_timestamps = 1;
  while (*endptr && *endptr != '\r' && *endptr != '\n') {
    unsigned int timestamp;
    errno = 0;
    if ((*endptr != ' ' && *endptr != '\t') ||
        ((timestamp = (int)strtoul(ptr = endptr, (char **)&endptr, 10)),
         errno) ||
        ptr == endptr) {
      free((void *)value);
      free(timestamps);
      (*log)(LOG_ERR, "Invalid list of timestamps in RATE_LIMIT. "
                  "Check \"%s\".", secret_filename);
      return -1;
    }
    num_timestamps++;
    unsigned int *tmp = (unsigned int *)realloc(timestamps,
                                                sizeof(int) * num_timestamps);
    if (!tmp) {
      free(timestamps);
      goto oom;
    }
    timestamps = tmp;
    timestamps[num_timestamps-1] = timestamp;
  }
  free((void *)value);
  value = NULL;

  // Sort time stamps, then prune all entries outside of the current time
  // interval.
  qsort(timestamps, num_timestamps, sizeof(int), comparator);
  int start = 0, stop = -1;
  for (int i = 0; i < num_timestamps; ++i) {
    if (timestamps[i] < now - interval) {
      start = i+1;
    } else if (timestamps[i] > now) {
      break;
    }
    stop = i;
  }

  // Error out, if there are too many login attempts.
  int exceeded = 0;
  if (stop - start + 1 > attempts) {
    exceeded = 1;
    start = stop - attempts + 1;
  }

  // Construct new list of timestamps within the current time interval.
  char *list = malloc(25 * (2 + (stop - start + 1)) + 4);
  if (!list) {
    free(timestamps);
    goto oom;
  }
  sprintf(list, "%d %d", attempts, interval);
  char *prnt = strchr(list, '\000');
  for (int i = start; i <= stop; ++i) {
    prnt += sprintf(prnt, " %u", timestamps[i]);
  }
  free(timestamps);

  // Try to update RATE_LIMIT line.
  if (set_cfg_value(log, "RATE_LIMIT", list, buf) < 0) {
    free(list);
    return -1;
  }
  free(list);

  // Mark the state file as changed.
  *updated = 1;

  // If necessary, notify the user of the rate limiting that is in effect.
  if (exceeded) {
    (*log)(LOG_ERR, "Too many concurrent login attempts. Please try again.");
    return -1;
  }

  return 0;
}

/* Checks for possible use of scratch codes. Returns -1 on error, 0 on success,
 * and 1, if no scratch code had been entered, and subsequent tests should be
 * applied.
 */
int check_scratch_codes(const char *secret_filename,
                               int *updated, char *buf, int code) {
  // Skip the first line. It contains the shared secret.
  char *ptr = buf + strcspn(buf, "\n");

  // Check if this is one of the scratch codes
  char *endptr = NULL;
  for (;;) {
    // Skip newlines and blank lines
    while (*ptr == '\r' || *ptr == '\n') {
      ptr++;
    }

    // Skip any lines starting with double-quotes. They contain option fields
    if (*ptr == '"') {
      ptr += strcspn(ptr, "\n");
      continue;
    }

    // Try to interpret the line as a scratch code
    errno = 0;
    int scratchcode = (int)strtoul(ptr, &endptr, 10);

    // Sanity check that we read a valid scratch code. Scratchcodes are all
    // numeric eight-digit codes. There must not be any other information on
    // that line.
    if (errno ||
        ptr == endptr ||
        (*endptr != '\r' && *endptr != '\n' && *endptr) ||
        scratchcode  <  10*1000*1000 ||
        scratchcode >= 100*1000*1000) {
      break;
    }

    // Check if the code matches
    if (scratchcode == code) {
      // Remove scratch code after using it
      while (*endptr == '\n' || *endptr == '\r') {
        ++endptr;
      }
      memmove(ptr, endptr, strlen(endptr) + 1);
      memset(strrchr(ptr, '\000'), 0, endptr - ptr + 1);

      // Mark the state file as changed
      *updated = 1;

      // Successfully removed scratch code. Allow user to log in.
      return 0;
    }
    ptr = endptr;
  }

  // No scratch code has been used. Continue checking other types of codes.
  return 1;
}

int window_size(logger *log, const char *secret_filename,
                       const char *buf) {
  const char *value = get_cfg_value(log, "WINDOW_SIZE", buf);
  if (!value) {
    // Default window size is 3. This gives us one 30s window before and
    // after the current one.
    free((void *)value);
    return 3;
  } else if (value == &oom) {
    // Out of memory. This is a fatal error.
    return 0;
  }

  char *endptr;
  errno = 0;
  int window = (int)strtoul(value, &endptr, 10);
  if (errno || !*value || value == endptr ||
      (*endptr && *endptr != ' ' && *endptr != '\t' &&
       *endptr != '\n' && *endptr != '\r') ||
      window < 1 || window > 100) {
    free((void *)value);
    (*log)(LOG_ERR, "Invalid WINDOW_SIZE option in \"%s\"",
                secret_filename);
    return 0;
  }
  free((void *)value);
  return window;
}

/* If the DISALLOW_REUSE option has been set, record timestamps have been
 * used to log in successfully and disallow their reuse.
 *
 * Returns -1 on error, and 0 on success.
 */
int invalidate_timebased_code(int tm, logger *log,
                                     const char *secret_filename,
                                     int *updated, char **buf) {
  char *disallow = get_cfg_value(log, "DISALLOW_REUSE", *buf);
  if (!disallow) {
    // Reuse of tokens is not explicitly disallowed. Allow the login request
    // to proceed.
    return 0;
  } else if (disallow == &oom) {
    // Out of memory. This is a fatal error.
    return -1;
  }

  // Allow the user to customize the window size parameter.
  int window = window_size(log, secret_filename, *buf);
  if (!window) {
    // The user configured a non-standard window size, but there was some
    // error with the value of this parameter.
    free((void *)disallow);
    return -1;
  }

  // The DISALLOW_REUSE option is followed by all known timestamps that are
  // currently unavailable for login.
  for (char *ptr = disallow; *ptr;) {
    // Skip white-space, if any
    ptr += strspn(ptr, " \t\r\n");
    if (!*ptr) {
      break;
    }

    // Parse timestamp value.
    char *endptr;
    errno = 0;
    int blocked = (int)strtoul(ptr, &endptr, 10);

    // Treat syntactically invalid options as an error
    if (errno ||
        ptr == endptr ||
        (*endptr != ' ' && *endptr != '\t' &&
         *endptr != '\r' && *endptr != '\n' && *endptr)) {
      free((void *)disallow);
      return -1;
    }

    if (tm == blocked) {
      // The code is currently blocked from use. Disallow login.
      free((void *)disallow);
      (*log)(LOG_ERR,
                  "Trying to reuse a previously used time-based code. "
                  "Retry again in 30 seconds. "
                  "Warning! This might mean, you are currently subject to a "
                  "man-in-the-middle attack.");
      return -1;
    }

    // If the blocked code is outside of the possible window of timestamps,
    // remove it from the file.
    if (blocked - tm >= window || tm - blocked >= window) {
      endptr += strspn(endptr, " \t");
      memmove(ptr, endptr, strlen(endptr) + 1);
    } else {
      ptr = endptr;
    }
  }

  // Add the current timestamp to the list of disallowed timestamps.
  char *resized = realloc(disallow, strlen(disallow) + 40);
  if (!resized) {
    free((void *)disallow);
    (*log)(LOG_ERR,
                "Failed to allocate memory when updating \"%s\"",
                secret_filename);
    return -1;
  }
  disallow = resized;
  sprintf(strrchr(disallow, '\000'), " %d" + !*disallow, tm);
  if (set_cfg_value(log, "DISALLOW_REUSE", disallow, buf) < 0) {
    free((void *)disallow);
    return -1;
  }
  free((void *)disallow);

  // Mark the state file as changed
  *updated = 1;

  // Allow access.
  return 0;
}

/* If a user repeated attempts to log in with the same time skew, remember
 * this skew factor for future login attempts.
 */
int check_time_skew(logger *log, const char *secret_filename,
                           int *updated, char **buf, int skew, int tm) {
  int rc = -1;

  // Parse current RESETTING_TIME_SKEW line, if any.
  char *resetting = get_cfg_value(log, "RESETTING_TIME_SKEW", *buf);
  if (resetting == &oom) {
    // Out of memory. This is a fatal error.
    return -1;
  }

  // If the user can produce a sequence of three consecutive codes that fall
  // within a day of the current time. And if he can enter these codes in
  // quick succession, then we allow the time skew to be reset.
  // N.B. the number "3" was picked so that it would not trigger the rate
  // limiting limit if set up with default parameters.
  unsigned int tms[3];
  int skews[sizeof(tms)/sizeof(int)];

  int num_entries = 0;
  if (resetting) {
    char *ptr = resetting;

    // Read the three most recent pairs of time stamps and skew values into
    // our arrays.
    while (*ptr && *ptr != '\r' && *ptr != '\n') {
      char *endptr;
      errno = 0;
      unsigned int i = (int)strtoul(ptr, &endptr, 10);
      if (errno || ptr == endptr || (*endptr != '+' && *endptr != '-')) {
        break;
      }
      ptr = endptr;
      int j = (int)strtoul(ptr + 1, &endptr, 10);
      if (errno ||
          ptr == endptr ||
          (*endptr != ' ' && *endptr != '\t' &&
           *endptr != '\r' && *endptr != '\n' && *endptr)) {
        break;
      }
      if (*ptr == '-') {
        j = -j;
      }
      if (num_entries == sizeof(tms)/sizeof(int)) {
        memmove(tms, tms+1, sizeof(tms)-sizeof(int));
        memmove(skews, skews+1, sizeof(skews)-sizeof(int));
      } else {
        ++num_entries;
      }
      tms[num_entries-1]   = i;
      skews[num_entries-1] = j;
      ptr = endptr;
    }

    // If the user entered an identical code, assume they are just getting
    // desperate. This doesn't actually provide us with any useful data,
    // though. Don't change any state and hope the user keeps trying a few
    // more times.
    if (num_entries &&
        tm + skew == tms[num_entries-1] + skews[num_entries-1]) {
      free((void *)resetting);
      return -1;
    }
  }
  free((void *)resetting);

  // Append new timestamp entry
  if (num_entries == sizeof(tms)/sizeof(int)) {
    memmove(tms, tms+1, sizeof(tms)-sizeof(int));
    memmove(skews, skews+1, sizeof(skews)-sizeof(int));
  } else {
    ++num_entries;
  }
  tms[num_entries-1]   = tm;
  skews[num_entries-1] = skew;

  // Check if we have the required amount of valid entries.
  if (num_entries == sizeof(tms)/sizeof(int)) {
    unsigned int last_tm = tms[0];
    int last_skew = skews[0];
    int avg_skew = last_skew;
    for (int i = 1; i < sizeof(tms)/sizeof(int); ++i) {
      // Check that we have a consecutive sequence of timestamps with no big
      // gaps in between. Also check that the time skew stays constant. Allow
      // a minor amount of fuzziness on all parameters.
      if (tms[i] <= last_tm || tms[i] > last_tm+2 ||
          last_skew - skew < -1 || last_skew - skew > 1) {
        goto keep_trying;
      }
      last_tm   = tms[i];
      last_skew = skews[i];
      avg_skew += last_skew;
    }
    avg_skew /= (int)(sizeof(tms)/sizeof(int));

    // The user entered the required number of valid codes in quick
    // succession. Establish a new valid time skew for all future login
    // attempts.
    char time_skew[40];
    sprintf(time_skew, "%d", avg_skew);
    if (set_cfg_value(log, "TIME_SKEW", time_skew, buf) < 0) {
      return -1;
    }
    rc = 0;
  keep_trying:;
  }

  // Set the new RESETTING_TIME_SKEW line, while the user is still trying
  // to reset the time skew.
  char reset[80 * (sizeof(tms)/sizeof(int))];
  *reset = '\000';
  if (rc) {
    for (int i = 0; i < num_entries; ++i) {
      sprintf(strrchr(reset, '\000'), " %d%+d" + !*reset, tms[i], skews[i]);
    }
  }
  if (set_cfg_value(log, "RESETTING_TIME_SKEW", reset, buf) < 0) {
    return -1;
  }

  // Mark the state file as changed
  *updated = 1;

  return rc;
}

/* Checks for time based verification code. Returns -1 on error, 0 on success,
 * and 1, if no time based code had been entered, and subsequent tests should
 * be applied.
 */
int check_timebased_code(logger *log, const char*secret_filename,
                                int *updated, char **buf, const uint8_t*secret,
                                int secretLen, int code, Params *params) {
  if (!is_totp(*buf)) {
    // The secret file does not actually contain information for a time-based
    // code. Return to caller and see if any other authentication methods
    // apply.
    return 1;
  }

  if (code < 0 || code >= 1000000) {
    // All time based verification codes are no longer than six digits.
    return 1;
  }

  // Compute verification codes and compare them with user input
  const int tm = get_timestamp();
  const char *skew_str = get_cfg_value(log, "TIME_SKEW", *buf);
  if (skew_str == &oom) {
    // Out of memory. This is a fatal error
    return -1;
  }

  int skew = 0;
  if (skew_str) {
    skew = (int)strtol(skew_str, NULL, 10);
  }
  free((void *)skew_str);

  int window = window_size(log, secret_filename, *buf);
  if (!window) {
    return -1;
  }
  for (int i = -((window-1)/2); i <= window/2; ++i) {
    unsigned int hash = compute_code(secret, secretLen, tm + skew + i);
    if (hash == (unsigned int)code) {
      return invalidate_timebased_code(tm + skew + i, log, secret_filename,
                                       updated, buf);
    }
  }

  if (!params->noskewadj) {
    // The most common failure mode is for the clocks to be insufficiently
    // synchronized. We can detect this and store a skew value for future
    // use.
    skew = 1000000;
    for (int i = 0; i < 25*60; ++i) {
      unsigned int hash = compute_code(secret, secretLen, tm - i);
      if (hash == (unsigned int)code && skew == 1000000) {
        // Don't short-circuit out of the loop as the obvious difference in
        // computation time could be a signal that is valuable to an attacker.
        skew = -i;
      }
      hash = compute_code(secret, secretLen, tm + i);
      if (hash == (unsigned int)code && skew == 1000000) {
        skew = i;
      }
    }
    if (skew != 1000000) {
      return check_time_skew(log, secret_filename, updated, buf, skew, tm);
    }
  }

  return 1;
}

/* Checks for counter based verification code. Returns -1 on error, 0 on
 * success, and 1, if no counter based code had been entered, and subsequent
 * tests should be applied.
 */
int check_counterbased_code(logger *log,
                                   const char*secret_filename, int *updated,
                                   char **buf, const uint8_t*secret,
                                   int secretLen, int code, Params *params,
                                   long hotp_counter,
                                   int *must_advance_counter) {
  if (hotp_counter < 1) {
    // The secret file did not actually contain information for a counter-based
    // code. Return to caller and see if any other authentication methods
    // apply.
    return 1;
  }

  if (code < 0 || code >= 1000000) {
    // All counter based verification codes are no longer than six digits.
    return 1;
  }

  // Compute [window_size] verification codes and compare them with user input.
  // Future codes are allowed in case the user computed but did not use a code.
  int window = window_size(log, secret_filename, *buf);
  if (!window) {
    return -1;
  }
  for (int i = 0; i < window; ++i) {
    unsigned int hash = compute_code(secret, secretLen, hotp_counter + i);
    if (hash == (unsigned int)code) {
      char counter_str[40];
      sprintf(counter_str, "%ld", hotp_counter + i + 1);
      if (set_cfg_value(log, "HOTP_COUNTER", counter_str, buf) < 0) {
        return -1;
      }
      *updated = 1;
      *must_advance_counter = 0;
      return 0;
    }
  }

  *must_advance_counter = 1;
  return 1;
}

#ifdef TESTING
time_t current_time;
void set_time(time_t t) __attribute__((visibility("default")));
void set_time(time_t t) {
  current_time = t;
}

time_t get_time(void) {
  return current_time;
}
#else
time_t get_time(void) {
  return time(NULL);
}
#endif

int get_timestamp(void) {
  return get_time() / 30;
}

int open_secret_file(logger *log, const char *secret_filename, Params *params,
                            const char *username,
                            int uid, off_t *size, time_t *mtime) {
  // Try to open "~/.google_authenticator"
  *size = 0;
  *mtime = 0;
  int fd = open(secret_filename, O_RDONLY);
  struct stat sb;
  if (fd < 0 ||
      fstat(fd, &sb) < 0) {
      (*log)(LOG_ERR, "Failed to read \"%s\"", secret_filename);
 error:
    if (fd >= 0) {
      close(fd);
    }
    return -1;
  }

  // Check permissions on "~/.google_authenticator"
  if ((sb.st_mode & 03577) != 0400 ||
      !S_ISREG(sb.st_mode) ||
      sb.st_uid != (uid_t)uid) {
    char buf[80];
    (*log)(LOG_ERR,
                "Secret file \"%s\" must only be accessible by %s",
                secret_filename, username);
    goto error;
  }

  // Sanity check for file length
  if (sb.st_size < 1 || sb.st_size > 64*1024) {
    (*log)(LOG_ERR, "Invalid file size for \"%s\"", secret_filename);
    goto error;
  }

  *size = sb.st_size;
  *mtime = sb.st_mtime;
  return fd;
}

char *read_file_contents(logger *log, const char *secret_filename, int *fd,
                                off_t filesize) {
  // Read file contents
  char *buf = malloc(filesize + 1);
  if (!buf ||
      read(*fd, buf, filesize) != filesize) {
    close(*fd);
    *fd = -1;
    (*log)(LOG_ERR, "Could not read \"%s\"", secret_filename);
 error:
    if (buf) {
      memset(buf, 0, filesize);
      free(buf);
    }
    return NULL;
  }
  close(*fd);
  *fd = -1;

  // The rest of the code assumes that there are no NUL bytes in the file.
  if (memchr(buf, 0, filesize)) {
    (*log)(LOG_ERR, "Invalid file contents in \"%s\"", secret_filename);
    goto error;
  }

  // Terminate the buffer with a NUL byte.
  buf[filesize] = '\000';

  return buf;
}
