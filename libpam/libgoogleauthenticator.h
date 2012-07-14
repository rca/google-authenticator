#include <sys/types.h>
#include <sys/stat.h>
#include <pwd.h>
#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>

#include "base32.h"
#include "hmac.h"
#include "sha1.h"

#define SECRET      "~/.google_authenticator"

typedef struct Params {
  const char *secret_filename_spec;
  enum { NULLERR=0, NULLOK, SECRETNOTFOUND } nullok;
  int        noskewadj;
  int        echocode;
  int        fixed_uid;
  uid_t      uid;
  enum { PROMPT = 0, TRY_FIRST_PASS, USE_FIRST_PASS } pass_mode;
  int        forward_pass;
} Params;

typedef int (*logger)(int level, char *message, ...);

int compute_code(const uint8_t *secret, int secretLen, unsigned long value);

char *get_secret_filename(logger *log, const char *username, int *uid);

uint8_t *get_shared_secret(logger *log, const char *secret_filename, const char *buf, int *secretLen);

int is_totp(const char *buf);

int write_file_contents(logger *log, const char *secret_filename,
                        off_t old_size, time_t old_mtime,
                        const char *buf);

char *get_cfg_value(logger *log, const char *key, const char *buf);

int set_cfg_value(logger *log, const char *key, const char *val, char **buf);

long get_hotp_counter(logger *log, const char *buf);

int rate_limit(logger *log, const char *secret_filename, int *updated, char **buf);

int check_scratch_codes(const char *secret_filename, int *updated, char *buf, int code);

int window_size(logger *log, const char *secret_filename, const char *buf);

int invalidate_timebased_code(int tm,
                              logger *log,
                              const char *secret_filename,
                              int *updated, char **buf);

int check_time_skew(logger *log,
                    const char *secret_filename,
                    int *updated, char **buf, int skew, int tm);

int check_timebased_code(logger *log, const char*secret_filename,
                         int *updated, char **buf, const uint8_t*secret,
                         int secretLen, int code, Params *params);

int check_counterbased_code(logger *log,
                            const char*secret_filename, int *updated,
                            char **buf, const uint8_t*secret,
                            int secretLen, int code, Params *params,
                            long hotp_counter,
                            int *must_advance_counter);

time_t get_time(void);

int get_timestamp(void);

int open_secret_file(logger *log, const char *secret_filename, Params *params,
                     const char *username,
                     int uid, off_t *size, time_t *mtime);

char *read_file_contents(logger *log, const char *secret_filename, int *fd, off_t filesize);
