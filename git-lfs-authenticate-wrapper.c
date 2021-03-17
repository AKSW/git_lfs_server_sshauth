#define _GNU_SOURCE
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
#include <stdio.h>


int main(int argc, char *argv[]) {
  uid_t uid = getuid();
  uid_t euid = geteuid();
  if (uid == euid)
    return 1;
  
  struct passwd *p = getpwuid(uid);
  if (p == NULL)
    return 2;

  if (argc != 3)
    return 3;

  char *user, *project, *command;
  if (asprintf(&user, "user=%s", p->pw_name) == -1)
    return -1;
  if (asprintf(&project, "project=%s", argv[1]) == -1)
    return -1;
  if (asprintf(&command, "command=%s", argv[2]) == -1)
    return -1;

  execle("/usr/bin/curl", "git-lfs-authenticate",
	 "--netrc", /* look up username and password in .netrc */
	 "--silent",
	 "--fail",
	 "--show-error",
	 "--data-raw", user,
	 "--data-raw", project,
	 "--data-raw", command,
	 "https://git-lfs.example.org/api/token_factory", (char *) NULL, NULL);
}
