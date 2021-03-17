#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>

int cat_pam(const char *path)
{
  FILE *fi;
  int c;
  if ((fi = fopen(path, "r")) == NULL)
    return 1;

  while ((c = getc(fi)) != EOF) {
    if (c == '%') {
      if ((c = getc(fi)) == EOF)
	break;
      switch(c) {
      case 'u':
	{
	  struct passwd *pw;
	  uid_t uid;

	  uid = getuid();
	  pw = getpwuid(uid);
	  if (pw)
	    printf("%s", pw->pw_name);
	}
	break;
      case 'h':
	{
	  char hostname[65];
	  gethostname(hostname, sizeof hostname);
	  printf("%s", hostname);
	}
	break;
      default:
	putchar('%');
      case '%':
	putchar(c);
      }	  
    } else {
      putchar(c);
    }
  }
  fclose(fi);
  return 0;
}

int main(int argc, char *argv[]) {
  if (argc == 3 && strncmp("git-lfs-authenticate", argv[2], 20) == 0
      && (argv[2][20] == '\0' || argv[2][20] == ' ')) {
    char *new_arg[4] = { NULL };
    char *a;
    int p, q;
    a = argv[2];
    p = 1;
    q = 0;
    new_arg[0] = a;
    while (*a != '\0' && p < 4) {
      if (*a == '"' && q) {
	q--;
	*a = '\0';
      } else if (*a == ' ' && !q) {
	*a = '\0';
	if (a[1] == '"') {
	  new_arg[p++] = a+2;
	  q = 2;
	}
	else
	  new_arg[p++] = a+1;
      }
      a++;
    }
    execvpe("/usr/local/bin/git-lfs-authenticate", new_arg, NULL);
  }

  return cat_pam("/opt/git_lfs_server/info.txt");
}
