# Git LFS Server with SSH Authentication backing

A simple, single-file LFS server with authentication based on JSON Web
Tokens (JWT).

## Features

* Store files to any path on your system.
* Serve files using sendfile in Apache httpd (optional).
* Easy to modify.

### Not implemented

* Locking API

## Usage

Create a `.lfsconfig` file in your Repository with the following content:

```
[lfs]
	url = https://git-lfs.example.org/api/namespace/repo
	pushurl = ssh://git-lfs.example.org/api/namespace/repo
```

## Deployment

* Modify the paths at top of `git_lfs_server`. You should specify the `$storage_path` and the path to your private EC key needed for JWT encryption (`-----BEGIN EC PRIVATE KEY-----` kind of file). Or just modify the encryption to suit your needs.
* Protect the secret key with UNIX permissions (`chown && chmod`).
* Token factory (**IMPORTANT!**)
  * Make sure to protect the `/token_factory` end-point for example with HTTP Basic Auth and a mutual secret.
  * Or delete the token_factory end-point from the script.
* Deploy the LFS server on any PSGI application server. You can check the `apache_vhost.conf` for an example involving Apache httpd.

## Authentication

* It is really up to you!
* In the general case, you should have an SSH end-point which dispenses valid JSON Web Tokens when calling the `git-lfs-authenticate`.
* The tokens have to be signed/encrypted with the key specified in the deployment section, contain a valid `sub` (user-name) and the `aud` value of the token has to match the requested project (`namespace/repo`)
* Some simple examples are included/introduced below:

### Token factory

* In the LFS server there is a `/token_factory` end-point which will create valid tokens for arbitrary users/projects. To use it, send the domain name as the HTTP Basic Authentication `Username`, and the desired user and project as query parameters. Make sure to properly protect, or remove it.

### Direct access to token factory from SSH

* The included `git-lfs-authenticate-wrapper` will call the token factory using `curl` and the user name of the currently logged in user. If each of your SSH users should be able to commit to arbitrary LFS repositories, you can drop this file as `git-lfs-authenticate` into the `$PATH`.
* To make it secure:
  * Create a dedicated user for git-lfs-authenticate
  * Enable the setuid bit
  * set up a shared secret between the token factory end-point.
  * store the password in `.netrc`, readable only to git-lfs-authenticate

### Restricted SSH

* The included `restricted_sh` can be installed as a restricted shell for users that should have LFS access but no further access. It will simply forward the call to ``/usr/local/bin/git-lfs-authenticate` (modify as required).
* Research how to create a locked-down SSH server.
* Set the restricted_sh as the users' shell/forced command.
* When doing `ssh git-lfs.example.org git-lfs-authenticate ...`, the restricted_sh should be invoked like `restricted_sh -c "git-lfs-authenticate ..."`

### Single-user SSH (like gitolite)

* When using it with an external Git server (like GitHub), change the `.lfsconfig` to include the user name:
  ```
  [lfs]
	  url = https://git-lfs.example.org/api/namespace/repo
	  pushurl = ssh://git-lfs@git-lfs.example.org/api/namespace/repo
  ```
* See https://github.com/HimaJyun/gitolite-lfs for more examples how it could be integrated to gitolite.

## Trouble-shooting

If Apache httpd crashes, there may be a symbol conflict between libasn1 and CryptX. You can re-install CryptX but this time like this, as a workaround:

```
export CFLAGS="-imacros $PWD/rename_symbols.inc"
cpan -c CryptX
cpan CryptX
```
