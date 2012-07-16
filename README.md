Google Authenticator
====================

This is a fork of the [Google Authenticator
project](http://code.google.com/p/google-authenticator/), which includes
two-factor verification for SSH key-based logins via command defined in the
`authorized_keys` file.

Getting Started
-------------

Clone the repository and run `sudo make install-ssh-key-verify`.  This will
build and install the necessary programs into `/usr/local/bin/`.

Once installed, run `google-authenticator` to generate the secrets file.  You
will need to install [Google Authenticator](http://support.google.com/accounts/bin/answer.py?hl=en&answer=1066447)
on your mobile device.

Finally, prepend the following to any key in `~/.ssh/authorized_keys` that you
would like to protect:

```command="/usr/local/bin/google-ssh-key-authenticator" ```

This will cache the verification per IP address for 9 hours, meaning once you have successfully entered a secret, you will not have to from that location for another 9 hours.

Notes
-----

Make sure your system clock is in sync with the planet.  It's best to run NTP
or at the very least run `ntpdate` periodically to make sure your system's
clock doesn't drift too far off reality.

Next, before logging out of your system, connect from another shell and verify
you are able to login using the secret.
