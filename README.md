Nginx module to use a Yubikey for simple http authentication
============================================================
&nbsp;
Requirements
-----------

yubico-c-client (you can get it at [https://github.com/Yubico/yubico-c-client](https://github.com/Yubico/yubico-c-client "yubico-c-client"))
curl (use the version of your OS)


Compilation
-----------

When compiling from source build as usual adding the -add-module option:

	./configure --add-module=$PATH_TO_MODULE

Configuration
-------------

The module has the following directives:

- "auth\_yubikey": This is the http authentication realm. 

- "auth\_yubikey\_client\_id": This is the client id provided by Yubico.

- "auth\_yubikey\_secret\_key": This is the secret key provided by Yubico.

- "auth\_yubikey\_file": Path to the user to key mapping file. The file
  contains the username and first 12 chars of your key (just press your
  yubikey once the module will ignore the rest). If this directive is
  not included every user with a valid key which is registered at the
  Yubico API can authenticate.

- "auth\_yubikey\_ttl": Set the cache timeout is seconds for after the
  first login of the user. Default is set to 24 hours. If set to
  a low value the user needs to log-in every-time because of the replayed
  OTP.

You have to obtain an Yubico API key at [https://upgrade.yubico.com/getapikey](https://upgrade.yubico.com/getapikey "Get API key") 
to get this module working.

Examples
--------

To protect everything under "/yubikey" you will add the following to the
"nginx.conf" file:

	location /yubikey {
		auth_yubikey "Restricted Zone";
		auth_yubikey_api_url "https://api.yubico.com/wsapi/2.0/verify?id=%d&otp=%s";
		auth_yubikey_client_id "1234";
		auth_yubikey_secret_key "1Ab+CdEfgHi/jkl2M3nOp4qrsT5=";
		auth_yubikey_file "/etc/yubikey.conf";
		auth_yubikey_ttl "43200";
	}

In the file "/etc/yubikey.conf" put the username followed by a colon
and after the colon just press your Yubikey once.

**Example:**

	admin:ekuhubcruhrkrhkicucbevftickivilrfekvntkjbnvv
