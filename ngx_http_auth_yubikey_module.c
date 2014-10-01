/* 
 * Copyright (C) 2011, Alexander Verhaar <sanderv32@gmail.com>
 * Copyright (C) 2009-2011, Igor Sysoev
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */


/*
 * Many part of this module are a sameless copy of the basic athentication
 * module of Igor (better good stolen than badly coded ;-) ).
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_md5.h>
#include <time.h>
#include <ykclient.h>
#include "b64/cencode.h"
#include "b64/cdecode.h"

#define NGX_HTTP_AUTH_BUF_SIZE  8192
#define NGX_CACHED_CRED_SIZE	100		/* Authentication slots */
#define NGX_YUBIKEY_TTL			86400	/* Cached credentials ttl */

/* Cached credentials structure */
typedef struct {
	ngx_int_t					ttl;
	u_char						md5[MD5_DIGEST_LENGTH];
} ngx_cached_cred_t;

typedef struct {
	ngx_str_t					realm;
	ngx_str_t					client_id;
	ngx_str_t					secret_key;
	ngx_int_t					ttl;
	ngx_http_complex_value_t	user_file;
	ngx_str_t					wsapi_url;

	ngx_uint_t					count;
	ngx_cached_cred_t			cached_cred[NGX_CACHED_CRED_SIZE];
} ngx_http_auth_yubikey_loc_conf_t;


static ngx_int_t ngx_http_auth_yubikey_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_auth_yubikey_otp_handler(ngx_http_request_t *r,
    void *config);
static ngx_int_t ngx_http_auth_yubikey_set_realm(ngx_http_request_t *r,
    ngx_str_t *realm);
static void *ngx_http_auth_yubikey_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_auth_yubikey_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);
static ngx_int_t ngx_http_auth_yubikey_init(ngx_conf_t *cf);
static char *ngx_http_auth_yubikey(ngx_conf_t *cf, void *post, void *data);
static char *ngx_http_auth_yubikey_user_file(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static void ngx_http_auth_yubikey_close(ngx_file_t *file);

static ngx_conf_post_handler_pt  ngx_http_auth_yubikey_p = ngx_http_auth_yubikey;

static ngx_command_t  ngx_http_auth_yubikey_commands[] = {

    { ngx_string("auth_yubikey"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF
                        |NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_yubikey_loc_conf_t, realm),
      &ngx_http_auth_yubikey_p },

	{ ngx_string("auth_yubikey_client_id"),
	  NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF
						|NGX_CONF_TAKE1,
	  ngx_conf_set_str_slot,
	  NGX_HTTP_LOC_CONF_OFFSET,
	  offsetof(ngx_http_auth_yubikey_loc_conf_t, client_id),
	  NULL },

	{ ngx_string("auth_yubikey_secret_key"),
	  NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF
						|NGX_CONF_TAKE1,
	  ngx_conf_set_str_slot,
	  NGX_HTTP_LOC_CONF_OFFSET,
	  offsetof(ngx_http_auth_yubikey_loc_conf_t, secret_key),
	  NULL },

	{ ngx_string("auth_yubikey_ttl"),
	  NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF
						|NGX_CONF_TAKE1,
	  ngx_conf_set_num_slot,
	  NGX_HTTP_LOC_CONF_OFFSET,
	  offsetof(ngx_http_auth_yubikey_loc_conf_t, ttl),
	  NULL },

	{ ngx_string("auth_yubikey_file"),
	  NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF
	  					|NGX_CONF_TAKE1,
	  ngx_http_auth_yubikey_user_file,
	  NGX_HTTP_LOC_CONF_OFFSET,
	  offsetof(ngx_http_auth_yubikey_loc_conf_t, user_file),
	  NULL },

	{ ngx_string("auth_yubikey_api_url"),
	  NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF
	  					|NGX_CONF_TAKE1,
	  ngx_conf_set_str_slot,
	  NGX_HTTP_LOC_CONF_OFFSET,
	  offsetof(ngx_http_auth_yubikey_loc_conf_t, wsapi_url),
	  NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_auth_yubikey_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_auth_yubikey_init,              /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_auth_yubikey_create_loc_conf,   /* create location configuration */
    ngx_http_auth_yubikey_merge_loc_conf     /* merge location configuration */
};


ngx_module_t  ngx_http_auth_yubikey_module = {
    NGX_MODULE_V1,
    &ngx_http_auth_yubikey_module_ctx,		/* module context */
    ngx_http_auth_yubikey_commands,			/* module directives */
    NGX_HTTP_MODULE,						/* module type */
    NULL,									/* init master */
    NULL,									/* init module */
    NULL,									/* init process */
    NULL,									/* init thread */
    NULL,									/* exit thread */
    NULL,									/* exit process */
    NULL,									/* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_int_t
ngx_http_auth_yubikey_handler(ngx_http_request_t *r)
{
    ngx_int_t                        rc;
    ngx_http_auth_yubikey_loc_conf_t  *alcf;

    alcf = ngx_http_get_module_loc_conf(r, ngx_http_auth_yubikey_module);

    if (alcf->realm.len == 0 || alcf->client_id.len == 0 ||
		alcf->secret_key.len == 0 || alcf->wsapi_url.len == 0) {
        return NGX_DECLINED;
    }

    rc = ngx_http_auth_basic_user(r);

    if (rc == NGX_DECLINED) {
        return ngx_http_auth_yubikey_set_realm(r, &alcf->realm);
    }

    if (rc == NGX_ERROR) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

	return ngx_http_auth_yubikey_otp_handler(r, alcf);
}


static ngx_int_t
ngx_http_auth_yubikey_otp_handler(ngx_http_request_t *r, void *conf)
{
	size_t		len;
	ssize_t		n;
	ngx_fd_t	fd;
	ngx_file_t	file;
    ngx_int_t   rc, declen=0, oldest;
	ngx_err_t	err;
	ngx_uint_t	level, i, j, cslot;
	ngx_md5_t	md5;
	ngx_str_t	user_file, user;
	u_char		key[22], *p, *ykey, md5_buf[MD5_DIGEST_LENGTH];
	u_char		buf[NGX_HTTP_AUTH_BUF_SIZE];
	u_char		tmpbuf[NGX_HTTP_AUTH_BUF_SIZE];
	base64_decodestate state;
	ykclient_t *ykc;

	ngx_http_auth_yubikey_loc_conf_t *alcf = conf;

	ngx_memset(buf, 0, sizeof(buf));
	ngx_memset(md5_buf, 0, sizeof(md5_buf));

	for(len=0; len < r->headers_in.user.len; len++)
		if ( r->headers_in.user.data[len] == ':' ) break;

	user.data = ngx_palloc(r->pool, len+1);
	user.len = len;

	p = ngx_cpymem(user.data, r->headers_in.user.data, len);
	*p = '\0';
	
	if (r->connection->log->log_level & NGX_LOG_DEBUG_HTTP) {
    	ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
						"User: \"%s\" Password: \"%s\"", user.data, r->headers_in.passwd.data);
	}

	/* Read the user file if there is entry */
	if (alcf->user_file.value.len > 0) {
		if (ngx_http_complex_value(r, &alcf->user_file, &user_file) != NGX_OK) {
			return NGX_ERROR;
		}

		fd = ngx_open_file(user_file.data, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);

		if (fd == NGX_INVALID_FILE) {
			err = ngx_errno;

			if (err == NGX_ENOENT) {
				level = NGX_LOG_ERR;
				rc = NGX_HTTP_FORBIDDEN;
			} else {
				level = NGX_LOG_CRIT;
				rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
			}

			ngx_log_error(level, r->connection->log, err,
						  ngx_open_file_n " \"%s\" failed", user_file.data);

			return rc;
		}
		file.fd = fd;
		file.name = user_file;
		file.log = r->connection->log;

		n = ngx_read_file(&file, buf, NGX_HTTP_AUTH_BUF_SIZE, 0);
		if (n == NGX_ERROR) {
			ngx_http_auth_yubikey_close(&file);
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		}

		ngx_http_auth_yubikey_close(&file);
	}

	/* Check if the credentials are already cached */
	ngx_memset(&md5, 0, sizeof(md5));
	ngx_md5_init(&md5);
	ngx_md5_update(&md5, r->headers_in.user.data, r->headers_in.user.len+46);
	ngx_md5_final(md5_buf, &md5);

	for(i=0; i < alcf->count; i++) {
		if ( alcf->cached_cred[i].md5 ) {
			if ( ngx_memcmp(alcf->cached_cred[i].md5, md5_buf, MD5_DIGEST_LENGTH) == 0 ) {
				/* User is already cached, check ttl */
				/* timeout with time now             */
				if (alcf->cached_cred[i].ttl < time(NULL)) {
					if (r->connection->log->log_level & NGX_LOG_DEBUG_HTTP) {
						ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
									"Found user %s. Cache (ttl %ud) expired", user.data, alcf->cached_cred[i].ttl);
					}
					return NGX_HTTP_UNAUTHORIZED;
				} else
					if (r->connection->log->log_level & NGX_LOG_DEBUG_HTTP) {
						ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
									"Found user %s. Cache (ttl %ud) valid", user.data, alcf->cached_cred[i].ttl);
					}
					return NGX_OK;
			}
		}
	}

	/* User not found in cache, let's make an entry in the cache */
	j = alcf->count;
	if ( alcf->count >= NGX_CACHED_CRED_SIZE ) {
		/* All entries in the cache are full, search oldest one and clear it */
		oldest=-1;
		for(i=0; i < alcf->count; i++) {
			if (alcf->cached_cred[i].ttl < oldest ) {
				oldest = alcf->cached_cred[i].ttl;
				j = i;
			}
		}
	}
	alcf->cached_cred[j].ttl = time(NULL) + alcf->ttl;
	/*alcf->cached_cred[j].md5.data = ngx_palloc(r->pool, 17);
	alcf->cached_cred[j].md5.len = 17;*/
	p = ngx_cpymem(alcf->cached_cred[j].md5, md5_buf, MD5_DIGEST_LENGTH);
   	*p = '\0';

	ngx_memset(tmpbuf, 0, sizeof(tmpbuf));
	for(i=0; i<MD5_DIGEST_LENGTH; i++) {
		sprintf((char*)tmpbuf,"%s%2.2x",tmpbuf,alcf->cached_cred[j].md5[i]);
	}

	if (r->connection->log->log_level & NGX_LOG_DEBUG_HTTP) {
		ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
					"alcf : default ttl -> %ud ttl->%ud md5->%s %s",
					alcf->ttl,alcf->cached_cred[j].ttl, tmpbuf, r->headers_in.user.data);
	}

	cslot = j;
	alcf->count = ++j;

	/* Initialize base64 decoder */
	base64_init_decodestate(&state);
	declen=base64_decode_block((char*)alcf->secret_key.data, strlen((char *)alcf->secret_key.data), (char*)key, &state);

	/* Check if auth_yubikey_client_id is set to a proper value */
    if (ngx_atoi(alcf->client_id.data, alcf->client_id.len) <= 0)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
        			  "error: client identity must be a non-zero integer");
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

	/* Check if the password send to the server has a valid OTP length */
    if (strlen((char*)r->headers_in.passwd.data) < 32)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
        			  "error: ModHex encoded token must be at least 32 characters.");
		return ngx_http_auth_yubikey_set_realm(r, &alcf->realm);
    }

	rc = ykclient_init (&ykc);
	if ( rc != YKCLIENT_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "ykclient error: %s",
                      ykclient_strerror(rc));
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	/* Set WSAPI URL */
	if (r->connection->log->log_level & NGX_LOG_DEBUG_HTTP) {
    	ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
						"WSApi url \"%s\"", alcf->wsapi_url.data);
	}
    ykclient_set_url_template(ykc, (char*)alcf->wsapi_url.data);
    ykclient_set_client (ykc, atoi((char*)alcf->client_id.data), declen, (char*)key);

	/* Yubikey exist on the server of Yubico, now check the key against the first 12 chars */
	if (alcf->user_file.value.len > 0) {
		if ( strstr((char*)buf, (char*)user.data) ) {
			/* User found in file, check against key */
			p = (u_char*)strstr((char*)buf, (char*)user.data);
			ykey = (u_char*)strstr((char*)p, ":")+1;
			*strstr((char*)ykey, "\n") = '\0';

			if (ngx_strncmp(ykey, r->headers_in.passwd.data, 12) == 0) {
				rc = ykclient_request (ykc, (char*)r->headers_in.passwd.data);

				if (rc!=YKCLIENT_OK) {
        			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    			  "ykclient error: %s",
                    			  ykclient_strerror(rc));
					ykclient_done (&ykc);
    				ngx_memzero(&alcf->cached_cred[cslot], sizeof(ngx_cached_cred_t));
					return NGX_HTTP_FORBIDDEN;
				}
        	} else {
				if (r->connection->log->log_level & NGX_LOG_DEBUG_HTTP) {
					r->headers_in.passwd.data[12] = '\0';
	   				ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
									"User \"%s\" send \"%s\" is not using key \"%s\"",
									user.data, r->headers_in.passwd.data, ykey);
				}
				return NGX_HTTP_UNAUTHORIZED;
			}
		} else {
			/* User not found in file */
			ykclient_done (&ykc);
			/* return ngx_http_auth_yubikey_set_realm(r, &alcf->realm); */
			return NGX_HTTP_FORBIDDEN;
		}
	}

	ykclient_done (&ykc);

	/* Yes, we have a valid user and a valid OTP password */
    return NGX_OK;
}

static ngx_int_t
ngx_http_auth_yubikey_set_realm(ngx_http_request_t *r, ngx_str_t *realm)
{
    r->headers_out.www_authenticate = ngx_list_push(&r->headers_out.headers);
    if (r->headers_out.www_authenticate == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    r->headers_out.www_authenticate->hash = 2;
    ngx_str_set(&r->headers_out.www_authenticate->key, "WWW-Authenticate");
    r->headers_out.www_authenticate->value = *realm;

    return NGX_HTTP_UNAUTHORIZED;
}

static void *
ngx_http_auth_yubikey_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_auth_yubikey_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_auth_yubikey_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }
	conf->ttl = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_http_auth_yubikey_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_auth_yubikey_loc_conf_t  *prev = parent;
    ngx_http_auth_yubikey_loc_conf_t  *conf = child;

    if (conf->realm.data == NULL) {
        conf->realm = prev->realm;
    }

	ngx_conf_merge_value(conf->ttl, prev->ttl, NGX_YUBIKEY_TTL);

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_auth_yubikey_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_auth_yubikey_handler;

    return NGX_OK;
}


static char *
ngx_http_auth_yubikey(ngx_conf_t *cf, void *post, void *data)
{
    ngx_str_t  *realm = data;

    size_t   len;
    u_char  *basic, *p;

    if (ngx_strcmp(realm->data, "off") == 0) {
        ngx_str_set(realm, "");
        return NGX_CONF_OK;
    }

    len = sizeof("Basic realm=\"") - 1 + realm->len + 1;

    basic = ngx_pnalloc(cf->pool, len);
    if (basic == NULL) {
        return NGX_CONF_ERROR;
    }

    p = ngx_cpymem(basic, "Basic realm=\"", sizeof("Basic realm=\"") - 1);
    p = ngx_cpymem(p, realm->data, realm->len);
    *p = '"';

    realm->len = len;
    realm->data = basic;

    return NGX_CONF_OK;
}

static char *
ngx_http_auth_yubikey_user_file(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_auth_yubikey_loc_conf_t *alcf = conf;

    ngx_str_t                         *value;
    ngx_http_compile_complex_value_t   ccv;

    if (alcf->user_file.value.len) {
        return "is duplicate";
    }

    value = cf->args->elts;

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &alcf->user_file;
    ccv.zero = 1;
    ccv.conf_prefix = 1;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

static void
ngx_http_auth_yubikey_close(ngx_file_t *file)
{
    if (ngx_close_file(file->fd) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, file->log, ngx_errno,
                      ngx_close_file_n " \"%s\" failed", file->name.data);
    }
}


/* vim: set ts=4 sw=8 tw=0 noet :*/
