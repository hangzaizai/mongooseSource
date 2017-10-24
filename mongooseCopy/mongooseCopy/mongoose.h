//
//  mongoose.c
//  mongooseCopy
//
//  Created by xtkj20170918 on 24/10/17.
//  Copyright © 2017年 mySelf. All rights reserved.
//

#ifndef __MONGOOSE__H
#define __MONGOOSE__H

#include <stdio.h>

struct mg_context;   /* handle for tht http service itself */

struct mg_connection;  /* handle for infividual for connection */

struct mg_request_info
{
    char    *request_method;    /* "GET","POST" */
    char    *uri;               /* normalized URI*/
    char    *query_string;      /*  \0 - terminated */
    char    *post_data;         /* POST data buffer */
    char    *remote_user;       /* authenticated user */
    long    remote_ip;          /* client,s IP address */
    int     remote_port;        /* client,t port */
    int     post_data_len;      /* POST buffer length */
    int     http_version_major;
    int     http_version_minor;
    int     status_code;        /* HTTP status code */
    int     num_headers;        /* number of headers */
    struct  mg_header{
        char    *name;          /* hTTP header name */
        char    *value;         /* HTTP header value */
    }http_headers[64];
};

/*
 user-defined callback function prototype for URI handling,error handling
 */
typedef void (*mg_callback_t)(struct mg_connection *,const struct mg_request_info *info,void *user_data);

/* start the wev server 
 * this must be the first fuction called by the application
 * it creates a serving thread,and returns a context structure that 
 * can be used to alter the configration and stop the server
 */
struct mg_context *mg_start(void);

/*
 * stop the web server
 * must be caled last,when an application wants to stop the web server and
 * release all asscoiated resources.this function blocks until all mongoose
 * threads are stopped.context pointer becomes invalid
 */
void mg_stop(struct mg_context *);

/*
 * return current value of aparticular option
 */
const char *mg_get_option(const struct mg_context *,const char *option_name);

int mg_set_option(struct mg_context *,const char *opt_name,const char *value);

int mg_modify_password_file(struct mg_context *ctx,const char *file_name,const char *user_name,const char *password);

void mg_set_uri_callback(struct mg_context *ctx,const char *uri_regex,mg_callback_t func,void *user_data);

/*
 * Register HTTP error handler.
 * An application may use that function if it wants to customize the error
 * page that user gets on the browser (for example, 404 File Not Found message).
 * It is possible to specify a error handler for all errors by passing 0 as
 * error_code. That '0' error handler must be set last, if more specific error
 * handlers are also used. The actual error code value can be taken from
 * the request info structure that is passed to the callback.
 */
void mg_set_error_callback(struct mg_context *ctx, int error_code,
                           mg_callback_t func, void *user_data);


/*
 * Register authorization handler.
 * This function provides a mechanism to implement custom authorization,
 * for example cookie based (look at examples/authorization.c).
 * The callback function must analyze the request, and make its own judgement
 * on wether it should be authorized or not. After the decision is made, a
 * callback must call mg_authorize() if the request is authorized.
 */
void mg_set_auth_callback(struct mg_context *ctx, const char *uri_regex,
                          mg_callback_t func, void *user_data);


/*
 * Register log handler.
 * By default, Mongoose logs all error messages to stderr. If "error_log"
 * option is specified, the errors are written in the specified file. However,
 * if an application registers its own log handler, Mongoose will not log
 * anything but call the handler function, passing an error message as
 * "user_data" callback argument.
 */
void mg_set_log_callback(struct mg_context *ctx, mg_callback_t func);


/*
 * Register SSL password handler.
 * This is needed only if SSL certificate asks for a password. Instead of
 * prompting for a password on a console a specified function will be called.
 */
typedef int (*mg_spcb_t)(char *buf, int num, int w, void *key);
void mg_set_ssl_password_callback(struct mg_context *ctx, mg_spcb_t func);


/*
 * Send data to the browser.
 * Return number of bytes sent. If the number of bytes sent is less then
 * requested or equals to -1, network error occured, usually meaning the
 * remote side has closed the connection.
 */
int mg_write(struct mg_connection *, const void *buf, int len);


/*
 * Send data to the browser using printf() semantics.
 * Works exactly like mg_write(), but allows to do message formatting.
 * Note that mg_printf() uses internal buffer of size MAX_REQUEST_SIZE
 * (8 Kb by default) as temporary message storage for formatting. Do not
 * print data that is bigger than that, otherwise it will be truncated.
 * Return number of bytes sent.
 */
int mg_printf(struct mg_connection *, const char *fmt, ...);


/*
 * Get the value of particular HTTP header.
 * This is a helper function. It traverses request_info->http_headers array,
 * and if the header is present in the array, returns its value. If it is
 * not present, NULL is returned.
 */
const char *mg_get_header(const struct mg_connection *, const char *hdr_name);


/*
 * Authorize the request.
 * See the documentation for mg_set_auth_callback() function.
 */
void mg_authorize(struct mg_connection *);


/*
 * Get a value of particular form variable.
 * Both query string (whatever comes after '?' in the URL) and a POST buffer
 * are scanned. If a variable is specified in both query string and POST
 * buffer, POST buffer wins. Return value:
 *	NULL      if the variable is not found
 *	non-NULL  if found. NOTE: this returned value is dynamically allocated
 *		  and is subject to mg_free() when no longer needed. It is
 *		  an application's responsibility to mg_free() the variable.
 */
char *mg_get_var(const struct mg_connection *, const char *var_name);


/*
 * Free up memory returned by mg_get_var().
 */
void mg_free(char *var);


/*
 * Return Mongoose version.
 */
const char *mg_version(void);


/*
 * Print command line usage string.
 */
void mg_show_usage_string(FILE *fp);

#endif

