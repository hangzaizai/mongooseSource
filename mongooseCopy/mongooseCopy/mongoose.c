//
//  mongoose.c
//  mongooseCopy
//
//  Created by xtkj20170918 on 24/10/17.
//  Copyright © 2017年 mySelf. All rights reserved.
//

#include "mongoose.h"

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>

#include <time.h>
#include <stdlib.h>
#include <stdarg.h>
#include <assert.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>
#include <stddef.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>




#define MONGOOSE_VERSION                        "2.8"
#define PASSWORDS_FILE_NAME                     ".htpasswd"
#define CGI_ENVIRONMENT_SIZE                    4096
#define MAX_CGI_ENVIR_VARS                      64
#define MAX_REQUEST_SIZE                        8192
#define MAX_LISTENING_SOCKETS                   (10)
#define MAX_CALLBACKS                           (20)
#define ARRAY_SIZE(array)                       (sizeof(array)/array[0])

typedef int  bool_t;
typedef int SOCKET;


#if !defined(FALSE)
enum{FALSE,TRUE};
#endif

typedef struct ssl_st       SSL;
typedef struct ssl_method_st    SSL_METHOD;
typedef struct ssl_ctx_st SSL_CTX;

/* dynamically loaded SSL fuctionality */
struct ssl_func
{
    const char *name; /* SSL function name*/
    void       (*ptr)(void); /* function pointer*/
};

static struct ssl_func ssl_sw[] =
{
    {"SSL_free",			NULL},
    {"SSL_accept",			NULL},
    {"SSL_connect",			NULL},
    {"SSL_read",			NULL},
    {"SSL_write",			NULL},
    {"SSL_get_error",		NULL},
    {"SSL_set_fd",			NULL},
    {"SSL_new",			NULL},
    {"SSL_CTX_new",			NULL},
    {"SSLv23_server_method",	NULL},
    {"SSL_library_init",		NULL},
    {"SSL_CTX_use_PrivateKey_file",	NULL},
    {"SSL_CTX_use_certificate_file",NULL},
    {"SSL_CTX_set_default_passwd_cb",NULL},
    {"SSL_CTX_free",		NULL},
    {NULL,				NULL}
};

static struct ssl_func crypto_sw[] =
{
    {"CRYPTO_num_locks",		NULL},
    {"CRYPTO_set_locking_callback",	NULL},
    {"CRYPTO_set_id_callback",	NULL},
    {NULL,				NULL}
};

/*
 Month names
 */
static const char *month_names[] =
{
    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
};

/*
 unified socket address. for IPV6 support,add IPv6 address structure
 *in the union u.
 */
struct usa
{
    socklen_t len;
    union {
        struct sockaddr sa;
        struct sockaddr_in sin;
    }u;
};

/*
 *specifies a string (chunk of memory).
 *used to traverse comma separated lists of options
 */
struct vec
{
    const char  *ptr;
    size_t      len;
};

/*
 structure used by mg_stat() function uses 64bit file length
 */
struct mgstat
{
    bool_t          is_directory;  /* directory marker */
    uint64_t        size;          /* file size */
    time_t          mtime;         /* modification time */
};

struct mg_option
{
    const char *name;
    const char *description;
    const char *default_value;
    int        index;
    bool_t (*setter)(struct mg_context *,const char *);
};

/*
 numberic indexes for the option values in context,ctx->options
 */
enum mg_option_index
{
    OPT_ROOT, OPT_INDEX_FILES, OPT_PORTS, OPT_DIR_LIST, OPT_CGI_EXTENSIONS,
    
    OPT_CGI_INTERPRETER, OPT_CGI_ENV, OPT_SSI_EXTENSIONS, OPT_AUTH_DOMAIN,
    OPT_AUTH_GPASSWD, OPT_AUTH_PUT, OPT_ACCESS_LOG, OPT_ERROR_LOG,
    OPT_SSL_CERTIFICATE, OPT_ALIASES, OPT_ACL, OPT_UID, OPT_PROTECT,
    OPT_SERVICE, OPT_HIDE, OPT_ADMIN_URI, OPT_MAX_THREADS, OPT_IDLE_TIME,
    OPT_MIME_TYPES,
    NUM_OPTIONS
};

struct socket
{
    SOCKET          sock;   /* listening socket */
    struct usa      lsa;    /* local socket address */
    struct usa      rsa;    /* remote socket address */
    bool_t          is_ssl;  /* is socket ssl-ed */
};

struct callback
{
    char            *uri_regex;   /* URI regex to handel */
    mg_callback_t   func;         /* user callback */
    bool_t          is_auth;      /* func is auth checker */
    int             status_code;  /* error code to handle */
    void            *user_data;   /* opaque user data */
};

struct mg_context
{
    int                 stop_flag;    /* should we stop event loop */
    SSL_CTX             *ssl_ctx;     /* SSL context */
    
    FILE                *access_log;  /* opened access log */
    FILE                *error_log;   /* opened error log */
    
    struct socket       listeners[MAX_LISTENING_SOCKETS];
    int                 num_listeners;
    
    struct callback     callbacks[MAX_CALLBACKS];
    int                 num_callbacks;
    
    char                *options[NUM_OPTIONS];  /*congifured opions*/
    pthread_mutex_t     opt_mutex[NUM_OPTIONS]; /* option ptotector */
    
    int                 max_threads;            /*maxmum number of threads */
    int                 num_threads;            /* number of threads */
    int                 num_idle;               /* number of idle threads */
    pthread_mutex_t     thr_mutex;              /* ptotects (max|num)_threads*/
    pthread_cond_t      thr_cond;
    pthread_mutex_t     bind_mutex;             /* ptotects bind operations */

    struct socket       queue[20];                    /* accepted sockets */
    int                 sq_head;                    /*head of the socket queue */
    int                 sq_tail;                /* tail of the socket queue */
    pthread_cond_t      empty_cond;             /* socket queue tmpty condvar */
    pthread_cond_t      full_cond;              /* socket queuq full condvar */
    
    mg_spcb_t           ssl_password_callback;
    mg_callback_t       log_callback;
};

/* client connection */
struct mg_connection
{
    struct mg_request_info      request_info;
    struct mg_context           *ctx;
    SSL                         *ssl;   /*SSL descriptor*/
    struct  socket              client;  /* connected client */
    time_t                      birth_time;  /*time connection was accepted*/
    bool_t                      free_post_data;  /*post_data was malloc-ed*/
    bool_t                      enbedded_auth;    /*used for authorization */
    uint64_t                    num_bytes_send;   /*total byres sent to client */
};


/*print error message to the opend error log stream */
static void cry(struct mg_connection *conn,const char *fmt,...)
{
    char            buf[BUFSIZ];
    va_list         ap;
    
    va_start(ap, fmt);
    (void)vsnprintf(buf, sizeof(buf), fmt, ap);
    conn->ctx->log_callback(conn,&conn->request_info,buf);
    va_end(ap);
}

/*
 return fake connection structure used for logging if connection
 * is not applicable at the moment of logging
 */
static struct mg_connection *fc(struct mg_context *ctx)
{
    static struct mg_connection fake_connection;
    fake_connection.ctx = ctx;
    return  (&fake_connection);
}

/*
 * if an embedded code does not intercept logging by calling
 * mg_set_log_callback(),this fuction is used for logging,
 * it print stuff to the con->error_log,which is stderr unless "error_log"
 * option was set
 */
static void builtin_error_log(struct mg_connection *conn,const struct mg_request_info *request_info,void * message)
{
    FILE        *fp;
    time_t      timestamp;
    
    fp = conn->ctx->error_log;
    flockfile(fp);
    
    timestamp = time(NULL);
    
    (void)fprintf(fp, "[%010lu] [error] [client %s] ",(unsigned long)timestamp,inet_ntoa(conn->client.rsa.u.sin.sin_addr));
    
    if ( request_info->request_method != NULL ) {
        (void)fprintf(fp, "%s %s: ",request_info->request_method,request_info->uri);
    }
    
    (void)fprintf(fp, "%s",(char *)message);
    
    fputc('\n', fp);
    
    funlockfile(fp);
    
}

const char *mg_version(void)
{
    return (MONGOOSE_VERSION);
}

static void mg_strlcpy(register char *dst,register const char *src,size_t n)
{
    for (; *src != '\0' && n > 1 ; n-- ) {
        *dst++ = *src++;
    }
    
    *dst = '\0';
}

static int lowercase(const char *s)
{
    return (tolower(*(unsigned char *)s));
}

static int mg_strncasecmp(const char *s1,const char *s2,size_t len)
{
    int diff = 0;
    
    if ( len > 0 ) {
        do {
            diff = lowercase(s1++) - lowercase(s2++);
        } while ( diff == 0 && s1[-1] != '\0' && --len > 0 );
    }
    
    return (diff);
}

static int mg_strcasecmp(const char *s1,const char *s2)
{
    int diff;
    
    do {
        diff = lowercase(s1++) - lowercase(s2++);
    } while (diff == 0 && s1[-1] != '\0');
    
    return (diff);
}


static char *
mg_strndup(const char *ptr, size_t len)
{
    char	*p;
    
    if ((p = (char *) malloc(len + 1)) != NULL)
        mg_strlcpy(p, ptr, len + 1);
    
    return (p);
    
}

static char *
mg_strdup(const char *str)
{
    return (mg_strndup(str, strlen(str)));
}


/*
 * Like snprintf(), but never returns negative value, or the value
 * that is larger than a supplied buffer.
 * Thanks to Adam Zeldis to pointing snprintf()-caused vulnerability
 * in his audit report.
 */
static int
mg_vsnprintf(struct mg_connection *conn,
             char *buf, size_t buflen, const char *fmt, va_list ap)
{
    int	n;
    
    if (buflen == 0)
        return (0);
    
    n = vsnprintf(buf, buflen, fmt, ap);
    
    if (n < 0) {
        cry(conn, "vsnprintf error");
        n = 0;
    } else if (n >= (int) buflen) {
        cry(conn, "truncating vsnprintf buffer: [%.*s]",
            n > 200 ? 200 : n, buf);
        n = (int) buflen - 1;
    }
    buf[n] = '\0';
    
    return (n);
}

static int
mg_snprintf(struct mg_connection *conn,
            char *buf, size_t buflen, const char *fmt, ...)
{
    va_list	ap;
    int	n;
    
    va_start(ap, fmt);
    n = mg_vsnprintf(conn, buf, buflen, fmt, ap);
    va_end(ap);
    
    return (n);
}

static bool_t is_true(const char *str)
{
    static const char	*trues[] = {"1", "yes", "true", "ja", NULL};
    int			i;
    
    for (i = 0; trues[i] != NULL; i++)
        if (str != NULL && mg_strcasecmp(str, trues[i]) == 0)
            return (TRUE);
    
    return (FALSE);
}

/*
 * Skip the characters until one of the delimiters characters found.
 * 0-terminate resulting word. Skip the rest of the delimiters if any.
 * Advance pointer to buffer to the next word. Return found 0-terminated word.
 */
static char *
skip(char **buf, const char *delimiters)
{
    char	*p, *begin_word, *end_word, *end_delimiters;
    
    begin_word = *buf;
    end_word = begin_word + strcspn(begin_word, delimiters);
    end_delimiters = end_word + strspn(end_word, delimiters);
    
    for (p = end_word; p < end_delimiters; p++)
        *p = '\0';
    
    *buf = end_delimiters;
    
    return (begin_word);
}

/* return HTTP header value or null if not found */
static const char *get_header(const struct mg_request_info *ri,const char *name)
{
    int         i;
    for ( i=0 ; i < ri->num_headers; i++ ) {
        if ( mg_strcasecmp(name, ri->http_headers[i].name)) {
            return (ri->http_headers[i].value);
        }
    }
    
    return  (NULL);
}

const char *mg_get_header(const struct mg_connection *conn, const char *hdr_name)
{
    return (get_header(&conn->request_info, hdr_name));
}
