#include <stdio.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_connect.h>
#include <ngx_event_pipe.h>
#include <ngx_http.h>

static void* ngx_http_myupstream_create_loc_conf(ngx_conf_t *cf);
ngx_int_t myupstream_create_request(ngx_http_request_t *r);
ngx_int_t myupstream_process_status_line(ngx_http_request_t *r);
ngx_int_t myupstream_process_header(ngx_http_request_t *r);
static void myupstream_finalize_request(ngx_http_request_t *r, ngx_int_t rc);
static char* ngx_http_myupstream(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
typedef struct {
    ngx_http_upstream_conf_t upstream;
} ngx_http_myupstream_conf_t;

typedef struct {
    ngx_http_status_t status;
    ngx_str_t backendServer;
} ngx_http_myupstream_ctx_t;

static ngx_http_module_t  ngx_http_myupstream_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                   /* create main configuration */
    NULL,                                   /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_myupstream_create_loc_conf,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};

static ngx_command_t  ngx_http_myupstream_commands[] = {
    {
        ngx_string("myupstream"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF|NGX_CONF_NOARGS,
        ngx_http_myupstream,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL
    },
    {
        ngx_string("connect_timeout"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_msec_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_myupstream_conf_t, upstream.connect_timeout),
        NULL
    },
    {
        ngx_string("send_timeout"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_msec_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_myupstream_conf_t, upstream.send_timeout),
        NULL
    },
    {
        ngx_string("read_timeout"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_msec_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_myupstream_conf_t, upstream.read_timeout),
        NULL
    },
    {
        ngx_string("store_access"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE123,
        ngx_conf_set_access_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_myupstream_conf_t, upstream.store_access),
        NULL
    },
    {
        ngx_string("buffering"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_num_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_myupstream_conf_t, upstream.buffering),
        NULL
    },
    {
        ngx_string("bufs_num"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_num_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_myupstream_conf_t, upstream.bufs.num),
        NULL
    },
    {
        ngx_string("bufs_size"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_size_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_myupstream_conf_t, upstream.bufs.size),
        NULL
    },
    {
        ngx_string("buffer_size"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_size_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_myupstream_conf_t, upstream.buffer_size),
        NULL
    },
    {
        ngx_string("busy_buffers_size"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_size_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_myupstream_conf_t, upstream.busy_buffers_size),
        NULL
    },
    {
        ngx_string("temp_file_write_size "),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_size_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_myupstream_conf_t, upstream.temp_file_write_size),
        NULL
    },
    {
        ngx_string("max_temp_file_size"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_size_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_myupstream_conf_t, upstream.max_temp_file_size),
        NULL
    },
    ngx_null_command
};



ngx_module_t  ngx_http_myupstream_module = {
    NGX_MODULE_V1,
    &ngx_http_myupstream_module_ctx,             /* module context */
    ngx_http_myupstream_commands,                /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static void*
ngx_http_myupstream_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_myupstream_conf_t *mycf;
    mycf = (ngx_http_myupstream_conf_t*)ngx_palloc(cf->pool, sizeof(ngx_http_myupstream_conf_t));
    if(mycf == NULL)
    {
        return NULL;
    }
    mycf->upstream.connect_timeout = NGX_CONF_UNSET_MSEC;
    mycf->upstream.send_timeout = NGX_CONF_UNSET_MSEC;
    mycf->upstream.read_timeout = NGX_CONF_UNSET_MSEC;
    mycf->upstream.store_access = NGX_CONF_UNSET_UINT;

    mycf->upstream.buffering = NGX_CONF_UNSET;
    mycf->upstream.bufs.num = NGX_CONF_UNSET;
    mycf->upstream.bufs.size = NGX_CONF_UNSET_SIZE;
    mycf->upstream.buffer_size = NGX_CONF_UNSET_SIZE;
    mycf->upstream.busy_buffers_size = NGX_CONF_UNSET_SIZE;
    mycf->upstream.temp_file_write_size = NGX_CONF_UNSET_SIZE;
    mycf->upstream.max_temp_file_size = NGX_CONF_UNSET_SIZE;

    mycf->upstream.hide_headers = NGX_CONF_UNSET_PTR;
    mycf->upstream.pass_headers = NGX_CONF_UNSET_PTR;

    return mycf;
}

static ngx_int_t ngx_http_myupstream_handler(ngx_http_request_t *r)
{
    //设置模块上下文结构,第二个参数是ngx_module_t
    ngx_http_myupstream_ctx_t *myctx = ngx_http_get_module_ctx(r, ngx_http_myupstream_module);
    if(myctx == NULL)
    {
        myctx = ngx_palloc(r->pool, sizeof(ngx_http_myupstream_ctx_t));
        if(myctx == NULL)
        {
            return NGX_ERROR;
        }
        ngx_http_set_ctx(r, myctx, ngx_http_myupstream_module);
    }
    
    if(ngx_http_upstream_create(r) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_upstream_create() fialed");
        return NGX_ERROR;
    }

    //获取配置结构体
    ngx_http_myupstream_conf_t *mycf = (ngx_http_myupstream_conf_t*) ngx_http_get_module_loc_conf(r, ngx_http_myupstream_module);
    ngx_http_upstream_t *u = r->upstream;
    u->conf = &mycf->upstream;
    u->buffering = mycf->upstream.buffering;

    //初始化u->resolved
    u->resolved = (ngx_http_upstream_resolved_t*) ngx_palloc(r->pool, sizeof(ngx_http_upstream_resolved_t));
    if(u->resolved == NULL)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "init resolved error: %s", strerror(errno)); 
        return NGX_ERROR;
    }

    //设置www.google.com
    static struct sockaddr_in backendSockAddr;
    struct hostent *pHost = gethostbyname((char *)"www.google.com");
    if(pHost == NULL)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "gethostbyname error: %s", strerror(errno)); 
        return NGX_ERROR;
    }

    backendSockAddr.sin_family = AF_INET;
    backendSockAddr.sin_port = htons((in_port_t)80);

    char *pDmsIP = inet_ntoa(*(struct in_addr*) (pHost->h_addr_list[0]));
    backendSockAddr.sin_addr.s_addr = inet_addr(pDmsIP);
    myctx->backendServer.data = (u_char*)pDmsIP;
    myctx->backendServer.len = strlen(pDmsIP);

    //将地址设置到resolved成员
    u->resolved->sockaddr = (struct sockaddr*)&backendSockAddr;
    u->resolved->socklen = sizeof(struct sockaddr_in);
    u->resolved->naddrs = 1;

    //设置三个回调方法
    u->create_request = myupstream_create_request;
    u->process_header = myupstream_process_status_line;
    u->finalize_request = myupstream_finalize_request;

    r->main->count++;
    ngx_http_upstream_init(r);

    return NGX_DONE;
}

static char*
ngx_http_myupstream(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t *clcf;
    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_myupstream_handler;

    return NGX_CONF_OK;
}



//构造发往上游服务器的请求
ngx_int_t 
myupstream_create_request(ngx_http_request_t *r)
{
    static ngx_str_t backendQueryLine = ngx_string("GET /search?q=%V HTTP/1.1\r\nHost: www.google.com\r\nConnection: close\r\n\r\n");
    ngx_int_t queryLineLen = backendQueryLine.len + r->args.len - 2;

    ngx_buf_t *b = ngx_create_temp_buf(r->pool, queryLineLen);
    if(b == NULL)
        return NGX_ERROR;

    //因为请求可能要调用多次epoll，所以不能放在堆中
    b->last = b->pos + queryLineLen;
    ngx_snprintf(b->pos, queryLineLen, (char *)backendQueryLine.data, &r->args);
    
    //发送请求的buf链
    r->upstream->request_bufs = ngx_alloc_chain_link(r->pool);
    if(r->upstream->request_bufs == NULL)
        return NGX_ERROR;
    r->upstream->request_bufs->buf = b;
    r->upstream->request_bufs->next = NULL;

    r->upstream->request_sent = 0;
    r->upstream->header_sent = 0;
    r->header_hash =  1;
    return NGX_OK;
}


ngx_int_t 
myupstream_process_status_line(ngx_http_request_t *r)
{
    size_t len;
    ngx_int_t rc;
    ngx_http_upstream_t *u;

    ngx_http_myupstream_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_myupstream_module);
    if(ctx == NULL)
        return NGX_ERROR;

    u = r->upstream;
    //使用ngx提供的函数将上游返回的字节流解析到ctx->status中
    rc = ngx_http_parse_status_line(r, &u->buffer, &ctx->status);
    if(rc == NGX_AGAIN)
        return rc;
    if(rc == NGX_ERROR)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "upstream sent no valid HTTP/1.0 header");
        r->http_version = NGX_HTTP_VERSION_9;
        //为什么返回ok
        u->state->status = NGX_HTTP_OK;
        return NGX_OK;
    }

    //已经解析到完整的响应头
    if(u->state)
    {
        u->state->status = ctx->status.code;
    }
    u->headers_in.status_n = ctx->status.code;
    len = ctx->status.end - ctx->status.start;
    u->headers_in.status_line.len = len;
    u->headers_in.status_line.data = ngx_palloc(r->pool, len);
    if(u->headers_in.status_line.data == NULL)
    {
        return NGX_ERROR;
    }
    ngx_memcpy(u->headers_in.status_line.data, ctx->status.start, len);
    //其他http头部信息有myupstream_process_header处理
    u->process_header = myupstream_process_header;

    return myupstream_process_header(r);
}

ngx_int_t 
myupstream_process_header(ngx_http_request_t *r)
{
    ngx_int_t rc;
    ngx_table_elt_t *h;
    ngx_http_upstream_header_t *hh;
    ngx_http_upstream_main_conf_t *umcf;

    umcf = ngx_http_get_module_ctx(r, ngx_http_upstream_module);
    
    for(;;)
    {
        rc = ngx_http_parse_header_line(r, &r->upstream->buffer, 1);
        if(rc == NGX_OK)
        {
            //向headers_in.headers这个ngx_list_t中添加HTTP头部
            h = ngx_list_push(&r->upstream->headers_in.headers);
            if(h == NULL)
                return NGX_ERROR;
            h->hash = r->header_hash;
            h->key.len = r->header_name_end - r->header_name_start;
            h->value.len = r->header_end - r->header_start;

            h->key.data = ngx_pnalloc(r->pool, h->key.len + 1 + h->value.len + 1 + h->key.len);
            if(h->key.data == NULL)
                return NGX_ERROR;

            h->value.data = h->key.data + h->key.len + 1;
            h->lowcase_key = h->key.data + h->key.len + 1 + h->value.len + 1;

            ngx_memcpy(h->key.data, r->header_name_start, h->key.len);
            h->key.data[h->key.len] = '\0';
            ngx_memcpy(h->value.data, r->header_start, h->value.len);
            h->value.data[h->value.len] = '\0';

            //lowcase_index的作用？
            if(h->key.len == r->lowcase_index)
            {
                ngx_memcpy(h->lowcase_key, r->lowcase_header, h->key.len);
            }
            else
            {
                ngx_strlow(h->lowcase_key, h->key.data, h->key.len);
            }

            //查找该头部是否在配置文件中
            hh = ngx_hash_find(&umcf->headers_in_hash, h->hash, h->lowcase_key, h->key.len);
            if(hh && hh->handler(r, h, hh->offset) != NGX_OK)
            {
                return NGX_ERROR;
            }
            continue;
        }

        if(rc == NGX_HTTP_PARSE_HEADER_DONE)
        {
            //根据http协议规定server和date头部必须有，如果没有则设置
            if(r->upstream->headers_in.server == NULL)
            {
                h = ngx_list_push(&r->upstream->headers_in.headers);
                if(h == NULL)
                {
                    return NGX_ERROR;
                }
                h->hash = ngx_hash(ngx_hash(ngx_hash(ngx_hash(ngx_hash('s', 'e'), 'r'), 'v'), 'e'), 'r');
                ngx_str_set(&h->key, "Server");
                ngx_str_null(&h->value);
                h->lowcase_key = (u_char*) "server";
            }
            if(r->upstream->headers_in.date == NULL)
            {
                h = ngx_list_push(&r->upstream->headers_in.headers);
                if(h == NULL)
                {
                    return NGX_ERROR;
                }
                h->hash = ngx_hash(ngx_hash(ngx_hash('d', 'a'), 't'), 'e');
                ngx_str_set(&h->key, "Date");
                ngx_str_null(&h->value);
                h->lowcase_key = (u_char*) "date";
            }
            return NGX_OK;
        }
        if(rc == NGX_AGAIN)
        {
            return rc;
        }
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "upstream sent invalid header");
        return NGX_HTTP_UPSTREAM_INVALID_HEADER;
    }
}

static void
myupstream_finalize_request(ngx_http_request_t *r, ngx_int_t rc)
{
    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "myupstream_finalize_request");
}
