#include <stdio.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_connect.h>
#include <ngx_event_pipe.h>
#include <ngx_http.h>

static ngx_http_module_t  ngx_http_mytest_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                   /* create main configuration */
    NULL,                                   /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};

static ngx_command_t  ngx_http_mytest_commands[] = {
    {
        ngx_string("mytest"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF|NGX_CONF_NOARGS,
        ngx_http_test,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL
    },
    ngx_null_command
};



ngx_module_t  ngx_http_mytest_module = {
    NGX_MODULE_V1,
    &ngx_http_mytest_module_ctx,             /* module context */
    ngx_http_mytest_commands,                /* module directives */
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

static char*
ngx_http_mytest(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t *clcf;
    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_mytest_handler;

    return NGX_CONF_OK;
}

static ngx_int_t ngx_http_mytest_handler(ngx_http_request_t *r)
{
    if(! (r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD)) )
    {
        return NGX_HTTP_NOT_ALLOWED;
    }

    //丢弃包体
    ngx_int_t rc = ngx_http_discard_request_body(r);
    if(rc != NGX_OK)
    {
        return rc;
    }

    //设置Content-Type
    ngx_str_t type = ngx_string("text/plain");
    //返回包体内容
    ngx_str_t response = ngx_string("Hello World!");
    //设置返回状态码
    r->headers_out.status = NGX_HTTP_OK;
    //设置包体长度
    r->headers_out.content_length_n = response.len;
    r->headers_out.content_type = type;

    //发送http头部
    rc = ngx_http_send_header(r);
    if(rc ==  NGX_ERROR || rc > NGX_OK || r->header_only)
    {
        return rc;
    }

    //构造ngx_buf_t准备发送包体
    ngx_buf_t *b;
    b = ngx_create_temp_buf(r->pool, response.len);
    if(b == NULL)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    //这里copy一次是因为nginx是全异步的，所以response中的内存离开这个函数时很可能就被释放的
    ngx_memcopy(b->pos, response->data, response.len);
    b->last = b->pos + response.len;
    b->last_buf = 1;

    //构造发送时的ngx_chain_t结构体
    ngx_chain_t out;
    out.buf = b;
    //这个next必须设置为NULL，否则这个请求不会结束
    out.next = NULL;

    //发送包体，发送结束后http框架会调用ngx_http_finalize_request方法结束请求
    return ngx_http_output_filter(r, &out);
}

