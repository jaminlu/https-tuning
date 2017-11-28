基于cavium 加速卡，对nginx 源码做了相关修改如下：
diff -Nur nginx-1.9.9/src/event/ngx_event.h nginx-1.9.9_mod/src/event/ngx_event.h
--- nginx-1.9.9/src/event/ngx_event.h	2015-12-09 09:47:21.000000000 -0500
+++ nginx-1.9.9_mod/src/event/ngx_event.h	2016-12-20 14:08:24.560678962 -0500
@@ -15,6 +15,9 @@
 
 #define NGX_INVALID_INDEX  0xd0d0d0d0
 
+#ifdef CAVIUM_ASYNC_SUPPORT
+#define CAVIUM_DELAY_TIMEOUT 10
+#endif
 
 #if (NGX_HAVE_IOCP)
 
@@ -108,6 +111,11 @@
     unsigned         available:1;
 #endif
 
+#ifdef CAVIUM_ASYNC_SUPPORT
+    unsigned int cavium_poll_timeout;
+    unsigned int cavium_keepalive_timeout;
+#endif
+
     ngx_event_handler_pt  handler;
 
 
diff -Nur nginx-1.9.9/src/event/ngx_event_openssl.c nginx-1.9.9_mod/src/event/ngx_event_openssl.c
--- nginx-1.9.9/src/event/ngx_event_openssl.c	2015-12-09 09:47:21.000000000 -0500
+++ nginx-1.9.9_mod/src/event/ngx_event_openssl.c	2016-12-20 14:08:24.561678956 -0500
@@ -8,7 +8,9 @@
 #include <ngx_config.h>
 #include <ngx_core.h>
 #include <ngx_event.h>
-
+#ifdef CAVIUM_ASYNC_SUPPORT
+#include <openssl/cav_ssl.h>
+#endif
 
 #define NGX_SSL_PASSWORD_BUFFER_SIZE  4096
 
@@ -1052,6 +1054,10 @@
         return NGX_ERROR;
     }
 
+#ifdef CAVIUM_ASYNC_SUPPORT
+   cav_set_nb_mode(sc->connection, 1);
+#endif
+
     if (flags & NGX_SSL_CLIENT) {
         SSL_set_connect_state(sc->connection);
 
@@ -1176,6 +1182,14 @@
 
     sslerr = SSL_get_error(c->ssl->connection, n);
 
+#ifdef CAVIUM_ASYNC_SUPPORT
+    if(sslerr == SSL_ERROR_WANT_CAVIUM_CRYPTO) {
+        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "SSL_get_error: %d", sslerr);
+        c->read->handler = ngx_ssl_handshake_handler;
+        c->write->handler = ngx_ssl_handshake_handler;
+        return NGX_AGAIN;
+    }
+#endif
     ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "SSL_get_error: %d", sslerr);
 
     if (sslerr == SSL_ERROR_WANT_READ) {
@@ -1241,6 +1255,7 @@
     ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                    "SSL handshake handler: %d", ev->write);
 
+#ifndef CAVIUM_ASYNC_SUPPORT
     if (ev->timedout) {
         c->ssl->handler(c);
         return;
@@ -1249,7 +1264,19 @@
     if (ngx_ssl_handshake(c) == NGX_AGAIN) {
         return;
     }
-
+#else
+    ev->cavium_poll_timeout += CAVIUM_DELAY_TIMEOUT;
+    if (ev->cavium_poll_timeout  > c->listening->post_accept_timeout) {
+        c->ssl->handler(c);
+        return;
+    }
+    if (ngx_ssl_handshake(c) == NGX_AGAIN) {
+        ngx_add_timer(ev, CAVIUM_DELAY_TIMEOUT);
+        return;
+    }
+    ev->cavium_poll_timeout = 0;
+    ev->timedout = 0;
+#endif
     c->ssl->handler(c);
 }
 
@@ -1443,6 +1470,11 @@
 
     ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "SSL_get_error: %d", sslerr);
 
+#ifdef CAVIUM_ASYNC_SUPPORT
+    if(sslerr == SSL_ERROR_WANT_CAVIUM_CRYPTO) {
+        return NGX_AGAIN;
+    }
+#endif
     if (sslerr == SSL_ERROR_WANT_READ) {
         c->read->ready = 0;
         return NGX_AGAIN;
@@ -1699,6 +1731,13 @@
     err = (sslerr == SSL_ERROR_SYSCALL) ? ngx_errno : 0;
 
     ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "SSL_get_error: %d", sslerr);
+#ifdef CAVIUM_ASYNC_SUPPORT
+    if(sslerr == SSL_ERROR_WANT_CAVIUM_CRYPTO) {
+        c->write->ready = 0;
+        c->write->active = 0;
+        return NGX_AGAIN;
+    }
+#endif
 
     if (sslerr == SSL_ERROR_WANT_WRITE) {
         c->write->ready = 0;
diff -Nur nginx-1.9.9/src/http/ngx_http_request.c nginx-1.9.9_mod/src/http/ngx_http_request.c
--- nginx-1.9.9/src/http/ngx_http_request.c	2015-12-09 09:47:21.000000000 -0500
+++ nginx-1.9.9_mod/src/http/ngx_http_request.c	2016-12-20 14:27:01.483343534 -0500
@@ -384,20 +384,26 @@
     c = rev->data;
 
     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http wait request handler");
+    hc = c->data;
+    cscf = ngx_http_get_module_srv_conf(hc->conf_ctx, ngx_http_core_module);
 
+#ifdef CAVIUM_ASYNC_SUPPORT
+    if(rev->cavium_poll_timeout > cscf->client_header_timeout) {
+#else 
     if (rev->timedout) {
+#endif
         ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "client timed out");
         ngx_http_close_connection(c);
         return;
     }
-
+#ifdef CAVIUM_ASYNC_SUPPORT
+   rev->timedout = 0;
+#endif
     if (c->close) {
         ngx_http_close_connection(c);
         return;
     }
 
-    hc = c->data;
-    cscf = ngx_http_get_module_srv_conf(hc->conf_ctx, ngx_http_core_module);
 
     size = cscf->client_header_buffer_size;
 
@@ -429,6 +435,11 @@
 
     if (n == NGX_AGAIN) {
 
+#ifdef CAVIUM_ASYNC_SUPPORT
+	rev->cavium_poll_timeout += CAVIUM_DELAY_TIMEOUT;
+	ngx_add_timer(rev, CAVIUM_DELAY_TIMEOUT);
+#endif
+
         if (!rev->timer_set) {
             ngx_add_timer(rev, c->listening->post_accept_timeout);
             ngx_reusable_connection(c, 1);
@@ -463,6 +474,9 @@
     }
 
     b->last += n;
+#ifdef CAVIUM_ASYNC_SUPPORT
+    rev->cavium_poll_timeout = 0;
+#endif
 
     if (hc->proxy_protocol) {
         hc->proxy_protocol = 0;
@@ -653,7 +667,6 @@
     if (n == -1) {
         if (err == NGX_EAGAIN) {
             rev->ready = 0;
-
             if (!rev->timer_set) {
                 ngx_add_timer(rev, c->listening->post_accept_timeout);
                 ngx_reusable_connection(c, 1);
@@ -718,6 +731,10 @@
             rc = ngx_ssl_handshake(c);
 
             if (rc == NGX_AGAIN) {
+#ifdef CAVIUM_ASYNC_SUPPORT
+	        rev->cavium_poll_timeout += CAVIUM_DELAY_TIMEOUT;
+                ngx_add_timer(rev, 10);
+#endif
 
                 if (!rev->timer_set) {
                     ngx_add_timer(rev, c->listening->post_accept_timeout);
@@ -918,20 +935,31 @@
     ngx_str_t            host;
     ngx_connection_t    *c;
     ngx_http_request_t  *r;
+#ifdef CAVIUM_ASYNC_SUPPORT
+    ngx_http_core_srv_conf_t *cscf;
+#endif
 
     c = rev->data;
     r = c->data;
 
     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, rev->log, 0,
                    "http process request line");
+#ifdef CAVIUM_ASYNC_SUPPORT
+    cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);
 
+    if(rev->cavium_poll_timeout > cscf->client_header_timeout) {
+#else
     if (rev->timedout) {
+#endif
         ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "client timed out");
         c->timedout = 1;
         ngx_http_close_request(r, NGX_HTTP_REQUEST_TIME_OUT);
         return;
     }
 
+#ifdef CAVIUM_ASYNC_SUPPORT
+    rev->timedout = 0;
+#endif
     rc = NGX_AGAIN;
 
     for ( ;; ) {
@@ -1388,6 +1416,10 @@
     }
 
     if (n == NGX_AGAIN) {
+#ifdef CAVIUM_ASYNC_SUPPORT 
+	rev->cavium_poll_timeout += CAVIUM_DELAY_TIMEOUT;
+	ngx_add_timer(rev, CAVIUM_DELAY_TIMEOUT);
+#endif
         if (!rev->timer_set) {
             cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);
             ngx_add_timer(rev, cscf->client_header_timeout);
@@ -3058,7 +3090,12 @@
     c->idle = 1;
     ngx_reusable_connection(c, 1);
 
+#ifdef CAVIUM_ASYNC_SUPPORT
+    rev->cavium_keepalive_timeout = clcf->keepalive_timeout;
+    rev->cavium_poll_timeout = 0;
+#else
     ngx_add_timer(rev, clcf->keepalive_timeout);
+#endif
 
     if (rev->ready) {
         ngx_post_event(rev, &ngx_posted_events);
@@ -3078,11 +3115,18 @@
 
     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http keepalive handler");
 
+#ifdef CAVIUM_ASYNC_SUPPORT
+    if(rev->cavium_poll_timeout > rev->cavium_keepalive_timeout || c->close) {
+#else 
     if (rev->timedout || c->close) {
+#endif
         ngx_http_close_connection(c);
         return;
     }
 
+#ifdef CAVIUM_ASYNC_SUPPORT
+   rev->timedout = 0;
+#endif
 #if (NGX_HAVE_KQUEUE)
 
     if (ngx_event_flags & NGX_USE_KQUEUE_EVENT) {
@@ -3137,6 +3181,10 @@
     c->log_error = NGX_ERROR_INFO;
 
     if (n == NGX_AGAIN) {
+#ifdef CAVIUM_ASYNC_SUPPORT
+	rev->cavium_poll_timeout += CAVIUM_DELAY_TIMEOUT;
+	ngx_add_timer(rev, CAVIUM_DELAY_TIMEOUT);
+#endif
         if (ngx_handle_read_event(rev, 0) != NGX_OK) {
             ngx_http_close_connection(c);
             return;
@@ -3190,7 +3238,11 @@
     c->sent = 0;
     c->destroyed = 0;
 
+#ifdef CAVIUM_ASYNC_SUPPORT
+    rev->cavium_poll_timeout = 0;
+#else
     ngx_del_timer(rev);
+#endif
 
     rev->handler = ngx_http_process_request_line;
     ngx_http_process_request_line(rev);
