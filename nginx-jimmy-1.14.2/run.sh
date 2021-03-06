DIR="/usr/share/nginx2"
./configure --with-cc-opt='-g -O2 -fPIE -fstack-protector-strong -Wformat -Werror=format-security -Wdate-time -D_FORTIFY_SOURCE=2' --with-ld-opt='-Wl,-Bsymbolic-functions -fPIE -pie -Wl,-z,relro -Wl,-z,now' \
 --prefix=${DIR} \
 --conf-path=${DIR}/etc/nginx/nginx.conf \
 --http-log-path=${DIR}/var/log/nginx/access.log \
 --error-log-path=${DIR}/var/log/nginx/error.log \
 --lock-path=${DIR}/var/lock/nginx.lock \
 --pid-path=${DIR}/run/nginx.pid \
 --http-client-body-temp-path=${DIR}/var/lib/nginx/body \
 --http-fastcgi-temp-path=${DIR}/var/lib/nginx/fastcgi \
 --http-proxy-temp-path=${DIR}/var/lib/nginx/proxy \
 --http-scgi-temp-path=${DIR}/var/lib/nginx/scgi \
 --http-uwsgi-temp-path=${DIR}/var/lib/nginx/uwsgi \
 --with-pcre-jit --with-http_ssl_module --with-http_stub_status_module --with-http_realip_module \
 --with-http_auth_request_module --with-http_addition_module --with-http_dav_module --with-http_geoip_module \
 --with-http_gunzip_module --with-http_gzip_static_module --with-http_image_filter_module --with-http_v2_module \
 --with-http_sub_module --with-http_xslt_module --with-stream --with-stream_ssl_module --with-stream_geoip_module \
 --with-stream_ssl_preread_module --with-stream_realip_module --with-file-aio \
 --with-mail --with-mail_ssl_module --with-threads --with-compat \
 --add-module=/suyong1/devel/nginx_mod/nginx-jimmy-1.14.2/custom_modules/ngx_cache_purge \
 --add-module=/suyong1/devel/nginx_mod/nginx-jimmy-1.14.2/custom_modules/nginx-module-vts \
 --add-module=/suyong1/devel/nginx_mod/nginx-jimmy-1.14.2/custom_modules/ngx-module-otu \
 --with-debug 
