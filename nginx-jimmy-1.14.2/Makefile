
default:	build

clean:
	rm -rf Makefile objs

build:
	$(MAKE) -f objs/Makefile

install:
	$(MAKE) -f objs/Makefile install

modules:
	$(MAKE) -f objs/Makefile modules

upgrade:
	/usr/share/nginx2/sbin/nginx -t

	kill -USR2 `cat /usr/share/nginx2/run/nginx.pid`
	sleep 1
	test -f /usr/share/nginx2/run/nginx.pid.oldbin

	kill -QUIT `cat /usr/share/nginx2/run/nginx.pid.oldbin`
