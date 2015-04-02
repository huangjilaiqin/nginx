#/bin/sh
while [ -f "bin/logs/nginx.pid" ]
do
#cat bin/logs/nginx.pid | xargs kill -TERM
#echo "stop nginx ,pid: `cat /home/Jhuang/dev/nginx/bin/logs/nginx.pid`"
#sleep 1
    /home/Jhuang/dev/nginx/bin/sbin/nginx -s stop
done
