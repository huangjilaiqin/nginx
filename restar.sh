#/bin/sh
if [ -f "bin/logs/nginx.pid" ]
then
    cat bin/logs/nginx.pid | xargs kill -TERM
    echo "stop nginx ,pid: `cat bin/logs/nginx.pid`"
fi
while [ -f "bin/logs/nginx.pid" ]
do
    sleep 1
done
echo "start ...";
bin/sbin/nginx
