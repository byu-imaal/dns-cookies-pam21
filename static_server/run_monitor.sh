# basic wrapper to run `monitor_static.py` on each of the IPs/domains we're interested in

script="/home/jacob/PycharmProjects/IMAAL_workspace/dns_cookies/monitor_static.py"
out_dir="/home/jacob/data/auth/static"

python3 $script 208.80.153.231 wikipedia.org $out_dir/wikipedia.log
python3 $script 91.198.174.239 wikipedia.org $out_dir/wikipedia.log

python3 $script 108.61.206.56 pantip.com $out_dir/pantip.log
python3 $script 103.253.133.3 pantip.com $out_dir/pantip.log

python3 $script 172.96.140.18 ibb.co $out_dir/ibb.log
python3 $script 51.210.112.129 ibb.co $out_dir/ibb.log
python3 $script 51.81.66.79 ibb.co $out_dir/ibb.log

python3 $script 46.229.175.90 postimg.cc $out_dir/postimg.log
python3 $script 104.238.220.13 postimg.cc $out_dir/postimg.log
python3 $script 51.91.224.95 postimg.cc $out_dir/postimg.log
