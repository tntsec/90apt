#!/bin/bash
echo "90APT云服务器一键包2.0 更新时间2025.12.2"
echo "只支持alma8、anolis8、opencloudos8、rockylinux8、oraclelinux8、centos8操作系统，不支持其他操作系统，建议使用国外服务器搭建"
echo "请先在云服务面板安全组放行 53UDP 443TCP 8888TCP端口"
echo "在线监测您的服务器IP为"; curl -sS http://ipip.me  | head -n 1
echo "请输入服务器IP";read ipadd
echo "您输入的IP为 $ipadd"
echo "您要安装啥， 2、华阳德赛西威无线ADB工具 3、安波福调试模式"
echo "只输入数字:";read gongcheng
yum install bind nginx -y
yum install python39 -y
pip3.9 install flask
firewall-cmd --add-port=53/udp --permanent
firewall-cmd --add-port=443/tcp --permanent
firewall-cmd --add-port=8888/tcp --permanent
firewall-cmd --reload
curl http://gwm.90apt.com/linux/named.conf > /etc/named.conf
curl http://gwm.90apt.com/linux/named.rfc1912.zones > /etc/named.rfc1912.zones
curl http://gwm.90apt.com/linux/gwm.com.cn.zone > /var/named/gwm.com.cn.zone
mkdir /90apt
curl http://gwm.90apt.com/linux/90panel.py > /90apt/90panel.py
chmod +x /etc/rc.local
nohup python3.9 /90apt/90panel.py > /90apt/90panel.log 2>&1 &
# 检查并添加命令的单行版本
if ! grep -q "nohup python3.9 /90apt/90panel.py" /etc/rc.local; then 
    sed -i '/exit 0/i\nohup python3.9 /90apt/90panel.py > /90apt/90panel.log 2>&1 &' /etc/rc.local || echo 'nohup python3.9 /90apt/90panel.py > /90apt/90panel.log 2>&1 &' >> /etc/rc.local
fi 
sed -i "s/127.0.0.1/${ipadd}/g"  /var/named/gwm.com.cn.zone
systemctl start named;systemctl enable named
curl http://gwm.90apt.com/linux/key.pem > /etc/key.pem
curl http://gwm.90apt.com/linux/cert.pem > /etc/cert.pem
curl http://gwm.90apt.com/linux/nginx.conf > /etc/nginx/nginx.conf
curl http://gwm.90apt.com/linux/index.html > /usr/share/nginx/html/index.html
systemctl start nginx;systemctl enable nginx
if [[ $gongcheng -eq 1 ]];then
        curl http://gwm.90apt.com/linux/wn.apk.1 > /usr/share/nginx/html/3.0.apk
elif [[ $gongcheng -eq 2 ]];then
        curl http://gwm.90apt.com/linux/hy.apk.1 > /usr/share/nginx/html/3.0.apk
else
        curl http://gwm.90apt.com/linux/abf.apk.1 > /usr/share/nginx/html/3.0.apk
fi
echo "搭建完成，查看 gwm.90apt.com 教程，自行确认DNS搭建是否正常，简单测试: nslookup dzsms.gwm.com.cn IP地址"
echo "务必登录 $ipadd:8888 服务器管理后台，修改密码，后续可自行替换apk文件"

