概述：
**注意端口 tcp/udp的开放**

安装coturn和janus前先安装依赖包

证书和turnserver用户密码需配套

前提准备

基础环境的准备，包括服务器环境、地址、证书、防火墙配置等。</br>
环境准备</br>
操作系统：centos 7.6 x64</br>
一个带有SSL证书的域名</br>
需要开放对应的端口：8088 8188 3478 3480-3500 7000-9000 443</br>
证书转换
```sh
mkdir /etc/ssl/cert/domain.com
cd /etc/ssl/cert/domain.com
```
上传证书至此目录，一般用Nginx适用的证书即可。如果有pem的最好，直接上传到此处，如果没有的话，需要转换。
```sh
openssl rsa -in domain.com.key -text > key.pem
openssl x509 -inform PEM -in domain.com.crt > cert.pem
```
开始安装
开始Webrtc服务的部署及安装，将分步骤详细记录。以及在按步骤执行过程中遇到的问题的处理。
## 安装依赖包
```sh
yum update
yum install  texinfo  libmicrohttpd-devel.x86_64   uncrustify

yum -y install epel-release nginx libmicrohttpd-devel jansson-devel openssl-devel libsrtp-devel sofia-sip-devel glib2-devel opus-devel libogg-devel libcurl-devel pkgconfig gengetopt libconfig-devel libtool autoconf automake libnice libnice-devel libwebsockets libwebsockets-devel doxygen graphviz cmake gtk-doc-tools git lrzsz
```
安装libsrtp
```sh
cd ~
wget https://github.com/cisco/libsrtp/archive/v1.5.4.tar.gz
tar zxvf v1.5.4.tar.gz && cd libsrtp-1.5.4
./configure --prefix=/usr --enable-openssl --libdir=/usr/lib64
make shared_library && sudo make install
```
安装usrsctp
```sh
cd ~
git clone https://github.com/sctplab/usrsctp
cd usrsctp
./bootstrap
./configure --prefix=/usr --libdir=/usr/lib64 && make && sudo make install
```
安装RabbitMQ (非必选)
```sh
cd ~
git clone https://github.com/alanxz/rabbitmq-c
cd rabbitmq-c
git submodule init
git submodule update
mkdir build && cd build
cmake -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_INSTALL_LIBDIR=/usr/lib64 ..
make && sudo make install
```
安装Janus-Gateway
```sh
cd ~
git clone https://github.com/meetecho/janus-gateway.git
cd janus-gateway
sh autogen.sh
./configure --prefix=/opt/janus --enable-websockets  
make
make install
make configs
```
输出以下信息，说明
```
./configure --prefix=/opt/janus --enable-websockets 执行成功。
Compiler:                  gcc
libsrtp version:           1.5.x
SSL/crypto library:        OpenSSL
DTLS set-timeout:          not available
Mutex implementation:      GMutex (native futex on Linux)
DataChannels support:      yes
Recordings post-processor: no
TURN REST API client:      yes
Doxygen documentation:     no
Transports:
    REST (HTTP/HTTPS):     yes
    WebSockets:            yes
    RabbitMQ:              yes
    MQTT:                  no
    Unix Sockets:          yes
    Nanomsg:               no
Plugins:
    Echo Test:             yes
    Streaming:             yes
    Video Call:            yes
    SIP Gateway (Sofia):   no
    SIP Gateway (libre):   no
    NoSIP (RTP Bridge):    yes
    Audio Bridge:          yes
    Video Room:            yes
    Voice Mail:            yes
    Record&Play:           yes
    Text Room:             yes
    Lua Interpreter:       no
    Duktape Interpreter:   no
Event handlers:
    Sample event handler:  yes
    RabbitMQ event handler:yes
    MQTT event handler:    no
JavaScript modules:        no
```
## 安装CoTurn服务
在安装CoTurn服务执行./configure时，碰到了一个报错，这里提前说明，先做解决。
```
Libevent2 development is not installed properly
ERROR: Libevent2 development libraries are not installed properly in required location.
ERROR: may be you have just too old libevent tool - then you have to upgrade it.
See the INSTALL file.
Abort.
```
解决办法如下：
```sh
sudo yum install libevent libevent-devel  openssl openssl-libs -y 
```
然后：
```sh
cd ~
wget https://sourceforge.net/projects/levent/files/release-2.0.22-stable/libevent-2.0.22-stable.tar.gz/download
mv download libevent-2.0.22-stable.tar.gz
tar zxvf libevent-2.0.22-stable.tar.gz
cd libevent-2.0.22-stable
./configure
make
sudo make install
```
然后开始正常安装CoTurn服务。
```
cd ~
mkdir /root/webrtc
cd /root/webrtc
wget http://coturn.net/turnserver/v4.5.0.7/turnserver-4.5.0.7.tar.gz
tar zxvf turnserver-4.5.0.7.tar.gz
cd /root/webrtc/turnserver-4.5.0.7
./configure
make install
```
## 服务配置
此处主要是涉及到turn服务及Janus服务的配置项目。</br>
CoTurn服务的配置</br>
```
vi /usr/local/etc/turnserver.conf
```
打开后在文件中添加以下配置（注意配置项后不要有空格）：
```conf
#本地监听的网卡设备，这里根据自己的实际情况填写
listening-device=eth1
listening-port=3478
#本地用于转发的网卡设备，这里根据自己的实际情况填写
relay-device=eth1
#指定的转发端口的分配范围，测试时，可以将防火墙全部关闭，防止 UDP 端口被屏蔽
min-port=3480
max-port=3500
#日志输出级别，turnserver 启动时加上 -v,可以得到更清晰的日志输出
Verbose
#消息验证，WebRTC 的消息里会用到
fingerprint
#webrtc 通过 turn 中继，必须使用长验证方式
lt-cred-mech
# ICE REST API 认证需要（如果打开了这行，turn就不工作了）
# use-auth-secret
# REST API 加密所需的 KEY
# 这里我们使用“静态”的 KEY，Google 自己也用的这个（如果找开这个就不工作了）
#static-auth-secret=4080218913
#用户登录域，下面的写法可以不改变它，因为再启动 turnserver 时，可以通过指定参数覆盖它
realm=<填写你自己的域名>
#可为 TURN 服务提供更安全的访问（这个我没用，不知道干啥的）
#stale-nonce
#在Coturn代码中的/etc/examples/目录下有秘钥文件，可以直接用
cert=/usr/local/turnserver/etc/turn_server_cert.pem
pkey=/usr/local/turnserver/etc/turn_server_pkey.pem
#屏蔽 loopback, multicast IP地址的 relay
no-loopback-peers
no-multicast-peers
#启用 Mobility ICE 支持（不懂）
mobility
#禁用本地 telnet cli 管理接口
no-cli

```
## Janus配置
```sh
vi /opt/janus/etc/janus/janus.jcfg
```
找到certificates配置项，在里面打开以下内容的配置，并设置。
```
certificates:
        cert_pem = "/etc/ssl/certs/huawenyao.cn/server-cert.pem"
        cert_key = "/etc/ssl/certs/huawenyao.cn/server-key.pem"
```
找到nat配置项，在里面打开以下内容的配置，并设置,其中的用户名及密码为turnserver.conf中配置的用户名及密码。
```
nat:
        turn_server = "domain.com"
        turn_port = 3478
        turn_type = "udp"
        turn_user = "user"
        turn_pwd = "passwd123"
        ice_enforce_list = "eth0"
```
再打开janus.transport.http.jcfg进行配置。
```sh
vi /opt/janus/etc/janus/janus.transport.http.jcfg
```
分别找到general、admin、certificates三项的配置处，修改以下配置（没有提到的不用动）。
```
general:                                     
        https = true 
                                    
admin:
        admin_https = true 

certificates:
        cert_pem = "/etc/ssl/certs/huawenyao.cn/server-cert.pem"
        cert_key = "/etc/ssl/certs/huawenyao.cn/server-key.pem"
```
再打开janus.transport.websockets.jcfg进行配置。
```
vi /opt/janus/etc/janus/janus.transport.websockets.jcfg
```
分别找到general、admin、certificates三项的配置处，修改以下配置（没有提到的不用动）。
```
general:
        wss = true 

admin:
        admin_wss = true

certificates:
        cert_pem = "/etc/ssl/certs/huawenyao.cn/server-cert.pem"
        cert_key = "/etc/ssl/certs/huawenyao.cn/server-key.pem"
```
Nginx的配置
新创建一个配置文件：
```sh
vi /etc/nginx/conf.d/janus.conf
```
添加以下内容
```
 server {
     licsten 80;
     listen 443 ssl;
     server_name domain.com; 
     ssl_certificate /etc/ssl/cert/domain/domain.com.crt;
     ssl_certificate_key /etc/ssl/cert/domain/domain.com.key;
     charset     utf-8;
     root /opt/janus/share/janus/demos;
     index index.php index.html index.htm;
     access_log  /var/log/nginx/access.log  main;
     location / {
     }
 }
```
服务启动
此处主要为各个服务的启动方式。
启动Turn服务
```sh
/usr/local/bin/turnserver -c /usr/local/etc/turnserver.conf -o  -v
```
可以查看3478端口是否被占用，若占用，则说明服务启动成功。
```sh
netstat -nap|grep 3478
```
启动Janus服务
```sh
nohup /opt/janus/bin/janus >> /var/log/janus.log 2>&1 &
```
启动Nginx服务
```sh
systemctl restart nginx
```

验证

创建用户
```sh
sudo turnadmin -a -u 用户名 -p 密码 -r 域(随便写一个)
```
可以使用下面的命令查看创建的用户
turnadmin -l
测试 STUN
使用下面的命令即可测试 STUN 服务使用可用，唯一此参数是 STUN 服务器的 IP地址或域名。
# 测试 STUN
```sh
turnutils_stunclient 172.31.37.14
​turnadmin -k -u -r -p //turnadmin -k -A -u test  -r test -p webrtc
```

# 测试 TURN
```sh
turnutils_uclient -v -t -T -u test -w test  172.31.37.14
```
测试：https://webrtc.github.io/samples/src/content/peerconnection/trickle-ice/ 
——————————————————————————————————————
参考文档:https://github.com/meetecho/janus-gateway

 sudo openssl req -x509 -newkey rsa:2048 -keyout /etc/    turn_server_pkey.pem -out /etc/turn_server_cert.pem -days 99999 -nodes 

