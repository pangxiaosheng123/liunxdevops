#主脚本
#!/bin/bash
# 基础环境配置（保持不变）
setenforce 0 >/dev/null 2>&1 || true
sed -i "s/SELINUX=enforcing/SELINUX=disabled/" /etc/selinux/config
systemctl stop firewalld >/dev/null 2>&1 || true
systemctl disable firewalld >/dev/null 2>&1 || true
cd /etc/yum.repos.d/
rm -f ./*.repo
cat > centos.repo <<-EOF
[centos]
name=Local Repo
baseurl=file:///mnt
enabled=1
gpgcheck=0
EOF
cd
mount /dev/sr0 /mnt >/dev/null 2>&1 || true
yum clean all >/dev/null
yum makecache >/dev/null
yum install -y expect wget >/dev/null

# 核心参数（根据实际环境修改）
LOCAL_HOST="192.168.59.141"   # 本机IP
REMOTE_HOSTS=("192.168.59.136") # 远程主机列表
ALL_HOSTS=("$LOCAL_HOST" "${REMOTE_HOSTS[@]}")
USER="root"
PASSWORD="123123"             # 远程主机密码（确保正确）
SSH_DIR="/root/.ssh"
CONNECT_TIMEOUT=5             # SSH连接超时时间（秒）

# 函数：安全SSH交互（通用版，返回命令输出）
ssh_with_expect() {
    local host=$1
    local cmd=$2
    local output=$(/usr/bin/expect <<-EOF
        set timeout $CONNECT_TIMEOUT
        spawn ssh -o StrictHostKeyChecking=no $USER@$host "$cmd"
        expect {
            "*yes/no" { send "yes\r"; exp_continue }
            "*password:" { send "$PASSWORD\r"; exp_continue }
            timeout { send_user "连接超时：$host\n"; exit 1 }
            eof
        }
        set result \$expect_out(buffer)
        send_user \$result
        exit 0
EOF
    )
    echo "$output"
}

# 函数：生成SSH密钥对（支持本机/远程）
generate_ssh_key() {
    local host=$1
    if [ "$host" == "$LOCAL_HOST" ]; then
        echo "生成本机[$host] SSH密钥对..."
        mkdir -p "$SSH_DIR" && chmod 700 "$SSH_DIR"
        ssh-keygen -t rsa -b 2048 -f "$SSH_DIR/id_rsa" -q -N ''
    else
        echo "生成远程主机[$host] SSH密钥对..."
        ssh_with_expect "$host" "mkdir -p $SSH_DIR && chmod 700 $SSH_DIR && ssh-keygen -t rsa -b 2048 -f $SSH_DIR/id_rsa -q -N ''"
    fi
}

# 函数：获取主机公钥（支持本机/远程）
get_host_pubkey() {
    local host=$1
    if [ "$host" == "$LOCAL_HOST" ]; then
        cat "$SSH_DIR/id_rsa.pub"
    else
        ssh_with_expect "$host" "cat $SSH_DIR/id_rsa.pub"
    fi
}

# 函数：向目标主机写入公钥（支持本机/远程）
append_pubkey_to_host() {
    local src_host=$1
    local dest_host=$2
    local pubkey=$(get_host_pubkey "$src_host")

    if [ "$dest_host" == "$LOCAL_HOST" ]; then
        echo "本机[$dest_host] 写入 $src_host 公钥..."
        echo "$pubkey" >> "$SSH_DIR/authorized_keys"
        chmod 600 "$SSH_DIR/authorized_keys"
    else
        echo "远程主机[$dest_host] 写入 $src_host 公钥..."
        ssh_with_expect "$dest_host" "echo '$pubkey' >> $SSH_DIR/authorized_keys && chmod 600 $SSH_DIR/authorized_keys"
    fi
}

# 步骤1：清理旧密钥（避免重复）
echo "清理旧SSH密钥..."
rm -f "$SSH_DIR/id_rsa" "$SSH_DIR/id_rsa.pub" "$SSH_DIR/authorized_keys"
for host in "${REMOTE_HOSTS[@]}"; do
    ssh_with_expect "$host" "rm -f $SSH_DIR/id_rsa $SSH_DIR/id_rsa.pub $SSH_DIR/authorized_keys"
done

# 步骤2：为所有主机生成新密钥对
for host in "${ALL_HOSTS[@]}"; do
    generate_ssh_key "$host"
done

# 步骤3：配置本机自免密（核心修复）
echo "配置本机[$LOCAL_HOST]自免密..."
cat "$SSH_DIR/id_rsa.pub" >> "$SSH_DIR/authorized_keys"
chmod 600 "$SSH_DIR/authorized_keys"
chmod 700 "$SSH_DIR"

# 步骤4：配置所有主机互免密
for src_host in "${ALL_HOSTS[@]}"; do
    for dest_host in "${ALL_HOSTS[@]}"; do
        if [ "$src_host" != "$dest_host" ]; then
            append_pubkey_to_host "$src_host" "$dest_host"
        fi
    done
done

# 验证免密（关键验证步骤）
echo -e "\n===== 免密登录验证 ====="
for host in "${ALL_HOSTS[@]}"; do
    echo -n "验证本机到 $host 免密："
    ssh -o ConnectTimeout=$CONNECT_TIMEOUT -o StrictHostKeyChecking=no $USER@$host "echo 验证成功" >/dev/null 2>&1 && echo "✅" || echo "❌"
done
echo "SSH key distribution completed. All hosts should be able to SSH into each other without a password."
echo "-----------------------------开始PG数据库安装--------------------------------------"
dir=$(pwd)
echo  "db variable list"
BASEPATH=/pgdb
FILE_CONF=/pgdb/data/postgresql.conf
HBA_CONF=/pgdb/data/pg_hba.conf
PGDATA=/pgdb/data
PGHOME=/pgdb/pgsql
SCRIPTS_DIR=/pgdb/scripts
LOGPATH=/pgdb/data/log
PORT=5785
PASSWD="123456"
cpu=$(cat /proc/cpuinfo | grep 'physical id' | sort | uniq | wc -l)
echo  "1.system parameter configure"
echo  "1.1.add sudo postgres"
sed -ri '/^root/a\postgres    ALL=(ALL)       NOPASSWD: ALL' /etc/sudoers
echo  "1.2.adjust system parameter"
optimizeSystemConf(){
conf_exist=$(cat /etc/sysctl.conf|grep postgres|wc -l)
if [ $conf_exist -eq 0 ]; then
    echo "optimize system core conf"
    sed -ri '/net.ipv4.ip_forward/s#0#1#' /etc/sysctl.conf
    cat >> /etc/sysctl.conf <<EOF
kernel.sysrq = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv4.tcp_syn_retries = 2
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_keepalive_probes = 3
net.ipv4.tcp_keepalive_intvl =15
net.ipv4.tcp_retries1 = 3
net.ipv4.tcp_retries2 = 5
net.ipv4.tcp_fin_timeout = 10
net.ipv4.tcp_max_tw_buckets = 6000
net.ipv4.tcp_tw_recycle = 1
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_mem = 94500000 915000000 927000000
net.ipv4.tcp_fin_timeout = 10
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_orphans = 3276800
net.ipv4.tcp_max_syn_backlog = 16384
net.ipv4.tcp_max_orphans = 3276800
net.ipv4.tcp_syncookies=1
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_rmem = 4096 87380 4194304
net.ipv4.tcp_wmem = 4096 16384 4194304
net.core.wmem_default = 8388608
net.core.rmem_default = 8388608
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
fs.file-max = 1024000
net.ipv4.ip_local_port_range = 1024 65000
net.ipv4.route.gc_timeout = 100
net.core.somaxconn=1024
net.core.netdev_max_backlog = 262144
EOF
else
   echo "system configuration is already optimized, so we do nothing"
fi
}
optimizeSystemConf
echo  "1.3.adjust Optimize Limit"
optimizeLimitConf(){
conf_exist=$(cat /etc/security/limits.conf|grep postgres|wc -l)
if [ $conf_exist -eq 0 ]; then
    echo "optimize limit configuration"
    cat >> /etc/security/limits.conf << "EOF"
#add by postgres
postgres    soft    nproc    16384
postgres    hard    nproc    16384
postgres    soft    nofile    65536
postgres    hard    nofile    65536
postgres    soft    stack    1024000
postgres    hard    stack    1024000
EOF
else
    echo "limit is already optimized, so we do nothing"
fi
}
optimizeLimitConf

echo  "1.4.adjust optimize selinux"
sed -i "s/SELINUX=enforcing/SELINUX=disabled/g" /etc/selinux/config
setenforce 0 

echo  "1.5.off firwalld -- this must user do it myself"
function conf_firewall() {
##################gt>0
if [ $(systemctl status firewalld.service | grep -c running) -gt 0 ]; then  
     #systemctl stop firewalld.service
     #systemctl disable firewalld.service 
     firewall-cmd --zone=public --add-port=5785/tcp --permanent
     firewall-cmd --zone=public --add-port=22/tcp --permanent
     firewall-cmd --reload
     #禁用防火墙区域偏移
     sed -i 's/^AllowZoneDrifting=yes/AllowZoneDrifting=no/' /etc/firewalld/firewalld.conf 
   else
   echo "firewall not open"
fi
}
conf_firewall
echo  ""1.6.IPC, some system have this, so do it by user 配置防火墙策略"logind进程cpu占用100%处理"
sed -i 's/#RemoveIPC=no/RemoveIPC=no/g' /etc/systemd/logind.conf
systemctl daemon-reload
systemctl restart systemd-logind
echo  "1.7.安装相关依赖"
# 获取当前所在目录位置
current_dir=$(pwd)
echo "当前所在目录位置: $current_dir"
# 目标路径
target_dir="/soft"
# 检查目标路径是否存在，如果不存在则创建
if [ ! -d "$target_dir" ]; then
    mkdir -p "$target_dir"
    echo "已创建目录: $target_dir"
fi
# 移动当前目录下的所有文件到目标路径
mv $current_dir/pg_yum.tar.gz $target_dir
echo "已将当前目录下所有文件移动至 $target_dir"
yum install -y zlib-devel libaio cmake make gcc gcc-c++ readline readline-devel perl bison flex libyaml net-tools expect openssh-clients tcl openssl openssl-devel ncurses-devel python python-devel openldap pam systemtap-sdt-devel perl-ExtUtils-Embed libxml2 libxml2-devel libxslt libxslt-devel uuid-devel
echo  "2. postgres exits"
id $postgres >& /dev/null
if [ $? -ne 0 ]
then
        echo "postgres already exits"
else 
        echo "postgres not exits，please create"
        groupadd postgres
        useradd -g postgres postgres
        echo "$PASSWD"|passwd --stdin  postgres
        sed -ri '/^root/a\postgres ALL=(ALL) ALL' /etc/sudoers
fi

echo  "3.create directory"
if [ ! -d $BASEPATH ]
then
        mkdir -p $BASEPATH/{data,pg_archive,pg_backup,scripts,tmp}
fi

echo "4. unzip"
tar -zxf /opt/postgresql*.tar.gz -C $BASEPATH/
echo "pgsql upzip success"
echo "directory rights"
cd $BASEPATH
mv postgresql-14.12/ pgsql
chown -R postgres:postgres $BASEPATH
chmod -R 755 $BASEPATH
#-------------------------------install pgsql------------------------------------
echo "5.install dependency package"
cd $PGHOME
./configure --prefix=$PGHOME --with-pgport=$PORT --with-openssl --with-perl --with-python --with-blocksize=32  --with-readline --with-libxml --with-libxslt 
#./configure --prefix=$PGHOME --with-pgport=$PORT --with-openssl --with-perl --with-python --with-blocksize=128 --with-wal-blocksize=128 --with-wal-segsize=100 --with-readline --with-libxml --with-libxslt --with-uuid=ossp
if [ $? == 0 ]
then
        echo "configure配置通过，开始进行make编译"
        #gmake一次性将文档及附加模块全部进行编译和安装,保证所有数据库软件的一致性，避免给后期维护操作带来麻烦
        gmake world -j $cpu
        if [ $? == 0 ]
        then
                echo "make编译通过，开始进行make install安装步骤"
                gmake install-world  -j $cpu
                if [ $? != 0 ];then
                        echo "make install安装失败"
                fi
                echo "安装成功"
        else
                echo "make编译失败，检查错误。"
        fi
else
        echo "configure检查配置失败，请查看错误进行安装库文件"
fi
echo "6.添加环境变量,进入postgres用户的家目录"
cd /home/postgres
postgresenvConf(){
conf_exist=$(cat .bash_profile |grep postgres|wc -l)
if [ $conf_exist -eq 0 ]; then
    echo "postgres user env configuration"
    cp .bash_profile .bash_profile.bak
    sed -i 's/^export PATH/#export PATH/' .bash_profile
    echo "#add by postgres" >> .bash_profile
    echo "export PGHOME=$PGHOME" >> .bash_profile
    echo "export PGDATA=$PGDATA" >> .bash_profile
    echo "export PGPORT=5785" >> .bash_profile    
    echo "export PGPASSWORD=123456" >> .bash_profile    
    echo 'export PATH=$PGHOME/bin:$PATH' >> .bash_profile
    echo 'export MANPATH=$PGHOME/share/man:$MANPATH' >> .bash_profile
    echo 'export LD_LIBRARY_PATH=$PGHOME/lib:$LD_LIBRARY_PATH' >> .bash_profile
    echo 'SCRIPTS_DIR=/pgdb/scripts' >> .bash_profile
    echo "export LANG="en_US.UTF-8"" >> .bash_profile
    echo 'export DATE=`date +"%Y%m%d%H%M"`' >> .bash_profile
    source /home/postgres/.bash_profile    
else
    echo "postgres user env is already config, so we do nothing"
fi
}
postgresenvConf

echo  "7. 开始进行pgsql的配置"
echo "切换至postgres用户来初始化数据库，设置密码文件"
su - postgres -c 'echo "$PASSWD">> .pgpass'
su - postgres -c "chmod 0600 /home/postgres/.pgpass"
su - postgres -c "$PGHOME/bin/initdb  --username=postgres --pwfile=/home/postgres/.pgpass -D $PGDATA --encoding=UTF8 --lc-collate=en_US.UTF-8 --lc-ctype=en_US.UTF-8"
if [ $? == 0 ]
 then
    echo "初始化成功"
    chown -R postgres:postgres $BASEPATH
    chmod -R 755 $BASEPATH
    chmod -R 700 $PGDATA
 else 
    echo "初始化失败"
fi    
echo "configure param"
cp $FILE_CONF $PGDATA/postgresql.confbak
sed -i "/^#listen_addresses = 'localhost'/s/#listen_addresses = 'localhost'/listen_addresses = '*'/" $FILE_CONF
sed -i "s/^#port = 5785/port = $PORT/" $FILE_CONF   
sed -i 's/max_connections = 100/max_connections = 1000/' $FILE_CONF    #max_connections*work_mem 上千个连接，建议配置连接池
sed -i 's/^#superuser_reserved_connections = 3/superuser_reserved_connections=10/' $FILE_CONF    #为超级用户保留的连接数
sed -i "/^#max_prepared_transactions = 0/s/#max_prepared_transactions = 0/max_prepared_transactions = 500/" $FILE_CONF  #等于
sed -i "/^shared_buffers = 128MB/s/shared_buffers = 128MB/shared_buffers = 1024MB/" $FILE_CONF #物理内存1/4，小于1/2
sed -i "/^#effective_cache_size = 4GB/s/#effective_cache_size = 4GB/effective_cache_size = 3GB/" $FILE_CONF  #查询优化器可用的OS CACHE实际不占用内存 物理内存1/3~1/2
sed -i "/^#work_mem = 4MB/s/^#work_mem = 4MB/work_mem = 30MB/" $FILE_CONF  #在写入临时磁盘文件之前查询操作(例如排序或哈希表)可使用的最大内存容量  # max(min(规格内存/4096, 64MB), 4MB)
sed -i "/^#maintenance_work_mem = 64MB/s/#maintenance_work_mem = 64MB/maintenance_work_mem = 256MB/" $FILE_CONF    # min( 8G, (主机内存*1/8)/max_parallel_maintenance_workers )   
sed -i 's/^#vacuum_cost_limit = 200/vacuum_cost_limit = 500/' $FILE_CONF   #清理delete后的空间，此时对io影响较大，增加该值可以缩小对性能的影响
sed -i "/^#max_parallel_maintenance_workers = 2/s/#max_parallel_maintenance_workers = 2/max_parallel_maintenance_workers = 4/" $FILE_CONF    #CPU核数/4  
sed -i "/^#max_parallel_workers_per_gather = 2/s/#max_parallel_workers_per_gather = 2/max_parallel_workers_per_gather = 4/" $FILE_CONF    #CPU核数/4 每个执行节点的最大并行处理过程数，应用并行查询时设置该值大于1，不建议超过主机cores-2 
sed -i "/^#max_parallel_workers = 8/s/^#//" $FILE_CONF    #CPU核数 
sed -i "/^#max_worker_processes = 8/s/^#//" $FILE_CONF    #CPU核数 
sed -i 's/^min_wal_size = 80MB/min_wal_size = 1GB/' $FILE_CONF     #建议值shared_buffers/2
sed -i 's/^max_wal_size = 1GB/max_wal_size = 2GB/' $FILE_CONF     #该值越小，wal日志写入量越大，wal日志恢复时间越长
sed -i 's/^#checkpoint_timeout = 5min/checkpoint_timeout = 10min/' $FILE_CONF    
sed -i "/^#checkpoint_completion_target = 0.9/s/^#//" $FILE_CONF #去掉注释
sed -i "/^#wal_level/s/^#//" $FILE_CONF #去掉注释
sed -i 's/#archive_mode = off/archive_mode = on/' $FILE_CONF
sed -i "/^#archive_command = ''/s/#archive_command = ''/archive_command ='\/usr\/bin\/lz4 -q -z %p \/pgdb\/pg_archive\/%f.lz4'/" $FILE_CONF  #-q取消警告-z强制压缩
sed -i "/^#log_destination = 'stderr'/s/#log_destination = 'stderr'/log_destination = 'csvlog'/" $FILE_CONF
sed -i "/^#logging_collector = off/s/#logging_collector = off/logging_collector = on/" $FILE_CONF
sed -i "/^#log_disconnections = off/s/#log_disconnections = off/log_disconnections = on/" $FILE_CONF   #用户退出时是否写入日志
sed -i "/^#log_connections = off/s/#log_connections = off/log_connections = on/" $FILE_CONF   #用户session登录时写入日志
sed -i "/^#authentication_timeout = 1min/s/#authentication_timeout = 1min/authentication_timeout = 59s/" $FILE_CONF   #用户session登录时写入日志
sed -i "/^#log_directory = 'log'/s/^#//" $FILE_CONF #去掉注释
sed -i "/^#log_filename/s/^#//" $FILE_CONF #去掉注释
sed -i "/^#log_file_mode/s/^#//" $FILE_CONF #去掉注释
sed -i "/^#log_rotation_age/s/^#//" $FILE_CONF #去掉注释
sed -i "/^#log_rotation_size/s/^#//" $FILE_CONF #去掉注释
sed -i "/^#temp_buffers = 8MB/s/#temp_buffers = 8MB/temp_buffers = 256MB/" $FILE_CONF

cp $HBA_CONF $PGDATA/pg_hba.confbak
echo "host    all             all             0.0.0.0/0               md5" >> $HBA_CONF 
echo  "8. auto starting up"
cat > /usr/lib/systemd/system/postgres.service << "EOF"
[Unit]
Description=PostgreSQL database server
After=network.target
[Service]
Type=forking
User=postgres
Group=postgres
Environment=PGPORT=5785
Environment=PGDATA=/pgdb/data
OOMScoreAdjust=-1000
ExecStart=/pgdb/pgsql/bin/pg_ctl start -D $PGDATA
ExecStop=/pgdb/pgsql/bin/pg_ctl stop -D $PGDATA -s -m fast
ExecReload=/pgdb/pgsql/bin/pg_ctl reload -D $PGDATA -s
TimeoutSec=300
[Install]
WantedBy=multi-user.target
EOF
sed -i "s/^Environment=PGPORT=5785/Environment=PGPORT=$PORT/" /usr/lib/systemd/system/postgres.service  
chmod +x /usr/lib/systemd/system/postgres.service
systemctl daemon-reload
systemctl start postgres.service
systemctl enable postgres.service
#判断是否启动成功
process=$(ps -ef | grep  -v 'grep'| grep  '$PGHOME/bin/postgres'|awk '{print $2}')
if [ -n "$process"  ];then  #检测字符串长度是否不为 0，不为 0 返回 true。
    echo "install success ans start success"
else
    echo "install fail"
fi
echo "-----------------------------恭喜主库完成安装--------------------------------------"
echo "---------------------------9.切归档日志------------------------------------------------------"
su - postgres -c "$PGHOME/bin/psql -d postgres -h127.0.0.1 -p$PORT -c \"select pg_switch_wal();\""
echo "---------------------------------------------------------------------------------------"
echo "12.数据库信息"
echo "操作系统数据库用户：postgres;密码：postgres"
echo "数据库信息:postgres;密码：postgres;port:5785"
echo "-----------------------------开始从库安装--------------------------------------"
scp /opt/pginstall.sh root@192.168.59.136:/opt
scp /opt/*.tar.gz  root@192.168.59.136:/opt/
ssh -tt -p 22 root@192.168.59.136 "source /opt/pginstall.sh"
REMOTE_HOST="192.168.59.136"
#REMOTE_SCRIPT_PATH="/opt/mysql_install.sh"
#ssh 192.168.59.250 "source /opt/mysql_install.sh"
ssh =$REMOTE_HOST <<EOF
if [ $? -eq 0 ]; then
    echo "PG安装已成功完成."
else
    echo "PG安装失败，请检查日志或手动排查问题."
fi
# 添加其他命令，如清理临时文件或重启服务
# 例如： rm /tmp/temp_file
exit
EOF
sleep 10
/usr/bin/expect <<EOF
set timeout 60
# 启动SSH命令
spawn ssh root@192.168.59.141
# 处理首次连接提示的 "yes/no" 和密码输入
expect {
    "Are you sure you want to continue connecting (yes/no)?" { send "yes\r"; exp_continue }
    "password:" { send "123123\r"; exp_continue }
    eof
}
EOF
sleep 10
source /etc/profile
# -------------------- 主节点配置（新增服务文件） -------------------- #
local host=192.168.59.141
  echo "------------------- 配置主节点 -------------------"
  
# 使用expect处理首次SSH连接确认和密码输入
/usr/bin/expect <<EOF
set timeout 60
spawn ssh root@192.168.59.141
expect {
    "Are you sure you want to continue connecting (yes/no)?" { send "yes\r"; exp_continue }
    "password:" { send "123123\r"; exp_continue }
    eof
}
EOF

# 执行远程配置命令
ssh root@192.168.59.141 <<EOF
    set -ex  # 遇错退出+打印执行过程

    # 加载环境变量（明确检查是否加载成功）
    source /etc/profile || { echo "Error: 加载环境变量失败!" >&2; exit 1; }

    PG_PORT=5785
    PGDATA=/pgdb/data

    # 检查关键变量（强化错误提示）
    if [ -z "\${PGDATA}" ] || [ -z "\${PG_PORT}" ]; then
        echo "Error: PGDATA（\${PGDATA}）或 PG_PORT（\${PG_PORT}）未设置!" >&2
        exit 1
    fi
    if [ ! -d "\${PGDATA}" ]; then
        echo "Error: PGDATA 目录不存在: \${PGDATA}" >&2
        exit 1
    fi

    # 配置 postgresql.conf（添加备份，避免配置错误）
    cp \${PGDATA}/postgresql.conf \${PGDATA}/postgresql.conf.bak
    sed -i "s/^#listen_addresses = .*/listen_addresses = '*'/" \${PGDATA}/postgresql.conf
    sed -i "s/^port = .*/port = \${PG_PORT}/" \${PGDATA}/postgresql.conf
    cat >> \${PGDATA}/postgresql.conf <<-EOF_CONF
listen_addresses = '*'      # 监听所有ip
wal_level = hot_standby     # 热备模式
archive_mode = on           #允许归档
max_wal_senders = 10
wal_keep_size = 1GB
archive_mode = on
archive_command = 'test ! -f /pgdb/pg_archive/%f && cp %p /pgdb/pg_archive/%f'
synchronous_commit = on
wal_sender_timeout = 60s    #流复制主机发送数据的超时时间
max_connections = 200       #最大连接数，从库的max_connections必须要大于主库的
EOF_CONF
    echo "postgresql.conf 配置完成（备份：postgresql.conf.bak）"

    # 配置 pg_hba.conf（添加备份+格式校验）
    cp \${PGDATA}/pg_hba.conf \${PGDATA}/pg_hba.conf.bak
    echo "host    replication     replicator      192.168.59.136/32       md5" >> \${PGDATA}/pg_hba.conf
    echo "host    all             all             0.0.0.0/0               md5" >> \${PGDATA}/pg_hba.conf
    su - postgres -c "psql -c 'SELECT pg_reload_conf();'"  # 重载配置（无需重启）
    echo "pg_hba.conf 配置完成（备份：pg_hba.conf.bak）"

    # 创建归档目录（强化权限检查）
    mkdir -p /pgdb/pg_archive
    chown postgres:postgres /pgdb/pg_archive || { echo "Error: 归档目录授权失败!" >&2; exit 1; }
    echo "归档目录创建完成"
    chown -R postgres.postgres /pgdb/data/
    # 重启服务（优先用 systemctl，失败则用 pg_ctl，并验证状态）
    echo "正在重启 PostgreSQL 服务..."
    if systemctl restart postgres.service; then
        echo "systemctl 重启成功，等待服务就绪..."
        su - postgres -c "pg_ctl wait -D \${PGDATA} -t 30"  # 等待30秒直到服务就绪
    else
        echo "systemctl 重启失败，尝试 pg_ctl 重启..."
        su - postgres -c "pg_ctl restart -D \${PGDATA} -t 30"  # 指定超时30秒
    fi

    # 验证服务状态（关键！避免假成功）
    su - postgres -c "pg_ctl status -D \${PGDATA}" || { echo "Error: 服务未启动!" >&2; exit 1; }

    role_exists=\$(su - postgres -c "psql -tAc 'SELECT 1 FROM pg_roles WHERE rolname = '\''replicator'\'';'")
    
    if [ -z "\${role_exists}" ]; then
        # 角色不存在，执行创建
        su - postgres -c 'psql -c "CREATE ROLE replicator WITH LOGIN REPLICATION ENCRYPTED PASSWORD '\''postgres'\'';"'
        echo "复制用户创建成功"
    else
        # 角色已存在，跳过创建
        echo "复制用户已存在，跳过创建"
    fi

    echo "===== 所有任务执行完成 ====="
EOF
date



# -------------------- 从节点配置（修复pg_basebackup路径） -------------------- #
ssh 192.168.59.136

  echo "------------------- 配置从节点 -------------------"
export PRIMARY_HOST=192.168.59.141
export PG_PORT=5785
export USER=root
export PGDATA=/pgdb/data
rm -rf /pgdb/data
export PGPASSWORD='postgres'
pg_basebackup -D /pgdb/data -h 192.168.59.141 -p 5785 -U replicator -X stream -P
# 检测 PostgreSQL 服务名（优先使用 systemd 服务）
PG_SERVICE="postgresql.service"
if systemctl list-units --type=service | grep -q "postgresql-.*\.service"; then
    PG_SERVICE=$(systemctl list-units --type=service | grep "postgresql-.*\.service" | awk '{print $1}')
fi

ssh root@192.168.59.136 <<EOF
    set -ex

    # 加载环境变量
    source /etc/profile || { echo "环境变量加载失败"; exit 1; }

    # 停止服务（优先 systemctl，失败则 pg_ctl）
    if systemctl is-enabled "${PG_SERVICE}" &>/dev/null; then
        systemctl stop "${PG_SERVICE}" || true
    fi
    su - postgres -c "pg_ctl stop -D ${PGDATA} -m fast"  # 强制快速停止
    # 写入 standby 配置（避免覆盖原配置，改为追加关键参数）
    cp "${PGDATA}/postgresql.conf" "${PGDATA}/postgresql.conf.bak"  # 备份原配置
    cat >> "${PGDATA}/postgresql.conf" <<-EOF_CONF
primary_conninfo = 'host=${PRIMARY_HOST} port=${PG_PORT} user=replicator password=postgres'
hot_standby = on
wal_receiver_status_interval = 10s # 控制 walreceiver 进程向主服务器发送心跳消息的时间间隔
hot_standby_feedback = on # 控制备用服务器是否会向主服务器发送关于自己的复制状态和进度的信息
EOF_CONF

    # 校验配置文件语法（关键！避免启动失败）
    su - postgres -c "pg_ctl check -D ${PGDATA}" || { echo "配置文件语法错误"; exit 1; }

    # 修正数据目录权限
    chown -R postgres:postgres "${PGDATA}" || { echo "权限修改失败"; exit 1; }

    # 启动服务（优先 systemctl，失败则 pg_ctl）
    systemctl start postgres.service
    if systemctl start "${PG_SERVICE}"; then
        echo "systemctl 启动服务成功"
    else
        su - postgres -c "pg_ctl start -D ${PGDATA}" || { echo "pg_ctl 启动失败"; exit 1; }
    fi
    export PGDATA=/pgdb/data
    ls $PGDATA/standby.signal &> /dev/null || touch $PGDATA/standby.signal
    # 验证服务状态
    su - postgres -c "pg_ctl status -D ${PGDATA}" || { echo "服务未启动"; exit 1; }
    echo "PostgreSQL 备用节点配置完成"
EOF

# 验证（确保环境变量生效）
echo "------------------- 验证主从状态 -------------------"
  ssh root@192.168.59.141 "source /etc/profile && su - postgres -c 'psql -c \"SELECT * FROM pg_stat_replication;\"'"
for host in "${HOSTS[@]:1}"; do
  ssh root@192.168.59.136 "source /etc/profile && su - postgres -c 'psql -c \"SELECT * FROM pg_is_in_recovery();\"'"
done