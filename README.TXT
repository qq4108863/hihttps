一、HiHTTPS是一款完整源码的高性能SSL WEB应用防火墙（ SSL WAF），采用epoll模式支持高并发，并且兼容ModSecurity正则规则。
    [开源版提供完整的防护功能]
	    1. 恶意Web漏洞扫描
	    2. 数据库SQL注入
	    3. 跨站脚本攻击（XSS)
	    4、CC  & DDOS防护
	    5、密码暴力破解
	    6. URL黑白名单
	    7. 危险文件上传检测
	    8. 非法URL/文件访问
	    9. 兼容OWASP的ModSecurity正则规则
	    10.epoll模型单核3万+的HTTPS并发连接
	    .....
	   
	    
二、安装步骤  
  1. 安装OpenSSL和libpcre
  CentOS : 
  	yum install openssl openssl-devel
  	yum install -y pcre pcre-devel 
  	
  Debian/Ubuntu:
  	sudo apt-get install openssl libssl-dev
  	apt-get install libpcre3 libpcre3-dev  
  
  2.编译
  解压到任意目录，make后生成可执行文件hihttps.
  
  3.规则
  规则放在和hihttps同一级的rules目录即可，注意后缀是.conf或者.rule,更多规则请在
  https://github.com/SpiderLabs/owasp-modsecurity-crs/下载，根据需求配置。
  具体请看rules/main.conf详细说明。
  默认已经开启了DDOS & CC防御，要测试并发请求，可以临时停用DDOS规则。
  
  4.运行
  通常是hihttps前端运行443（https）端口，后端反向代理80端口。
  首先保证Web服务器80端口运行正常，443端口没占用（或者端口在config.cfg里改变配置)
  ./hihttps默认读取当前目录下的confg.cfg文件， 或者./hihttps --config /dir/config.cfg
  具体请看config.cfg详细说明， 如果成功打印加载了rules目录下的规则，代表运行成功。
  
  5.测试
  rules/main.rule默认加载了一条SQL语句检测规则，可以访问https://ip/select.html?testsql=delete * from test
  或者用WEB漏洞扫描器nikto运行：./nikto  -host ip -ssl -port 443 -C all
  如果产生了报警记录，则代表正常！相关图片在doc目录。
  
三、机器学习  
  机器学习在经过大量项目实战检验后，也会在http://www.hihttps.com/  开源，   QQ/微信:4108863 邮件:4108863@qq.com

  
  
  
  
