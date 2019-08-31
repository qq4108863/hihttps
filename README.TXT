一、HiHTTPS是一款高性能Web安全SSL防火墙
    [开源版提供基础防护功能]
	    1. 恶意Web漏洞扫描
	    2. 数据库SQL注入
	    3. 跨站脚本攻击（XSS)
	    4. URL黑白名单
	    5. 危险文件上传检测
	    6. 非法URL/文件访问
	    7. 支持HTTP1.1所有的SSL Web服务器
	    8. HTTP错误检测、可以扩展的日志
	    9. 兼容OWASP的ModSecurity正则规则
	    10.epoll模型单核3万+并发连接请求
	   
	 [专业版提供高级防护功能]
	    1. 超10万+高并发请求
	    2. CC  & DDOS
	    3. 密码暴力破解
	    4. 机器人/爬虫
	    5. 精准IP/URL等访问控制
	    6. 支持HTTP 2.0
	    7. 人工智能防御未知攻击(目标)
	    8. Web管理界面
	    9.  支持独立硬件部署，保护后端多台服务器 
	    10. 支持云虚拟化部署，保护云端多台服务器
	    ......(更多定制需求请加QQ/微信:4108863)
	    
二、安装步骤  
  1. 安装OpenSSL和libpcre开发库
  CentOS : 
  	yum install openssl openssl-devel
  	yum install -y pcre pcre-devel 
  	
  Debian/Ubuntu:
  	sudo apt-get install openssl libssl-dev
  	apt-get install libpcre3 libpcre3-dev  
  
  2.编译
  解压到任意目录，make即可，完成后生成可执行文件hihttps.
  
  3.规则
  规则放在和hihttps同一级的rules目录即可，注意后缀是.conf或者.rule,更多规则请在
  https://github.com/SpiderLabs/owasp-modsecurity-crs/下载，根据需求配置。
  具体请看rules/main.conf详细说明。
  
  4.运行
  通常是hihttps前端运行443（https）端口，后端反向代理80端口。
  首先保证Web服务器80端口运行正常，443端口没占用（或者端口在config.cfg里改变配置)
  ./hihttps默认读取当前目录下的confg.cfg文件， 或者./hihttps --config /dir/config.cfg
  具体请看config.cfg详细说明， 如果成功打印加载了rules目录下的规则，代表运行成功。
  
  5.测试
  rules/main.rule默认加载了一条SQL语句检测规则，可以访问https://ip/select.html?testsql=delete * from test
  或者用WEB漏洞扫描器nikto运行：./nikto  -host ip -ssl -port 443 -C all
  如果产生了报警记录，则代表正常！相关图片在doc目录。
  
  
  6.需要更多高级防护和web管理功能，请加QQ/微信:4108863
  
  
  
  
