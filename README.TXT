一、aihttps是hihttps的升级版，首款基于机器学习、自主对抗未知攻击的高性能WEB应用防火墙（ SSL WAF），源码完整并且兼容ModSecurity正则规则。
      1. 恶意Web漏洞扫描
	    2. 数据库SQL注入
	    3. 跨站脚本攻击（XSS)
	    4、CC  & DDOS防护
	    5、密码暴力破解
	    6. 危险文件上传检测
	    7. 非法URL/文件访问
	    8. 兼容OWASP的ModSecurity正则规则
	    9. epoll模型单核数万并发连接
	    10.无监督机器学习、自主生成对抗规则
	    .....	   
	    
二、编译运行,测试推荐CentOS7
  1. 安装openssl和libpcre库
  CentOS : 
  	yum install openssl openssl-devel
  	yum install -y pcre pcre-devel 
  	
  Debian/Ubuntu:
  	sudo apt-get install openssl libssl-dev
  	apt-get install libpcre3 libpcre3-dev  
  
  2.编译
  解压到任意目录，make后生成可执行文件aihttps
  [rules]是规则目录，[train]是样本采集目录，[vector]是自然语言word2doc向量生成目录，[src]是源码目录。
 
  
  3.规则
  规则放在和aihttps同一级的rules目录，更多规则在https://github.com/SpiderLabs/owasp-modsecurity-crs/ 下载。

  
  4.运行
  通常aihttps前端绑定443端口（https），后端反向代理80端口; 首先保证Web服务器80端口运行正常，443端口没占用。  
  ./aihttps默认读取当前目录下的confg.cfg文件，  或者./aihttps --config /dir/config.cfg， 打印出规则就成功。
  
三、攻击测试  
  1.ModSecuriyt规则测试
  rules/main.rule默认加载了一条SQL语句检测规则，可以访问https://serverip/select.html?testsql=delete * from test
  或者用Kali系统的漏洞扫描器nikto运行：./nikto  -host serverip -ssl -port 443 -C all
  如果产生了报警记录，则代表正常！
  
  
  2.机器学习/自主对抗规则测试方法：
  机器学习原理：https://www.freebuf.com/articles/web/226418.html
  
  机器学习是核心，但采集样本需要一定时间，为了方便测试，默认了一条aihttps.html对抗规则：
  如果访问https://serverip/aihttps.html?id=123采集到的样本大于99%都是这种形态，那么下面的网址都将产生攻击报警：
  
  https://serverip/aihttps.html?id=123' or 1='1
  https://serverip/aihttps.html?id=<script>alert(1);</script>
  https://serverip/aihttps.html?id=1234567890&t=123
  https://serverip/aihttps.html?id=abc
  
  3、要测试并发连接，可以用wrk等工具在相同环境测试比nginx反向代理的性能更强。
  wrk -c 25 -t 25 -d 10 https://127.0.0.1/
  

四、WEB管理 
   WEB管理仅商业版才提供，实战演示请访问http://101.42.31.94/  仅仅是一个静态网站，每天来自全球的未知攻击触目惊心。  

五、商业版  
   此源码仅供代码学习，不要在生产环境部署，实战请用商业版本，也是开源的。更多介绍请访问http://101.42.31.94/io/  或者   QQ/微信:4108863 邮件:4108863@qq.com      



  
  
  
  

