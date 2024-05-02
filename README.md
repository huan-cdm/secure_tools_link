##### 项目介绍

整理平时工作中比较好用的BurpSuite插件和安全工具，**持续更新**，欢迎Star。


##### BurpSuite插件汇总

- [TsojanScan](https://github.com/Tsojan/TsojanScan)：一个集成的BurpSuite漏洞探测插件，它会以最少的数据包请求来准确检测各漏洞存在与否，你只需要这一个足矣。
- [JsRouteScan](https://github.com/F6JO/JsRouteScan)：正则匹配获取响应中的路由进行探测或递归目录探测的burp插件。
- [ShiroScan](https://github.com/Daybr4ak/ShiroScan)：burp插件 Shiroscan 主要用于框架、无dnslog key检测，可被动扫描出默认的key。
- [turbo-intruder](https://github.com/PortSwigger/turbo-intruder)：Turbo  Intruder 是一个 Burp Suite 扩展插件， 用于发送大量 HTTP 请求并分析结果，它旨在处理那些需要异常速度、持续时间或复杂性的攻击来补充 Burp  Intruder，可以发现条件竞争和短信轰炸等漏洞。 
- [captcha-killer-modified](https://github.com/f0ng/captcha-killer-modified)：一款适用于Burp的验证码识别插件。
- [HackBar](https://github.com/d3vilbug/HackBar)：HackBar是burp插件，支持很多便携功能，SQL注入payload、XSS payload、常见LFI漏洞、web shell payload和反弹shell payload。
- [Autorize](https://github.com/Quitten/Autorize)：越权检测 burp插件。
- [HaE](https://github.com/gh0stkey/HaE)：HaE是一个基于BurpSuite Java插件API开发的辅助型框架式插件，旨在实现对HTTP消息的高亮标记和信息提取。该插件通过自定义正则表达式匹配响应报文或请求报文，并对匹配成功的报文进行标记和提取。
- [jsEncrypter](https://github.com/c0ny1/jsEncrypter)：本插件使用phantomjs启动前端加密函数对数据进行加密，方便对加密数据输入点进行fuzz，比如可以使用于前端加密传输爆破等场景。
- [Wsdler](https://github.com/NetSPI/Wsdler)：Wsdler 可以解析 WSDL 请求，以便使用 repeater 和 scanner 对 WSDL 请求进行测试。
- [domain_hunter_pro](https://github.com/bit4woo/domain_hunter_pro)：这款插件很好的补充了BURP的域名收集问题，让你的BURP更加强大，更加系统的收集项目内的域名和子域名扩大域名资产，增加攻击面。
- [J2EEScan](https://github.com/ilmila/J2EEScan)：J2EEScan 是一个扫描器增强插件，可以通过该插件扫描 J2EE 漏洞，如 weblogic、struts2 、 jboss 等漏洞。
- [software-vulnerability-scanner](https://github.com/PortSwigger/software-vulnerability-scanner)：Software Vulnerability Scanner 是一个扫描器增强插件，它会检查网站的一些软件版本信息，然后通过 vulners.com 上的漏洞数据库来查询相应的 CVE 编号，找到的结果会显示在漏洞面板上，不用我们自己手动去查找某个版本的 CVE 。
- [BurpJSLinkFinder](https://github.com/InitRoot/BurpJSLinkFinder)：插件很好的兼容进了BURP里面，随着你的点击自动进行收集JS里面的路径。
- [jython-standalone](https://repo1.maven.org/maven2/org/python/jython-standalone/2.7.3/jython-standalone-2.7.3.jar)：Jython是一个将Python语言与Java虚拟机集成的工具，burp中安装python编写插件。
- [FastjsonScan](https://github.com/Maskhe/FastjsonScan)：被动扫描fastjson漏洞。
- [log4j2burpscanner](https://github.com/f0ng/log4j2burpscanner)：被动发现log4j2 RCE漏洞。
- [chunked-coding-converter](https://github.com/c0ny1/chunked-coding-converter)：分块传输绕WAF插件。


##### 漏洞扫描工具汇总
- [Struts2-Scan](https://github.com/HatBoy/Struts2-Scan)：Struts2漏洞利用扫描工具。
- [WeblogicScan](https://github.com/rabbitmask/WeblogicScan)：Weblogic一键漏洞检测工具。
- [fastjson_rec_exploit](https://github.com/mrknow001/fastjson_rec_exploit)：fastjson一键漏洞检测工具。
- [dddd](https://github.com/SleepingBag945/dddd)：信息收集和漏洞扫描工具。
- [fscan](https://github.com/shadow1ng/fscan)：一款内网综合扫描工具，方便一键自动化、全方位漏扫扫描。
支持主机存活探测、端口扫描、常见服务的爆破、ms17010、redis批量写公钥、计划任务反弹shell、读取win网卡信息、web指纹识别、web漏洞扫描、netbios探测、域控识别等功能。
- [xray](https://github.com/chaitin/xray)：一款功能强大的安全评估工具。
- [rad](https://github.com/chaitin/rad)：一款专为安全扫描而生的浏览器爬虫。
- [goby](https://gobysec.net/)：综合漏洞扫描工具。


##### 信息收集工具汇总
- [EHole](https://github.com/EdgeSecurityTeam/EHole)：EHole是一款对资产中重点系统指纹识别的工具，在红队作战中，信息收集是必不可少的环节，如何才能从大量的资产中提取有用的系统(如OA、VPN、Weblogic...)。EHole旨在帮助红队人员在信息收集期间能够快速从C段、大量杂乱的资产中精准定位到易被攻击的系统，从而实施进一步攻击。
- [URLFinder](https://github.com/pingc0y/URLFinder)：URLFinder是一款快速、全面、易用的页面信息提取工具用于分析页面中的js与url,查找隐藏在其中的敏感信息或未授权api接口。
- [JSFinder](https://github.com/Threezh1/JSFinder)：JSFinder是一款用作快速在网站的js文件中提取URL，子域名的工具。
- [dirsearch](https://github.com/maurosoria/dirsearch)：网站目录扫描。
- [Packer-Fuzzer](https://github.com/rtcatc/Packer-Fuzzer)：一款针对Webpack等前端打包工具所构造的网站进行快速、高效安全检测的扫描工具。
- [OneForAll](https://github.com/shmilylty/OneForAll)：OneForAll是一款功能强大的子域收集工具。
- [ARL](https://github.com/TophantTechnology/ARL)：旨在快速侦察与目标关联的互联网资产，构建基础资产信息库。 协助甲方安全团队或者渗透测试人员有效侦察和检索资产，发现存在的薄弱点和攻击面。
- [masscan](https://github.com/robertdavidgraham/masscan)：Masscan是一个高速的端口扫描工具,可以在数秒内扫描大量主机和端口。它使用异步套接字和线程,支持IPv4和IPv6网络,并且可以配置多个端口扫描选项。


##### APP安全测试工具汇总
- [apk2url](https://github.com/n0mi1k/apk2url)：提取apk中的IP和URL。
- [drozer](https://github.com/WithSecureLabs/drozer/)：drozer是一款针对Android系统的安全测试框架。


##### 火狐浏览器插件汇总（扩展和主题->插件->输入对应名字进行搜索->添加插件）
- [Wappalyzer](https://addons.mozilla.org/zh-CN/firefox/search/?q=Wappalyzer)：网站指纹识别。
- [FindSomething](https://addons.mozilla.org/zh-CN/firefox/search/?q=FindSomething)：用于快速在网页的html源码或js代码中提取一些有趣的信息，包括可能请求的资源、接口的url，可能请求的ip和域名，泄漏的证件号、手机号、邮箱等信息。
- [FoxyProxy Standard](https://addons.mozilla.org/zh-CN/firefox/search/?q=FoxyProxy%20Standard)：FoxyProxy是一个高级的代理管理工具。
- [HackTools](https://addons.mozilla.org/zh-CN/firefox/search/?q=Hack-Tools)：Hacktools，是一个方便您的web应用程序渗透测试的web扩展，它包括小抄以及测试期间使用的所有工具，如XSS有效载荷，反向shell来测试您的web应用程序。
- [superSearchPlus](https://addons.mozilla.org/zh-CN/firefox/search/?q=SuperSearchPlus)：superSearchPlus是聚合型信息收集插件，支持综合查询，资产测绘查询，信息收集 整合了目前常见的资产测绘平台 同时支持数据导出。
- [Shodan](https://addons.mozilla.org/zh-CN/firefox/search/?q=shodan)：通过插件查看IP Address、Hostname、Open Ports、Tags。



-**持续更新中**