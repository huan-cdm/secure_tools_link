##### 项目介绍

平时工作中用到的安全工具链接，方便用的时候查找。  **持续更新**，欢迎Star。


##### BurpSuite插件汇总
- [TsojanScan](https://github.com/Tsojan/TsojanScan)：一个集成的BurpSuite漏洞探测插件，它会以最少的数据包请求来准确检测各漏洞存在与否，你只需要这一个足矣。
- [JsRouteScan](https://github.com/F6JO/JsRouteScan)：正则匹配获取响应中的路由进行探测或递归目录探测的burp插件。
- [BurpAPIFinder](https://github.com/shuanx/BurpAPIFinder/)：攻防演练过程中，我们通常会用浏览器访问一些资产，但很多未授权/敏感信息/越权隐匿在已访问接口过html、JS文件等，该插件能让我们发现未授权/敏感信息/越权/登陆接口等。
- [BurpShiroPassiveScan](https://github.com/pmiaowu/BurpShiroPassiveScan)：一款基于BurpSuite的被动式shiro检测插件。
- [turbo-intruder](https://github.com/PortSwigger/turbo-intruder)：Turbo  Intruder 是一个 Burp Suite 扩展插件， 用于发送大量 HTTP 请求并分析结果，它旨在处理那些需要异常速度、持续时间或复杂性的攻击来补充 Burp  Intruder，可以发现条件竞争和短信轰炸等漏洞。 
- [captcha-killer-modified](https://github.com/f0ng/captcha-killer-modified)：一款适用于Burp的验证码识别插件。
- [HackBar](https://github.com/d3vilbug/HackBar)：HackBar是burp插件，支持很多便携功能，SQL注入payload、XSS payload、常见LFI漏洞、web shell payload和反弹shell payload。
- [Autorize](https://github.com/Quitten/Autorize)：越权检测 burp插件。
- [HaE](https://github.com/gh0stkey/HaE)：HaE是一个基于BurpSuite Java插件API开发的辅助型框架式插件，旨在实现对HTTP消息的高亮标记和信息提取。该插件通过自定义正则表达式匹配响应报文或请求报文，并对匹配成功的报文进行标记和提取。
- [jsEncrypter](https://github.com/c0ny1/jsEncrypter)：本插件使用phantomjs启动前端加密函数对数据进行加密，方便对加密数据输入点进行fuzz，比如可以使用于前端加密传输爆破等场景。
- [Wsdler](https://github.com/NetSPI/Wsdler)：Wsdler 可以解析 WSDL 请求，以便使用 repeater 和 scanner 对 WSDL 请求进行测试。
- [domain_hunter_pro](https://github.com/bit4woo/domain_hunter_pro)：这款插件很好的补充了BURP的域名收集问题，让你的BURP更加强大，更加系统的收集项目内的域名和子域名扩大域名资产，增加攻击面。
- [J2EEScan](https://github.com/ilmila/J2EEScan)：J2EEScan 是一个扫描器增强插件，可以通过该插件扫描 J2EE 漏洞，如 weblogic、struts2 、 jboss 等漏洞。
- [Struts2Burp](https://github.com/x1a0t/Struts2Burp)：一款检测Struts2 RCE漏洞的burp被动扫描插件，仅检测url后缀为.do以及.action的数据包。
- [software-vulnerability-scanner](https://github.com/PortSwigger/software-vulnerability-scanner)：Software Vulnerability Scanner 是一个扫描器增强插件，它会检查网站的一些软件版本信息，然后通过 vulners.com 上的漏洞数据库来查询相应的 CVE 编号，找到的结果会显示在漏洞面板上，不用我们自己手动去查找某个版本的 CVE 。
- [BurpJSLinkFinder](https://github.com/InitRoot/BurpJSLinkFinder)：插件很好的兼容进了BURP里面，随着你的点击自动进行收集JS里面的路径。
- [jython-standalone](https://repo1.maven.org/maven2/org/python/jython-standalone/2.7.3/jython-standalone-2.7.3.jar)：Jython是一个将Python语言与Java虚拟机集成的工具，burp中安装python编写插件。
- [FastjsonScan](https://github.com/Maskhe/FastjsonScan)：被动扫描fastjson漏洞。
- [BurpFastJsonScan](https://github.com/pmiaowu/BurpFastJsonScan)：一款基于BurpSuite的被动式FastJson检测插件。
- [log4j2burpscanner](https://github.com/f0ng/log4j2burpscanner)：被动发现log4j2 RCE漏洞。
- [chunked-coding-converter](https://github.com/c0ny1/chunked-coding-converter)：分块传输绕WAF插件。
- [CaA](https://github.com/gh0stkey/CaA)：CaA是一个基于BurpSuite Java插件API开发的流量收集和分析插件。它的主要作用就是收集HTTP协议报文中的参数、路径、文件、参数值等信息，并统计出现的频次，为使用者积累真正具有实战意义的Fuzzing字典。除此之外，CaA还提供了独立的Fuzzing功能，可以根据用户输入的字典，以不同的请求方式交叉遍历请求，从而帮助用户发现隐藏的参数、路径、文件，以便于进一步发现安全漏洞。
- [APIKit](https://github.com/API-Security/APIKit)：APIKit可以主动/被动扫描发现应用泄露的API文档，并将API文档解析成BurpSuite中的数据包用于API安全测试。
- [ssrf-king](https://github.com/ethicalhackingplayground/ssrf-king)：burp插件自动化检测ssrf漏洞。
- [npscrack](https://github.com/weishen250/npscrack)：蓝队利器、溯源反制、NPS 漏洞利用、NPS exp、NPS poc、Burp插件、一键利用。
- [burpFakeIP](https://github.com/TheKingOfDuck/burpFakeIP)：伪造请求IP插件。
- [BurpSuite_403Bypasser](https://github.com/sting8k/BurpSuite_403Bypasser)：绕过 403 受限目录的 burpsuite 扩展。




##### 漏洞扫描和利用工具汇总
- [BurpSuite](https://pan.baidu.com/s/1fG_2tTDbaGUjkk3Br_puSg?pwd=vvkm)：代理抓包工具。
- [Struts2-Scan](https://github.com/HatBoy/Struts2-Scan)：Struts2漏洞利用扫描工具。
- [Struts2VulsScanTools](https://github.com/abc123info/Struts2VulsScanTools)：Struts2全版本漏洞检测工具s。
- [WeblogicScan](https://github.com/rabbitmask/WeblogicScan)：Weblogic一键漏洞检测工具。
- [fastjson_rec_exploit](https://github.com/mrknow001/fastjson_rec_exploit)：fastjson一键漏洞检测工具。
- [ShiroAttack2](https://github.com/SummerSec/ShiroAttack2)：一款针对Shiro550漏洞进行快速漏洞利用工具。
- [ShiroExploit-Deprecated](https://github.com/feihong-cs/ShiroExploit-Deprecated)：Shiro550/Shiro721 一键化利用工具，支持多种回显方式。
- [springboot core命令执行](https://github.com/zangcc/CVE-2022-22965-rexbb)：springboot core 命令执行漏洞，CVE-2022-22965漏洞利用工具，基于JavaFx开发，图形化操作更简单，提高效率。
- [ThinkphpGUI](https://github.com/Lotus6/ThinkphpGUI)：Thinkphp(GUI)漏洞利用工具，支持各版本TP漏洞检测，命令执行，getshell。
- [heapdump_tool](https://github.com/wyzxxz/heapdump_tool)：对pringboot actuator未授权泄露的heapdump文件进行解密，可解密出账号密码等敏感信息。
- [dddd](https://github.com/SleepingBag945/dddd)：信息收集和漏洞扫描工具。
- [EZ](https://github.com/m-sec-org/EZ)：EZ是一款集信息收集、端口扫描、服务暴破、URL爬虫、指纹识别、被动扫描为一体的跨平台漏洞扫描器，渗透测试中，可辅助发现常见的SQL注入、XSS、XXE、SSRF之类的漏洞，通过内置的POC辅助发现Apache Shiro、RabbitMQ、Struts2之类的通用组件漏洞，以及某服VPN、通达OA以及泛微OA之类的被曝出已知漏洞的系统，可谓是外围打点，破局进内网，全面发现漏洞的渗透测试必备武器。
- [xray](https://github.com/chaitin/xray)：一款功能强大的安全评估工具。
- [super-xray](https://github.com/4ra1n/super-xray/)：xray GUI版，来帮助新人更快使用。
- [rad](https://github.com/chaitin/rad)：一款专为安全扫描而生的浏览器爬虫。
- [katana](https://github.com/projectdiscovery/katana)：一款专为安全扫描而生的浏览器爬虫。
- [在线端口扫描](http://coolaf.com/tool/port)：在线端口扫描工具。
- [goby](https://gobysec.net/)：综合漏洞扫描工具。
- [Hyacinth](https://github.com/pureqh/Hyacinth)：一款java漏洞集合工具，其中包含Struts2、Fastjson、Weblogic（xml）、Shiro、Log4j、Jboss、SpringCloud、等漏洞检测利用模块，及免杀webshell生成模块 Bypass、以及一些小工具模块等。
- [vulmap](https://github.com/zhzyker/vulmap)：Vulmap 是一款 web 漏洞扫描和验证工具, 可对 webapps 进行漏洞扫描, 并且具备漏洞利用功能, 目前支持的 webapps 包括 activemq, flink, shiro, solr, struts2, tomcat, unomi, drupal, elasticsearch, fastjson, jenkins, nexus, weblogic, jboss, spring, thinkphp。
- [nikto](https://github.com/sullo/nikto)：nikto是一款比较综合性的漏洞扫描工具。支持XSS SQL注入等常见的漏洞扫描，因其使用简单，扫描效率比较高。
- [yakit](https://github.com/yaklang/yakit)：综合漏洞扫描工具、单兵作战武器库、可以代替BurpSuite。
- [oracleShell](https://github.com/jas502n/oracleShell)：oracleShell oracle 数据库命令执行、支持普通、DBA、注入3种模式。
- [nuclei](https://github.com/projectdiscovery/nuclei)：Nuclei 用于基于模板跨目标发送请求，从而实现零误报并提供对大量主机的快速扫描。Nuclei 提供对各种协议的扫描，包括 TCP、DNS、HTTP、SSL、File、Whois、Websocket、Headless 等。凭借强大而灵活的模板，Nuclei 可用于对各种安全检查进行建模。
- [Fiora](https://github.com/bit4woo/Fiora)：该项目为PoC框架nuclei提供图形界面，实现快速搜索、一键运行等功能，提升nuclei的使用体验。
- [SNETCracker](https://github.com/shack2/SNETCracker)：超级弱口令检查工具是一款Windows平台的弱口令审计工具，工具目前支持SSH、RDP、SMB、MySQL、SQLServer、Oracle、FTP、MongoDB、Memcached、PostgreSQL、Telnet、SMTP、SMTP_SSL、POP3、POP3_SSL、IMAP、IMAP_SSL、SVN、VNC、Redis等服务的弱口令检查工作。
- [nessus](https://mp.weixin.qq.com/s/JnIQL8FeYcqWR4zES56K_g)：综合漏洞扫描工具。
- [awvs](https://mp.weixin.qq.com/s/IclMKi0mZj75gbntntat8A)：综合漏洞扫描工具。
- [XSStrike](https://github.com/s0md3v/XSStrike)：XSStrike 是一款专门用于检测和利用跨站脚本（XSS）漏洞的工具。
- [scan4all](https://github.com/GhostTroops/scan4all)：综合漏洞扫描工具。
- [afrog](https://github.com/zan8in/afrog)：综合漏洞扫描工具。
- [OA-EXPTOOL](https://github.com/LittleBear4/OA-EXPTOOL)：OA综合漏洞检测工具（与msf操作方法类似）。
- [I-Wanna-Get-All](https://github.com/R4gd0ll/I-Wanna-Get-All)：OA综合漏洞检测工具（图形化）。
- [超级未授权检测工具](https://pan.baidu.com/s/1cfYdWoETxKeNf5myCqY_OA?from=init&pwd=0000)：超级未授权检测工具，目前已实现47种未授权检测。
- [NaturalTeeth](https://github.com/ddwGeGe/NaturalTeeth)：OA系统漏洞利用工具。
- [EasyPen](https://github.com/lijiejie/EasyPen/)：EasyPen是使用Python + wxPython编写、提供简洁图形界面、支持跨平台的安全扫描工具，可用于企业内外网巡检、应急响应、白帽子对各SRC的持续检测。
- [goon](https://github.com/i11us0ry/goon/)：goon,集合了fscan和kscan等优秀工具功能的扫描爆破工具。
功能包含：ip探活、port扫描、web指纹扫描、title扫描、fofa获取、ms17010、mssql、mysql、postgres、redis、ssh、smb、rdp、telnet等爆破
以及如netbios探测等功能。
- [onlinetools](https://github.com/iceyhexman/onlinetools)：在线工具集、在线cms识别、信息泄露、工控、系统、物联网安全、cms漏洞扫描、nmap端口扫描、子域名获取。
- [cloud_asset_management_tools](https://github.com/huan-cdm/cloud_asset_management_tools)：云存储利用工具。
- [container-escape-check](https://github.com/teamssix/container-escape-check)：容器逃逸检测脚本。
- [aliyun-accesskey-Tools](https://github.com/mrknow001/aliyun-accesskey-Tools)：阿里云accesskey利用工具。
- [Cloud-Bucket-Leak-Detection-Tools](https://github.com/UzJu/Cloud-Bucket-Leak-Detection-Tools)：六大云存储，泄露利用检测工具。
- [marshalsec](https://github.com/mbechler/marshalsec)：Java反序列漏洞利用工具，快速开启RMI和LDAP服务，下载使maven进行编译即可。
- [ysoserial](https://github.com/frohoff/ysoserial)：Java反序列漏洞利用工具。




##### 内网渗透常用工具汇总
- [fscan](https://github.com/shadow1ng/fscan)：一款内网综合扫描工具，方便一键自动化、全方位漏扫扫描。
支持主机存活探测、端口扫描、常见服务的爆破、ms17010、redis批量写公钥、计划任务反弹shell、读取win网卡信息、web指纹识别、web漏洞扫描、netbios探测、域控识别等功能。
- [Ladon](https://github.com/k8gege/Ladon)：Ladon大型内网渗透工具集合
- [EquationToolsGUI](https://github.com/abc123info/EquationToolsGUI)：仅用来扫描和验证MS17-010、MS09-050、MS08-067漏洞，并可协助管理员修复系统漏洞。



##### 摄像头相关汇总
- [HikvisionIVMSGetShell](https://github.com/Tas9er/HikvisionIVMSGetShell)：海康威视IVMS综合安防管理平台软件漏洞利用工具。




##### 代码审计工具汇总
- [rips-scanner](https://sourceforge.net/projects/rips-scanner/files/)：php代码审计工具。
- [seay](https://github.com/f1tz/cnseay)：php代码审计工具。
- [VisualCodeGrepper](https://sourceforge.net/projects/visualcodegrepp/?source=directory)：VCG 是一款适用于 C++、C#、VB、PHP、Java、PL/SQL 和 COBOL 的自动化代码安全审查工具，旨在通过识别不良/不安全代码来加快代码审查过程。
- [Fortify](https://pan.baidu.com/s/1umNn7SFP-Y0Mw2R_L9zaBg?pwd=a3oq)：Fortify Source Code Analysis Suite是目前在全球使用最为广泛的软件源代码安全扫描，分析和软件安全风险管理软件。使用此款工具的前提是，代码能够正常编译且不报错，否则扫描后会出现error，影响测试结果。支持在Linux、Windows、Mac OSX系统中进行安装。如果测试Objective-C语言，需要使用Mac OSX系统，同时注意Xcode版本和fortify版本的兼容性问题。
- [sublimetext](https://www.sublimetext.com/)：文本编辑器。
- [IntelliJ IDEA](https://www.jetbrains.com/zh-cn/idea/download/?section=windows)：代码编辑器，动态调试。
- [MOMO CODE SEC INSPECTOR](https://www.jetbrains.com/zh-cn/idea/download/?section=windows)：IntelliJ IDEA代码审计插件，在插件商店下载。




##### 信息收集工具汇总
- [EHole](https://github.com/EdgeSecurityTeam/EHole)：EHole是一款对资产中重点系统指纹识别的工具，在红队作战中，信息收集是必不可少的环节，如何才能从大量的资产中提取有用的系统(如OA、VPN、Weblogic...)。EHole旨在帮助红队人员在信息收集期间能够快速从C段、大量杂乱的资产中精准定位到易被攻击的系统，从而实施进一步攻击。
- [Finger](https://github.com/EASY233/Finger)：一款红队在大量的资产中存活探测与重点攻击系统指纹探测工具。
- [URLFinder](https://github.com/pingc0y/URLFinder)：URLFinder是一款快速、全面、易用的页面信息提取工具用于分析页面中的js与url,查找隐藏在其中的敏感信息或未授权api接口。
- [JSFinder](https://github.com/Threezh1/JSFinder)：JSFinder是一款用作快速在网站的js文件中提取URL，子域名的工具。
- [dirsearch](https://github.com/maurosoria/dirsearch)：网站目录扫描。
- [Packer-Fuzzer](https://github.com/rtcatc/Packer-Fuzzer)：一款针对Webpack等前端打包工具所构造的网站进行快速、高效安全检测的扫描工具。
- [OneForAll](https://github.com/shmilylty/OneForAll)：OneForAll是一款功能强大的子域收集工具。
- [subDomainsBrute](https://github.com/lijiejie/subDomainsBrute)：子域名收集工具。
- [证书发现子域名](https://crt.sh/)：基于证书的子域名查询网站。
- [ARL](https://github.com/TophantTechnology/ARL)：旨在快速侦察与目标关联的互联网资产，构建基础资产信息库。 协助甲方安全团队或者渗透测试人员有效侦察和检索资产，发现存在的薄弱点和攻击面。
- [masscan](https://github.com/robertdavidgraham/masscan)：Masscan是一个高速的端口扫描工具,可以在数秒内扫描大量主机和端口。它使用异步套接字和线程,支持IPv4和IPv6网络,并且可以配置多个端口扫描选项。
- [httpx](https://github.com/projectdiscovery/httpx)：httpx 是一个go语言开发的快速且多用途的 HTTP 工具包，允许使用 retryablehttp 库运行多个探测器。可以获取url的状态，title，jarm等信息，也可以对网站截图。
- [alivecheck](https://pan.baidu.com/s/1b9MxHb0VoPJ3CI2X3a04dQ?pwd=oc63)：小米范存活检测工具。
- [Search_Viewer](https://github.com/G3et/Search_Viewer)：网络空间搜索引擎客户端，目前支持fofa、shodan、hunter、quake、zoomeye。
- [fofa_viewer](https://github.com/wgpsec/fofa_viewer)：Fofa Viewer 是一个用 JavaFX 编写的用户友好的 FOFA 客户端。
- [TideFinger](https://github.com/TideSec/TideFinger)：TideFinger——指纹识别小工具，汲取整合了多个web指纹库，结合了多种指纹检测方法，让指纹检测更快捷、准确。
- [云悉](https://www.yunsee.cn/)：云悉WEB资产梳理-在线CMS指纹识别平台。
- [Github-Monitor](https://github.com/VKSRC/Github-Monitor)：监控Github代码仓库的系统。
- [Hawkeye](https://github.com/0xbug/Hawkeye)：监控github代码库，及时发现员工托管公司代码到GitHub行为并预警，降低代码泄露风险。
- [BBScan](https://github.com/lijiejie/BBScan)：BBScan 是一个高并发、轻量级的信息泄露扫描工具。
- [GitHack](https://github.com/lijiejie/GitHack)：GitHack是一个.git泄露利用脚本，通过泄露的.git文件夹下的文件，重建还原工程源代码。
- [ds_store_exp](https://github.com/lijiejie/ds_store_exp)：ds_store_exp是一个 .DS_Store 文件泄漏利用脚本，它解析.DS_Store文件并递归地下载文件到本地。
- [AppInfoScanner](https://github.com/kelvinBen/AppInfoScanner)：一款适用于以HW行动/红队/渗透测试团队为场景的移动端(Android、iOS、WEB、H5、静态网站)信息收集扫描工具，可以帮助渗透测试工程师、攻击队成员、红队成员快速收集到移动端或者静态WEB站点中关键的资产信息并提供基本的信息输出,如：Title、Domain、CDN、指纹信息、状态信息等。
- [WebBatchRequest](https://github.com/ScriptKid-Beta/WebBatchRequest/)：WEB批量请求器（WebBatchRequest）是对目标地址批量进行快速的存活探测、Title获取，简单的banner识别，支持HTTP代理以及可自定义HTTP请求用于批量的漏洞验证等的一款基于JAVA编写的轻量工具。
- [wafw00f](https://github.com/EnableSecurity/wafw00f)：waf识别工具。
- [七麦数据](https://www.qimai.cn/)：企业app搜索网站。
- [小蓝本](https://sou.xiaolanben.com/pc)：企业网站资产查询，配合天眼查、企查查等。
- [virustotal](https://www.virustotal.com/graph/)：企业资产梳理，包括子域名等，需要登录。
- [ShuiZe_0x727](https://github.com/0x727/ShuiZe_0x727)：协助红队人员快速的信息收集，测绘目标资产，寻找薄弱点。




##### 溯源相关汇总
- [IP位置查询](https://ip.sy/)：IP定位查询。
- [域名备案查询](https://icp.chinaz.com/krev.com)：域名备案查询。
- [情报社区](https://x.threatbook.com/)：微步在线X情报社区。
- [REG007](https://www.reg007.com/)：通过手机号和邮箱查询注册过哪些网站。
- [注册宝](http://www.regbao.com/)：通过手机号和邮箱查询注册过哪些网站。
- [Privacy](https://privacy.aiuys.com/)：免费社工库（需翻墙访问）。
- [ip138](https://site.ip138.com/ip138.ip/)：IP反查域名。
- [whois](http://whois.bugscaner.com/)：域名whois查询。
- [chaipip](https://www.chaipip.com/aiwen.html)：埃文科技IP定位查询。
- [wireshark](https://www.wireshark.org/)：数据包分析工具。




##### 应急响应汇总
- [D盾_防火墙](https://www.d99net.net/)：webshell查杀工具。
- [火绒剑](https://www.huorong.cn/)：火绒剑是一款安全工具，主要用于分析和处理恶意程序火绒剑提供了多种功能，包括但不限于程序行为监控、进程管理、启动项管理、内核程序管理、钩子扫描、服务管理、驱动扫描、网络监控、文件管理和注册表管理等。
- [yara_scan](https://github.com/huan-cdm/yara_scan)：利用yara引擎自定义检测规则，支持静态文件和内存木马的扫描。
- [360星图](https://pan.baidu.com/s/1n2mlbUK0PXfM6Msn_e70EA?pwd=yeop)：网站日志分析工具。
- [AppCompatCacheParser](https://www.sans.org/tools/appcompatcacheparser/)：获取windows系统可执行文件记录。
- [Log Parser](https://www.sans.org/tools/appcompatcacheparser/)：windows系统日志分析工具。
- [Everything](https://www.voidtools.com/zh-cn/downloads/)：文本搜索工具。
- [FireKylin](https://github.com/MountCloud/FireKylin)：网络安全应急响应工具(系统痕迹采集)，面对多台主机需要排查时，只需要把agent端发给服务器运维管理人员运行采集器，将采集结果给到安全人员，来由安全人员进行分析。
- [河马webshell查杀工具](https://www.shellpub.com/)：河马webshell查杀工具（安装版）。
- [日志分析工具合集](https://www.cnblogs.com/xiaozi/p/13198071.html)：应急响应日志分析工具 。
- [BlueTeamTools](https://github.com/abc123info/BlueTeamTools)：蓝队分析工具箱by:ABC_123 "蓝队分析研判工具箱"就是把我平时写的蓝队小工具集合起来形成的，重点解决蓝队分析工作中的一些痛点问题 。
- [processhacker](https://processhacker.sourceforge.io/downloads.php)：一款强大的系统监控与管理工具。





##### APP安全测试工具汇总
- [apk2url](https://github.com/n0mi1k/apk2url)：提取apk中的IP和URL。
- [apkleaks](https://github.com/dwisiswant0/apkleaks)：apk爬虫工具可提取包内url等信息。
- [drozer](https://github.com/WithSecureLabs/drozer/)：drozer是一款针对Android系统的安全测试框架。
- [Yaazhini](https://www.vegabird.com/yaazhini/)：Yaazhini是一款针对Android APK和API的免费漏洞扫描工具，这款工具提供了用户友好的操作界面，广大移动端安全研究人员可以在Yaazhini的帮助下，轻松扫描任何Android应用程序的APK文件以及API接口，而且Yaazhini还会给你提供非常丰富的扫描结果数据。
- [AndroidKiller](https://pan.baidu.com/s/1yYlky-I1QQQrjHbVEz0N7Q?pwd=gvxg)：Android逆向工具。
- [夜神模拟器](https://pan.baidu.com/s/1bvBLA2tRqILjzBGvglF_XQ?pwd=1ncq)：夜神模拟器v6.6.1.1版本。
- [Charles](https://www.charlesproxy.com/latest-release/download.do)：APP网络层抓包工具，和Postern、BurpSuite配合使用。
- [Charles破解](https://www.zzzmode.com/mytools/charles/)：charles在线激活网站。
- [Postern](https://pan.baidu.com/s/19FRlASE-v5iCinyYGxoudQ?pwd=bbwt)：Android代理客户端，和Charles、BurpSuite配合使用。
- [Mobile-Security-Framework-MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF)：APP漏洞扫描平台。
- [jadx-gui](https://github.com/skylot/jadx)：apk反编译工具。
- [PKID](https://pan.baidu.com/s/1OVm7BPEitIMZLPzSQXSRcg?pwd=7vk8)：apk查壳工具。
- [Xposed模块仓库](https://modules.lsposed.org/)：Xposed模块仓库。




##### 小程序安全测试工具汇总
- [PC微信小程序一键解密](https://github.com/huan-cdm/Wechat-small-program-decompile)：PC微信小程序一键解密，PC微信小程序需先利用UnpackMiniApp.exe解密在进行反编译。
- [WxAppUnpacker](https://github.com/huan-cdm/Wechat-small-program-decompile)：微信小程序反编译工具。
- [微信开发者工具](https://developers.weixin.qq.com/miniprogram/dev/devtools/stable.html)：微信开发者工具调试微信小程序。
- [Proxifier](https://pan.baidu.com/s/1UHF_KsOqJpsY2P8-uHauoA?pwd=8hk9)：微信小程序抓包用到的代理客户端。




##### 火狐浏览器插件汇总（扩展和主题->插件->输入对应名字进行搜索->添加插件）
- [Wappalyzer](https://addons.mozilla.org/zh-CN/firefox/search/?q=Wappalyzer)：网站指纹识别。
- [FindSomething](https://addons.mozilla.org/zh-CN/firefox/search/?q=FindSomething)：用于快速在网页的html源码或js代码中提取一些有趣的信息，包括可能请求的资源、接口的url，可能请求的ip和域名，泄漏的证件号、手机号、邮箱等信息。
- [FoxyProxy Standard](https://addons.mozilla.org/zh-CN/firefox/search/?q=FoxyProxy%20Standard)：FoxyProxy是一个高级的代理管理工具。
- [HackTools](https://addons.mozilla.org/zh-CN/firefox/search/?q=Hack-Tools)：Hacktools，是一个方便您的web应用程序渗透测试的web扩展，它包括小抄以及测试期间使用的所有工具，如XSS有效载荷，反向shell来测试您的web应用程序。
- [superSearchPlus](https://addons.mozilla.org/zh-CN/firefox/search/?q=SuperSearchPlus)：superSearchPlus是聚合型信息收集插件，支持综合查询，资产测绘查询，信息收集 整合了目前常见的资产测绘平台 同时支持数据导出。
- [Shodan](https://addons.mozilla.org/zh-CN/firefox/search/?q=shodan)：通过插件查看IP Address、Hostname、Open Ports、Tags。
- [Ctool](https://addons.mozilla.org/zh-CN/firefox/addon/ctool/)：程序日常开发常用小工具集合,提供哈希/加解密/编码转换/时间戳/二维码/拼音/IP查询/代码优化/Unicode/正则等多种工具。




##### 暴力破解字典汇总
- [fuzzDicts](https://github.com/TheKingOfDuck/fuzzDicts)：暴力破解字典。
- [weakpass](https://zzzteph.github.io/weakpass/)：在线密码字典生成网站。
- [密码字典生成器](https://www.shentoushi.top/tools/dict/index.php)：在线密码字典生成网站。
- [UserNameDictTools](https://github.com/abc123info/UserNameDictTools)：用户名字典生成工具V0.2发布，(将中文汉字姓名转成11种格式的拼音)。




##### 接口分析工具汇总
- [Apifox](https://apifox.com/)：Apifox是一个集接口文档、接口调试、自动化测试、Mock服务于一体的全新一代API管理工具。它通过图形界面提供了一种简单直观的方式来创建、管理和测试API接口，无论是前端开发者、后端开发者还是测试人员都能快速上手。Apifox不仅支持RESTful API，也支持GraphQL、Dubbo等多种接口类型，满足不同项目的需求。




##### webshell管理工具汇总
- [Behinder](https://github.com/rebeyond/Behinder)：冰蝎动态二进制加密网站管理客户端。
- [Godzilla](https://github.com/BeichenDream/Godzilla)：哥斯拉websheell管理客户端。
- [antSword](https://github.com/AntSwordProject/antSword)：中国蚁剑是一款跨平台的开源网站管理工具。
- [caidao](https://github.com/raddyfiy/caidao-official-version)：中国菜刀官方版本。




##### 数据库管理工具汇总
- [AnotherRedisDesktopManager](https://github.com/qishibo/AnotherRedisDesktopManager)：redis客户端管理工具。




##### 靶场汇总
- [Vulhub](https://vulhub.org/)：Vulhub是一个基于docker和docker-compose的漏洞环境集合，进入对应目录并执行一条语句即可启动一个全新的漏洞环境，让漏洞复现变得更加简单，让安全研究者更加专注于漏洞原理本身。
- [pikachu](https://github.com/zhuifengshaonianhanlu/pikachu)：Pikachu是一个带有漏洞的Web应用系统，在这里包含了常见的web安全漏洞。 如果你是一个Web渗透测试学习人员且正发愁没有合适的靶场进行练习，那么Pikachu可能正合你意。
- [dwva](https://github.com/digininja/DVWA)：DVWA(Damn Vulnerable Web Application)一个用来进行安全脆弱性鉴定的PHP/MySQL Web 应用，旨在为安全专业人员测试自己的专业技能和工具提供合法的环境，帮助web开发者更好的理解web应用安全防范的过程。
- [upload-labs](https://github.com/c0ny1/upload-labs)：upload-labs是一个使用php语言编写的，专门收集渗透测试和CTF中遇到的各种上传漏洞的靶场。
- [sqli-labs](https://github.com/Audi-1/sqli-labs)：sql注入练习靶场。
- [ctfhub](https://www.ctfhub.com/#/index)：在线版ctf靶场。
- [acunetix](http://vulnweb.com/)：acunetix在线靶场。
- [portswigger](https://portswigger.net/web-security)：BurpSuite官方靶场。




##### 网络空间搜索汇总
- [QUAKE](https://quake.360.net/quake/#/index)：网络空间搜索平台。
- [FOFA](https://fofa.info/)：网络空间搜索平台。
- [HUNTER](https://hunter.qianxin.com/)：网络空间搜索平台。
- [binaryedge](https://app.binaryedge.io/login)：网络空间搜索平台。
- [shodan](https://www.shodan.io/)：网络空间搜索平台。




##### 在线dnslog平台汇总
- [DNSlog](http://www.dnslog.cn/)：在线DNSLog平台。
- [CEYE](http://ceye.io/)：在线DNSLog平台。




##### 博客文库汇总
- [乌云](https://wy.zone.ci/bugs.php)：博客和文库整理。
- [先知社区](https://xz.aliyun.com/)：博客和文库整理。
- [PeiQi文库](https://peiqi.wgpsec.org/)：博客和文库整理。
- [Track 安全社区](https://bbs.zkaq.cn/)：博客和文库整理。
- [freebuf](https://www.freebuf.com/)：博客和文库整理。
- [离别歌](https://www.leavesongs.com/)：博客和文库整理。
- [Web安全学习笔记](https://www.bookstack.cn/read/LyleMi-Learn-Web-Hacking/81ab7f9e9d252390.md)：博客和文库整理。
- [内网相关](https://www.chabug.org/web/1263)：博客和文库整理。
- [应急响应](https://github.com/Bypass007/Emergency-Response-Notes)：博客和文库整理。
- [公众号文章](http://www.nmd5.com/test/index.php#)：博客和文库整理。
- [T Wiki](https://wiki.teamssix.com/about/)：云安全知识文库。
- [渗透师导航](https://www.shentoushi.top/)：渗透师导航。
- [SummaryOf2022](https://github.com/abc123info/SummaryOf2022)：2022年ABC123公众号年刊 2023年ABC123公众号年刊。




##### 科学上网代理汇总
- [GW树洞](https://helloshudong.com/)：科学上网。
- [一元机场](https://xn--4gq62f52gdss.com/#/login)：科学上网。
- [rotateproxy](https://github.com/akkuman/rotateproxy)：利用fofa搜索socks5开放代理进行代理池轮切的工具。
- [Gofreeproxy](https://github.com/ja9er/Gofreeproxy)：利用fofa搜索socks5开放代理进行代理池轮切的工具。




##### 安全加固汇总
- [jshaman](http://jshaman.com/)：JavaScript源代码混淆加密 - JS混淆、JS加密。
- [Maven Repository](https://mvnrepository.com/)：查看pom中的组件版本是否存在安全漏洞。




##### 常用链接汇总
- [java环境](https://www.oracle.com/java/technologies/downloads/)：java jdk下载。
- [python环境](https://www.python.org/downloads/)：python下载。
- [Notepad++](https://notepad-plus.en.softonic.com/)：文本编辑器。
- [keepass](https://keepass.info/download.html)：密码管理工具。
- [FinalShell](http://www.hostbuf.com/t/988.html)：SSH工具。
- [NirSoft](https://www.nirsoft.net/)：NirSoft 网站提供了一系列独特的小型实用软件。




##### 在线加解密网站汇总
- [jwt](https://jwt.io/)：jwt加解密网站。
- [cmd5](https://cmd5.com/)：md5加解密网站。
- [somd5](https://www.somd5.com/)：md5加解密网站。
- [unicode](https://tool.chinaz.com/tools/unicode.aspx)：unicode编码转换网站。
- [base64](https://tool.chinaz.com/Tools/Base64.aspx)：base64编码转换网站。
- [aes](http://tool.chacuo.net/cryptaes)：aes加解密网站。
- [字符串<->十六进制](https://www.sojson.com/hexadecimal.html)：十六进制字符串转换网站。




##### 服务器汇总
- [xampp](https://www.apachefriends.org/zh_cn/index.html)：XAMPP（Apache+MySQL+PHP+PERL）是一个功能强大的建站集成软件包。
- [phpstudy](https://www.xp.cn/)：phpStudy是一个PHP调试环境的程序集成包。该程序包集成最新的Apache+PHP+MySQL+phpMyAdmin+ZendOptimizer，一次性安装，无须配置即可使用，是非常方便、好用的PHP调试环境。
- [Apache Tomcat](https://tomcat.apache.org/)：运行java代码的web服务器。


-**持续更新中**