##### 项目介绍

平时工作中用到的安全工具链接，方便用的时候查找。  **持续更新**，欢迎Star。
##### 信息安全相关面试题
- [Sec-Interview-4-2023](https://github.com/vvmdx/Sec-Interview-4-2023)：一个2023届毕业生在毕业前持续更新、收集的安全岗面试题及面试经验分享~




##### HW期间POC总结
- [2022-HW-POC](https://github.com/Phuong39/2022-HW-POC)：2022 护网行动 POC 整理。
- [2023HW](https://github.com/huan-cdm/2023HW)：2023HW资料汇总。




##### BurpSuite插件汇总
- [Fiora](https://github.com/bit4woo/Fiora)：该项目为PoC框架nuclei提供图形界面，实现快速搜索、一键运行等功能，提升nuclei的使用体验。
- [autoDecoder](https://github.com/f0ng/autoDecoder)：工具本身就自带了一些常见的加解密算法，除此之外复杂的可以调接口。
- [TsojanScan](https://github.com/Tsojan/TsojanScan)：一个集成的BurpSuite漏洞探测插件，它会以最少的数据包请求来准确检测各漏洞存在与否，你只需要这一个足矣。
- [JsRouteScan](https://github.com/F6JO/JsRouteScan)：正则匹配获取响应中的路由进行探测或递归目录探测的burp插件。
- [BurpAPIFinder](https://github.com/shuanx/BurpAPIFinder/)：攻防演练过程中，我们通常会用浏览器访问一些资产，但很多未授权/敏感信息/越权隐匿在已访问接口过html、JS文件等，该插件能让我们发现未授权/敏感信息/越权/登陆接口等。
- [BurpShiroPassiveScan](https://github.com/pmiaowu/BurpShiroPassiveScan)：一款基于BurpSuite的被动式shiro检测插件✳。
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
- [FastjsonScan](https://github.com/Maskhe/FastjsonScan)：被动扫描fastjson漏洞✳。
- [BurpFastJsonScan](https://github.com/pmiaowu/BurpFastJsonScan)：一款基于BurpSuite的被动式FastJson检测插件。
- [log4j2burpscanner](https://github.com/f0ng/log4j2burpscanner)：被动发现log4j2 RCE漏洞。
- [chunked-coding-converter](https://github.com/c0ny1/chunked-coding-converter)：分块传输绕WAF插件。
- [CaA](https://github.com/gh0stkey/CaA)：CaA是一个基于BurpSuite Java插件API开发的流量收集和分析插件。它的主要作用就是收集HTTP协议报文中的参数、路径、文件、参数值等信息，并统计出现的频次，为使用者积累真正具有实战意义的Fuzzing字典。除此之外，CaA还提供了独立的Fuzzing功能，可以根据用户输入的字典，以不同的请求方式交叉遍历请求，从而帮助用户发现隐藏的参数、路径、文件，以便于进一步发现安全漏洞。
- [APIKit](https://github.com/API-Security/APIKit)：APIKit可以主动/被动扫描发现应用泄露的API文档，并将API文档解析成BurpSuite中的数据包用于API安全测试。
- [ssrf-king](https://github.com/ethicalhackingplayground/ssrf-king)：burp插件自动化检测ssrf漏洞。
- [npscrack](https://github.com/weishen250/npscrack)：蓝队利器、溯源反制、NPS 漏洞利用、NPS exp、NPS poc、Burp插件、一键利用。
- [burpFakeIP](https://github.com/TheKingOfDuck/burpFakeIP)：伪造请求IP插件。
- [BurpSuite_403Bypasser](https://github.com/sting8k/BurpSuite_403Bypasser)：绕过 403 受限目录的 burpsuite 扩展。
- [gatherBurp](https://github.com/kN6jq/gatherBurp)：一款综合的burp插件。
- [xia_Liao](https://github.com/smxiazi/xia_Liao)：xia Liao（瞎料）burp插件 用于Windows在线进程/杀软识别 与 web渗透注册时，快速生成需要的资料用来填写，资料包含：姓名、手机号、身份证、统一社会信用代码、组织机构代码、银行卡，以及各类web语言的hello world输出和生成弱口令字典等。
- [OneScan](https://github.com/vaycore/OneScan)：OneScan是递归目录扫描的BurpSuite插件。
- [BurpFingerPrint](https://github.com/shuanx/BurpFingerPrint)：攻击过程中，我们通常会用浏览器访问一些资产，该BurpSuite插件实现被动指纹识别+网站提取链接+OA爆破，可帮助我们发现更多资产。
- [reflector](https://github.com/elkokc/reflector)：BurpSuite反射XSS插件。
- [BucketVulTools](https://github.com/libaibaia/BucketVulTools)：Burpsuite存储桶配置不当漏洞检测插件。




##### 综合漏洞扫描工具汇总
- [info_scan](https://github.com/huan-cdm/info_scan)：自动化漏洞扫描系统。
- [BurpSuite](https://pan.baidu.com/s/1fG_2tTDbaGUjkk3Br_puSg?pwd=vvkm)：代理抓包工具。
- [heapdump_tool](https://github.com/wyzxxz/heapdump_tool)：对pringboot actuator未授权泄露的heapdump文件进行解密，可解密出账号密码等敏感信息。
- [dddd](https://github.com/SleepingBag945/dddd)：信息收集和漏洞扫描工具。
- [EZ](https://github.com/m-sec-org/EZ)：EZ是一款集信息收集、端口扫描、服务暴破、URL爬虫、指纹识别、被动扫描为一体的跨平台漏洞扫描器，渗透测试中，可辅助发现常见的SQL注入、XSS、XXE、SSRF之类的漏洞，通过内置的POC辅助发现Apache Shiro、RabbitMQ、Struts2之类的通用组件漏洞，以及某服VPN、通达OA以及泛微OA之类的被曝出已知漏洞的系统，可谓是外围打点，破局进内网，全面发现漏洞的渗透测试必备武器。
- [super-xray](https://github.com/4ra1n/super-xray/)：xray GUI版，来帮助新人更快使用。
- [rad](https://github.com/chaitin/rad)：一款专为安全扫描而生的浏览器爬虫。
- [katana](https://github.com/projectdiscovery/katana)：一款专为安全扫描而生的浏览器爬虫。
- [linbing](https://github.com/taomujian/linbing)：本系统是对Web中间件和Web框架进行自动化渗透的一个系统,根据扫描选项去自动化收集资产,然后进行POC扫描,POC扫描时会根据指纹选择POC插件去扫描,POC插件扫描用异步方式扫描.前端采用vue技术,后端采用python fastapi。
- [ScopeSentry](https://github.com/Autumn-27/ScopeSentry)：Scope Sentry是一款具有资产测绘、子域名枚举、信息泄露检测、漏洞扫描、目录扫描、子域名接管、爬虫、页面监控功能的工具，通过构建多个节点，自由选择节点运行扫描任务。当出现新漏洞时可以快速排查关注资产是否存在相关组件。
- [nikto](https://github.com/sullo/nikto)：nikto是一款比较综合性的漏洞扫描工具。支持XSS SQL注入等常见的漏洞扫描，因其使用简单，扫描效率比较高。
- [yakit](https://github.com/yaklang/yakit)：综合漏洞扫描工具、单兵作战武器库、可以代替BurpSuite。
- [oracleShell](https://github.com/jas502n/oracleShell)：oracleShell oracle 数据库命令执行、支持普通、DBA、注入3种模式。
- [nuclei](https://github.com/projectdiscovery/nuclei)：Nuclei 用于基于模板跨目标发送请求，从而实现零误报并提供对大量主机的快速扫描。Nuclei 提供对各种协议的扫描，包括 TCP、DNS、HTTP、SSL、File、Whois、Websocket、Headless 等。凭借强大而灵活的模板，Nuclei 可用于对各种安全检查进行建模。
- [nessus](https://mp.weixin.qq.com/s/JnIQL8FeYcqWR4zES56K_g)：综合漏洞扫描工具。
- [awvs](https://mp.weixin.qq.com/s/IclMKi0mZj75gbntntat8A)：综合漏洞扫描工具。
- [scan4all](https://github.com/GhostTroops/scan4all)：综合漏洞扫描工具。
- [oday](https://github.com/Janhsu/oday)：本工具是采用javafx编写，使用sqllite进行poc储存的poc管理和漏洞扫描集成化工具。可以可视化添加POC和指纹进行POC管理和漏洞扫描功能，包含POC管理、漏洞扫描、指纹识别、指纹库等模块。
- [prismx](https://github.com/yqcs/prismx)：棱镜 X 一体化的轻量型跨平台渗透系统。
- [OA-EXPTOOL](https://github.com/LittleBear4/OA-EXPTOOL)：OA综合漏洞检测工具（与msf操作方法类似）。
- [I-Wanna-Get-All](https://github.com/R4gd0ll/I-Wanna-Get-All)：OA综合漏洞检测工具（图形化）。
- [超级未授权检测工具](https://pan.baidu.com/s/1cfYdWoETxKeNf5myCqY_OA?from=init&pwd=0000)：超级未授权检测工具，目前已实现47种未授权检测。
- [TscanPlus](https://github.com/TideSec/TscanPlus)：一款综合性网络安全检测和运维工具，旨在快速资产发现、识别、检测，构建基础资产信息库，协助甲方安全团队或者安全运维人员有效侦察和检索资产，发现存在的薄弱点和攻击面。
- [NaturalTeeth](https://github.com/ddwGeGe/NaturalTeeth)：OA系统漏洞利用工具。
- [EasyPen](https://github.com/lijiejie/EasyPen/)：EasyPen是使用Python + wxPython编写、提供简洁图形界面、支持跨平台的安全扫描工具，可用于企业内外网巡检、应急响应、白帽子对各SRC的持续检测。
- [goon](https://github.com/i11us0ry/goon/)：goon,集合了fscan和kscan等优秀工具功能的扫描爆破工具。
功能包含：ip探活、port扫描、web指纹扫描、title扫描、fofa获取、ms17010、mssql、mysql、postgres、redis、ssh、smb、rdp、telnet等爆破
以及如netbios探测等功能。
- [onlinetools](https://github.com/iceyhexman/onlinetools)：在线工具集、在线cms识别、信息泄露、工控、系统、物联网安全、cms漏洞扫描、nmap端口扫描、子域名获取。
- [murphysec](https://github.com/murphysecurity/murphysec)：An open source tool focused on software supply chain security. 墨菲安全专注于软件供应链安全，具备专业的软件成分分析（SCA）、漏洞检测、专业漏洞库。
- [PotatoTool](https://github.com/HotBoy-java/PotatoTool?tab=readme-ov-file)：这款工具是一款功能强大的网络安全综合工具，旨在为安全从业者、红蓝对抗人员和网络安全爱好者提供全面的网络安全解决方案。它集成了多种实用功能，包括解密、分析、扫描、溯源等，为用户提供了便捷的操作界面和丰富的功能选择。



##### Web通用漏洞工具
- [sqlmc](https://github.com/malvads/sqlmc)：SQL注入检测工具。
- [XSStrike](https://github.com/s0md3v/XSStrike)：XSStrike 是一款专门用于检测和利用跨站脚本（XSS）漏洞的工具。




##### Java反序列漏洞利用工具汇总
- [marshalsec](https://github.com/mbechler/marshalsec)：Java反序列漏洞利用工具，快速开启RMI和LDAP服务，下载使maven进行编译即可。
- [ysoserial](https://github.com/frohoff/ysoserial)：Java反序列漏洞利用工具。
- [JNDInjector](https://github.com/rebeyond/JNDInjector)：一个高度可定制化的JNDI和Java反序列化利用工具。
- [JNDIExploit](https://github.com/zzwlpx/JNDIExploit)：A malicious LDAP server for JNDI injection attacks。
- [ysoserial](https://github.com/frohoff/ysoserial)：java反序列化有效负载的项目。
- [JNDI-Injection-Exploit](https://github.com/welk1n/JNDI-Injection-Exploit)：JNDI注入测试工具。





##### 云安全测试工具汇总
- [cloud_asset_management_tools](https://github.com/huan-cdm/cloud_asset_management_tools)：部分OSS存储利用工具备份。
- [container-escape-check](https://github.com/teamssix/container-escape-check)：容器逃逸检测脚本。
- [aliyun-accesskey-Tools](https://github.com/mrknow001/aliyun-accesskey-Tools)：阿里云accesskey利用工具。
- [Cloud-Bucket-Leak-Detection-Tools](https://github.com/UzJu/Cloud-Bucket-Leak-Detection-Tools)：六大云存储，泄露利用检测工具。
- [OSSFileBrowse](https://github.com/jdr2021/OSSFileBrowse)：存储桶遍历漏洞利用工具。
- [cloudTools](https://github.com/dark-kingA/cloudTools)：云资产管理工具 目前工具定位是云安全相关工具，目前是两个模块 云存储工具、云服务工具， 云存储工具主要是针对oss存储、查看、删除、上传、下载、预览等等 云服务工具主要是针对rds、服务器的管理，查看、执行命令、接管等等。
- [ossbrowser](https://www.alibabacloud.com/help/zh/oss/developer-reference/install-and-log-on-to-ossbrowser#p-4ca-yxe-p7r)：阿里云官方ossbrowser图形化工具。
- [T Wiki](https://wiki.teamssix.com/about/)：云安全漏洞测试SOP文档。
- [行云管家](https://yun.cloudbility.com/)：行云管家。
- [ossx](https://github.com/sourcexu7/ossx)：存储桶遍历漏洞利用脚本。
- [Docker容器挂载目录原理](https://blog.csdn.net/wang2leee/article/details/134453249)：Docker容器挂载目录原理。



##### 红队常用命令总结
- [红队常用命令速查](https://github.com/safe6Sec/command)：红队常用命令速查。



##### 红队前期打点工具汇总
- [Finger](https://github.com/EASY233/Finger)：一款红队在大量的资产中存活探测与重点攻击系统指纹探测工具。
- [ShuiZe_0x727](https://github.com/0x727/ShuiZe_0x727)：协助红队人员快速的信息收集，测绘目标资产，寻找薄弱点。
- [POC-bomber](https://github.com/tr0uble-mAker/POC-bomber)：利用大量高威胁poc/exp快速获取目标权限，用于渗透和红队快速打点
- [afrog](https://github.com/zan8in/afrog)：综合漏洞扫描工具。
- [vulmap](https://github.com/zhzyker/vulmap)：Vulmap 是一款 web 漏洞扫描和验证工具, 可对 webapps 进行漏洞扫描, 并且具备漏洞利用功能, 目前支持的 webapps 包括 activemq, flink, shiro, solr, struts2, tomcat, unomi, drupal, elasticsearch, fastjson, jenkins, nexus, weblogic, jboss, spring, thinkphp。
- [fscan](https://github.com/shadow1ng/fscan)：一款内网综合扫描工具，方便一键自动化、全方位漏扫扫描。
- [railgun](https://github.com/lz520520/railgun/)：Railgun为一款GUI界面的渗透工具，将部分人工经验转换为自动化，集成了渗透过程中常用到的一些功能，目前集成了端口扫描、端口爆破、web指纹扫描、漏洞扫描、漏洞利用以及编码转换功能，后续会持续更新。
- [Web-Fuzzing-Box](https://github.com/gh0stkey/Web-Fuzzing-Box)：Web Fuzzing Box - Web 模糊测试字典与一些Payloads，主要包含：弱口令暴力破解、目录以及文件枚举、Web漏洞...。
- [ServerScan](https://github.com/Adminisme/ServerScan)：一款使用Golang开发且适用于攻防演习内网横向信息收集的高并发网络扫描、服务探测工具。
- [goby](https://gobysec.net/)：综合漏洞扫描工具。
- [xray](https://github.com/chaitin/xray)：一款功能强大的安全评估工具。
- [pocscan](https://github.com/DSO-Lab/pocscan)：该工具主要用于指纹识别后，进行漏洞精准扫描。
- [myscan](https://github.com/amcai/myscan)：myscan是参考awvs的poc目录架构，pocsuite3、sqlmap等代码框架，以及搜集互联网上大量的poc，由python3开发而成的被动扫描工具。
- [w9scan](https://github.com/w-digital-scanner/w9scan)：一款全能型的网站漏洞扫描器，借鉴了各位前辈的优秀代码。内置1200+插件可对网站进行一次规模的检测，功能包括但不限于web指纹检测、端口指纹检测、网站结构分析、各种流行的漏洞检测、爬虫以及SQL注入检测、XSS检测等等，w9scan会自动生成精美HTML格式结果报告。
- [pocsuite3](https://github.com/knownsec/pocsuite3)：开源的远程漏洞测试框架。
- [TangGo](https://tanggo.nosugar.tech/)：TangGo是一款国产化综合性测试平台，用于Web站点的功能测试和安全评估。
- [ApolloScanner](https://github.com/b0bac/ApolloScanner)：自动化巡航扫描框架（可用于红队打点评估）。
- [kscan](https://github.com/lcvvvv/kscan)：Kscan是一款纯go开发的全方位扫描器，具备端口扫描、协议检测、指纹识别，暴力破解等功能。支持协议1200+，协议指纹10000+，应用指纹20000+，暴力破解协议10余种。
- [bscan](https://github.com/broken5/bscan)：bscan的是一款强大、简单、实用、高效的HTTP扫描器。
- [ARL](https://github.com/Aabyss-Team/ARL)：AboutARL官方仓库备份项目：ARL(Asset Reconnaissance Lighthouse)资产侦察灯塔系统旨在快速侦察与目标关联的互联网资产，构建基础资产信息库。 协助甲方安全团队或者渗透测试人员有效侦察和检索资产，发现存在的薄弱点和攻击面。
- [xpoc](https://github.com/chaitin/xpoc)：为供应链漏洞扫描设计的快速应急响应工具 [快速应急] [漏洞扫描] [端口扫描]。
- [mitan](https://github.com/kkbo8005/mitan)：密探渗透测试工具包含资产信息收集，子域名爆破，搜索语法，资产测绘（FOFA，Hunter，quake, ZoomEye），指纹识别，敏感信息采集，文件扫描、密码字典等功能。





##### 中间件框架漏洞利用工具汇总
- [SpringExploit](https://github.com/SummerSec/SpringExploit)：Spring系列漏洞利用工具。
- [ShiroScan](https://github.com/sv3nbeast/ShiroScan)：Shiro<=1.2.4反序列化，一键检测工具。
- [shiro_rce_tool](https://github.com/wyzxxz/shiro_rce_tool)：shiro 反序列 命令执行辅助检测工具。
- [ShiroAttack2](https://github.com/SummerSec/ShiroAttack2)：shiro反序列化漏洞综合利用,包含（回显执行命令/注入内存马）修复原版中NoCC的问题。
- [shiro-exploit](https://github.com/Ares-X/shiro-exploit)：Shiro反序列化利用工具，支持新版本(AES-GCM)Shiro的key爆破，配合ysoserial，生成回显Payload。
- [ShiroExploit-Deprecated](https://github.com/feihong-cs/ShiroExploit-Deprecated)：Shiro550/Shiro721 一键化利用工具，支持多种回显方式。
- [springboot core命令执行](https://github.com/zangcc/CVE-2022-22965-rexbb)：springboot core 命令执行漏洞，CVE-2022-22965漏洞利用工具，基于JavaFx开发，图形化操作更简单，提高效率。
- [FastjsonExploit](https://github.com/c0ny1/FastjsonExploit)：fastjson漏洞快速利用框架。
- [fastjson_rec_exploit](https://github.com/mrknow001/fastjson_rec_exploit)：fastjson一键漏洞检测工具。
- [jexboss](https://github.com/joaomatosf/jexboss)：Jboss（和 Java 反序列化漏洞）验证和利用工具。
- [WeblogicScan](https://github.com/rabbitmask/WeblogicScan)：Weblogic一键漏洞检测工具。
- [weblogicScanner](https://github.com/0xn0ne/weblogicScanner)：weblogic 漏洞扫描工具。目前包含对以下漏洞的检测能力：CVE-2014-4210、CVE-2016-0638、CVE-2016-3510、CVE-2017-3248、CVE-2017-3506、CVE-2017-10271、CVE-2018-2628、CVE-2018-2893、CVE-2018-2894、CVE-2018-3191、CVE-2018-3245、CVE-2018-3252、CVE-2019-2618、CVE-2019-2725、CVE-2019-2729、CVE-2019-2890、CVE-2020-2551、CVE-2020-14750、CVE-2020-14882、CVE-2020-14883。
- [weblogic-infodetector](https://github.com/woodpecker-appstore/weblogic-infodetector)：woodpecker框架weblogic信息探测插件。
- [dubbo-exp](https://github.com/threedr3am/dubbo-exp)：dubbo快速利用exp，基本上老版本覆盖100%。
- [Jiraffe](https://github.com/0x48piraj/Jiraffe)：Jiraffe 是为利用 Jira 实例而编写的半自动安全工具。
- [STS2G](https://github.com/xfiftyone/STS2G)：Struts2漏洞扫描利用工具 - Golang版。
- [Struts2-Scan](https://github.com/HatBoy/Struts2-Scan)：Struts2漏洞利用扫描工具。
- [Struts2VulsScanTools](https://github.com/abc123info/Struts2VulsScanTools)：Struts2全版本漏洞检测工具。
- [log4j-shell-poc](https://github.com/kozmer/log4j-shell-poc)：log4j漏洞利用工具。
- [CVE-2022-26134-Godzilla-MEMSHELL](https://github.com/BeichenDream/CVE-2022-26134-Godzilla-MEMSHELL)：Confluence-OGNL一键注入内存shell。
- [nacos-poc](https://github.com/ayoundzw/nacos-poc)：阿里 NACOS 远程命令执行漏洞POC。
- [NacosExploitGUI](https://github.com/charonlight/NacosExploitGUI)：Nacos漏洞综合利用GUI工具，集成了默认口令漏洞、SQL注入漏洞、身份认证绕过漏洞、反序列化漏洞的检测及其利用。
- [Hyacinth](https://github.com/pureqh/Hyacinth)：一款java漏洞集合工具，其中包含Struts2、Fastjson、Weblogic（xml）、Shiro、Log4j、Jboss、SpringCloud、等漏洞检测利用模块，及免杀webshell生成模块 Bypass、以及一些小工具模块等。
- [exphub](https://github.com/zhzyker/exphub)：Exphub[漏洞利用脚本库] 包括Webloigc、Struts2、Tomcat、Nexus、Solr、Jboss、Drupal的漏洞利用脚本，最新添加CVE-2020-14882、CVE-2020-11444、CVE-2020-10204、CVE-2020-10199、CVE-2020-1938、CVE-2020-2551、CVE-2020-2555、CVE-2020-2883、CVE-2019-17558、CVE-2019-6340。
- [jeecg-](https://github.com/MInggongK/jeecg-)：jeecg综合漏洞利用工具。




##### cms漏洞利用工具汇总
- [seeyon_exp](https://github.com/Summer177/seeyon_exp)：致远OA综合利用工具。
- [TDOA_RCE](https://github.com/xinyu2428/TDOA_RCE)：通达OA综合利用工具。
- [weaver_exp](https://github.com/z1un/weaver_exp)：泛微OA漏洞综合利用脚本。
- [EgGateWayGetShell](https://github.com/Tas9er/EgGateWayGetShell)：锐捷网络EG易网关RCE批量安全检测。
- [CMSmap](https://github.com/Dionach/CMSmap)：CMSmap 针对流行CMS进行安全扫描的工具。
- [wordpress-exploit-framework](https://github.com/rastating/wordpress-exploit-framework)：WordPress漏洞扫描工具。
- [Aazhen-RexHa](https://github.com/zangcc/Aazhen-RexHa)：自研JavaFX图形化漏洞扫描工具，支持扫描的漏洞分别是： ThinkPHP-2.x-RCE， ThinkPHP-5.0.23-RCE， ThinkPHP5.0.x-5.0.23通杀RCE， ThinkPHP5-SQL注入&敏感信息泄露， ThinkPHP 3.x 日志泄露NO.1， ThinkPHP 3.x 日志泄露NO.2， ThinkPHP 5.x 数据库信息泄露的漏洞检测，以及批量检测的功能。漏洞POC基本适用ThinkPHP全版本漏洞。
- [ThinkphpGUI](https://github.com/Lotus6/ThinkphpGUI)：Thinkphp(GUI)漏洞利用工具，支持各版本TP漏洞检测，命令执行，getshell。
- [Thinkphp_Red-Tasselled-Spear](https://github.com/CllmsyK/Thinkphp_Red-Tasselled-Spear)：Thinkphp图形化检测工具。
- [TPscan](https://github.com/Lucifer1993/TPscan)：基于python3的一键ThinkPHP漏洞检测工具。
- [thinkphp_gui_tools](https://github.com/bewhale/thinkphp_gui_tools)：ThinkPHP漏洞综合利用工具, 图形化界面, 命令执行, 一键getshell, 批量检测, 日志遍历, session包含,宝塔绕过。
- [Apt_t00ls](https://github.com/White-hua/Apt_t00ls)：高危漏洞利用工具。
- [oFx](https://github.com/bigblackhat/oFx)：漏洞批量验证框架。
- [Frchannel](https://github.com/7wkajk/Frchannel)：帆软bi反序列化漏洞利用工具。




##### 内网渗透常用工具汇总
支持主机存活探测、端口扫描、常见服务的爆破、ms17010、redis批量写公钥、计划任务反弹shell、读取win网卡信息、web指纹识别、web漏洞扫描、netbios探测、域控识别等功能。
- [Ladon](https://github.com/k8gege/Ladon)：Ladon大型内网渗透工具集合
- [EquationToolsGUI](https://github.com/abc123info/EquationToolsGUI)：仅用来扫描和验证MS17-010、MS09-050、MS08-067漏洞，并可协助管理员修复系统漏洞。
- [Windows提权辅助工具](https://i.hacking8.com/tiquan/)：在线版Windows 提权辅助工具。
- [shellcodeloader](https://github.com/knownsec/shellcodeloader/)：Windows平台的shellcode免杀加载器。
- [Open3389](https://github.com/3had0w/Open3389/tree/master)：利用Windows的RegCreateKeyEx和RegSetValueEx两个API和RegistryKey类来操作系统注册表，与无Net.exe添加管理员用户一样，都是直接利用的Windows API来执行相应操作。
- [gotohttp](https://gotohttp.com/)：远控工具，控制端不用安装，通过网页控制。
- [searchall](https://github.com/Naturehi666/searchall/)：强大的敏感信息搜索工具。
- [readTdose-xiangrikui](https://github.com/flydyyg/readTdose-xiangrikui?tab=readme-ov-file)：Todest和向日葵ID和密码读取工具。
- [SAMInside](https://www.downza.cn/soft/271449.html)：Saminside是一个暴力破解工具,可以通过读取本地帐户的lmhash值,对hash值进行暴力破解,从而得到真正的登录密码。
- [MaLoader](https://github.com/lv183037/MaLoader)：一款基于Tauri+Rust的免杀马生成工具。
- [e0e1-config](https://github.com/eeeeeeeeee-code/e0e1-config/)：支持firefox、ie和chromium内核浏览器、Windows记事本和Notepad++、向日葵、ToDesk、Navicat 、DBeaver 、FinalShell 、Xshell和Xftp、FileZilla 、winscp等密码一键提取。




##### 隧道代理工具汇总
- [Neo-reGeorg](https://github.com/L-codes/Neo-reGeorg)：Neo-reGeorg 是 reGeorg 和 reDuh 的升级版，是为了应付复杂的网络环境重构的项目。该工具基于 HTTP(S) 协议建立隧道，会在本地创建 Socket 监听 1080 端口用于正向代理访问 Web 服务器隧道脚本，通过正向代理的方式把数据加密封装到 HTTP 数据包中转发到服务器的横向网络中，同时隧道脚本也会把内网服务器端口的数据加密封装到 HTTP 数据包中转发到本地的 Socket 接口。
- [frp](https://github.com/fatedier/frp)：一个快速反向代理，帮助您将NAT或防火墙后面的本地服务器暴露到互联网上。




##### 硬件安全相关汇总
- [HikvisionIVMSGetShell](https://github.com/Tas9er/HikvisionIVMSGetShell)：海康威视IVMS综合安防管理平台软件漏洞利用工具。
- [wifi-crack-tool](https://github.com/baihengaead/wifi-crack-tool)：WiFi密码暴力破解工具-图形界面。




##### 代码审计工具汇总
- [rips-scanner](https://sourceforge.net/projects/rips-scanner/files/)：php代码审计工具。
- [seay](https://github.com/f1tz/cnseay)：php代码审计工具。
- [VisualCodeGrepper](https://sourceforge.net/projects/visualcodegrepp/?source=directory)：VCG 是一款适用于 C++、C#、VB、PHP、Java、PL/SQL 和 COBOL 的自动化代码安全审查工具，旨在通过识别不良/不安全代码来加快代码审查过程。
- [Fortify](https://pan.baidu.com/s/1umNn7SFP-Y0Mw2R_L9zaBg?pwd=a3oq)：Fortify Source Code Analysis Suite是目前在全球使用最为广泛的软件源代码安全扫描，分析和软件安全风险管理软件。使用此款工具的前提是，代码能够正常编译且不报错，否则扫描后会出现error，影响测试结果。支持在Linux、Windows、Mac OSX系统中进行安装。如果测试Objective-C语言，需要使用Mac OSX系统，同时注意Xcode版本和fortify版本的兼容性问题。
- [sublimetext](https://www.sublimetext.com/)：文本编辑器。
- [IntelliJ IDEA](https://www.jetbrains.com/zh-cn/idea/download/?section=windows)：代码编辑器，动态调试。
- [MOMO CODE SEC INSPECTOR](https://www.jetbrains.com/zh-cn/idea/download/?section=windows)：IntelliJ IDEA代码审计插件，在插件商店下载。
- [bandit](https://github.com/PyCQA/bandit)：python代码审计工具。




##### 子域名扫描工具汇总
- [OneForAll](https://github.com/shmilylty/OneForAll)：OneForAll是一款功能强大的子域收集工具。
- [subDomainsBrute](https://github.com/lijiejie/subDomainsBrute)：子域名收集工具。
- [Sublist3r](https://github.com/aboul3la/Sublist3r)：子域名收集工具。
- [crt.sh](https://crt.sh/)：这是一个利用证书透明性收集子域名的工具, 其原理是所有SSL/TLS证书都会被记录并公开访问, 只需要要前往crt.sh并输入要枚举的域名即可。
- [Google Dorking](https://www.google.com/)：语法：site:*.domain.com -www。
- [Amass](https://github.com/owasp-amass/amass)：OWASP中的Amass(https://github.com/owasp-amass/amass)是一款功能强大的工具, 它可以通过其API集成连接到其他服务, 使其获取额外的扩展功能。
- [Recon-ng](https://github.com/lanmaster53/recon-ng)：一款全能型OSINT侦查工具, 可以执行各种任务, 包括: 收集电子邮件, 这里只展示其搜集子域的功能。
- [SubDomainizer](https://github.com/nsonaniya2010/SubDomainizer)：不仅仅是一款子域名枚举工具, 还可以找到其他关键信息,例如: API密钥, 该工具语法简单, 易于使用。
- [Pentest Tools Subdomain Finder](https://pentest-tools.com/information-gathering/find-subdomains-of-domain)：一款基于网页的轻量级子域名枚举工具, 使用者可以在没有账号的情况下执行扫描, 但如果想要更多的扫描和更多的工具, 可以注册一个免费账户使用。
- [Shodan](https://www.shodan.io/)：Shodan可以定位子域，并提供基于Web和命令行的界面。要使用Web界面查找子域，访问 https://www.shodan.io/domain/domain.com，将“domain.com”替换为想要枚举的域名。
- [PureDNS](https://github.com/d3mondev/puredns)：PureDNS可以通过启用每秒数千个同时DNS请求来执行快速的子域名枚举，使用公共解析器。要查找子域名。
- [ffuf](https://github.com/ffuf/ffuf)：采用更主动的方法进行枚举。它接受一个给定的单词列表，并通过发出HTTP/S请求检查每个条目，从而确定哪些子域存在。
- [ksubdomain](https://github.com/boy-hack/ksubdomain)：ksubdomain是一款基于无状态的子域名爆破工具，类似无状态端口扫描，支持在Windows/Linux/Mac上进行快速的DNS爆破，拥有重发机制不用担心漏包。
- [在线子域名查询](https://chaziyu.com/)：在线子域名查询。
- [DNSdumpster](https://dnsdumpster.com/)：基于DNS记录获取历史子域名。





##### 指纹识别汇总
- [TideFinger](https://github.com/TideSec/TideFinger)：TideFinger——指纹识别小工具，汲取整合了多个web指纹库，结合了多种指纹检测方法，让指纹检测更快捷、准确。
- [潮汐在线指纹识别](http://finger.tidesec.com/)：潮汐在线指纹识别。
- [云悉](https://www.yunsee.cn/)：云悉WEB资产梳理-在线CMS指纹识别平台。
- [ObserverWard](https://github.com/0x727/ObserverWard)：侦查守卫(ObserverWard)指纹识别工具。
- [WhatWeb](https://github.com/urbanadventurer/WhatWeb)：一个web应用程序指纹识别工具。
- [Glass](https://github.com/s7ckTeam/Glass)：Glass是一款针对资产列表的快速指纹识别工具，通过调用Fofa/ZoomEye/Shodan/360等api接口快速查询资产信息并识别重点资产的指纹，也可针对IP/IP段或资产列表进行快速的指纹识别。
 - [EHole](https://github.com/EdgeSecurityTeam/EHole)：EHole是一款对资产中重点系统指纹识别的工具，在红队作战中，信息收集是必不可少的环节，如何才能从大量的资产中提取有用的系统(如OA、VPN、Weblogic...)。EHole旨在帮助红队人员在信息收集期间能够快速从C段、大量杂乱的资产中精准定位到易被攻击的系统，从而实施进一步攻击。
 - [Webfinger](https://github.com/se55i0n/Webfinger)：Web指纹识别工具。
 - [CMSeek](https://github.com/Tuhinshubhra/CMSeek)：CMS检测和利用套件-扫描WordPress、Joomla、Drupal以及超过180种其他CMS。
  




##### CDN检测工具
- [站长工具多地ping](https://ping.chinaz.com/)：站长工具多地ping。
- [全球多地ping](https://www.itdog.cn/ping/)：全球多地ping。
- [多地ping](https://www.17ce.com/)：多地ping。
- [域名查询IP](https://site.ip138.com/)：对多地ping和IP38查询到的地址是一样的并且只有1个IP证明不存在CDN，反之存在CDN。
- [nslookup查询](https://tool.chinaz.com/nslookup)：nslookup查询，存在1个IP证明不存在CDN,反之存在CDN。
- [全球多地ping](https://tools.ipip.net/cdn.php)：全球多地ping。
- [国外域名查询IP](https://get-site-ip.com/)：国外域名查询IP。




##### 旁站检测汇总
- [站长工具旁站查询](https://tool.chinaz.com/same/)：站长工具旁站查询。




##### 蜜罐判断
- [honeyscore](https://honeyscore.shodan.io/)：蜜罐判断。
- [anti-honeypot](https://github.com/cnrstar/anti-honeypot)：蜜罐判断。
- [Heimdallr](https://github.com/Ghr07h/Heimdallr)：蜜罐判断。


##### js文件提取敏感api接口
- [URLFinder](https://github.com/pingc0y/URLFinder)：URLFinder是一款快速、全面、易用的页面信息提取工具用于分析页面中的js与url,查找隐藏在其中的敏感信息或未授权api接口。
- [JSFinder](https://github.com/Threezh1/JSFinder)：JSFinder是一款用作快速在网站的js文件中提取URL，子域名的工具。
- [url-extractor](https://www.bulkdachecker.com/url-extractor/)：网站URL在线版提取网站。
- [Packer-Fuzzer](https://github.com/rtcatc/Packer-Fuzzer)：一款针对Webpack等前端打包工具所构造的网站进行快速、高效安全检测的扫描工具。




##### 端口扫描工具汇总
- [masscan](https://github.com/robertdavidgraham/masscan)：Masscan是一个高速的端口扫描工具,可以在数秒内扫描大量主机和端口。它使用异步套接字和线程,支持IPv4和IPv6网络,并且可以配置多个端口扫描选项。
- [在线端口扫描](http://coolaf.com/tool/port)：在线端口扫描工具。
- [RustScan](https://github.com/RustScan/RustScan/)：RustScan是一个现代端口扫描器。官方称可以3秒内扫描完成所有65k个端口。它有完整的脚本引擎支持。自动将结果通过管道传输到 Nmap。我们可以使用官方提供的脚本，或自定义脚本来做我们想做的事。
- [nmap](https://github.com/nmap/nmap)：端口扫描。
- [TXPortMap](https://github.com/4dogs-cn/TXPortMap)：端口扫描工具。
- [masnmapscan-V1.0](https://github.com/hellogoldsnakeman/masnmapscan-V1.0)：一款用于资产探测的端口扫描工具。整合了masscan和nmap两款扫描器，masscan扫描端口，nmap扫描端口对应服务，二者结合起来实现了又快又好地扫描。
- [在线端口扫描](https://tool.chinaz.com/port)：在线端口扫描。





##### 弱口令爆破工具汇总
- [SNETCracker](https://github.com/shack2/SNETCracker)：超级弱口令检查工具是一款Windows平台的弱口令审计工具，工具目前支持SSH、RDP、SMB、MySQL、SQLServer、Oracle、FTP、MongoDB、Memcached、PostgreSQL、Telnet、SMTP、SMTP_SSL、POP3、POP3_SSL、IMAP、IMAP_SSL、SVN、VNC、Redis等服务的弱口令检查工作。
- [hydra](https://github.com/vanhauser-thc/thc-hydra)：hydra作为一款暴力破解工具，可以帮助渗透测试人员暴力破解网络服务密码。hydra可以对50多种协议进行快速字典攻击，包括telnet、ftp、http、https、smb、数据库和一些其他服务。hydra由知名黑客组织The Hacker's Choice开发，最早于2000年作为一款POC工具发布。hydra也是一个多线程登录爆破程序，这可以大大提高爆破所用的时间，同样支持apt-get install hydra(ubuntu)。
- [x-crack](https://github.com/netxfly/x-crack)：x-crack - Weak password scanner, Support: FTP/SSH/SNMP/MSSQL/MYSQL/PostGreSQL/REDIS/ElasticSearch/MONGODB。





##### 目录扫描工具汇总
- [dirsearch](https://github.com/maurosoria/dirsearch)：网站目录扫描。
- [BBScan](https://github.com/lijiejie/BBScan)：BBScan 是一个高并发、轻量级的信息泄露扫描工具。
- [dirScan](https://github.com/Degree-21/dirScan)：网站目录、后台扫描 基于御剑字典。
- [dirpro](https://github.com/coleak2021/dirpro)：dirpro 是一款由 python 编写的目录扫描器，操作简单，功能强大，高度自动化自动根据返回状态码和返回长度，对扫描结果进行二次整理和判断，准确性非常高。
- [spray](https://github.com/chainreactors/spray)：下一代目录/文件扫描工具。
- [feroxbuster](https://github.com/epi052/feroxbuster)：用Rust编写的快速，简单，递归的内容发现工具。




##### waf识别和绕过工具汇总
- [wafw00f](https://github.com/EnableSecurity/wafw00f)：waf识别工具。
- [blazehttp](https://github.com/chaitin/blazehttp)：BlazeHTTP 是一款简单易用的 WAF 防护效果测试工具。




##### 网络空间搜索客户端汇总
- [Search_Viewer](https://github.com/G3et/Search_Viewer)：网络空间搜索引擎客户端，目前支持fofa、shodan、hunter、quake、zoomeye。
- [fofa_viewer](https://github.com/wgpsec/fofa_viewer)：Fofa Viewer 是一个用 JavaFX 编写的用户友好的 FOFA 客户端。
- [ThunderSearch](https://github.com/xzajyjs/ThunderSearch)：小而美【支持Fofa、Shodan、Hunter、Zoomeye、Quake网络空间搜索引擎】闪电搜索器；GUI图形化(Mac/Windows)渗透测试信息搜集工具；资产搜集引擎；hw红队工具hvv。




##### github泄露扫描工具汇总
- [Github-Monitor](https://github.com/VKSRC/Github-Monitor)：监控Github代码仓库的系统。
- [GitHack](https://github.com/lijiejie/GitHack)：GitHack是一个.git泄露利用脚本，通过泄露的.git文件夹下的文件，重建还原工程源代码。
- [Hawkeye](https://github.com/0xbug/Hawkeye)：监控github代码库，及时发现员工托管公司代码到GitHub行为并预警，降低代码泄露风险。




##### 网站存活检测工具汇总
- [httpx](https://github.com/projectdiscovery/httpx)：httpx 是一个go语言开发的快速且多用途的 HTTP 工具包，允许使用 retryablehttp 库运行多个探测器。可以获取url的状态，title，jarm等信息，也可以对网站截图。
- [alivecheck](https://pan.baidu.com/s/1b9MxHb0VoPJ3CI2X3a04dQ?pwd=oc63)：小米范存活检测工具。
- [FCDN](https://github.com/ccc-f/FCDN)：通过域名批量查找没有使用 cdn、云waf、dmzweb的站点。




##### 信息收集工具汇总
- [ds_store_exp](https://github.com/lijiejie/ds_store_exp)：ds_store_exp是一个 .DS_Store 文件泄漏利用脚本，它解析.DS_Store文件并递归地下载文件到本地。
- [WebBatchRequest](https://github.com/ScriptKid-Beta/WebBatchRequest/)：WEB批量请求器（WebBatchRequest）是对目标地址批量进行快速的存活探测、Title获取，简单的banner识别，支持HTTP代理以及可自定义HTTP请求用于批量的漏洞验证等的一款基于JAVA编写的轻量工具。
- [virustotal](https://www.virustotal.com/graph/)：企业资产梳理，包括子域名等，需要登录。
- [archive](https://archive.org/)：网页缓存查询。
- [archive](http://www.cachedpages.com/)：网页缓存查询。
- [SiteScan](https://github.com/kracer127/SiteScan)：专注一站化解决渗透测试的信息收集任务，功能包括域名ip历史解析、nmap常见端口爆破、子域名信息收集、旁站信息收集、whois信息收集、网站架构分析、cms解析、备案信息收集、CDN信息解析、是否存在waf检测、后台寻找以及生成检测结果html报告表。
- [zpscan](https://github.com/niudaii/zpscan)：一个有点好用的信息收集工具。
- [dumpall](https://github.com/0xHJK/dumpall)：一款信息泄漏利用工具，适用于.git/.svn/.DS_Store泄漏和目录列出。




##### 公司邮箱收集
- [Hunter](https://hunter.io/)：公司邮箱收集。




##### 企业信息收集汇总
- [七麦数据](https://www.qimai.cn/)：企业app搜索网站。
- [小蓝本](https://sou.xiaolanben.com/pc)：企业网站资产查询，配合天眼查、企查查等。
- [天眼查](https://www.tianyancha.com/)：天眼查。
- [爱企查](https://aiqicha.baidu.com/?from=pz)：爱企查。
- [企查查](https://www.qcc.com/)：企查查。




##### APP信息收集汇总
- [mogua](https://mogua.co/)：app信息收集。
- [apk2url](https://github.com/n0mi1k/apk2url)：提取apk中的IP和URL。
- [AppInfoScanner](https://github.com/kelvinBen/AppInfoScanner)：一款适用于以HW行动/红队/渗透测试团队为场景的移动端(Android、iOS、WEB、H5、静态网站)信息收集扫描工具，可以帮助渗透测试工程师、攻击队成员、红队成员快速收集到移动端或者静态WEB站点中关键的资产信息并提供基本的信息输出,如：Title、Domain、CDN、指纹信息、状态信息等。
- [APKDeepLens](https://github.com/d78ui98/APKDeepLens)：APKDeepLens是一款基于 Python 的工具，用于扫描 Android 应用程序（APK 文件）中的安全漏洞。它专门针对 OWASP Top 10 安卓漏洞，为开发人员、渗透测试人员和安全研究人员提供了一种简单有效的方法来评估 Android 应用程序的安全状况。




##### 新平台信息收集汇总
- [语雀](https://www.yuque.com/)：语雀信息收集。
- [抖音](https://www.douyin.com/)：抖音信息收集。




##### 证书信息收集汇总
- [chinassl.net](https://csr.chinassl.net/ssl-checker.html)：证书信息收集。



##### 网盘信息收集汇总
- [凌风云网盘搜索](https://www.lingfengyun.com/)：凌风云网盘搜索。
- [超能搜网盘搜索](https://www.chaonengsou.com/)：超能搜网盘搜索。
- [超能搜网盘搜索](https://www.chaonengsou.com/)：超能搜网盘搜索。
- [小马盘网盘搜索](https://www.xiaomapan.com/)：小马盘网盘搜索。
- [飞猪网盘搜索](https://www.feizhupan.com/#/)：飞猪网盘搜索。


##### 流量设备检测规则相关汇总
- [suricata](https://redmine.openinfosecfoundation.org/projects/suricata)：suricata是开源入侵检测和防御引擎。
- [yara官方文档](https://yara.readthedocs.io/en/v3.7.0/index.html)：yara官方文档。
- [yara引擎](https://github.com/VirusTotal/yara/releases)：yara引擎。
- [yara案例](https://www.yuque.com/p1ut0/qtmgyx/eubd9v)：yara案例。
- [Lua](https://www.runoob.com/lua/lua-tutorial.html)：Lua学习教程。





##### HW相关溯源汇总
- [IP位置查询](https://ip.sy/)：IP定位查询。
- [域名备案查询](https://icp.chinaz.com/krev.com)：域名备案查询。
- [REG007](https://www.reg007.com/)：通过手机号和邮箱查询注册过哪些网站。
- [注册宝](http://www.regbao.com/)：通过手机号和邮箱查询注册过哪些网站。
- [Privacy](https://privacy.aiuys.com/)：免费社工库（需翻墙访问）。
- [ip138](https://site.ip138.com/ip138.ip/)：IP反查域名。
- [whois](http://whois.bugscaner.com/)：域名whois查询。
- [chaipip](https://www.chaipip.com/aiwen.html)：埃文科技IP定位查询。
- [wireshark](https://www.wireshark.org/)：数据包分析工具。
- [SGK_Sites_and_Bots](https://github.com/telegram-sgk/SGK_Sites_and_Bots)：免费在线社工库，免费Telegram社工库。





##### HW相关威胁情报汇总
- [360安全大脑](https://ti.360.net/)：360安全大脑。
- [CNTD网络安全威胁情报共享平台](http://www.cntd.org.cn/)：CNTD网络安全威胁情报共享平台。
- [深信服威胁情报中心](https://ti.sangfor.com.cn/analysis-platform)：深信服威胁情报中心。
- [山石网科威胁情报中心](https://ti.hillstonenet.com.cn/main)：山石网科威胁情报中心。
- [绿盟威胁情报云](https://ti.nsfocus.com/)：绿盟威胁情报云。
- [安恒安全星图平台](https://ti.dbappsecurity.com.cn/)：安恒安全星图平台。
- [奇安信威胁情报中心](https://ti.qianxin.com/)：奇安信威胁情报中心。
- [华为安全中心平台](https://isecurity.huawei.com/sec/web/urlClassification.do#)：华为安全中心平台。
- [微步在线X情报社区](https://x.threatbook.com/)：微步在线X情报社区。
- [IBM威胁情报平台](https://exchange.xforce.ibmcloud.com/)：IBM威胁情报平台。
- [启明星辰威胁情报中心](https://www.venuseye.com.cn/)：启明星辰威胁情报中心。
- [腾讯安全威胁情报中心](https://tix.qq.com/)：讯安全威胁情报中心。
- [安天威胁情报中心](https://www.antiycloud.com/#/antiy/index)：安天威胁情报中心。




##### HW相关沙箱汇总
- [360沙箱云](https://ata.360.net/)：360沙箱云平台。
- [virscan](https://www.virscan.org/)：VirScan是一个多引擎文件检测平台，也是国内最早做文件在线检测的平台之一。
- [腾讯哈勃分析系统](https://habo.qq.com/)：腾讯哈勃分析系统。
- [FREEBUF云沙箱](https://mac-cloud.riskivy.com/detect)：FREEBUF云沙箱。
- [卡巴斯基云沙箱](https://opentip.kaspersky.com/)：卡巴斯基云沙箱。
- [virustotal云沙箱](https://www.virustotal.com/gui/home/upload)：virustotal云沙箱。
- [计算机病毒防御技术国家工程实验室可疑文件分析云](https://cloud.vdnel.cn/)：计算机病毒防御技术国家工程实验室可疑文件分析云沙箱。
- [绿盟威胁分析中心沙箱](https://poma.nsfocus.com/)：绿盟威胁分析中心沙箱。
- [ANY.RUN](https://app.any.run/)：交互式恶意软件分析。
- [安恒云沙箱](https://sandbox.dbappsecurity.com.cn/)：安恒云沙箱。





##### HW相关应急响应工具汇总
- [D盾_防火墙](https://www.d99net.net/)：webshell查杀工具。
- [火绒剑](https://www.huorong.cn/)：火绒剑是一款安全工具，主要用于分析和处理恶意程序火绒剑提供了多种功能，包括但不限于程序行为监控、进程管理、启动项管理、内核程序管理、钩子扫描、服务管理、驱动扫描、网络监控、文件管理和注册表管理等。
- [360星图](https://pan.baidu.com/s/1n2mlbUK0PXfM6Msn_e70EA?pwd=yeop)：网站日志分析工具。
- [AppCompatCacheParser](https://www.sans.org/tools/appcompatcacheparser/)：获取windows系统可执行文件记录。
- [Log Parser](https://www.sans.org/tools/appcompatcacheparser/)：windows系统日志分析工具。
- [FullEventLogView](http://www.nirsoft.net/utils/full_event_log_view.html)：Event Log Explorer是一个检测系统安全的工具，可以查看、检索和分析日志事件、包括安全、系统、应用程序和其他windows系统记录事件。
- [Everything](https://www.voidtools.com/zh-cn/downloads/)：文本搜索工具。
- [FireKylin](https://github.com/MountCloud/FireKylin)：网络安全应急响应工具(系统痕迹采集)，面对多台主机需要排查时，只需要把agent端发给服务器运维管理人员运行采集器，将采集结果给到安全人员，来由安全人员进行分析。
- [河马webshell查杀工具](https://www.shellpub.com/)：河马webshell查杀工具（安装版）。
- [日志分析工具合集](https://www.cnblogs.com/xiaozi/p/13198071.html)：应急响应日志分析工具 。
- [BlueTeamTools](https://github.com/abc123info/BlueTeamTools)：蓝队分析工具箱by:ABC_123 "蓝队分析研判工具箱"就是把我平时写的蓝队小工具集合起来形成的，重点解决蓝队分析工作中的一些痛点问题 。
- [processhacker](https://processhacker.sourceforge.io/downloads.php)：一款强大的系统监控与管理工具。
- [Whoamifuck](https://github.com/enomothem/Whoamifuck)：Linux应急响应工具（shell脚本）-V6.0。
- [OpenArk](https://github.com/BlackINT3/OpenArk/)：应急响应/逆向工具箱。
- [DuckMemoryScan](https://github.com/huoji120/DuckMemoryScan)：检测绝大部分所谓的内存免杀马。
- [Rattler](https://github.com/sensepost/rattler)：全自动检测工具Rattler来发现DLL劫持。






##### HW相关应急响应工具之内存马汇总
- [yara_scan](https://github.com/huan-cdm/yara_scan)：利用yara引擎自定义检测规则，支持静态文件和内存木马的扫描。
- [java-memshell-scanner](https://github.com/c0ny1/java-memshell-scanner)：通过jsp脚本扫描java web Filter/Servlet型内存马。
- [arthas](https://github.com/alibaba/arthas/)：Arthas 是Alibaba开源的Java诊断工具，不是专门用户内存马的检测，但是由于java内存马相当于利用了jvm的底层特性，所以可以给我们对内存马的排查带来很多便利，常用命令（classloader、sc *.Filter、sc *.Servlet、jad、heapdump）。
- [FindShell](https://github.com/geekmc/FindShell)：内存马查杀工具，尤其针对Agent型，原理是dump出JVM当前的class并进行字节码分析，并加入自动修复的功能。
- [copagent](https://github.com/LandGrey/copagent)：自动化分析内存马jar包。
- [内存马检测文章](https://mp.weixin.qq.com/s/G0IWtQvwMo4l4qYuKaZhCw)：冰蝎、哥斯拉 内存马应急排查。
- [内存马检测文章](https://mp.weixin.qq.com/s/Hr8AEK1HVgc_6T6i1pUhWQ)：内存马检测排查手段。
- [nginx_shell](https://github.com/veo/nginx_shell)：nginx WebShell/内存马，更优雅的nignx backdoor。




##### APP安全测试工具汇总
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
- [jd-gui](https://java-decompiler.github.io/)：Java反编译工具。
- [PKID](https://pan.baidu.com/s/1OVm7BPEitIMZLPzSQXSRcg?pwd=7vk8)：apk查壳工具。
- [Xposed模块仓库](https://modules.lsposed.org/)：Xposed模块仓库。




##### 小程序安全测试工具汇总
- [PC微信小程序一键解密](https://github.com/huan-cdm/Wechat-small-program-decompile)：PC微信小程序一键解密，PC微信小程序需先利用UnpackMiniApp.exe解密在进行反编译。
- [WxAppUnpacker](https://github.com/huan-cdm/Wechat-small-program-decompile)：微信小程序反编译工具。
- [微信开发者工具](https://developers.weixin.qq.com/miniprogram/dev/devtools/stable.html)：微信开发者工具调试微信小程序。
- [Proxifier](https://pan.baidu.com/s/1UHF_KsOqJpsY2P8-uHauoA?pwd=8hk9)：微信小程序抓包用到的代理客户端。
- [‌Reqable](https://github.com/reqable/reqable-app)：‌Reqable是一款多功能的API开发和网络流量分析工具‌，支持HTTP/HTTPS/WebSocket等协议抓包、调试和测试，提供桌面端与移动端协同功能，适用于开发者和测试人员（github下载地址）。
- [‌Reqable](https://reqable.com/zh-CN/)：‌Reqable是一款多功能的API开发和网络流量分析工具‌，支持HTTP/HTTPS/WebSocket等协议抓包、调试和测试，提供桌面端与移动端协同功能，适用于开发者和测试人员（官网下载地址）。
- [最新版微信小程序抓包](https://mp.weixin.qq.com/s/Dq7LAop1KRFh7jEAHbpcoA)：最新版微信小程序抓包。
- [小程序信息收集](https://mp.weixin.qq.com/s/YsIQYCU0oe1VyP-Q7Iiq5A)：小程序信息收集。
- [微信历史版本](https://github.com/tom-snow/wechat-windows-versions)：微信历史版本。
- [WeChatOpenDevTool](https://github.com/JaveleyQAQ/WeChatOpenDevTools-Python)：微信小程序强制开启开发者工具。
- [自动小程序反编译并匹配敏感信息](https://github.com/fasnow/fine)：自动小程序反编译并匹配敏感信息。




##### 火狐浏览器插件汇总（扩展和主题->插件->输入对应名字进行搜索->添加插件）
- [Wappalyzer](https://addons.mozilla.org/zh-CN/firefox/search/?q=Wappalyzer)：网站指纹识别。
- [FindSomething](https://addons.mozilla.org/zh-CN/firefox/search/?q=FindSomething)：用于快速在网页的html源码或js代码中提取一些有趣的信息，包括可能请求的资源、接口的url，可能请求的ip和域名，泄漏的证件号、手机号、邮箱等信息。
- [FoxyProxy Standard](https://addons.mozilla.org/zh-CN/firefox/search/?q=FoxyProxy%20Standard)：FoxyProxy是一个高级的代理管理工具。
- [HackTools](https://addons.mozilla.org/zh-CN/firefox/search/?q=Hack-Tools)：Hacktools，是一个方便您的web应用程序渗透测试的web扩展，它包括小抄以及测试期间使用的所有工具，如XSS有效载荷，反向shell来测试您的web应用程序。
- [superSearchPlus](https://addons.mozilla.org/zh-CN/firefox/search/?q=SuperSearchPlus)：superSearchPlus是聚合型信息收集插件，支持综合查询，资产测绘查询，信息收集 整合了目前常见的资产测绘平台 同时支持数据导出。
- [Shodan](https://addons.mozilla.org/zh-CN/firefox/search/?q=shodan)：通过插件查看IP Address、Hostname、Open Ports、Tags。
- [Ctool](https://addons.mozilla.org/zh-CN/firefox/addon/ctool/)：程序日常开发常用小工具集合,提供哈希/加解密/编码转换/时间戳/二维码/拼音/IP查询/代码优化/Unicode/正则等多种工具。




##### 暴力破解字典汇总
- [fuzzDicts](https://github.com/TheKingOfDuck/fuzzDicts)：安全测试常用字典。
- [PentesterSpecialDict](https://github.com/a3vilc0de/PentesterSpecialDict)：安全测试常用字典。
- [字典](https://github.com/coffinxp/payloads)：安全测试常用字典。
- [Fuzzing-Dicts](https://github.com/3had0w/Fuzzing-Dicts)：安全测试常用字典。
- [Fuzz_dic](https://github.com/7hang/Fuzz_dic)：参数 | 字典 collections。




##### 社工密码字典
- [weakpass](https://zzzteph.github.io/weakpass/)：在线密码字典生成网站。
- [密码字典生成器](https://www.shentoushi.top/tools/dict/index.php)：在线密码字典生成网站。
- [UserNameDictTools](https://github.com/abc123info/UserNameDictTools)：用户名字典生成工具V0.2发布，(将中文汉字姓名转成11种格式的拼音)。
- [SocialEngineeringDictionaryGenerator](https://github.com/zgjx6/SocialEngineeringDictionaryGenerator)：社会工程学密码生成器，是一个利用个人信息生成密码的工具。
- [cupp](https://github.com/Mebus/cupp)：根据用户习惯生成弱口令探测字典脚本。
- [默认密码](https://www.routerpasswords.com/)：默认密码。
- [haveibeenpwned](https://haveibeenpwned.com/)：查询账户是否泄露。
- [HoneypotDic](https://github.com/ExpLangcn/HoneypotDic)：蜜罐抓到的Top密码，根据使用频率排序，持续更新中...。



##### API接口测试汇总
- [API测试文章](https://mp.weixin.qq.com/s/Dhbm9Q6VMCRZADIUGzz4Jg)：API测试文章。
- [Apifox](https://apifox.com/)：Apifox是一个集接口文档、接口调试、自动化测试、Mock服务于一体的全新一代API管理工具。它通过图形界面提供了一种简单直观的方式来创建、管理和测试API接口，无论是前端开发者、后端开发者还是测试人员都能快速上手。Apifox不仅支持RESTful API，也支持GraphQL、Dubbo等多种接口类型，满足不同项目的需求。
- [Postman](https://www.postman.com/downloads/)：API调试工具。
- [swagger-exp](https://github.com/lijiejie/swagger-exp)： Swagger REST API 信息泄露利用工具。
- [api-scanner](https://pentest-tools.com/website-vulnerability-scanning/api-scanner)：
- [SoapUI](https://www.soapui.org/downloads/soapui/)：SoapUI可以对webservice、REST和 http 接口进行相关的测试。
- [swagger-hack](https://github.com/jayus0821/swagger-hack)：自动化爬取并自动测试所有swagger接口。
- [ReadyAPI接口测试工具](https://www.filehorse.com/download-readyapi/)：ReadyAPI接口测试工具。




##### webshell管理工具汇总
- [Behinder](https://github.com/rebeyond/Behinder)：冰蝎动态二进制加密网站管理客户端。
- [Godzilla](https://github.com/BeichenDream/Godzilla)：哥斯拉websheell管理客户端。
- [antSword](https://github.com/AntSwordProject/antSword)：中国蚁剑是一款跨平台的开源网站管理工具。
- [caidao](https://github.com/raddyfiy/caidao-official-version)：中国菜刀官方版本。




##### 数据库相关
- [AnotherRedisDesktopManager](https://github.com/qishibo/AnotherRedisDesktopManager)：redis客户端管理工具。
- [PentestDB](https://github.com/safe6Sec/PentestDB)：各种数据库的利用姿势。




##### 靶场汇总
- [Vulhub](https://vulhub.org/)：Vulhub是一个基于docker和docker-compose的漏洞环境集合，进入对应目录并执行一条语句即可启动一个全新的漏洞环境，让漏洞复现变得更加简单，让安全研究者更加专注于漏洞原理本身。
- [pikachu](https://github.com/zhuifengshaonianhanlu/pikachu)：Pikachu是一个带有漏洞的Web应用系统，在这里包含了常见的web安全漏洞。 如果你是一个Web渗透测试学习人员且正发愁没有合适的靶场进行练习，那么Pikachu可能正合你意。
- [dwva](https://github.com/digininja/DVWA)：DVWA(Damn Vulnerable Web Application)一个用来进行安全脆弱性鉴定的PHP/MySQL Web 应用，旨在为安全专业人员测试自己的专业技能和工具提供合法的环境，帮助web开发者更好的理解web应用安全防范的过程。
- [upload-labs](https://github.com/c0ny1/upload-labs)：upload-labs是一个使用php语言编写的，专门收集渗透测试和CTF中遇到的各种上传漏洞的靶场。
- [sqli-labs](https://github.com/Audi-1/sqli-labs)：sql注入练习靶场。
- [acunetix](http://vulnweb.com/)：acunetix在线靶场。
- [portswigger](https://portswigger.net/web-security)：BurpSuite官方靶场。
- [雷池WAF测试](https://demo.waf-ce.chaitin.cn/)：雷池WAF测试。
- [encrypt-labs](https://github.com/SwagXz/encrypt-labs)：前端加密对抗练习靶场，包含非对称加密、对称加密、加签以及禁止重放的测试场景，比如AES、DES、RSA，用于渗透测试练习。
- [vulfocus](https://vulfocus.cn/#/login?redirect=%2Fdashboard)：vulfocus靶场。




##### CTF相关汇总
- [CTFHub](https://www.ctfhub.com/#/index)：CTF靶场。
- [BUUCTF](https://buuoj.cn/)：CTF靶场。
- [Hello-Java-Sec](https://github.com/j3ers3/Hello-Java-Sec)：Java Security，安全编码和代码审计。
- [网络信息安全攻防学习平台](https://hackinglab.cn/)：网络信息安全攻防学习平台。
- [实验吧](https://www.shiyanbar.com/upgrade.html)：实验吧。
- [i春秋](https://www.ichunqiu.com/)：i春秋。
- [蚁景网安实验室](https://www.yijinglab.com/)：蚁景网安实验室。
- [CTFTIME](https://ctftime.org/)：CTFTIME。
- [BugKu-CTF平台](https://ctf.bugku.com/login)：BugKu-CTF平台。
- [RedTiger's Hackit](http://redtiger.labs.overthewire.org/)：RedTiger's Hackit。
- [XSS-Game](http://prompt.ml/0)：RedTiger's Hackit。
- [ctfs](https://github.com/ctfs)：ctf writeup。
- [ctf-writeups](https://github.com/vulnHub/ctf-writeups)：ctf-writeups。
- [[随波逐流]CTF编码工具](http://1o1o.xyz/bo_ctfcode.html)：[随波逐流]CTF编码工具。
- [CTF-OS](https://github.com/ProbiusOfficial/CTF-OS)：【Hello CTF】专为CTF比赛封装的虚拟机，基于工具集封装多个版本和系统，更多选择，开箱即用。比赛愉快！
- [Hello-CTF](https://github.com/ProbiusOfficial/Hello-CTF)：【Hello CTF】题目配套，免费开源的CTF入门教程，针对0基础新手编写，同时兼顾信息差的填补，对各阶段的CTFer都友好的开源教程，致力于CTF和网络安全的开源生态！
- [ctftools-all-in-one](https://github.com/RemusDBD/ctftools-all-in-one)：CTF综合工具。




##### 网络空间搜索汇总
- [QUAKE](https://quake.360.net/quake/#/index)：网络空间搜索平台。
- [FOFA](https://fofa.info/)：网络空间搜索平台。
- [HUNTER](https://hunter.qianxin.com/)：网络空间搜索平台。
- [binaryedge](https://app.binaryedge.io/login)：网络空间搜索平台。
- [shodan](https://www.shodan.io/)：网络空间搜索平台。




##### 在线dnslog平台汇总
- [DNSlog](http://www.dnslog.cn/)：在线DNSLog平台。
- [CEYE](http://ceye.io/)：在线DNSLog平台。




##### 博客汇总
- [CT Stack安全社区](https://stack.chaitin.com/)：长亭安全社区。
- [乌云漏洞库](https://wy.zone.ci/bugs.php)：乌云漏洞库。
- [先知社区](https://xz.aliyun.com/)：先知社区。
- [Track 安全社区](https://bbs.zkaq.cn/)：Track 安全社区。
- [freebuf](https://www.freebuf.com/)：freebuf。
- [离别歌](https://www.leavesongs.com/)：离别歌。
- [Web安全学习笔记](https://www.bookstack.cn/read/LyleMi-Learn-Web-Hacking/81ab7f9e9d252390.md)：Web安全学习笔记。
- [内网相关](https://www.chabug.org/web/1263)：博客和文库整理。
- [应急响应](https://github.com/Bypass007/Emergency-Response-Notes)：博客和文库整理。
- [公众号文章](http://www.nmd5.com/test/index.php#)：博客和文库整理。
- [渗透师导航](https://www.shentoushi.top/)：渗透师导航。
- [SummaryOf2022](https://github.com/abc123info/SummaryOf2022)：2022年ABC123公众号年刊 2023年ABC123公众号年刊。
- [SDL序列课程](https://mp.weixin.qq.com/s/-PkwA5Hd4m82jKsgo-d86w)：SDL第一阶段的总结，还是简单一点的总结吧，主要围绕了从理论到实战，从不同的角度来看待SDL的建设存在的问题点、风险点、解决点，一共发表了13篇文章，大家可以具体看对应的内容。
- [HackReport](https://github.com/awake1t/HackReport)：渗透测试报告/资料文档/渗透经验文档/安全书籍。
- [奇安信知识库](https://kb.qianxin.com/)：奇安信知识库。




##### 漏洞文库汇总
- [PeiQi文库](https://peiqi.wgpsec.org/)：漏洞文库。
- [POC](https://github.com/wy876/POC)：漏洞文库。
- [web-sec](https://github.com/ReAbout/web-sec)：WEB安全手册(红队安全技能栈)，漏洞理解，漏洞利用，代码审计和渗透测试总结。【持续更新】。




##### 大模型相关汇总
- [ChatGPT](https://chat.openai.com/chat)：ChatGPT。
- [纳米AI搜索](https://www.n.cn/)：纳米AI搜索。
- [deepseek](https://www.deepseek.com/)：deepseek。
- [360智脑](https://chat.360.com/)：360智脑。
- [文心一言](https://yiyan.baidu.com/)：文心一言。
- [豆包](https://www.doubao.com/chat/)：豆包。
- [kimi](https://kimi.moonshot.cn/)：Kimi。
- [智谱清言](https://chatglm.cn/)：智谱清言。
- [天工AI](https://beta.tiangong.cn/)：天工AI。
- [讯飞星火大模型](https://xinghuo.xfyun.cn/)：讯飞星火大模型。
- [通义千问](https://tongyi.aliyun.com/qianwen/)：通义千问。
- [腾讯混元大模型](https://hunyuan.tencent.com/)：腾讯混元大模型。



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
- [golang环境](https://golang.google.cn/dl/)：golang环境。
- [Notepad++](https://notepad-plus.en.softonic.com/)：文本编辑器。
- [keepass](https://keepass.info/download.html)：密码管理工具。
- [FinalShell](http://www.hostbuf.com/t/988.html)：SSH工具。
- [NirSoft](https://www.nirsoft.net/)：NirSoft 网站提供了一系列独特的小型实用软件。



##### JWT相关汇总
- [JWT在线加解密](https://jwt.io/)：JWT在线加解密。
- [JWT在线加解密](https://www.bejson.com/jwt/)：JWT在线加解密（推荐）。
- [JWT攻击手册](https://www.cnblogs.com/xiaozi/p/12005929.html)：JWT攻击手册。
- [JWT破解工具](https://github.com/ticarpi/jwt_tool)：JWT破解工具。
- [JWT认证共计详情总结](https://www.cnblogs.com/backlion/p/16699442.html)：JWT认证共计详情总结。
- [JWT靶场地址](https://demo.sjoerdlangkemper.nl/jwtdemo/hs256.php)：JWT靶场地址。



##### 在线加解密网站汇总
- [BCryptDecode](https://github.com/wolaile08/BCryptDecode)：BCrypt解密爆破工具。
- [cmd5](https://cmd5.com/)：md5加解密网站。
- [somd5](https://www.somd5.com/)：md5加解密网站。
- [unicode](https://tool.chinaz.com/tools/unicode.aspx)：unicode编码转换网站。
- [base64](https://tool.chinaz.com/Tools/Base64.aspx)：base64编码转换网站。
- [aes](http://tool.chacuo.net/cryptaes)：aes加解密网站。
- [字符串<->十六进制](https://www.sojson.com/hexadecimal.html)：十六进制字符串转换网站。
- [CTF在线工具](http://www.hiencode.com/)：CTF在线工具。
- [sm234_decrypt_gui](https://github.com/milu001/sm234_decrypt_gui)：国密SM系列加解密图形化GUI工具，支持sm2加密，sm2解密，sm3加密，sm4加密，sm4解密，sm4支持多种填充方式，输入输出支持hex与base64。不依赖网络，适合内网使用。



##### 服务器汇总
- [xampp](https://www.apachefriends.org/zh_cn/index.html)：XAMPP（Apache+MySQL+PHP+PERL）是一个功能强大的建站集成软件包。
- [phpstudy](https://www.xp.cn/)：phpStudy是一个PHP调试环境的程序集成包。该程序包集成最新的Apache+PHP+MySQL+phpMyAdmin+ZendOptimizer，一次性安装，无须配置即可使用，是非常方便、好用的PHP调试环境。
- [Apache Tomcat](https://tomcat.apache.org/)：运行java代码的web服务器。
- [nacos](https://github.com/alibaba/nacos/)：Nacos 是一个易于使用的动态服务发现、配置和服务管理平台，它是阿里巴巴开源的。Nacos 支持服务的注册与发现、配置管理、服务的元数据和流量管理等功能。它被设计为云原生，可以与 Kubernetes、Spring Cloud 等技术栈很好地集成。



##### 数据安全相关汇总
- [APP违规收集用户信息复现](https://mp.weixin.qq.com/mp/appmsgalbum?__biz=MzU2MDQ0NzkyMw==&action=getalbum&album_id=2372108076222283777&scene=173&from_msgid=2247483938&from_itemidx=1&count=3&nolastread=1#wechat_redirect)：APP违规收集用户信息复现。





##### 开发常用汇总
- [pdf.js](https://mozilla.github.io/pdf.js/getting_started/#download)：pdf.js组件。
- [iconfont](https://www.iconfont.cn/?_refluxos=a10)：阿里巴巴矢量图标库。
- [51tool](https://www.51tool.com/)：在线生成ICO图标。



##### 渗透测试辅助工具汇总
- [SwitchHosts](https://github.com/oldj/SwitchHosts)：SwitchHosts 是一个管理 hosts 文件的应用，基于 Electron 、React、Jotai 、Chakra UI、CodeMirror 等技术开发。

-**持续更新中**