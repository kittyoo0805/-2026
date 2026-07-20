# 📋 网络安全实验报告

## Flask 用户管理系统 — SQL注入漏洞分析与修复

---

| 实验信息 | 内容 |
|---------|------|
| **实验名称** | Web 应用 SQL 注入漏洞分析与修复实践 |
| **实验平台** | Flask + SQLite 用户信息管理系统 |
| **项目路径** | `/opt/Class01/` |
| **GitHub 仓库** | https://github.com/kittyoo0805/-2026 |
| **报告日期** | 2026-07-20 |

---

## 目录

1. [实验背景](#1-实验背景)
2. [漏洞发现过程](#2-漏洞发现过程)
3. [漏洞原理分析](#3-漏洞原理分析)
4. [POC 验证过程](#4-poc-验证过程)
5. [修复方案与原理](#5-修复方案与原理)
6. [修复后验证](#6-修复后验证)
7. [其他漏洞修复](#7-其他漏洞修复)
8. [实验总结](#8-实验总结)

---

## 1. 实验背景

### 1.1 系统概况

本实验对象是一个基于 Flask 框架开发的用户信息管理平台，包含以下功能：

- **登录**：用户输入用户名和密码进行身份验证
- **注册**：新用户填写信息注册账号
- **搜索**：已登录用户按关键词搜索其他用户
- **用户信息展示**：登录后展示个人资料

### 1.2 初始技术架构

```
前端：HTML + CSS（Jinja2 模板）
后端：Python Flask 框架
数据库：SQLite（存储注册用户数据）
认证：Session + Cookie 机制（admin/alice 存储在内存字典）
```

### 1.3 初始安全状态

应用最初存在 7 个安全漏洞，其中 **SQL 注入** 为最严重漏洞（严重程度：🔴 严重）。

---

## 2. 漏洞发现过程

### 2.1 代码审查阶段

通过对 `app.py` 的源代码审查，发现以下不安全代码模式：

#### 发现点 1：搜索功能的 SQL 拼接（app.py 第 154 行）

```python
# 首次构建搜索功能时使用的代码（有漏洞版本）
sql = f"SELECT id, username, email, phone FROM users WHERE username LIKE '%{keyword}%' OR email LIKE '%{keyword}%'"
```

**发现过程**：
1. 阅读搜索路由 `/search` 的代码
2. 注意到 `keyword` 参数直接来自 URL 查询字符串 `request.args.get("keyword", "")`
3. 该参数未经任何处理，直接通过 f-string 嵌入到 SQL 语句中
4. 判断存在 SQL 注入漏洞

#### 发现点 2：注册功能的 SQL 拼接（app.py 第 120 行）

```python
# 首次构建注册功能时使用的代码（有漏洞版本）
sql = f"INSERT INTO users (username, password, email, phone) VALUES ('{username}', '{password}', '{email}', '{phone}')"
```

**发现过程**：
1. 阅读注册路由 `/register` 的代码
2. 注意到 `username`、`password`、`email`、`phone` 全部来自 POST 表单
3. 四个参数直接通过 f-string 嵌入 SQL
4. 判断存在 SQL 注入漏洞

### 2.2 攻击面分析

| 攻击入口 | 参数来源 | 注入方式 |
|---------|---------|---------|
| `/search?keyword=` | URL 参数（GET） | UNION 注入、OR 注入 |
| `/register` POST | 表单字段 | 闭合 SQL 插入恶意数据 |

### 2.3 漏洞严重性评估

| 漏洞 | 危害 | 严重程度 |
|------|------|:--------:|
| SQL 注入（搜索） | 窃取全部用户数据、获取数据库控制权 | 🔴 严重 |
| SQL 注入（注册） | 插入恶意数据、破坏数据库完整性 | 🔴 严重 |

---

## 3. 漏洞原理分析

### 3.1 SQL 注入核心原理

SQL 注入的本质是：**用户输入被当作 SQL 代码执行，而非普通数据**。

```
正常流程：
用户输入 "admin" → SQL: WHERE name LIKE '%admin%' → 查找包含 admin 的用户

注入流程：
用户输入 "' OR '1'='1" → SQL: WHERE name LIKE '%' OR '1'='1%'
                                                    ^^^^^^^^^^^
                                                    用户输入改变了 SQL 结构
```

### 3.2 漏洞 1：搜索功能字符串拼接

#### 问题代码

```python
@app.route("/search", methods=["GET"])
def search():
    keyword = request.args.get("keyword", "").strip()   # 用户输入
    sql = f"SELECT id, username, email, phone FROM users WHERE username LIKE '%{keyword}%' OR email LIKE '%{keyword}%'"
    #     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    #     f-string 直接拼接，keyword 中的特殊字符会破坏 SQL 结构
    c.execute(sql)
```

#### 漏洞分析

`f"..."` 是 Python 的 f-string 格式化语法。当 `keyword` 变量包含 SQL 特殊字符时，这些字符会成为 SQL 语句的一部分。

例如输入 `keyword = admin`，生成的 SQL 是安全的：
```sql
SELECT * FROM users WHERE username LIKE '%admin%' OR email LIKE '%admin%'
```

但如果输入 `keyword = ' OR '1'='1`，生成的 SQL 变为：
```sql
SELECT * FROM users WHERE username LIKE '%' OR '1'='1%' OR email LIKE '%' OR '1'='1%'
```

这里的 `'`（单引号）闭合了字符串，`OR '1'='1` 成为了永真条件，导致返回全部数据。

### 3.3 漏洞 2：注册功能字符串拼接

#### 问题代码

```python
@app.route("/register", methods=["POST"])
def register():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    email = request.form.get("email", "")
    phone = request.form.get("phone", "")
    
    sql = f"INSERT INTO users (username, password, email, phone) VALUES ('{username}', '{password}', '{email}', '{phone}')"
    c.execute(sql)
```

#### 漏洞分析

四个表单字段全部通过 f-string 拼接。攻击者可以在任意字段中注入 SQL。

例如 `username = hacker', 'hacker_pass', 'h@x.com', '666')--`，

生成的 SQL 变为：
```sql
INSERT INTO users (username, password, email, phone) VALUES ('hacker', 'hacker_pass', 'h@x.com', '666')--', 'irrelevant', '', '')
```

- `hacker', 'hacker_pass', 'h@x.com', '666')--` 这部分闭合了 VALUES 并插入恶意数据
- `--` 是 SQL 注释符，后面的 `', '...` 被注释掉

### 3.4 漏洞 3：无输入过滤

应用没有对用户输入做任何：
- **转义**：没有转义单引号、双引号等特殊字符
- **过滤**：没有过滤 SQL 关键字（UNION、OR、AND、SELECT 等）
- **类型校验**：没有校验输入是否为期望的数据类型

### 3.5 漏洞 4：搜索结果回显

```
攻击者构造恶意 UNION SELECT 查询
    ↓
UNION 的结果集和原始查询结果合并
    ↓
合并后的结果呈现在 HTML 表格中
    ↓
攻击者通过浏览器直接看到窃取的数据
```

这种"有回显"的注入是最容易利用的 SQL 注入类型，攻击者不需要盲注或时间注入等复杂技术。

---

## 4. POC 验证过程

### 4.1 POC 1：UNION 注入获取任意数据

#### 攻击目标

向搜索结果中注入自定义数据，证明攻击者可以读取任意数据。

#### 攻击步骤

```bash
# 步骤 1：登录获取 session cookie
curl http://127.0.0.1:5000/login \
  -d "username=admin&password=admin123" \
  -c /tmp/cookies.txt

# 步骤 2：执行 UNION 注入
curl "http://127.0.0.1:5000/search?keyword=%27%20UNION%20SELECT%201,%27inj%27,%27inj%40x.com%27,%27138%27--" \
  -b /tmp/cookies.txt | grep "inj"
```

#### URL 解码分析

```
%27 → '          (单引号，闭合 LIKE 字符串)
%20 → (空格)
UNION SELECT     (合并查询结果)
1,'inj','inj@x.com','138'  (注入的自定义数据)
--               (注释掉原始 SQL 的剩余部分)
```

#### SQL 执行过程

```
原始 SQL（关键词被注入后）：
SELECT * FROM users
WHERE username LIKE '%' UNION SELECT 1,'inj','inj@x.com','138'--%'
      ^                ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
      LIKE 被闭合      UNION 合并了一个自定义查询
                       后面的 '--' 注释掉了 '%' OR email LIKE ...'
```

#### 实际输出结果

```
ID  用户名   邮箱            手机
──────────────────────────────────
1   admin    admin@example.com   13800138000
1   inj      inj@x.com           138          ← 攻击者注入的数据！
2   alice    alice@example.com   13900139001
3   bob      bob@test.com        13000000001
```

#### 为什么列数必须是 4？

```sql
-- users 表结构（4 列）:
-- id INTEGER, username TEXT, email TEXT, phone TEXT

-- 注入的查询也必须是 4 列，否则 UNION 报错：
UNION SELECT 1,'inj','inj@x.com','138'
--          ^  ^        ^         ^
--          列1 列2     列3       列4
```

如果列数不匹配，SQLite 会报错：
```
SELECTs to the left and right of UNION
do not have the same number of result columns
```

### 4.2 POC 2：OR 注入搜索全部用户

#### 攻击目标

绕过 WHERE 条件限制，返回数据库中所有用户记录。

#### 攻击步骤

```bash
curl "http://127.0.0.1:5000/search?keyword=%27%20OR%20%271%27%3D%271" \
  -b /tmp/cookies.txt
```

#### SQL 执行过程

```
原始 SQL：
SELECT * FROM users
WHERE username LIKE '%' OR '1'='1%' OR email LIKE '%' OR '1'='1%'
                       ^^^^^^^^^^^
                       '1'='1' 永远为真（永真条件）
                       整个 WHERE 条件变成永真
                       返回 users 表全部数据
```

#### 实际输出结果

```
ID  用户名   邮箱            手机
──────────────────────────────────
1   admin    admin@example.com   13800138000
2   alice    alice@example.com   13900139001
3   bob      bob@test.com        13000000001
```

### 4.3 POC 3：注册功能 SQL 注入

#### 攻击目标

在注册过程中执行恶意 SQL，破坏数据库或窃取数据。

#### 攻击步骤

```bash
curl http://127.0.0.1:5000/register \
  -d "username=hacker', 'hacker_pass', 'h@x.com', '666')--" \
  -d "password=irrelevant"
```

#### SQL 执行过程

```
原始 INSERT 语句（f-string 展开后）：
INSERT INTO users (username, password, email, phone)
VALUES ('hacker', 'hacker_pass', 'h@x.com', '666')--', 'irrelevant', '', '')

分析：
1.'hacker', 'hacker_pass', 'h@x.com', '666'  → 完整的 VALUES 数据
2.)--  →  ) 闭合 VALUES, -- 注释掉剩余部分
3. 实际插入：username='hacker', password='hacker_pass', email='h@x.com', phone='666'
```

#### 实际输出结果

```
注册成功

验证数据库：
ID  username    email       phone
────────────────────────────────
1   admin       admin@...   13800138000
2   alice       alice@...   13900139001
3   bob         bob@...     13000000001
4   hacker      h@x.com     666           ← 注入创建的恶意用户
```

### 4.4 Burp Suite 列数探测

#### 探测过程

```
步骤 1：拦截 GET /search?keyword=admin 请求
步骤 2：发送到 Repeater
步骤 3：修改 keyword 参数测试列数
```

| 输入 | 生成的 SQL | 结果 |
|------|-----------|:----:|
| `admin' OR '1'='1` | `WHERE ... LIKE '%admin' OR '1'='1%'` | 返回所有用户 ✅ |
| `' UNION SELECT 1,2,3--` | `WHERE ... LIKE '%' UNION SELECT 1,2,3--%'` | 报错（列数不匹配） |
| `' UNION SELECT 1,2,3,4--` | `WHERE ... LIKE '%' UNION SELECT 1,2,3,4--%'` | 返回数字替代数据 ✅ |
| `' UNION SELECT 1,username,password,email FROM users--` | 同上 | 返回密码等敏感数据 ✅ |

---

## 5. 修复方案与原理

### 5.1 核心修复：参数化查询

#### 修复前（有漏洞）

```python
# ❌ f-string 字符串拼接
# 用户输入和 SQL 结构混在一起
keyword = "' OR '1'='1"
sql = f"SELECT * FROM users WHERE username LIKE '%{keyword}%'"
c.execute(sql)
# 实际执行：SELECT * FROM users WHERE username LIKE '%' OR '1'='1%'
```

#### 修复后（安全）

```python
# ✅ 参数化查询（Prepared Statement）
# 用户输入和 SQL 结构分离
keyword = "' OR '1'='1"
sql = "SELECT * FROM users WHERE username LIKE ?"
c.execute(sql, (f"%{keyword}%",))
# 实际执行：SELECT * FROM users WHERE username LIKE '%' OR ''1'='1%'
#                                       ↑ 特殊字符被转义为普通文本
#                                       LIKE 匹配的是字符串本身
#                                       不会命中任何用户 → "无搜索结果"
```

#### 修复后完整代码对照

```python
# ===== 搜索功能 =====
# 修复前
sql = f"SELECT id, username, email, phone FROM users WHERE username LIKE '%{keyword}%' OR email LIKE '%{keyword}%'"
c.execute(sql)

# 修复后
sql = "SELECT id, username, email, phone FROM users WHERE username LIKE ? OR email LIKE ?"
c.execute(sql, (f"%{keyword}%", f"%{keyword}%"))

# ===== 注册功能 =====
# 修复前
sql = f"INSERT INTO users (username, password, email, phone) VALUES ('{username}', '{password}', '{email}', '{phone}')"
c.execute(sql)

# 修复后
sql = "INSERT INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)"
c.execute(sql, (username, password, email, phone))
```

### 5.2 参数化查询原理

```
参数化查询的工作方式：

语句结构：  SELECT * FROM users WHERE username LIKE ?
占位符：    ? 是参数占位符，定义查询结构
参数：      ('%keyword%') 是传入的用户数据

数据库引擎处理流程：
1. 解析 SQL 模板（仅解析一次，编译为执行计划）
2. 将参数绑定到占位符
3. 执行时自动对参数中的特殊字符进行转义
   ' → ''（SQLite 中两个单引号表示一个单引号）
   \ → \\
   -- → 不会被视为注释
```

### 5.3 参数化查询 vs 字符串拼接

| 对比项 | 字符串拼接 (f-string) | 参数化查询 (?) |
|--------|---------------------|---------------|
| SQL 结构 | 和用户数据混在一起 | 和用户数据分离 |
| 用户输入 `' OR '1'='1` | `LIKE '%' OR '1'='1%'` → **注入成功** | `LIKE '%' OR ''1''=''1%'` → **被转义为普通文本** |
| 用户输入 `'--` | `LIKE '%'--%'` → **注释符生效** | `LIKE '%''--%'` → **被转义为普通文本** |
| 性能 | 每次都要重新解析 SQL | 可预编译复用 |
| 安全性 | ❌ 极不安全 | ✅ 安全 |

### 5.4 为什么参数化查询能防御 SQL 注入？

**核心原因**：参数化查询在**数据库引擎层面**就区分了"SQL 代码"和"数据"。

```
字符串拼接的工作方式：
"SELECT * FROM users WHERE name = '" + input + "'"
                                                         ← 输入直接嵌入 SQL 字符串
                                                         数据库无法区分哪部分是代码、哪部分是数据
                                                         导致用户输入中的 ' 可以闭合 SQL 语句

参数化查询的工作方式：
1. 数据库收到：SELECT * FROM users WHERE name = ?
2. 数据库编译这个模板，知道 ? 是一个参数（数据）
3. 数据库收到：('hello')
4. 数据库把 'hello' 当作纯数据填入，不会将其中的任何字符解释为 SQL
5. 即使输入是 "' OR '1'='1"，数据库也把它当作：
   "搜索一个用户名叫' OR '1'='1 的人" 而不是 "执行 OR 条件"
```

### 5.5 其他 SQL 注入防御措施（本实验未采用，供参考）

| 防御措施 | 说明 | 为什么不采用 |
|---------|------|------------|
| **参数化查询** ✅ | 使用 `?` 占位符 | **已采用** |
| **输入过滤** | 过滤 SQL 关键字 | 参数化查询足够，过滤可能影响正常使用 |
| **存储过程** | 将 SQL 封装在数据库端 | 小型项目不必要 |
| **最小权限原则** | 数据库用户只给必要权限 | 本实验为教学目的 |
| **WAF** | Web 应用防火墙 | 超出范围 |

---

## 6. 修复后验证

### 6.1 正常功能测试

| 测试项 | 预期 | 结果 |
|--------|------|:----:|
| admin 登录 | 成功，跳转到首页 | ✅ |
| alice 登录 | 成功 | ✅ |
| 注册新用户 | 成功，跳转到登录页 | ✅ |
| 正常搜索 `admin` | 返回 admin 用户 | ✅ |
| 搜索不存在的用户 | "无搜索结果" | ✅ |
| 退出登录 | Session 清空，回到首页 | ✅ |

### 6.2 SQL 注入防御验证

#### POC 1：UNION 注入验证

```bash
# 修复前：搜索结果中出现 "inj" 用户名
# 修复后：无搜索结果
curl -b cookies.txt "http://.../?keyword=%27%20UNION%20SELECT%201,%27inj%27,%27inj%40x.com%27,%27138%27--"
```

| 阶段 | 输出 | 结论 |
|:----:|------|:----:|
| 修复前 | 显示 `inj` 用户名 | ❌ 注入成功 |
| 修复后 | "无搜索结果" | ✅ 已防御 |

**为什么修复后无效？**

```
参数化查询后，注入的 SQL 变成了 LIKE 模式的一部分：
c.execute("SELECT ... WHERE username LIKE ? OR email LIKE ?",
          ("%' UNION SELECT 1,'inj','inj@x.com','138'--%",
           "%' UNION SELECT 1,'inj','inj@x.com','138'--%"))

数据库执行的是：
SELECT ... WHERE username LIKE '%'' UNION SELECT 1,''inj'',''inj@x.com'',''138''--%'
                                       ↑
                                       SQLite 自动将用户输入中的 ' 转义为 ''
                                       UNION SELECT 不再是 SQL 关键字，而是普通文本
```

#### POC 2：OR 注入验证

```bash
# 修复前：返回所有用户
# 修复后：无搜索结果
curl -b cookies.txt "http://.../?keyword=%27%20OR%20%271%27%3D%271"
```

| 阶段 | 输出 | 结论 |
|:----:|------|:----:|
| 修复前 | 显示 admin、alice 等全部用户 | ❌ 注入成功 |
| 修复后 | "无搜索结果" | ✅ 已防御 |

#### POC 3：注册注入验证

```bash
# 修复前：成功插入恶意用户 hacker
# 修复后：用户名被原样存储（包含特殊字符）
curl -X POST http://.../register \
  -d "username=hacker', 'hacker_pass', 'h@x.com', '666')--" \
  -d "password=irrelevant"
```

| 阶段 | 数据库内容 | 结论 |
|:----:|-----------|:----:|
| 修复前 | `hacker \| h@x.com \| 666`（干净数据） | ❌ 注入成功 |
| 修复后 | `hacker', 'hacker_pass', 'h@x.com', '666')-- \| irrelevant \|`（含特殊字符的完整字符串） | ✅ 已防御（被当作普通用户名） |

### 6.3 Burp Suite 列数探测验证

```bash
# 3 列 UNION → 报错（有漏洞版本可以探测到列数）
curl ".../?keyword=%27%20UNION%20SELECT%201,2,3--"
# 修复前：报错 "列数不匹配"（泄露了列数信息）
# 修复后："无搜索结果"（不泄露任何信息）

# 4 列 UNION → 返回数字
curl ".../?keyword=%27%20UNION%20SELECT%201,2,3,4--"
# 修复前：返回 1,2,3,4 作为搜索结果（列数正确）
# 修复后："无搜索结果"（注入被当作普通文本）
```

---

## 7. 其他漏洞修复

### 7.1 漏洞总览

除 SQL 注入外，实验过程中还发现并修复了以下 6 个安全漏洞：

| 编号 | 漏洞名称 | 严重程度 | 修复方式 |
|:----:|---------|:--------:|---------|
| ① | SQL 注入（注册+搜索） | 🔴 严重 | 参数化查询 |
| ② | Session Secret Key 弱密钥 | 🔴 严重 | `secrets.token_hex(32)` |
| ③ | 密码明文存储 | 🟠 高危 | `generate_password_hash()` |
| ④ | 暴力破解无限制 | 🟠 高危 | 同 IP 每分钟限 5 次 |
| ⑤ | Debug 模式开启（RCE 风险） | 🟠 高危 | `debug=False` |
| ⑥ | 服务器指纹泄露 | 🟢 中危 | 自定义 Server 头 |
| ⑦ | 安全响应头缺失 | 🟢 中危 | CSP/X-Frame-Options 等 |

### 7.2 各漏洞修复详情

#### 漏洞②：Session Secret Key 弱密钥

```python
# 修复前
app.secret_key = "dev-key-2025"   # 固定字符串，可被 flask-unsign 工具破解

# 修复后
app.secret_key = secrets.token_hex(32)  # 随机 64 位十六进制，不可预测
```

**攻击方式**：攻击者用 `flask-unsign` 工具解码 session cookie，然后用已知密钥伪造任意用户的身份。

#### 漏洞③：密码明文存储

```python
# 修复前
USERS = {"admin": {"password": "admin123"}}  # 明文

# 修复后
from werkzeug.security import generate_password_hash

USERS = {"admin": {"password_hash": generate_password_hash("admin123")}}  # 哈希值
```

**攻击方式**：数据库泄露时所有密码直接暴露，用户可能多平台共用密码。

#### 漏洞④：暴力破解无限制

```python
# 修复前
# 登录接口没有任何限制

# 修复后
LOGIN_LIMIT = {}  # {IP地址: [失败时间戳列表]}

def check_login_limit(ip, max_attempts=5, window=60):
    """限制同一 IP 每分钟最多失败 5 次"""
    now = time.time()
    LOGIN_LIMIT[ip] = [t for t in LOGIN_LIMIT.get(ip, []) if now - t < window]
    return len(LOGIN_LIMIT[ip]) < max_attempts

# 验证效果
curl -X POST .../login -d "username=admin&password=wrong"
第 5 次失败后：
"登录尝试过于频繁，请 60 秒后再试"
状态码: 429
```

#### 漏洞⑤：Debug 模式

```python
# 修复前
app.run(debug=True, host="0.0.0.0", port=5000)

# 修复后
app.run(debug=False, host="0.0.0.0", port=5000)
```

**风险**：debug=True 会开启 Werkzeug 调试器，攻击者访问 `/console` 可能远程执行 Python 代码。

#### 漏洞⑥：服务器指纹泄露

```python
# 修复前：Flask 默认响应头
Server: Werkzeug/3.1.8 Python/3.13.12

# 修复后
response.headers["Server"] = "WebServer"
```

**风险**：攻击者知道具体版本后，可针对性搜索已知 CVE 漏洞。

#### 漏洞⑦：安全响应头缺失

```python
@app.after_request
def set_security_headers(response):
    response.headers["X-Frame-Options"] = "DENY"                              # 防点击劫持
    response.headers["X-Content-Type-Options"] = "nosniff"                    # 防 MIME 嗅探
    response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Server"] = "WebServer"
    return response
```

### 7.3 代码 Bug 修复

| Bug | 修复前 | 修复后 |
|:----|--------|--------|
| 登录后 URL 卡在 `/login` | `render_template("index.html")` | `redirect("/")` |
| base.html 未被子模板继承 | 4 个文件各有重复导航栏 | 3 个模板统一 `extends "base.html"` |
| 按钮样式不一致 | `btn-primary` 缺少 `btn` 基类 | `btn btn-primary` |

---

## 8. 实验总结

### 8.1 漏洞修复效果对比

| 检测项目 | 修复前 | 修复后 |
|---------|:------:|:------:|
| UNION 注入 | ✅ **成功** 注入自定义数据 | ❌ **失败**，"无搜索结果" |
| OR 注入爆全部用户 | ✅ **成功**，返回 3 条记录 | ❌ **失败**，"无搜索结果" |
| 注册注入插入恶意用户 | ✅ **成功**，创建 hacker 用户 | ❌ **失败**，特殊字符被原样存储 |
| Burp 列数探测 | 可探测列数为 4 | 不泄露任何信息 |
| Session 伪造 | 可用 `flask-unsign` 破解 | 不可预测随机密钥 |
| 暴力破解 | 无限尝试 | 第 6 次返回 429 Too Many Requests |
| 密码安全 | 明文存储，页面显示 | 哈希存储，页面不显示 |
| Debug 远程代码执行 | 可访问 `/console` | 已关闭 |
| 正常功能 | ✅ 正常 | ✅ 正常 |

### 8.2 安全启示

1. **永远不要使用字符串拼接构造 SQL** — f-string、%、format() 都不安全
2. **参数化查询是最有效的 SQL 注入防御手段** — 从数据库层面隔离代码和数据
3. **深度防御** — 除了 SQL 注入，还要关注会话安全、密码存储、暴力破解等
4. **最小信息泄露** — 错误信息、服务器版本、列数信息都不应暴露给攻击者
5. **安全需要持续维护** — 添加新功能时要同步考虑安全性

### 8.3 修复后文件结构

```
/opt/Class01/
├── app.py                     # ✅ 主程序（全部漏洞已修复）
├── .gitignore
├── SECURITY_REPORT.md         # 完整安全报告
├── data/                      # SQLite 数据库目录
├── static/css/style.css       # 样式文件（按钮样式统一）
└── templates/
    ├── base.html              # 基础模板（导航栏，被其他页面继承）
    ├── index.html             # 首页 + 搜索功能
    ├── login.html             # 登录页面
    └── register.html          # 注册页面
```

### 8.4 GitHub 提交历史

```
b5e2c4e  初始化：用户信息管理平台（Flask）
c411955  Revert "SQL注入修复"（回退有漏洞版本用于教学）
ebbe17b  完整安全修复（参数化查询/哈希/限流/响应头）
98b6687  添加安全审计报告
6f41898  修复注册用户无法登录问题
164494e  修复 4 个 Bug（redirect/模板继承/按钮样式）
```

---

*本实验报告由 Claude 自动生成，基于对 Flask 用户管理系统的完整安全审计过程。*
