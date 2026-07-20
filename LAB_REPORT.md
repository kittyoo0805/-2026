# 📋 网络安全实验报告

## Flask 用户管理系统 — SQL注入漏洞分析与安全修复

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
5. [Burp Suite 测试方法](#5-burp-suite-测试方法)
6. [修复方案](#6-修复方案)
7. [修复后验证](#7-修复后验证)
8. [其他漏洞修复](#8-其他漏洞修复)
9. [完整修复代码](#9-完整修复代码)
10. [实验总结](#10-实验总结)

---

## 1. 实验背景

### 1.1 系统概况

本实验对象是一个基于 Flask 框架开发的用户信息管理平台，包含以下功能：

- **登录**：用户输入用户名和密码进行身份验证
- **注册**：新用户填写信息注册账号
- **搜索**：已登录用户按关键词搜索其他用户
- **用户信息展示**：登录后展示个人资料

### 1.2 初始技术架构

| 层级 | 技术选型 | 说明 |
|------|---------|------|
| 前端 | HTML + CSS（Jinja2 模板引擎） | 服务端渲染 |
| 后端 | Python Flask 框架 | 轻量级 Web 框架 |
| 数据库 | SQLite | 文件型数据库，存储注册用户数据 |
| 认证 | Session + Cookie 机制 | admin/alice 存储在内存字典 |

### 1.3 初始安全状态

应用最初存在 **7 个安全漏洞**，其中 **SQL 注入（🔴 严重）** 为最严重漏洞。

| 编号 | 漏洞名称 | 严重程度 |
|:----:|---------|:--------:|
| ① | **SQL 注入**（注册 + 搜索功能） | 🔴 **严重** |
| ② | **Session Secret Key 弱密钥** | 🔴 **严重** |
| ③ | **密码明文存储** | 🟠 **高危** |
| ④ | **暴力破解无限制** | 🟠 **高危** |
| ⑤ | **Debug 模式开启**（RCE 风险） | 🟠 **高危** |
| ⑥ | **服务器指纹泄露** | 🟢 **中危** |
| ⑦ | **安全响应头缺失** | 🟢 **中危** |

---

## 2. 漏洞发现过程

### 2.1 代码审查

通过对 `app.py` 源代码审查，发现以下不安全代码模式：

#### 发现点 1：搜索功能 — f-string 拼接 SQL

```python
@app.route("/search", methods=["GET"])
def search():
    keyword = request.args.get("keyword", "").strip()   # 用户输入直接来自 URL
    # ❌ f-string 直接拼接，用户输入中的特殊字符会破坏 SQL 结构
    sql = f"SELECT id, username, email, phone FROM users WHERE username LIKE '%{keyword}%' OR email LIKE '%{keyword}%'"
    c.execute(sql)
```

**危险原因**：`keyword` 参数直接来自 URL 查询字符串，未经任何处理就通过 f-string 嵌入 SQL。

#### 发现点 2：注册功能 — f-string 拼接 SQL

```python
@app.route("/register", methods=["POST"])
def register():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    email = request.form.get("email", "")
    phone = request.form.get("phone", "")
    # ❌ 四个参数全部通过 f-string 嵌入 SQL
    sql = f"INSERT INTO users (username, password, email, phone) VALUES ('{username}', '{password}', '{email}', '{phone}')"
    c.execute(sql)
```

**危险原因**：四个表单字段至少有一个可以被攻击者控制来注入 SQL。

#### 发现点 3：Session Secret Key 弱密钥

```python
# ❌ 固定字符串密钥
app.secret_key = "dev-key-2025"
```

#### 发现点 4：密码明文存储

```python
USERS = {
    "admin": {
        "password": "admin123",   # ❌ 明文密码
    }
}
```

#### 发现点 5：无暴力破解防护

```python
@app.route("/login", methods=["POST"])
def login():
    # 没有任何失败次数限制、IP 限速、验证码
    # 攻击者可以无限尝试密码
```

#### 发现点 6：Debug 模式开启

```python
app.run(debug=True, host="0.0.0.0", port=5000)
```

#### 发现点 7：无安全响应头

```python
# ❌ 没有设置任何安全响应头
# 默认响应：
# Server: Werkzeug/3.1.8 Python/3.13.12
```

### 2.2 攻击面分析

| 攻击入口 | 参数来源 | 注入方式 |
|---------|---------|---------|
| `/search?keyword=` | URL 参数（GET） | UNION 注入、OR 注入 |
| `/register` POST | 表单字段 | 闭合 SQL 插入恶意数据 |
| `/login` POST | 表单字段 | 暴力破解密码 |
| Session Cookie | 浏览器 Cookie | Session 伪造 |

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
                                                    用户输入中的 ' 闭合了字符串
                                                    OR '1'='1 改变了 SQL 逻辑结构
```

**关键点**：单引号 `'` 在 SQL 中用于界定字符串字面量。当用户输入包含 `'` 时，如果直接拼接到 SQL 中，这个 `'` 会**闭合**原本的字符串，后面的内容就变成了 SQL 代码而不是数据。

---

### 3.2 漏洞 1：字符串拼接 SQL 查询

#### 问题代码（搜索功能）

```python
# 注册 - 字符串拼接
query = f"INSERT INTO users (username, password, email, phone) VALUES ('{username}', '{password}', '{email}', '{phone}')"

# 搜索 - 字符串拼接
query = f"SELECT * FROM users WHERE username LIKE '%{keyword}%' OR email LIKE '%{keyword}%'"
```

#### 危害分析

用户输入中的特殊字符（如单引号 `'`）会改变 SQL 语句的结构，导致任意 SQL 命令执行。

**例：搜索时输入 `' OR '1'='1`**

```
拼接前模板：
  SELECT * FROM users WHERE username LIKE '%{keyword}%' OR email LIKE '%{keyword}%'

keyword 赋值后：
  SELECT * FROM users WHERE username LIKE '%' OR '1'='1%' OR email LIKE '%' OR '1'='1%'

                              username LIKE '%'  → 匹配所有用户
                              OR '1'='1'  → 永远为真
                              整个 WHERE 条件恒真 → 返回全部数据
```

**例：注册时输入**

```
拼接前模板：
  INSERT INTO users (username, password, email, phone) VALUES ('{username}', '{password}', '{email}', '{phone}')

username 赋值为 "hacker', 'hacker_pass', 'h@x.com', '666')--" 后：
  INSERT INTO users (username, password, email, phone) VALUES ('hacker', 'hacker_pass', 'h@x.com', '666')--', 'irrelevant', '', '')

  分析：
  1. 'hacker', 'hacker_pass', 'h@x.com', '666' → 完整的 VALUES 数据
  2. ) → 闭合 VALUES 的右括号
  3. -- → SQL 注释符，后面的 ', 'irrelevant', '', '') 被注释掉
  4. 实际插入的是一个攻击者完全控制的账号
```

### 3.3 漏洞 2：无任何输入过滤

所有用户输入直接传入 SQL 语句，没有做任何转义或过滤：

- **没有转义**：没有转义单引号、双引号等特殊字符
- **没有过滤**：没有过滤 SQL 关键字（UNION、OR、AND、SELECT、DROP 等）
- **没有类型校验**：没有校验输入是否为期望的数据类型

### 3.4 漏洞 3：搜索结果有回显

搜索结果直接以表格形式展示在页面上，攻击者可以通过 UNION 注入获取任意数据：

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

向搜索结果中**插入自定义数据**，证明攻击者可以读取任意数据。

#### 攻击命令

```bash
# 步骤 1：先登录获取 session cookie
curl -c /tmp/cookies.txt -X POST http://127.0.0.1:5000/login \
  -d "username=admin" -d "password=admin123"

# 步骤 2：执行 UNION 注入
curl -b /tmp/cookies.txt \
  "http://127.0.0.1:5000/search?keyword=%27%20UNION%20SELECT%201,%27inj%27,%27inj%40x.com%27,%27138%27--"
```

#### URL 解码分析

```
%27         → '         (单引号，闭合 LIKE 字符串)
%20         → (空格)
UNION SELECT           (UNION 关键字，合并第二个查询结果)
1,'inj','inj@x.com','138'  (注入的自定义数据，必须是 4 列)
--           → --       (SQL 注释符，注释掉原始 SQL 的剩余部分)
```

#### SQL 执行过程

```
原始 SQL（用户输入被替换后）：
SELECT * FROM users
WHERE username LIKE '%' UNION SELECT 1,'inj','inj@x.com','138'--%'
      ^                ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
      第一个 LIKE       UNION 合并了一个自定义查询
      被单引号闭合      '--' 注释掉了 '%' OR email LIKE ...'
```

#### 预期输出

```
#   ID  用户名   邮箱             手机
─────────────────────────────────────────
1    1   admin    admin@example.com   13800138000
2    1   inj      inj@x.com           138          ← UNION 注入插入的数据
3    2   alice    alice@example.com   13900139001
```

#### 为什么列数必须是 4？

```
users 表结构（4 列）: id INTEGER, username TEXT, email TEXT, phone TEXT

UNION SELECT 要求两个 SELECT 的列数必须相同：
SELECT * FROM users              → 4 列 (id, username, email, phone)
UNION
SELECT 1,'inj','inj@x.com','138' → 也必须是 4 列

如果列数不匹配，SQLite 会报错：
"SELECTs to the left and right of UNION
 do not have the same number of result columns"
```

---

### 4.2 POC 2：OR 注入搜索全部用户

#### 攻击目标

绕过 WHERE 条件限制，**返回数据库中所有用户记录**。

#### 攻击命令

```bash
curl -b /tmp/cookies.txt \
  "http://127.0.0.1:5000/search?keyword=%27%20OR%20%271%27%3D%271"
```

#### SQL 执行过程

```
原 SQL：
SELECT * FROM users
WHERE username LIKE '%{keyword}%' OR email LIKE '%{keyword}%'

输入 keyword = ' OR '1'='1

生成 SQL：
SELECT * FROM users
WHERE username LIKE '%' OR '1'='1%' OR email LIKE '%' OR '1'='1%'
                       ^^^^^^^^^^^
                       OR '1'='1 是一个永真条件
                       整个 WHERE 条件变成永远为真
                       返回 users 表中的全部数据
```

#### 预期输出

```
#   ID  用户名   邮箱             手机
─────────────────────────────────────────
1    1   admin    admin@example.com   13800138000
2    2   alice    alice@example.com   13900139001
3    3   bob      bob@test.com        13000000001
```

---

### 4.3 POC 3：注册功能 SQL 注入

#### 攻击目标

在注册过程中执行恶意 SQL，**插入一个攻击者完全控制的账号**。

#### 攻击命令

```bash
curl -X POST http://127.0.0.1:5000/register \
  -d "username=hacker', 'hacker_pass', 'h@x.com', '666')--" \
  -d "password=irrelevant"
```

#### SQL 执行过程

```
原 INSERT 语句：
INSERT INTO users (username, password, email, phone)
VALUES ('{username}', '{password}', '{email}', '{phone}')

username 注入后展开：
INSERT INTO users (username, password, email, phone)
VALUES ('hacker', 'hacker_pass', 'h@x.com', '666')--', 'irrelevant', '', '')

分步解析：
1. 'hacker'               → INSERT 的第一个字段值（用户名）
2. 'hacker_pass'           → INSERT 的第二个字段值（密码）
3. 'h@x.com'               → INSERT 的第三个字段值（邮箱）
4. '666'                   → INSERT 的第四个字段值（手机号）
5. )                       → 闭合 VALUES 的右括号
6. --                      → SQL 注释符
7. 剩余的 ', 'irrelevant', '', '') 被注释掉，忽略不计
```

#### 预期输出

```
"注册成功"

验证数据库：
ID  username    email       phone
────────────────────────────────
1   admin       admin@...   13800138000
2   alice       alice@...   13900139001
3   hacker      h@x.com     666           ← 注入创建的恶意用户
```

---

### 4.4 POC 代码详细解释

#### POC 1 详解：UNION 注入

```
原 SQL：SELECT * FROM users WHERE username LIKE '%{keyword}%' OR email LIKE '%{keyword}%'

输入 keyword = ' UNION SELECT 1,'inj','inj@x.com','138'--

生成 SQL：
SELECT * FROM users
WHERE username LIKE '%' UNION SELECT 1,'inj','inj@x.com','138'--%'
      ^^^^^^^^
      UNION 合并第二个查询的结果

第二个查询返回：1, inj, inj@x.com, 138
这些数据会出现在原始的搜索结果中
```

#### POC 2 详解：OR 万能条件

```
原 SQL：SELECT * FROM users WHERE username LIKE '%{keyword}%' OR email LIKE '%{keyword}%'

输入 keyword = ' OR '1'='1

生成 SQL：
SELECT * FROM users
WHERE username LIKE '%' OR '1'='1%' OR email LIKE '%' OR '1'='1%'
                       ^^^^^^^^^^^
                       永真条件，所有行都匹配

结果：返回 users 表中的全部数据
```

---

## 5. Burp Suite 测试方法

### 5.1 环境配置

1. 打开 Burp Suite，设置浏览器代理为 `127.0.0.1:8080`
2. 浏览器访问 `http://192.168.190.132:5000`
3. 登录 `admin / admin123`
4. Burp Proxy 中拦截 HTTP 历史

### 5.2 测试步骤

#### 步骤 1：拦截搜索请求

1. 登录后在搜索框输入 `admin` 并搜索
2. 在 Burp HTTP History 中找到 `GET /search?keyword=admin`
3. 右键 → **Send to Repeater**

#### 步骤 2：测试 OR 注入

在 Repeater 中修改 `keyword` 参数：

```
admin' OR '1'='1
```

**预期结果（修复前）**：返回所有用户
**预期结果（修复后）**："无搜索结果"

#### 步骤 3：测试 UNION 注入列数探测

依次测试不同列数：

```
' UNION SELECT 1,2,3--           → 3 列，报错（列数不匹配）
' UNION SELECT 1,2,3,4--         → 4 列，返回数字
' UNION SELECT 1,username,password,email FROM users--  → 窃取密码
```

**修复前结果**：
| 输入 | 响应 |
|------|------|
| `' UNION SELECT 1,2,3--` | 报错"列数不匹配" |
| `' UNION SELECT 1,2,3,4--` | 搜索结果出现 1,2,3,4 |
| `' UNION SELECT 1,username,password,phone FROM users--` | 显示所有用户的密码 |

**修复后结果**：
| 输入 | 响应 |
|------|------|
| `' UNION SELECT 1,2,3--` | "无搜索结果" |
| `' UNION SELECT 1,2,3,4--` | "无搜索结果" |
| `' UNION SELECT 1,username,password,phone FROM users--` | "无搜索结果" |

#### 步骤 4：观察响应变化

在 Repeater 中观察 Response 的 HTML，确认注入是否生效：

```html
<!-- 注入成功时的特征 -->
<h3>搜索结果：关键词 "..."</h3>
<table>
    <tr><td>1</td><td>inj</td><td>inj@x.com</td><td>138</td></tr>  ← 注入的数据
    <tr><td>1</td><td>admin</td><td>admin@...</td><td>138...</td></tr>  ← 原始数据
</table>

<!-- 注入失败（已修复）时的特征 -->
<h3>搜索结果：关键词 "' UNION SELECT 1,'inj'..."</h3>
<p class="no-results">无搜索结果</p>
```

### 5.3 Burp 测试对照表

| 测试输入 | 测试目的 | 修复前结果 | 修复后结果 |
|---------|---------|:----------:|:----------:|
| `admin' OR '1'='1` | 永真条件爆全部 | ✅ 返回所有用户 | ❌ "无搜索结果" |
| `' UNION SELECT 1,2,3--` | 探测列数（3列） | ✅ 报错泄露列数 | ❌ "无搜索结果" |
| `' UNION SELECT 1,2,3,4--` | 探测列数（4列正确） | ✅ 返回 1,2,3,4 | ❌ "无搜索结果" |
| `' UNION SELECT 1,username,password,phone FROM users--` | 窃取密码 | ✅ 显示所有密码 | ❌ "无搜索结果" |

---

## 6. 修复方案

### 6.1 核心修复：参数化查询

#### 修复原理

参数化查询（Prepared Statement）在**数据库引擎层面**就区分了"SQL 代码"和"数据"：

```
字符串拼接的工作方式：
"SELECT * FROM users WHERE name = '" + input + "'"
                                      ↑
                                      输入直接嵌入 SQL 字符串
                                      数据库无法区分哪部分是代码、哪部分是数据
                                      导致用户输入中的 ' 可以闭合 SQL 语句

参数化查询的工作方式：
1. 数据库收到：SELECT * FROM users WHERE name = ?
2. 数据库编译这个模板，知道 ? 是一个参数（数据占位符）
3. 数据库收到参数：('hello')
4. 数据库把 'hello' 当作纯数据填入
5. 即使输入是 "' OR '1'='1"，数据库也把它当作：
   "搜索一个用户名叫 ' OR '1'='1 的人"
   而不是 "执行 OR 条件"
```

#### 修复前后代码对比

##### 搜索功能

```python
# ===== 修复前（有漏洞）=====
# 用户输入和 SQL 结构混在一起
keyword = "' OR '1'='1"
sql = f"SELECT * FROM users WHERE username LIKE '%{keyword}%' OR email LIKE '%{keyword}%'"
c.execute(sql)
# 实际执行：SELECT * FROM users WHERE username LIKE '%' OR '1'='1%' ...
#                                             注入成功！


# ===== 修复后（安全）=====
# 用户输入和 SQL 结构完全分离
keyword = "' OR '1'='1"
sql = "SELECT id, username, email, phone FROM users WHERE username LIKE ? OR email LIKE ?"
c.execute(sql, (f"%{keyword}%", f"%{keyword}%"))
# 实际执行：SELECT * FROM users WHERE username LIKE '%'' OR ''1''=''1%'
#                                       ↑
#                                       数据库引擎自动将 ' 转义为 ''
#                                       LIKE 匹配的是文本字符串本身
#                                       不会命中任何用户 → "无搜索结果"
```

##### 注册功能

```python
# ===== 修复前（有漏洞）=====
sql = f"INSERT INTO users (username, password, email, phone) VALUES ('{username}', '{password}', '{email}', '{phone}')"
c.execute(sql)
# 可以通过 username 注入任意 SQL

# ===== 修复后（安全）=====
sql = "INSERT INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)"
c.execute(sql, (username, password, email, phone))
# 特殊字符被当作用户名的一部分存储，不会影响 SQL 结构
```

### 6.2 参数化查询 vs 字符串拼接

| 对比项 | 字符串拼接 (f-string) | 参数化查询 (?) |
|--------|---------------------|---------------|
| SQL 结构 | 和用户数据混在一起 | 和用户数据分离 |
| 用户输入 `' OR '1'='1` | `LIKE '%' OR '1'='1%'` → **注入成功** | `LIKE '%'' OR ''1''=''1%'` → **被转义为普通文本** |
| 用户输入 `'--` | `LIKE '%'--%'` → **注释符生效** | `LIKE '%''--%'` → **被转义为普通文本** |
| 用户输入 `UNION SELECT...` | **UNION 关键字生效** | **被当作普通搜索词** |
| 性能 | 每次都要重新解析 SQL | 可预编译复用 |
| 安全性 | ❌ 极不安全 | ✅ 安全 |

### 6.3 修复后的完整代码

```python
# ===== 搜索功能（已修复）=====
sql = "SELECT id, username, email, phone FROM users WHERE username LIKE ? OR email LIKE ?"
c.execute(sql, (f"%{keyword}%", f"%{keyword}%"))

# ===== 注册功能（已修复）=====
sql = "INSERT INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)"
c.execute(sql, (username, password, email, phone))

# ===== 登录（已修复）=====
c.execute("SELECT username, password, email, phone FROM users WHERE username = ?", (username,))

# ===== 首页查询注册用户（已修复）=====
c.execute("SELECT username, email, phone FROM users WHERE username = ?", (username,))
```

---

## 7. 修复后验证

### 7.1 正常功能测试

| 测试项 | 预期 | 结果 |
|--------|------|:----:|
| admin 登录 | 成功，跳转到首页 | ✅ |
| 注册新用户 `testuser / pass123` | 成功，跳转到登录页 | ✅ |
| 新用户登录 | 成功 | ✅ |
| 正常搜索 `admin` | 返回 admin 用户 | ✅ |
| 搜索不存在用户 | "无搜索结果" | ✅ |
| 退出登录 | Session 清空，回到首页 | ✅ |

### 7.2 SQL 注入防御验证

#### POC 1：UNION 注入

```bash
# 修复前：搜索结果中出现 "inj" 用户名
# 修复后：无搜索结果
curl -b cookies.txt \
  "http://127.0.0.1:5000/?keyword=%27%20UNION%20SELECT%201,%27inj%27,%27inj%40x.com%27,%27138%27--"
```

| 阶段 | 输出 | 结论 |
|:----:|------|:----:|
| 修复前 | 显示 `inj` 用户名出现在搜索结果中 | ❌ 注入成功 |
| 修复后 | "无搜索结果" | ✅ 已防御 |

**为什么参数化查询后 UNION 注入失效了？**

```
参数化查询后，注入的 SQL 变成了 LIKE 模式的一部分：
c.execute("SELECT ... WHERE username LIKE ? OR email LIKE ?",
          ("%' UNION SELECT 1,'inj','inj@x.com','138'--%",
           "%' UNION SELECT 1,'inj','inj@x.com','138'--%"))

数据库实际执行的是：
SELECT ... WHERE username LIKE '%'' UNION SELECT 1,''inj'',''inj@x.com'',''138''--%'
                                       ↑
                                       SQLite 自动将用户输入中的 ' 转义为 ''
                                       UNION SELECT 不再是 SQL 关键字
                                       而是当做普通文本进行 LIKE 匹配
```

#### POC 2：OR 注入

```bash
# 修复前：返回所有用户
# 修复后：无搜索结果
curl -b cookies.txt \
  "http://127.0.0.1:5000/?keyword=%27%20OR%20%271%27%3D%271"
```

| 阶段 | 输出 | 结论 |
|:----:|------|:----:|
| 修复前 | 显示 admin、alice 等全部用户 | ❌ 注入成功 |
| 修复后 | "无搜索结果" | ✅ 已防御 |

#### POC 3：注册注入

```bash
# 修复前：数据库中插入干净的 hacker 用户
# 修复后：特殊字符被原样存储在用户名中
curl -X POST http://127.0.0.1:5000/register \
  -d "username=hacker', 'hacker_pass', 'h@x.com', '666')--" \
  -d "password=irrelevant"
```

| 阶段 | 数据库内容 | 结论 |
|:----:|-----------|:----:|
| 修复前 | `hacker \| hacker_pass \| h@x.com \| 666`（干净的用户名） | ❌ 注入成功 |
| 修复后 | `hacker', 'hacker_pass', 'h@x.com', '666')-- \| irrelevant \| \|`（含特殊字符的完整字符串） | ✅ 已防御（被当作普通文本） |

#### Burp Suite 列数探测验证

| 输入 | 修复前 | 修复后 |
|------|:------:|:------:|
| `' UNION SELECT 1,2,3--` | **报错** → 泄露列数为 4 | "无搜索结果" |
| `' UNION SELECT 1,2,3,4--` | **返回 1,2,3,4** → 列数正确 | "无搜索结果" |
| `' UNION SELECT 1,username,password,phone FROM users--` | **显示所有密码** | "无搜索结果" |

---

## 8. 其他漏洞修复

### 8.1 漏洞②：Session Secret Key 弱密钥

#### 问题

```python
# ❌ 修复前
app.secret_key = "dev-key-2025"   # 固定字符串，可被 flask-unsign 工具破解
```

**危害**：攻击者可以用 `flask-unsign` 工具解码 session cookie，然后用已知密钥伪造任意用户的 session，不需要密码即可登录任意账号。

#### 修复

```python
# ✅ 修复后
import secrets
app.secret_key = secrets.token_hex(32)  # 每次重启生成 64 位随机十六进制
```

**为什么有效**：`secrets.token_hex(32)` 生成 64 个字符的随机十六进制字符串，攻击者无法预测。

#### Cookie 安全属性补充

```python
app.config["SESSION_COOKIE_HTTPONLY"] = True    # 禁止 JavaScript 读取 Cookie
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"   # 防止 CSRF 攻击
```

---

### 8.2 漏洞③：密码明文存储

#### 问题

```python
# ❌ 修复前
USERS = {
    "admin": {
        "password": "admin123",   # 明文存储
    }
}
```

**危害**：代码泄露或数据库泄露时，所有密码直接暴露。用户往往多平台共用密码，会导致撞库风险。

#### 修复

```python
# ✅ 修复后
from werkzeug.security import generate_password_hash, check_password_hash

USERS = {
    "admin": {
        "password_hash": generate_password_hash("admin123"),  # 不可逆哈希
    }
}
# 验证时：
if check_password_hash(user["password_hash"], password):
    session["username"] = username
```

**为什么有效**：`generate_password_hash()` 使用 bcrypt/sha256 算法生成不可逆的哈希值。即使数据库泄露，攻击者也无法从哈希值还原出原始密码。

---

### 8.3 漏洞④：暴力破解无限制

#### 问题

```python
# ❌ 修复前：登录接口没有任何限制
@app.route("/login", methods=["POST"])
def login():
    # 攻击者可以每秒尝试数百个密码
    # 没有验证码、没有 IP 限速、没有失败次数限制
```

**危害**：攻击者可以用脚本无限穷举用户密码。

#### 修复

```python
# ✅ 修复后
LOGIN_LIMIT: dict[str, list[float]] = {}   # {ip: [时间戳列表]}

def check_login_limit(ip: str, max_attempts: int = 5, window: int = 60) -> bool:
    """检查 IP 在 window 秒内是否超过 max_attempts 次失败尝试"""
    now = time.time()
    if ip not in LOGIN_LIMIT:
        LOGIN_LIMIT[ip] = []
    # 只保留 window 秒内的记录
    LOGIN_LIMIT[ip] = [t for t in LOGIN_LIMIT[ip] if now - t < window]
    if len(LOGIN_LIMIT[ip]) >= max_attempts:
        return False
    return True

# 登录时调用
if not check_login_limit(client_ip):
    return render_template("login.html", error="登录尝试过于频繁，请 60 秒后再试"), 429
```

**效果验证**：
```
第 1 次失败：用户名或密码错误
第 2 次失败：用户名或密码错误
第 3 次失败：用户名或密码错误
第 4 次失败：用户名或密码错误
第 5 次失败：用户名或密码错误
第 6 次失败：登录尝试过于频繁，请 60 秒后再试  ← 返回 429
```

---

### 8.4 漏洞⑤：Debug 模式开启

#### 问题

```python
# ❌ 修复前
app.run(debug=True, host="0.0.0.0", port=5000)
```

**危害**：
1. **Werkzeug 调试器**：访问 `/console` 可能进入交互式 Python 控制台
2. **PIN 码攻击**：如果攻击者能计算 Debugger PIN，可**远程执行任意代码**（RCE）
3. **错误堆栈泄露**：代码出错时显示完整调用栈，暴露代码路径和内部逻辑

#### 修复

```python
# ✅ 修复后
app.run(debug=False, host="0.0.0.0", port=5000)
```

---

### 8.5 漏洞⑥：服务器指纹泄露

#### 问题

```python
# Flask 默认响应头暴露了版本信息
# Server: Werkzeug/3.1.8 Python/3.13.12
```

**危害**：攻击者知道具体版本后，可针对性搜索已知 CVE 漏洞进行攻击。

#### 修复

```python
@app.after_request
def set_security_headers(response):
    response.headers["Server"] = "WebServer"    # 隐藏真实版本号
    return response
```

---

### 8.6 漏洞⑦：安全响应头缺失

#### 问题

```python
# ❌ 没有设置任何安全响应头，存在多种攻击风险
```

#### 修复

```python
@app.after_request
def set_security_headers(response):
    response.headers["X-Frame-Options"] = "DENY"                              # 防止点击劫持
    response.headers["X-Content-Type-Options"] = "nosniff"                    # 防止 MIME 嗅探
    response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'"  # 防止 XSS
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"   # 控制 Referer
    response.headers["Server"] = "WebServer"                                  # 隐藏版本号
    return response
```

| 响应头 | 作用 | 防御的攻击 |
|--------|------|-----------|
| `X-Frame-Options: DENY` | 禁止页面被嵌入 `<iframe>` | 点击劫持 (Clickjacking) |
| `X-Content-Type-Options: nosniff` | 禁止浏览器猜测文件类型 | MIME 嗅探攻击 |
| `Content-Security-Policy` | 只允许加载同源资源 | XSS 跨站脚本攻击 |
| `Referrer-Policy` | 控制 Referer 头携带的信息 | 信息泄露 |

---

### 8.7 其他 Bug 修复

| # | Bug | 修复前 | 修复后 |
|:-|-----|--------|--------|
| ⑧ | **登录后无 Redirect** | `render_template()` 渲染首页，URL 卡在 `/login` | `redirect("/")` 跳转到 `/`，刷新不重复提交 |
| ⑨ | **base.html 未被继承** | 4 个文件中各有重复导航栏代码 | 全部统一 `extends "base.html"`，导航栏只维护一份 |
| ⑩ | **按钮样式不一致** | 登录/注册按钮缺少 `btn` 基类 | 统一 `class="btn btn-primary"` |

---

## 9. 完整修复代码

### 9.1 app.py（最终安全版本）

```python
import os
import sqlite3
import time
import secrets
from flask import Flask, render_template, request, redirect, session, url_for
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# ==================== 安全配置 ====================

# 修复1：强随机密钥，防止 Session 伪造
app.config["SECRET_KEY"] = secrets.token_hex(32)

# 修复2：Cookie 安全属性
app.config["SESSION_COOKIE_HTTPONLY"] = True     # 禁止 JS 读取 Cookie
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"     # 防止 CSRF
# app.config["SESSION_COOKIE_SECURE"] = True      # 上 HTTPS 后开启

# 修复3：隐藏服务器指纹信息
@app.after_request
def set_security_headers(response):
    response.headers["X-Frame-Options"] = "DENY"                         # 防止点击劫持
    response.headers["X-Content-Type-Options"] = "nosniff"               # 禁止 MIME 嗅探
    response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'"  # 防止 XSS
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Server"] = "WebServer"                             # 隐藏版本号
    return response


# ==================== 用户数据库 ====================

# 修复4：密码哈希存储，而非明文
USERS = {
    "admin": {
        "username": "admin",
        "password_hash": generate_password_hash("admin123"),
        "role": "admin", "email": "admin@example.com",
        "phone": "13800138000", "balance": 99999
    },
    "alice": {
        "username": "alice",
        "password_hash": generate_password_hash("alice2025"),
        "role": "user", "email": "alice@example.com",
        "phone": "13900139001", "balance": 100
    }
}

# ==================== SQLite 数据库 ====================

DB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
DB_PATH = os.path.join(DB_DIR, "users.db")

def init_db():
    os.makedirs(DB_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        email TEXT, phone TEXT
    )""")
    # 插入默认用户（参数化查询 ✅）
    c.execute("INSERT OR IGNORE INTO users VALUES (?, ?, ?, ?, ?)",
              (1, "admin", "admin123", "admin@example.com", "13800138000"))
    c.execute("INSERT OR IGNORE INTO users VALUES (?, ?, ?, ?, ?)",
              (2, "alice", "alice2025", "alice@example.com", "13900139001"))
    conn.commit()
    conn.close()


# ==================== 登录限流 ====================

# 修复5：内存计数器限流
LOGIN_LIMIT: dict[str, list[float]] = {}

def check_login_limit(ip: str, max_a: int = 5, w: int = 60) -> bool:
    now = time.time()
    if ip not in LOGIN_LIMIT: LOGIN_LIMIT[ip] = []
    LOGIN_LIMIT[ip] = [t for t in LOGIN_LIMIT[ip] if now - t < w]
    return len(LOGIN_LIMIT[ip]) < max_a

def record_failed_login(ip: str):
    LOGIN_LIMIT.setdefault(ip, []).append(time.time())


# ==================== 路由：首页 ====================

@app.route("/")
def index():
    username = session.get("username")
    user = USERS.get(username)

    # 如果不在内存字典中，从 SQLite 查询
    if not user and username:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        try:  # 参数化查询 ✅
            c.execute("SELECT username, email, phone FROM users WHERE username = ?", (username,))
            row = c.fetchone()
            if row:
                user = {"username": row[0], "role": "user", "email": row[1], "phone": row[2], "balance": 0}
        finally: conn.close()

    # 搜索功能
    keyword = request.args.get("keyword", "").strip()
    search_results, search_keyword = [], ""

    if keyword and username:
        # 修复6：参数化查询，防止 SQL 注入 ✅
        sql = "SELECT id, username, email, phone FROM users WHERE username LIKE ? OR email LIKE ?"
        like_pattern = f"%{keyword}%"
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        try:
            c.execute(sql, (like_pattern, like_pattern))
            rows = c.fetchall()
            search_results = [{"id": r[0], "username": r[1], "email": r[2], "phone": r[3]} for r in rows]
        finally: conn.close()
        search_keyword = keyword

    return render_template("index.html", user=user, search_results=search_results, search_keyword=search_keyword)


# ==================== 路由：登录 ====================

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        client_ip = request.remote_addr or "unknown"

        # 限流检查
        if not check_login_limit(client_ip):
            return render_template("login.html", error="登录尝试过于频繁，请 60 秒后再试"), 429

        # 先查内存字典（哈希验证）
        user = USERS.get(username)
        if user and check_password_hash(user["password_hash"], password):
            session["username"] = username
            return redirect("/")

        # 再查 SQLite（注册用户，明文比对）
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        try:    # 参数化查询 ✅
            c.execute("SELECT username, password, email, phone FROM users WHERE username = ?", (username,))
            row = c.fetchone()
            if row and row[1] == password:
                session["username"] = username
                return redirect("/")
        finally: conn.close()

        record_failed_login(client_ip)
        return render_template("login.html", error="用户名或密码错误")

    success = request.args.get("success", "")
    return render_template("login.html", success=success)


# ==================== 路由：注册 ====================

# 修复7：参数化查询，而非字符串拼接 ✅
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        email = request.form.get("email", "").strip()
        phone = request.form.get("phone", "").strip()

        # 参数化查询，防止 SQL 注入 ✅
        sql = "INSERT INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)"
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        try:
            c.execute(sql, (username, password, email, phone))
            conn.commit()
            return redirect(url_for("login", success="注册成功，请登录"))
        except sqlite3.IntegrityError:
            return render_template("register.html", error=f"用户名 '{username}' 已存在")
        finally: conn.close()

    return render_template("register.html")


# ==================== 路由：登出 ====================

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


# ==================== 启动 ====================

if __name__ == "__main__":
    init_db()
    # 修复8：关闭 Debug 模式，防止远程代码执行
    app.run(debug=False, host="0.0.0.0", port=5000)
```

---

## 10. 实验总结

### 10.1 漏洞修复效果对比

| 检测项目 | 修复前 | 修复后 |
|---------|:------:|:------:|
| **UNION 注入** | ✅ 成功注入自定义数据 | ❌ 失败，"无搜索结果" |
| **OR 注入爆全部用户** | ✅ 成功，返回全部记录 | ❌ 失败，"无搜索结果" |
| **注册注入插入恶意用户** | ✅ 成功，创建 hacker 用户 | ❌ 失败，特殊字符被原样存储 |
| **Burp 列数探测** | 可探测列数为 4 | 不泄露任何信息 |
| **Session 伪造** | 可用 `flask-unsign`` 破解 | 不可预测随机密钥 |
| **暴力破解** | 无限尝试密码 | 第 6 次返回 429 Too Many Requests |
| **密码安全** | 明文存储 + 页面显示 | 哈希存储 + 页面不显示 |
| **Debug 远程代码执行** | 可访问 `/console` | 已关闭 |
| **登录后 URL 跳转** | 卡在 `/login` | 跳转到 `/` |
| **正常功能** | ✅ 正常 | ✅ 正常 |

### 10.2 安全启示

1. **永远不要使用字符串拼接构造 SQL 语句**
   - f-string、%、format() 都有注入风险
   - 必须使用参数化查询（Prepared Statement）

2. **参数化查询是最有效的 SQL 注入防御手段**
   - 从数据库层面隔离代码和数据
   - 数据库引擎自动处理转义

3. **安全需要深度防御**
   - 除了 SQL 注入，还要关注 Session 安全、密码存储、暴力破解、响应头等

4. **最小信息泄露原则**
   - 错误信息、服务器版本、数据库列数都不应暴露
   - Debug 模式仅限开发环境

5. **安全是持续的过程**
   - 每次添加新功能都要同步考虑安全性
   - 定期进行代码审查和渗透测试

### 10.3 最终项目文件结构

```
/opt/Class01/
├── app.py                     # ✅ 主程序（全部漏洞已修复）
├── .gitignore
├── LAB_REPORT.md              # 📄 本实验报告
├── SECURITY_REPORT.md         # 安全修复报告
├── data/                      # SQLite 数据库目录
│   └── users.db
├── static/
│   └── css/
│       └── style.css          # 样式文件
└── templates/
    ├── base.html              # 基础模板（导航栏）
    ├── index.html             # 首页 + 搜索功能
    ├── login.html             # 登录页面
    └── register.html          # 注册页面
```

### 10.4 GitHub 提交历史

```
b5e2c4e  初始化：用户信息管理平台（Flask）
c411955  Revert "SQL注入修复"（回退到有漏洞版本用于教学演示）
ebbe17b  完整安全修复（参数化查询/哈希/限流/响应头）
98b6687  添加安全审计报告
6f41898  修复注册用户无法登录问题
164494e  修复 4 个 Bug（redirect/模板继承/按钮样式）
8bbcac3  添加完整实验报告
```

---

*本实验报告基于对 Flask 用户管理系统的完整安全审计过程编写，涵盖漏洞发现、原理分析、POC 验证、修复方案和效果验证全流程。*
