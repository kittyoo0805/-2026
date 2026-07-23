# 🛡️ 漏洞修复报告（第二批）

> **项目**: Flask 用户信息管理平台
> **路径**: `/opt/Class01/`
> **GitHub**: https://github.com/kittyoo0805/-2026

---

## 一、文件包含漏洞（路径穿越）

| 项目 | 内容 |
|:----|------|
| **漏洞名称** | 路径穿越 / 文件包含 |
| **漏洞类型** | 路径遍历（Path Traversal） |
| **漏洞位置** | `GET /page?name=` |
| **代码行号** | 第 461-498 行 |

### 漏洞描述

`/page?name=` 路由将用户输入的 `name` 参数直接拼接到文件路径中，没有过滤 `../`，导致攻击者可以读取服务器上的任意文件。

### 漏洞演示（修复前）

```bash
# 读取 app.py 源码
curl "http://target:5000/page?name=../app.py"
# → 返回 Flask 源代码

# 读取系统文件
curl "http://target:5000/page?name=../../../etc/passwd"
# → 返回系统用户列表
```

### 修复方式

```python
# 修复前
page_path = os.path.join("pages", name)           # name=../app.py → pages/../app.py → 穿越成功

# 修复后
name = os.path.basename(name)                      # 过滤掉 ../，只保留文件名
page_path = os.path.join("pages", name)            # name=../app.py → basename→ app.py → pages/app.py → 文件不存在
```

`os.path.basename()` 会从路径中提取最后的文件名部分：
- `../app.py` → `app.py`
- `../../../etc/passwd` → `passwd`
- `help` → `help`

### 验证结果

| 测试 | 修复前 | 修复后 |
|:----|:------:|:------:|
| `?name=../app.py` | ✅ 读到源码 | ❌ "页面不存在" |
| `?name=../../../etc/passwd` | ✅ 读到系统文件 | ❌ "页面不存在" |
| `?name=help`（正常访问） | ✅ 正常 | ✅ 正常 |

---

## 二、业务逻辑漏洞（4 个）

### 漏洞①：余额不持久化

| 项目 | 内容 |
|:----|------|
| **漏洞位置** | `USER_BALANCES` 字典 |
| **类型** | 数据完整性 |

#### 漏洞描述

余额存储在内存字典 `USER_BALANCES` 中，服务器重启后所有充值记录全部丢失。

#### 修复前

```python
USER_BALANCES: dict[str, float] = {}   # 纯内存存储

def set_user_balance(username, balance):
    if username in USERS:
        USERS[username]["balance"] = balance  # 只写内存
    else:
        USER_BALANCES[username] = balance     # 只写内存
```

#### 修复后

```python
def set_user_balance(username, balance):
    balance = round(balance, 2)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("UPDATE users SET balance = ? WHERE username = ?", (balance, username))
    if c.rowcount > 0:
        conn.commit()           # 写入数据库（持久化）
    # 同时同步内存缓存
```

#### 验证

```bash
# 充值50后
sqlite3 users.db "SELECT username, balance FROM users;"
# bob | 150.0   ← 持久化到数据库
```

| 测试 | 修复前 | 修复后 |
|:----|:------:|:------:|
| 充值后重启服务器 | ❌ 余额归零 | ✅ 余额保留 |

---

### 漏洞②：新用户初始余额不公平

| 项目 | 内容 |
|:----|------|
| **漏洞位置** | 注册路由 `POST /register` |
| **类型** | 业务逻辑 |

#### 漏洞描述

admin 初始余额 99999，alice 余额 100，但新注册用户余额为 0，不公平。

#### 修复前

```sql
INSERT INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)
-- 没有 balance 字段，默认为 0
```

#### 修复后

```sql
INSERT INTO users (username, password, email, phone, balance) VALUES (?, ?, ?, ?, ?)
-- 新用户初始余额 100
```

#### 验证

```bash
# 注册 bob
curl -X POST .../register -d "username=bob&password=bob123"
# bob 余额 → 100.0  ✅
```

---

### 漏洞③：充值无频率限制

| 项目 | 内容 |
|:----|------|
| **漏洞位置** | `POST /recharge` |
| **类型** | 接口滥用 |

#### 漏洞描述

充值接口没有任何频率限制，攻击者可以瞬间发送大量请求刷余额。

#### 修复前

```python
# 没有任何限制，1000 次请求全部成功
```

#### 修复后

```python
RECHARGE_LIMIT: dict[str, list[float]] = {}

def check_recharge_limit(ip, max_attempts=3, window=10):
    # 10秒内最多3次充值
```

#### 验证

```bash
# 连续充值5次
第 1 次: ✅ 成功
第 2 次: ✅ 成功
第 3 次: ✅ 成功
第 4 次: ❌ "充值操作过于频繁，请稍后再试"
第 5 次: ❌ "充值操作过于频繁，请稍后再试"
```

---

### 漏洞④：Float 精度丢失

| 项目 | 内容 |
|:----|------|
| **漏洞位置** | 余额计算 |
| **类型** | 数据精度 |

#### 漏洞描述

Python `float` 在涉及金钱计算时有精度问题，例如 `0.1 + 0.2 = 0.30000000000000004`。

#### 修复前

```python
new_balance = current_balance + amount  # 可能有精度误差
```

#### 修复后

```python
balance = round(balance, 2)  # 保留2位小数
new_balance = current_balance + amount
```

---

## 三、修复文件清单

| 文件 | 修改内容 |
|:----|---------|
| `app.py` | `/page` 路由增加 `basename()` 过滤；数据库增加 `balance` 列；余额持久化读写数据库；注册初始余额100；新增充值限流；`round()` 防精度丢失 |

## 四、验证结果汇总

| 测试项 | 漏洞类型 | 修复前 | 修复后 |
|:------|---------|:------:|:------:|
| `?name=../app.py` 穿越读文件 | 文件包含 | ✅ 读到源码 | ❌ "页面不存在" |
| 充值后重启服务器余额保留 | 业务逻辑 | ❌ 丢失 | ✅ 保留 |
| 新注册用户初始余额 | 业务逻辑 | ❌ 0 元 | ✅ 100 元 |
| 10秒内充4次 | 业务逻辑 | ✅ 全部成功 | ❌ 第4次被限流 |
| 余额精度 `0.1+0.2` | 业务逻辑 | ❌ 0.30000000000000004 | ✅ 0.30 |
