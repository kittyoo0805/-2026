# 🛡️ 漏洞修复报告（第三批）

> **项目**: Flask 用户信息管理平台
> **路径**: `/opt/Class01/`
> **GitHub**: https://github.com/kittyoo0805/-2026

---

## 修复的漏洞：6 个

| # | 漏洞类型 | 漏洞名称 | 严重程度 |
|:-|---------|---------|:--------:|
| ① | 🔐 密码漏洞 | **修改密码无需原密码** | 🔴 高危 |
| ② | 🔐 密码漏洞+越权 | **越权修改他人密码** | 🔴 高危 |
| ③ | 🌐 CSRF | **充值接口无 CSRF 防护** | 🟠 中危 |
| ④ | 🌐 CSRF | **改密接口无 CSRF 防护** | 🟠 中危 |
| ⑤ | 🔓 越权 | **用户 ID 遍历枚举** | 🟢 低危 |
| ⑥ | 🔓 越权 | **错误信息过于详细** | 🟢 低危 |

---

## 漏洞①：修改密码无需原密码

| 项目 | 内容 |
|:----|------|
| **位置** | `POST /change-password` |
| **问题** | 直接接收新密码，不需要输入原密码即可修改 |

### 修复前

```python
username = request.form.get("username", "")
new_password = request.form.get("new_password", "")
# 直接生成哈希并更新，不验证原密码
hashed = generate_password_hash(new_password)
c.execute("UPDATE users SET password = ? WHERE username = ?", (hashed, username))
```

### 修复后

```python
old_password = request.form.get("old_password", "")

# 验证原密码
user = USERS.get(username)
if user and check_password_hash(user["password_hash"], old_password):
    password_valid = True
else:
    c.execute("SELECT password FROM users WHERE username = ?", (username,))
    row = c.fetchone()
    if row and check_password_hash(row[0], old_password):
        password_valid = True

if not password_valid:
    return render_template("profile.html", error="原密码错误")
```

### 验证

| 测试 | 结果 |
|:----|:----:|
| 错误原密码改密 | ❌ "原密码错误" |
| 正确原密码改密 | ✅ 302 重定向成功 |

---

## 漏洞②：越权修改他人密码

| 项目 | 内容 |
|:----|------|
| **位置** | `POST /change-password` |
| **问题** | `username` 从表单获取，未校验与当前 session 是否匹配 |

### 修复前

```python
username = request.form.get("username", "")
# 直接更新，不校验 session
```

### 修复后

```python
current_username = session["username"]
username = request.form.get("username", "")

if username != current_username:
    return render_template("profile.html", error="无权修改其他用户的密码")
```

### 验证

| 测试 | 结果 |
|:----|:----:|
| admin 改 alice 密码 | ❌ "无权修改其他用户的密码" |
| admin 改自己密码 | ✅ 成功 |

---

## 漏洞③④：CSRF 跨站请求伪造

| 项目 | 内容 |
|:----|------|
| **位置** | `POST /recharge`、`POST /change-password` |
| **问题** | 两个接口都没有 CSRF Token 验证，攻击者可伪造表单 |

### 修复方式

增加 CSRF Token 生成和验证机制：

```python
def generate_csrf_token() -> str:
    token = secrets.token_hex(16)
    session["csrf_token"] = token
    return token

def validate_csrf_token() -> bool:
    token = request.form.get("csrf_token", "")
    session_token = session.get("csrf_token", "")
    return token and session_token and token == session_token
```

模板中表单增加隐藏字段：
```html
<input type="hidden" name="csrf_token" value="{{ csrf_token }}">
```

POST 路由中验证：
```python
if not validate_csrf_token():
    return render_template("profile.html", error="请求已过期，请重试")
```

### 验证

| 测试 | 结果 |
|:----|:----:|
| 无 Token 充值 | ❌ "请求已过期，请重试" |
| 无 Token 改密 | ❌ "请求已过期，请重试" |
| 带正确 Token 充值 | ✅ 302 成功 |
| 带正确 Token 改密 | ✅ 302 成功 |

---

## 漏洞⑤⑥：用户 ID 遍历枚举 + 错误信息泄露

| 项目 | 内容 |
|:----|------|
| **位置** | `GET /profile?user_id=` |
| **问题** | 区分"用户不存在"和"无权查看"，攻击者可遍历 ID 枚举用户 |

### 修复前

```python
if not row:
    return "用户不存在"          # 不存在的 ID

if row[1] != current_username:
    return "无权查看其他用户的资料"  # 存在的 ID 但无权
# 攻击者可以通过返回信息区分 ID 是否存在
```

### 修复后

```python
if not row or row[1] != current_username:
    return "无权查看该用户资料"     # 统一返回，不区分
```

### 验证

| 测试 | 结果 |
|:----|:----:|
| `user_id=999`（不存在） | ❌ "无权查看该用户资料" |
| `user_id=2`（无权查看） | ❌ "无权查看该用户资料" |
| `user_id=1`（自己） | ✅ 正常显示 |

---

## 验证结果汇总

| 测试项 | 漏洞类型 | 修复前 | 修复后 |
|:------|---------|:------:|:------:|
| 不改原密码直接改密 | 密码漏洞 | ✅ 成功 | ❌ "原密码错误" |
| admin 修改 alice 密码 | 越权 | ✅ 成功 | ❌ "无权修改其他用户的密码" |
| 无 Token 充值 | CSRF | ✅ 成功 | ❌ "请求已过期" |
| 无 Token 改密 | CSRF | ✅ 成功 | ❌ "请求已过期" |
| 遍历 `user_id=999` | 枚举 | ✅ 提示"用户不存在" | ❌ 统一"无权查看" |
| 遍历 `user_id=2` | 枚举 | ✅ 提示"无权查看" | ❌ 统一"无权查看" |
| 正常带 Token 充值 | 正常功能 | ✅ | ✅ |
| 正常带 Token+原密码改密 | 正常功能 | ✅ | ✅ |
