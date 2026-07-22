# 📋 漏洞修复报告

> **项目**: Flask 用户信息管理平台
> **路径**: `/opt/Class01/`
> **GitHub**: https://github.com/kittyoo0805/-2026

---

## 一、修复的漏洞

### 1. 水平越权 — 查看他人资料

| 项目 | 内容 |
|------|------|
| **路由** | `GET /profile` |
| **问题** | `user_id` 从 URL 参数获取，未校验与当前登录用户是否匹配 |
| **修复前** | `jack?user_id=1` → 可以看到 admin 的邮箱、手机、余额 |
| **修复后** | `jack?user_id=1` → ❌ "无权查看其他用户的资料" |

**改动代码**：
```python
# 修复前
user_id = request.args.get("user_id")
# ... 直接查询并返回

# 修复后
user_id = request.args.get("user_id")
c.execute("SELECT ... FROM users WHERE id = ?", (user_id,))
row = c.fetchone()
if row[1] != current_username:     # 新增身份校验
    return "无权查看其他用户的资料"
```

---

### 2. 水平越权 — 越权充值

| 项目 | 内容 |
|------|------|
| **路由** | `POST /recharge` |
| **问题** | 表单 `user_id` 未校验，A 用户可给 B 用户充值 |
| **修复前** | `jack` 给 `user_id=1` 充值成功 |
| **修复后** | `jack` 给 `user_id=1` 充值 → ❌ "无权操作其他用户的账户" |

**改动代码**：
```python
# 修复前
if row:
    new_balance = current_balance + amount

# 修复后
if row[0] != current_username:
    return "无权操作其他用户的账户"
```

---

### 3. 水平越权 — 搜索泄露隐私

| 项目 | 内容 |
|------|------|
| **路由** | `GET /`（搜索功能） |
| **问题** | 搜索能查到所有匹配用户，普通用户可搜索管理员信息 |
| **修复前** | `jack` 搜索 `admin` → 搜到 admin 的邮箱和手机 |
| **修复后** | `jack` 搜索 `admin` → ❌ "无搜索结果" |

**改动代码**：
```sql
-- 修复前
WHERE username LIKE ? OR email LIKE ?

-- 修复后（只搜索自己）
WHERE username = ? AND (username LIKE ? OR email LIKE ?)
```

---

### 4. 业务逻辑 — 负数金额充值

| 项目 | 内容 |
|------|------|
| **路由** | `POST /recharge` |
| **问题** | `amount` 未校验正负，充负数等于扣钱 |
| **修复前** | `amount=-99999` → 余额被扣掉 |
| **修复后** | `amount=-99999` → ❌ "充值金额必须大于 0" |

**改动代码**：
```python
# 修复前
new_balance = current_balance + amount

# 修复后
if amount <= 0:
    return "充值金额必须大于 0"
```

---

## 二、验证结果

| 测试场景 | 修复前 | 修复后 |
|----------|:------:|:------:|
| `jack` 查看 `admin` 资料 | ✅ 可以看到 | ❌ 无权查看 |
| `jack` 给 `admin` 充值 | ✅ 成功 | ❌ 无权操作 |
| `jack` 搜索 `admin` | ✅ 搜到隐私 | ❌ 无搜索结果 |
| 自己充负数 `-50` | ✅ 扣钱成功 | ❌ 金额必须大于 0 |
| 自己充正数 `100` | ✅ 成功 | ✅ 成功 |
| 自己搜索自己 | ✅ 正常 | ✅ 正常 |
| `admin` 自己操作 | ✅ 正常 | ✅ 正常 |

---

## 三、修改的文件

| 文件 | 修改内容 |
|------|---------|
| `app.py` | `/profile` 增加身份校验、`/recharge` 增加身份校验和金额正负校验、搜索功能增加只搜自己 |
