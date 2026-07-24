import os
import sqlite3
import time
import secrets
import hashlib
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

# 配置上传文件大小限制 16MB
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024

# Session 过期时间（修复6：防止 Session 永不过期）
app.config["PERMANENT_SESSION_LIFETIME"] = 30 * 60  # 30 分钟

# 允许上传的文件类型（修复1：限制文件类型）
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "bmp", "webp", "svg"}

# 上传目录路径
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static", "uploads")

# 用户余额存储（内存字典，用于临时缓存）
USER_BALANCES: dict[str, float] = {}

# 充值限流（防止刷钱）
RECHARGE_LIMIT: dict[str, list[float]] = {}


def get_user_balance(username: str) -> float:
    """获取用户余额（优先从数据库读）"""
    # 先查数据库持久化余额
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute("SELECT balance FROM users WHERE username = ?", (username,))
        row = c.fetchone()
        if row is not None:
            return row[0]
    finally:
        conn.close()
    # 内存字典兜底（admin/alice）
    if username in USERS:
        return USERS[username]["balance"]
    return USER_BALANCES.get(username, 0.0)


def set_user_balance(username: str, balance: float):
    """设置用户余额（持久化到数据库）"""
    balance = round(balance, 2)  # 修复精度
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute("UPDATE users SET balance = ? WHERE username = ?", (balance, username))
        if c.rowcount > 0:
            conn.commit()
        else:
            # 内存字典兜底（admin/alice 也可能在内存中）
            if username in USERS:
                USERS[username]["balance"] = balance
            else:
                USER_BALANCES[username] = balance
    finally:
        conn.close()
    # 同步更新内存缓存
    if username in USERS:
        USERS[username]["balance"] = balance
    else:
        USER_BALANCES[username] = balance


def check_recharge_limit(ip: str, max_attempts: int = 3, window: int = 10) -> bool:
    """检查 IP 在 window 秒内是否超过 max_attempts 次充值"""
    now = time.time()
    if ip not in RECHARGE_LIMIT:
        RECHARGE_LIMIT[ip] = []
    RECHARGE_LIMIT[ip] = [t for t in RECHARGE_LIMIT[ip] if now - t < window]
    return len(RECHARGE_LIMIT[ip]) < max_attempts


def record_recharge(ip: str):
    """记录一次充值操作"""
    RECHARGE_LIMIT.setdefault(ip, [])
    RECHARGE_LIMIT[ip].append(time.time())


# ==================== CSRF 防护 ====================

def generate_csrf_token() -> str:
    """生成 CSRF Token 并存入 session"""
    token = secrets.token_hex(16)
    session["csrf_token"] = token
    return token


def validate_csrf_token() -> bool:
    """验证 CSRF Token"""
    token = request.form.get("csrf_token", "")
    session_token = session.get("csrf_token", "")
    return token and session_token and token == session_token


# 修复3：隐藏服务器指纹信息
@app.after_request
def set_security_headers(response):
    response.headers["X-Frame-Options"] = "DENY"                         # 防止点击劫持
    response.headers["X-Content-Type-Options"] = "nosniff"               # 禁止 MIME 嗅探
    response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'"  # 防止 XSS
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Server"] = "WebServer"                             # 隐藏版本号
    return response


# ==================== 用户数据库（内存字典，用于登录验证） ====================

# 修复4：密码哈希存储，而非明文
USERS = {
    "admin": {
        "username": "admin",
        "password_hash": generate_password_hash("admin123"),
        "role": "admin",
        "email": "admin@example.com",
        "phone": "13800138000",
        "balance": 99999
    },
    "alice": {
        "username": "alice",
        "password_hash": generate_password_hash("alice2025"),
        "role": "user",
        "email": "alice@example.com",
        "phone": "13900139001",
        "balance": 100
    }
}


# ==================== SQLite 数据库（注册、搜索用） ====================

DB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
DB_PATH = os.path.join(DB_DIR, "users.db")


def allowed_file(filename: str) -> bool:
    """修复1：检查文件后缀是否允许"""
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def init_db():
    """初始化 SQLite 数据库，创建 users 表并插入默认用户"""
    os.makedirs(DB_DIR, exist_ok=True)
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT,
            phone TEXT,
            balance REAL DEFAULT 0.0
        )
    """)
    # 检查是否有 balance 列（兼容旧表）
    try:
        c.execute("ALTER TABLE users ADD COLUMN balance REAL DEFAULT 0.0")
        conn.commit()
    except sqlite3.OperationalError:
        pass  # 列已存在

    # 插入默认用户（哈希密码存储）
    c.execute("INSERT OR IGNORE INTO users (username, password, email, phone, balance) VALUES (?, ?, ?, ?, ?)",
              ("admin", generate_password_hash("admin123"), "admin@example.com", "13800138000", 99999))
    c.execute("INSERT OR IGNORE INTO users (username, password, email, phone, balance) VALUES (?, ?, ?, ?, ?)",
              ("alice", generate_password_hash("alice2025"), "alice@example.com", "13900139001", 100))
    conn.commit()
    conn.close()


# ==================== 登录限流（防止暴力破解） ====================

# 修复5：内存计数器限流
LOGIN_LIMIT: dict[str, list[float]] = {}   # {ip: [timestamp1, timestamp2, ...]}


def check_login_limit(ip: str, max_attempts: int = 5, window: int = 60) -> bool:
    """检查 IP 在 window 秒内是否超过 max_attempts 次失败尝试"""
    now = time.time()
    if ip not in LOGIN_LIMIT:
        LOGIN_LIMIT[ip] = []
    # 清理过期记录
    LOGIN_LIMIT[ip] = [t for t in LOGIN_LIMIT[ip] if now - t < window]
    if len(LOGIN_LIMIT[ip]) >= max_attempts:
        return False
    return True


def record_failed_login(ip: str):
    """记录一次失败的登录尝试"""
    LOGIN_LIMIT.setdefault(ip, [])
    LOGIN_LIMIT[ip].append(time.time())


# ==================== 路由：首页 ====================

@app.route("/")
def index():
    username = session.get("username")
    user = USERS.get(username)

    # 如果不在内存字典中，从 SQLite 查询注册用户
    if not user and username:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        try:
            c.execute("SELECT username, email, phone FROM users WHERE username = ?", (username,))
            row = c.fetchone()
            if row:
                user = {
                    "username": row[0],
                    "role": "user",
                    "email": row[1],
                    "phone": row[2],
                    "balance": get_user_balance(row[0])  # 从数据库读取余额
                }
        finally:
            conn.close()

    # 如果带搜索参数，调用搜索功能
    keyword = request.args.get("keyword", "").strip()
    search_results = []
    search_keyword = ""

    if keyword and username:
        # 修复：只搜索当前登录用户自己的信息（防止搜索他人隐私）
        sql = "SELECT id, username, email, phone FROM users WHERE username = ? AND (username LIKE ? OR email LIKE ?)"
        like_pattern = f"%{keyword}%"
        print(f"[SQL] 执行搜索: keyword={keyword}")

        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        try:
            c.execute(sql, (username, like_pattern, like_pattern))
            rows = c.fetchall()
            search_results = [{"id": r[0], "username": r[1], "email": r[2], "phone": r[3]} for r in rows]
        except Exception as e:
            print(f"[DB] 搜索出错: {e}")
        finally:
            conn.close()
        search_keyword = keyword

    return render_template("index.html", user=user,
                           search_results=search_results, search_keyword=search_keyword)


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

        # 先查内存字典（admin/alice，哈希密码）
        user = USERS.get(username)
        if user and check_password_hash(user["password_hash"], password):
            session["username"] = username
            session.permanent = True
            return redirect("/")

        # 再查 SQLite 数据库（注册用户，哈希密码）
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        try:
            c.execute("SELECT username, password, email, phone FROM users WHERE username = ?", (username,))
            row = c.fetchone()
            if row and check_password_hash(row[1], password):  # 修复5：哈希比对
                session["username"] = username
                session.permanent = True
                return redirect("/")
        finally:
            conn.close()

        record_failed_login(client_ip)
        return render_template("login.html", error="用户名或密码错误")

    success = request.args.get("success", "")
    return render_template("login.html", success=success)


# ==================== 路由：注册 ====================

# 修复7：使用参数化查询注册 SQL，而非字符串拼接
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        email = request.form.get("email", "").strip()
        phone = request.form.get("phone", "").strip()

        # 修复4：哈希密码后再存入数据库
        hashed_password = generate_password_hash(password)
        # 修复业务逻辑：新用户初始余额 100
        sql = "INSERT INTO users (username, password, email, phone, balance) VALUES (?, ?, ?, ?, ?)"
        print(f"[SQL] 执行注册: username={username}")

        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        try:
            c.execute(sql, (username, hashed_password, email, phone, 100))
            conn.commit()
            return redirect(url_for("login", success="注册成功，请登录"))
        except sqlite3.IntegrityError:
            error = f"用户名 '{username}' 已存在"
            return render_template("register.html", error=error)
        except Exception as e:
            error = f"注册失败: {e}"
            return render_template("register.html", error=error)
        finally:
            conn.close()

    return render_template("register.html")


# ==================== 路由：头像上传 ====================

@app.route("/upload", methods=["GET", "POST"])
def upload():
    # 需要登录才能访问
    if "username" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        # 检查是否有文件上传
        if "file" not in request.files:
            return render_template("upload.html", error="未选择文件")

        file = request.files["file"]

        # 检查文件名是否为空
        if file.filename == "":
            return render_template("upload.html", error="未选择文件")

        # 修复2：防止路径穿越，只取文件名部分
        filename = os.path.basename(file.filename)

        # 修复1：检查文件后缀，只允许图片类型
        if not allowed_file(filename):
            return render_template("upload.html", error="不支持的文件类型，仅允许图片文件 (jpg, png, gif, bmp, webp, svg)")

        # 修复3：检查文件是否已存在，存在则自动重命名
        file_path = os.path.join(UPLOAD_FOLDER, filename)
        counter = 1
        name_part, ext_part = filename.rsplit(".", 1)
        while os.path.exists(file_path):
            filename = f"{name_part}_{counter}.{ext_part}"
            file_path = os.path.join(UPLOAD_FOLDER, filename)
            counter += 1

        file.save(file_path)

        # 返回文件访问 URL
        file_url = url_for("static", filename=f"uploads/{filename}")
        print(f"[UPLOAD] 用户 {session['username']} 上传文件: {filename}")
        return render_template("upload.html", success=True, file_url=file_url, filename=filename)

    return render_template("upload.html")


# ==================== 路由：个人中心 ====================

@app.route("/profile", methods=["GET"])
def profile():
    if "username" not in session:
        return redirect(url_for("login"))

    current_username = session["username"]

    # 从 URL 参数获取 user_id；如果没传则自动查询当前用户的 ID
    user_id = request.args.get("user_id")

    if not user_id:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        try:
            c.execute("SELECT id FROM users WHERE username = ?", (current_username,))
            row = c.fetchone()
            if row:
                user_id = str(row[0])
        finally:
            conn.close()

    if not user_id:
        return render_template("profile.html", error="请提供用户 ID")

    # 查询用户是否存在
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute("SELECT id, username, email, phone FROM users WHERE id = ?", (user_id,))
        row = c.fetchone()
    finally:
        conn.close()

    if not row or row[1] != current_username:
        # 修复枚举：不区分"用户不存在"和"无权查看"，统一返回相同信息
        return render_template("profile.html", error="无权查看该用户资料")

    user_info = {
        "id": row[0],
        "username": row[1],
        "email": row[2] or "",
        "phone": row[3] or "",
        "balance": get_user_balance(row[1])
    }

    success = request.args.get("success", "")
    token = generate_csrf_token()
    return render_template("profile.html", user_info=user_info, success=success, csrf_token=token)


# ==================== 路由：充值 ====================

@app.route("/recharge", methods=["POST"])
def recharge():
    if "username" not in session:
        return redirect(url_for("login"))

    current_username = session["username"]

    # 修复CSRF：验证 Token
    if not validate_csrf_token():
        return render_template("profile.html", error="请求已过期，请重试", csrf_token=generate_csrf_token())

    # 从表单接收 user_id 和 amount
    user_id = request.form.get("user_id")
    try:
        amount = float(request.form.get("amount", 0))
    except (ValueError, TypeError):
        amount = 0

    # 修复业务逻辑：充值限流，10秒内最多3次
    client_ip = request.remote_addr or "unknown"
    if not check_recharge_limit(client_ip):
        return render_template("profile.html", error="充值操作过于频繁，请稍后再试", csrf_token=generate_csrf_token()), 429

    # 查询用户是否存在
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute("SELECT username FROM users WHERE id = ?", (user_id,))
        row = c.fetchone()
    finally:
        conn.close()

    if not row:
        return redirect(url_for("profile", user_id=user_id))

    # 修复水平越权：只能给自己充值
    if row[0] != current_username:
        return render_template("profile.html", error="无权操作其他用户的账户", csrf_token=generate_csrf_token())

    # 修复业务逻辑：金额必须为正数
    if amount <= 0:
        return render_template("profile.html", error="充值金额必须大于 0", csrf_token=generate_csrf_token())

    username = row[0]
    current_balance = get_user_balance(username)
    new_balance = current_balance + amount
    set_user_balance(username, new_balance)
    record_recharge(client_ip)  # 记录充值操作（用于限流）
    print(f"[RECHARGE] 用户 {username} 充值 {amount}，余额 {current_balance} → {new_balance}")

    return redirect(url_for("profile", user_id=user_id))


# ==================== 路由：动态页面加载 ====================

@app.route("/page", methods=["GET"])
def dynamic_page():
    name = request.args.get("name", "")

    if not name:
        return redirect("/")

    # 修复文件包含：只允许 pages/ 目录下的文件名（不含路径）
    name = os.path.basename(name)

    # 构建文件路径
    page_path = os.path.join("pages", name)
    page_content = None

    # 先尝试直接读取
    if os.path.exists(page_path):
        with open(page_path, "r", encoding="utf-8") as f:
            page_content = f.read()
    else:
        # 尝试加上 .html 后缀
        html_path = page_path + ".html"
        if os.path.exists(html_path):
            with open(html_path, "r", encoding="utf-8") as f:
                page_content = f.read()
        else:
            page_content = "页面不存在"

    # 获取用户信息用于渲染首页
    username = session.get("username")
    user = USERS.get(username)
    if not user and username:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        try:
            c.execute("SELECT username, email, phone FROM users WHERE username = ?", (username,))
            row = c.fetchone()
            if row:
                user = {"username": row[0], "role": "user", "email": row[1], "phone": row[2], "balance": get_user_balance(row[0])}
        finally:
            conn.close()

    return render_template("index.html", user=user, page_content=page_content)


# ==================== 路由：修改密码 ====================

@app.route("/change-password", methods=["POST"])
def change_password():
    if "username" not in session:
        return redirect(url_for("login"))

    current_username = session["username"]

    # 修复CSRF：验证 Token
    if not validate_csrf_token():
        return render_template("profile.html", error="请求已过期，请重试", csrf_token=generate_csrf_token())

    username = request.form.get("username", "")
    old_password = request.form.get("old_password", "")
    new_password = request.form.get("new_password", "")

    if not username or not new_password:
        return render_template("profile.html", error="用户名和密码不能为空", csrf_token=generate_csrf_token())

    # 修复密码漏洞：只能修改自己的密码
    if username != current_username:
        return render_template("profile.html", error="无权修改其他用户的密码", csrf_token=generate_csrf_token())

    # 修复密码漏洞：必须验证原密码
    # 先查 USERS 字典（admin/alice）
    user = USERS.get(username)
    password_valid = False
    if user and check_password_hash(user["password_hash"], old_password):
        password_valid = True
    else:
        # 再查 SQLite 数据库（注册用户）
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        try:
            c.execute("SELECT password FROM users WHERE username = ?", (username,))
            row = c.fetchone()
            if row and check_password_hash(row[0], old_password):
                password_valid = True
        finally:
            conn.close()

    if not password_valid:
        return render_template("profile.html", error="原密码错误", csrf_token=generate_csrf_token())

    # 更新密码
    hashed = generate_password_hash(new_password)

    # 先更新 SQLite 数据库
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute("UPDATE users SET password = ? WHERE username = ?", (hashed, username))
        conn.commit()
    finally:
        conn.close()

    # 如果用户也在 USERS 字典中，同步更新
    if username in USERS:
        USERS[username]["password_hash"] = hashed

    print(f"[CHANGE_PASSWORD] 用户 {username} 密码已修改")
    return redirect(url_for("profile", user_id=request.form.get("user_id", ""), success="密码修改成功"))


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
