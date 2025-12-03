#!/usr/bin/env python3
"""
服务管理Web应用 - 增强版
功能：
1. 监听8888端口
2. 提供登录界面，初始账号密码为admin/admin
3. 首次登录强制要求修改密码
4. 登录后显示服务状态面板
5. 可以控制bind和nginx服务（启动、停止、重启、允许开机启动、禁止开机启动）
6. 可以上传APK文件替换/usr/share/nginx/html/3.0.apk
7. 使用JSON文件存储用户数据
"""

import os
import json
import hashlib
import subprocess
import time
import shutil
import uuid
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash, send_file
from functools import wraps
import secrets

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)  # 生成安全的随机密钥
app.config['USER_DATA_FILE'] = 'users.json'
app.config['PASSWORD_MIN_LENGTH'] = 8
app.config['PASSWORD_HISTORY_COUNT'] = 3  # 密码历史记录数量，防止重复使用旧密码
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024  # 最大上传500MB
app.config['ALLOWED_EXTENSIONS'] = {'apk'}

# 登录验证装饰器
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# 首次登录检查装饰器
def first_login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' in session and session.get('first_login', True):
            return redirect(url_for('change_password'))
        return f(*args, **kwargs)
    return decorated_function

# 密码加密函数
def hash_password(password, salt=None):
    """使用SHA-256和盐值加密密码"""
    if salt is None:
        salt = secrets.token_hex(16)
    
    # 将盐值和密码组合
    salted_password = salt + password
    # 计算哈希值
    hashed_password = hashlib.sha256(salted_password.encode()).hexdigest()
    
    return hashed_password, salt

# 验证密码函数
def verify_password(stored_hash, stored_salt, password):
    """验证密码是否匹配"""
    hashed_password, _ = hash_password(password, stored_salt)
    return hashed_password == stored_hash

# 密码强度检查
def check_password_strength(password):
    """检查密码强度"""
    if len(password) < app.config['PASSWORD_MIN_LENGTH']:
        return False, f"密码长度至少为{app.config['PASSWORD_MIN_LENGTH']}个字符"
    
    # 检查是否包含数字
    if not any(char.isdigit() for char in password):
        return False, "密码必须包含至少一个数字"
    
    # 检查是否包含大写字母
    if not any(char.isupper() for char in password):
        return False, "密码必须包含至少一个大写字母"
    
    # 检查是否包含小写字母
    if not any(char.islower() for char in password):
        return False, "密码必须包含至少一个小写字母"
    
    # 检查是否包含特殊字符
    special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    if not any(char in special_chars for char in password):
        return False, "密码必须包含至少一个特殊字符 (!@#$%^&*()_+-=[]{}|;:,.<>?)"
    
    return True, "密码强度足够"

# 检查文件扩展名
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# 用户数据管理
class UserManager:
    def __init__(self, data_file):
        self.data_file = data_file
        self.users = self.load_users()
        self.ensure_default_user()
    
    def load_users(self):
        """从文件加载用户数据"""
        try:
            if os.path.exists(self.data_file):
                with open(self.data_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    # 确保返回的是字典格式
                    if isinstance(data, dict):
                        print(f"成功加载用户数据，找到 {len(data)} 个用户")
                        return data
                    else:
                        print(f"警告: users.json 文件格式不正确，重置为空字典")
                        return {}
            else:
                print(f"用户数据文件不存在，将创建新文件: {self.data_file}")
                return {}
        except (json.JSONDecodeError, FileNotFoundError) as e:
            print(f"加载用户数据失败: {e}")
            return {}
        except Exception as e:
            print(f"加载用户数据时发生错误: {e}")
            return {}
    
    def save_users(self):
        """保存用户数据到文件"""
        try:
            with open(self.data_file, 'w', encoding='utf-8') as f:
                json.dump(self.users, f, indent=2, ensure_ascii=False)
            print(f"用户数据已保存到: {self.data_file}")
        except Exception as e:
            print(f"保存用户数据失败: {e}")
    
    def ensure_default_user(self):
        """确保默认用户存在"""
        # 只在文件不存在或admin用户不存在时才创建默认用户
        if not os.path.exists(self.data_file) or 'admin' not in self.users:
            print("创建默认管理员用户")
            # 创建默认管理员用户
            hashed_password, salt = hash_password('admin')
            self.users['admin'] = {
                'username': 'admin',
                'password_hash': hashed_password,
                'salt': salt,
                'first_login': True,
                'password_history': [],
                'created_at': datetime.now().isoformat(),
                'last_login': None,
                'last_password_change': None
            }
            self.save_users()
        else:
            print(f"找到已存在的管理员用户: {self.users['admin'].get('username', 'admin')}")
            # 确保数据结构完整
            user = self.users['admin']
            if 'first_login' not in user:
                user['first_login'] = False
            if 'password_history' not in user:
                user['password_history'] = []
            if 'created_at' not in user:
                user['created_at'] = datetime.now().isoformat()
            if 'last_login' not in user:
                user['last_login'] = None
            if 'last_password_change' not in user:
                user['last_password_change'] = None
    
    def get_user(self, username):
        """获取用户信息"""
        return self.users.get(username)
    
    def authenticate(self, username, password):
        """验证用户凭据"""
        user = self.get_user(username)
        if not user:
            return False, "用户不存在"
        
        if verify_password(user['password_hash'], user['salt'], password):
            # 更新最后登录时间
            user['last_login'] = datetime.now().isoformat()
            self.save_users()
            return True, "登录成功"
        
        return False, "密码错误"
    
    def change_password(self, username, old_password, new_password):
        """更改用户密码"""
        user = self.get_user(username)
        if not user:
            return False, "用户不存在"
        
        # 验证旧密码
        if not verify_password(user['password_hash'], user['salt'], old_password):
            return False, "当前密码错误"
        
        # 检查密码强度
        is_strong, msg = check_password_strength(new_password)
        if not is_strong:
            return False, msg
        
        # 检查是否与历史密码重复
        for history in user['password_history']:
            if verify_password(history['hash'], history['salt'], new_password):
                return False, "不能使用最近使用过的密码"
        
        # 生成新密码的哈希值
        new_hash, new_salt = hash_password(new_password)
        
        # 将当前密码添加到历史记录
        user['password_history'].append({
            'hash': user['password_hash'],
            'salt': user['salt'],
            'changed_at': datetime.now().isoformat()
        })
        
        # 只保留最近N个密码历史
        if len(user['password_history']) > app.config['PASSWORD_HISTORY_COUNT']:
            user['password_history'] = user['password_history'][-app.config['PASSWORD_HISTORY_COUNT']:]
        
        # 更新用户密码信息
        user['password_hash'] = new_hash
        user['salt'] = new_salt
        user['first_login'] = False
        user['last_password_change'] = datetime.now().isoformat()
        
        self.save_users()
        return True, "密码修改成功"
    
    def update_first_login(self, username, first_login):
        """更新首次登录状态"""
        user = self.get_user(username)
        if user:
            user['first_login'] = first_login
            self.save_users()

# 初始化用户管理器
user_manager = UserManager(app.config['USER_DATA_FILE'])

# 检查服务状态函数
def check_service_status(service_name):
    """检查服务状态和开机启动状态"""
    try:
        # 检查服务运行状态
        result = subprocess.run(
            ['systemctl', 'is-active', service_name],
            capture_output=True,
            text=True,
            timeout=5
        )
        status = result.stdout.strip()
        
        if status == 'active':
            run_status = 'running'
        elif status == 'inactive':
            run_status = 'stopped'
        else:
            # 如果systemctl失败，尝试使用ps检查
            result = subprocess.run(
                ['ps', 'aux'],
                capture_output=True,
                text=True
            )
            if service_name in result.stdout:
                run_status = 'running'
            else:
                run_status = 'stopped'
        
        # 检查开机启动状态
        result = subprocess.run(
            ['systemctl', 'is-enabled', service_name],
            capture_output=True,
            text=True,
            timeout=5
        )
        enabled_status = result.stdout.strip()
        
        if enabled_status == 'enabled':
            startup_status = 'enabled'
        elif enabled_status == 'disabled':
            startup_status = 'disabled'
        else:
            # 如果无法确定，检查是否存在服务文件
            try:
                if os.path.exists(f'/etc/systemd/system/{service_name}.service') or \
                   os.path.exists(f'/lib/systemd/system/{service_name}.service') or \
                   os.path.exists(f'/usr/lib/systemd/system/{service_name}.service'):
                    startup_status = 'unknown'
                else:
                    startup_status = 'not-installed'
            except:
                startup_status = 'unknown'
        
        return {
            'run_status': run_status,
            'startup_status': startup_status
        }
        
    except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.CalledProcessError):
        # 如果systemctl不可用，尝试其他方法
        try:
            # 对于nginx，检查进程
            if 'nginx' in service_name.lower():
                result = subprocess.run(
                    ['ps', 'aux', '|', 'grep', 'nginx', '|', 'grep', '-v', 'grep'],
                    shell=True,
                    capture_output=True,
                    text=True
                )
                if result.returncode == 0 and 'nginx' in result.stdout:
                    run_status = 'running'
                else:
                    run_status = 'stopped'
                
                # 检查开机启动（通过检查rc.local或init.d）
                if os.path.exists('/etc/rc.local'):
                    with open('/etc/rc.local', 'r') as f:
                        rc_content = f.read()
                        if 'nginx' in rc_content:
                            startup_status = 'enabled'
                        else:
                            startup_status = 'disabled'
                else:
                    startup_status = 'unknown'
                
                return {
                    'run_status': run_status,
                    'startup_status': startup_status
                }
            
            # 对于bind服务，检查named
            elif 'named' in service_name.lower() or 'bind' in service_name.lower():
                result = subprocess.run(
                    ['ps', 'aux', '|', 'grep', 'named', '|', 'grep', '-v', 'grep'],
                    shell=True,
                    capture_output=True,
                    text=True
                )
                if result.returncode == 0 and 'named' in result.stdout:
                    run_status = 'running'
                else:
                    run_status = 'stopped'
                
                # 检查开机启动
                if os.path.exists('/etc/rc.local'):
                    with open('/etc/rc.local', 'r') as f:
                        rc_content = f.read()
                        if 'named' in rc_content:
                            startup_status = 'enabled'
                        else:
                            startup_status = 'disabled'
                else:
                    startup_status = 'unknown'
                
                return {
                    'run_status': run_status,
                    'startup_status': startup_status
                }
            
            else:
                return {
                    'run_status': 'unknown',
                    'startup_status': 'unknown'
                }
        except Exception as e:
            return {
                'run_status': 'unknown',
                'startup_status': 'unknown'
            }

# 控制服务函数
def control_service(service_name, action):
    """控制服务启动/停止/重启/允许开机启动/禁止开机启动"""
    try:
        if action == 'start':
            # 启动服务
            result = subprocess.run(
                ['systemctl', 'start', service_name],
                capture_output=True,
                text=True
            )
            if result.returncode == 0:
                return True, f"服务 {service_name} 已启动"
            else:
                # 如果systemctl失败，尝试直接启动
                if 'nginx' in service_name.lower():
                    subprocess.run(['nginx'], capture_output=True, text=True)
                    return True, f"服务 {service_name} 已启动"
                elif 'named' in service_name.lower():
                    subprocess.run(['systemctl', 'start', 'named'], capture_output=True, text=True)
                    return True, f"服务 {service_name} 已启动"
                else:
                    return False, f"无法启动 {service_name}: {result.stderr}"
        
        elif action == 'stop':
            # 停止服务
            result = subprocess.run(
                ['systemctl', 'stop', service_name],
                capture_output=True,
                text=True
            )
            if result.returncode == 0:
                return True, f"服务 {service_name} 已停止"
            else:
                # 如果systemctl失败，尝试直接停止
                if 'nginx' in service_name.lower():
                    subprocess.run(['nginx', '-s', 'stop'], capture_output=True, text=True)
                    return True, f"服务 {service_name} 已停止"
                elif 'named' in service_name.lower():
                    subprocess.run(['systemctl', 'stop', 'named'], capture_output=True, text=True)
                    return True, f"服务 {service_name} 已停止"
                else:
                    return False, f"无法停止 {service_name}: {result.stderr}"
        
        elif action == 'restart':
            # 重启服务
            result = subprocess.run(
                ['systemctl', 'restart', service_name],
                capture_output=True,
                text=True
            )
            if result.returncode == 0:
                return True, f"服务 {service_name} 已重启"
            else:
                return False, f"无法重启 {service_name}: {result.stderr}"
        
        elif action == 'enable':
            # 允许开机启动
            result = subprocess.run(
                ['systemctl', 'enable', service_name],
                capture_output=True,
                text=True
            )
            if result.returncode == 0:
                return True, f"服务 {service_name} 已设置为开机启动"
            else:
                # 如果systemctl失败，尝试其他方法
                if os.path.exists('/etc/rc.local'):
                    # 备份rc.local
                    shutil.copy2('/etc/rc.local', '/etc/rc.local.backup')
                    
                    # 读取rc.local内容
                    with open('/etc/rc.local', 'r') as f:
                        content = f.read()
                    
                    # 添加启动命令
                    start_cmd = f"\n# Start {service_name} at boot\n"
                    if 'nginx' in service_name.lower():
                        start_cmd += "nginx\n"
                    elif 'named' in service_name.lower():
                        start_cmd += "systemctl start named\n"
                    
                    # 写入新内容
                    with open('/etc/rc.local', 'a') as f:
                        f.write(start_cmd)
                    
                    return True, f"服务 {service_name} 已设置为开机启动"
                else:
                    return False, f"无法设置开机启动 {service_name}: {result.stderr}"
        
        elif action == 'disable':
            # 禁止开机启动
            result = subprocess.run(
                ['systemctl', 'disable', service_name],
                capture_output=True,
                text=True
            )
            if result.returncode == 0:
                return True, f"服务 {service_name} 已禁止开机启动"
            else:
                # 如果systemctl失败，尝试其他方法
                if os.path.exists('/etc/rc.local'):
                    # 备份rc.local
                    shutil.copy2('/etc/rc.local', '/etc/rc.local.backup')
                    
                    # 读取rc.local内容
                    with open('/etc/rc.local', 'r') as f:
                        lines = f.readlines()
                    
                    # 删除相关启动命令
                    new_lines = []
                    skip_next = False
                    for i, line in enumerate(lines):
                        if f"Start {service_name}" in line:
                            skip_next = True
                            continue
                        if skip_next and ('nginx' in line or 'named' in line):
                            skip_next = False
                            continue
                        new_lines.append(line)
                    
                    # 写入新内容
                    with open('/etc/rc.local', 'w') as f:
                        f.writelines(new_lines)
                    
                    return True, f"服务 {service_name} 已禁止开机启动"
                else:
                    return False, f"无法禁止开机启动 {service_name}: {result.stderr}"
        
        else:
            return False, f"未知操作: {action}"
    
    except Exception as e:
        return False, f"操作失败: {str(e)}"

# 获取所有服务状态
def get_all_services_status():
    """获取所有服务的状态"""
    services = {
        'nginx': 'Nginx Web服务器',
        'named': 'BIND DNS服务器'
    }
    
    status = {}
    for service, name in services.items():
        service_status = check_service_status(service)
        status[service] = {
            'name': name,
            'run_status': service_status.get('run_status', 'unknown'),
            'startup_status': service_status.get('startup_status', 'unknown'),
            'display_name': name
        }
    
    return status

# 文件上传处理
def handle_apk_upload(file):
    """处理APK文件上传"""
    if not file or file.filename == '':
        return False, "没有选择文件"
    
    if not allowed_file(file.filename):
        return False, "只允许上传APK文件"
    
    try:
        # 创建上传目录
        upload_dir = app.config['UPLOAD_FOLDER']
        if not os.path.exists(upload_dir):
            os.makedirs(upload_dir)
        
        # 生成唯一文件名
        filename = f"{uuid.uuid4().hex}.apk"
        filepath = os.path.join(upload_dir, filename)
        
        # 保存上传的文件
        file.save(filepath)
        
        # 目标文件路径
        target_path = '/usr/share/nginx/html/3.0.apk'
        
        # 检查目标目录是否存在
        target_dir = os.path.dirname(target_path)
        if not os.path.exists(target_dir):
            os.makedirs(target_dir, exist_ok=True)
        
        # 备份原文件（如果存在）
        if os.path.exists(target_path):
            backup_path = f"{target_path}.backup.{int(time.time())}"
            shutil.copy2(target_path, backup_path)
        
        # 复制文件到目标位置
        shutil.copy2(filepath, target_path)
        
        # 设置适当的权限
        os.chmod(target_path, 0o644)
        
        # 保存上传记录
        upload_record = {
            'filename': file.filename,
            'saved_as': filename,
            'target_path': target_path,
            'upload_time': datetime.now().isoformat(),
            'size': os.path.getsize(filepath)
        }
        
        # 保存到上传历史文件
        history_file = os.path.join(upload_dir, 'upload_history.json')
        history_data = []
        
        if os.path.exists(history_file):
            with open(history_file, 'r', encoding='utf-8') as f:
                try:
                    history_data = json.load(f)
                except:
                    history_data = []
        
        history_data.append(upload_record)
        
        # 只保留最近10条记录
        if len(history_data) > 10:
            history_data = history_data[-10:]
        
        with open(history_file, 'w', encoding='utf-8') as f:
            json.dump(history_data, f, indent=2, ensure_ascii=False)
        
        return True, f"APK文件已成功上传并替换到 {target_path}"
    
    except Exception as e:
        return False, f"上传失败: {str(e)}"

# 路由定义
@app.route('/')
@login_required
@first_login_required
def index():
    """主页面"""
    services_status = get_all_services_status()
    
    # 获取当前APK文件信息
    apk_info = {}
    target_path = '/usr/share/nginx/html/3.0.apk'
    if os.path.exists(target_path):
        apk_info = {
            'exists': True,
            'path': target_path,
            'size': os.path.getsize(target_path),
            'modified_time': datetime.fromtimestamp(os.path.getmtime(target_path)).strftime('%Y-%m-%d %H:%M:%S')
        }
    else:
        apk_info = {
            'exists': False,
            'path': target_path
        }
    
    return render_template('index.html', services=services_status, apk_info=apk_info)

@app.route('/login', methods=['GET', 'POST'])
def login():
    """登录页面"""
    # 如果已登录，重定向到首页
    if 'logged_in' in session:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # 验证账号密码
        success, message = user_manager.authenticate(username, password)
        
        if success:
            session['logged_in'] = True
            session['username'] = username
            
            # 检查是否为首次登录
            user = user_manager.get_user(username)
            if user and user.get('first_login', True):
                session['first_login'] = True
                return redirect(url_for('change_password'))
            else:
                session['first_login'] = False
                return redirect(url_for('index'))
        else:
            return render_template('login.html', error=message)
    
    return render_template('login.html')

@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    """修改密码页面"""
    # 如果不是首次登录且不是从强制修改密码页面来的，重定向到首页
    if not session.get('first_login', True):
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        # 验证输入
        if not current_password or not new_password or not confirm_password:
            return render_template('change_password.html', error="所有字段都必须填写")
        
        # 验证新密码和确认密码是否一致
        if new_password != confirm_password:
            return render_template('change_password.html', error="新密码和确认密码不一致")
        
        # 更改密码
        username = session.get('username')
        success, message = user_manager.change_password(username, current_password, new_password)
        
        if success:
            # 更新会话状态
            session['first_login'] = False
            user_manager.update_first_login(username, False)
            return redirect(url_for('index'))
        else:
            return render_template('change_password.html', error=message)
    
    return render_template('change_password.html')

@app.route('/logout')
def logout():
    """退出登录"""
    session.pop('logged_in', None)
    session.pop('username', None)
    session.pop('first_login', None)
    return redirect(url_for('login'))

@app.route('/api/service/status')
@login_required
@first_login_required
def service_status():
    """API: 获取服务状态"""
    services_status = get_all_services_status()
    return jsonify(services_status)

@app.route('/api/service/control', methods=['POST'])
@login_required
@first_login_required
def service_control():
    """API: 控制服务"""
    service = request.json.get('service')
    action = request.json.get('action')
    
    if not service or not action:
        return jsonify({'success': False, 'message': '缺少参数'})
    
    if action not in ['start', 'stop', 'restart', 'enable', 'disable']:
        return jsonify({'success': False, 'message': '不支持的操作'})
    
    success, message = control_service(service, action)
    
    # 等待一小段时间让服务状态更新
    time.sleep(1)
    
    # 获取更新后的状态
    services_status = get_all_services_status()
    
    return jsonify({
        'success': success,
        'message': message,
        'services': services_status
    })

@app.route('/upload-apk', methods=['POST'])
@login_required
@first_login_required
def upload_apk():
    """上传APK文件"""
    if 'apk_file' not in request.files:
        return jsonify({'success': False, 'message': '没有选择文件'})
    
    file = request.files['apk_file']
    
    # 检查文件大小
    file.seek(0, 2)  # 移动到文件末尾
    file_size = file.tell()
    file.seek(0)  # 移回文件开头
    
    if file_size > app.config['MAX_CONTENT_LENGTH']:
        return jsonify({'success': False, 'message': '文件太大，最大支持500MB'})
    
    success, message = handle_apk_upload(file)
    
    if success:
        return jsonify({
            'success': True,
            'message': message,
            'redirect': url_for('index')
        })
    else:
        return jsonify({'success': False, 'message': message})

@app.route('/download-apk')
@login_required
@first_login_required
def download_apk():
    """下载当前APK文件"""
    target_path = '/usr/share/nginx/html/3.0.apk'
    
    if os.path.exists(target_path):
        return send_file(target_path, as_attachment=True, download_name='3.0.apk')
    else:
        return jsonify({'success': False, 'message': 'APK文件不存在'})

@app.route('/profile')
@login_required
@first_login_required
def profile():
    """用户个人资料页面"""
    username = session.get('username')
    user = user_manager.get_user(username)
    
    if user:
        # 格式化日期时间
        created_at = user.get('created_at', '未知')
        last_login = user.get('last_login', '从未登录')
        last_password_change = user.get('last_password_change', '从未修改')
        
        # 尝试解析并格式化日期
        try:
            if created_at != '未知':
                created_at = datetime.fromisoformat(created_at).strftime('%Y-%m-%d %H:%M:%S')
        except:
            pass
        
        try:
            if last_login != '从未登录':
                last_login = datetime.fromisoformat(last_login).strftime('%Y-%m-%d %H:%M:%S')
        except:
            pass
        
        try:
            if last_password_change != '从未修改':
                last_password_change = datetime.fromisoformat(last_password_change).strftime('%Y-%m-%d %H:%M:%S')
        except:
            pass
        
        user_info = {
            'username': user.get('username', '未知'),
            'created_at': created_at,
            'last_login': last_login,
            'last_password_change': last_password_change,
            'password_history_count': len(user.get('password_history', []))
        }
        
        return render_template('profile.html', user=user_info)
    
    return redirect(url_for('index'))

# 创建HTML模板
def create_templates():
    """创建HTML模板文件"""
    templates_dir = os.path.join(os.path.dirname(__file__), 'templates')
    
    # 创建目录
    os.makedirs(templates_dir, exist_ok=True)
    
    # 登录页面模板
    login_html = '''
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>90APT管理面板 - 登录</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        
        body {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
        }
        
        .login-container {
            background-color: white;
            padding: 40px;
            border-radius: 10px;
            box-shadow: 0 15px 30px rgba(0, 0, 0, 0.2);
            width: 100%;
            max-width: 400px;
        }
        
        .login-header {
            text-align: center;
            margin-bottom: 30px;
        }
        
        .login-header h1 {
            color: #333;
            font-size: 28px;
            margin-bottom: 10px;
        }
        
        .login-header p {
            color: #666;
            font-size: 14px;
        }
        
        .form-group {
            margin-bottom: 20px;
        }
        
        .form-group label {
            display: block;
            margin-bottom: 5px;
            color: #555;
            font-weight: 500;
        }
        
        .form-group input {
            width: 100%;
            padding: 12px 15px;
            border: 1px solid #ddd;
            border-radius: 5px;
            font-size: 16px;
            transition: border-color 0.3s;
        }
        
        .form-group input:focus {
            border-color: #667eea;
            outline: none;
        }
        
        .btn-login {
            width: 100%;
            padding: 14px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 5px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s;
        }
        
        .btn-login:hover {
            transform: translateY(-2px);
        }
        
        .btn-login:active {
            transform: translateY(0);
        }
        
        .error-message {
            background-color: #ffebee;
            color: #c62828;
            padding: 10px;
            border-radius: 5px;
            margin-bottom: 20px;
            text-align: center;
            font-size: 14px;
        }
        
        .info-message {
            background-color: #e3f2fd;
            color: #1565c0;
            padding: 10px;
            border-radius: 5px;
            margin-bottom: 20px;
            text-align: center;
            font-size: 14px;
        }
        
        .login-footer {
            text-align: center;
            margin-top: 20px;
            color: #666;
            font-size: 14px;
        }
        
        .login-footer a {
            color: #667eea;
            text-decoration: none;
        }
        
        @media (max-width: 480px) {
            .login-container {
                padding: 30px 20px;
                margin: 20px;
            }
        }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="login-header">
            <h1>90APT管理面板</h1>
            <p>请输入账号密码登录系统</p>
        </div>
        
        {% if error %}
        <div class="error-message">
            {{ error }}
        </div>
        {% endif %}
        
        <div class="info-message">
            <p>首次登录需要修改默认密码</p>
            <p>默认账号: <strong>admin</strong> 密码: <strong>admin</strong></p>
        </div>
        
        <form method="POST" action="/login">
            <div class="form-group">
                <label for="username">账号</label>
                <input type="text" id="username" name="username" placeholder="请输入账号" required>
            </div>
            
            <div class="form-group">
                <label for="password">密码</label>
                <input type="password" id="password" name="password" placeholder="请输入密码" required>
            </div>
            
            <button type="submit" class="btn-login">登录</button>
        </form>
        
        <div class="login-footer">
            <p>&copy; 2025 90APT管理面板</p>
        </div>
    </div>
</body>
</html>
'''
    
    # 修改密码页面模板
    change_password_html = '''
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>修改密码 - 90APT管理面板</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        
        body {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
        }
        
        .password-container {
            background-color: white;
            padding: 40px;
            border-radius: 10px;
            box-shadow: 0 15px 30px rgba(0, 0, 0, 0.2);
            width: 100%;
            max-width: 500px;
        }
        
        .password-header {
            text-align: center;
            margin-bottom: 30px;
        }
        
        .password-header h1 {
            color: #333;
            font-size: 28px;
            margin-bottom: 10px;
        }
        
        .password-header p {
            color: #666;
            font-size: 16px;
            line-height: 1.5;
        }
        
        .requirements {
            background-color: #f5f7fa;
            border-left: 4px solid #667eea;
            padding: 15px;
            margin-bottom: 25px;
            border-radius: 0 5px 5px 0;
        }
        
        .requirements h3 {
            color: #333;
            margin-bottom: 10px;
            font-size: 16px;
        }
        
        .requirements ul {
            color: #555;
            padding-left: 20px;
            font-size: 14px;
        }
        
        .requirements li {
            margin-bottom: 5px;
        }
        
        .requirements li.strong {
            color: #4caf50;
        }
        
        .requirements li.weak {
            color: #f44336;
        }
        
        .form-group {
            margin-bottom: 20px;
        }
        
        .form-group label {
            display: block;
            margin-bottom: 5px;
            color: #555;
            font-weight: 500;
        }
        
        .form-group input {
            width: 100%;
            padding: 12px 15px;
            border: 1px solid #ddd;
            border-radius: 5px;
            font-size: 16px;
            transition: border-color 0.3s;
        }
        
        .form-group input:focus {
            border-color: #667eea;
            outline: none;
        }
        
        .password-strength {
            height: 5px;
            margin-top: 5px;
            border-radius: 5px;
            background-color: #eee;
            overflow: hidden;
        }
        
        .password-strength-meter {
            height: 100%;
            width: 0%;
            transition: width 0.3s, background-color 0.3s;
        }
        
        .btn-submit {
            width: 100%;
            padding: 14px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 5px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s;
            margin-top: 10px;
        }
        
        .btn-submit:hover {
            transform: translateY(-2px);
        }
        
        .btn-submit:active {
            transform: translateY(0);
        }
        
        .btn-back {
            width: 100%;
            padding: 10px;
            background-color: #f5f7fa;
            color: #666;
            border: 1px solid #ddd;
            border-radius: 5px;
            font-size: 14px;
            font-weight: 500;
            cursor: pointer;
            transition: background-color 0.3s;
            margin-top: 15px;
        }
        
        .btn-back:hover {
            background-color: #e9ecef;
        }
        
        .error-message {
            background-color: #ffebee;
            color: #c62828;
            padding: 10px;
            border-radius: 5px;
            margin-bottom: 20px;
            text-align: center;
            font-size: 14px;
        }
        
        .success-message {
            background-color: #e8f5e9;
            color: #2e7d32;
            padding: 10px;
            border-radius: 5px;
            margin-bottom: 20px;
            text-align: center;
            font-size: 14px;
        }
        
        @media (max-width: 480px) {
            .password-container {
                padding: 30px 20px;
                margin: 20px;
            }
        }
    </style>
</head>
<body>
    <div class="password-container">
        <div class="password-header">
            <h1>修改密码</h1>
            <p>首次登录需要修改默认密码。请设置一个强密码以确保账户安全。</p>
        </div>
        
        {% if error %}
        <div class="error-message">
            {{ error }}
        </div>
        {% endif %}
        
        <div class="requirements">
            <h3>密码要求：</h3>
            <ul>
                <li>至少8个字符</li>
                <li>至少包含一个大写字母</li>
                <li>至少包含一个小写字母</li>
                <li>至少包含一个数字</li>
                <li>至少包含一个特殊字符 (!@#$%^&*()_+-=[]{}|;:,.<>?)</li>
                <li>不能使用最近使用过的密码</li>
            </ul>
        </div>
        
        <form method="POST" action="/change-password" id="passwordForm">
            <div class="form-group">
                <label for="current_password">当前密码</label>
                <input type="password" id="current_password" name="current_password" placeholder="请输入当前密码" required>
            </div>
            
            <div class="form-group">
                <label for="new_password">新密码</label>
                <input type="password" id="new_password" name="new_password" placeholder="请输入新密码" required>
                <div class="password-strength">
                    <div class="password-strength-meter" id="passwordStrength"></div>
                </div>
            </div>
            
            <div class="form-group">
                <label for="confirm_password">确认新密码</label>
                <input type="password" id="confirm_password" name="confirm_password" placeholder="请再次输入新密码" required>
            </div>
            
            <button type="submit" class="btn-submit">修改密码</button>
        </form>
        
        <form method="GET" action="/logout">
            <button type="submit" class="btn-back">返回登录</button>
        </form>
    </div>
    
    <script>
        // 密码强度检查
        document.getElementById('new_password').addEventListener('input', function() {
            var password = this.value;
            var strengthMeter = document.getElementById('passwordStrength');
            var strength = 0;
            
            // 长度检查
            if (password.length >= 8) strength += 20;
            
            // 包含大写字母
            if (/[A-Z]/.test(password)) strength += 20;
            
            // 包含小写字母
            if (/[a-z]/.test(password)) strength += 20;
            
            // 包含数字
            if (/[0-9]/.test(password)) strength += 20;
            
            // 包含特殊字符
            if (/[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]/.test(password)) strength += 20;
            
            // 更新强度条
            strengthMeter.style.width = strength + '%';
            
            // 根据强度设置颜色
            if (strength < 40) {
                strengthMeter.style.backgroundColor = '#f44336'; // 红色
            } else if (strength < 80) {
                strengthMeter.style.backgroundColor = '#ff9800'; // 橙色
            } else {
                strengthMeter.style.backgroundColor = '#4caf50'; // 绿色
            }
        });
        
        // 表单验证
        document.getElementById('passwordForm').addEventListener('submit', function(event) {
            var newPassword = document.getElementById('new_password').value;
            var confirmPassword = document.getElementById('confirm_password').value;
            
            // 检查密码是否一致
            if (newPassword !== confirmPassword) {
                alert('新密码和确认密码不一致！');
                event.preventDefault();
                return;
            }
            
            // 检查密码长度
            if (newPassword.length < 8) {
                alert('密码长度至少为8个字符！');
                event.preventDefault();
                return;
            }
            
            // 检查是否包含大写字母
            if (!/[A-Z]/.test(newPassword)) {
                alert('密码必须包含至少一个大写字母！');
                event.preventDefault();
                return;
            }
            
            // 检查是否包含小写字母
            if (!/[a-z]/.test(newPassword)) {
                alert('密码必须包含至少一个小写字母！');
                event.preventDefault();
                return;
            }
            
            // 检查是否包含数字
            if (!/[0-9]/.test(newPassword)) {
                alert('密码必须包含至少一个数字！');
                event.preventDefault();
                return;
            }
            
            // 检查是否包含特殊字符
            if (!/[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]/.test(newPassword)) {
                alert('密码必须包含至少一个特殊字符！');
                event.preventDefault();
                return;
            }
        });
    </script>
</body>
</html>
'''
    
    # 主页面模板
    index_html = '''
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>90APT管理面板</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        
        body {
            background-color: #f5f7fa;
            color: #333;
        }
        
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px 30px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
        }
        
        .header h1 {
            font-size: 24px;
            font-weight: 600;
        }
        
        .user-info {
            display: flex;
            align-items: center;
            gap: 15px;
        }
        
        .user-info span {
            font-weight: 500;
        }
        
        .user-menu {
            position: relative;
        }
        
        .user-menu-btn {
            background-color: rgba(255, 255, 255, 0.2);
            color: white;
            border: none;
            padding: 8px 16px;
            border-radius: 4px;
            cursor: pointer;
            font-weight: 500;
            transition: background-color 0.3s;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        
        .user-menu-btn:hover {
            background-color: rgba(255, 255, 255, 0.3);
        }
        
        .user-dropdown {
            position: absolute;
            top: 100%;
            right: 0;
            background-color: white;
            border-radius: 5px;
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.1);
            min-width: 180px;
            display: none;
            z-index: 1000;
            overflow: hidden;
        }
        
        .user-dropdown.show {
            display: block;
        }
        
        .user-dropdown a {
            display: block;
            padding: 12px 20px;
            color: #333;
            text-decoration: none;
            transition: background-color 0.3s;
        }
        
        .user-dropdown a:hover {
            background-color: #f5f7fa;
        }
        
        .user-dropdown a i {
            margin-right: 8px;
            width: 20px;
            text-align: center;
        }
        
        .container {
            max-width: 1200px;
            margin: 30px auto;
            padding: 0 20px;
        }
        
        .status-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 30px;
        }
        
        .status-header h2 {
            font-size: 22px;
            color: #444;
        }
        
        .btn-refresh {
            background-color: #667eea;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 5px;
            cursor: pointer;
            font-weight: 500;
            display: flex;
            align-items: center;
            gap: 8px;
            transition: background-color 0.3s;
        }
        
        .btn-refresh:hover {
            background-color: #5a6fd8;
        }
        
        .services-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(400px, 1fr));
            gap: 25px;
            margin-bottom: 40px;
        }
        
        .service-card {
            background-color: white;
            border-radius: 10px;
            padding: 25px;
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.05);
            transition: transform 0.3s, box-shadow 0.3s;
        }
        
        .service-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 8px 20px rgba(0, 0, 0, 0.1);
        }
        
        .service-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
        }
        
        .service-name {
            font-size: 20px;
            font-weight: 600;
            color: #333;
        }
        
        .service-status-container {
            display: flex;
            flex-direction: column;
            align-items: flex-end;
            gap: 5px;
        }
        
        .service-status {
            padding: 6px 12px;
            border-radius: 20px;
            font-size: 14px;
            font-weight: 500;
        }
        
        .status-running {
            background-color: #e8f5e9;
            color: #2e7d32;
        }
        
        .status-stopped {
            background-color: #ffebee;
            color: #c62828;
        }
        
        .status-unknown {
            background-color: #fff3e0;
            color: #ef6c00;
        }
        
        .startup-status {
            font-size: 12px;
            color: #666;
            display: flex;
            align-items: center;
            gap: 5px;
        }
        
        .startup-enabled {
            color: #2e7d32;
        }
        
        .startup-disabled {
            color: #c62828;
        }
        
        .service-description {
            color: #666;
            margin-bottom: 25px;
            line-height: 1.5;
        }
        
        .service-actions {
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
        }
        
        .btn-action {
            flex: 1;
            min-width: 80px;
            padding: 10px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-weight: 500;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
            transition: all 0.3s;
            font-size: 14px;
        }
        
        .btn-start {
            background-color: #4caf50;
            color: white;
        }
        
        .btn-start:hover {
            background-color: #43a047;
        }
        
        .btn-stop {
            background-color: #f44336;
            color: white;
        }
        
        .btn-stop:hover {
            background-color: #e53935;
        }
        
        .btn-restart {
            background-color: #ff9800;
            color: white;
        }
        
        .btn-restart:hover {
            background-color: #f57c00;
        }
        
        .btn-enable {
            background-color: #2196f3;
            color: white;
        }
        
        .btn-enable:hover {
            background-color: #0b7dda;
        }
        
        .btn-disable {
            background-color: #9c27b0;
            color: white;
        }
        
        .btn-disable:hover {
            background-color: #7b1fa2;
        }
        
        .btn-action:disabled {
            background-color: #e0e0e0;
            color: #9e9e9e;
            cursor: not-allowed;
        }
        
        .apk-upload-section {
            background-color: white;
            border-radius: 10px;
            padding: 25px;
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.05);
            margin-bottom: 40px;
        }
        
        .section-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
        }
        
        .section-header h2 {
            font-size: 22px;
            color: #444;
        }
        
        .apk-info {
            background-color: #f5f7fa;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        
        .apk-info p {
            margin-bottom: 8px;
            color: #555;
        }
        
        .apk-info strong {
            color: #333;
        }
        
        .file-upload-form {
            display: flex;
            flex-direction: column;
            gap: 15px;
        }
        
        .file-input-container {
            display: flex;
            gap: 10px;
            align-items: center;
        }
        
        .file-input-label {
            padding: 10px 15px;
            background-color: #e0e0e0;
            border-radius: 5px;
            cursor: pointer;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        
        .file-input-label:hover {
            background-color: #d5d5d5;
        }
        
        .file-input {
            display: none;
        }
        
        .file-name {
            color: #666;
            font-style: italic;
        }
        
        .btn-upload {
            padding: 12px 24px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 5px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 10px;
        }
        
        .btn-upload:hover {
            transform: translateY(-2px);
        }
        
        .btn-download {
            padding: 10px 20px;
            background-color: #4caf50;
            color: white;
            border: none;
            border-radius: 5px;
            font-size: 14px;
            font-weight: 500;
            cursor: pointer;
            transition: background-color 0.3s;
            display: flex;
            align-items: center;
            gap: 8px;
            text-decoration: none;
        }
        
        .btn-download:hover {
            background-color: #43a047;
        }
        
        .notification {
            position: fixed;
            top: 20px;
            right: 20px;
            padding: 15px 20px;
            border-radius: 5px;
            color: white;
            font-weight: 500;
            display: flex;
            align-items: center;
            gap: 10px;
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.1);
            z-index: 1000;
            transform: translateX(150%);
            transition: transform 0.5s;
        }
        
        .notification.show {
            transform: translateX(0);
        }
        
        .notification-success {
            background-color: #4caf50;
        }
        
        .notification-error {
            background-color: #f44336;
        }
        
        .notification-info {
            background-color: #2196f3;
        }
        
        .footer {
            text-align: center;
            margin-top: 40px;
            padding: 20px;
            color: #666;
            font-size: 14px;
            border-top: 1px solid #eee;
        }
        
        @media (max-width: 768px) {
            .services-grid {
                grid-template-columns: 1fr;
            }
            
            .header {
                flex-direction: column;
                gap: 15px;
                text-align: center;
            }
            
            .status-header {
                flex-direction: column;
                gap: 15px;
                align-items: flex-start;
            }
            
            .user-info {
                flex-direction: column;
                gap: 10px;
            }
            
            .service-actions {
                flex-direction: column;
            }
            
            .file-input-container {
                flex-direction: column;
                align-items: flex-start;
            }
        }
    </style>
</head>
<body>
    <div class="header">
        <h1><i class="fas fa-server"></i> 90APT管理面板</h1>
        <div class="user-info">
            <span>欢迎, {{ session.username }}</span>
            <div class="user-menu">
                <button class="user-menu-btn" id="userMenuBtn">
                    <i class="fas fa-user"></i> {{ session.username }}
                    <i class="fas fa-chevron-down"></i>
                </button>
                <div class="user-dropdown" id="userDropdown">
                    <a href="/profile"><i class="fas fa-id-card"></i> 个人资料</a>
                    <a href="#" onclick="showPasswordChangeModal()"><i class="fas fa-key"></i> 修改密码</a>
                    <a href="/logout"><i class="fas fa-sign-out-alt"></i> 退出登录</a>
                </div>
            </div>
        </div>
    </div>
    
    <div class="container">
        <div class="status-header">
            <h2><i class="fas fa-chart-bar"></i> 服务状态监控</h2>
            <button class="btn-refresh" id="refreshBtn">
                <i class="fas fa-sync-alt"></i> 刷新状态
            </button>
        </div>
        
        <div class="services-grid" id="servicesGrid">
            {% for service_id, service in services.items() %}
            <div class="service-card">
                <div class="service-header">
                    <div class="service-name">
                        {% if 'nginx' in service_id %}
                        <i class="fas fa-globe"></i>
                        {% elif 'named' in service_id %}
                        <i class="fas fa-network-wired"></i>
                        {% else %}
                        <i class="fas fa-cog"></i>
                        {% endif %}
                        {{ service.display_name }}
                    </div>
                    <div class="service-status-container">
                        <div class="service-status status-{{ service.run_status }}">
                            {% if service.run_status == 'running' %}
                            运行中
                            {% elif service.run_status == 'stopped' %}
                            已停止
                            {% else %}
                            未知状态
                            {% endif %}
                        </div>
                        <div class="startup-status">
                            <i class="fas fa-power-off"></i>
                            <span class="{% if service.startup_status == 'enabled' %}startup-enabled{% else %}startup-disabled{% endif %}">
                                {% if service.startup_status == 'enabled' %}
                                开机启动
                                {% elif service.startup_status == 'disabled' %}
                                禁止开机启动
                                {% elif service.startup_status == 'not-installed' %}
                                未安装
                                {% else %}
                                未知
                                {% endif %}
                            </span>
                        </div>
                    </div>
                </div>
                
                <div class="service-description">
                    {% if 'nginx' in service_id %}
                    Nginx是一个高性能的HTTP和反向代理web服务器。
                    {% elif 'named' in service_id %}
                    BIND (Berkeley Internet Name Domain) 是DNS协议的最常用实现软件。
                    {% else %}
                    系统服务
                    {% endif %}
                </div>
                
                <div class="service-actions">
                    <button class="btn-action btn-start" onclick="controlService('{{ service_id }}', 'start')" 
                            {% if service.run_status == 'running' %}disabled{% endif %}>
                        <i class="fas fa-play"></i> 启动
                    </button>
                    <button class="btn-action btn-stop" onclick="controlService('{{ service_id }}', 'stop')"
                            {% if service.run_status != 'running' %}disabled{% endif %}>
                        <i class="fas fa-stop"></i> 停止
                    </button>
                    <button class="btn-action btn-restart" onclick="controlService('{{ service_id }}', 'restart')"
                            {% if service.run_status != 'running' %}disabled{% endif %}>
                        <i class="fas fa-redo"></i> 重启
                    </button>
                    <button class="btn-action btn-enable" onclick="controlService('{{ service_id }}', 'enable')"
                            {% if service.startup_status == 'enabled' %}disabled{% endif %}>
                        <i class="fas fa-check-circle"></i> 开机启动
                    </button>
                    <button class="btn-action btn-disable" onclick="controlService('{{ service_id }}', 'disable')"
                            {% if service.startup_status != 'enabled' %}disabled{% endif %}>
                        <i class="fas fa-times-circle"></i> 禁止开机
                    </button>
                </div>
            </div>
            {% endfor %}
        </div>
        
        <div class="apk-upload-section">
            <div class="section-header">
                <h2><i class="fas fa-upload"></i> APK文件管理</h2>
                {% if apk_info.exists %}
                <a href="/download-apk" class="btn-download">
                    <i class="fas fa-download"></i> 下载当前APK
                </a>
                {% endif %}
            </div>
            
            <div class="apk-info">
                <p><strong>目标路径:</strong> {{ apk_info.path }}</p>
                {% if apk_info.exists %}
                <p><strong>文件大小:</strong> {{ (apk_info.size / 1024 / 1024) | round(2) }} MB</p>
                <p><strong>最后修改时间:</strong> {{ apk_info.modified_time }}</p>
                {% else %}
                <p><strong>状态:</strong> 文件不存在</p>
                {% endif %}
            </div>
            
            <form class="file-upload-form" id="apkUploadForm" enctype="multipart/form-data">
                <div class="file-input-container">
                    <label class="file-input-label">
                        <i class="fas fa-file"></i> 选择APK文件
                        <input type="file" class="file-input" id="apkFile" name="apk_file" accept=".apk" required>
                    </label>
                    <span class="file-name" id="fileName">未选择文件</span>
                </div>
                
                <button type="submit" class="btn-upload" id="uploadBtn">
                    <i class="fas fa-upload"></i> 上传并替换APK文件
                </button>
            </form>
        </div>
        
        <div class="footer">
            <p>90APT管理面板 v2.0 &copy; 2025 | 监听端口: 8888 | 支持服务控制和APK文件上传</p>
        </div>
    </div>
    
    <!-- 修改密码模态框 -->
    <div id="passwordChangeModal" style="display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background-color: rgba(0,0,0,0.5); z-index: 2000; justify-content: center; align-items: center;">
        <div style="background-color: white; padding: 30px; border-radius: 10px; width: 90%; max-width: 500px; max-height: 90vh; overflow-y: auto;">
            <h2 style="margin-bottom: 20px; color: #333;">修改密码</h2>
            <div style="margin-bottom: 20px; color: #666;">
                <p>密码要求：至少8个字符，包含大小写字母、数字和特殊字符。</p>
            </div>
            <form id="passwordChangeForm">
                <div style="margin-bottom: 15px;">
                    <label style="display: block; margin-bottom: 5px; color: #555;">当前密码</label>
                    <input type="password" id="modalCurrentPassword" style="width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 5px;" required>
                </div>
                <div style="margin-bottom: 15px;">
                    <label style="display: block; margin-bottom: 5px; color: #555;">新密码</label>
                    <input type="password" id="modalNewPassword" style="width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 5px;" required>
                </div>
                <div style="margin-bottom: 25px;">
                    <label style="display: block; margin-bottom: 5px; color: #555;">确认新密码</label>
                    <input type="password" id="modalConfirmPassword" style="width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 5px;" required>
                </div>
                <div style="display: flex; gap: 10px;">
                    <button type="button" onclick="hidePasswordChangeModal()" style="flex: 1; padding: 10px; background-color: #f5f7fa; color: #666; border: 1px solid #ddd; border-radius: 5px; cursor: pointer;">取消</button>
                    <button type="submit" style="flex: 1; padding: 10px; background-color: #667eea; color: white; border: none; border-radius: 5px; cursor: pointer;">确认修改</button>
                </div>
            </form>
        </div>
    </div>
    
    <div class="notification" id="notification"></div>
    
    <script>
        // 用户菜单
        document.getElementById('userMenuBtn').addEventListener('click', function() {
            document.getElementById('userDropdown').classList.toggle('show');
        });
        
        // 点击页面其他位置关闭用户菜单
        document.addEventListener('click', function(event) {
            var userMenu = document.getElementById('userMenuBtn');
            var dropdown = document.getElementById('userDropdown');
            
            if (!userMenu.contains(event.target) && !dropdown.contains(event.target)) {
                dropdown.classList.remove('show');
            }
        });
        
        // 刷新服务状态
        document.getElementById('refreshBtn').addEventListener('click', refreshStatus);
        
        function refreshStatus() {
            const refreshBtn = document.getElementById('refreshBtn');
            refreshBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> 刷新中...';
            refreshBtn.disabled = true;
            
            fetch('/api/service/status')
                .then(response => response.json())
                .then(data => {
                    updateServicesGrid(data);
                    showNotification('状态已更新', 'success');
                })
                .catch(error => {
                    console.error('刷新状态失败:', error);
                    showNotification('刷新状态失败', 'error');
                })
                .finally(() => {
                    setTimeout(() => {
                        refreshBtn.innerHTML = '<i class="fas fa-sync-alt"></i> 刷新状态';
                        refreshBtn.disabled = false;
                    }, 500);
                });
        }
        
        // 控制服务
        function controlService(service, action) {
            const button = event.target;
            const originalText = button.innerHTML;
            
            button.innerHTML = '<i class="fas fa-spinner fa-spin"></i> 处理中...';
            button.disabled = true;
            
            fetch('/api/service/control', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({service, action})
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    updateServicesGrid(data.services);
                    showNotification(data.message, 'success');
                } else {
                    showNotification(data.message, 'error');
                }
            })
            .catch(error => {
                console.error('控制服务失败:', error);
                showNotification('操作失败: ' + error.message, 'error');
            })
            .finally(() => {
                setTimeout(() => {
                    button.innerHTML = originalText;
                    button.disabled = false;
                }, 1000);
            });
        }
        
        // 更新服务状态网格
        function updateServicesGrid(services) {
            // 简单实现：重新加载页面以更新状态
            location.reload();
        }
        
        // 显示通知
        function showNotification(message, type) {
            const notification = document.getElementById('notification');
            notification.textContent = message;
            notification.className = 'notification';
            
            if (type === 'success') {
                notification.classList.add('notification-success');
                notification.innerHTML = `<i class="fas fa-check-circle"></i> ${message}`;
            } else if (type === 'error') {
                notification.classList.add('notification-error');
                notification.innerHTML = `<i class="fas fa-exclamation-circle"></i> ${message}`;
            } else {
                notification.classList.add('notification-info');
                notification.innerHTML = `<i class="fas fa-info-circle"></i> ${message}`;
            }
            
            notification.classList.add('show');
            
            setTimeout(() => {
                notification.classList.remove('show');
            }, 3000);
        }
        
        // 显示修改密码模态框
        function showPasswordChangeModal() {
            document.getElementById('passwordChangeModal').style.display = 'flex';
            document.getElementById('userDropdown').classList.remove('show');
        }
        
        // 隐藏修改密码模态框
        function hidePasswordChangeModal() {
            document.getElementById('passwordChangeModal').style.display = 'none';
            document.getElementById('passwordChangeForm').reset();
        }
        
        // 处理修改密码表单提交
        document.getElementById('passwordChangeForm').addEventListener('submit', function(event) {
            event.preventDefault();
            
            const currentPassword = document.getElementById('modalCurrentPassword').value;
            const newPassword = document.getElementById('modalNewPassword').value;
            const confirmPassword = document.getElementById('modalConfirmPassword').value;
            
            // 基本验证
            if (newPassword !== confirmPassword) {
                showNotification('新密码和确认密码不一致', 'error');
                return;
            }
            
            if (newPassword.length < 8) {
                showNotification('密码长度至少为8个字符', 'error');
                return;
            }
            
            // 发送密码修改请求
            fetch('/change-password', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: `current_password=${encodeURIComponent(currentPassword)}&new_password=${encodeURIComponent(newPassword)}&confirm_password=${encodeURIComponent(confirmPassword)}`
            })
            .then(response => {
                if (response.redirected) {
                    window.location.href = response.url;
                } else {
                    return response.text();
                }
            })
            .then(text => {
                if (text) {
                    // 如果响应是HTML，说明有错误
                    const parser = new DOMParser();
                    const doc = parser.parseFromString(text, 'text/html');
                    const errorElement = doc.querySelector('.error-message');
                    
                    if (errorElement) {
                        showNotification(errorElement.textContent, 'error');
                    }
                }
            })
            .catch(error => {
                console.error('修改密码失败:', error);
                showNotification('修改密码失败: ' + error.message, 'error');
            });
        });
        
        // 文件选择处理
        document.getElementById('apkFile').addEventListener('change', function() {
            const fileName = this.files[0] ? this.files[0].name : '未选择文件';
            document.getElementById('fileName').textContent = fileName;
            
            // 检查文件大小
            if (this.files[0]) {
                const fileSize = this.files[0].size;
                const maxSize = 500 * 1024 * 1024; // 500MB
                
                if (fileSize > maxSize) {
                    showNotification('文件太大，最大支持500MB', 'error');
                    this.value = '';
                    document.getElementById('fileName').textContent = '未选择文件';
                }
            }
        });
        
        // APK上传表单处理
        document.getElementById('apkUploadForm').addEventListener('submit', function(event) {
            event.preventDefault();
            
            const fileInput = document.getElementById('apkFile');
            const uploadBtn = document.getElementById('uploadBtn');
            
            if (!fileInput.files[0]) {
                showNotification('请选择APK文件', 'error');
                return;
            }
            
            // 检查文件扩展名
            const fileName = fileInput.files[0].name;
            if (!fileName.toLowerCase().endsWith('.apk')) {
                showNotification('只允许上传APK文件', 'error');
                return;
            }
            
            const formData = new FormData();
            formData.append('apk_file', fileInput.files[0]);
            
            uploadBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> 上传中...';
            uploadBtn.disabled = true;
            
            fetch('/upload-apk', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showNotification(data.message, 'success');
                    if (data.redirect) {
                        setTimeout(() => {
                            window.location.href = data.redirect;
                        }, 1500);
                    }
                } else {
                    showNotification(data.message, 'error');
                }
            })
            .catch(error => {
                console.error('上传失败:', error);
                showNotification('上传失败: ' + error.message, 'error');
            })
            .finally(() => {
                setTimeout(() => {
                    uploadBtn.innerHTML = '<i class="fas fa-upload"></i> 上传并替换APK文件';
                    uploadBtn.disabled = false;
                }, 1000);
            });
        });
        
        // 页面加载时每300秒自动刷新状态
        window.addEventListener('load', function() {
            setTimeout(refreshStatus, 300000);
        });
        
        // 每300秒自动刷新状态
        setInterval(refreshStatus, 300000);
        
        // 点击模态框背景关闭模态框
        document.getElementById('passwordChangeModal').addEventListener('click', function(event) {
            if (event.target === this) {
                hidePasswordChangeModal();
            }
        });
    </script>
</body>
</html>
'''
    
    # 个人资料页面模板
    profile_html = '''
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>个人资料 - 90APT管理面板</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        
        body {
            background-color: #f5f7fa;
            color: #333;
        }
        
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px 30px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
        }
        
        .header h1 {
            font-size: 24px;
            font-weight: 600;
        }
        
        .header-actions {
            display: flex;
            gap: 10px;
        }
        
        .btn-back {
            background-color: rgba(255, 255, 255, 0.2);
            color: white;
            border: none;
            padding: 8px 16px;
            border-radius: 4px;
            cursor: pointer;
            font-weight: 500;
            transition: background-color 0.3s;
            display: flex;
            align-items: center;
            gap: 8px;
            text-decoration: none;
        }
        
        .btn-back:hover {
            background-color: rgba(255, 255, 255, 0.3);
        }
        
        .container {
            max-width: 800px;
            margin: 30px auto;
            padding: 0 20px;
        }
        
        .profile-card {
            background-color: white;
            border-radius: 10px;
            padding: 30px;
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.05);
        }
        
        .profile-header {
            display: flex;
            align-items: center;
            margin-bottom: 30px;
            padding-bottom: 20px;
            border-bottom: 1px solid #eee;
        }
        
        .profile-avatar {
            width: 80px;
            height: 80px;
            border-radius: 50%;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            display: flex;
            align-items: center;
            justify-content: center;
            margin-right: 20px;
            font-size: 36px;
            color: white;
        }
        
        .profile-info h2 {
            font-size: 24px;
            color: #333;
            margin-bottom: 5px;
        }
        
        .profile-info p {
            color: #666;
            font-size: 16px;
        }
        
        .profile-details {
            margin-bottom: 30px;
        }
        
        .detail-row {
            display: flex;
            margin-bottom: 15px;
            padding-bottom: 15px;
            border-bottom: 1px solid #f5f7fa;
        }
        
        .detail-label {
            width: 200px;
            font-weight: 600;
            color: #555;
        }
        
        .detail-value {
            flex: 1;
            color: #333;
        }
        
        .password-history {
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #eee;
        }
        
        .password-history h3 {
            font-size: 18px;
            color: #333;
            margin-bottom: 15px;
        }
        
        .history-item {
            background-color: #f9f9f9;
            padding: 12px 15px;
            border-radius: 5px;
            margin-bottom: 10px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .history-item span {
            color: #666;
        }
        
        .history-count {
            background-color: #667eea;
            color: white;
            padding: 3px 10px;
            border-radius: 20px;
            font-size: 14px;
        }
        
        .footer {
            text-align: center;
            margin-top: 40px;
            padding: 20px;
            color: #666;
            font-size: 14px;
            border-top: 1px solid #eee;
        }
        
        @media (max-width: 768px) {
            .profile-header {
                flex-direction: column;
                text-align: center;
            }
            
            .profile-avatar {
                margin-right = 0;
                margin-bottom: 15px;
            }
            
            .detail-row {
                flex-direction: column;
            }
            
            .detail-label {
                width: 100%;
                margin-bottom: 5px;
            }
            
            .header {
                flex-direction: column;
                gap: 15px;
            }
            
            .header-actions {
                width: 100%;
                justify-content: center;
            }
        }
    </style>
</head>
<body>
    <div class="header">
        <h1><i class="fas fa-server"></i> 90APT管理面板</h1>
        <div class="header-actions">
            <a href="/" class="btn-back"><i class="fas fa-arrow-left"></i> 返回控制面板</a>
            <a href="/logout" class="btn-back"><i class="fas fa-sign-out-alt"></i> 退出登录</a>
        </div>
    </div>
    
    <div class="container">
        <div class="profile-card">
            <div class="profile-header">
                <div class="profile-avatar">
                    <i class="fas fa-user"></i>
                </div>
                <div class="profile-info">
                    <h2>{{ user.username }}</h2>
                    <p>系统管理员</p>
                </div>
            </div>
            
            <div class="profile-details">
                <div class="detail-row">
                    <div class="detail-label">用户名</div>
                    <div class="detail-value">{{ user.username }}</div>
                </div>
                
                <div class="detail-row">
                    <div class="detail-label">账户创建时间</div>
                    <div class="detail-value">{{ user.created_at }}</div>
                </div>
                
                <div class="detail-row">
                    <div class="detail-label">最后登录时间</div>
                    <div class="detail-value">{{ user.last_login }}</div>
                </div>
                
                <div class="detail-row">
                    <div class="detail-label">最后密码修改时间</div>
                    <div class="detail-value">{{ user.last_password_change }}</div>
                </div>
            </div>
            
            <div class="password-history">
                <h3>密码历史记录</h3>
                <div class="history-item">
                    <span>已保存的历史密码数量</span>
                    <span class="history-count">{{ user.password_history_count }}</span>
                </div>
                <p style="color: #666; font-size: 14px; margin-top: 10px;">
                    系统会保存最近使用过的3个密码，以防止您重复使用旧密码。
                </p>
            </div>
        </div>
        
        <div class="footer">
            <p>90APT服务管理面板 v2.0 &copy; 2025 | 支持服务控制和APK文件上传</p>
        </div>
    </div>
</body>
</html>
'''
    
    # 写入模板文件
    with open(os.path.join(templates_dir, 'login.html'), 'w', encoding='utf-8') as f:
        f.write(login_html)
    
    with open(os.path.join(templates_dir, 'change_password.html'), 'w', encoding='utf-8') as f:
        f.write(change_password_html)
    
    with open(os.path.join(templates_dir, 'index.html'), 'w', encoding='utf-8') as f:
        f.write(index_html)
    
    with open(os.path.join(templates_dir, 'profile.html'), 'w', encoding='utf-8') as f:
        f.write(profile_html)
    
    print("模板文件已创建")

def create_upload_folder():
    """创建上传文件夹"""
    upload_dir = app.config['UPLOAD_FOLDER']
    if not os.path.exists(upload_dir):
        os.makedirs(upload_dir)
        print(f"创建上传目录: {upload_dir}")

if __name__ == '__main__':
    # 创建模板文件
    create_templates()
    
    # 创建上传文件夹
    create_upload_folder()
    
    # 启动Flask应用
    print("服务管理面板启动中...")
    print("访问地址: http://localhost:8888")
    print("初始登录账号: admin 密码: admin")
    print("首次登录将强制要求修改密码")
    print("支持服务: nginx, bind (named)")
    print("支持操作: 启动、停止、重启、允许开机启动、禁止开机启动")
    print("APK文件上传: 将替换 /usr/share/nginx/html/3.0.apk")
    print("按 Ctrl+C 停止服务")
    
    # 设置模板文件夹
    app.template_folder = 'templates'
    
    # 运行应用
    app.run(host='0.0.0.0', port=8888, debug=True)
