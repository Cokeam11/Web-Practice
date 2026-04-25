const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const pool = require('./db');
const { createToken, verifyToken } = require('./jwt');

// 成功响应
function success(res, data = {}, msg = '操作成功', code = 200) {
  res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify({ code, msg, data }));
}

// 失败响应
function fail(res, msg = '操作失败', code = 400) {
  res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify({ code, msg }));
}

// 解析POST请求体
async function parseBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => {
      try {
        resolve(body ? JSON.parse(body) : {});
      } catch (err) {
        reject(err);
      }
    });
    req.on('error', reject);
  });
}

// 验证登录状态
function checkAuth(req) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return null;
  return verifyToken(token);
}

// 静态文件服务
function serveStatic(req, res) {
  let urlPath = req.url.split('?')[0].split('#')[0];
  if (urlPath === '/') urlPath = '/pages/login.html';

  const relPath = decodeURIComponent(urlPath.replace(/^\/+/, ''));
  const publicDir = path.join(__dirname, '..', 'public');
  const safePath = path.resolve(publicDir, relPath);

  console.log('静态请求:', req.method, req.url, '=>', safePath);

  if (!safePath.startsWith(publicDir + path.sep) && safePath !== publicDir) {
    res.writeHead(403, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('403 Forbidden');
    return;
  }

  const ext = path.extname(safePath).toLowerCase();
  const mimeMap = {
    '.html': 'text/html; charset=utf-8',
    '.css': 'text/css; charset=utf-8',
    '.js': 'application/javascript; charset=utf-8',
    '.json': 'application/json; charset=utf-8',
    '.png': 'image/png',
    '.jpg': 'image/jpeg',
    '.jpeg': 'image/jpeg',
    '.gif': 'image/gif',
    '.svg': 'image/svg+xml',
    '.ico': 'image/x-icon'
  };

  fs.readFile(safePath, (err, data) => {
    if (err) {
      console.error('静态文件读取失败:', safePath, err.message);
      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('404 Not Found');
      return;
    }
    res.writeHead(200, { 'Content-Type': mimeMap[ext] || 'application/octet-stream' });
    res.end(data);
  });
}

// 创建服务器
const server = http.createServer(async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  try {
    const urlObj = new URL(req.url, `http://${req.headers.host}`);
    const pathname = urlObj.pathname;
    const searchParams = urlObj.searchParams;

    // =========================
    // 静态文件
    // =========================
    if (!pathname.startsWith('/api')) {
      serveStatic(req, res);
      return;
    }

    // =========================
    // 登录
    // =========================
    if (req.method === 'POST' && pathname === '/api/login') {
      const { username, password } = await parseBody(req);

      if (!username || !password) {
        return fail(res, '用户名或密码不能为空');
      }

      const [users] = await pool.query(
        'SELECT * FROM users WHERE username = ?',
        [username]
      );

      if (users.length === 0) {
        return fail(res, '用户不存在');
      }

      const user = users[0];

      const hashedPassword = crypto
        .createHash('sha256')
        .update(password)
        .digest('hex');

      console.log('====== 登录调试 ======');
      console.log('username:', username);
      console.log('password:', password);
      console.log('hashedPassword:', hashedPassword);
      console.log('dbPassword:', user.password);
      console.log('equal:', user.password === hashedPassword);
      console.log('=====================');

      if (user.password !== hashedPassword) {
        return fail(res, '密码错误');
      }

      const token = createToken(user);

      return success(res, {
        token,
        user: {
          id: user.id,
          username: user.username,
          role: user.role,
          classId: user.class_id
        }
      }, '登录成功');
    }

    // =========================
    // 验证登录状态
    // =========================
    const userInfo = checkAuth(req);
    if (!userInfo) {
      return fail(res, '请先登录', 401);
    }

    // =========================
    // 获取班级列表
    // =========================
    if (req.method === 'GET' && pathname === '/api/classes') {
      const [classes] = await pool.query('SELECT * FROM classes');
      return success(res, classes);
    }

    // =========================
    // 获取成绩列表
    // =========================
    if (req.method === 'GET' && pathname === '/api/scores') {
      let sql = `
        SELECT
          s.id,
          s.student_id,
          s.class_id,
          u.username AS studentName,
          s.subject,
          s.score,
          s.exam_name,
          s.created_at,
          s.updated_at
        FROM scores s
        LEFT JOIN users u ON s.student_id = u.id
        WHERE 1 = 1
      `;
      const params = [];

      const classId = searchParams.get('classId');
      const subject = searchParams.get('subject');
      const studentId = searchParams.get('studentId');

      if (classId) {
        sql += ' AND s.class_id = ?';
        params.push(classId);
      }

      if (subject) {
        sql += ' AND s.subject LIKE ?';
        params.push(`%${subject}%`);
      }

      if (studentId) {
        sql += ' AND s.student_id = ?';
        params.push(studentId);
      }

      // 学生只能看自己的成绩
      if (userInfo.role === 'student') {
        sql += ' AND s.student_id = ?';
        params.push(userInfo.id);
      }

      // 教师如果绑定了班级，只看自己班级
      if (userInfo.role === 'teacher' && userInfo.class_id) {
        sql += ' AND s.class_id = ?';
        params.push(userInfo.class_id);
      }

      sql += ' ORDER BY s.updated_at DESC, s.id DESC';

      const [scores] = await pool.query(sql, params);
      return success(res, scores);
    }

    // =========================
    // 添加成绩
    // =========================
    if (req.method === 'POST' && pathname === '/api/score') {
      if (userInfo.role === 'student') {
        return fail(res, '无权限操作', 403);
      }

      const { student_id, class_id, subject, score, exam_name } = await parseBody(req);

      if (!student_id || !class_id || !subject || score === undefined || score === null || !exam_name) {
        return fail(res, '请填写完整信息');
      }

      const scoreNum = Number(score);
      if (Number.isNaN(scoreNum) || scoreNum < 0 || scoreNum > 100) {
        return fail(res, '成绩必须在 0 到 100 之间');
      }

      // 教师只能操作自己班级
      if (userInfo.role === 'teacher' && userInfo.class_id && Number(class_id) !== Number(userInfo.class_id)) {
        return fail(res, '只能操作自己班级的成绩', 403);
      }

      await pool.query(
        `
        INSERT INTO scores (student_id, class_id, subject, score, exam_name, created_by)
        VALUES (?, ?, ?, ?, ?, ?)
        `,
        [student_id, class_id, subject, scoreNum, exam_name, userInfo.id]
      );

      return success(res, {}, '添加成绩成功');
    }

    // =========================
    // 编辑成绩
    // =========================
    if (req.method === 'PUT' && pathname === '/api/score') {
      if (userInfo.role === 'student') {
        return fail(res, '无权限操作', 403);
      }

      const { id, student_id, class_id, subject, score, exam_name } = await parseBody(req);

      if (!id) {
        return fail(res, '成绩ID不能为空');
      }

      if (!student_id || !class_id || !subject || score === undefined || score === null || !exam_name) {
        return fail(res, '请填写完整信息');
      }

      const scoreNum = Number(score);
      if (Number.isNaN(scoreNum) || scoreNum < 0 || scoreNum > 100) {
        return fail(res, '成绩必须在 0 到 100 之间');
      }

      const [rows] = await pool.query('SELECT * FROM scores WHERE id = ?', [id]);
      if (rows.length === 0) {
        return fail(res, '成绩不存在', 404);
      }

      const oldScore = rows[0];

      // 教师只能修改自己班级成绩
      if (userInfo.role === 'teacher' && userInfo.class_id && Number(oldScore.class_id) !== Number(userInfo.class_id)) {
        return fail(res, '只能操作自己班级的成绩', 403);
      }

      // 教师不能改成别的班级
      if (userInfo.role === 'teacher' && userInfo.class_id && Number(class_id) !== Number(userInfo.class_id)) {
        return fail(res, '只能操作自己班级的成绩', 403);
      }

      await pool.query(
        `
        UPDATE scores
        SET student_id = ?, class_id = ?, subject = ?, score = ?, exam_name = ?
        WHERE id = ?
        `,
        [student_id, class_id, subject, scoreNum, exam_name, id]
      );

      return success(res, {}, '编辑成绩成功');
    }

    // =========================
    // 删除成绩
    // =========================
    if (req.method === 'DELETE' && pathname.startsWith('/api/score/')) {
      if (userInfo.role === 'student') {
        return fail(res, '无权限操作', 403);
      }

      const id = pathname.split('/').pop();
      if (!id) {
        return fail(res, '成绩ID不能为空');
      }

      const [rows] = await pool.query('SELECT * FROM scores WHERE id = ?', [id]);
      if (rows.length === 0) {
        return fail(res, '成绩不存在', 404);
      }

      const scoreRow = rows[0];

      // 教师只能删除自己班级
      if (userInfo.role === 'teacher' && userInfo.class_id && Number(scoreRow.class_id) !== Number(userInfo.class_id)) {
        return fail(res, '只能操作自己班级的成绩', 403);
      }

      await pool.query('DELETE FROM scores WHERE id = ?', [id]);
      return success(res, {}, '删除成绩成功');
    }

    // =========================
    // 获取通知列表
    // =========================
    if (req.method === 'GET' && pathname === '/api/notices') {
      const [notices] = await pool.query(`
        SELECT n.*, u.username as creatorName
        FROM notices n
        LEFT JOIN users u ON n.created_by = u.id
        ORDER BY n.created_at DESC
      `);
      return success(res, notices);
    }

    // =========================
    // 添加通知
    // =========================
    if (req.method === 'POST' && pathname === '/api/notice') {
      const { title, content, class_id } = await parseBody(req);

      if (!title || !content) {
        return fail(res, '标题和内容不能为空');
      }

      await pool.query(`
        INSERT INTO notices (title, content, class_id, created_by, created_at)
        VALUES (?, ?, ?, ?, NOW())
      `, [title, content, class_id || 0, userInfo.id]);

      return success(res, {}, '发布通知成功');
    }

    // =========================
    // 标记通知已读
    // =========================
    if (req.method === 'POST' && pathname === '/api/notice/read') {
      const { notice_id } = await parseBody(req);
      if (!notice_id) return fail(res, '通知ID不能为空');

      await pool.query(`
        INSERT IGNORE INTO notice_reads (notice_id, student_id, read_at)
        VALUES (?, ?, NOW())
      `, [notice_id, userInfo.id]);

      return success(res, {}, '标记已读成功');
    }

    return fail(res, '接口不存在', 404);

  } catch (error) {
    console.error('服务器错误：', error);
    return fail(res, '服务器内部错误', 500);
  }
});

// 启动服务器
const PORT = 3000;
server.listen(PORT, () => {
  console.log(`服务器运行在 http://localhost:${PORT}`);
});
