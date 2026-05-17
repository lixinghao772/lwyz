const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const db = require('./database');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'lwyz-community-secret-key-1952';
const ADMIN_KEY = 'LWYZ1952';

const storage = multer.memoryStorage();
const upload = multer({ storage, limits: { fileSize: 5 * 1024 * 1024 } });

app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

function auth(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: '未登录' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: '登录已过期' });
  }
}

// ========== Auth ==========
app.post('/api/register', (req, res) => {
  const { nickname, grade, department, class: cls, password, adminKey } = req.body;
  if (!nickname || !grade || !department || !cls || !password) {
    return res.status(400).json({ error: '请填写完整信息' });
  }
  const exists = db.prepare('SELECT id FROM users WHERE nickname = ?').get(nickname);
  if (exists) return res.status(400).json({ error: '昵称已被注册' });

  const hash = bcrypt.hashSync(password, 10);
  const isAdmin = adminKey === ADMIN_KEY ? 1 : 0;
  const result = db.prepare(`
    INSERT INTO users (nickname, grade, department, class, password, is_admin)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(nickname, grade, department, cls, hash, isAdmin);

  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(result.lastInsertRowid);
  const token = jwt.sign({ id: user.id, isAdmin: user.is_admin }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, user: sanitizeUser(user) });
});

app.post('/api/login', (req, res) => {
  const { nickname, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE nickname = ?').get(nickname);
  if (!user || !bcrypt.compareSync(password, user.password)) {
    return res.status(400).json({ error: '昵称或密码错误' });
  }
  const token = jwt.sign({ id: user.id, isAdmin: user.is_admin }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, user: sanitizeUser(user) });
});

app.get('/api/me', auth, (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  res.json(sanitizeUser(user));
});

app.post('/api/avatar', auth, upload.single('avatar'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: '请上传图片' });
  const base64 = 'data:' + req.file.mimetype + ';base64,' + req.file.buffer.toString('base64');
  db.prepare('UPDATE users SET avatar = ? WHERE id = ?').run(base64, req.user.id);
  res.json({ avatar: base64 });
});

// ========== Posts ==========
app.get('/api/posts', (req, res) => {
  const posts = db.prepare(`
    SELECT p.*, u.nickname, u.grade, u.department, u.class, u.avatar, u.is_admin
    FROM posts p
    JOIN users u ON p.user_id = u.id
    ORDER BY p.created_at DESC
  `).all();

  const result = posts.map(p => ({
    ...p,
    images: JSON.parse(p.images || '[]'),
    likes: db.prepare('SELECT COUNT(*) as count FROM likes WHERE post_id = ?').get(p.id).count,
    comments: db.prepare('SELECT COUNT(*) as count FROM comments WHERE post_id = ?').get(p.id).count,
    isLiked: req.headers.authorization ? 
      !!db.prepare('SELECT id FROM likes WHERE post_id = ? AND user_id = ?').get(p.id, jwt.verify(req.headers.authorization.replace('Bearer ', ''), JWT_SECRET).id)
      : false
  }));
  res.json(result);
});

app.get('/api/posts/search', (req, res) => {
  const q = req.query.q?.trim();
  if (!q) return res.json([]);
  const posts = db.prepare(`
    SELECT p.*, u.nickname, u.grade, u.department, u.class, u.avatar, u.is_admin
    FROM posts p
    JOIN users u ON p.user_id = u.id
    WHERE p.title LIKE ? OR p.content LIKE ? OR u.nickname LIKE ?
    ORDER BY p.created_at DESC
  `).all('%' + q + '%', '%' + q + '%', '%' + q + '%');

  res.json(posts.map(p => ({
    ...p,
    images: JSON.parse(p.images || '[]'),
    likes: db.prepare('SELECT COUNT(*) as count FROM likes WHERE post_id = ?').get(p.id).count,
    comments: db.prepare('SELECT COUNT(*) as count FROM comments WHERE post_id = ?').get(p.id).count,
    isLiked: req.headers.authorization ? 
      !!db.prepare('SELECT id FROM likes WHERE post_id = ? AND user_id = ?').get(p.id, jwt.verify(req.headers.authorization.replace('Bearer ', ''), JWT_SECRET).id)
      : false
  })));
});

app.get('/api/posts/:id', (req, res) => {
  const post = db.prepare(`
    SELECT p.*, u.nickname, u.grade, u.department, u.class, u.avatar, u.is_admin
    FROM posts p
    JOIN users u ON p.user_id = u.id
    WHERE p.id = ?
  `).get(req.params.id);
  if (!post) return res.status(404).json({ error: '帖子不存在' });

  post.images = JSON.parse(post.images || '[]');
  post.likes = db.prepare('SELECT COUNT(*) as count FROM likes WHERE post_id = ?').get(post.id).count;
  post.comments = db.prepare(`
    SELECT c.*, u.nickname, u.grade, u.department, u.class, u.avatar
    FROM comments c
    JOIN users u ON c.user_id = u.id
    WHERE c.post_id = ?
    ORDER BY c.created_at ASC
  `).all(post.id);
  res.json(post);
});

app.post('/api/posts', auth, (req, res) => {
  const { title, content, images = [] } = req.body;
  if (!title && !content) return res.status(400).json({ error: '内容不能为空' });
  const result = db.prepare(`
    INSERT INTO posts (user_id, title, content, images)
    VALUES (?, ?, ?, ?)
  `).run(req.user.id, title || content.slice(0, 20), content || title, JSON.stringify(images));
  const post = db.prepare('SELECT * FROM posts WHERE id = ?').get(result.lastInsertRowid);
  res.json(post);
});

app.delete('/api/posts/:id', auth, (req, res) => {
  const post = db.prepare('SELECT * FROM posts WHERE id = ?').get(req.params.id);
  if (!post) return res.status(404).json({ error: '帖子不存在' });
  if (post.user_id !== req.user.id && !req.user.isAdmin) {
    return res.status(403).json({ error: '无权删除' });
  }
  db.prepare('DELETE FROM posts WHERE id = ?').run(req.params.id);
  res.json({ success: true });
});

// ========== Comments ==========
app.post('/api/posts/:id/comments', auth, (req, res) => {
  const { content } = req.body;
  if (!content?.trim()) return res.status(400).json({ error: '评论不能为空' });
  const result = db.prepare(`
    INSERT INTO comments (post_id, user_id, content)
    VALUES (?, ?, ?)
  `).run(req.params.id, req.user.id, content.trim());
  const comment = db.prepare(`
    SELECT c.*, u.nickname, u.grade, u.department, u.class, u.avatar
    FROM comments c
    JOIN users u ON c.user_id = u.id
    WHERE c.id = ?
  `).get(result.lastInsertRowid);
  res.json(comment);
});

app.delete('/api/comments/:id', auth, (req, res) => {
  const comment = db.prepare('SELECT * FROM comments WHERE id = ?').get(req.params.id);
  if (!comment) return res.status(404).json({ error: '评论不存在' });
  if (comment.user_id !== req.user.id && !req.user.isAdmin) {
    return res.status(403).json({ error: '无权删除' });
  }
  db.prepare('DELETE FROM comments WHERE id = ?').run(req.params.id);
  res.json({ success: true });
});

// ========== Likes ==========
app.post('/api/posts/:id/like', auth, (req, res) => {
  const exists = db.prepare('SELECT id FROM likes WHERE post_id = ? AND user_id = ?').get(req.params.id, req.user.id);
  if (exists) {
    db.prepare('DELETE FROM likes WHERE post_id = ? AND user_id = ?').run(req.params.id, req.user.id);
    res.json({ liked: false });
  } else {
    db.prepare('INSERT INTO likes (post_id, user_id) VALUES (?, ?)').run(req.params.id, req.user.id);
    res.json({ liked: true });
  }
});

// ========== Messages / DM ==========
app.get('/api/messages', auth, (req, res) => {
  const msgs = db.prepare(`
    SELECT m.*, 
      uf.nickname as from_nickname, uf.avatar as from_avatar, uf.grade as from_grade, uf.department as from_department, uf.class as from_class,
      ut.nickname as to_nickname, ut.avatar as to_avatar, ut.grade as to_grade, ut.department as to_department, ut.class as to_class
    FROM messages m
    JOIN users uf ON m.from_user = uf.id
    JOIN users ut ON m.to_user = ut.id
    WHERE m.from_user = ? OR m.to_user = ?
    ORDER BY m.created_at ASC
  `).all(req.user.id, req.user.id);
  res.json(msgs);
});

app.get('/api/messages/unread', auth, (req, res) => {
  const count = db.prepare('SELECT COUNT(*) as count FROM messages WHERE to_user = ? AND read = 0').get(req.user.id);
  res.json(count);
});

app.get('/api/messages/:userId', auth, (req, res) => {
  const partnerId = parseInt(req.params.userId);
  // Mark as read
  db.prepare('UPDATE messages SET read = 1 WHERE from_user = ? AND to_user = ? AND read = 0').run(partnerId, req.user.id);
  const msgs = db.prepare(`
    SELECT m.*,
      uf.nickname as from_nickname, uf.avatar as from_avatar, uf.grade as from_grade, uf.department as from_department, uf.class as from_class,
      ut.nickname as to_nickname, ut.avatar as to_avatar, ut.grade as to_grade, ut.department as to_department, ut.class as to_class
    FROM messages m
    JOIN users uf ON m.from_user = uf.id
    JOIN users ut ON m.to_user = ut.id
    WHERE (m.from_user = ? AND m.to_user = ?) OR (m.from_user = ? AND m.to_user = ?)
    ORDER BY m.created_at ASC
  `).all(req.user.id, partnerId, partnerId, req.user.id);
  res.json(msgs);
});

app.post('/api/messages/:userId', auth, (req, res) => {
  const { content } = req.body;
  const toId = parseInt(req.params.userId);
  if (!content?.trim()) return res.status(400).json({ error: '消息不能为空' });
  const userExists = db.prepare('SELECT id FROM users WHERE id = ?').get(toId);
  if (!userExists) return res.status(404).json({ error: '用户不存在' });

  const result = db.prepare(`
    INSERT INTO messages (from_user, to_user, content)
    VALUES (?, ?, ?)
  `).run(req.user.id, toId, content.trim());

  const msg = db.prepare(`
    SELECT m.*,
      uf.nickname as from_nickname, uf.avatar as from_avatar, uf.grade as from_grade, uf.department as from_department, uf.class as from_class,
      ut.nickname as to_nickname, ut.avatar as to_avatar, ut.grade as to_grade, ut.department as to_department, ut.class as to_class
    FROM messages m
    JOIN users uf ON m.from_user = uf.id
    JOIN users ut ON m.to_user = ut.id
    WHERE m.id = ?
  `).get(result.lastInsertRowid);
  res.json(msg);
});

// ========== Users Search (for DM) ==========
app.get('/api/users/search', auth, (req, res) => {
  const q = req.query.q?.trim() || '';
  const users = db.prepare(`
    SELECT id, nickname, grade, department, class, avatar
    FROM users
    WHERE id != ? AND (nickname LIKE ? OR grade LIKE ? OR class LIKE ?)
    LIMIT 50
  `).all(req.user.id, '%' + q + '%', '%' + q + '%', '%' + q + '%');
  res.json(users.map(sanitizeUser));
});

app.get('/api/users/:id', auth, (req, res) => {
  const user = db.prepare('SELECT id, nickname, grade, department, class, avatar, is_admin FROM users WHERE id = ?').get(req.params.id);
  if (!user) return res.status(404).json({ error: '用户不存在' });
  res.json(sanitizeUser(user));
});

// ========== Utils ==========
function sanitizeUser(user) {
  if (!user) return null;
  const { password, ...rest } = user;
  return rest;
}

app.listen(PORT, () => {
  console.log(`🚀 莱芜一中社区服务已启动: http://localhost:${PORT}`);
  console.log(`📁 请将前端 HTML 文件放入 public/index.html 以提供完整服务`);
});
