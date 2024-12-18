const express = require('express');
const path = require('path');
const fs = require('fs');
const fsPromises = require('fs').promises;
const toml = require('@iarna/toml');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const upload = multer({ dest: 'public/files/' });
const app = express();

// 设置模板引擎
app.set('view engine', 'ejs');

// 静态资源目录 - 仅供内部资源使用
const ASSETS_PATH = '/assets';
app.use(ASSETS_PATH, (req, res, next) => {
    // 允许访问 css、webfonts 目录、images 目录和 favicon.ico
    if (req.path.startsWith('/css/') || 
        req.path.startsWith('/webfonts/') || 
        req.path.startsWith('/images/') || 
        req.path === '/favicon.ico') {
        express.static(path.join(__dirname, 'public/assets'))(req, res, next);
    } else {
        res.status(403).send('禁止访问');
    }
});

// 文件浏览目录 - CDN文件存储位置
const STATIC_DIR = './public/files';

// 获取文件图标的函数
function getFileIcon(filename) {
  const ext = path.extname(filename).toLowerCase();
  const icons = {
    // 网页相关
    '.html': 'fab fa-html5',           // HTML5 标志
    '.css': 'fab fa-css3-alt',         // CSS3 标志
    '.js': 'fab fa-js-square',         // JavaScript 标志
    
    // 编程语言
    '.java': 'fab fa-java',            // Java 标志
    '.py': 'fab fa-python',            // Python 标志
    
    // 图片
    '.jpg': 'fas fa-image',
    '.jpeg': 'fas fa-image',
    '.png': 'fas fa-image',
    '.gif': 'fas fa-image',
    '.webp': 'fas fa-image',
    '.svg': 'fas fa-bezier-curve',     // SVG 矢量图标
    
    // 文档
    '.doc': 'fas fa-file-word',
    '.docx': 'fas fa-file-word',
    '.xls': 'fas fa-file-excel',
    '.xlsx': 'fas fa-file-excel',
    '.ppt': 'fas fa-file-powerpoint',
    '.pptx': 'fas fa-file-powerpoint',
    '.pdf': 'fas fa-file-pdf',
    '.txt': 'fas fa-file-alt',
    '.csv': 'fas fa-file-csv',
    
    // 媒体文件
    '.mp3': 'fas fa-music',            // 音乐图标
    '.mp4': 'fas fa-video',            // 视频图标
    '.avi': 'fas fa-video',            // 视频图标
  };
  
  return icons[ext] || 'fas fa-file-text';
}

// API 响应格式化工具
const ApiResponse = {
    success(data = null, message = '操作成功') {
        return {
            code: 0,
            message,
            data,
            timestamp: Date.now()
        };
    },
    
    error(message = '操作失败', code = 500, data = null) {
        return {
            code,
            message,
            data,
            timestamp: Date.now()
        };
    }
};

// 添加验证 token 的中间件
const verifyAuthStatus = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    try {
        if (token) {
            // 验证 token
            jwt.verify(token, process.env.JWT_SECRET);
            req.isAuthenticated = true;
        } else {
            req.isAuthenticated = false;
        }
    } catch (err) {
        req.isAuthenticated = false;
    }
    next();
};

// 修改路由处理，使用验证中间件
app.get('/*', verifyAuthStatus, async (req, res,next) => {
    try {
        const requestPath = req.path;
        const normalizedPath = path.normalize(requestPath);
        const absolutePath = path.join(STATIC_DIR, normalizedPath);
        const parentPath = path.dirname(normalizedPath);

        console.log(requestPath)
        // 如果是 api 路径，跳过这个处理器
        if (requestPath.startsWith('/api')) {
            console.log(requestPath+"跳过")
            return next();
        }
        // 防止访问 assets 目录
        if (requestPath.startsWith(ASSETS_PATH)) {
            return res.status(403).send(ApiResponse.error('禁止访问'));
        }

        try {
            await fsPromises.access(absolutePath);
        } catch (err) {
            return res.status(404).send(ApiResponse.error('路径不存在'));
        }

        const stats = await fsPromises.stat(absolutePath);

        if (stats.isFile()) {
            return res.download(absolutePath);
        }

        const files = await fsPromises.readdir(absolutePath);
        const fileList = await Promise.all(files.map(async file => {
            const filePath = path.join(absolutePath, file);
            const stat = await fsPromises.stat(filePath);
            return {
                name: file,
                isDirectory: stat.isDirectory(),
                icon: stat.isDirectory() ? 'fas fa-folder' : getFileIcon(file),
                path: path.join(normalizedPath, file)
            };
        }));

        res.render('files', {
            files: fileList,
            currentPath: normalizedPath,
            parentPath: parentPath,
            isAuthenticated: req.isAuthenticated  // 使用中间件设置的认证状态
        });
    } catch (err) {
        console.error(err);
        res.status(500).send('服务器错误');
    }
});

// 读取配置文件
const config = toml.parse(fs.readFileSync('./public/conf/init.toml', 'utf-8'));
const JWT_SECRET = require('crypto').randomBytes(64).toString('hex');

// 验证 JWT 的中间件
const verifyToken = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json(ApiResponse.error('未授权', 401));

    const token = authHeader.split(' ')[1];
    try {
        jwt.verify(token, JWT_SECRET);
        next();
    } catch (err) {
        res.status(401).json(ApiResponse.error('令牌无效或已过期', 401));
    }
};

// 排除验证的 API 路由列表
const publicApis = [
    '/verify-password',  // 密码验证
    '/check-token',      // token 检查
    '/file-details',      // 查看文件详情
];

// API 中间件 - 处理所有 /api 路由的认证
app.use('/api', (req, res, next) => {
    // 如果是公开 API 或文件详情 API，直接放行
    if (publicApis.includes(req.path)) {
        return next();
    }
    // 其他 API 需要验证 token
    verifyToken(req, res, next);
});

// API 路由定义
app.post('/api/verify-password', express.json(), (req, res) => {
    const { password } = req.body;
    
    if (password === config.upload_password) {
        const token = jwt.sign({}, JWT_SECRET, { expiresIn: '15m' });
        res.json(ApiResponse.success({ token }, '验证成功'));
    } else {
        res.status(401).json(ApiResponse.error('密码错误', 401));
    }
});

app.get('/api/check-token', (req, res) => {
    res.json(ApiResponse.success(null, 'token有效'));
});

app.get('/api/file-details', async (req, res) => {
    try {
        // 确保路径以 / 开头，并规范化路径
        const requestPath = req.query.path || '';
        const normalizedPath = path.normalize(requestPath.startsWith('/') ? requestPath : '/' + requestPath);
        const filePath = path.join(STATIC_DIR, normalizedPath);

        // 确保不能访问上级目录
        const realPath = path.resolve(filePath);
        if (!realPath.startsWith(path.resolve(STATIC_DIR))) {
            return res.status(403).json(ApiResponse.error('禁止访问', 403));
        }
        
        try {
            const stats = await fsPromises.stat(filePath);
            const data = {
                name: path.basename(filePath),
                path: path.dirname(normalizedPath),
                size: formatSize(stats.size),
                created: stats.birthtime.toLocaleString('zh-CN', {
                    year: 'numeric',
                    month: '2-digit',
                    day: '2-digit',
                    hour: '2-digit',
                    minute: '2-digit',
                    second: '2-digit'
                }),
                modified: stats.mtime.toLocaleString('zh-CN', {
                    year: 'numeric',
                    month: '2-digit',
                    day: '2-digit',
                    hour: '2-digit',
                    minute: '2-digit',
                    second: '2-digit'
                })
            };
            res.json(ApiResponse.success(data));
        } catch (err) {
            res.status(404).json(ApiResponse.error('文件不存在', 404));
        }
    } catch (err) {
        console.error(err);
        res.status(500).json(ApiResponse.error('获取文件信息失败'));
    }
});

app.post('/api/upload', upload.array('files'), async (req, res) => {
    if (!req.files || req.files.length === 0) {
        return res.status(400).json(ApiResponse.error('没有文件被上传', 400));
    }

    try {
        const uploadPath = path.join(STATIC_DIR, req.body.path || '');
        
        // 确保上传路径在允许的目录内
        const realPath = path.resolve(uploadPath);
        if (!realPath.startsWith(path.resolve(STATIC_DIR))) {
            return res.status(403).json(ApiResponse.error('非法上传路径', 403));
        }

        // 确保目标目录存在
        await fsPromises.mkdir(uploadPath, { recursive: true });

        for (const file of req.files) {
            const targetPath = path.join(uploadPath, file.originalname);
            await fsPromises.rename(file.path, targetPath);
        }

        res.json(ApiResponse.success(null, '上传成功'));
    } catch (err) {
        console.error('上传失败:', err);
        // 清理临时文件
        for (const file of req.files) {
            try {
                await fsPromises.unlink(file.path);
            } catch (e) {
                console.error('清理临时文件失败:', e);
            }
        }
        res.status(500).json(ApiResponse.error('上传失败'));
    }
});

app.post('/api/delete', express.json(), async (req, res) => {
    try {
        const targetPath = path.join(STATIC_DIR, req.body.path);
        
        try {
            const stats = await fsPromises.stat(targetPath);
            
            if (stats.isDirectory()) {
                await fsPromises.rm(targetPath, { recursive: true });
            } else {
                await fsPromises.unlink(targetPath);
            }
            
            res.json(ApiResponse.success(null, '删除成功'));
        } catch (err) {
            res.status(404).json(ApiResponse.error('文件不存在', 404));
        }
    } catch (err) {
        console.error(err);
        res.status(500).json(ApiResponse.error('删除失败'));
    }
});

// 文件大小格式化函数
function formatSize(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`server running on http://localhost:${PORT}`);
}); 