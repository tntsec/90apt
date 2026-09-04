# FuncConfig.dat 在线加解密工具

高德地图车机版 FuncConfig.dat 文件在线加解密和编辑工具，支持 7.5 / 8.1 / 8.5 / 9.1 / 9.5 版本。

## 功能

- **在线解密**：上传 `.dat` 文件，解密为可编辑的 JSON/文本
- **在线加密**：上传 `.txt` 或 `.json` 文件，加密为 `.dat` 文件
- **JSON 编辑器**：解密后可直接在浏览器中编辑，格式化后下载
- **多版本支持**：内置 7.5、8.1、8.5、9.1、9.5 版本预设密钥，支持自定义密钥
- **完全本地**：所有操作在浏览器中完成，数据不上传服务器

## 部署到 GitHub Pages

1. 创建 GitHub 仓库
2. 将代码推送到仓库
3. 进入 Settings -> Pages
4. Source 选择 `main` 分支
5. 点击 Save

访问地址：`https://<username>.github.io/<repo-name>/`

## 技术实现

- **加密算法**：AES-CBC / NoPadding
- **前端库**：CryptoJS 4.2.0
- **无后端依赖**：纯静态 HTML/CSS/JS

## 版本密钥

| 版本 | KEY | IV | Prefix |
|------|-----|-----|--------|
| 7.5 | `Jbga21autoj7ZAsF` | `Jbga21autoj7ZAsF` | `1234567812345678` |
| 8.1 | `Yqwr31autou4PbNM` | `1234567812345678` | `9zxc46abc7o28l4t` |
| 8.5 | `Yqwr31autou4PbNM` | `1234567812345678` | `9zxc46abc7o28l4t` |
| 9.1 | `Yqwr31autou4PbNM` | `1234567812345678` | `9zxc46abc7o28l4t` |
| 9.5 | `Yqwr31autou4PbNM` | `1234567812345678` | `9zxc46abc7o28l4t` |

## 文件结构

```
.
├── index.html          # 主页面
├── css/
│   └── style.css       # 样式文件
├── js/
│   ├── crypto.js       # 加解密核心模块
│   └── app.js          # 应用逻辑
├── .nojekyll           # GitHub Pages 配置
└── README.md           # 项目说明
```

## License

MIT
