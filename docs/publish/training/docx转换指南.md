# Markdown 转 Google Docs 格式指南

## 问题背景

Markdown 中的代码块（```bash ... ```）在复制粘贴到 Google Docs 后会丢失格式，变成普通文本。直接用 `pandoc` 转换的 docx 代码块也没有背景色、边框等视觉区分，导入 Google Docs 后可读性差。

## 解决方案

采用 **pandoc 转 docx + python-docx 后处理** 两步流程。

## 依赖

```bash
# pandoc（Markdown → docx 转换）
brew install pandoc

# python-docx（docx 后处理）
pip3 install python-docx
```

## 转换步骤

### 第一步：pandoc 转换

```bash
pandoc 网络测量工具培训文档.md -o 网络测量工具培训文档.docx
```

### 第二步：后处理脚本

```bash
python3 postprocess_docx.py 网络测量工具培训文档.docx
```

脚本位置：`docs/publish/training/postprocess_docx.py`

### 第三步：导入 Google Docs

上传 docx 到 Google Drive → 右键"用 Google 文档打开"。

## 后处理脚本说明

`postprocess_docx.py` 对 pandoc 生成的 docx 做以下样式处理：

### 代码块（Source Code 段落）

| 属性 | 值 | 说明 |
|------|------|------|
| 背景色 | `#F4F4F4` | 浅灰背景区分正文 |
| 左边框 | `#4A90D9` 8pt | 蓝色竖线标识代码区 |
| 字体 | Courier New 8.5pt | 等宽字体 |
| 行距 | 13pt | 紧凑行距 |
| 缩进 | 左右各 0.15 英寸 | 与正文产生视觉间距 |

### 行内代码（Verbatim Char 字符样式）

| 属性 | 值 |
|------|------|
| 字体 | Courier New 9pt |
| 字色 | `#D63384`（粉色） |
| 背景色 | `#F0F0F0` |

### 表格

| 属性 | 值 |
|------|------|
| 边框 | `#BBBBBB` 细线 |
| 表头背景 | `#E8E8E8` |
| 表头文字 | 加粗 |

## 注意事项

1. **Mermaid 图不会自动渲染**：pandoc 不识别 mermaid 代码块，在 docx 中显示为原始文本。需单独导出为 PNG 后手动插入 Google Docs
2. **pandoc 代码块样式名**：pandoc 生成的代码块使用 `Source Code` 段落样式，字符样式包括 `Verbatim Char`、`FunctionTok`、`CommentTok` 等。后处理脚本依赖这些名称匹配
3. **中文等宽字体**：代码注释中的中文字符使用 Courier New 时宽度可能不一致，但不影响可读性
4. **重复执行**：后处理脚本可重复执行，会覆盖之前的样式设置
5. **Google Docs 转换**：Google Docs 导入 docx 时会保留大部分样式，但部分细节（如精确缩进值）可能略有偏差
