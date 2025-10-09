/* =======================================================================
   运维管理 (最终修正版)
   ======================================================================= */

.commands-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 20px;
}
@media (max-width: 768px) {
  .commands-grid { grid-template-columns: 1fr; }
}

.command-section {
  background: #f5f5f5;
  border: 1px solid #d1d5db;
  border-radius: 8px;
  padding: 12px;
}
/* 修正1: 标题(h3) */
.command-section h3 {
  margin: 0 0 16px;
  font-size: 0.9rem;
  font-weight: 600;
  color: #1e293b;
  display: flex;
  align-items: center;
  gap: 6px;
}

/* 列表整体：两列网格（左列命令 / 右列注释） */
#ops-panel .command-list,
.commands-grid .command-list,
.command-list {
  font-size: 0.8rem;
  line-height: 1.3;
  margin: 0;
  padding: 0;
  list-style: none;

  display: grid;
  /* 修正2: 左列最多占 50%，避免长命令挤压注释 */
  grid-template-columns: minmax(auto,50%) 1fr;
  column-gap: 10px;
  row-gap: 4px;
  align-items: center;
  grid-auto-flow: row dense;
}

/* 隐藏 <br> 产生的额外空白 */
#ops-panel .command-list > br,
.commands-grid .command-list > br,
.command-list > br { display: none; }

/* 普通命令 <code>：灰底胶囊 */
#ops-panel .command-list > code,
.commands-grid .command-list > code,
.command-list > code {
  grid-column: 1;
  display: inline-block;
  justify-self: start;
  background: #e2e8f0;
  color: #1f2937;
  padding: 2px 6px;
  border-radius: 4px;
  font-family: monospace;
  font-size: 0.78rem;
  line-height: 1.2;
  white-space: pre-wrap;
  max-width: 100%;
  margin: 0;
}

/* 示例命令 <a>：与 <code> 同款灰底胶囊（蓝字） */
#ops-panel .command-list > a,
.commands-grid .command-list > a,
.command-list > a {
  grid-column: 1;
  display: inline-block;
  justify-self: start;
  background: #e2e8f0;
  padding: 2px 6px;
  border-radius: 4px;
  text-decoration: none;
  margin: 0;

  color: #2563eb;
  font-family: monospace;
  font-size: 0.78rem;
  line-height: 1.2;
  white-space: pre-wrap;
  max-width: 100%;
}

/* 注释 <span>（右列左对齐） */
#ops-panel .command-list > span,
.commands-grid .command-list > span,
.command-list > span {
  grid-column: 2;
  color: #6b7280;
  text-align: left;
  margin: 0;
  line-height: 1.25;
}

/* 标题行（如 “示例：”“level:”“代理URL格式：”）——统一成蓝字，无灰底 */
#ops-panel .command-list > :not(code):not(span):not(a),
.commands-grid .command-list > :not(code):not(span):not(a),
.command-list > :not(code):not(span):not(a) {
  grid-column: 1 / -1;
  margin: 0;
  line-height: 1.3;
  color: #2563eb;           /* 标题蓝字 */
  font-size: 0.78rem;       /* 与示例一致 */
  font-weight: 600;
}

/* 关键改动①：标题后的“内容块”(div)里若没有链接 <a>（例如 level 列表），
   也做成蓝字灰底的小胶囊，按行断开。*/
#ops-panel .command-list > div + div:not(:has(a)),
.commands-grid .command-list > div + div:not(:has(a)),
.command-list > div + div:not(:has(a)) {
  grid-column: 1 / -1;
  display: inline;                 /* 让一个块按行内渲染，配合 clone 逐行成胶囊 */
  background: #e2e8f0;
  color: #2563eb;
  font-family: monospace;
  font-size: 0.78rem;
  line-height: 1.2;
  padding: 2px 6px;
  border-radius: 4px;
  box-decoration-break: clone;     /* 每个换行(<br>)单独成一枚胶囊 */
}

/* 关键改动②：标题后的“内容块”里若包含链接 <a>（例如 代理URL格式），
   链接本身已由上面的 a 规则渲染为蓝字灰底胶囊；确保整体与普通行同等行距。*/
#ops-panel .command-list > div + div:has(a),
.commands-grid .command-list > div + div:has(a),
.command-list > div + div:has(a) {
  grid-column: 1 / -1;
  margin: 0;
  line-height: 1.3;
}

/* 防止内容块内部的段落自带外边距 */
#ops-panel .command-list p,
.commands-grid .command-list p,
.command-list p { margin: 0; }
