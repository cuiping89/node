/* =======================================================================
   EdgeBox 控制面板 - 样式表 v3.0 (修复版)
   ======================================================================= */

/* --- 1. 全局重置与基础皮肤 --- */
/* 描述：清除浏览器默认样式，并设定统一的盒模型、字体、背景色等，为后续样式提供一致的基础。*/
* {
  margin: 0;
  padding: 0;
  box-sizing: border-box; /* 统一盒模型，使元素的宽度和高度计算包含内边距和边框 */
}

body {
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; /* 优先使用各平台的系统默认字体 */
  background: #f3f4f6; /* 页面背景色：浅灰色 */
  min-height: 100vh;
  padding: 20px;
  color: #1f2937; /* 全局默认文字颜色 */
}


/* --- 2. 基础排版与文字样式 --- */
/* 描述：定义内容容器、各级标题和基础文本的通用样式。*/
.container {
  max-width: 1400px; /* 页面主体内容的最大宽度 */
  margin: 0 auto; /* 水平居中 */
}

/* 各级标题样式 */
h1 { font-size: 23px; font-weight: 700; color: #1f2937; line-height: 32px; }
h2 { font-size: 18px; font-weight: 600; color: #1f2937; line-height: 26px; }
h3 { font-size: 15px; font-weight: 600; color: #1f2937; line-height: 22px; }
h4 { font-size: 14px; font-weight: 500; color: #1f2937; line-height: 20px; }

/* 基础文本样式 */
body, p, span, td, div {
  font-size: 13px;
  font-weight: 500;
  color: #1f2937;
  line-height: 20px;
}

/* 辅助文字颜色类 */
.text-muted { color: #6b7280; }
.text-secondary { color: #4b5563; }


/* --- 3. 布局与通用组件 --- */
/* 描述：定义可复用的布局容器（如卡片、网格）和小型UI组件（如按钮、徽章）。*/

/* -- 3.1 CSS 变量 (全局) -- */
/* 使用CSS变量统一管理常用值，便于全局主题的修改和维护。 */
:root {
  --heading-color: #111827;   /* h3标题颜色（黑色） */
  --subheading-color: #6b7280; /* h4标题颜色（灰色） */
  --content-color: #6b7280;   /* 内容文本颜色（灰色） */
  --h3-size: 15px;            /* h3字体大小 */
  --h4-size: 14px;            /* h4字体大小 */
}

/* -- 3.2 卡片样式 -- */
.main-card { /* 最外层的整体容器 */
  background: #fff;
  border: 1px solid #d1d5db;
  border-radius: 10px;
  box-shadow: 0 2px 6px rgba(0, 0, 0, .08);
  overflow: hidden;
  margin-bottom: 20px;
  padding: 0;
}

.card { /* 各功能模块的基础容器 */
  background: #fff;
  border: 1px solid #d1d5db;
  border-radius: 10px;
  box-shadow: 0 2px 6px rgba(0, 0, 0, .08);
  padding: 20px;
  margin-bottom: 20px;
  transition: box-shadow .2s;
}
.card:hover { /* 鼠标悬浮时阴影加深，提供交互反馈 */
  box-shadow: 0 4px 8px rgba(0, 0, 0, .08);
}
.card-header {
  margin-bottom: 20px;
  padding-bottom: 12px;
  border-bottom: 1px solid #e5e7eb;
}
.card-header h2 {
  display: flex;
  justify-content: space-between;
  align-items: center;
}
.card-note { /* 卡片标题旁的小字注释 */
  font-size: 11px;
  color: #6b7280;
  font-weight: 400;
}

/* -- 3.3 网格布局 -- */
.grid { display: grid; gap: 20px; }
.grid-3 { grid-template-columns: repeat(3, 1fr); }
.grid-1-2 { grid-template-columns: 1fr 2fr; }

/* -- 3.4 全局通用组件 -- */
.info-item { /* 信息展示行 (标签 + 内容) */
  display: flex;
  justify-content: space-between;
  padding: 6px 0;
}
.info-item label { color: #6b7280; }
.info-item value { color: #1f2937; font-weight: 500; }

.status-badge { /* 状态徽章 (运行中/已停止) */
  display: inline-flex;
  align-items: center;
  height: 20px;
  line-height: 20px;
  padding: 0 10px;
  border-radius: 999px;
  font-size: 11px;
}
.status-running { background: #d1fae5; color: #059669; border-color: #a7f3d0; }
.status-stopped { background: #fee2e2; color: #ef4444; border-color: #fecaca; }

/* 页面主标题 */
.main-header {
  background: linear-gradient(135deg, #e2e8f0 0%, #f1f5f9 50%, #f8fafc 100%);
  border-radius: 0;
  border-top-left-radius: 9px;
  border-top-right-radius: 9px;
  padding: 16px 20px;
  position: relative;
  margin: 0;
  box-shadow: inset 0 -1px 0 rgba(0,0,0,0.1), inset 0 1px 0 rgba(255,255,255,0.9);
}
.main-header h1 {
  text-align: center;
  font-size: 24px;
  font-weight: 700;
  text-shadow: 0 1px 2px rgba(0,0,0,0.1);
}
.main-header::after { /* 标题下方的装饰性渐变线条 */
  content: "";
  position: absolute;
  left: 50%;
  bottom: 0;
  transform: translateX(-50%);
  width: 60px;
  height: 2px;
  background: linear-gradient(90deg, transparent, #10b981, transparent);
  opacity: 0.6;
}
.main-content {
  padding: 20px;
}


/* --- 4. 特定模块样式 --- */
/* 描述：针对每个独立的功能面板（如系统概览、证书配置等）进行精细化样式定义。*/

/* -- 4.1 系统概览 (#system-overview) -- */
#system-overview {
  --label-w: 72px;           /* 定义此模块内专用的CSS变量 */
  --percent-col: 33px;
  --meter-height: 20px;
}
#system-overview .inner-block {
  padding: 12px;
  margin-bottom: 0;
}
#system-overview .progress-bar { /* 进度条 */
  position: relative;
  height: var(--meter-height);
  background: #e2e8f0;
  border-radius: 999px;
  overflow: hidden;
}
#system-overview .progress-fill { /* 进度条填充部分 */
  height: 100%;
  background: linear-gradient(90deg, #059669, #10b981);
  transition: width .25s ease;
}
#system-overview .progress-text { /* 进度条上的文字 */
  position: absolute;
  left: 4px; right: 4px; top: 50%;
  transform: translateY(-50%);
  font-size: 11px;
  color: #fff;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

/* -- 4.2 运维管理 -- */
.commands-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 20px;
}
.command-section {
  background: #f5f5f5;
  border: 1px solid #d1d5db;
  border-radius: 8px;
  padding: 12px;
}
.command-list code { /* 命令文本的灰色背景块 */
  background: #e2e8f0;
  color: #1f2937;
  padding: 1px 6px;
  border-radius: 4px;
  font-family: monospace;
}

/* -- 4.3 协议配置表格 -- */
.data-table {
  width: 100%;
  border-collapse: collapse;
}
.data-table th {
  background: #f5f5f5;
  color: #4b5563;
  padding: 10px;
  text-align: left;
  font-size: 12px;
  border-bottom: 1px solid #e5e7eb;
}
.data-table td {
  padding: 10px;
  border-bottom: 1px solid #f3f4f6;
  font-size: 12px;
}
.data-table tr:hover td { background: #f5f5f5; }
.data-table tr.subs-row td { background: #f5f5f5; } /* 订阅行的特殊样式 */

/* -- 4.4 流量统计图表 -- */
/* 【关键修复】通过设定具体高度，防止图表因容器是flex/grid布局而无限拉伸 */
.traffic-charts {
  display: grid;
  grid-template-columns: 7fr 3fr;
  gap: 20px;
  align-items: stretch; /* 子项等高 */
}
.chart-container {
  position: relative;
  display: flex;
  flex-direction: column;
  overflow: hidden;
}
.chart-column:first-child .chart-container,
.traffic-charts:not(.traffic--subcards) .chart-column:first-child .chart-container {
  height: 300px; /* 设定一个固定的高度 */
  min-height: 300px;
}
.chart-column:last-child .chart-container,
.traffic-charts:not(.traffic--subcards) .chart-column:last-child .chart-container {
    height: calc(50px + 12px + 300px); /* 根据另一列的高度动态计算，保持对齐 */
    min-height: calc(50px + 12px + 300px);
}
.traffic-card .chart-container > canvas {
  display: block;
  width: 100% !important;
  height: 100% !important; /* 让canvas填满其容器 */
  flex: 1 1 auto;
}

/* -- 4.5 通知中心 -- */
.notification-center {
  position: relative;
  display: inline-flex;
  width: 38px;
  height: 38px;
  margin-right: 22px;
}
.notification-badge { /* 未读消息数量徽章 */
  position: absolute;
  top: 2px;
  right: 2px;
  background: #ef4444;
  color: white;
  border-radius: 10px;
  padding: 1px 6px;
  font-size: 11px;
  animation: notification-pulse 2s infinite; /* 脉冲动画 */
}
@keyframes notification-pulse {
  50% { transform: scale(1.1); }
}
.notification-panel { /* 弹出的通知面板 */
  position: absolute;
  top: 100%;
  right: 0;
  width: 320px;
  background: white;
  border-radius: 8px;
  box-shadow: 0 10px 20px rgba(0, 0, 0, 0.15);
  display: none; /* 默认隐藏 */
  z-index: 1000;
}
.notification-panel.show { display: block; }


/* --- 5. 弹窗 (Modal) 与按钮样式 --- */
/* 描述：定义所有弹窗的统一样式，并【关键修复】按钮样式和内容对齐问题。*/

/* -- 5.1 弹窗基础结构 -- */
.modal {
  display: none;
  position: fixed;
  inset: 0;
  background: rgba(0, 0, 0, .5); /* 半透明遮罩层 */
  z-index: 9998;
}
.modal .modal-content, dialog[open] { /* 兼容<dialog>标签 */
  position: fixed;
  left: 50%;
  top: 50%;
  transform: translate(-50%, -50%); /* 垂直水平居中 */
  width: 630px;
  height: 730px;
  max-height: 85vh;
  background: #fff;
  border-radius: 14px;
  box-shadow: 0 10px 30px rgba(17,24,39,.18);
  display: flex;
  flex-direction: column;
  overflow: hidden;
}
.modal-header { text-align: left; } /* 标题左对齐 */
.modal-body { flex: 1; overflow-y: auto; }
.modal-footer { display: flex; justify-content: flex-end; }

/* -- 5.2 查看详情弹窗内容左对齐修复 -- */
/* 【关键修复】为详情弹窗内的 .info-item 使用 grid 布局，强制实现标签和内容的左对齐。*/
#ipqModal .info-item {
  display: grid;
  grid-template-columns: 144px 1fr; /* 左列固定宽度，右列自适应 */
  gap: 12px;
  align-items: start;
  text-align: left; /* 确保内部文本都左对齐 */
}
#ipqModal .info-item label,
#ipqModal .info-item value {
  text-align: left; /* 再次强调左对齐 */
}

/* -- 5.3 二维码样式 (确保可见性) -- */
/* 【关键修复】为二维码容器和canvas设定明确的尺寸和居中样式，防止其丢失或错位。*/
.modal-body .qr-container, .modal-body .qrcode {
  text-align: center;
  margin: 16px auto;
}
.modal-body .qr-container canvas, .modal-body .qrcode canvas {
  width: 180px !important;
  height: 180px !important;
  display: block;
  margin: 12px auto;
}

/* -- 5.4 弹窗按钮样式修复 -- */
/* 【关键修复】严格恢复所有按钮的原始样式，包括通用按钮和弹窗内专用按钮。*/
/* 通用按钮 (查看详情、查看全部等) */
.btn-detail, .btn-viewall, .btn-link, .link, .whitelist-more {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  height: 28px;
  padding: 0 12px;
  border: 1px solid #d1d5db;
  border-radius: 6px;
  background: #fff;
  color: #2563eb; /* 蓝字 */
  font-size: 12px;
  cursor: pointer;
  transition: all .15s ease;
}
.btn-detail:hover, .btn-viewall:hover, .btn-link:hover, .link:hover, .whitelist-more:hover {
  background: #f3f4f6;
  color: #1d4ed8;
}

/* 弹窗内的复制按钮 */
.modal .copy-btn, .modal .btn-copy, .modal .btn-secondary, .modal [data-action="copy"] {
  background: #ffffff;
  color: #6b7280;
  border: 1px solid #d1d5db;
  border-radius: 8px;
  padding: 8px 12px;
  font-size: 12px;
  cursor: pointer;
  box-shadow: 0 1px 2px rgba(0,0,0,.04);
  transition: all 0.15s ease;
}
.modal .copy-btn:hover, .modal .btn-copy:hover, .modal .btn-secondary:hover, .modal [data-action="copy"]:hover {
  background: #f9fafb;
  color: #374151;
}
.modal .copy-btn:active, .modal .btn-copy:active, .modal .btn-secondary:active, .modal [data-action="copy"]:active {
  background: #f3f4f6;
  transform: translateY(1px);
}

/* 弹窗关闭按钮 */
.modal .close-btn {
  position: absolute;
  right: 12px;
  top: 12px;
  width: 32px;
  height: 28px;
  border: 1px solid #e5e7eb;
  border-radius: 8px;
  background: #fff;
  display: flex;
  align-items: center;
  justify-content: center;
  cursor: pointer;
}


/* --- 6. 响应式布局 --- */
/* 描述：使用媒体查询，针对不同屏幕尺寸调整布局，以提供更好的浏览体验。*/
@media (max-width: 1024px) { /* 平板设备 */
  .grid-3, .grid-1-2, .traffic-charts {
    grid-template-columns: 1fr; /* 所有网格变为单列堆叠 */
  }
}

@media (max-width: 768px) { /* 移动设备 */
  .commands-grid {
    grid-template-columns: 1fr;
  }
  .modal .modal-content {
    width: 95%; /* 弹窗宽度适应手机屏幕 */
    height: auto; /* 高度自动 */
    max-height: 90vh; /* 限制最大高度 */
  }
}
