import { defineConfig } from '@playwright/test'

export default defineConfig({
  testDir: './tests',
  timeout: 60_000,
  use: {
    headless: true
  },
  // 由于测试脚本依赖 ts-node 解析 .ts import，确保 Playwright 使用 ts-node
  // Playwright v1.43+ 会自动注入 ts-node/register 当检测到 TS 配置文件
  // 此处无需额外设置。
}) 