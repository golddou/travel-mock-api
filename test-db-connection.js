#!/usr/bin/env node

const { createConnection } = require('mysql2/promise');

console.log('=== 数据库连接测试工具 ===\n');

// 配置信息
const config = {
  host: 'travel-app-db-travel-mock-db.h.aivencloud.com',
  port: 25484,
  user: 'avnadmin',
  password: process.env.DB_PASSWORD || 'your_password_here', // 从环境变量获取密码
  database: 'defaultdb',
  ssl: {
    // 尝试不同的SSL配置
    rejectUnauthorized: false
  },
  connectTimeout: 30000
};

// 主测试函数
async function testConnection() {
  console.log('正在测试数据库连接...');
  console.log(`连接到: ${config.host}:${config.port}`);
  console.log(`用户: ${config.user}`);
  console.log(`数据库: ${config.database}`);
  
  try {
    const connection = await createConnection(config);
    console.log('✅ 成功连接到数据库！');
    
    // 测试简单查询
    console.log('\n正在测试简单查询...');
    const [results] = await connection.query('SELECT 1 + 1 AS result');
    console.log('查询结果:', results[0].result);
    
    // 关闭连接
    await connection.end();
    console.log('\n✅ 数据库连接已关闭');
    
    return true;
  } catch (error) {
    console.error('❌ 数据库连接失败:');
    console.error('错误信息:', error.message);
    console.error('错误代码:', error.code);
    console.error('错误号:', error.errno);
    console.error('SQL状态:', error.sqlState);
    
    // 检查SSL错误
    if (error.code === 'HANDSHAKE_SSL_ERROR') {
      console.error('\n💡 这是一个SSL握手错误，可能的解决方案:');
      console.error('1. 确保Aiven服务已启用SSL');
      console.error('2. 尝试调整SSL配置');
      console.error('3. 检查网络连接是否稳定');
    }
    
    return false;
  }
}

// 运行测试
testConnection().then(success => {
  process.exit(success ? 0 : 1);
});