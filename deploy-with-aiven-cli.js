#!/usr/bin/env node

const { createConnection } = require('mysql2/promise');
const fs = require('fs');
const { execSync } = require('child_process');

console.log('=== Aiven CLI 部署工具 ===\n');

// 配置信息
const config = {
  serviceName: 'travel-app-db',
  sqlFile: 'travel-app-schema.sql',
  verifyCommand: 'SHOW TABLES;'
};

// 检查 Aiven CLI 是否安装
function checkAivenCli() {
  try {
    execSync('avn --version', { stdio: 'ignore' });
    console.log('✅ Aiven CLI 已安装');
    return true;
  } catch (error) {
    console.error('❌ Aiven CLI 未安装');
    console.error('请先安装 Aiven CLI:');
    console.error('  - 使用 pip: pip install aiven-client');
    console.error('  - 使用 Homebrew: brew install aiven');
    console.error('  - 更多信息: https://docs.aiven.io/docs/tools/cli');
    return false;
  }
}

// 检查 SQL 文件是否存在
function checkSqlFile() {
  if (fs.existsSync(config.sqlFile)) {
    console.log('✅ SQL 文件已找到:', config.sqlFile);
    return true;
  } else {
    console.error('❌ SQL 文件未找到:', config.sqlFile);
    console.error('请确保 travel-app-schema.sql 文件在当前目录');
    return false;
  }
}

// 执行 Aiven CLI 命令
function runAivenCommand(command, description) {
  console.log(`\n正在 ${description}...`);
  try {
    const output = execSync(command, { encoding: 'utf8' });
    console.log('✅', description, '成功');
    return output;
  } catch (error) {
    console.error('❌', description, '失败');
    console.error('错误信息:', error.stdout || error.stderr);
    throw error;
  }
}

// 执行部署
async function deploy() {
  try {
    // 检查前置条件
    if (!checkAivenCli() || !checkSqlFile()) {
      process.exit(1);
    }

    // 简化的登录检查
    try {
      // 使用 avn user info 命令检查是否已登录
      const userInfoOutput = execSync('avn user info', { encoding: 'utf8' });
      console.log('✅ 已登录到 Aiven CLI');
    } catch (error) {
      console.log('🔑 需要登录到 Aiven CLI');
      console.log('请在同一个终端会话中执行以下命令登录：');
      console.log('  avn user login');
      console.log('使用邮箱：29629755@qq.com');
      console.log('登录成功后，在同一个终端会话中重新运行本脚本');
      process.exit(0);
    }
    
    // 直接执行部署，不切换项目

    // 使用 list 命令获取服务列表，确认服务存在
    const servicesCommand = `avn service list`;
    const servicesOutput = runAivenCommand(servicesCommand, '获取服务列表');
    
    console.log('\n📋 服务列表:');
    console.log(servicesOutput);
    
    // 直接使用已知的连接信息
    console.log('\n📋 使用已知的连接信息:');
    const host = 'travel-app-db-travel-mock-db.h.aivencloud.com';
    const port = '25484';
    const user = 'avnadmin';
    const password = process.env.DB_PASSWORD || 'your_password_here'; // 从环境变量获取密码
    const database = 'defaultdb';
    
    console.log(`Host: ${host}`);
    console.log(`Port: ${port}`);
    console.log(`User: ${user}`);
    console.log(`Database: ${database}`);
    
    // 解析连接信息（已使用已知信息，无需解析）
    
    // 使用 mysql2 直接执行 SQL 文件，不依赖外部 mysql 命令
    console.log('\n📋 使用 mysql2 模块直接执行 SQL 文件...');
    
    try {
      // 读取 SQL 文件内容
      const sqlContent = fs.readFileSync(config.sqlFile, 'utf8');
      
      // 创建数据库连接，使用宽松的SSL设置
      // 修复MySQL2配置选项，只使用支持的选项
      const connection = await createConnection({
        host: host,
        port: port,
        user: user,
        password: password,
        database: database,
        ssl: {
          rejectUnauthorized: false
        },
        connectTimeout: 10000
      });
      
      // 执行 SQL 文件
      await connection.query(sqlContent);
      console.log('✅ SQL 文件执行成功');
      
      // 验证部署
      console.log('\n📋 验证结果:');
      const [verifyResult] = await connection.query(config.verifyCommand);
      console.table(verifyResult);
      
      // 检查表数量
      const tables = verifyResult.map(row => Object.values(row)[0]);
      console.log(`\n✅ 已创建 ${tables.length} 个表`);
      
      // 关闭连接
      await connection.end();
      
      console.log('🎉 所有表都已成功创建！');
    } catch (error) {
      console.error('❌ SQL 文件执行失败');
      console.error('错误信息:', error.message);
      process.exit(1);
    }

    console.log('\n📋 部署完成！');
    console.log('\n下一步操作：');
    console.log('1. 更新 .env.local 文件中的 DB_* 环境变量');
    console.log('2. 启动 API 服务器：npm start');
    console.log('3. 测试 API 连接：curl http://localhost:5000/health');

  } catch (error) {
    console.error('\n❌ 部署失败');
    process.exit(1);
  }
}

// 运行部署
deploy();
