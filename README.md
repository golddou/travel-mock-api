\# Travel Mock API Server



旅行应用模拟API服务器，用于提供真实数据库数据。



\## 技术栈

\- Node.js

\- Express

\- Sequelize

\- MySQL



\## 安装依赖

```bash

npm install

```



\## 启动服务器

```bash

npm start

```



\## API接口

\- POST /api/auth/login - 用户登录

\- GET /api/auth/me - 获取当前用户信息

\- GET /api/trips - 获取旅行列表

\- POST /api/trips - 创建旅行

\- GET /api/trips/:id - 获取旅行详情

\- GET /api/trips/:tripId/expenses - 获取旅行费用记录



\## 部署说明

推荐部署到Vercel、Railway或Render等云服务。

