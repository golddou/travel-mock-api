const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2/promise');
const { Sequelize, DataTypes, Op } = require('sequelize');

const app = express();
const PORT = process.env.PORT || 5000;

// 配置CORS
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));

// 解析JSON请求体
app.use(express.json());

// 请求日志中间件
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.url}`);
  next();
});

// 创建数据库连接
const sequelize = new Sequelize(
  process.env.DB_NAME || 'aoyoymmkjb',      // 数据库名称
  process.env.DB_USER || 'qynufyga',        // 用户名
  process.env.DB_PASSWORD || 'FoZwgUg0O21vFik0',// 密码
  {
    host: process.env.DB_HOST || 'mysql2.sqlpub.com',// 主机地址
    port: process.env.DB_PORT || 3307,       // 端口号
    dialect: 'mysql', // 数据库类型
    timezone: '+08:00',// 时区
    logging: (msg) => {
      // 过滤掉包含十六进制地址的日志
      if (!/0x[0-9a-fA-F]+/g.test(msg)) {
        console.log(msg);
      }
    }, // 自定义日志过滤
  }
);

// 定义数据模型
// 用户模型
const User = sequelize.define('User', {
  user_id: {
    type: DataTypes.STRING,
    primaryKey: true
  },
  id: {
    type: DataTypes.VIRTUAL,
    get() {
      return this.get('user_id');
    }
  },
  first_name: {
    type: DataTypes.STRING,
    allowNull: false
  },
  last_name: {
    type: DataTypes.STRING,
    allowNull: false
  },
  name: {
    type: DataTypes.VIRTUAL,
    get() {
      return `${this.get('first_name')} ${this.get('last_name')}`.trim();
    }
  },
  email: {
    type: DataTypes.STRING,
    allowNull: false,
    unique: true
  },
  username: {
    type: DataTypes.STRING,
    allowNull: false,
    unique: true
  },
  password: {
    type: DataTypes.STRING,
    allowNull: false
  },
  created_at: {
    type: DataTypes.DATE,
    allowNull: false
  },
  updated_at: {
    type: DataTypes.DATE,
    allowNull: false
  }
}, {
  tableName: 'users',
  timestamps: false,
  createdAt: 'created_at',
  updatedAt: 'updated_at',
  // 设置正确的主键名
  id: false
});

// 旅行模型
const Trip = sequelize.define('Trip', {
  trip_id: {
    type: DataTypes.STRING,
    primaryKey: true
  },
  user_id: {
    type: DataTypes.STRING,
    allowNull: false
  },
  name: {
    type: DataTypes.STRING,
    allowNull: false
  },
  description: {
    type: DataTypes.TEXT
  },
  destination: {
    type: DataTypes.STRING,
    allowNull: false
  },
  start_date: {
    type: DataTypes.DATE,
    allowNull: false
  },
  end_date: {
    type: DataTypes.DATE,
    allowNull: false
  },
  created_at: {
    type: DataTypes.DATE,
    allowNull: false
  },
  updated_at: {
    type: DataTypes.DATE,
    allowNull: false
  },
  trip_type: {
    type: DataTypes.STRING
  },
  is_public: {
    type: DataTypes.BOOLEAN,
    defaultValue: false
  }
}, {
  tableName: 'trips',
  timestamps: false,
  createdAt: 'created_at',
  updatedAt: 'updated_at',
  // 设置正确的主键名
  id: false
});

// 旅行成员模型
const TripMember = sequelize.define('TripMember', {
  // 暂时不定义，因为表结构未知，使用时通过raw query处理
}, {
  tableName: 'trip_participants',
  timestamps: false
});

// 费用模型
const Expense = sequelize.define('Expense', {
  expense_id: {
    type: DataTypes.STRING,
    primaryKey: true
  },
  trip_id: {
    type: DataTypes.STRING,
    allowNull: false
  },
  amount: {
    type: DataTypes.DECIMAL(10, 2),
    allowNull: false
  },
  currency: {
    type: DataTypes.STRING,
    allowNull: false
  },
  category: {
    type: DataTypes.STRING,
    allowNull: false
  },
  description: {
    type: DataTypes.TEXT
  },
  date: {
    type: DataTypes.DATE,
    allowNull: false
  },
  paid_by: {
    type: DataTypes.STRING,
    allowNull: false
  },
  split_method: {
    type: DataTypes.STRING
  },
  split_details: {
    type: DataTypes.JSON
  },
  created_by: {
    type: DataTypes.STRING,
    allowNull: false
  },
  created_at: {
    type: DataTypes.DATE,
    allowNull: false
  },
  updated_at: {
    type: DataTypes.DATE,
    allowNull: false
  }
}, {
  tableName: 'expenses',
  timestamps: false,
  createdAt: 'created_at',
  updatedAt: 'updated_at',
  // 设置正确的主键名
  id: false
});

// 费用分摊模型
const ExpenseShare = sequelize.define('ExpenseShare', {
  // 暂时不定义，因为表结构未知，使用时通过raw query处理
}, {
  tableName: 'expense_shares',
  timestamps: false
});

// 预算模型
const Budget = sequelize.define('Budget', {
  budget_id: {
    type: DataTypes.STRING,
    primaryKey: true
  },
  id: {
    type: DataTypes.VIRTUAL,
    get() {
      return this.get('budget_id');
    }
  },
  trip_id: {
    type: DataTypes.STRING,
    allowNull: false
  },
  category: {
    type: DataTypes.STRING
  },
  amount: {
    type: DataTypes.DECIMAL(10, 2),
    allowNull: false
  },
  currency: {
    type: DataTypes.STRING,
    allowNull: false
  },
  spent: {
    type: DataTypes.DECIMAL(10, 2),
    allowNull: false,
    defaultValue: 0
  },
  created_at: {
    type: DataTypes.DATE,
    allowNull: false
  },
  updated_at: {
    type: DataTypes.DATE,
    allowNull: false
  }
}, {
  tableName: 'budgets',
  timestamps: false,
  createdAt: 'created_at',
  updatedAt: 'updated_at',
  id: false
});

// 定义关联关系
// 旅行和创建者关联 - 使用正确的外键名
Trip.belongsTo(User, { as: 'creator', foreignKey: 'user_id' });

// 旅行成员关联
TripMember.belongsTo(User, { as: 'user', foreignKey: 'user_id' });
TripMember.belongsTo(Trip, { as: 'trip', foreignKey: 'trip_id' });

// 费用关联 - 使用正确的外键名
Expense.belongsTo(User, { as: 'payer', foreignKey: 'paid_by' });
Expense.belongsTo(Trip, { as: 'trip', foreignKey: 'trip_id' });

// 预算关联
Budget.belongsTo(Trip, { as: 'trip', foreignKey: 'trip_id' });

// 费用分摊关联
ExpenseShare.belongsTo(Expense, { as: 'expense', foreignKey: 'expense_id' });
ExpenseShare.belongsTo(User, { as: 'user', foreignKey: 'user_id' });

// 生成JWT令牌
const generateToken = (user) => {
  return jwt.sign({ id: user.user_id, email: user.email, username: user.username }, 'secret_key', { expiresIn: '7d' });
};

// 认证中间件
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.sendStatus(401);

  console.log('[AuthMiddleware] 收到token:', token);
  console.log('[AuthMiddleware] 开始验证token');
  
  jwt.verify(token, 'secret_key', (err, user) => {
    if (err) {
      console.error('[AuthMiddleware] token验证失败:', err.message);
      console.error('[AuthMiddleware] 错误类型:', err.name);
      console.error('[AuthMiddleware] 错误详情:', err);
      return res.status(403).json({ message: 'token验证失败:' + err.message });
    }
    console.log('[AuthMiddleware] token验证成功，用户:', user);
    req.user = user;
    next();
  });
};

// 只进行数据库连接，不自动同步模型
async function syncDatabase() {
  try {
    await sequelize.authenticate();
    console.log('数据库连接成功！');
    // 不再自动同步模型，避免修改已存在的表结构
    console.log('跳过数据库模型自动同步，使用已存在的表结构！');
  } catch (error) {
    console.error('数据库连接失败:', error);
    process.exit(1);
  }
}

// API端点

// 健康检查
app.get('/health', (req, res) => {
  res.json({ status: 'ok', message: 'HELLOWORLD from MySQL API server!' });
});

// 调试端点：查看表结构
app.get('/api/debug/trip_invitations_structure', async (req, res) => {
  try {
    const structure = await sequelize.query(
      `DESCRIBE trip_invitations`,
      { type: Sequelize.QueryTypes.SELECT }
    );
    res.json(structure);
  } catch (error) {
    console.error('获取表结构失败:', error);
    res.status(500).json({ message: '获取表结构失败', error: error.message });
  }
});

// 调试端点：查看trip_participants表结构
app.get('/api/debug/trip_participants_structure', async (req, res) => {
  try {
    const structure = await sequelize.query(
      `DESCRIBE trip_participants`,
      { type: Sequelize.QueryTypes.SELECT }
    );
    res.json(structure);
  } catch (error) {
    console.error('获取表结构失败:', error);
    res.status(500).json({ message: '获取表结构失败', error: error.message });
  }
});

// 调试端点：查看expense_shares表结构
app.get('/api/debug/expense_shares_structure', async (req, res) => {
  try {
    const structure = await sequelize.query(
      `DESCRIBE expense_shares`,
      { type: Sequelize.QueryTypes.SELECT }
    );
    res.json(structure);
  } catch (error) {
    console.error('获取表结构失败:', error);
    res.status(500).json({ message: '获取表结构失败', error: error.message });
  }
});

// 调试端点：查看expense_shares表数据
app.get('/api/debug/expense_shares_data', async (req, res) => {
  try {
    const data = await sequelize.query(
      `SELECT * FROM expense_shares`,
      { type: Sequelize.QueryTypes.SELECT }
    );
    res.json(data);
  } catch (error) {
    console.error('获取表数据失败:', error);
    res.status(500).json({ message: '获取表数据失败', error: error.message });
  }
});

// 调试端点：查看expenses表数据
app.get('/api/debug/expenses_data', async (req, res) => {
  try {
    const data = await sequelize.query(
      `SELECT * FROM expenses`,
      { type: Sequelize.QueryTypes.SELECT }
    );
    res.json(data);
  } catch (error) {
    console.error('获取表数据失败:', error);
    res.status(500).json({ message: '获取表数据失败', error: error.message });
  }
});

// 根路径
app.get('/', (req, res) => {
  res.json({ message: 'Travel Expense Sharing API with MySQL' });
});

// 获取所有系统用户（用于邀请成员）
app.get('/api/users', authenticateToken, async (req, res) => {
  try {
    console.log('当前用户ID:', req.user.id);
    // 返回所有用户，除了当前用户
    const systemUsers = await User.findAll({
      attributes: ['user_id', 'first_name', 'last_name', 'email', 'username']
    });
    
    console.log('系统用户查询结果:', systemUsers);
    
    // 转换为前端期望的格式，过滤掉当前用户
    const responseUsers = systemUsers
      .filter(user => user.user_id !== req.user.id) // 过滤掉当前用户
      .map(user => ({
        id: user.user_id,
        name: `${user.first_name} ${user.last_name}`.trim() || user.username || '未知用户',
        email: user.email || '',
        username: user.username || ''
      }));
    
    console.log('转换后的用户数据:', responseUsers);
    
    res.json(responseUsers);
  } catch (error) {
    console.error('获取系统用户失败:', error);
    res.status(500).json({ message: '获取用户列表失败' });
  }
});

// 测试端点：获取所有用户，包括当前用户
app.get('/api/test/users', authenticateToken, async (req, res) => {
  try {
    // 返回所有用户，包括当前用户
    const allUsers = await User.findAll({
      attributes: ['user_id', 'first_name', 'last_name', 'email', 'username']
    });
    
    console.log('所有用户:', allUsers);
    
    res.json(allUsers);
  } catch (error) {
    console.error('获取所有用户失败:', error);
    res.status(500).json({ message: '获取用户列表失败' });
  }
});

// 登录
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({
      where: { username, password }
    });

    if (!user) {
      return res.status(401).json({ message: '用户名或密码错误' });
    }

    // 确保返回的用户对象使用前端期望的字段名
    const userWithStringId = {
      id: user.user_id,
      name: `${user.first_name} ${user.last_name}`, // 组合姓名
      first_name: user.first_name,
      last_name: user.last_name,
      email: user.email,
      username: user.username,
      created_at: user.created_at,
      updated_at: user.updated_at
    };

    const token = generateToken(user);
    res.json({ access_token: token, token_type: 'bearer', user: userWithStringId });
  } catch (error) {
    console.error('登录失败:', error);
    res.status(500).json({ message: '登录失败，请稍后重试' });
  }
});

// 获取当前用户信息
app.get('/api/auth/me', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const user = await User.findOne({
      where: { user_id: userId }
    });

    if (!user) {
      return res.status(404).json({ message: '用户未找到' });
    }

    // 确保返回的用户对象使用前端期望的字段名
    const userWithStringId = {
      id: user.user_id,
      name: `${user.first_name} ${user.last_name}`, // 组合姓名
      first_name: user.first_name,
      last_name: user.last_name,
      email: user.email,
      username: user.username,
      created_at: user.created_at,
      updated_at: user.updated_at
    };

    res.json(userWithStringId);
  } catch (error) {
    console.error('获取用户信息失败:', error);
    res.status(500).json({ message: '获取用户信息失败' });
  }
});

// 注册
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, username, nickname } = req.body;
    
    // 检查邮箱是否已存在
    const existingEmail = await User.findOne({ where: { email } });
    if (existingEmail) {
      return res.status(400).json({ message: '该邮箱已被注册' });
    }
    
    // 检查用户名是否已存在
    const existingUsername = await User.findOne({ where: { username } });
    if (existingUsername) {
      return res.status(400).json({ message: '该用户名已被使用' });
    }

    // 使用UUID生成user_id
    const { v4: uuidv4 } = require('uuid');
    const userId = uuidv4();
    
    // 拆分nickname为first_name和last_name
    const nameParts = nickname.split(' ');
    const first_name = nameParts[0] || nickname;
    const last_name = nameParts.slice(1).join(' ') || '';

    const newUser = await User.create({
      user_id: userId,
      first_name,
      last_name,
      email,
      password,
      username,
      created_at: new Date(),
      updated_at: new Date()
    });
    
    // 确保返回的用户对象使用前端期望的字段名
    const userWithStringId = {
      id: newUser.user_id,
      name: `${newUser.first_name} ${newUser.last_name}`.trim(),
      first_name: newUser.first_name,
      last_name: newUser.last_name,
      email: newUser.email,
      username: newUser.username,
      created_at: newUser.created_at,
      updated_at: newUser.updated_at
    };

    const token = generateToken(newUser);
    res.json({ access_token: token, token_type: 'bearer', user: userWithStringId });
  } catch (error) {
    console.error('注册失败:', error);
    res.status(500).json({ message: '注册失败，请稍后重试' });
  }
});

// 获取当前用户
app.get('/api/auth/me', authenticateToken, async (req, res) => {
  try {
    // 从认证信息中获取当前用户ID
    const currentUserId = req.user.id;
    
    const user = await User.findByPk(currentUserId);
    if (!user) return res.status(404).json({ message: 'User not found' });
    
    // 确保返回的用户对象使用前端期望的字段名
    const userWithStringId = {
      id: user.user_id,
      name: `${user.first_name} ${user.last_name}`.trim(),
      first_name: user.first_name,
      last_name: user.last_name,
      email: user.email,
      username: user.username,
      created_at: user.created_at,
      updated_at: user.updated_at
    };
    
    res.json(userWithStringId);
  } catch (error) {
    console.error('获取当前用户失败:', error);
    res.status(500).json({ message: '获取用户信息失败' });
  }
});

// 辅助函数：获取旅行成员列表，包括待处理邀请
async function getTripMembersWithPending(trip, sequelize) {
  let members = [];
  
  try {
    // 使用raw query获取旅行成员及其用户信息
    const membersResult = await sequelize.query(
      `SELECT tp.*, u.user_id, u.first_name, u.last_name, u.username, u.email 
       FROM trip_participants tp 
       LEFT JOIN users u ON tp.user_id = u.user_id 
       WHERE tp.trip_id = :tripId`,
      { replacements: { tripId: trip.trip_id }, type: Sequelize.QueryTypes.SELECT }
    );
    
    // 确保tripMembers是一维数组
    const tripMembers = Array.isArray(membersResult) 
      ? Array.isArray(membersResult[0]) 
        ? membersResult[0] 
        : membersResult 
      : [];
    
    // 查询待处理的邀请
    let pendingInvitations = [];
    try {
      const invitationsResult = await sequelize.query(
        `SELECT ti.*, u.user_id, u.first_name, u.last_name, u.username, u.email 
         FROM trip_invitations ti 
         LEFT JOIN users u ON ti.invitee_id = u.user_id 
         WHERE ti.trip_id = :tripId AND ti.status = 'pending'`,
        { replacements: { tripId: trip.trip_id }, type: Sequelize.QueryTypes.SELECT }
      );
      
      if (Array.isArray(invitationsResult)) {
        if (Array.isArray(invitationsResult[0]) && invitationsResult.length === 2) {
          pendingInvitations = invitationsResult[0] || [];
        } else {
          pendingInvitations = invitationsResult || [];
        }
      } else {
        pendingInvitations = [];
      }
    } catch (inviteError) {
      console.error('查询旅行待处理邀请失败:', inviteError);
      pendingInvitations = [];
    }
    
    // 转换数据库查询到的成员
    const dbMembers = tripMembers.map(member => ({
      id: member.participant_id,
      trip_id: member.trip_id,
      user_id: member.user_id,
      is_admin: member.user_id === trip.user_id, // 创建者是管理员
      is_creator: member.user_id === trip.user_id, // 标记是否为创建者
      invitation_status: member.user_id === trip.user_id ? 'creator' : 'accepted', // 创建者特殊状态
      joined_at: member.joined_at,
      user: {
        id: member.user_id,
        name: `${member.first_name} ${member.last_name}`.trim() || member.username || '未知用户',
        email: member.email || '',
        username: member.username || ''
      }
    }));
    
    // 转换待处理邀请为成员格式
    const pendingMembers = pendingInvitations.map(invitation => ({
      id: invitation.invitation_id,
      trip_id: invitation.trip_id,
      user_id: invitation.invitee_id,
      is_admin: false,
      invitation_status: 'pending',
      joined_at: null,
      user: {
        id: invitation.invitee_id,
        name: `${invitation.first_name} ${invitation.last_name}`.trim() || invitation.username || '未知用户',
        email: invitation.email || '',
        username: invitation.username || ''
      }
    }));
    
    // 确保创建者在成员列表中
    const creatorMember = dbMembers.find(member => member.user_id === trip.user_id);
    
    // 如果创建者不在成员列表中（可能是trip_participants表中没有），则添加
    let allMembers = [...dbMembers];
    if (!creatorMember) {
      // 添加创建者，使用与dbMembers一致的结构，并标记为创建者
      allMembers.unshift({
        id: trip.user_id,
        trip_id: trip.trip_id,
        user_id: trip.user_id,
        is_admin: true,
        is_creator: true, // 标记是否为创建者
        invitation_status: 'creator', // 创建者特殊状态
        joined_at: trip.created_at,
        user: {
          id: trip.user_id,
          name: `${trip.first_name} ${trip.last_name}`.trim() || trip.username || '未知用户',
          email: trip.email || '',
          username: trip.username || ''
        }
      });
    }
    
    // 添加待处理邀请
    allMembers = [...allMembers, ...pendingMembers];
    
    // 去重，确保每个用户只有一个条目
    const uniqueMembers = Array.from(new Map(allMembers.map(member => [member.user_id, member])).values());
    
    members = uniqueMembers;
  } catch (memberError) {
    console.error(`获取旅行 ${trip.trip_id} 成员失败:`, memberError);
    // 如果获取失败，至少包含创建者
    members = [{
      id: trip.user_id,
      trip_id: trip.trip_id,
      user_id: trip.user_id,
      is_admin: true,
      is_creator: true,
      invitation_status: 'creator',
      joined_at: trip.created_at,
      user: {
        id: trip.user_id,
        name: `${trip.first_name} ${trip.last_name}`.trim(),
        email: trip.email,
        username: trip.username
      }
    }];
  }
  
  return members;
}

// 获取旅行列表
app.get('/api/trips', authenticateToken, async (req, res) => {
  try {
    // 从认证信息中获取当前用户ID
    const currentUserId = req.user.id;
    
    // 查询用户创建的旅行或作为参与者的旅行
    const userTripsResult = await sequelize.query(
      `SELECT t.*, u.first_name, u.last_name, u.username, u.email 
       FROM trips t 
       LEFT JOIN users u ON t.user_id = u.user_id 
       WHERE t.user_id = :currentUserId OR t.trip_id IN (
         SELECT tp.trip_id FROM trip_participants tp WHERE tp.user_id = :currentUserId
       )
       ORDER BY t.updated_at DESC`,
      { 
        replacements: { currentUserId },
        type: Sequelize.QueryTypes.SELECT
      }
    );
    
    // 处理查询结果，确保是一维数组
    const tripsToProcess = Array.isArray(userTripsResult) 
      ? Array.isArray(userTripsResult[0]) 
        ? userTripsResult[0] 
        : userTripsResult 
      : [];
    
    // 处理每个旅行，获取完整的成员信息
    const trips = [];
    for (const trip of tripsToProcess) {
      // 使用辅助函数获取成员列表
      const members = await getTripMembersWithPending(trip, sequelize);
      
      // 添加旅行到结果列表
      trips.push({
        id: trip.trip_id,
        name: trip.name,
        description: trip.description,
        start_date: trip.start_date,
        end_date: trip.end_date,
        location: trip.destination,
        is_active: true,
        creator_id: trip.user_id,
        creator_name: `${trip.first_name} ${trip.last_name}`.trim(),
        created_at: trip.created_at,
        updated_at: trip.updated_at,
        members: members // 返回完整的成员列表
      });
    }
    
    res.json(trips);
  } catch (error) {
    console.error('获取旅行列表失败:', error);
    // 如果是表不存在的错误，返回空数组
    if (error.code === 'ER_NO_SUCH_TABLE') {
      res.json([]);
    } else {
      res.status(500).json({ message: '获取旅行列表失败' });
    }
  }
});

// 创建旅行
app.post('/api/trips', authenticateToken, async (req, res) => {
  try {
    const { name, description, start_date, end_date, location, destination, members = [] } = req.body;
    
    // 从认证信息中获取当前用户ID
    const currentUserId = req.user.id;
    
    // 使用UUID生成trip_id
    const { v4: uuidv4 } = require('uuid');
    const tripId = uuidv4();
    
    // 开始事务
    await sequelize.transaction(async (transaction) => {
      // 创建旅行 - 使用正确的列名，同时支持location和destination字段
      const newTrip = await Trip.create({
        trip_id: tripId,
        user_id: currentUserId,
        name,
        description,
        destination: destination || location, // 使用正确的列名，优先使用destination
        start_date,
        end_date,
        created_at: new Date(),
        updated_at: new Date()
      }, { transaction });
      
      // 使用UUID生成id
      const tripParticipantId = uuidv4();
      
      // 添加创建者为旅行成员
      await sequelize.query(
        `INSERT INTO trip_participants 
         (participant_id, trip_id, user_id, joined_at) 
         VALUES (?, ?, ?, ?)`,
        { 
          replacements: [
            tripParticipantId, 
            tripId, 
            currentUserId, 
            new Date()
          ],
          type: Sequelize.QueryTypes.INSERT,
          transaction
        }
      );
      
      // 添加选中的成员
      for (const memberId of members) {
        const memberParticipantId = uuidv4();
        await sequelize.query(
          `INSERT INTO trip_participants 
           (participant_id, trip_id, user_id, joined_at) 
           VALUES (?, ?, ?, ?)`,
          { 
            replacements: [
              memberParticipantId, 
              tripId, 
              memberId, 
              new Date()
            ],
            type: Sequelize.QueryTypes.INSERT,
            transaction
          }
        );
      }
      
      // 转换为前端期望的格式
      const responseTrip = {
        id: newTrip.trip_id,
        name: newTrip.name,
        description: newTrip.description,
        start_date: newTrip.start_date,
        end_date: newTrip.end_date,
        location: newTrip.destination, // 转换回前端期望的字段名
        is_active: true,
        creator_id: newTrip.user_id,
        created_at: newTrip.created_at,
        updated_at: newTrip.updated_at,
        members: [{ // 返回包含创建者的成员列表
          id: tripParticipantId,
          trip_id: tripId,
          user_id: currentUserId,
          is_admin: true,
          is_creator: true,
          invitation_status: 'creator',
          joined_at: new Date(),
          user: {
            id: currentUserId,
            name: `${newTrip.creator?.first_name || ''} ${newTrip.creator?.last_name || ''}`.trim(),
            email: newTrip.creator?.email || '',
            username: newTrip.creator?.username || ''
          }
        }]
      };
      
      res.json(responseTrip);
    });
  } catch (error) {
    console.error('创建旅行失败:', error);
    res.status(500).json({ message: '创建旅行失败' });
  }
});

// 获取旅行详情
app.get('/api/trips/:id', authenticateToken, async (req, res) => {
  try {
    const tripId = req.params.id; // 不再转换为整数，因为实际是字符串UUID
    
    const trip = await Trip.findByPk(tripId, {
      include: [
        {
          model: User,
          as: 'creator'
        }
      ]
    });
    
    if (!trip) return res.status(404).json({ message: '旅行未找到' });
    
    let members = [];
    
    // 尝试获取旅行的所有成员，如果表不存在则返回包含创建者的列表
    try {
      // 使用raw query避免模型定义问题
      const queryResult = await sequelize.query(
        `SELECT tp.*, u.user_id, u.first_name, u.last_name, u.username, u.email 
         FROM trip_participants tp 
         LEFT JOIN users u ON tp.user_id = u.user_id 
         WHERE tp.trip_id = :tripId`,
        { replacements: { tripId }, type: Sequelize.QueryTypes.SELECT }
      );
      
      // 确保tripMembers是一维数组
      const tripMembers = Array.isArray(queryResult) 
        ? Array.isArray(queryResult[0]) 
          ? queryResult[0] 
          : queryResult 
        : [];
      
      // 查询待处理的邀请
      let pendingInvitations = [];
      try {
        const invitationsResult = await sequelize.query(
          `SELECT ti.*, u.user_id, u.first_name, u.last_name, u.username, u.email 
           FROM trip_invitations ti 
           LEFT JOIN users u ON ti.invitee_id = u.user_id 
           WHERE ti.trip_id = :tripId AND ti.status = 'pending'`,
          { replacements: { tripId }, type: Sequelize.QueryTypes.SELECT }
        );
        
        if (Array.isArray(invitationsResult)) {
          if (Array.isArray(invitationsResult[0]) && invitationsResult.length === 2) {
            pendingInvitations = invitationsResult[0] || [];
          } else {
            pendingInvitations = invitationsResult || [];
          }
        } else {
          pendingInvitations = [];
        }
      } catch (inviteError) {
        console.error('查询旅行待处理邀请失败:', inviteError);
        pendingInvitations = [];
      }
      
      // 转换数据库查询到的成员
      const dbMembers = tripMembers.map(member => ({
        id: member.participant_id,
        trip_id: member.trip_id,
        user_id: member.user_id,
        is_admin: member.user_id === trip.user_id, // 创建者是管理员
        is_creator: member.user_id === trip.user_id, // 标记是否为创建者
        invitation_status: member.user_id === trip.user_id ? 'creator' : 'accepted', // 创建者特殊状态
        joined_at: member.joined_at,
        user: {
          id: member.user_id,
          name: `${member.first_name} ${member.last_name}`.trim() || member.username || '未知用户',
          email: member.email || '',
          username: member.username || ''
        }
      }));
      
      // 转换待处理邀请为成员格式
      const pendingMembers = pendingInvitations.map(invitation => ({
        id: invitation.invitation_id,
        trip_id: invitation.trip_id,
        user_id: invitation.invitee_id,
        is_admin: false,
        invitation_status: 'pending',
        joined_at: null,
        user: {
          id: invitation.invitee_id,
          name: `${invitation.first_name} ${invitation.last_name}`.trim() || invitation.username || '未知用户',
          email: invitation.email || '',
          username: invitation.username || ''
        }
      }));
      
      // 确保创建者在成员列表中
      const creatorMember = dbMembers.find(member => member.user_id === trip.user_id);
      
      // 如果创建者不在成员列表中（可能是trip_participants表中没有），则添加
      let allMembers = [...dbMembers];
      if (!creatorMember) {
        allMembers.unshift({
          id: trip.user_id,
          trip_id: trip.trip_id,
          user_id: trip.user_id,
          is_admin: true,
          is_creator: true,
          invitation_status: 'creator',
          joined_at: trip.created_at,
          user: {
            id: trip.user_id,
            name: `${trip.creator.first_name} ${trip.creator.last_name}`.trim(),
            email: trip.creator.email,
            username: trip.creator.username
          }
        });
      }
      
      // 添加待处理邀请
      allMembers = [...allMembers, ...pendingMembers];
      
      // 去重，确保每个用户只有一个条目
      const uniqueMembers = Array.from(new Map(allMembers.map(member => [member.user_id, member])).values());
      
      members = uniqueMembers;
    } catch (memberError) {
      if (memberError.code === 'ER_NO_SUCH_TABLE') {
        console.log('trip_members 表不存在，只返回创建者');
        // 只返回创建者作为成员
        members = [{
          id: trip.user_id,
          trip_id: trip.trip_id,
          user_id: trip.user_id,
          is_admin: true,
          is_creator: true,
          invitation_status: 'creator',
          joined_at: trip.created_at,
          user: {
            id: trip.creator.user_id,
            name: `${trip.creator.first_name} ${trip.creator.last_name}`.trim(),
            email: trip.creator.email,
            username: trip.creator.username
          }
        }];
      } else {
        console.error('获取旅行成员失败:', memberError);
        // 至少返回创建者作为成员
        members = [{
          id: trip.user_id,
          trip_id: trip.trip_id,
          user_id: trip.user_id,
          is_admin: true,
          invitation_status: 'accepted',
          joined_at: trip.created_at,
          user: {
            id: trip.creator.user_id,
            name: `${trip.creator.first_name} ${trip.creator.last_name}`.trim(),
            email: trip.creator.email,
            username: trip.creator.username
          }
        }];
      }
    }
    
    // 转换为前端期望的格式
    const responseTrip = {
      id: trip.trip_id,
      name: trip.name,
      description: trip.description,
      start_date: trip.start_date,
      end_date: trip.end_date,
      location: trip.destination, // 转换回前端期望的字段名
      is_active: true,
      creator_id: trip.user_id,
      creator_name: trip.creator ? `${trip.creator.first_name} ${trip.creator.last_name}`.trim() : '未知用户',
      created_at: trip.created_at,
      updated_at: trip.updated_at,
      members: members // 返回完整的成员列表，包含用户信息
    };
    
    res.json(responseTrip);
  } catch (error) {
    console.error('获取旅行详情失败:', error);
    res.status(500).json({ message: '获取旅行详情失败' });
  }
});

// 更新旅行
app.put('/api/trips/:id', authenticateToken, async (req, res) => {
  try {
    const tripId = req.params.id;
    const { name, description, start_date, end_date, location } = req.body;
    const currentUserId = req.user.id;
    
    // 检查当前用户是否有权限更新该旅行
    const trip = await Trip.findByPk(tripId);
    if (!trip) {
      return res.status(404).json({ message: '旅行未找到' });
    }
    
    // 只有创建者才能更新旅行
    if (trip.user_id !== currentUserId) {
      return res.status(403).json({ message: '没有权限更新该旅行' });
    }
    
    // 更新旅行信息
    const rowsUpdated = await Trip.update(
      {
        name,
        description,
        start_date,
        end_date,
        destination: location,
        updated_at: new Date()
      },
      {
        where: { trip_id: tripId }
      }
    );
    
    if (rowsUpdated === 0) {
      return res.status(404).json({ message: '旅行未找到' });
    }
    
    // 获取更新后的旅行信息
    const updatedTrip = await Trip.findByPk(tripId, {
      include: [
        {
          model: User,
          as: 'creator'
        }
      ]
    });
    
    // 转换为前端期望的格式
    const responseTrip = {
      id: updatedTrip.trip_id,
      name: updatedTrip.name,
      description: updatedTrip.description,
      start_date: updatedTrip.start_date,
      end_date: updatedTrip.end_date,
      location: updatedTrip.destination,
      is_active: true,
      creator_id: updatedTrip.user_id,
      creator_name: updatedTrip.creator ? `${updatedTrip.creator.first_name} ${updatedTrip.creator.last_name}`.trim() : '未知用户',
      created_at: updatedTrip.created_at,
      updated_at: updatedTrip.updated_at,
      members: []
    };
    
    res.json(responseTrip);
  } catch (error) {
    console.error('更新旅行失败:', error);
    res.status(500).json({ message: '更新旅行失败' });
  }
});

// 获取旅行费用列表
app.get('/api/trips/:tripId/expenses', authenticateToken, async (req, res) => {
  try {
    const tripId = req.params.tripId; // 直接使用字符串UUID
    
    // 从数据库中查询旅行的所有费用
    const expenses = await Expense.findAll({
      where: { trip_id: tripId },
      order: [['created_at', 'DESC']] // 按创建时间倒序
    });
    
    // 转换为前端期望的格式
    const responseExpenses = expenses.map(expense => {
      let shares = [];
      let shareUserIds = [];
      
      try {
        if (expense.split_details) {
          // 处理split_details，它可能是字符串或数组
          if (typeof expense.split_details === 'string') {
            // 如果是字符串，尝试解析为JSON数组
            shareUserIds = JSON.parse(expense.split_details);
          } else if (Array.isArray(expense.split_details)) {
            // 如果已经是数组，直接使用
            shareUserIds = expense.split_details;
          } else if (expense.split_details instanceof Buffer) {
            // 如果是Buffer，尝试转换为字符串再解析
            shareUserIds = JSON.parse(expense.split_details.toString());
          } else {
            // 其他情况，尝试转换为字符串再解析
            shareUserIds = JSON.parse(JSON.stringify(expense.split_details));
          }
          
          // 确保shareUserIds是数组
          if (!Array.isArray(shareUserIds)) {
            shareUserIds = [shareUserIds];
          }
          
          // 去除重复的user_id
          shareUserIds = [...new Set(shareUserIds)];
          
          // 构建前端期望的shares格式
          const perPersonAmount = parseFloat(expense.amount) / Math.max(shareUserIds.length, 1);
          shares = shareUserIds.map(userId => ({
            id: `${expense.expense_id}-${userId}`,
            expense_id: expense.expense_id,
            user_id: userId,
            amount: perPersonAmount,
            user: null // 用户信息将由前端通过userId查询
          }));
        }
      } catch (error) {
        console.error('解析split_details失败:', error);
        shares = [];
      }
      
      return {
        id: expense.expense_id,
        trip_id: expense.trip_id,
        description: expense.description,
        amount: parseFloat(expense.amount),
        currency: expense.currency,
        category: expense.category,
        date: expense.date,
        payer_id: expense.paid_by,
        created_by: expense.created_by,
        created_at: expense.created_at,
        updated_at: expense.updated_at,
        shares: shares
      };
    });
    
    res.json(responseExpenses);
  } catch (error) {
    console.error('获取旅行费用列表失败:', error);
    // 发生错误时返回空数组，避免前端出现错误
    res.json([]);
  }
});

// 创建旅行费用
app.post('/api/trips/:tripId/expenses', authenticateToken, async (req, res) => {
  try {
    const tripId = req.params.tripId; // 直接使用字符串UUID
    const { description, amount, payer_id, shares = [], category, currency = 'CNY', date } = req.body;
    const currentUserId = req.user.id;
    
    // 检查当前用户是否是该旅行的成员
    const isMemberResult = await sequelize.query(
      `SELECT * FROM trip_participants WHERE trip_id = :tripId AND user_id = :userId`,
      { 
        replacements: { tripId, userId: currentUserId },
        type: Sequelize.QueryTypes.SELECT 
      }
    );
    
    // 确保isMember是一维数组
    const isMember = Array.isArray(isMemberResult) 
      ? Array.isArray(isMemberResult[0]) 
        ? isMemberResult[0] 
        : isMemberResult 
      : [];
    
    if (isMember.length === 0) {
      return res.status(403).json({ message: '没有权限添加费用' });
    }
    
    // 使用UUID生成expense_id
    const { v4: uuidv4 } = require('uuid');
    const expenseId = uuidv4();
    
    // 验证日期格式
    const formattedDate = date ? new Date(date) : new Date();
    if (isNaN(formattedDate.getTime())) {
      return res.status(400).json({ message: '日期格式无效' });
    }
    
    // 创建费用
    const newExpense = await Expense.create({
      expense_id: expenseId,
      trip_id: tripId,
      description,
      amount,
      currency,
      category,
      date: formattedDate,
      paid_by: payer_id, // 使用正确的字段名
      split_method: 'equal', // 默认等分
      split_details: shares.length > 0 ? shares : [{ user_id: payer_id, amount: amount }],
      created_by: req.user.id,
      created_at: new Date(),
      updated_at: new Date()
    });
    
    // 计算人均金额，确保总是创建分摊记录
    const sharesToUse = shares.length > 0 ? shares : [payer_id];
    const perPersonAmount = parseFloat(amount) / sharesToUse.length;
    
    // 创建费用分摊记录
    const expenseShares = [];
    for (const userId of sharesToUse) {
      const shareId = uuidv4();
      expenseShares.push({
        expense_share_id: shareId,
        expense_id: expenseId,
        user_id: userId,
        amount: perPersonAmount,
        created_at: new Date(),
        updated_at: new Date()
      });
    }
    
    // 使用raw query插入，避免模型定义问题
    try {
      await sequelize.query(
        `INSERT INTO expense_shares (expense_share_id, expense_id, user_id, amount, created_at, updated_at) VALUES ?`,
        { 
          replacements: [expenseShares.map(share => [
            share.expense_share_id, 
            share.expense_id, 
            share.user_id, 
            share.amount, 
            share.created_at, 
            share.updated_at
          ])],
          type: Sequelize.QueryTypes.INSERT 
        }
      );
    } catch (shareError) {
      console.error('创建费用分摊记录失败:', shareError);
      // 忽略错误，继续执行
    }
    
    // 更新预算使用情况
    // 查找与费用类别匹配的预算
    const [budgetsResult] = await sequelize.query(
      `SELECT * FROM budgets WHERE trip_id = :tripId AND category = :category`,
      {
        replacements: { tripId, category },
        type: Sequelize.QueryTypes.SELECT
      }
    );
    
    // 如果找到匹配的预算，更新其spent字段
    if (budgetsResult && budgetsResult.length > 0) {
      // 计算该类别的总支出
      const [totalSpentResult] = await sequelize.query(
        `SELECT SUM(amount) as total_spent 
         FROM expenses 
         WHERE trip_id = :tripId AND category = :category`,
        {
          replacements: { tripId, category },
          type: Sequelize.QueryTypes.SELECT
        }
      );
      
      // 更新预算的spent字段
      await sequelize.query(
        `UPDATE budgets 
         SET spent = :totalSpent, 
             updated_at = NOW() 
         WHERE trip_id = :tripId AND category = :category`,
        {
          replacements: {
            tripId,
            category,
            totalSpent: totalSpentResult[0]?.total_spent || 0
          },
          type: Sequelize.QueryTypes.UPDATE
        }
      );
    }
    
    // 获取创建的费用详情
    const createdExpenseResult = await sequelize.query(
      `SELECT e.*, u.user_id, u.first_name, u.last_name, u.username, u.email 
       FROM expenses e 
       LEFT JOIN users u ON e.paid_by = u.user_id 
       WHERE e.expense_id = ?`,
      { replacements: [expenseId], type: Sequelize.QueryTypes.SELECT }
    );
    
    // 确保createdExpense是有效的
    const createdExpenseArray = Array.isArray(createdExpenseResult) 
      ? Array.isArray(createdExpenseResult[0]) 
        ? createdExpenseResult[0] 
        : createdExpenseResult 
      : [];
    
    const createdExpense = createdExpenseArray[0];
    
    // 转换为前端期望的格式
    const responseExpense = {
      id: createdExpense.expense_id,
      trip_id: createdExpense.trip_id,
      description: createdExpense.description,
      amount: parseFloat(createdExpense.amount) || 0,
      currency: createdExpense.currency || 'CNY',
      category: createdExpense.category,
      date: createdExpense.date,
      paid_by: createdExpense.paid_by,
      payer_id: createdExpense.paid_by,
      created_at: createdExpense.created_at,
      updated_at: createdExpense.updated_at,
      payer: createdExpense.user_id ? {
        id: createdExpense.user_id,
        name: `${createdExpense.first_name} ${createdExpense.last_name}`.trim(),
        email: createdExpense.email,
        username: createdExpense.username
      } : null,
      shares: shares.map(userId => ({
        id: `${expenseId}-${userId}`,
        expense_id: expenseId,
        user_id: userId,
        amount: parseFloat(amount) / Math.max(shares.length, 1),
        user: null // 暂时不包含用户详情，前端可以通过user_id查询
      }))
    };
    
    res.json(responseExpense);
  } catch (error) {
    console.error('创建旅行费用失败:', error);
    res.status(500).json({ message: '创建费用失败' });
  }
});

// 获取单个旅行费用详情
app.get('/api/trips/:tripId/expenses/:expenseId', authenticateToken, async (req, res) => {
  try {
    const tripId = req.params.tripId;
    const expenseId = req.params.expenseId;
    
    // 查询费用详情
    const expenseResult = await sequelize.query(
      `SELECT e.*, u.user_id, u.first_name, u.last_name, u.username, u.email 
       FROM expenses e 
       LEFT JOIN users u ON e.paid_by = u.user_id 
       WHERE e.expense_id = :expenseId AND e.trip_id = :tripId`,
      { 
        replacements: { expenseId, tripId },
        type: Sequelize.QueryTypes.SELECT 
      }
    );
    
    // 确保expense是有效的
    const expenseArray = Array.isArray(expenseResult) 
      ? Array.isArray(expenseResult[0]) 
        ? expenseResult[0] 
        : expenseResult 
      : [];
    
    if (expenseArray.length === 0) {
      return res.status(404).json({ message: '费用未找到' });
    }
    
    const expense = expenseArray[0];
    
    // 获取分担人列表
    let shares = [];
    let shareUserIds = [];
    
    // 检查split_details字段
    if (expense.split_details) {
      // 处理split_details，它可能是字符串或数组
      try {
        if (typeof expense.split_details === 'string') {
          // 如果是字符串，尝试解析为JSON数组
          shareUserIds = JSON.parse(expense.split_details);
        } else if (Array.isArray(expense.split_details)) {
          // 如果已经是数组，直接使用
          shareUserIds = expense.split_details;
        } else if (expense.split_details instanceof Buffer) {
          // 如果是Buffer，尝试转换为字符串再解析
          shareUserIds = JSON.parse(expense.split_details.toString());
        } else {
          // 其他情况，尝试转换为字符串再解析
          shareUserIds = JSON.parse(JSON.stringify(expense.split_details));
        }
        
        // 确保shareUserIds是数组
        if (!Array.isArray(shareUserIds)) {
          shareUserIds = [shareUserIds];
        }
      } catch (parseError) {
        console.error('解析split_details失败:', parseError);
        // 如果解析失败，默认使用支付人作为唯一分担人
        shareUserIds = [expense.paid_by];
      }
    } else {
      // 如果split_details为空，默认使用支付人作为唯一分担人
      shareUserIds = [expense.paid_by];
    }
    
    // 去除重复的user_id
    shareUserIds = [...new Set(shareUserIds)];
    
    // 查询所有分担人的用户信息
    if (shareUserIds.length > 0) {
      try {
        const usersResult = await sequelize.query(
          `SELECT u.user_id, u.first_name, u.last_name, u.username 
           FROM users u 
           WHERE u.user_id IN (:userIds)`,
          { 
            replacements: { userIds: shareUserIds },
            type: Sequelize.QueryTypes.SELECT 
          }
        );
        
        // 确保users是有效的
        const usersArray = Array.isArray(usersResult) 
          ? Array.isArray(usersResult[0]) 
            ? usersResult[0] 
            : usersResult 
          : [];
        
        // 构建用户映射表
        const userMap = new Map();
        usersArray.forEach(user => {
          userMap.set(user.user_id, {
            id: user.user_id,
            name: `${user.first_name} ${user.last_name}`.trim() || user.username || '未知用户',
            username: user.username
          });
        });
        
        // 计算人均金额
        const perPersonAmount = parseFloat(expense.amount) / Math.max(shareUserIds.length, 1);
        
        // 构建分担人列表
        shares = shareUserIds.map(userId => ({
          id: `${expense.expense_id}-${userId}`,
          expense_id: expense.expense_id,
          user_id: userId,
          amount: perPersonAmount,
          user: userMap.get(userId) || {
            id: userId,
            name: '未知用户',
            username: ''
          }
        }));
      } catch (usersError) {
        console.error('获取用户信息失败:', usersError);
        // 如果获取用户信息失败，创建简单的分担人列表
        shares = shareUserIds.map(userId => ({
          id: `${expense.expense_id}-${userId}`,
          expense_id: expense.expense_id,
          user_id: userId,
          amount: parseFloat(expense.amount) / Math.max(shareUserIds.length, 1),
          user: {
            id: userId,
            name: '未知用户',
            username: ''
          }
        }));
      }
    } else {
      // 如果没有分担人，默认使用支付人
      shares = [{
        id: `${expense.expense_id}-${expense.paid_by}`,
        expense_id: expense.expense_id,
        user_id: expense.paid_by,
        amount: parseFloat(expense.amount),
        user: expense.user_id ? {
          id: expense.user_id,
          name: `${expense.first_name} ${expense.last_name}`.trim(),
          username: expense.username
        } : {
          id: expense.paid_by,
          name: '未知用户',
          username: ''
        }
      }];
    }
    
    // 转换为前端期望的格式
    const responseExpense = {
      id: expense.expense_id,
      trip_id: expense.trip_id,
      description: expense.description,
      amount: parseFloat(expense.amount) || 0,
      currency: expense.currency || 'CNY',
      category: expense.category,
      date: expense.date,
      paid_by: expense.paid_by,
      payer_id: expense.paid_by,
      created_at: expense.created_at,
      updated_at: expense.updated_at,
      payer: expense.user_id ? {
        id: expense.user_id,
        name: `${expense.first_name} ${expense.last_name}`.trim(),
        email: expense.email,
        username: expense.username
      } : null,
      shares: shares
    };
    
    console.log('返回的费用详情:', responseExpense);
    
    res.json(responseExpense);
  } catch (error) {
    console.error('获取旅行费用详情失败:', error);
    res.status(500).json({ message: '获取费用详情失败' });
  }
});

// 更新旅行费用
app.put('/api/trips/:tripId/expenses/:expenseId', authenticateToken, async (req, res) => {
  try {
    const tripId = req.params.tripId;
    const expenseId = req.params.expenseId;
    const { description, amount, category, currency, payer_id, shares = [], date } = req.body;
    
    // 验证日期格式
    const formattedDate = date ? new Date(date) : new Date();
    if (isNaN(formattedDate.getTime())) {
      return res.status(400).json({ message: '日期格式无效' });
    }
    
    // 如果shares为空，使用支付人作为唯一分担人
    const sharesToUse = shares.length > 0 ? shares : [payer_id];
    
    // 开始事务
    await sequelize.transaction(async (transaction) => {
      // 更新费用基本信息，包括split_details
      await Expense.update(
        {
          description,
          amount,
          category,
          currency,
          paid_by: payer_id,
          date: formattedDate,
          split_details: sharesToUse, // 更新split_details字段，存储分担人列表
          updated_at: new Date()
        },
        {
          where: { expense_id: expenseId, trip_id: tripId },
          transaction
        }
      );
      
      // 获取更新后的费用详情
      const updatedExpenseResult = await sequelize.query(
        `SELECT e.*, u.user_id, u.first_name, u.last_name, u.username, u.email 
         FROM expenses e 
         LEFT JOIN users u ON e.paid_by = u.user_id 
         WHERE e.expense_id = :expenseId AND e.trip_id = :tripId`,
        { 
          replacements: { expenseId, tripId },
          type: Sequelize.QueryTypes.SELECT,
          transaction 
        }
      );
      
      // 确保expense是有效的
      const updatedExpenseArray = Array.isArray(updatedExpenseResult) 
        ? Array.isArray(updatedExpenseResult[0]) 
          ? updatedExpenseResult[0] 
          : updatedExpenseResult 
        : [];
      
      const updatedExpense = updatedExpenseArray[0];
      
      // 查询所有相关用户信息
      const allUserIds = [...new Set([...sharesToUse, updatedExpense.paid_by])];
      const usersResult = await sequelize.query(
        `SELECT u.user_id, u.first_name, u.last_name, u.username 
         FROM users u 
         WHERE u.user_id IN (:userIds)`,
        { 
          replacements: { userIds: allUserIds },
          type: Sequelize.QueryTypes.SELECT,
          transaction 
        }
      );
      
      // 确保users是有效的
      const usersArray = Array.isArray(usersResult) 
        ? Array.isArray(usersResult[0]) 
          ? usersResult[0] 
          : usersResult 
        : [];
      
      // 构建用户映射表
      const userMap = new Map();
      usersArray.forEach(user => {
        userMap.set(user.user_id, {
          id: user.user_id,
          name: `${user.first_name} ${user.last_name}`.trim() || user.username || '未知用户',
          username: user.username
        });
      });
      
      // 构建分担人列表
      const perPersonAmount = parseFloat(amount) / Math.max(sharesToUse.length, 1);
      const updatedShares = sharesToUse.map(userId => ({
        id: `${expenseId}-${userId}`,
        expense_id: expenseId,
        user_id: userId,
        amount: perPersonAmount,
        user: userMap.get(userId) || {
          id: userId,
          name: '未知用户',
          username: ''
        }
      }));
      
      // 转换为前端期望的格式
      const responseExpense = {
        id: updatedExpense.expense_id,
        trip_id: updatedExpense.trip_id,
        description: updatedExpense.description,
        amount: parseFloat(updatedExpense.amount) || 0,
        currency: updatedExpense.currency || 'CNY',
        category: updatedExpense.category,
        date: updatedExpense.date,
        paid_by: updatedExpense.paid_by,
        payer_id: updatedExpense.paid_by,
        created_at: updatedExpense.created_at,
        updated_at: updatedExpense.updated_at,
        payer: userMap.get(updatedExpense.paid_by) || null,
        shares: updatedShares
      };
      
      res.json(responseExpense);
    });
  } catch (error) {
    console.error('更新旅行费用失败:', error);
    res.status(500).json({ message: '更新费用失败' });
  }
});

// 获取旅行成员列表
app.get('/api/trips/:tripId/members', authenticateToken, async (req, res) => {
  try {
    const tripId = req.params.tripId; // 使用字符串UUID
    
    // 首先获取旅行信息，包括创建者
    const trip = await Trip.findByPk(tripId, {
      include: [
        {
          model: User,
          as: 'creator'
        }
      ]
    });
    
    if (!trip) {
      return res.status(404).json({ message: '旅行未找到' });
    }
    
    // 使用raw query避免模型定义问题
    let tripMembers = [];
    try {
      console.log('[API] 查询旅行成员列表，tripId:', tripId);
      // sequelize.query() 对于 SELECT 查询返回结果数组
      const queryResult = await sequelize.query(
        `SELECT tp.*, u.user_id, u.first_name, u.last_name, u.username, u.email 
         FROM trip_participants tp 
         LEFT JOIN users u ON tp.user_id = u.user_id 
         WHERE tp.trip_id = :tripId`,
        { replacements: { tripId }, type: Sequelize.QueryTypes.SELECT }
      );
      
      // 确保tripMembers是一个可迭代的数组
      if (Array.isArray(queryResult)) {
        // 检查是否是二维数组
        if (Array.isArray(queryResult[0]) && queryResult.length === 2) {
          // 如果是 [results, metadata] 格式，取第一个元素
          tripMembers = queryResult[0] || [];
        } else {
          // 否则直接使用结果
          tripMembers = queryResult || [];
        }
      } else {
        // 如果不是数组，设置为空数组
        tripMembers = [];
      }
      
      console.log('[API] 查询旅行成员列表成功，结果类型:', typeof tripMembers);
      console.log('[API] 查询旅行成员列表成功，是否数组:', Array.isArray(tripMembers));
      console.log('[API] 查询旅行成员列表成功，结果:', JSON.stringify(tripMembers));
    } catch (queryError) {
      console.error('查询旅行成员列表失败:', queryError);
      // 如果是表不存在的错误，返回空数组
      if (queryError.code === 'ER_NO_SUCH_TABLE') {
        tripMembers = [];
      } else {
        throw queryError;
      }
    }
    
    // 查询待处理的邀请
    let pendingInvitations = [];
    try {
      console.log('[API] 查询旅行待处理邀请，tripId:', tripId);
      const invitationsResult = await sequelize.query(
        `SELECT ti.*, u.user_id, u.first_name, u.last_name, u.username, u.email 
         FROM trip_invitations ti 
         LEFT JOIN users u ON ti.invitee_id = u.user_id 
         WHERE ti.trip_id = :tripId AND ti.status = 'pending'`,
        { replacements: { tripId }, type: Sequelize.QueryTypes.SELECT }
      );
      
      if (Array.isArray(invitationsResult)) {
        if (Array.isArray(invitationsResult[0]) && invitationsResult.length === 2) {
          pendingInvitations = invitationsResult[0] || [];
        } else {
          pendingInvitations = invitationsResult || [];
        }
      } else {
        pendingInvitations = [];
      }
      
      console.log('[API] 查询旅行待处理邀请成功，结果:', JSON.stringify(pendingInvitations));
    } catch (inviteError) {
      console.error('查询旅行待处理邀请失败:', inviteError);
      pendingInvitations = [];
    }
    
    // 添加创建者为默认成员
    const creatorAsMember = {
      id: trip.user_id,
      trip_id: trip.trip_id,
      user_id: trip.user_id,
      is_admin: true,
      is_creator: true,
      invitation_status: 'creator',
      joined_at: trip.created_at,
      first_name: trip.creator.first_name,
      last_name: trip.creator.last_name,
      username: trip.creator.username,
      email: trip.creator.email
    };
    
    // 合并成员列表，避免重复
    console.log('[API] 开始合并成员列表，creatorAsMember:', JSON.stringify(creatorAsMember));
    console.log('[API] tripMembers类型:', typeof tripMembers);
    console.log('[API] tripMembers是否数组:', Array.isArray(tripMembers));
    
    // 确保tripMembers是一个可迭代的数组
    const safeTripMembers = Array.isArray(tripMembers) ? tripMembers : [];
    console.log('[API] safeTripMembers:', JSON.stringify(safeTripMembers));
    
    // 转换待处理邀请为成员格式
    const pendingMembers = pendingInvitations.map(invitation => ({
      id: invitation.invitation_id,
      trip_id: invitation.trip_id,
      user_id: invitation.invitee_id,
      is_admin: false,
      invitation_status: 'pending',
      joined_at: null,
      first_name: invitation.first_name,
      last_name: invitation.last_name,
      username: invitation.username,
      email: invitation.email
    }));
    console.log('[API] 转换后的待处理成员:', JSON.stringify(pendingMembers));
    
    // 合并所有成员，包括创建者、已加入成员和待处理邀请
    const allMembers = [creatorAsMember, ...safeTripMembers, ...pendingMembers];
    console.log('[API] allMembers:', JSON.stringify(allMembers));
    
    // 去重，使用user_id作为唯一键
    const uniqueMembers = Array.from(new Map(allMembers.map(member => [member.user_id, member])).values());
    console.log('[API] uniqueMembers:', JSON.stringify(uniqueMembers));
    
    // 转换为前端期望的格式
    const responseMembers = uniqueMembers.map(member => ({
      id: member.id || member.trip_member_id || member.user_id,
      trip_id: member.trip_id || tripId,
      user_id: member.user_id,
      is_admin: member.is_admin || false,
      is_creator: member.is_creator || member.user_id === trip.user_id,
      invitation_status: member.invitation_status || (member.user_id === trip.user_id ? 'creator' : 'accepted'),
      joined_at: member.joined_at || trip.created_at,
      user: {
        id: member.user_id,
        name: `${member.first_name} ${member.last_name}`.trim(),
        email: member.email,
        username: member.username
      }
    }));
    
    res.json(responseMembers);
  } catch (error) {
    console.error('获取旅行成员列表失败:', error);
    // 如果出现错误，返回包含当前用户的成员列表
    try {
      // 获取当前用户信息
      const currentUserId = req.user.id;
      const currentUser = await User.findByPk(currentUserId);
      
      if (currentUser) {
        // 返回包含当前用户的成员列表
        res.json([{
          id: currentUserId,
          trip_id: req.params.tripId,
          user_id: currentUserId,
          is_admin: true,
          invitation_status: 'accepted',
          joined_at: new Date(),
          user: {
            id: currentUserId,
            name: `${currentUser.first_name} ${currentUser.last_name}`.trim(),
            email: currentUser.email,
            username: currentUser.username
          }
        }]);
      } else {
        // 如果无法获取当前用户，返回空数组
        res.json([]);
      }
    } catch (userError) {
      // 如果获取当前用户也失败，返回空数组
      res.json([]);
    }
  }
});

// 接受邀请
app.put('/api/invitations/:invitationId/accept', authenticateToken, async (req, res) => {
  console.log('[API] 收到接受邀请请求，invitationId:', req.params.invitationId);
  console.log('[API] 当前用户:', JSON.stringify(req.user));
  
  try {
    const invitationId = req.params.invitationId;
    const currentUserId = req.user.id;
    
    // 开始事务
    await sequelize.transaction(async (transaction) => {
      // 查找邀请记录
      const invitation = await sequelize.query(
        `SELECT * FROM trip_invitations 
         WHERE invitation_id = :invitationId AND invitee_id = :inviteeId AND status = 'pending'`,
        { 
          replacements: { invitationId, inviteeId: currentUserId },
          type: Sequelize.QueryTypes.SELECT,
          transaction
        }
      );
      
      if (!invitation || invitation.length === 0) {
        return res.status(404).json({ message: '邀请未找到或已处理' });
      }
      
      const tripId = invitation[0].trip_id;
      
      // 使用UUID生成participant_id
      const { v4: uuidv4 } = require('uuid');
      const participantId = uuidv4();
      
      // 插入到trip_participants表
      await sequelize.query(
        `INSERT INTO trip_participants 
         (participant_id, trip_id, user_id, joined_at) 
         VALUES (?, ?, ?, ?)`,
        { 
          replacements: [participantId, tripId, currentUserId, new Date()],
          type: Sequelize.QueryTypes.INSERT,
          transaction
        }
      );
      
      // 更新邀请状态为已接受
      await sequelize.query(
        `UPDATE trip_invitations 
         SET status = 'accepted', updated_at = :updatedAt 
         WHERE invitation_id = :invitationId`,
        { 
          replacements: { invitationId, updatedAt: new Date() },
          type: Sequelize.QueryTypes.UPDATE,
          transaction
        }
      );
      
      // 发送通知给邀请者
      await sequelize.query(
        `INSERT INTO notifications 
         (notification_id, user_id, title, message, type, read_status, trip_id, created_at, updated_at) 
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        { 
          replacements: [
            uuidv4(), 
            invitation[0].inviter_id, 
            '邀请已接受', 
            `${req.user.username} 已接受您的行程邀请`, 
            'trip_invite_accepted', 
            0, 
            tripId, 
            new Date(), 
            new Date()
          ],
          type: Sequelize.QueryTypes.INSERT,
          transaction
        }
      );
    });
    
    res.json({ message: '邀请已接受' });
  } catch (error) {
    console.error('接受邀请失败:', error);
    res.status(500).json({ message: '接受邀请失败' });
  }
});

// 获取当前用户的待处理邀请
app.get('/api/invitations/pending', authenticateToken, async (req, res) => {
  console.log('[API] 收到获取待处理邀请请求');
  console.log('[API] 当前用户:', JSON.stringify(req.user));
  
  try {
    const currentUserId = req.user.id;
    
    // 查询当前用户的待处理邀请
    const invitations = await sequelize.query(
      `SELECT ti.*, t.name as trip_name, t.destination, t.start_date, t.end_date, u.username as inviter_username, u.first_name, u.last_name 
       FROM trip_invitations ti 
       LEFT JOIN trips t ON ti.trip_id = t.trip_id 
       LEFT JOIN users u ON ti.inviter_id = u.user_id 
       WHERE ti.invitee_id = :inviteeId AND ti.status = 'pending'`,
      { 
        replacements: { inviteeId: currentUserId },
        type: Sequelize.QueryTypes.SELECT
      }
    );
    
    // 转换邀请数据，确保返回正确的字段名和格式
    const formattedInvitations = invitations.map(invitation => ({
      id: invitation.invitation_id,
      trip_id: invitation.trip_id,
      trip_name: invitation.trip_name,
      trip_destination: invitation.destination,
      trip_start_date: invitation.start_date,
      trip_end_date: invitation.end_date,
      inviter_id: invitation.inviter_id,
      inviter_name: invitation.first_name && invitation.last_name 
        ? `${invitation.first_name} ${invitation.last_name}`.trim() 
        : invitation.inviter_username || '未知用户',
      status: invitation.status,
      created_at: invitation.invited_at || invitation.created_at
    }));
    
    console.log('[API] 查询到的待处理邀请:', JSON.stringify(invitations));
    console.log('[API] 格式化后的待处理邀请:', JSON.stringify(formattedInvitations));
    
    res.json(formattedInvitations);
  } catch (error) {
    console.error('获取待处理邀请失败:', error);
    res.status(500).json({ message: '获取待处理邀请失败' });
  }
});

// 拒绝邀请
app.put('/api/invitations/:invitationId/reject', authenticateToken, async (req, res) => {
  console.log('[API] 收到拒绝邀请请求，invitationId:', req.params.invitationId);
  console.log('[API] 当前用户:', JSON.stringify(req.user));
  
  try {
    const invitationId = req.params.invitationId;
    const currentUserId = req.user.id;
    
    // 开始事务
    await sequelize.transaction(async (transaction) => {
      // 查找邀请记录
      const invitation = await sequelize.query(
        `SELECT * FROM trip_invitations 
         WHERE invitation_id = :invitationId AND invitee_id = :inviteeId AND status = 'pending'`,
        { 
          replacements: { invitationId, inviteeId: currentUserId },
          type: Sequelize.QueryTypes.SELECT,
          transaction
        }
      );
      
      if (!invitation || invitation.length === 0) {
        return res.status(404).json({ message: '邀请未找到或已处理' });
      }
      
      // 更新邀请状态为已拒绝
      await sequelize.query(
        `UPDATE trip_invitations 
         SET status = 'rejected', updated_at = :updatedAt 
         WHERE invitation_id = :invitationId`,
        { 
          replacements: { invitationId, updatedAt: new Date() },
          type: Sequelize.QueryTypes.UPDATE,
          transaction
        }
      );
      
      // 发送通知给邀请者
      await sequelize.query(
        `INSERT INTO notifications 
         (notification_id, user_id, title, message, type, read_status, trip_id, created_at, updated_at) 
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        { 
          replacements: [
            uuidv4(), 
            invitation[0].inviter_id, 
            '邀请已拒绝', 
            `${req.user.username} 已拒绝您的行程邀请`, 
            'trip_invite_rejected', 
            0, 
            invitation[0].trip_id, 
            new Date(), 
            new Date()
          ],
          type: Sequelize.QueryTypes.INSERT,
          transaction
        }
      );
    });
    
    res.json({ message: '邀请已拒绝' });
  } catch (error) {
    console.error('拒绝邀请失败:', error);
    res.status(500).json({ message: '拒绝邀请失败' });
  }
});

// 邀请成员
app.post('/api/trips/:tripId/invite', authenticateToken, async (req, res) => {
  console.log('[API] 收到邀请成员请求，tripId:', req.params.tripId);
  console.log('[API] 请求体:', JSON.stringify(req.body));
  console.log('[API] 当前用户:', JSON.stringify(req.user));
  
  try {
    const tripId = req.params.tripId; // 使用字符串UUID
    const { memberIds = [] } = req.body; // 前端发送的是memberIds数组
    
    console.log('[API] 处理邀请成员，memberIds:', JSON.stringify(memberIds));
    
    if (!Array.isArray(memberIds)) {
      console.error('[API] memberIds不是数组，返回400错误');
      return res.status(400).json({ message: 'memberIds必须是数组' });
    }
    
    const addedMembers = [];
    
    // 处理邀请的成员
    for (const userId of memberIds) {
      console.log('[API] 处理用户邀请，userId:', userId);
      
      try {
        // 查找匹配的用户（通过user_id）
        console.log('[API] 开始查找用户，user_id:', userId);
        const users = await sequelize.query(
          `SELECT * FROM users WHERE user_id = :userId`,
          { 
            replacements: { userId },
            type: Sequelize.QueryTypes.SELECT 
          }
        );
        
        console.log('[API] 用户查询结果:', JSON.stringify(users));
        // 对于SELECT查询，sequelize.query()直接返回结果数组
        const user = Array.isArray(users) ? users[0] : null;
        
        if (user) {
          console.log('[API] 找到用户，user_id:', userId, '用户名:', user.username);
          // 检查是否已经存在邀请记录
          console.log('[API] 检查是否已存在邀请记录，tripId:', tripId, 'userId:', userId);
          // 对于 SELECT 查询，sequelize.query() 返回的是结果数组
          const existingInvitations = await sequelize.query(
            `SELECT invitation_id FROM trip_invitations 
             WHERE trip_id = :tripId AND invitee_id = :inviteeId`,
            { 
              replacements: { tripId, inviteeId: userId },
              type: Sequelize.QueryTypes.SELECT 
            }
          );
          
          // 检查是否存在邀请记录
          const existingInvitation = Array.isArray(existingInvitations) ? existingInvitations[0] : null;
          console.log('[API] 现有邀请记录:', JSON.stringify(existingInvitation));
          
          if (!existingInvitation) {
            console.log('[API] 不存在邀请记录，开始创建邀请');
            // 使用UUID生成trip_participant_id
            const { v4: uuidv4 } = require('uuid');
            const tripParticipantId = uuidv4();
            const invitationId = uuidv4();
            
            console.log('[API] 生成的tripParticipantId:', tripParticipantId, 'invitationId:', invitationId);
            
            // 开始事务
            console.log('[API] 开始事务，创建邀请记录');
            await sequelize.transaction(async (transaction) => {
              // 插入邀请记录到trip_invitations表，使用正确的字段名
              await sequelize.query(
                `INSERT INTO trip_invitations 
                 (invitation_id, trip_id, inviter_id, invitee_id, status, invited_at, updated_at) 
                 VALUES (?, ?, ?, ?, ?, ?, ?)`,
                { 
                  replacements: [
                    invitationId, 
                    tripId, 
                    req.user.id, 
                    userId, 
                    'pending', 
                    new Date(), 
                    new Date()
                  ],
                  type: Sequelize.QueryTypes.INSERT,
                  transaction
                }
              );
              
              console.log('[API] 插入trip_invitations成功');
              
              // 插入通知记录
              console.log('[API] 插入notifications记录');
              await sequelize.query(
                `INSERT INTO notifications 
                 (notification_id, user_id, title, message, type, read_status, trip_id, created_at, updated_at) 
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                { 
                  replacements: [
                    uuidv4(), 
                    userId, 
                    '行程邀请', 
                    `您收到了来自${req.user.username}的行程邀请`, 
                    'trip_invite', 
                    0, 
                    tripId, 
                    new Date(), 
                    new Date()
                  ],
                  type: Sequelize.QueryTypes.INSERT,
                  transaction
                }
              );
              
              console.log('[API] 插入notifications成功');
            });
            
            console.log('[API] 事务执行成功，开始添加成员到返回列表');
            
            // 返回添加的成员信息
            const addedMember = {
              id: tripParticipantId,
              trip_id: tripId,
              user_id: userId,
              is_admin: false,
              invitation_status: 'pending',
              joined_at: new Date(),
              user: {
                id: user.user_id,
                name: `${user.first_name} ${user.last_name}`.trim(),
                email: user.email,
                username: user.username
              }
            };
            
            addedMembers.push(addedMember);
            console.log('[API] 用户邀请处理成功，添加到返回列表:', JSON.stringify(addedMember));
          } else {
            console.log('[API] 用户已存在邀请记录，跳过处理');
          }
        } else {
          console.log('[API] 未找到用户，user_id:', userId);
        }
      } catch (inviteError) {
        console.error('处理用户邀请失败:', inviteError);
        // 忽略错误，继续处理下一个成员
      }
    }
    
    console.log('[API] 邀请成员处理完成，返回成员数:', addedMembers.length);
    console.log('[API] 返回数据:', JSON.stringify(addedMembers));
    res.json(addedMembers);
  } catch (error) {
    console.error('邀请成员失败:', error);
    res.status(500).json({ message: '邀请成员失败' });
  }
});

// 接受邀请
app.put('/api/invitations/:invitationId/accept', authenticateToken, async (req, res) => {
  try {
    const invitationId = req.params.invitationId;
    const currentUserId = req.user.id;
    
    // 开始事务
    await sequelize.transaction(async (transaction) => {
      // 查找邀请记录
      const [invitation] = await sequelize.query(
        `SELECT * FROM trip_invitations 
         WHERE invitation_id = :invitationId AND invitee_id = :inviteeId AND status = 'pending'`,
        { 
          replacements: { invitationId, inviteeId: currentUserId },
          type: Sequelize.QueryTypes.SELECT,
          transaction
        }
      );
      
      if (!invitation) {
        throw new Error('邀请记录不存在或已过期');
      }
      
      // 更新邀请状态
      await sequelize.query(
        `UPDATE trip_invitations 
         SET status = 'accepted', updated_at = NOW() 
         WHERE invitation_id = :invitationId`,
        { 
          replacements: { invitationId },
          type: Sequelize.QueryTypes.UPDATE,
          transaction
        }
      );
      
      // 添加到旅行成员表
      await sequelize.query(
        `INSERT INTO trip_participants 
         (participant_id, trip_id, user_id, is_admin, invitation_status, joined_at, created_at, updated_at) 
         VALUES (?, ?, ?, ?, ?, NOW(), NOW(), NOW())`,
        { 
          replacements: [
            (await import('uuid')).v4(), 
            invitation.trip_id, 
            currentUserId,
            false,
            'accepted'
          ],
          type: Sequelize.QueryTypes.INSERT,
          transaction
        }
      );
      
      // 发送通知给邀请者
      await sequelize.query(
        `INSERT INTO notifications 
         (notification_id, user_id, title, message, type, read_status, trip_id, created_at, updated_at) 
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        { 
          replacements: [
            (await import('uuid')).v4(), 
            invitation.inviter_id, 
            '邀请已接受', 
            `${req.user.username} 接受了您的行程邀请`, 
            'invitation_accepted', 
            0, 
            invitation.trip_id, 
            new Date(), 
            new Date()
          ],
          type: Sequelize.QueryTypes.INSERT,
          transaction
        }
      );
    });
    
    res.json({ success: true, message: '邀请已接受' });
  } catch (error) {
    console.error('接受邀请失败:', error);
    res.status(500).json({ message: error.message || '接受邀请失败' });
  }
});

// 拒绝邀请
app.put('/api/invitations/:invitationId/reject', authenticateToken, async (req, res) => {
  try {
    const invitationId = req.params.invitationId;
    const currentUserId = req.user.id;
    
    // 开始事务
    await sequelize.transaction(async (transaction) => {
      // 查找邀请记录
      const [invitation] = await sequelize.query(
        `SELECT * FROM trip_invitations 
         WHERE invitation_id = :invitationId AND invitee_id = :inviteeId AND status = 'pending'`,
        { 
          replacements: { invitationId, inviteeId: currentUserId },
          type: Sequelize.QueryTypes.SELECT,
          transaction
        }
      );
      
      if (!invitation) {
        throw new Error('邀请记录不存在或已过期');
      }
      
      // 更新邀请状态
      await sequelize.query(
        `UPDATE trip_invitations 
         SET status = 'rejected', updated_at = NOW() 
         WHERE invitation_id = :invitationId`,
        { 
          replacements: { invitationId },
          type: Sequelize.QueryTypes.UPDATE,
          transaction
        }
      );
      
      // 发送通知给邀请者
      await sequelize.query(
        `INSERT INTO notifications 
         (notification_id, user_id, title, message, type, read_status, trip_id, created_at, updated_at) 
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        { 
          replacements: [
            (await import('uuid')).v4(), 
            invitation.inviter_id, 
            '邀请已拒绝', 
            `${req.user.username} 拒绝了您的行程邀请`, 
            'invitation_rejected', 
            0, 
            invitation.trip_id, 
            new Date(), 
            new Date()
          ],
          type: Sequelize.QueryTypes.INSERT,
          transaction
        }
      );
    });
    
    res.json({ success: true, message: '邀请已拒绝' });
  } catch (error) {
    console.error('拒绝邀请失败:', error);
    res.status(500).json({ message: error.message || '拒绝邀请失败' });
  }
});

// 获取用户的邀请列表
app.get('/api/invitations', authenticateToken, async (req, res) => {
  try {
    const currentUserId = req.user.id;
    
    const [invitations] = await sequelize.query(
      `SELECT ti.invitation_id AS id, ti.trip_id, ti.inviter_id, ti.invitee_id, ti.status, ti.invited_at, ti.updated_at, 
              t.name AS trip_name, t.destination, t.start_date, t.end_date, 
              u.user_id AS inviter_user_id, u.first_name, u.last_name, u.username, u.email 
       FROM trip_invitations ti 
       LEFT JOIN trips t ON ti.trip_id = t.trip_id 
       LEFT JOIN users u ON ti.inviter_id = u.user_id 
       WHERE ti.invitee_id = :inviteeId 
       ORDER BY ti.invited_at DESC`,
      { replacements: { inviteeId: currentUserId }, type: Sequelize.QueryTypes.SELECT }
    );
    
    res.json(invitations);
  } catch (error) {
    console.error('获取邀请列表失败:', error);
    res.status(500).json({ message: '获取邀请列表失败' });
  }
});

// 获取行程的待确认邀请列表
app.get('/api/trips/:tripId/invitations/pending', authenticateToken, async (req, res) => {
  try {
    const tripId = req.params.tripId;
    
    const [invitations] = await sequelize.query(
      `SELECT ti.invitation_id AS id, ti.trip_id, ti.inviter_id, ti.invitee_id, ti.status, ti.invited_at, ti.updated_at, 
              u.user_id AS invitee_user_id, u.first_name, u.last_name, u.username, u.email 
       FROM trip_invitations ti 
       LEFT JOIN users u ON ti.invitee_id = u.user_id 
       WHERE ti.trip_id = :tripId AND ti.status = 'pending' 
       ORDER BY ti.invited_at DESC`,
      { replacements: { tripId }, type: Sequelize.QueryTypes.SELECT }
    );
    
    res.json(invitations);
  } catch (error) {
    console.error('获取待确认邀请列表失败:', error);
    res.status(500).json({ message: '获取待确认邀请列表失败' });
  }
});

// 通知相关API

// 获取通知列表
app.get('/api/notifications', authenticateToken, async (req, res) => {
  try {
    const currentUserId = req.user.id;
    
    const [notifications] = await sequelize.query(
      `SELECT notification_id AS id, user_id, title, message AS content, type, read_status AS is_read, trip_id, created_at, updated_at 
       FROM notifications 
       WHERE user_id = :userId 
       ORDER BY created_at DESC`,
      { replacements: { userId: currentUserId }, type: Sequelize.QueryTypes.SELECT }
    );
    
    res.json(notifications);
  } catch (error) {
    console.error('获取通知列表失败:', error);
    res.status(500).json({ message: '获取通知列表失败' });
  }
});

// 获取未读通知数量
app.get('/api/notifications/unread-count', authenticateToken, async (req, res) => {
  try {
    const currentUserId = req.user.id;
    
    const [result] = await sequelize.query(
      `SELECT COUNT(*) AS count 
       FROM notifications 
       WHERE user_id = :userId AND read_status = 0`,
      { replacements: { userId: currentUserId }, type: Sequelize.QueryTypes.SELECT }
    );
    
    res.json({ count: parseInt(result[0].count) });
  } catch (error) {
    console.error('获取未读通知数量失败:', error);
    res.status(500).json({ message: '获取未读通知数量失败' });
  }
});

// 标记通知为已读
app.put('/api/notifications/:notificationId/read', authenticateToken, async (req, res) => {
  try {
    const notificationId = req.params.notificationId;
    const currentUserId = req.user.id;
    
    const [result] = await sequelize.query(
      `UPDATE notifications 
       SET read_status = 1, updated_at = NOW() 
       WHERE notification_id = :notificationId AND user_id = :userId`,
      { 
        replacements: { notificationId, userId: currentUserId },
        type: Sequelize.QueryTypes.UPDATE 
      }
    );
    
    res.json({ success: true });
  } catch (error) {
    console.error('标记通知为已读失败:', error);
    res.status(500).json({ message: '标记通知为已读失败' });
  }
});

// 标记所有通知为已读
app.put('/api/notifications/read-all', authenticateToken, async (req, res) => {
  try {
    const currentUserId = req.user.id;
    
    await sequelize.query(
      `UPDATE notifications 
       SET read_status = 1, updated_at = NOW() 
       WHERE user_id = :userId`,
      { 
        replacements: { userId: currentUserId },
        type: Sequelize.QueryTypes.UPDATE 
      }
    );
    
    res.json({ success: true });
  } catch (error) {
    console.error('标记所有通知为已读失败:', error);
    res.status(500).json({ message: '标记所有通知为已读失败' });
  }
});

// 删除通知
app.delete('/api/notifications/:notificationId', authenticateToken, async (req, res) => {
  try {
    const notificationId = req.params.notificationId;
    const currentUserId = req.user.id;
    
    await sequelize.query(
      `DELETE FROM notifications 
       WHERE notification_id = :notificationId AND user_id = :userId`,
      { 
        replacements: { notificationId, userId: currentUserId },
        type: Sequelize.QueryTypes.DELETE 
      }
    );
    
    res.json({ success: true });
  } catch (error) {
    console.error('删除通知失败:', error);
    res.status(500).json({ message: '删除通知失败' });
  }
});

// 删除所有通知
app.delete('/api/notifications', authenticateToken, async (req, res) => {
  try {
    const currentUserId = req.user.id;

    await sequelize.query(
      `DELETE FROM notifications
       WHERE user_id = :userId`,
      {
        replacements: { userId: currentUserId },
        type: Sequelize.QueryTypes.DELETE
      }
    );

    res.json({ success: true });
  } catch (error) {
    console.error('删除所有通知失败:', error);
    res.status(500).json({ message: '删除所有通知失败' });
  }
});

// 预算相关端点
// 获取旅行预算列表
app.get('/api/trips/:tripId/budgets', authenticateToken, async (req, res) => {
  try {
    const tripId = req.params.tripId;
    
    // 查询旅行的所有预算
    const [budgetsResult] = await sequelize.query(
      `SELECT * FROM budgets WHERE trip_id = :tripId ORDER BY created_at DESC`,
      {
        replacements: { tripId },
        type: Sequelize.QueryTypes.SELECT
      }
    );
    
    // 构建返回的预算列表
    const budgets = budgetsResult.map(budget => ({
      id: budget.budget_id,
      trip_id: budget.trip_id,
      category: budget.category,
      amount: parseFloat(budget.amount),
      currency: budget.currency,
      spent: parseFloat(budget.spent),
      created_at: budget.created_at,
      updated_at: budget.updated_at
    }));
    
    res.json(budgets);
  } catch (error) {
    console.error('获取旅行预算列表失败:', error);
    res.status(500).json({ message: '获取预算失败' });
  }
});

// 创建预算
app.post('/api/trips/:tripId/budgets', authenticateToken, async (req, res) => {
  try {
    const tripId = req.params.tripId;
    const budgetData = req.body;
    
    // 生成唯一的预算ID
    const { v4: uuidv4 } = require('uuid');
    const budgetId = uuidv4();
    
    // 创建新预算
    await sequelize.query(
      `INSERT INTO budgets (budget_id, trip_id, category, amount, currency, spent, created_at, updated_at) 
       VALUES (:budgetId, :tripId, :category, :amount, :currency, :spent, NOW(), NOW())`,
      {
        replacements: {
          budgetId,
          tripId,
          category: budgetData.category,
          amount: budgetData.amount,
          currency: budgetData.currency || 'CNY',
          spent: 0
        },
        type: Sequelize.QueryTypes.INSERT
      }
    );
    
    // 查询刚创建的预算
    const [newBudgetResult] = await sequelize.query(
      `SELECT * FROM budgets WHERE budget_id = :budgetId`,
      {
        replacements: { budgetId },
        type: Sequelize.QueryTypes.SELECT
      }
    );
    
    // 构建返回的预算对象
    const newBudget = {
      id: newBudgetResult.budget_id,
      trip_id: newBudgetResult.trip_id,
      category: newBudgetResult.category,
      amount: parseFloat(newBudgetResult.amount),
      currency: newBudgetResult.currency,
      spent: parseFloat(newBudgetResult.spent),
      created_at: newBudgetResult.created_at,
      updated_at: newBudgetResult.updated_at
    };
    
    res.json(newBudget);
  } catch (error) {
    console.error('创建预算失败:', error);
    res.status(500).json({ message: '创建预算失败' });
  }
});

// 更新预算
app.put('/api/trips/:tripId/budgets/:budgetId', authenticateToken, async (req, res) => {
  try {
    const tripId = req.params.tripId;
    const budgetId = req.params.budgetId;
    const budgetData = req.body;
    
    // 更新预算
    await sequelize.query(
      `UPDATE budgets 
       SET category = :category, 
           amount = :amount, 
           currency = :currency, 
           updated_at = NOW() 
       WHERE budget_id = :budgetId AND trip_id = :tripId`,
      {
        replacements: {
          budgetId,
          tripId,
          category: budgetData.category,
          amount: budgetData.amount,
          currency: budgetData.currency
        },
        type: Sequelize.QueryTypes.UPDATE
      }
    );
    
    // 查询更新后的预算
    const [updatedBudgetResult] = await sequelize.query(
      `SELECT * FROM budgets WHERE budget_id = :budgetId`,
      {
        replacements: { budgetId },
        type: Sequelize.QueryTypes.SELECT
      }
    );
    
    // 构建返回的预算对象
    const updatedBudget = {
      id: updatedBudgetResult.budget_id,
      trip_id: updatedBudgetResult.trip_id,
      category: updatedBudgetResult.category,
      amount: parseFloat(updatedBudgetResult.amount),
      currency: updatedBudgetResult.currency,
      spent: parseFloat(updatedBudgetResult.spent),
      created_at: updatedBudgetResult.created_at,
      updated_at: updatedBudgetResult.updated_at
    };
    
    res.json(updatedBudget);
  } catch (error) {
    console.error('更新预算失败:', error);
    res.status(500).json({ message: '更新预算失败' });
  }
});

// 删除预算
app.delete('/api/trips/:tripId/budgets/:budgetId', authenticateToken, async (req, res) => {
  try {
    const tripId = req.params.tripId;
    const budgetId = req.params.budgetId;
    
    // 删除预算
    await sequelize.query(
      `DELETE FROM budgets WHERE budget_id = :budgetId AND trip_id = :tripId`,
      {
        replacements: { budgetId, tripId },
        type: Sequelize.QueryTypes.DELETE
      }
    );
    
    res.json({ success: true });
  } catch (error) {
    console.error('删除预算失败:', error);
    res.status(500).json({ message: '删除预算失败' });
  }
});

// 获取预算使用情况
app.get('/api/trips/:tripId/budgets/usage', authenticateToken, async (req, res) => {
  try {
    const tripId = req.params.tripId;
    
    // 查询旅行的所有预算
    const [budgetsResult] = await sequelize.query(
      `SELECT * FROM budgets WHERE trip_id = :tripId`,
      {
        replacements: { tripId },
        type: Sequelize.QueryTypes.SELECT
      }
    );
    
    // 计算总预算和总支出
    const totalBudget = budgetsResult.reduce((sum, budget) => sum + parseFloat(budget.amount), 0);
    const totalSpent = budgetsResult.reduce((sum, budget) => sum + parseFloat(budget.spent), 0);
    
    res.json({ totalBudget, totalSpent });
  } catch (error) {
    console.error('获取预算使用情况失败:', error);
    res.status(500).json({ message: '获取预算使用情况失败' });
  }
});

// 启动服务器
async function startServer() {
  // 同步数据库
  await syncDatabase();
  
  // 启动Express服务器
  app.listen(PORT, () => {
    console.log(`MySQL API Server is running on port ${PORT}`);
    console.log(`Health check: http://localhost:${PORT}/health`);
    console.log(`API base URL: http://localhost:${PORT}/api`);
  });
}

// 启动服务器
startServer();
