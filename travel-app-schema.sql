-- 创建 users 表（先创建，被其他表依赖）
CREATE TABLE `users` (
  `user_id` varchar(36) NOT NULL,
  `username` varchar(50) NOT NULL,
  `email` varchar(100) NOT NULL,
  `password` varchar(255) NOT NULL,
  `first_name` varchar(50) NOT NULL,
  `last_name` varchar(50) NOT NULL,
  `created_at` datetime NOT NULL,
  `updated_at` datetime NOT NULL,
  PRIMARY KEY (`user_id`),
  UNIQUE KEY `username` (`username`),
  UNIQUE KEY `email` (`email`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- 创建 trips 表（依赖 users 表）
CREATE TABLE `trips` (
  `trip_id` varchar(36) NOT NULL,
  `user_id` varchar(36) NOT NULL,
  `name` varchar(100) NOT NULL,
  `description` text,
  `destination` varchar(100) NOT NULL,
  `start_date` date NOT NULL,
  `end_date` date NOT NULL,
  `created_at` datetime NOT NULL,
  `updated_at` datetime NOT NULL,
  `trip_type` varchar(50) DEFAULT NULL,
  `is_public` tinyint(1) DEFAULT '0',
  PRIMARY KEY (`trip_id`),
  KEY `user_id` (`user_id`),
  CONSTRAINT `trips_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`user_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- 创建 trip_participants 表（依赖 trips 和 users 表）
CREATE TABLE `trip_participants` (
  `participant_id` varchar(36) NOT NULL,
  `trip_id` varchar(36) NOT NULL,
  `user_id` varchar(36) NOT NULL,
  `joined_at` datetime NOT NULL,
  PRIMARY KEY (`participant_id`),
  KEY `trip_id` (`trip_id`),
  KEY `user_id` (`user_id`),
  CONSTRAINT `trip_participants_ibfk_1` FOREIGN KEY (`trip_id`) REFERENCES `trips` (`trip_id`),
  CONSTRAINT `trip_participants_ibfk_2` FOREIGN KEY (`user_id`) REFERENCES `users` (`user_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- 创建 trip_invitations 表（依赖 trips 和 users 表）
CREATE TABLE `trip_invitations` (
  `invitation_id` varchar(36) NOT NULL,
  `trip_id` varchar(36) NOT NULL,
  `inviter_id` varchar(36) NOT NULL,
  `invitee_id` varchar(36) NOT NULL,
  `status` varchar(20) NOT NULL,
  `invited_at` datetime NOT NULL,
  `updated_at` datetime NOT NULL,
  PRIMARY KEY (`invitation_id`),
  KEY `trip_id` (`trip_id`),
  KEY `inviter_id` (`inviter_id`),
  KEY `invitee_id` (`invitee_id`),
  CONSTRAINT `trip_invitations_ibfk_1` FOREIGN KEY (`trip_id`) REFERENCES `trips` (`trip_id`),
  CONSTRAINT `trip_invitations_ibfk_2` FOREIGN KEY (`inviter_id`) REFERENCES `users` (`user_id`),
  CONSTRAINT `trip_invitations_ibfk_3` FOREIGN KEY (`invitee_id`) REFERENCES `users` (`user_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- 创建 expenses 表（依赖 trips 和 users 表）
CREATE TABLE `expenses` (
  `expense_id` varchar(36) NOT NULL,
  `trip_id` varchar(36) NOT NULL,
  `amount` decimal(10,2) NOT NULL,
  `currency` varchar(10) NOT NULL,
  `category` varchar(50) NOT NULL,
  `description` text,
  `date` date NOT NULL,
  `paid_by` varchar(36) NOT NULL,
  `split_method` varchar(20) DEFAULT NULL,
  `split_details` json DEFAULT NULL,
  `created_by` varchar(36) NOT NULL,
  `created_at` datetime NOT NULL,
  `updated_at` datetime NOT NULL,
  PRIMARY KEY (`expense_id`),
  KEY `trip_id` (`trip_id`),
  KEY `paid_by` (`paid_by`),
  KEY `created_by` (`created_by`),
  CONSTRAINT `expenses_ibfk_1` FOREIGN KEY (`trip_id`) REFERENCES `trips` (`trip_id`),
  CONSTRAINT `expenses_ibfk_2` FOREIGN KEY (`paid_by`) REFERENCES `users` (`user_id`),
  CONSTRAINT `expenses_ibfk_3` FOREIGN KEY (`created_by`) REFERENCES `users` (`user_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- 创建 settlements 表（依赖 trips 和 users 表）
CREATE TABLE `settlements` (
  `settlement_id` varchar(36) NOT NULL,
  `trip_id` varchar(36) NOT NULL,
  `amount` decimal(10,2) NOT NULL,
  `currency` varchar(10) NOT NULL,
  `description` text,
  `date` date NOT NULL,
  `status` varchar(20) NOT NULL,
  `created_by` varchar(36) NOT NULL,
  `created_at` datetime NOT NULL,
  `updated_at` datetime NOT NULL,
  PRIMARY KEY (`settlement_id`),
  KEY `trip_id` (`trip_id`),
  KEY `created_by` (`created_by`),
  CONSTRAINT `settlements_ibfk_1` FOREIGN KEY (`trip_id`) REFERENCES `trips` (`trip_id`),
  CONSTRAINT `settlements_ibfk_2` FOREIGN KEY (`created_by`) REFERENCES `users` (`user_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- 创建 notifications 表（依赖 users 和 trips 表）
CREATE TABLE `notifications` (
  `notification_id` varchar(36) NOT NULL,
  `user_id` varchar(36) NOT NULL,
  `title` varchar(100) NOT NULL,
  `message` text NOT NULL,
  `type` varchar(20) NOT NULL,
  `read_status` tinyint(1) DEFAULT '0',
  `trip_id` varchar(36) DEFAULT NULL,
  `created_at` datetime NOT NULL,
  `updated_at` datetime NOT NULL,
  PRIMARY KEY (`notification_id`),
  KEY `user_id` (`user_id`),
  KEY `trip_id` (`trip_id`),
  CONSTRAINT `notifications_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`user_id`),
  CONSTRAINT `notifications_ibfk_2` FOREIGN KEY (`trip_id`) REFERENCES `trips` (`trip_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

