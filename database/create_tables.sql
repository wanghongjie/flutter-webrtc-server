-- 创建数据库
CREATE DATABASE IF NOT EXISTS webrtc_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 使用数据库
USE webrtc_db;

-- 创建用户表
CREATE TABLE users (
  id           BIGINT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
  email        VARCHAR(255) NOT NULL UNIQUE,
  password_hash VARCHAR(255) NOT NULL,
  status       ENUM('active', 'deleted') NOT NULL DEFAULT 'active' COMMENT '用户状态',
  created_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 创建邮箱验证码表
CREATE TABLE email_verification_codes (
  id         BIGINT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
  email      VARCHAR(255) NOT NULL,
  code       VARCHAR(10) NOT NULL,
  expires_at DATETIME NOT NULL,
  used       TINYINT(1) NOT NULL DEFAULT 0,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_email (email),
  INDEX idx_email_code (email, code)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 创建设备绑定表
CREATE TABLE device_bindings (
  id BIGINT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
  monitor_email VARCHAR(255) NOT NULL COMMENT '监控端邮箱',
  camera_email VARCHAR(255) NOT NULL COMMENT '相机端邮箱',
  camera_device_id VARCHAR(100) NOT NULL COMMENT '相机端设备ID（WebRTC peer ID）',
  camera_name VARCHAR(255) COMMENT '相机端自定义名称',
  camera_location VARCHAR(255) COMMENT '相机端位置信息',
  camera_online TINYINT(1) NOT NULL DEFAULT 0 COMMENT '相机是否在线(0离线/1在线)',
  status ENUM('pending', 'active', 'revoked') DEFAULT 'pending' COMMENT '绑定状态',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  INDEX idx_monitor_email (monitor_email),
  INDEX idx_camera_email (camera_email),
  INDEX idx_camera_device_id (camera_device_id),
  UNIQUE KEY uk_monitor_camera (monitor_email, camera_email, camera_device_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='设备绑定关系表';

-- 创建意见反馈表
CREATE TABLE feedbacks (
  id BIGINT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
  email VARCHAR(255) NULL COMMENT '反馈人邮箱（可选）',
  device_id VARCHAR(100) NULL COMMENT '设备ID（可选）',
  content TEXT NOT NULL COMMENT '反馈内容',
  contact VARCHAR(255) NULL COMMENT '联系方式（可选）',
  ip VARCHAR(45) NULL COMMENT '提交IP',
  user_agent VARCHAR(512) NULL COMMENT 'User-Agent',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_email (email),
  INDEX idx_device_id (device_id),
  INDEX idx_created_at (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='意见反馈表';
