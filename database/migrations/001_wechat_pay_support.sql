-- 001_wechat_pay_support.sql
--
-- 为「微信支付（国内版）」补齐数据库支持。
--
-- 背景：subscriptions.platform 原为 ENUM('android','ios')，而微信支付代码
-- 全部写入 'wechat'，在 MySQL 严格模式（STRICT_TRANS_TABLES）下会直接报错
-- 或被截断为空串，导致订单落库失败。本迁移把枚举扩展为三值，并修正
-- status 字段的语义注释。
--
-- 执行方式：
--   mysql -u <user> -p webrtc_db < database/migrations/001_wechat_pay_support.sql
--
-- 幂等：可重复执行（通过 information_schema 判断是否已变更）。

USE webrtc_db;

-- 1. subscriptions.platform 扩展 wechat
SET @col_type := (
  SELECT COLUMN_TYPE FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'subscriptions'
    AND COLUMN_NAME = 'platform'
);

SET @sql := IF(
  @col_type LIKE '%wechat%',
  'SELECT "skip: platform already supports wechat" AS msg',
  "ALTER TABLE subscriptions MODIFY COLUMN platform ENUM('android','ios','wechat') NOT NULL DEFAULT 'android' COMMENT '支付渠道: android=Google Play, ios=App Store, wechat=微信支付'"
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- 2. users.platform 同步扩展（国内版用户也可能落到 wechat 渠道）
SET @u_col_type := (
  SELECT COLUMN_TYPE FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'users'
    AND COLUMN_NAME = 'platform'
);

SET @sql2 := IF(
  @u_col_type LIKE '%wechat%',
  'SELECT "skip: users.platform already supports wechat" AS msg',
  "ALTER TABLE users MODIFY COLUMN platform ENUM('android','ios','wechat') DEFAULT NULL COMMENT '最近一次支付渠道: android=Google Play, ios=App Store, wechat=微信支付'"
);
PREPARE stmt2 FROM @sql2;
EXECUTE stmt2;
DEALLOCATE PREPARE stmt2;

-- 3. 统一 status 语义（消除「2=宽限期」与「2=待支付」的冲突）
--    最终约定：
--      0 = 无效 / 过期 / 支付失败 / 已关闭
--      1 = 生效中
--      2 = 待支付（微信下单后、回调前）
--      3 = 宽限期（预留，Google/Apple 订阅保留）
--      4 = 暂停（预留）
ALTER TABLE subscriptions
  MODIFY COLUMN status TINYINT DEFAULT 1
  COMMENT '状态: 0=无效/过期, 1=生效中, 2=待支付, 3=宽限期, 4=暂停';

-- 4. 微信订单补单索引：微信查单/回调都按 order_id 定位，已有 uk_order_id 唯一键，
--    这里补充 (email, status) 复合索引，加速「我的会员」与对账查询。
SET @idx_exists := (
  SELECT COUNT(*) FROM information_schema.STATISTICS
  WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'subscriptions'
    AND INDEX_NAME = 'idx_email_status'
);

SET @sql3 := IF(
  @idx_exists > 0,
  'SELECT "skip: idx_email_status already exists" AS msg',
  'ALTER TABLE subscriptions ADD INDEX idx_email_status (email, status)'
);
PREPARE stmt3 FROM @sql3;
EXECUTE stmt3;
DEALLOCATE PREPARE stmt3;
