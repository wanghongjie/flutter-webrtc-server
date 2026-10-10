-- 002_align_subscription_state.sql
--
-- 对齐 users.subscription_state 与 subscriptions.status 的状态语义。
--
-- 背景：迁移 001 已把 subscriptions.status 统一为
--         0=无效/过期, 1=生效中, 2=待支付, 3=宽限期, 4=暂停
--       但 users.subscription_state 仍是旧语义
--         0=无/过期, 1=生效中, 2=宽限期, 3=暂停
--       同一个数字在两张表里含义不同（users 的 2=宽限期 vs subscriptions 的 2=待支付，
--       users 的 3=暂停 vs subscriptions 的 3=宽限期），跨表比对与后台展示会误判。
--
-- 数据说明：
--   - 本迁移只改列注释，不刷数据。历史代码对 users.subscription_state 只写入
--     0（无/过期）与 1（生效中），这两个值在两套语义下含义一致。
--   - users.subscription_state 只是 users 侧的「派生快照」，
--     权益的唯一真源是 subscriptions.status；判断用户是否为会员请以 subscriptions 为准。
--
-- 执行方式：
--   mysql -u <user> -p webrtc_db < database/migrations/002_align_subscription_state.sql
--
-- 幂等：可重复执行（仅修改列注释，无数据变更）。

USE webrtc_db;

ALTER TABLE users
  MODIFY COLUMN subscription_state TINYINT DEFAULT 0
  COMMENT '订阅状态(与 subscriptions.status 同义): 0=无效/过期, 1=生效中, 2=待支付, 3=宽限期, 4=暂停';
