package auth

import (
	"crypto/subtle"
	"database/sql"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/flutter-webrtc/flutter-webrtc-server/pkg/logger"
)

// ============================================================================
// 后台管理接口（/api/admin/*）
//
// 仅用于运营后台查看数据（web/admin.html），不参与客户端业务逻辑：
//   GET    /api/admin/stats            概览统计
//   GET    /api/admin/users            用户列表（搜索 / 筛选 / 分页）
//   GET    /api/admin/user/detail      单个用户详情（含设备绑定、订阅、反馈）
//   GET    /api/admin/feedbacks        意见反馈列表（搜索 / 筛选 / 分页）
//   POST   /api/admin/feedback/delete  删除一条意见反馈
//
// 鉴权：请求头 X-Admin-Token，值来自 configs/config.ini 的 general.admin_token
// 或环境变量 ADMIN_TOKEN。未配置时接口整体返回 503（默认关闭，避免裸奔）。
// ============================================================================

// adminToken 为后台管理接口令牌，由 SetAdminToken 注入。
var adminToken string

// SetAdminToken 设置后台管理接口令牌（空值表示关闭后台接口）。
func SetAdminToken(token string) {
	adminToken = strings.TrimSpace(token)
}

// AdminEnabled 返回后台管理接口是否已启用。
func AdminEnabled() bool {
	return adminToken != ""
}

// AdminMiddleware 校验 X-Admin-Token 后放行。
func AdminMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !AdminEnabled() {
			writeJSON(w, http.StatusServiceUnavailable, jsonResponse{
				Success: false,
				Message: "admin api disabled: admin_token not configured",
			})
			return
		}

		token := strings.TrimSpace(r.Header.Get("X-Admin-Token"))
		if token == "" {
			token = strings.TrimSpace(r.URL.Query().Get("admin_token"))
		}
		if token == "" || subtle.ConstantTimeCompare([]byte(token), []byte(adminToken)) != 1 {
			writeJSON(w, http.StatusUnauthorized, jsonResponse{Success: false, Message: "invalid admin token"})
			return
		}
		next(w, r)
	}
}

// ---------------------------- 通用工具 ----------------------------

// queryInt 读取 int 型查询参数，缺失或非法时使用默认值，并做上下界裁剪。
func queryInt(r *http.Request, key string, def, min, max int) int {
	raw := strings.TrimSpace(r.URL.Query().Get(key))
	if raw == "" {
		return def
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		return def
	}
	if v < min {
		return min
	}
	if v > max {
		return max
	}
	return v
}

// nullStrPtr 把可空字符串转成 JSON 友好的 *string。
func nullStrPtr(ns sql.NullString) *string {
	if !ns.Valid || ns.String == "" {
		return nil
	}
	v := ns.String
	return &v
}

// nullTimePtr 把可空时间转成 RFC3339 字符串的 *string。
func nullTimePtr(nt sql.NullTime) *string {
	if !nt.Valid {
		return nil
	}
	v := nt.Time.Format(time.RFC3339)
	return &v
}

// ---------------------------- 数据模型 ----------------------------

type adminUserStats struct {
	Total    int `json:"total"`
	Active   int `json:"active"`
	Deleted  int `json:"deleted"`
	Vip      int `json:"vip"`
	NewToday int `json:"new_today"`
	New7d    int `json:"new_7d"`
	New30d   int `json:"new_30d"`
}

type adminFeedbackStats struct {
	Total     int `json:"total"`
	Today     int `json:"today"`
	Last7d    int `json:"last_7d"`
	Anonymous int `json:"anonymous"`
}

type adminBindingStats struct {
	Total    int `json:"total"`
	Active   int `json:"active"`
	Online   int `json:"online"`
	Cameras  int `json:"cameras"`
	Monitors int `json:"monitors"`
}

type adminSubStats struct {
	Total      int `json:"total"`
	Active     int `json:"active"`
	AndroidSub int `json:"android"`
	IosSub     int `json:"ios"`
	WechatSub  int `json:"wechat"`
}

type adminDailyPoint struct {
	Date      string `json:"date"`
	Users     int    `json:"users"`
	Feedbacks int    `json:"feedbacks"`
}

type adminStats struct {
	Users         adminUserStats     `json:"users"`
	Feedbacks     adminFeedbackStats `json:"feedbacks"`
	Bindings      adminBindingStats  `json:"bindings"`
	Subscriptions adminSubStats      `json:"subscriptions"`
	Daily         []adminDailyPoint  `json:"daily"`
	GeneratedAt   string             `json:"generated_at"`
}

type adminUserItem struct {
	ID                uint64  `json:"id"`
	Email             string  `json:"email"`
	Status            string  `json:"status"`
	VipLevel          uint8   `json:"vip_level"`
	ExpireAt          *string `json:"expire_at"`
	Language          *string `json:"language"`
	Platform          *string `json:"platform"`
	SubscriptionState int     `json:"subscription_state"`
	HasFCMToken       bool    `json:"has_fcm_token"`
	LastVerifyAt      *string `json:"last_verify_at"`
	CreatedAt         string  `json:"created_at"`
	DeviceCount       int     `json:"device_count"`
	FeedbackCount     int     `json:"feedback_count"`
}

type adminFeedbackItem struct {
	ID        uint64  `json:"id"`
	Email     *string `json:"email"`
	DeviceID  *string `json:"device_id"`
	Content   string  `json:"content"`
	Contact   *string `json:"contact"`
	IP        *string `json:"ip"`
	UserAgent *string `json:"user_agent"`
	CreatedAt string  `json:"created_at"`
}

type adminBindingItem struct {
	ID             uint64  `json:"id"`
	MonitorEmail   string  `json:"monitor_email"`
	CameraEmail    string  `json:"camera_email"`
	CameraDeviceID string  `json:"camera_device_id"`
	CameraName     *string `json:"camera_name"`
	CameraLocation *string `json:"camera_location"`
	CameraOnline   bool    `json:"camera_online"`
	Status         *string `json:"status"`
	CreatedAt      string  `json:"created_at"`
	UpdatedAt      string  `json:"updated_at"`
}

type adminSubscriptionItem struct {
	ID           uint64  `json:"id"`
	OrderID      string  `json:"order_id"`
	ProductID    string  `json:"product_id"`
	BasePlanID   *string `json:"base_plan_id"`
	Platform     string  `json:"platform"`
	PurchaseTime *string `json:"purchase_time"`
	ExpireTime   *string `json:"expire_time"`
	Status       int     `json:"status"`
	AutoRenewing bool    `json:"auto_renewing"`
	CreatedAt    string  `json:"created_at"`
}

type adminUserFeedbackItem struct {
	ID        uint64  `json:"id"`
	Content   string  `json:"content"`
	Contact   *string `json:"contact"`
	DeviceID  *string `json:"device_id"`
	CreatedAt string  `json:"created_at"`
}

type adminUserDetail struct {
	User          adminUserItem           `json:"user"`
	Bindings      []adminBindingItem      `json:"bindings"`
	Subscriptions []adminSubscriptionItem `json:"subscriptions"`
	Feedbacks     []adminUserFeedbackItem `json:"feedbacks"`
}

type adminPaged struct {
	Total    int         `json:"total"`
	Page     int         `json:"page"`
	PageSize int         `json:"page_size"`
	Items    interface{} `json:"items"`
}

// ---------------------------- 概览统计 ----------------------------

// HandleAdminStats GET /api/admin/stats?days=7
func (s *Service) HandleAdminStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, jsonResponse{Success: false, Message: "method not allowed"})
		return
	}

	days := queryInt(r, "days", 7, 1, 90)
	stats := adminStats{
		Daily:       []adminDailyPoint{},
		GeneratedAt: time.Now().Format(time.RFC3339),
	}

	// 用户维度
	if err := s.DB.QueryRow(`
		SELECT COUNT(*),
		       SUM(status = 'active'),
		       SUM(status = 'deleted'),
		       SUM(status = 'active' AND vip_level > 0),
		       SUM(created_at >= CURDATE()),
		       SUM(created_at >= DATE_SUB(CURDATE(), INTERVAL 7 DAY)),
		       SUM(created_at >= DATE_SUB(CURDATE(), INTERVAL 30 DAY))
		FROM users`).Scan(
		&stats.Users.Total, nullInt(&stats.Users.Active), nullInt(&stats.Users.Deleted),
		nullInt(&stats.Users.Vip), nullInt(&stats.Users.NewToday),
		nullInt(&stats.Users.New7d), nullInt(&stats.Users.New30d),
	); err != nil {
		logger.Errorf("admin stats users error: %v", err)
		writeJSON(w, http.StatusInternalServerError, jsonResponse{Success: false, Message: "server error"})
		return
	}

	// 反馈维度
	if err := s.DB.QueryRow(`
		SELECT COUNT(*),
		       SUM(created_at >= CURDATE()),
		       SUM(created_at >= DATE_SUB(CURDATE(), INTERVAL 7 DAY)),
		       SUM(email IS NULL OR email = '')
		FROM feedbacks`).Scan(
		&stats.Feedbacks.Total, nullInt(&stats.Feedbacks.Today),
		nullInt(&stats.Feedbacks.Last7d), nullInt(&stats.Feedbacks.Anonymous),
	); err != nil {
		logger.Errorf("admin stats feedbacks error: %v", err)
		writeJSON(w, http.StatusInternalServerError, jsonResponse{Success: false, Message: "server error"})
		return
	}

	// 设备绑定维度
	if err := s.DB.QueryRow(`
		SELECT COUNT(*),
		       SUM(status = 'active'),
		       SUM(camera_online = 1),
		       COUNT(DISTINCT camera_device_id),
		       COUNT(DISTINCT monitor_email)
		FROM device_bindings WHERE status != 'revoked'`).Scan(
		&stats.Bindings.Total, nullInt(&stats.Bindings.Active), nullInt(&stats.Bindings.Online),
		&stats.Bindings.Cameras, &stats.Bindings.Monitors,
	); err != nil {
		logger.Errorf("admin stats bindings error: %v", err)
		writeJSON(w, http.StatusInternalServerError, jsonResponse{Success: false, Message: "server error"})
		return
	}

	// 订阅维度
	if err := s.DB.QueryRow(`
		SELECT COUNT(*),
		       SUM(status = 1),
		       SUM(platform = 'android'),
		       SUM(platform = 'ios'),
		       SUM(platform = 'wechat')
		FROM subscriptions`).Scan(
		&stats.Subscriptions.Total, nullInt(&stats.Subscriptions.Active),
		nullInt(&stats.Subscriptions.AndroidSub), nullInt(&stats.Subscriptions.IosSub),
		nullInt(&stats.Subscriptions.WechatSub),
	); err != nil {
		logger.Errorf("admin stats subscriptions error: %v", err)
		writeJSON(w, http.StatusInternalServerError, jsonResponse{Success: false, Message: "server error"})
		return
	}

	// 近 N 天趋势：分别按天聚合后在 Go 里合并，避免依赖 MySQL 生成日期序列
	userMap := map[string]int{}
	feedbackMap := map[string]int{}
	if rows, err := s.DB.Query(`
		SELECT DATE(created_at) d, COUNT(*) c FROM users
		WHERE created_at >= DATE_SUB(CURDATE(), INTERVAL ? DAY) GROUP BY d`, days); err == nil {
		for rows.Next() {
			var d string
			var c int
			if err := rows.Scan(&d, &c); err == nil {
				userMap[d] = c
			}
		}
		rows.Close()
	} else {
		logger.Errorf("admin stats daily users error: %v", err)
	}
	if rows, err := s.DB.Query(`
		SELECT DATE(created_at) d, COUNT(*) c FROM feedbacks
		WHERE created_at >= DATE_SUB(CURDATE(), INTERVAL ? DAY) GROUP BY d`, days); err == nil {
		for rows.Next() {
			var d string
			var c int
			if err := rows.Scan(&d, &c); err == nil {
				feedbackMap[d] = c
			}
		}
		rows.Close()
	} else {
		logger.Errorf("admin stats daily feedbacks error: %v", err)
	}

	now := time.Now()
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	for i := days - 1; i >= 0; i-- {
		day := today.AddDate(0, 0, -i).Format("2006-01-02")
		stats.Daily = append(stats.Daily, adminDailyPoint{
			Date:      day,
			Users:     userMap[day],
			Feedbacks: feedbackMap[day],
		})
	}

	writeJSON(w, http.StatusOK, jsonResponse{Success: true, Data: stats})
}

// nullInt 用于扫描 SUM() 可能返回 NULL 的列，NULL 视为 0。
type nullIntDest struct {
	p *int
}

func (n nullIntDest) Scan(value interface{}) error {
	if value == nil {
		*n.p = 0
		return nil
	}
	switch v := value.(type) {
	case int64:
		*n.p = int(v)
	case []byte:
		return parseIntBytes(string(v), n.p)
	case string:
		return parseIntBytes(v, n.p)
	case float64:
		*n.p = int(v)
	default:
		*n.p = 0
	}
	return nil
}

// parseIntBytes 解析 SUM() 可能返回的十进制字符串（如 "12" / "12.0"）。
func parseIntBytes(s string, p *int) error {
	if i, err := strconv.Atoi(s); err == nil {
		*p = i
		return nil
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		*p = 0
		return err
	}
	*p = int(f)
	return nil
}

// nullInt 把 *int 包装成可接收 NULL 的扫描目标。
func nullInt(p *int) nullIntDest {
	return nullIntDest{p: p}
}

// ---------------------------- 用户列表 ----------------------------

// HandleAdminUsers GET /api/admin/users?page=1&page_size=20&keyword=&status=&vip=&platform=&sort=&order=
func (s *Service) HandleAdminUsers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, jsonResponse{Success: false, Message: "method not allowed"})
		return
	}

	q := r.URL.Query()
	keyword := strings.TrimSpace(q.Get("keyword"))
	status := strings.TrimSpace(q.Get("status"))     // active / deleted
	vip := strings.TrimSpace(q.Get("vip"))           // 0=免费 1=VIP
	platform := strings.TrimSpace(q.Get("platform")) // android / ios / wechat
	sortBy := strings.TrimSpace(q.Get("sort"))
	order := strings.ToUpper(strings.TrimSpace(q.Get("order")))
	page := queryInt(r, "page", 1, 1, 100000)
	pageSize := queryInt(r, "page_size", 20, 1, 100)

	where := []string{"1=1"}
	args := []interface{}{}
	if keyword != "" {
		where = append(where, "u.email LIKE ?")
		args = append(args, "%"+keyword+"%")
	}
	if status == "active" || status == "deleted" {
		where = append(where, "u.status = ?")
		args = append(args, status)
	}
	if vip == "1" {
		where = append(where, "u.vip_level > 0")
	} else if vip == "0" {
		where = append(where, "u.vip_level = 0")
	}
	if platform == "android" || platform == "ios" || platform == "wechat" {
		where = append(where, "u.platform = ?")
		args = append(args, platform)
	}
	whereSQL := strings.Join(where, " AND ")

	// 白名单排序，避免 SQL 注入
	sortCols := map[string]string{
		"id":             "u.id",
		"email":          "u.email",
		"created_at":     "u.created_at",
		"last_verify_at": "u.last_verify_at",
		"expire_at":      "u.expire_at",
		"vip_level":      "u.vip_level",
	}
	col, ok := sortCols[sortBy]
	if !ok {
		col = "u.created_at"
	}
	if order != "ASC" {
		order = "DESC"
	}

	var total int
	if err := s.DB.QueryRow("SELECT COUNT(*) FROM users u WHERE "+whereSQL, args...).Scan(&total); err != nil {
		logger.Errorf("admin users count error: %v", err)
		writeJSON(w, http.StatusInternalServerError, jsonResponse{Success: false, Message: "server error"})
		return
	}

	offset := (page - 1) * pageSize
	listSQL := `SELECT u.id, u.email, u.status, u.vip_level, u.expire_at, u.language, u.platform,
			   u.subscription_state, u.fcm_token, u.created_at, u.last_verify_at,
			   (SELECT COUNT(*) FROM device_bindings b WHERE b.monitor_email = u.email AND b.status != 'revoked'),
			   (SELECT COUNT(*) FROM feedbacks f WHERE f.email = u.email)
			FROM users u WHERE ` + whereSQL + ` ORDER BY ` + col + ` ` + order + ` LIMIT ? OFFSET ?`
	rows, err := s.DB.Query(listSQL, append(args, pageSize, offset)...)
	if err != nil {
		logger.Errorf("admin users query error: %v", err)
		writeJSON(w, http.StatusInternalServerError, jsonResponse{Success: false, Message: "server error"})
		return
	}
	defer rows.Close()

	items := []adminUserItem{}
	for rows.Next() {
		var (
			it        adminUserItem
			expireAt  sql.NullTime
			language  sql.NullString
			platformV sql.NullString
			subState  sql.NullInt64
			fcmToken  sql.NullString
			lastVer   sql.NullTime
			createdAt time.Time
		)
		if err := rows.Scan(&it.ID, &it.Email, &it.Status, &it.VipLevel, &expireAt, &language,
			&platformV, &subState, &fcmToken, &createdAt, &lastVer, &it.DeviceCount, &it.FeedbackCount); err != nil {
			logger.Errorf("admin users scan error: %v", err)
			continue
		}
		it.ExpireAt = nullTimePtr(expireAt)
		it.Language = nullStrPtr(language)
		it.Platform = nullStrPtr(platformV)
		it.SubscriptionState = int(subState.Int64)
		it.HasFCMToken = fcmToken.Valid && fcmToken.String != ""
		it.LastVerifyAt = nullTimePtr(lastVer)
		it.CreatedAt = createdAt.Format(time.RFC3339)
		items = append(items, it)
	}
	if err := rows.Err(); err != nil {
		logger.Errorf("admin users rows error: %v", err)
	}

	writeJSON(w, http.StatusOK, jsonResponse{Success: true, Data: adminPaged{
		Total: total, Page: page, PageSize: pageSize, Items: items,
	}})
}

// ---------------------------- 用户详情 ----------------------------

// HandleAdminUserDetail GET /api/admin/user/detail?email=xxx (或 ?id=123)
func (s *Service) HandleAdminUserDetail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, jsonResponse{Success: false, Message: "method not allowed"})
		return
	}

	q := r.URL.Query()
	email := strings.TrimSpace(q.Get("email"))
	id := strings.TrimSpace(q.Get("id"))
	if email == "" && id == "" {
		writeJSON(w, http.StatusBadRequest, jsonResponse{Success: false, Message: "email or id required"})
		return
	}

	var (
		u         adminUserItem
		expireAt  sql.NullTime
		language  sql.NullString
		platformV sql.NullString
		subState  sql.NullInt64
		fcmToken  sql.NullString
		lastVer   sql.NullTime
		createdAt time.Time
	)
	query := `SELECT id, email, status, vip_level, expire_at, language, platform,
			  subscription_state, fcm_token, created_at, last_verify_at FROM users WHERE `
	var err error
	if email != "" {
		query += "email = ?"
		err = s.DB.QueryRow(query, email).Scan(&u.ID, &u.Email, &u.Status, &u.VipLevel, &expireAt,
			&language, &platformV, &subState, &fcmToken, &createdAt, &lastVer)
	} else {
		query += "id = ?"
		err = s.DB.QueryRow(query, id).Scan(&u.ID, &u.Email, &u.Status, &u.VipLevel, &expireAt,
			&language, &platformV, &subState, &fcmToken, &createdAt, &lastVer)
	}
	if err == sql.ErrNoRows {
		writeJSON(w, http.StatusNotFound, jsonResponse{Success: false, Message: "user not found"})
		return
	}
	if err != nil {
		logger.Errorf("admin user detail error: %v", err)
		writeJSON(w, http.StatusInternalServerError, jsonResponse{Success: false, Message: "server error"})
		return
	}
	u.ExpireAt = nullTimePtr(expireAt)
	u.Language = nullStrPtr(language)
	u.Platform = nullStrPtr(platformV)
	u.SubscriptionState = int(subState.Int64)
	u.HasFCMToken = fcmToken.Valid && fcmToken.String != ""
	u.LastVerifyAt = nullTimePtr(lastVer)
	u.CreatedAt = createdAt.Format(time.RFC3339)

	detail := adminUserDetail{
		User:          u,
		Bindings:      []adminBindingItem{},
		Subscriptions: []adminSubscriptionItem{},
		Feedbacks:     []adminUserFeedbackItem{},
	}

	// 设备绑定（作为监控端或相机端都列出）
	if rows, err := s.DB.Query(`SELECT id, monitor_email, camera_email, camera_device_id, camera_name,
			camera_location, camera_online, status, created_at, updated_at
		FROM device_bindings WHERE monitor_email = ? OR camera_email = ? ORDER BY updated_at DESC LIMIT 200`,
		u.Email, u.Email); err == nil {
		for rows.Next() {
			var (
				b       adminBindingItem
				name    sql.NullString
				loc     sql.NullString
				online  sql.NullInt64
				statusV sql.NullString
				ct, ut  time.Time
			)
			if err := rows.Scan(&b.ID, &b.MonitorEmail, &b.CameraEmail, &b.CameraDeviceID, &name,
				&loc, &online, &statusV, &ct, &ut); err != nil {
				continue
			}
			b.CameraName = nullStrPtr(name)
			b.CameraLocation = nullStrPtr(loc)
			b.CameraOnline = online.Int64 == 1
			b.Status = nullStrPtr(statusV)
			b.CreatedAt = ct.Format(time.RFC3339)
			b.UpdatedAt = ut.Format(time.RFC3339)
			detail.Bindings = append(detail.Bindings, b)
		}
		rows.Close()
	} else {
		logger.Errorf("admin user bindings error: %v", err)
	}

	// 订阅记录
	if rows, err := s.DB.Query(`SELECT id, order_id, product_id, base_plan_id, platform, purchase_time,
			expire_time, status, auto_renewing, created_at
		FROM subscriptions WHERE email = ? ORDER BY created_at DESC LIMIT 200`, u.Email); err == nil {
		for rows.Next() {
			var (
				sub    adminSubscriptionItem
				base   sql.NullString
				pt, et sql.NullTime
				st     sql.NullInt64
				auto   sql.NullInt64
				ct     time.Time
			)
			if err := rows.Scan(&sub.ID, &sub.OrderID, &sub.ProductID, &base, &sub.Platform,
				&pt, &et, &st, &auto, &ct); err != nil {
				continue
			}
			sub.BasePlanID = nullStrPtr(base)
			sub.PurchaseTime = nullTimePtr(pt)
			sub.ExpireTime = nullTimePtr(et)
			sub.Status = int(st.Int64)
			sub.AutoRenewing = auto.Int64 == 1
			sub.CreatedAt = ct.Format(time.RFC3339)
			detail.Subscriptions = append(detail.Subscriptions, sub)
		}
		rows.Close()
	} else {
		logger.Errorf("admin user subscriptions error: %v", err)
	}

	// 历史反馈
	if rows, err := s.DB.Query(`SELECT id, content, contact, device_id, created_at
		FROM feedbacks WHERE email = ? ORDER BY created_at DESC LIMIT 100`, u.Email); err == nil {
		for rows.Next() {
			var (
				f     adminUserFeedbackItem
				c     sql.NullString
				devID sql.NullString
				ct    time.Time
			)
			if err := rows.Scan(&f.ID, &f.Content, &c, &devID, &ct); err != nil {
				continue
			}
			f.Contact = nullStrPtr(c)
			f.DeviceID = nullStrPtr(devID)
			f.CreatedAt = ct.Format(time.RFC3339)
			detail.Feedbacks = append(detail.Feedbacks, f)
		}
		rows.Close()
	} else {
		logger.Errorf("admin user feedbacks error: %v", err)
	}

	writeJSON(w, http.StatusOK, jsonResponse{Success: true, Data: detail})
}

// ---------------------------- 意见反馈列表 ----------------------------

// HandleAdminFeedbacks GET /api/admin/feedbacks?page=1&page_size=20&keyword=&start=&end=
func (s *Service) HandleAdminFeedbacks(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, jsonResponse{Success: false, Message: "method not allowed"})
		return
	}

	q := r.URL.Query()
	keyword := strings.TrimSpace(q.Get("keyword"))
	start := strings.TrimSpace(q.Get("start")) // 2006-01-02
	end := strings.TrimSpace(q.Get("end"))
	page := queryInt(r, "page", 1, 1, 100000)
	pageSize := queryInt(r, "page_size", 20, 1, 100)

	where := []string{"1=1"}
	args := []interface{}{}
	if keyword != "" {
		where = append(where, "(content LIKE ? OR email LIKE ? OR device_id LIKE ? OR contact LIKE ? OR ip LIKE ?)")
		kw := "%" + keyword + "%"
		args = append(args, kw, kw, kw, kw, kw)
	}
	if start != "" {
		where = append(where, "created_at >= ?")
		args = append(args, start+" 00:00:00")
	}
	if end != "" {
		where = append(where, "created_at <= ?")
		args = append(args, end+" 23:59:59")
	}
	whereSQL := strings.Join(where, " AND ")

	var total int
	if err := s.DB.QueryRow("SELECT COUNT(*) FROM feedbacks WHERE "+whereSQL, args...).Scan(&total); err != nil {
		logger.Errorf("admin feedbacks count error: %v", err)
		writeJSON(w, http.StatusInternalServerError, jsonResponse{Success: false, Message: "server error"})
		return
	}

	offset := (page - 1) * pageSize
	rows, err := s.DB.Query(`SELECT id, email, device_id, content, contact, ip, user_agent, created_at
		FROM feedbacks WHERE `+whereSQL+` ORDER BY created_at DESC LIMIT ? OFFSET ?`,
		append(args, pageSize, offset)...)
	if err != nil {
		logger.Errorf("admin feedbacks query error: %v", err)
		writeJSON(w, http.StatusInternalServerError, jsonResponse{Success: false, Message: "server error"})
		return
	}
	defer rows.Close()

	items := []adminFeedbackItem{}
	for rows.Next() {
		var (
			it    adminFeedbackItem
			email sql.NullString
			devID sql.NullString
			c     sql.NullString
			ip    sql.NullString
			ua    sql.NullString
			ct    time.Time
		)
		if err := rows.Scan(&it.ID, &email, &devID, &it.Content, &c, &ip, &ua, &ct); err != nil {
			logger.Errorf("admin feedbacks scan error: %v", err)
			continue
		}
		it.Email = nullStrPtr(email)
		it.DeviceID = nullStrPtr(devID)
		it.Contact = nullStrPtr(c)
		it.IP = nullStrPtr(ip)
		it.UserAgent = nullStrPtr(ua)
		it.CreatedAt = ct.Format(time.RFC3339)
		items = append(items, it)
	}
	if err := rows.Err(); err != nil {
		logger.Errorf("admin feedbacks rows error: %v", err)
	}

	writeJSON(w, http.StatusOK, jsonResponse{Success: true, Data: adminPaged{
		Total: total, Page: page, PageSize: pageSize, Items: items,
	}})
}

// ---------------------------- 删除意见反馈 ----------------------------

// HandleAdminDeleteFeedback POST/DELETE /api/admin/feedback/delete?id=123
func (s *Service) HandleAdminDeleteFeedback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodDelete {
		writeJSON(w, http.StatusMethodNotAllowed, jsonResponse{Success: false, Message: "method not allowed"})
		return
	}

	id := strings.TrimSpace(r.URL.Query().Get("id"))
	if id == "" {
		id = strings.TrimSpace(r.PostFormValue("id"))
	}
	if id == "" {
		writeJSON(w, http.StatusBadRequest, jsonResponse{Success: false, Message: "id required"})
		return
	}

	res, err := s.DB.Exec("DELETE FROM feedbacks WHERE id = ?", id)
	if err != nil {
		logger.Errorf("admin delete feedback error: %v", err)
		writeJSON(w, http.StatusInternalServerError, jsonResponse{Success: false, Message: "server error"})
		return
	}
	affected, _ := res.RowsAffected()

	writeJSON(w, http.StatusOK, jsonResponse{
		Success: true,
		Message: "feedback deleted",
		Data:    map[string]interface{}{"affected": affected},
	})
}
