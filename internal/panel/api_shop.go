package panel

import (
	"crypto/md5"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"math"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

func orderNo() string {
	return time.Now().Format("20060102150405") + strings.ToUpper(randHex(4))
}

func (s *Server) handlePlans(w http.ResponseWriter, r *http.Request, u *User) {
	plans, err := listPlans(s.reader(), false)
	if err != nil {
		s.dbErr(w, err)
		return
	}
	s.ok(w, plans)
}

// 单行账务写入即使没有 SQL 错误，也必须确实修改一行才能提交。
func shopWriteOne(q dbq, stmt string, args ...any) error {
	res, err := q.Exec(stmt, args...)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return fmt.Errorf("账务写入影响 %d 行，预期 1 行", n)
	}
	return nil
}

// applyPlan 把套餐应用到用户:
// 续费同一套餐且未到期 -> 到期时间顺延;其余情况从现在起算。两种情况都会重置已用流量。
func applyPlan(tx dbq, u *User, p *Plan) error {
	t := now()
	var expire int64
	if p.Days > 0 {
		base := t
		if u.PlanID == p.ID && u.ExpireAt > t {
			base = u.ExpireAt
		}
		expire = base + int64(p.Days)*86400
	}
	return shopWriteOne(tx, `UPDATE users SET plan_id=?, traffic_quota=?, traffic_used=0, expire_at=?, max_rules=?,
		speed_limit=?, conn_limit=?, ip_limit=? WHERE id=?`,
		p.ID, p.Traffic, expire, p.MaxRules, p.SpeedLimit, p.ConnLimit, p.IPLimit, u.ID)
}

// purchase 用余额购买套餐(购买与自动续费共用)。
func (s *Server) purchase(userID, planID int64, typ string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	u, err := getUser(tx, userID)
	if err != nil {
		return err
	}
	p, err := getPlan(tx, planID)
	if err != nil {
		return errors.New("套餐不存在")
	}
	if p.Hidden && (typ != "plan" || !u.IsAdmin()) {
		return errors.New("套餐已下架")
	}
	if u.Balance < p.Price {
		return errors.New("余额不足,请先充值")
	}
	if err := shopWriteOne(tx, `UPDATE users SET balance=balance-? WHERE id=? AND balance>=?`, p.Price, u.ID, p.Price); err != nil {
		return err
	}
	if err := applyPlan(tx, u, p); err != nil {
		return err
	}
	t := now()
	if err := shopWriteOne(tx, `INSERT INTO orders(order_no,user_id,type,plan_id,amount,status,pay_method,note,created_at,paid_at)
		VALUES(?,?,?,?,?,'paid','balance',?,?,?)`, orderNo(), u.ID, typ, p.ID, p.Price, p.Name, t, t); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.hub.Dirty()
	return nil
}

func (s *Server) handleBuy(w http.ResponseWriter, r *http.Request, u *User) {
	if err := s.purchase(u.ID, pathID(r), "plan"); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			s.dbErr(w, err)
		} else {
			s.fail(w, 400, err.Error())
		}
		return
	}
	nu, _ := getUser(s.reader(), u.ID)
	s.ok(w, nu)
}

func (s *Server) queryOrders(where string, args ...any) ([]*Order, error) {
	rows, err := s.reader().Query(`SELECT o.id,o.order_no,o.user_id,COALESCE(u.username,''),o.type,o.plan_id,o.amount,o.status,
		o.pay_method,o.trade_no,o.note,o.created_at,o.paid_at FROM orders o LEFT JOIN users u ON u.id=o.user_id `+
		where+` ORDER BY o.id DESC LIMIT 500`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Order{}
	for rows.Next() {
		o := &Order{}
		if err := rows.Scan(&o.ID, &o.OrderNo, &o.UserID, &o.Username, &o.Type, &o.PlanID, &o.Amount, &o.Status,
			&o.PayMethod, &o.TradeNo, &o.Note, &o.CreatedAt, &o.PaidAt); err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

func (s *Server) handleOrders(w http.ResponseWriter, r *http.Request, u *User) {
	out, err := s.queryOrders(`WHERE o.user_id=?`, u.ID)
	if err != nil {
		s.dbErr(w, err)
		return
	}
	s.ok(w, out)
}

// handleRedeem 兑换码:余额型直接入账,套餐型直接开通。
func (s *Server) handleRedeem(w http.ResponseWriter, r *http.Request, u *User) {
	if !s.limiter.allow("redeem:"+strconv.FormatInt(u.ID, 10), 10, time.Minute) {
		s.fail(w, http.StatusTooManyRequests, "尝试次数过多,请稍后再试")
		return
	}
	var in struct {
		Code string `json:"code"`
	}
	if err := bind(r, &in); err != nil {
		s.fail(w, 400, err.Error())
		return
	}
	tx, err := s.db.Begin()
	if err != nil {
		s.dbErr(w, err)
		return
	}
	defer tx.Rollback()
	var id, amount, planID, usedBy int64
	var typ string
	err = tx.QueryRow(`SELECT id,type,amount,plan_id,used_by FROM redeem_codes WHERE code=?`, strings.TrimSpace(in.Code)).
		Scan(&id, &typ, &amount, &planID, &usedBy)
	if err != nil || usedBy != 0 {
		s.fail(w, 400, "兑换码无效或已被使用")
		return
	}
	t := now()
	note := ""
	if typ == "plan" {
		p, err := getPlan(tx, planID)
		if err != nil {
			s.fail(w, 400, "兑换码对应的套餐已不存在")
			return
		}
		cu, err := getUser(tx, u.ID)
		if err == nil {
			err = applyPlan(tx, cu, p)
		}
		if err != nil {
			s.dbErr(w, err)
			return
		}
		note = "兑换套餐: " + p.Name
	} else {
		if err := shopWriteOne(tx, `UPDATE users SET balance=balance+? WHERE id=?`, amount, u.ID); err != nil {
			s.dbErr(w, err)
			return
		}
		note = "兑换余额"
	}
	if err := shopWriteOne(tx, `UPDATE redeem_codes SET used_by=?, used_at=? WHERE id=? AND used_by=0`, u.ID, t, id); err != nil {
		s.dbErr(w, err)
		return
	}
	if err := shopWriteOne(tx, `INSERT INTO orders(order_no,user_id,type,plan_id,amount,status,pay_method,note,created_at,paid_at)
		VALUES(?,?,'redeem',?,?,'paid','code',?,?,?)`, orderNo(), u.ID, planID, amount, note, t, t); err != nil {
		s.dbErr(w, err)
		return
	}
	nu, err := getUser(tx, u.ID)
	if err != nil {
		s.dbErr(w, err)
		return
	}
	if err := tx.Commit(); err != nil {
		s.dbErr(w, err)
		return
	}
	if typ == "plan" {
		s.hub.Dirty()
	}
	s.ok(w, H{"message": note + "成功", "user": nu})
}

// ---- 易支付(彩虹易支付 submit 模式)----

// epaySign 计算签名:参数按键名升序拼成 k=v&k=v(跳过 sign、sign_type 与空值),末尾接商户密钥后取 MD5。
func epaySign(params map[string]string, key string) string {
	keys := make([]string, 0, len(params))
	for k, v := range params {
		if k == "sign" || k == "sign_type" || v == "" {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var sb strings.Builder
	for i, k := range keys {
		if i > 0 {
			sb.WriteByte('&')
		}
		sb.WriteString(k + "=" + params[k])
	}
	sb.WriteString(key)
	sum := md5.Sum([]byte(sb.String()))
	return hex.EncodeToString(sum[:])
}

func (s *Server) handleRecharge(w http.ResponseWriter, r *http.Request, u *User) {
	gateway := strings.TrimRight(s.setting("epay_url", ""), "/")
	pid, key := s.setting("epay_pid", ""), s.setting("epay_key", "")
	if gateway == "" || pid == "" || key == "" {
		s.fail(w, 400, "本站尚未配置在线支付,请使用兑换码或联系管理员充值")
		return
	}
	var in struct {
		Amount float64 `json:"amount"` // 元
		Method string  `json:"method"`
	}
	if err := bind(r, &in); err != nil {
		s.fail(w, 400, err.Error())
		return
	}
	cents := int64(math.Round(in.Amount * 100))
	minC, _ := strconv.ParseInt(s.setting("recharge_min", "100"), 10, 64)
	if cents < minC || cents > 10_000_000 {
		s.fail(w, 400, fmt.Sprintf("充值金额需不少于 %.2f 元", float64(minC)/100))
		return
	}
	if in.Method == "" {
		in.Method = "alipay"
	}
	allowed := false
	for _, method := range strings.Split(s.setting("epay_types", "alipay,wxpay"), ",") {
		if in.Method == strings.TrimSpace(method) && method != "" {
			allowed = true
			break
		}
	}
	if !allowed {
		s.fail(w, 400, "支付通道未启用")
		return
	}
	no := orderNo()
	res, err := s.db.Exec(`INSERT INTO orders(order_no,user_id,type,amount,status,pay_method,note,created_at)
		SELECT ?,?,'recharge',?,'pending',?,'余额充值',? WHERE (SELECT COUNT(*) FROM orders WHERE user_id=? AND type='recharge' AND status='pending')<5`, no, u.ID, cents, in.Method, now(), u.ID)
	if err != nil {
		s.dbErr(w, err)
		return
	}
	if n, err := res.RowsAffected(); err != nil {
		s.dbErr(w, err)
		return
	} else if n == 0 {
		s.fail(w, 429, "待支付订单已达上限")
		return
	}
	base := s.baseURL(r)
	p := map[string]string{
		"pid": pid, "type": in.Method, "out_trade_no": no,
		"notify_url": base + "/api/pay/epay/notify", "return_url": base + "/api/pay/epay/return",
		"name": "余额充值", "money": fmt.Sprintf("%.2f", float64(cents)/100),
	}
	q := url.Values{}
	for k, v := range p {
		q.Set(k, v)
	}
	q.Set("sign", epaySign(p, key))
	q.Set("sign_type", "MD5")
	s.ok(w, H{"url": gateway + "/submit.php?" + q.Encode(), "order_no": no})
}

// handleEpayNotify 是支付网关的异步回调:验签 -> 核对金额 -> 订单置为已支付并入账(幂等)。
func (s *Server) handleEpayNotify(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	p := map[string]string{}
	for k := range r.Form {
		p[k] = r.Form.Get(k)
	}
	key := s.setting("epay_key", "")
	if key == "" || p["pid"] == "" || p["pid"] != s.setting("epay_pid", "") || subtle.ConstantTimeCompare([]byte(epaySign(p, key)), []byte(strings.ToLower(p["sign"]))) != 1 {
		http.Error(w, "fail", http.StatusBadRequest)
		return
	}
	if p["trade_status"] != "TRADE_SUCCESS" {
		w.Write([]byte("success"))
		return
	}
	tx, err := s.db.Begin()
	if err != nil {
		http.Error(w, "fail", http.StatusInternalServerError)
		return
	}
	defer tx.Rollback()
	var id, uid, amount int64
	var status string
	if err := tx.QueryRow(`SELECT id,user_id,amount,status FROM orders WHERE order_no=? AND type='recharge'`,
		p["out_trade_no"]).Scan(&id, &uid, &amount, &status); err != nil {
		http.Error(w, "fail", http.StatusBadRequest)
		return
	}
	if status == "paid" {
		w.Write([]byte("success"))
		return
	}
	if status != "pending" {
		log.Printf("[支付] 非待支付订单 %s 收到成功回调，需要人工核对", p["out_trade_no"])
		http.Error(w, "fail", http.StatusConflict)
		return
	}
	money, _ := strconv.ParseFloat(p["money"], 64)
	if int64(math.Round(money*100)) != amount {
		log.Printf("[支付] 订单 %s 回调金额不符: %s", p["out_trade_no"], p["money"])
		http.Error(w, "fail", http.StatusBadRequest)
		return
	}
	if err := shopWriteOne(tx, `UPDATE orders SET status='paid', paid_at=?, trade_no=? WHERE id=? AND status=?`, now(), p["trade_no"], id, status); err != nil {
		http.Error(w, "fail", http.StatusInternalServerError)
		return
	}
	if err := shopWriteOne(tx, `UPDATE users SET balance=balance+? WHERE id=?`, amount, uid); err != nil {
		http.Error(w, "fail", http.StatusInternalServerError)
		return
	}
	if err := tx.Commit(); err != nil {
		http.Error(w, "fail", http.StatusInternalServerError)
		return
	}
	log.Printf("[支付] 订单 %s 已支付 %.2f 元", p["out_trade_no"], float64(amount)/100)
	w.Write([]byte("success"))
}
