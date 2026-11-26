package panel

import (
	"context"
	"log"
	"time"
)

// jobs 是面板的后台任务:到期处理、自动续费、数据清理。
func (s *Server) jobs(ctx context.Context) {
	tick := time.NewTicker(30 * time.Second)
	defer tick.Stop()
	hourly := time.NewTicker(time.Hour)
	defer hourly.Stop()
	last := now()
	s.cleanup()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			t := now()
			s.autoRenew(t)
			// 这段时间内刚到期的用户:重新下发配置以停掉其规则
			var n int
			s.db.QueryRow(`SELECT COUNT(*) FROM users WHERE expire_at>? AND expire_at<=?`, last, t).Scan(&n)
			if n > 0 {
				s.hub.Dirty()
			}
			last = t
		case <-hourly.C:
			s.cleanup()
		}
	}
}

// autoRenew 为已到期、开启了自动续费且余额足够的用户续费原套餐。
// 余额不足的用户会在之后充值到账时被自动续上。
func (s *Server) autoRenew(t int64) {
	rows, err := s.db.Query(`SELECT u.id, u.plan_id FROM users u JOIN plans p ON p.id=u.plan_id
		WHERE u.auto_renew=1 AND u.banned=0 AND u.expire_at>0 AND u.expire_at<=? AND u.balance>=p.price`, t)
	if err != nil {
		return
	}
	type item struct{ uid, pid int64 }
	var list []item
	for rows.Next() {
		var it item
		rows.Scan(&it.uid, &it.pid)
		list = append(list, it)
	}
	rows.Close()
	for _, it := range list {
		if err := s.purchase(it.uid, it.pid, "renew"); err != nil {
			log.Printf("[续费] 用户 #%d 自动续费失败: %v", it.uid, err)
		} else {
			log.Printf("[续费] 用户 #%d 已自动续费套餐 #%d", it.uid, it.pid)
		}
	}
}

func (s *Server) cleanup() {
	t := now()
	s.db.Exec(`DELETE FROM traffic_hourly WHERE hour<?`, t-62*86400)
	s.db.Exec(`UPDATE orders SET status='cancelled' WHERE status='pending' AND created_at<?`, t-86400)
}
