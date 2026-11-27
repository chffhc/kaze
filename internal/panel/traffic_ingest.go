package panel

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"

	"kaze/internal/proto"
)

// A node has a single outstanding batch. Persist its cursor in the same
// immediate SQLite transaction as ALL counters. A replay after commit can be
// confirmed without recomputing prices (which may since have changed).
func (h *Hub) ingest(gid int64, uid string, rep *proto.Report) error {
	if uid == "" || rep.Seq < 1 || len(rep.Items) == 0 {
		return errors.New("invalid traffic report")
	}
	if rep.Stream != "" {
		if len(rep.Stream) != 32 || strings.ToLower(rep.Stream) != rep.Stream {
			return errors.New("invalid traffic stream")
		}
		if _, err := hex.DecodeString(rep.Stream); err != nil {
			return errors.New("invalid traffic stream")
		}
	}
	b, err := json.Marshal(rep.Items)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(b)
	tx, err := h.s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var last int64
	var prev []byte
	err = tx.QueryRow(`SELECT seq,digest FROM traffic_cursors WHERE group_id=? AND uid=? AND stream=?`, gid, uid, rep.Stream).Scan(&last, &prev)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if last == rep.Seq {
		if !bytes.Equal(prev, digest[:]) {
			return errors.New("traffic sequence reused with different payload")
		}
		return nil
	}
	// v1 used a timestamp on boot; gaps are normal. A backwards clock or a
	// restored old snapshot must not turn an ambiguous report into a new debit.
	if rep.Seq < last || (rep.Stream != "" && rep.Seq-1 != last) {
		return errors.New("traffic sequence gap or regression; reconcile node state")
	}
	hour := now() / 3600 * 3600
	crossed := false
	for _, it := range rep.Items {
		if it.Up == 0 && it.Down == 0 && it.RuleID > 0 {
			continue
		}
		usedUp, err := ingestTrafficItem(tx, gid, uid, rep, it, hour)
		if err != nil {
			return err
		}
		crossed = crossed || usedUp
	}
	if err = trafficWrite(tx, 1, `INSERT INTO traffic_cursors(group_id,uid,stream,seq,digest) VALUES(?,?,?,?,?) ON CONFLICT(group_id,uid,stream) DO UPDATE SET seq=excluded.seq,digest=excluded.digest`, gid, uid, rep.Stream, rep.Seq, digest[:]); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	if crossed {
		h.Dirty()
	}
	return nil
}

// A historical route can still be billed after the live rule is moved or removed.
func ingestTrafficItem(tx *sql.Tx, gid int64, uid string, rep *proto.Report, it proto.Traffic, hour int64) (bool, error) {
	unattributed := func() error {
		return trafficWrite(tx, 1, `INSERT INTO traffic_unattributed(group_id,uid,stream,seq,rule_id,up,down,hour)
			VALUES(?,?,?,?,?,?,?,?)`, gid, uid, rep.Stream, rep.Seq, it.RuleID, it.Up, it.Down, hour)
	}
	if it.RuleID <= 0 || it.Up < 0 || it.Down < 0 || it.Up > math.MaxInt64-it.Down {
		return false, unattributed()
	}
	var user, out int64
	var ratio float64
	var hopJSON string
	err := tx.QueryRow(`SELECT r.user_id,r.out_group,COALESCE(i.ratio,1)+COALESCE(o.ratio,0),
		COALESCE(CASE WHEN o.type='chain' AND json_valid(o.config) THEN json_extract(o.config,'$.chain_hops') END,'[]')
		FROM rules r LEFT JOIN device_groups i ON i.id=r.in_group
		LEFT JOIN device_groups o ON o.id=r.out_group AND o.id<>i.id
		WHERE r.id=? AND r.in_group=?`, it.RuleID, gid).Scan(&user, &out, &ratio, &hopJSON)
	live := err == nil
	if errors.Is(err, sql.ErrNoRows) {
		err = tx.QueryRow(`SELECT user_id,out_group,ratio,hops FROM rule_billing_history
			WHERE rule_id=? AND in_group=?`, it.RuleID, gid).Scan(&user, &out, &ratio, &hopJSON)
	}
	if errors.Is(err, sql.ErrNoRows) {
		return false, unattributed()
	}
	if err != nil {
		return false, err
	}
	if ratio < 0 || math.IsNaN(ratio) || math.IsInf(ratio, 0) {
		return false, unattributed()
	}

	var used, quota int64
	var role string
	err = tx.QueryRow(`SELECT traffic_used,traffic_quota,role FROM users WHERE id=?`, user).Scan(&used, &quota, &role)
	if errors.Is(err, sql.ErrNoRows) {
		return false, unattributed()
	}
	if err != nil {
		return false, err
	}

	raw := it.Up + it.Down
	charge := float64(raw) * ratio
	billed := int64(math.MaxInt64)
	if charge < float64(math.MaxInt64) {
		billed = int64(charge)
	}
	if live {
		if err := trafficWrite(tx, 1, `UPDATE rules SET
			traffic_up=CASE WHEN traffic_up>? THEN ? ELSE traffic_up+? END,
			traffic_down=CASE WHEN traffic_down>? THEN ? ELSE traffic_down+? END
			WHERE id=? AND in_group=?`, math.MaxInt64-it.Up, math.MaxInt64, it.Up,
			math.MaxInt64-it.Down, math.MaxInt64, it.Down, it.RuleID, gid); err != nil {
			return false, err
		}
	}
	next := used + min(billed, math.MaxInt64-max(used, 0))
	if err := trafficWrite(tx, 1, `UPDATE users SET traffic_used=? WHERE id=?`, next, user); err != nil {
		return false, err
	}
	if err := trafficWrite(tx, 1, `INSERT INTO traffic_hourly(user_id,hour,up,down,billed) VALUES(?,?,?,?,?)
		ON CONFLICT(user_id,hour) DO UPDATE SET
		up=CASE WHEN up>? THEN ? ELSE up+excluded.up END,
		down=CASE WHEN down>? THEN ? ELSE down+excluded.down END,
		billed=CASE WHEN billed>? THEN ? ELSE billed+excluded.billed END`,
		user, hour, it.Up, it.Down, billed, math.MaxInt64-it.Up, math.MaxInt64,
		math.MaxInt64-it.Down, math.MaxInt64, math.MaxInt64-billed, math.MaxInt64); err != nil {
		return false, err
	}
	groups := map[int64]bool{gid: true}
	if out != 0 {
		groups[out] = true
	}
	var hops []int64
	if json.Unmarshal([]byte(hopJSON), &hops) == nil {
		for _, hop := range hops {
			groups[hop] = true
		}
	}
	for id := range groups {
		var exists bool
		if err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM device_groups WHERE id=?)`, id).Scan(&exists); err != nil {
			return false, err
		}
		if exists {
			if err := trafficWrite(tx, 1, `UPDATE device_groups SET
				traffic=CASE WHEN traffic>? THEN ? ELSE traffic+? END WHERE id=?`,
				math.MaxInt64-raw, math.MaxInt64, raw, id); err != nil {
				return false, err
			}
		}
	}
	return role != "admin" && used < quota && next >= quota, nil
}

func trafficWrite(tx *sql.Tx, want int64, stmt string, args ...any) error {
	res, err := tx.Exec(stmt, args...)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != want {
		return fmt.Errorf("traffic ledger write affected %d rows, expected %d", n, want)
	}
	return nil
}
