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
		if it.RuleID <= 0 || it.Up < 0 || it.Down < 0 || it.Up > math.MaxInt64-it.Down {
			return errors.New("invalid traffic delta")
		}
		raw := it.Up + it.Down
		if raw == 0 {
			continue
		}
		var user, out int64
		err = tx.QueryRow(`SELECT user_id,out_group FROM rules WHERE id=? AND in_group=?`, it.RuleID, gid).Scan(&user, &out)
		if errors.Is(err, sql.ErrNoRows) { // rule deleted or moved before a late report: preserve evidence instead of charging the new owner
			if err = trafficWrite(tx, 1, `INSERT INTO traffic_unattributed(group_id,uid,stream,seq,rule_id,up,down,hour) VALUES(?,?,?,?,?,?,?,?)`, gid, uid, rep.Stream, rep.Seq, it.RuleID, it.Up, it.Down, hour); err != nil {
				return err
			}
			continue
		}
		if err != nil {
			return err
		}
		var ratio float64
		var n int
		expected := int64(1)
		if out != 0 && out != gid {
			expected++
		}
		if err = tx.QueryRow(`SELECT COUNT(*),SUM(ratio) FROM device_groups WHERE id=? OR (id=? AND ?<>0)`, gid, out, out).Scan(&n, &ratio); err != nil {
			return err
		}
		charge := float64(raw) * ratio
		if int64(n) != expected || ratio < 0 || math.IsNaN(charge) || charge >= float64(math.MaxInt64) {
			return errors.New("invalid traffic billing groups or amount")
		}
		billed := int64(charge)
		if err = trafficWrite(tx, 1, `UPDATE rules SET traffic_up=traffic_up+?,traffic_down=traffic_down+? WHERE id=? AND in_group=? AND traffic_up<=? AND traffic_down<=?`, it.Up, it.Down, it.RuleID, gid, math.MaxInt64-it.Up, math.MaxInt64-it.Down); err != nil {
			return err
		}
		var used, quota int64
		var role string
		if err = tx.QueryRow(`UPDATE users SET traffic_used=traffic_used+? WHERE id=? AND traffic_used<=? RETURNING traffic_used,traffic_quota,role`, billed, user, math.MaxInt64-billed).Scan(&used, &quota, &role); err != nil {
			return err
		}
		if role != "admin" && used >= quota && used-billed < quota {
			crossed = true
		}
		if err = trafficWrite(tx, 1, `INSERT INTO traffic_hourly(user_id,hour,up,down,billed) VALUES(?,?,?,?,?) ON CONFLICT(user_id,hour) DO UPDATE SET up=up+excluded.up,down=down+excluded.down,billed=billed+excluded.billed WHERE up<=? AND down<=? AND billed<=?`, user, hour, it.Up, it.Down, billed, math.MaxInt64-it.Up, math.MaxInt64-it.Down, math.MaxInt64-billed); err != nil {
			return err
		}
		if err = trafficWrite(tx, expected, `UPDATE device_groups SET traffic=traffic+? WHERE (id=? OR (id=? AND ?<>0)) AND traffic<=?`, raw, gid, out, out, math.MaxInt64-raw); err != nil {
			return err
		}
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
