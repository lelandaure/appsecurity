package db

import (
	"context"
	"fmt"
)

func (q *Queries) GetUser(ctx context.Context, username string) (Access, error) {

	sqlStatement := fmt.Sprintf("SELECT UserId, Fullname, Username , Password FROM access WHERE Username='%s'", username)
	row := q.db.QueryRowContext(ctx, sqlStatement)

	var access Access
	err := row.Scan(
		&access.UserId,
		&access.Username,
		&access.FullName,
		&access.Password,
	)
	return access, err
}
