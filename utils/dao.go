package utils

import (
	"context"
	"database/sql"

	_ "github.com/mattn/go-sqlite3"
)

type UserID int

type User struct {
	ID       UserID
	Name     string
	Password string
}

type Dao struct {
	conn *sql.DB
}

func (d Dao) Create(ctx context.Context, u *User) (id UserID, err error) {
	id = UserID(-1)
	err = d.conn.QueryRowContext(ctx, "INSERT INTO users(name, password) VALUES($1, $2) RETURNING id",
		u.Name, u.Password).Scan(&id)
	return
}

func (d Dao) Update(ctx context.Context, u *User) (err error) {
	_, err = d.conn.ExecContext(ctx, "UPDATE users SET name = $1, password = $2 WHERE id = $3",
		u.Name, u.Password, u.ID)
	return
}

func (d Dao) Delete(ctx context.Context, id UserID) (err error) {
	_, err = d.conn.ExecContext(ctx, "DELETE FROM users WHERE id = $1", id)
	return
}

func (d Dao) Lookup(ctx context.Context, name string) (u User, err error) {
	conn := d.conn.QueryRowContext(ctx, "SELECT id, name, password FROM users WHERE name = $1", name)
	err = conn.Scan(&u.ID, &u.Name, &u.Password)
	return
}

func (d Dao) List(ctx context.Context) (users []User, err error) {
	conn, err := d.conn.QueryContext(ctx, "SELECT id, name, password FROM users")
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	users = make([]User, 0)
	for conn.Next() {
		u := User{}
		err = conn.Scan(&u.ID, &u.Name, &u.Password)
		if err != nil {
			return
		}
		users = append(users, u)
	}

	err = conn.Err()
	return
}

func (d Dao) Close() error {
	return d.conn.Close()
}

func CreateDao(ctx context.Context, dsn string) (*Dao, error) {
	conn, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, err
	}
	go func() {
		<-ctx.Done()
		_ = conn.Close()
	}()

	_, err = conn.ExecContext(ctx, "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT, password TEXT)")
	if err != nil {
		return nil, err
	}

	dao := &Dao{
		conn: conn,
	}
	return dao, nil
}
