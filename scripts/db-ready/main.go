// Wait for an explicitly supplied disposable test database without printing credentials.
package main

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"time"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/lib/pq"
)

func main() {
	driver, dsn := os.Getenv("OIDC_TEST_DRIVER"), os.Getenv("OIDC_TEST_DSN")
	if (driver != "mysql" && driver != "postgres") || dsn == "" {
		fmt.Fprintln(os.Stderr, "Explicit disposable database driver and DSN required")
		os.Exit(1)
	}
	db, err := sql.Open(driver, dsn)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Invalid test database configuration")
		os.Exit(1)
	}
	defer db.Close()
	deadline := time.Now().Add(time.Minute)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		err := db.PingContext(ctx)
		cancel()
		if err == nil {
			fmt.Println("Disposable database ready")
			return
		}
		time.Sleep(time.Second)
	}
	fmt.Fprintln(os.Stderr, "Disposable database did not become ready within one minute")
	os.Exit(1)
}
