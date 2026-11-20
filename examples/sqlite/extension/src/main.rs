use std::str::FromStr;

use sqlx::{
    query,
    sqlite::{SqliteConnectOptions, SqlitePool},
};

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let opts = SqliteConnectOptions::from_str(&std::env::var("DATABASE_URL")?)?;
    // The sqlx.toml file controls loading extensions for the CLI
    // and for the query checking macros, *not* for the
    // application while it's running. Thus, if we want the
    // extension to be available during program execution, we need
    // to load it.
    //
    // Note that while in this case the extension paths are the
    // same when checking the program (sqlx.toml) and when running
    // it (here), this is not required. The runtime environment
    // can be entirely different from the development one.
    //
    // The extension can be described with a full path, as seen
    // here, but in many cases that will not be necessary. As long
    // as the extension is installed in a directory on the library
    // search path, it is sufficient to just provide the extension
    // name, like "ipaddr"
    let opts = unsafe { opts.extension("/tmp/sqlite3-lib/ipaddr") };
    // The entrypoint for an extension is usually inferred as
    // `sqlite3_extension_init` or `sqlite3_X_init` where X is the
    // lowercase, ASCII-only equivalent of the filename. For the
    // extension below, this would be `sqlite3_uuidrenamed_init`.
    // The entrypoint can instead be explicitly provided.
    let opts = unsafe {
        opts.extension_with_entrypoint("/tmp/sqlite3-lib/uuid_renamed", "sqlite3_uuid_init")
    };

    let db = SqlitePool::connect_with(opts).await?;

    // We're not running the migrations here, for the sake of brevity
    // and to confirm that the needed extension was loaded during the
    // CLI migrate operation. It would not be unusual to run the
    // migrations here as well, though, using the database connection
    // we just configured.

    query!(
        "insert into addresses (address, family) values (?1, ipfamily(?1))",
        "10.0.0.10"
    )
    .execute(&db)
    .await?;

    query!("insert into uuids (uuid) values (uuid4())")
        .execute(&db)
        .await?;

    println!("Queries which require the extensions were successfully executed.");

    Ok(())
}

// `#[sqlx::test]` also applies the driver configuration from `sqlx.toml`,
// so migrations and fixtures that need the extensions can run in tests.
#[cfg(test)]
mod tests {
    use sqlx::{query_scalar, SqlitePool};

    #[sqlx::test]
    async fn test_migrations_with_extensions(pool: SqlitePool) -> sqlx::Result<()> {
        // These rows were inserted by a migration which requires the
        // `ipfamily()` extension function: half of the addresses are IPv6
        // (family 6) and half are IPv4 (family 4).
        let total: i64 = query_scalar("select count(*) from addresses")
            .fetch_one(&pool)
            .await?;

        let ipv6_count: i64 = query_scalar("select count(*) from addresses where family = 6")
            .fetch_one(&pool)
            .await?;

        let ipv4_count: i64 = query_scalar("select count(*) from addresses where family = 4")
            .fetch_one(&pool)
            .await?;

        assert_eq!(total, 18);
        assert_eq!(ipv6_count, 9);
        assert_eq!(ipv4_count, 9);

        // These rows were inserted by a migration which requires the
        // `uuid4()` extension function.
        let uuid_count: i64 = query_scalar("select count(*) from uuids")
            .fetch_one(&pool)
            .await?;

        assert_eq!(uuid_count, 3);

        // The extensions are also available to the test itself, as it uses
        // the same connection options.
        let family: i64 = query_scalar("select ipfamily('192.168.16.12')")
            .fetch_one(&pool)
            .await?;

        assert_eq!(family, 4);

        Ok(())
    }
}
