mod common;

use assert_cmd::cargo_bin_cmd;
use common::MigrateCommand;
use common::TestDatabase;

#[tokio::test]
async fn run_reversible_migrations() {
    let all_migrations: Vec<i64> = vec![
        20230101000000,
        20230201000000,
        20230301000000,
        20230401000000,
        20230501000000,
    ];
    // Without --target-version specified.k
    {
        let db = TestDatabase::new("run_reversible_latest", "migrations_reversible");
        db.run_migration(MigrateCommand::Run, None, false).success();
        assert_eq!(db.applied_migrations().await, all_migrations);
    }
    // With --target-version specified.
    {
        let db = TestDatabase::new("run_reversible_latest_explicit", "migrations_reversible");

        // Move to latest, explicitly specified.
        db.run_migration(MigrateCommand::Run, Some(20230501000000), false)
            .success();
        assert_eq!(db.applied_migrations().await, all_migrations);

        // Move to latest when we're already at the latest.
        db.run_migration(MigrateCommand::Run, Some(20230501000000), false)
            .success();
        assert_eq!(db.applied_migrations().await, all_migrations);

        // Upgrade to an old version.
        db.run_migration(MigrateCommand::Run, Some(20230301000000), false)
            .failure();
        assert_eq!(db.applied_migrations().await, all_migrations);
    }
    // With --target-version, incrementally upgrade.
    {
        let db = TestDatabase::new("run_reversible_incremental", "migrations_reversible");

        // First version
        db.run_migration(MigrateCommand::Run, Some(20230101000000), false)
            .success();
        assert_eq!(db.applied_migrations().await, vec![20230101000000]);

        // Dry run upgrade to latest.
        db.run_migration(MigrateCommand::Run, None, true).success();
        assert_eq!(db.applied_migrations().await, vec![20230101000000]);

        // Dry run upgrade + 2
        db.run_migration(MigrateCommand::Run, Some(20230301000000), true)
            .success();
        assert_eq!(db.applied_migrations().await, vec![20230101000000]);

        // Upgrade to non-existent version.
        db.run_migration(MigrateCommand::Run, Some(20230901000000999), false)
            .failure();
        assert_eq!(db.applied_migrations().await, vec![20230101000000]);

        // Upgrade + 1
        db.run_migration(MigrateCommand::Run, Some(20230201000000), false)
            .success();
        assert_eq!(
            db.applied_migrations().await,
            vec![20230101000000, 20230201000000]
        );

        // Upgrade + 2
        db.run_migration(MigrateCommand::Run, Some(20230401000000), false)
            .success();
        assert_eq!(db.applied_migrations().await, all_migrations[..4]);
    }
}

#[tokio::test]
async fn revert_migrations() {
    let all_migrations: Vec<i64> = vec![
        20230101000000,
        20230201000000,
        20230301000000,
        20230401000000,
        20230501000000,
    ];

    // Without --target-version
    {
        let db = TestDatabase::new("revert_incremental", "migrations_reversible");
        db.run_migration(MigrateCommand::Run, None, false).success();

        // Dry-run
        db.run_migration(MigrateCommand::Revert, None, true)
            .success();
        assert_eq!(db.applied_migrations().await, all_migrations);

        // Downgrade one
        db.run_migration(MigrateCommand::Revert, None, false)
            .success();
        assert_eq!(db.applied_migrations().await, all_migrations[..4]);

        // Downgrade one
        db.run_migration(MigrateCommand::Revert, None, false)
            .success();
        assert_eq!(db.applied_migrations().await, all_migrations[..3]);
    }
    // With --target-version
    {
        let db = TestDatabase::new("revert_incremental", "migrations_reversible");
        db.run_migration(MigrateCommand::Run, None, false).success();

        // Dry-run downgrade to version 3.
        db.run_migration(MigrateCommand::Revert, Some(20230301000000), true)
            .success();
        assert_eq!(db.applied_migrations().await, all_migrations);

        // Downgrade to version 3.
        db.run_migration(MigrateCommand::Revert, Some(20230301000000), false)
            .success();
        assert_eq!(db.applied_migrations().await, all_migrations[..3]);

        // Try downgrading to the same version.
        db.run_migration(MigrateCommand::Revert, Some(20230301000000), false)
            .success();
        assert_eq!(db.applied_migrations().await, all_migrations[..3]);

        // Try downgrading to a newer version.
        db.run_migration(MigrateCommand::Revert, Some(20230401000000), false)
            .failure();
        assert_eq!(db.applied_migrations().await, all_migrations[..3]);

        // Try downgrading to a non-existent version.
        db.run_migration(MigrateCommand::Revert, Some(9999), false)
            .failure();
        assert_eq!(db.applied_migrations().await, all_migrations[..3]);

        // Ensure we can still upgrade
        db.run_migration(MigrateCommand::Run, Some(20230401000000), false)
            .success();
        assert_eq!(db.applied_migrations().await, all_migrations[..4]);

        // Downgrade to zero.
        db.run_migration(MigrateCommand::Revert, Some(0), false)
            .success();
        assert_eq!(db.applied_migrations().await, Vec::<i64>::new());
    }
}

#[tokio::test]
async fn skip_reversible_migrations() {
    let all_migrations: Vec<i64> = vec![
        20230101000000,
        20230201000000,
        20230301000000,
        20230401000000,
        20230501000000,
    ];
    // Without --target-version specified.
    {
        let db = TestDatabase::new("migrate_skip_reversible_latest", "migrations_reversible");
        db.run_migration(MigrateCommand::Skip, None, false)
            .success();
        assert_eq!(db.applied_migrations().await, all_migrations);
    }
    // With --target-version specified.
    {
        let db = TestDatabase::new(
            "migrate_skip_reversible_latest_explicit",
            "migrations_reversible",
        );

        // Move to latest, explicitly specified.
        db.run_migration(MigrateCommand::Run, Some(20230501000000), false)
            .success();
        assert_eq!(db.applied_migrations().await, all_migrations);

        // Skip to latest when we're already at the latest.
        db.run_migration(MigrateCommand::Skip, Some(20230501000000), false)
            .success();
        assert_eq!(db.applied_migrations().await, all_migrations);

        // Upgrade to an old version.
        db.run_migration(MigrateCommand::Skip, Some(20230301000000), false)
            .failure();
        assert_eq!(db.applied_migrations().await, all_migrations);
    }
    // With --target-version, incrementally upgrade.
    {
        let db = TestDatabase::new(
            "migrate_skip_reversible_incremental",
            "migrations_reversible",
        );

        // Run first version
        db.run_migration(MigrateCommand::Run, Some(20230101000000), false)
            .success();
        assert_eq!(db.applied_migrations().await, vec![20230101000000]);

        // Skip and dry run upgrade to latest.
        db.run_migration(MigrateCommand::Skip, None, true).success();
        assert_eq!(db.applied_migrations().await, vec![20230101000000]);

        // Skip and dry run upgrade + 2
        db.run_migration(MigrateCommand::Skip, Some(20230301000000), true)
            .success();
        assert_eq!(db.applied_migrations().await, vec![20230101000000]);

        // Skip to non-existent version.
        db.run_migration(MigrateCommand::Skip, Some(20230901000000999), false)
            .failure();
        assert_eq!(db.applied_migrations().await, vec![20230101000000]);

        // Upgrade + 1
        db.run_migration(MigrateCommand::Run, Some(20230201000000), false)
            .success();
        assert_eq!(
            db.applied_migrations().await,
            vec![20230101000000, 20230201000000]
        );

        // Skip + 2
        db.run_migration(MigrateCommand::Skip, Some(20230401000000), false)
            .success();
        assert_eq!(db.applied_migrations().await, all_migrations[..4]);
    }
}

#[tokio::test]
async fn ignored_chars() {
    let mut db = TestDatabase::new("ignored-chars", "ignored-chars/LF");
    db.config_path = Some("tests/ignored-chars/sqlx.toml".into());

    db.run_migration(MigrateCommand::Run, None, false).success();

    db.set_migrations("ignored-chars/CRLF");

    let expected_info = "1/installed user\n2/installed post\n3/installed comment\n";

    // `ignored-chars` should produce the same migration checksum here
    db.migrate_info().success().stdout(expected_info);

    // Running migration should be a no-op
    db.run_migration(MigrateCommand::Run, None, false)
        .success()
        .stdout("");

    db.set_migrations("ignored-chars/BOM");
    db.migrate_info().success().stdout(expected_info);
    db.run_migration(MigrateCommand::Run, None, false)
        .success()
        .stdout("");

    db.set_migrations("ignored-chars/oops-all-tabs");
    db.migrate_info().success().stdout(expected_info);
    db.run_migration(MigrateCommand::Run, None, false)
        .success()
        .stdout("");
}

#[tokio::test]
async fn no_lock_migrations() {
    let all_migrations: Vec<i64> = vec![
        20230101000000,
        20230201000000,
        20230301000000,
        20230401000000,
        20230501000000,
    ];

    // `--no-lock` is accepted by `run`, including for dry runs, and by `revert`.
    {
        let db = TestDatabase::new("no_lock_run_revert", "migrations_reversible");

        db.run_migration_with(&["--no-lock"], MigrateCommand::Run, None, true)
            .success();
        assert!(db.applied_migrations().await.is_empty());

        db.run_migration_with(&["--no-lock"], MigrateCommand::Run, None, false)
            .success();
        assert_eq!(db.applied_migrations().await, all_migrations);

        db.run_migration_with(&["--no-lock"], MigrateCommand::Revert, None, false)
            .success();
        assert_eq!(db.applied_migrations().await, all_migrations[..4]);
    }

    // `--no-lock` is accepted by `migrate override skip`.
    {
        let db = TestDatabase::new("no_lock_skip", "migrations_reversible");

        db.run_migration_with(&["--no-lock"], MigrateCommand::Skip, None, false)
            .success();
        assert_eq!(db.applied_migrations().await, all_migrations);
    }

    // `--no-lock` is accepted by `database setup`.
    {
        let db = TestDatabase::new("no_lock_setup", "migrations_reversible");

        cargo_bin_cmd!("sqlx")
            .args(["database", "setup", "--no-lock"])
            .args(["--database-url", &db.connection_string()])
            .args(["--source", "tests/migrations_reversible"])
            .assert()
            .success();
        assert_eq!(db.applied_migrations().await, all_migrations);
    }
}

/// Regression test for #4487: concurrent `sqlx migrate run` invocations must not race.
///
/// The first invocation holds the database lock while it applies migrations, so the second
/// has to wait and then observe that everything was already applied instead of trying to
/// apply the same migrations again.
///
/// Only runs when `SQLX_CLI_TEST_POSTGRES_URL` points at a Postgres server, e.g.
/// `postgres://postgres:password@localhost`; SQLite's `lock()` is a no-op so it can't
/// exercise this behavior.
#[tokio::test]
async fn concurrent_run_waits_for_lock() {
    let Some(base_url) = std::env::var("SQLX_CLI_TEST_POSTGRES_URL").ok() else {
        eprintln!("skipping: SQLX_CLI_TEST_POSTGRES_URL is not set");
        return;
    };

    let db_name = format!("sqlx_cli_lock_test_{}", std::process::id());
    let db_url = format!("{base_url}/{db_name}");

    // A slow migration makes the race deterministic: without locking, the second
    // invocation starts applying it while the first is still sleeping.
    let migrations = tempfile::tempdir().unwrap();
    std::fs::write(
        migrations.path().join("0001_slow.sql"),
        "SELECT pg_sleep(1);\nCREATE TABLE sqlx_cli_lock_test (x INTEGER PRIMARY KEY);\n",
    )
    .unwrap();

    let sqlx = assert_cmd::cargo::cargo_bin("sqlx");

    // Clean up any leftover database from a previous run.
    let _ = std::process::Command::new(&sqlx)
        .args(["database", "drop", "-y", "--database-url", &db_url])
        .status();

    let create = std::process::Command::new(&sqlx)
        .args(["database", "create", "--database-url", &db_url])
        .status()
        .unwrap();
    assert!(create.success(), "failed to create {db_name}");

    let spawn = || {
        std::process::Command::new(&sqlx)
            .args(["migrate", "run", "--database-url", &db_url, "--source"])
            .arg(migrations.path())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap()
    };

    let first = spawn();
    // Give the first invocation a head start, so it's likely to be the one holding the lock.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let second = spawn();

    let (first, second) = tokio::task::spawn_blocking(move || {
        (
            first.wait_with_output().unwrap(),
            second.wait_with_output().unwrap(),
        )
    })
    .await
    .unwrap();

    let _ = std::process::Command::new(&sqlx)
        .args(["database", "drop", "-y", "--database-url", &db_url])
        .status();

    let output = |out: &std::process::Output| {
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
    };

    // Both invocations must succeed; without the lock, the one that loses the race fails
    // with a "relation already exists" error from the migration SQL.
    assert!(
        first.status.success(),
        "first migration run failed: {}",
        output(&first)
    );
    assert!(
        second.status.success(),
        "second migration run failed (it should have waited for the lock): {}",
        output(&second)
    );

    // Whichever invocation acquired the lock first applies the migration; the other one
    // waits for the lock and then finds nothing left to do.
    let applied = [output(&first), output(&second)]
        .iter()
        .filter(|out| out.contains("Applied 1/"))
        .count();
    assert_eq!(
        applied,
        1,
        "exactly one invocation should have applied the migration; first: {:?}, second: {:?}",
        output(&first),
        output(&second)
    );
}
