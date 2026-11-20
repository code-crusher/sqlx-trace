use sqlx::{postgres::Postgres, Column, Executor, SqlSafeStr, TypeInfo};
use sqlx_test::new;

#[sqlx_macros::test]
async fn it_describes_simple() -> anyhow::Result<()> {
    let mut conn = new::<Postgres>().await?;

    let d = conn.describe("SELECT * FROM tweet".into_sql_str()).await?;

    assert_eq!(d.columns()[0].name(), "id");
    assert_eq!(d.columns()[1].name(), "created_at");
    assert_eq!(d.columns()[2].name(), "text");
    assert_eq!(d.columns()[3].name(), "owner_id");

    assert_eq!(d.nullable(0), Some(false));
    assert_eq!(d.nullable(1), Some(false));
    assert_eq!(d.nullable(2), Some(false));
    assert_eq!(d.nullable(3), Some(true));

    assert_eq!(d.columns()[0].type_info().name(), "INT8");
    assert_eq!(d.columns()[1].type_info().name(), "TIMESTAMPTZ");
    assert_eq!(d.columns()[2].type_info().name(), "TEXT");
    assert_eq!(d.columns()[3].type_info().name(), "INT8");

    Ok(())
}

#[sqlx_macros::test]
async fn it_describes_expression() -> anyhow::Result<()> {
    let mut conn = new::<Postgres>().await?;

    let d = conn.describe("SELECT 1::int8 + 10".into_sql_str()).await?;

    // ?column? will cause the macro to emit an error ad ask the user to explicitly name the type
    assert_eq!(d.columns()[0].name(), "?column?");

    // postgres cannot infer nullability from an expression
    // this will cause the macro to emit `Option<_>`
    assert_eq!(d.nullable(0), None);
    assert_eq!(d.columns()[0].type_info().name(), "INT8");

    Ok(())
}

// Regression test for launchbadge/sqlx#3541 and #4274: the query macros force a
// generic query plan on their describe connection so that nullability inference via
// `EXPLAIN` isn't skewed by the `NULL` placeholder arguments bound during `describe`.
// This checks the mechanism still applies on PostgreSQL.
//
// The complementary half of #4274 -- skipping this on databases without `EXPLAIN`
// support (CockroachDB, Materialize, QuestDB), where the previous `DO` block failed
// to even parse -- cannot be exercised here, as CI runs no such database.
#[sqlx_macros::test]
async fn it_forces_generic_plan_for_describe() -> anyhow::Result<()> {
    let mut conn = new::<Postgres>().await?;

    conn.force_generic_plan_for_describe().await?;

    let mode: String = sqlx::query_scalar("SHOW plan_cache_mode")
        .fetch_one(&mut conn)
        .await?;
    assert_eq!(mode, "force_generic_plan");

    Ok(())
}

#[sqlx_macros::test]
async fn it_describes_enum() -> anyhow::Result<()> {
    let mut conn = new::<Postgres>().await?;

    let d = conn
        .describe("SELECT 'open'::status as _1".into_sql_str())
        .await?;

    assert_eq!(d.columns()[0].name(), "_1");

    let ty = d.columns()[0].type_info();

    assert_eq!(ty.name(), "status");

    assert_eq!(
        format!("{:?}", ty.kind()),
        r#"Enum(["new", "open", "closed"])"#
    );

    Ok(())
}

#[sqlx_macros::test]
async fn it_describes_record() -> anyhow::Result<()> {
    let mut conn = new::<Postgres>().await?;

    let d = conn
        .describe("SELECT (true, 10::int2)".into_sql_str())
        .await?;

    let ty = d.columns()[0].type_info();
    assert_eq!(ty.name(), "RECORD");

    Ok(())
}

#[sqlx_macros::test]
async fn it_describes_composite() -> anyhow::Result<()> {
    let mut conn = new::<Postgres>().await?;

    let d = conn
        .describe("SELECT ROW('name',10,500)::inventory_item".into_sql_str())
        .await?;

    let ty = d.columns()[0].type_info();

    assert_eq!(ty.name(), "inventory_item");

    assert_eq!(
        format!("{:?}", ty.kind()),
        r#"Composite([("name", PgTypeInfo(Text)), ("supplier_id", PgTypeInfo(Int4)), ("price", PgTypeInfo(Int8))])"#
    );

    Ok(())
}

// Regression test for #4332: `RETURNING old.<col>`/`new.<col>` reference the
// OLD/NEW transition relations (PostgreSQL 18+) and are null depending on the
// operation, even when the underlying column is `NOT NULL`.
#[sqlx_macros::test]
async fn it_describes_returning_transition_relations() -> anyhow::Result<()> {
    let mut conn = new::<Postgres>().await?;

    // Transition relations were introduced in PostgreSQL 18.
    if !matches!(conn.server_version_num(), Some(version) if version >= 180_000) {
        return Ok(());
    }

    conn.execute("DROP TABLE IF EXISTS issue_4332_files")
        .await?;
    conn.execute(
        "CREATE TABLE issue_4332_files (hash BYTEA PRIMARY KEY CHECK (LENGTH(hash) = 32))",
    )
    .await?;

    let d = conn
        .describe(
            "INSERT INTO issue_4332_files (hash) VALUES ('\\xdeadbeef'::bytea) \
             ON CONFLICT (hash) DO NOTHING RETURNING old.hash"
                .into_sql_str(),
        )
        .await?;
    assert_eq!(d.nullable(0), Some(true));

    // A plain reference to the column is still non-nullable.
    let d = conn
        .describe(
            "INSERT INTO issue_4332_files (hash) VALUES ('\\xdeadbeef'::bytea) \
             ON CONFLICT (hash) DO NOTHING RETURNING hash"
                .into_sql_str(),
        )
        .await?;
    assert_eq!(d.nullable(0), Some(false));

    // The same expression may also be returned more than once, and a plain
    // column reference in the same `RETURNING` list keeps its own nullability.
    let d = conn
        .describe(
            "INSERT INTO issue_4332_files (hash) VALUES ('\\xdeadbeef'::bytea) \
             ON CONFLICT (hash) DO NOTHING RETURNING old.hash, old.hash AS h, hash"
                .into_sql_str(),
        )
        .await?;
    assert_eq!(d.nullable(0), Some(true));
    assert_eq!(d.nullable(1), Some(true));
    assert_eq!(d.nullable(2), Some(false));

    // `new` is null for a row removed by `DELETE`.
    let d = conn
        .describe("DELETE FROM issue_4332_files RETURNING old.hash, new.hash".into_sql_str())
        .await?;
    assert_eq!(d.nullable(0), Some(true));
    assert_eq!(d.nullable(1), Some(true));

    conn.execute("DROP TABLE issue_4332_files").await?;

    Ok(())
}

// Regression test for #4497: resolving one custom type could drop other
// pending dependencies, leaving them unresolved on a cold type cache.
#[sqlx_macros::test]
async fn it_describes_nested_custom_types() -> anyhow::Result<()> {
    let mut conn = new::<Postgres>().await?;
    conn.execute(
        r#"
DROP TYPE IF EXISTS issue_4497_holder CASCADE;
DROP TYPE IF EXISTS issue_4497_pair CASCADE;
DROP TYPE IF EXISTS issue_4497_leaf_b CASCADE;
DROP TYPE IF EXISTS issue_4497_leaf_a CASCADE;

CREATE TYPE issue_4497_leaf_a AS (x int4);
CREATE TYPE issue_4497_leaf_b AS (y int4);
CREATE TYPE issue_4497_pair AS (a issue_4497_leaf_a, b issue_4497_leaf_b);
CREATE TYPE issue_4497_holder AS (items issue_4497_leaf_a[]);
"#,
    )
    .await?;

    // A fresh connection so the type-OID cache is cold.
    let mut conn = new::<Postgres>().await?;
    conn.describe(
        "SELECT NULL::issue_4497_pair[] AS pairs, NULL::issue_4497_holder AS holder".into_sql_str(),
    )
    .await?;

    Ok(())
}
