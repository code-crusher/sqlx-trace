use sqlx::Sqlite;
use sqlx_test::test_type;

#[derive(Debug, PartialEq, sqlx::Type)]
#[repr(u32)]
enum Origin {
    Foo = 1,
    Bar = 2,
}

test_type!(origin_enum<Origin>(Sqlite,
    "1" == Origin::Foo,
    "2" == Origin::Bar,
));

// A "strong" enum with a catch-all variant for values added to the database after this version
// of the program was built.
#[derive(Debug, PartialEq, sqlx::Type)]
#[sqlx(rename_all = "lowercase")]
enum Operation {
    Add,
    Subtract,
    #[sqlx(other)]
    Unknown(String),
}

test_type!(other_enum<Operation>(Sqlite,
    "'add'" == Operation::Add,
    "'subtract'" == Operation::Subtract,
    "'multiply'" == Operation::Unknown("multiply".to_owned()),
));

// Same as above, but for a "weak" enum which encodes to an integer.
#[derive(Debug, PartialEq, sqlx::Type)]
#[repr(i32)]
enum WeakOperation {
    Add = 1,
    Subtract = 2,
    #[sqlx(other)]
    Unknown(i32),
}

test_type!(other_weak_enum<WeakOperation>(Sqlite,
    "1" == WeakOperation::Add,
    "2" == WeakOperation::Subtract,
    "3" == WeakOperation::Unknown(3),
));

// Decoding a value that has no corresponding variant must not fail; this is what makes rolling
// deployments possible when the database gains a new enum value (see issue #4391).
#[sqlx_macros::test]
async fn other_enum_captures_unrecognized_value() -> anyhow::Result<()> {
    let mut conn = sqlx_test::new::<Sqlite>().await?;

    let value: Operation = sqlx::query_scalar("SELECT 'divide'")
        .fetch_one(&mut conn)
        .await?;

    assert_eq!(value, Operation::Unknown("divide".to_owned()));

    let value: WeakOperation = sqlx::query_scalar("SELECT 42").fetch_one(&mut conn).await?;

    assert_eq!(value, WeakOperation::Unknown(42));

    Ok(())
}

// The `other` variant doesn't have to be declared last, and the remaining variants are renamed
// exactly as they would be without it.
#[derive(Debug, PartialEq, sqlx::Type)]
#[sqlx(rename_all = "UPPERCASE")]
enum FirstOperation {
    #[sqlx(other)]
    Unknown(Box<str>),
    Alpha,
    #[sqlx(rename = "beta!")]
    Beta,
}

test_type!(other_enum_first<FirstOperation>(Sqlite,
    "'ALPHA'" == FirstOperation::Alpha,
    "'beta!'" == FirstOperation::Beta,
    "'GAMMA'" == FirstOperation::Unknown("GAMMA".into()),
));

#[derive(PartialEq, Eq, Debug, sqlx::Type)]
#[sqlx(transparent)]
struct TransparentTuple(i64);

#[derive(PartialEq, Eq, Debug, sqlx::Type)]
#[sqlx(transparent)]
struct TransparentNamed {
    field: i64,
}

test_type!(transparent_tuple<TransparentTuple>(Sqlite,
    "0" == TransparentTuple(0),
    "23523" == TransparentTuple(23523)
));

test_type!(transparent_named<TransparentNamed>(Sqlite,
    "0" == TransparentNamed { field: 0 },
    "23523" == TransparentNamed { field: 23523 },
));
