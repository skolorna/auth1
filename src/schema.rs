table! {
    users (id) {
        id -> Int4,
        email -> Varchar,
        email_verified -> Bool,
        hash -> Text,
        created_at -> Timestamptz,
    }
}
