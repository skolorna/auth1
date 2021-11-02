table! {
    certificates (id) {
        id -> Uuid,
        x509 -> Bytea,
        key -> Bytea,
        not_before -> Timestamptz,
        not_after -> Timestamptz,
    }
}

table! {
    users (id) {
        id -> Uuid,
        email -> Varchar,
        verified -> Bool,
        hash -> Text,
        created_at -> Timestamptz,
        full_name -> Text,
        jwt_secret -> Bytea,
    }
}

allow_tables_to_appear_in_same_query!(certificates, users,);
