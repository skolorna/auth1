table! {
    keys (id) {
        id -> Int4,
        sub -> Int4,
        public_key -> Bytea,
        private_key -> Bytea,
        iat -> Timestamptz,
    }
}

table! {
    users (id) {
        id -> Int4,
        email -> Varchar,
        email_verified -> Bool,
        hash -> Text,
        created_at -> Timestamptz,
    }
}

joinable!(keys -> users (sub));

allow_tables_to_appear_in_same_query!(keys, users,);
