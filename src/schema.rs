table! {
    sessions (id) {
        id -> Uuid,
        sub -> Uuid,
        public_key -> Bytea,
        private_key -> Bytea,
        started -> Timestamptz,
        exp -> Timestamptz,
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
    }
}

joinable!(sessions -> users (sub));

allow_tables_to_appear_in_same_query!(sessions, users,);
