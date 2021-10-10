table! {
    keypairs (id) {
        id -> Uuid,
        public -> Bytea,
        private -> Bytea,
        created_at -> Timestamptz,
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

allow_tables_to_appear_in_same_query!(keypairs, users,);
