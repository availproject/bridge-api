// @generated automatically by Diesel CLI.

pub mod sql_types {
    #[derive(diesel::query_builder::QueryId, Clone, diesel::sql_types::SqlType)]
    #[diesel(postgres_type(name = "claim_type"))]
    pub struct ClaimType;

    #[derive(diesel::query_builder::QueryId, Clone, diesel::sql_types::SqlType)]
    #[diesel(postgres_type(name = "status"))]
    pub struct Status;
}

diesel::table! {
    use diesel::sql_types::*;
    use super::sql_types::Status;
    use super::sql_types::ClaimType;

    avail_sends (message_id) {
        message_id -> Int8,
        status -> Status,
        #[max_length = 66]
        source_transaction_hash -> Varchar,
        source_block_number -> Int8,
        #[max_length = 66]
        source_block_hash -> Varchar,
        source_transaction_index -> Int8,
        source_timestamp -> Timestamp,
        #[max_length = 66]
        token_id -> Varchar,
        #[max_length = 66]
        destination_transaction_hash -> Nullable<Varchar>,
        destination_block_number -> Nullable<Int8>,
        #[max_length = 66]
        destination_block_hash -> Nullable<Varchar>,
        destination_timestamp -> Nullable<Timestamp>,
        #[max_length = 66]
        depositor_address -> Varchar,
        #[max_length = 22]
        receiver_address -> Varchar,
        #[max_length = 255]
        amount -> Varchar,
        claim_type -> ClaimType,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    use super::sql_types::Status;
    use super::sql_types::ClaimType;

    ethereum_sends (message_id) {
        message_id -> Int8,
        status -> Status,
        #[max_length = 66]
        source_transaction_hash -> Varchar,
        source_block_number -> Int8,
        #[max_length = 66]
        source_block_hash -> Varchar,
        source_timestamp -> Timestamp,
        #[max_length = 66]
        token_id -> Varchar,
        #[max_length = 66]
        destination_transaction_hash -> Nullable<Varchar>,
        destination_block_number -> Nullable<Int8>,
        #[max_length = 66]
        destination_block_hash -> Nullable<Varchar>,
        destination_transaction_index-> Nullable<Int8>,
        destination_timestamp -> Nullable<Timestamp>,
        #[max_length = 66]
        depositor_address -> Varchar,
        #[max_length = 66]
        receiver_address -> Varchar,
        #[max_length = 255]
        amount -> Varchar,
        claim_type -> ClaimType,
    }
}

diesel::allow_tables_to_appear_in_same_query!(avail_sends, ethereum_sends,);
