mod utils;

use chrono::{DateTime, NaiveDate, Utc};
use reqwest::header::HeaderMap;
use reqwest::Url;
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use serde_aux::prelude::deserialize_number_from_string;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum SafeGoldError {
    #[error("User with ID: {0} does not exist")]
    UserDoesNotExist(String),

    #[error("Bad Request error with message: {0}")]
    BadRequest(String),

    #[error("Missing required information: {0}")]
    MissingRequiredInformation(String),

    #[error("Vendor ID and User ID mismatch")]
    VendorUserMismatch,

    #[error("Invalid transaction ID")]
    InvalidTransaction,

    #[error("Transaction not found with ID: {0}")]
    TransactionNotFound(usize),

    #[error("User Id Missing In Transactions")]
    UserIdMissingInTransaction,

    #[error("Gold amount does not match")]
    GoldAmountDoesNotMatch,

    #[error("Invalid Rate")]
    InvalidRate,

    #[error("Invalid URL")]
    InvalidUrl(#[from] url::ParseError),

    #[error(transparent)]
    UndefinedError(#[from] reqwest::Error),

    #[error("Service not available")]
    ServiceUnavailable,
}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
struct SafeGoldClientError {
    code: usize,
    message: String,
}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct KycRequirement {
    identity_required: u8,
    pan_required: u8,
}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct User {
    id: usize,
    name: String,
    mobile_no: String,
    pincode: String,
    email: Option<String>,
    gold_balance: Decimal,
    kyc_requirement: KycRequirement,
}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct BuyPrice {
    current_price: Decimal,
    applicable_tax: Decimal,
    rate_id: usize,
    #[serde(with = "utils::custom_date_time_format")]
    rate_validity: DateTime<Utc>,
}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct BuyVerifyRequest {
    buy_price: Decimal,
    gold_amount: Decimal,
    rate_id: usize,
}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct BuyVerify {
    tx_id: usize,
    #[serde(deserialize_with = "deserialize_number_from_string")]
    rate_id: usize,
    sg_rate: Decimal,
    partner_rate: Decimal,
    gold_amount: Decimal,
    buy_price: Decimal,
    pre_gst_buy_price: Decimal,
    gst_amount: Decimal,
    #[serde(deserialize_with = "deserialize_number_from_string")]
    user_id: String,
}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct BuyConfirmRequest {
    tx_id: usize,
    date: NaiveDate,
}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct BuyConfirm {
    invoice_id: String,
}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct BuyStatus {
    status: usize,
    realization_status: usize,
    payment_status: usize,
    #[serde(with = "utils::custom_date_time_format")]
    created_at: DateTime<Utc>,
}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct TransactionList {
    transactions: Vec<Transaction>,
    meta: TransactionListMeta,
}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct TransactionListMeta {
    previous: Option<String>,
    next: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct Transaction {
    r#type: String,
    tx_id: usize,
    rate: Decimal,
    gold_amount: Decimal,
    buy_price: Option<Decimal>,
    sell_price: Option<Decimal>,
    pre_gst_buy_price: Option<Decimal>,
    gst_amount: Option<Decimal>,
    user_id: usize,
    #[serde(with = "utils::custom_date_time_format")]
    tx_date: DateTime<Utc>,
}

pub struct SafeGold {
    base_url: reqwest::Url,
    client: reqwest::Client,
}

impl SafeGold {
    pub fn new(base_url: &str, token: &str) -> Result<Self, SafeGoldError> {
        let base_url = Url::parse(base_url)?;
        let mut headers = HeaderMap::new();
        headers.insert(
            "Authorization",
            format!("Bearer {}", token).parse().unwrap(),
        );
        Ok(Self {
            base_url,
            client: reqwest::Client::builder()
                .default_headers(headers)
                .build()?,
        })
    }

    pub async fn get_user(&self, id: usize) -> Result<User, SafeGoldError> {
        let url: Url = format!("{}v1/users/{}", self.base_url, id).parse()?;
        let r = self.client.get(url).send().await?;
        match r.status().as_u16() {
            200 => Ok(r.json::<User>().await?),
            400 => Err(Self::handle_bad_request_error(
                r.json::<SafeGoldClientError>().await?,
            )),
            404 => Err(SafeGoldError::UserDoesNotExist(id.to_string())),
            _ => Err(SafeGoldError::ServiceUnavailable),
        }
    }

    pub async fn get_buy_price(&self) -> Result<BuyPrice, SafeGoldError> {
        let url: Url = format!("{}v1/buy-price", self.base_url).parse().unwrap();
        let r = self.client.get(url).send().await?;
        match r.status().as_u16() {
            200 => Ok(r.json::<BuyPrice>().await?),
            400 => Err(Self::handle_bad_request_error(
                r.json::<SafeGoldClientError>().await?,
            )),
            _ => Err(SafeGoldError::ServiceUnavailable),
        }
    }

    pub async fn buy_verify(
        &self,
        user_id: usize,
        buy_verify: &BuyVerifyRequest,
    ) -> Result<BuyVerify, SafeGoldError> {
        let url: Url = format!("{}v4/users/{}/buy-gold-verify", self.base_url, user_id).parse()?;
        let r = self.client.post(url).json(buy_verify).send().await?;
        match r.status().as_u16() {
            200 => Ok(r.json::<BuyVerify>().await?),
            400 => Err(Self::handle_bad_request_error(
                r.json::<SafeGoldClientError>().await?,
            )),
            _ => Err(SafeGoldError::ServiceUnavailable),
        }
    }

    pub async fn buy_confirm(
        &self,
        user_id: usize,
        buy_confirm: &BuyConfirmRequest,
    ) -> Result<BuyConfirm, SafeGoldError> {
        let url: Url = format!("{}v1/users/{}/buy-gold-confirm", self.base_url, user_id).parse()?;
        let r = self.client.post(url).json(buy_confirm).send().await?;
        match r.status().as_u16() {
            200 => Ok(r.json::<BuyConfirm>().await?),
            400 => Err(Self::handle_bad_request_error(
                r.json::<SafeGoldClientError>().await?,
            )),
            _ => Err(SafeGoldError::ServiceUnavailable),
        }
    }

    pub async fn buy_status(&self, tx_id: usize) -> Result<BuyStatus, SafeGoldError> {
        let url: Url = format!("{}v1/buy-gold/{}/order-status", self.base_url, tx_id).parse()?;
        let r = self.client.get(url).send().await?;
        match r.status().as_u16() {
            200 => Ok(r.json::<BuyStatus>().await?),
            400 => Err(Self::handle_bad_request_error(
                r.json::<SafeGoldClientError>().await?,
            )),
            404 => Err(SafeGoldError::TransactionNotFound(tx_id)),
            _ => Err(SafeGoldError::ServiceUnavailable),
        }
    }

    pub async fn get_user_transactions(
        &self,
        user_id: usize,
        page: Option<usize>,
    ) -> Result<TransactionList, SafeGoldError> {
        let page = match page {
            Some(x) if x > 0 => x,
            None | Some(0) => 1,
            _ => unreachable!(),
        };
        let url: Url = format!("{}/v1/users/{}/transactions", self.base_url, user_id).parse()?;
        let r = self.client.get(url).query(&[("page", page)]).send().await?;
        match r.status().as_u16() {
            200 => Ok(r.json::<TransactionList>().await?),
            400 => Err(Self::handle_bad_request_error(
                r.json::<SafeGoldClientError>().await?,
            )),
            _ => Err(SafeGoldError::ServiceUnavailable),
        }
    }

    fn handle_bad_request_error(r: SafeGoldClientError) -> SafeGoldError {
        match r.code {
            1 => SafeGoldError::MissingRequiredInformation(r.message),
            2 => SafeGoldError::InvalidTransaction,
            3 => SafeGoldError::VendorUserMismatch,
            4 => SafeGoldError::GoldAmountDoesNotMatch,
            5 => SafeGoldError::UserIdMissingInTransaction,
            8 => SafeGoldError::InvalidRate,
            _ => SafeGoldError::BadRequest(r.message),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{BuyConfirmRequest, BuyVerifyRequest, SafeGold, SafeGoldError};
    use chrono::Utc;
    use lazy_static::lazy_static;
    use rust_decimal::{Decimal, RoundingStrategy};
    use std::ops::Mul;

    const USER_ID: usize = 275567;
    const OLD_TX_ID: usize = 1288969;

    lazy_static! {
        static ref BASE_URL: String = std::env::var("BASE_URL").unwrap();
        static ref TOKEN: String = std::env::var("TOKEN").unwrap();
    }

    #[test]
    fn new_test() {
        let s = SafeGold::new("asdadada", "asdada");
        assert!(s.is_err());
        let s = SafeGold::new("https://valid-url.com", "asdada");
        assert!(s.is_ok());
    }

    #[tokio::test]
    async fn test_get_user() {
        let safegold = SafeGold::new(&BASE_URL, &TOKEN).unwrap();
        let user_response = safegold.get_user(USER_ID).await;
        assert!(user_response.is_ok());

        let user_response = safegold.get_user(275566).await;
        assert!(user_response.is_err());
    }

    #[tokio::test]
    async fn test_get_buy_price() {
        let safegold = SafeGold::new(&BASE_URL, &TOKEN).unwrap();
        let buy_price_response = safegold.get_buy_price().await;
        assert!(buy_price_response.is_ok());

        let bp = buy_price_response.unwrap();
        assert_eq!(bp.applicable_tax.to_string(), "3");
    }

    #[tokio::test]
    async fn test_buy_verify() {
        let safegold = SafeGold::new(&BASE_URL, &TOKEN).unwrap();
        let buy_price_response = safegold.get_buy_price().await.unwrap();

        let buy_verify_request = BuyVerifyRequest {
            buy_price: buy_price_response
                .current_price
                .mul(Decimal::new(103, 2))
                .round_dp_with_strategy(2, RoundingStrategy::RoundUp),
            gold_amount: Decimal::new(1, 0).round_dp_with_strategy(4, RoundingStrategy::RoundDown),
            rate_id: buy_price_response.rate_id,
        };
        let buy_verify = safegold.buy_verify(USER_ID, &buy_verify_request).await;
        assert!(buy_verify.is_ok());

        let buy_verify_request = BuyVerifyRequest {
            buy_price: buy_price_response
                .current_price
                .mul(Decimal::new(103, 2))
                .round_dp_with_strategy(2, RoundingStrategy::RoundUp),
            gold_amount: Decimal::new(1, 1).round_dp_with_strategy(4, RoundingStrategy::RoundDown),
            rate_id: buy_price_response.rate_id,
        };
        let buy_verify = safegold.buy_verify(USER_ID, &buy_verify_request).await;
        assert!(buy_verify.is_err());
        assert!(matches!(
            buy_verify.err().unwrap(),
            SafeGoldError::GoldAmountDoesNotMatch
        ));

        let buy_verify_request = BuyVerifyRequest {
            buy_price: buy_price_response
                .current_price
                .mul(Decimal::new(103, 2))
                .round_dp_with_strategy(2, RoundingStrategy::RoundUp),
            gold_amount: Decimal::new(1, 0).round_dp_with_strategy(4, RoundingStrategy::RoundDown),
            rate_id: buy_price_response.rate_id - 100,
        };
        let buy_verify = safegold.buy_verify(USER_ID, &buy_verify_request).await;
        assert!(buy_verify.is_err());
        assert!(matches!(
            buy_verify.err().unwrap(),
            SafeGoldError::InvalidRate
        ));
    }

    #[tokio::test]
    async fn test_buy_confirm() {
        let safegold = SafeGold::new(&BASE_URL, &TOKEN).unwrap();
        let buy_price_response = safegold.get_buy_price().await.unwrap();
        let buy_verify = safegold
            .buy_verify(
                USER_ID,
                &BuyVerifyRequest {
                    buy_price: buy_price_response
                        .current_price
                        .mul(Decimal::new(103, 2))
                        .round_dp_with_strategy(2, RoundingStrategy::RoundUp),
                    gold_amount: Decimal::new(1, 0)
                        .round_dp_with_strategy(4, RoundingStrategy::RoundDown),
                    rate_id: buy_price_response.rate_id,
                },
            )
            .await
            .unwrap();

        let buy_confirm_request = BuyConfirmRequest {
            date: Utc::now().naive_utc().date(),
            tx_id: buy_verify.tx_id,
        };
        let buy_confirm = safegold.buy_confirm(USER_ID, &buy_confirm_request).await;
        assert!(buy_confirm.is_ok());

        let buy_confirm_request = BuyConfirmRequest {
            date: Utc::now().naive_utc().date(),
            tx_id: 11111111111,
        };
        let buy_confirm = safegold.buy_confirm(USER_ID, &buy_confirm_request).await;
        assert!(buy_confirm.is_err());
        assert!(matches!(
            buy_confirm.unwrap_err(),
            SafeGoldError::InvalidTransaction
        ));

        let buy_confirm_request = BuyConfirmRequest {
            date: Utc::now().naive_utc().date(),
            tx_id: buy_verify.tx_id,
        };
        let buy_confirm = safegold.buy_confirm(12345, &buy_confirm_request).await;
        assert!(buy_confirm.is_err());
        assert!(matches!(
            buy_confirm.unwrap_err(),
            SafeGoldError::VendorUserMismatch
        ));

        // this user doesn't exist
        let buy_verify = safegold
            .buy_verify(
                275566,
                &BuyVerifyRequest {
                    buy_price: buy_price_response
                        .current_price
                        .mul(Decimal::new(103, 2))
                        .round_dp_with_strategy(2, RoundingStrategy::RoundUp),
                    gold_amount: Decimal::new(1, 0)
                        .round_dp_with_strategy(4, RoundingStrategy::RoundDown),
                    rate_id: buy_price_response.rate_id,
                },
            )
            .await
            .unwrap();
        let buy_confirm_request = BuyConfirmRequest {
            date: Utc::now().naive_utc().date(),
            tx_id: buy_verify.tx_id,
        };
        let buy_confirm = safegold.buy_confirm(275566, &buy_confirm_request).await;
        assert!(buy_confirm.is_err());
        assert!(matches!(
            buy_confirm.unwrap_err(),
            SafeGoldError::UserIdMissingInTransaction
        ));
    }

    #[tokio::test]
    async fn test_buy_status() {
        let safegold = SafeGold::new(&BASE_URL, &TOKEN).unwrap();
        let buy_price_response = safegold.get_buy_price().await.unwrap();
        let buy_verify = safegold
            .buy_verify(
                USER_ID,
                &BuyVerifyRequest {
                    buy_price: buy_price_response
                        .current_price
                        .mul(Decimal::new(103, 2))
                        .round_dp_with_strategy(2, RoundingStrategy::RoundUp),
                    gold_amount: Decimal::new(1, 0)
                        .round_dp_with_strategy(4, RoundingStrategy::RoundDown),
                    rate_id: buy_price_response.rate_id,
                },
            )
            .await
            .unwrap();

        let buy_status_response = safegold.buy_status(buy_verify.tx_id).await;
        assert!(buy_status_response.is_ok());
        assert_eq!(buy_status_response.unwrap().status, 0);

        let _buy_confirm = safegold
            .buy_confirm(
                USER_ID,
                &BuyConfirmRequest {
                    tx_id: buy_verify.tx_id,
                    date: Utc::now().naive_utc().date(),
                },
            )
            .await
            .unwrap();

        let buy_status_response = safegold.buy_status(buy_verify.tx_id).await;
        assert!(buy_status_response.is_ok());
        assert_eq!(buy_status_response.unwrap().status, 1);

        let buy_confirm = safegold
            .buy_confirm(
                USER_ID,
                &BuyConfirmRequest {
                    tx_id: OLD_TX_ID,
                    date: Utc::now().naive_utc().date(),
                },
            )
            .await;
        assert!(buy_confirm.is_err());
        let buy_status_response = safegold.buy_status(OLD_TX_ID).await;
        assert!(buy_status_response.is_ok());
        assert_eq!(buy_status_response.unwrap().status, 2);

        let buy_status_response = safegold.buy_status(11111111).await;
        assert!(buy_status_response.is_err());
        assert!(matches!(
            buy_status_response.err().unwrap(),
            SafeGoldError::TransactionNotFound(11111111)
        ));
    }

    #[tokio::test]
    async fn test_get_user_transactions() {
        let safegold = SafeGold::new(&BASE_URL, &TOKEN).unwrap();
        let user_transactions_response_page_none =
            safegold.get_user_transactions(USER_ID, None).await;

        assert!(user_transactions_response_page_none.is_ok());
        let user_transactions = user_transactions_response_page_none.unwrap();
        assert!(!user_transactions.transactions.is_empty());
        assert!(user_transactions.meta.previous.is_none());
        assert!(user_transactions.meta.next.is_some());

        let user_transactions_response_page_0 =
            safegold.get_user_transactions(USER_ID, Some(0)).await;
        assert!(user_transactions_response_page_0.is_ok());
        let user_transactions = user_transactions_response_page_0.unwrap();
        assert!(!user_transactions.transactions.is_empty());
        assert!(user_transactions.meta.previous.is_none());
        assert!(user_transactions.meta.next.is_some());

        let user_transactions_response_page_1 =
            safegold.get_user_transactions(USER_ID, Some(1)).await;
        assert!(user_transactions_response_page_1.is_ok());
        let user_transactions = user_transactions_response_page_1.unwrap();
        assert!(!user_transactions.transactions.is_empty());
        assert!(user_transactions.meta.previous.is_none());
        assert!(user_transactions.meta.next.is_some());

        let user_transactions_response_page_2 =
            safegold.get_user_transactions(USER_ID, Some(2)).await;
        assert!(user_transactions_response_page_2.is_ok());
        let user_transactions = user_transactions_response_page_2.unwrap();
        assert!(user_transactions.meta.previous.is_some());
        assert!(user_transactions.meta.next.is_some());
    }
}
