mod utils;

use reqwest::header::HeaderMap;
use reqwest::Url;
use serde::{Serialize, Deserialize};
use thiserror::Error;
use rust_decimal::Decimal;
use chrono::{DateTime, Utc, NaiveDate};
use serde_aux::prelude::deserialize_number_from_string;

#[derive(Error, Debug)]
pub enum SafeGoldError {
    #[error("User with ID: {0} does not exist")]
    UserDoesNotExist(String),

    #[error("Bad Request error with message: {0}")]
    BadRequest(String),

    #[error("Vendor ID and User ID mismatch")]
    VendorUserMismatch,

    #[error("Invalid transaction ID")]
    InvalidTransaction,

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

pub struct SafeGold {
    base_url: reqwest::Url,
    client: reqwest::Client,
}

impl SafeGold {
    pub fn new(base_url: &str, token: &str) -> Result<Self, SafeGoldError> {
        let base_url = Url::parse(base_url)?;
        let mut headers = HeaderMap::new();
        headers.insert("Authorization", format!("Bearer {}", token).parse().unwrap());
        Ok(Self { base_url, client: reqwest::Client::builder().default_headers(headers).build()? })
    }

    pub async fn get_user(&self, id: &str) -> Result<User, SafeGoldError> {
        let url: Url = format!("{}v1/users/{}", self.base_url, id).parse()?;
        let r = self.client.get(url).send().await?;
        match r.status() {
            x if x == 200 => Ok(r.json::<User>().await?),
            x if x == 404 => Err(SafeGoldError::UserDoesNotExist(id.to_string())),
            // x if x >= 400 && x < 500 => SafeGoldError::UndefinedError(),
            _ => Err(SafeGoldError::ServiceUnavailable),
        }
    }

    pub async fn get_buy_price(&self) -> Result<BuyPrice, SafeGoldError> {
        let url: Url = format!("{}v1/buy-price", self.base_url).parse().unwrap();
        let r = self.client.get(url).send().await?;
        match r.status() {
            x if x == 200 => Ok(r.json::<BuyPrice>().await?),
            _ => Err(SafeGoldError::ServiceUnavailable),
        }
    }

    pub async fn buy_verify(&self, user_id: &str, buy_verify: &BuyVerifyRequest) -> Result<BuyVerify, SafeGoldError> {
        let url: Url = format!("{}v4/users/{}/buy-gold-verify", self.base_url, user_id).parse()?;
        let r = self.client.post(url).json(buy_verify).send().await?;
        match r.status() {
            x if x == 200 => Ok(r.json::<BuyVerify>().await?),
            x if x == 400 => {
                let r = r.json::<SafeGoldClientError>().await?;
                match r.code {
                    x if x == 4 => Err(SafeGoldError::GoldAmountDoesNotMatch),
                    x if x == 8 => Err(SafeGoldError::InvalidRate),
                    _ => Err(SafeGoldError::BadRequest(r.message)),
                }
            }
            _ => Err(SafeGoldError::ServiceUnavailable)
        }
    }

    pub async fn buy_confirm(&self, user_id: &str, buy_confirm: &BuyConfirmRequest) -> Result<BuyConfirm, SafeGoldError> {
        let url: Url = format!("{}v1/users/{}/buy-gold-confirm", self.base_url, user_id).parse()?;
        let r = self.client.post(url).json(buy_confirm).send().await?;
        match r.status() {
            x if x == 200 => Ok(r.json::<BuyConfirm>().await?),
            x if x == 400 => {
                let r = r.json::<SafeGoldClientError>().await?;
                match r.code {
                    x if x == 2 => Err(SafeGoldError::InvalidTransaction),
                    x if x == 3 => Err(SafeGoldError::VendorUserMismatch),
                    x if x == 5 => Err(SafeGoldError::UserIdMissingInTransaction),
                    _ => Err(SafeGoldError::BadRequest(r.message)),
                }
            }
            _ => Err(SafeGoldError::ServiceUnavailable)
        }
    }
}

#[cfg(test)]
mod tests {
    use lazy_static::lazy_static;
    use crate::{SafeGold, BuyVerifyRequest, SafeGoldError, BuyConfirmRequest};
    use rust_decimal::{Decimal, RoundingStrategy};
    use std::ops::Mul;
    use chrono::Utc;

    const USER_ID: &str = "275567";

    lazy_static! {
       static ref BASE_URL: String = std::env::var("BASE_URL").unwrap();
       static ref TOKEN: String = std::env::var("TOKEN").unwrap();
       static ref SAFEGOLD: SafeGold = SafeGold::new(&BASE_URL, &TOKEN).unwrap();
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
        let user_response = SAFEGOLD.get_user(USER_ID).await;
        assert!(user_response.is_ok());

        let user_response = SAFEGOLD.get_user("275566").await;
        assert!(user_response.is_err());
    }

    #[tokio::test]
    async fn test_get_buy_price() {
        let buy_price_response = SAFEGOLD.get_buy_price().await;
        assert!(buy_price_response.is_ok());

        let bp = buy_price_response.unwrap();
        assert_eq!(bp.applicable_tax.to_string(), "3");
    }

    #[tokio::test]
    async fn test_buy_verify() {
        let buy_price_response = SAFEGOLD.get_buy_price().await.unwrap();

        let buy_verify_request = BuyVerifyRequest {
            buy_price: buy_price_response.current_price.mul(Decimal::new(103, 2)).round_dp_with_strategy(2, RoundingStrategy::RoundUp),
            gold_amount: Decimal::new(1, 0).round_dp_with_strategy(4, RoundingStrategy::RoundDown),
            rate_id: buy_price_response.rate_id,
        };
        let buy_verify = SAFEGOLD.buy_verify(USER_ID, &buy_verify_request).await;
        assert!(buy_verify.is_ok());

        let buy_verify_request = BuyVerifyRequest {
            buy_price: buy_price_response.current_price.mul(Decimal::new(103, 2)).round_dp_with_strategy(2, RoundingStrategy::RoundUp),
            gold_amount: Decimal::new(1, 1).round_dp_with_strategy(4, RoundingStrategy::RoundDown),
            rate_id: buy_price_response.rate_id,
        };
        let buy_verify = SAFEGOLD.buy_verify(USER_ID, &buy_verify_request).await;
        assert!(buy_verify.is_err());
        assert!(matches!(buy_verify.err().unwrap(), SafeGoldError::GoldAmountDoesNotMatch));

        let buy_verify_request = BuyVerifyRequest {
            buy_price: buy_price_response.current_price.mul(Decimal::new(103, 2)).round_dp_with_strategy(2, RoundingStrategy::RoundUp),
            gold_amount: Decimal::new(1, 0).round_dp_with_strategy(4, RoundingStrategy::RoundDown),
            rate_id: buy_price_response.rate_id - 100,
        };
        let buy_verify = SAFEGOLD.buy_verify(USER_ID, &buy_verify_request).await;
        assert!(buy_verify.is_err());
        assert!(matches!(buy_verify.err().unwrap(), SafeGoldError::InvalidRate));
    }

    #[tokio::test]
    async fn test_buy_confirm() {
        let buy_price_response = SAFEGOLD.get_buy_price().await.unwrap();
        let buy_verify = SAFEGOLD.buy_verify(USER_ID, &BuyVerifyRequest {
            buy_price: buy_price_response.current_price.mul(Decimal::new(103, 2)).round_dp_with_strategy(2, RoundingStrategy::RoundUp),
            gold_amount: Decimal::new(1, 0).round_dp_with_strategy(4, RoundingStrategy::RoundDown),
            rate_id: buy_price_response.rate_id,
        }).await.unwrap();

        let buy_confirm_request = BuyConfirmRequest {
            date: Utc::now().naive_utc().date(),
            tx_id: buy_verify.tx_id,
        };
        let buy_confirm = SAFEGOLD.buy_confirm(USER_ID, &buy_confirm_request).await;
        assert!(buy_confirm.is_ok());

        let buy_confirm_request = BuyConfirmRequest {
            date: Utc::now().naive_utc().date(),
            tx_id: 11111111111,
        };
        let buy_confirm = SAFEGOLD.buy_confirm(USER_ID, &buy_confirm_request).await;
        assert!(buy_confirm.is_err());
        assert!(matches!(buy_confirm.unwrap_err(), SafeGoldError::InvalidTransaction));

        let buy_confirm_request = BuyConfirmRequest {
            date: Utc::now().naive_utc().date(),
            tx_id: buy_verify.tx_id,
        };
        let buy_confirm = SAFEGOLD.buy_confirm("12345", &buy_confirm_request).await;
        assert!(buy_confirm.is_err());
        assert!(matches!(buy_confirm.unwrap_err(), SafeGoldError::VendorUserMismatch));

        // this user doesn't exist
        let buy_verify = SAFEGOLD.buy_verify("275566", &BuyVerifyRequest {
            buy_price: buy_price_response.current_price.mul(Decimal::new(103, 2)).round_dp_with_strategy(2, RoundingStrategy::RoundUp),
            gold_amount: Decimal::new(1, 0).round_dp_with_strategy(4, RoundingStrategy::RoundDown),
            rate_id: buy_price_response.rate_id,
        }).await.unwrap();
        let buy_confirm_request = BuyConfirmRequest {
            date: Utc::now().naive_utc().date(),
            tx_id: buy_verify.tx_id,
        };
        let buy_confirm = SAFEGOLD.buy_confirm("275566", &buy_confirm_request).await;
        assert!(buy_confirm.is_err());
        assert!(matches!(buy_confirm.unwrap_err(), SafeGoldError::UserIdMissingInTransaction));
    }
}
