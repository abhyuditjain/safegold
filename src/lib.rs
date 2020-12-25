mod utils;

use chrono::{DateTime, NaiveDate, Utc};
use reqwest::header::HeaderMap;
use reqwest::Url;
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use serde_aux::prelude::deserialize_number_from_string;
use thiserror::Error;
use validator::{Validate, ValidationErrors};

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

    #[error("Insufficient Gold balance")]
    InsufficientGoldBalance,

    #[error("Gold balance above KYC Limit")]
    BalanceAboveKYCLimit,

    #[error("Gold balance above PAN Limit")]
    BalanceAbovePANLimit,

    #[error("Invalid Rate")]
    InvalidRate,

    #[error("SafeGold rate does not match current rate")]
    RateMismatch,

    #[error("Invalid product code")]
    InvalidProductCode,

    #[error("Product out of stock")]
    ProductOutOfStock,

    #[error("Invalid URL")]
    InvalidUrl(#[from] url::ParseError),

    #[error(transparent)]
    UndefinedError(#[from] reqwest::Error),

    #[error("validation error: {0}")]
    ValidationError(#[from] ValidationErrors),

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
    pub identity_required: u8,
    pub pan_required: u8,
}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct User {
    id: usize,
    name: String,
    mobile_no: String,
    #[serde(deserialize_with = "deserialize_number_from_string")]
    pincode: usize,
    email: Option<String>,
    gold_balance: Decimal,
    gstin: Option<String>,
    kyc_requirement: KycRequirement,
}

#[derive(Serialize, Deserialize, Validate, Debug, Eq, PartialEq)]
pub struct RegisterUser {
    name: String,
    mobile_no: String,
    pin_code: usize,
    #[validate(email)]
    email: Option<String>,
    gstin: Option<String>,
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
pub struct SellPrice {
    current_price: Decimal,
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
pub struct SellVerifyRequest {
    sell_price: Decimal,
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
    user_id: usize,
}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct SellVerify {
    tx_id: usize,
    #[serde(deserialize_with = "deserialize_number_from_string")]
    rate_id: usize,
    rate: Decimal,
    gold_amount: Decimal,
    sell_price: Decimal,
}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct BuyConfirmRequest {
    tx_id: usize,
    date: NaiveDate,
}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct SellConfirmRequest {
    tx_id: usize,
    date: NaiveDate,
}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct BuyConfirm {
    invoice_id: String,
}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct SellConfirm {
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
pub struct SellStatus {
    status: usize,
    settled_status: usize,
    invoice_id: Option<String>,
    bank_reference_number: String,
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

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct Invoice {
    link: String,
}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct ValidatePincodeRequest {
    pin_code: usize,
}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct PincodeStatus {
    status: usize,
    pin_code: Option<usize>,
    city: Option<String>,
    state: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct ProductMedia {
    images: Vec<String>,
    videos: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct GoldProduct {
    id: usize,
    in_stock: char,
    sku_number: Option<String>,
    media: Option<ProductMedia>,
    description: Option<String>,
    metal_weight: usize,
    metal_stamp: Option<String>,
    brand: Option<String>,
    delivery_minting_cost: usize,
    estimated_days_for_dispatch: usize,
    product_dimensions: Option<String>,
    product_thickness: Option<String>,
    certification: Option<String>,
    packaging: Option<String>,
    metal: Option<String>,
    refund_policy: Option<String>,
    product_highlights: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct Address {
    state: String,
    city: String,
    address: String,
    pincode: usize,
    landmark: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct RedeemVerifyRequest {
    product_code: usize,
    name: Option<String>,
    phone_no: Option<usize>,
    address: Address,
}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct RedeemVerify {
    tx_id: usize,
    estimated_dispatch: usize,
    price: usize,
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

    pub async fn register_user(&self, user: &RegisterUser) -> Result<User, SafeGoldError> {
        user.validate()?;
        let url: Url = format!("{}v1/users", self.base_url).parse()?;
        let r = self.client.post(url).json(user).send().await?;
        match r.status().as_u16() {
            200 => Ok(r.json::<User>().await?),
            400 => Err(Self::handle_register_user_bad_request(
                r.json::<SafeGoldClientError>().await?,
            )),
            _ => Err(SafeGoldError::ServiceUnavailable),
        }
    }

    pub async fn get_user(&self, id: usize) -> Result<User, SafeGoldError> {
        let url: Url = format!("{}v1/users/{}", self.base_url, id).parse()?;
        let r = self.client.get(url).send().await?;
        match r.status().as_u16() {
            200 => Ok(r.json::<User>().await?),
            400 => Err(Self::handle_get_user_bad_request(
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

    pub async fn get_sell_price(&self) -> Result<SellPrice, SafeGoldError> {
        let url: Url = format!("{}v1/sell-price", self.base_url).parse().unwrap();
        let r = self.client.get(url).send().await?;
        match r.status().as_u16() {
            200 => Ok(r.json::<SellPrice>().await?),
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
            400 => Err(Self::handle_buy_verify_bad_request(
                r.json::<SafeGoldClientError>().await?,
            )),
            _ => Err(SafeGoldError::ServiceUnavailable),
        }
    }

    pub async fn sell_verify(
        &self,
        user_id: usize,
        sell_verify: &SellVerifyRequest,
    ) -> Result<SellVerify, SafeGoldError> {
        let url: Url = format!("{}v4/users/{}/sell-gold-verify", self.base_url, user_id).parse()?;
        let r = self.client.post(url).json(sell_verify).send().await?;
        match r.status().as_u16() {
            200 => Ok(r.json::<SellVerify>().await?),
            400 => Err(Self::handle_sell_verify_bad_request(
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
            400 => Err(Self::handle_buy_confirm_bad_request(
                r.json::<SafeGoldClientError>().await?,
            )),
            _ => Err(SafeGoldError::ServiceUnavailable),
        }
    }

    pub async fn sell_confirm(
        &self,
        user_id: usize,
        sell_confirm: &SellConfirmRequest,
    ) -> Result<SellConfirm, SafeGoldError> {
        let url: Url =
            format!("{}v1/users/{}/sell-gold-confirm", self.base_url, user_id).parse()?;
        let r = self.client.post(url).json(sell_confirm).send().await?;
        match r.status().as_u16() {
            200 => Ok(r.json::<SellConfirm>().await?),
            400 => Err(Self::handle_sell_confirm_bad_request(
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
            400 => Err(Self::handle_buy_status_bad_request(
                r.json::<SafeGoldClientError>().await?,
            )),
            404 => Err(SafeGoldError::TransactionNotFound(tx_id)),
            _ => Err(SafeGoldError::ServiceUnavailable),
        }
    }

    pub async fn sell_status(&self, tx_id: usize) -> Result<SellStatus, SafeGoldError> {
        let url: Url = format!("{}v1/sell-gold/{}/order-status", self.base_url, tx_id).parse()?;
        let r = self.client.get(url).send().await?;
        match r.status().as_u16() {
            200 => Ok(r.json::<SellStatus>().await?),
            400 => Err(Self::handle_sell_status_bad_request(
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
        let page = page.unwrap_or(1).max(1);
        let url: Url = format!("{}/v1/users/{}/transactions", self.base_url, user_id).parse()?;
        let r = self.client.get(url).query(&[("page", page)]).send().await?;
        match r.status().as_u16() {
            200 => Ok(r.json::<TransactionList>().await?),
            400 => Err(Self::handle_get_user_transactions_bad_request(
                r.json::<SafeGoldClientError>().await?,
            )),
            _ => Err(SafeGoldError::ServiceUnavailable),
        }
    }

    pub async fn get_invoice(&self, tx_id: usize) -> Result<Invoice, SafeGoldError> {
        let url: Url =
            format!("{}/v1/transactions/{}/fetch-invoice", self.base_url, tx_id).parse()?;
        let r = self.client.get(url).send().await?;
        match r.status().as_u16() {
            200 => Ok(r.json::<Invoice>().await?),
            400 => Err(Self::handle_get_invoice_bad_request(
                r.json::<SafeGoldClientError>().await?,
            )),
            _ => Err(SafeGoldError::ServiceUnavailable),
        }
    }

    pub async fn validate_pincode(
        &self,
        pincode_request: &ValidatePincodeRequest,
    ) -> Result<PincodeStatus, SafeGoldError> {
        let url: Url = format!("{}v1/validate-pincode", self.base_url).parse()?;
        let r = self.client.post(url).json(pincode_request).send().await?;
        match r.status().as_u16() {
            200 => Ok(r.json::<PincodeStatus>().await?),
            400 => Err(Self::handle_validate_pincode_bad_request(
                r.json::<SafeGoldClientError>().await?,
            )),
            _ => Err(SafeGoldError::ServiceUnavailable),
        }
    }

    pub async fn get_gold_products(&self) -> Result<Vec<GoldProduct>, SafeGoldError> {
        let url: Url = format!("{}v1/gold-products", self.base_url).parse()?;
        let r = self.client.get(url).send().await?;
        match r.status().as_u16() {
            200 => Ok(r.json::<Vec<GoldProduct>>().await?),
            400 => Err(Self::handle_bad_request_error(
                r.json::<SafeGoldClientError>().await?,
            )),
            _ => Err(SafeGoldError::ServiceUnavailable),
        }
    }

    pub async fn redeem_verify(
        &self,
        user_id: usize,
        redeem_verify: &RedeemVerifyRequest,
    ) -> Result<RedeemVerify, SafeGoldError> {
        let url: Url =
            format!("{}v1/users/{}/redeem-gold-verify", self.base_url, user_id).parse()?;
        let r = self.client.post(url).json(redeem_verify).send().await?;
        match r.status().as_u16() {
            200 => Ok(r.json::<RedeemVerify>().await?),
            400 => Err(Self::handle_redeem_verify_bad_request(
                r.json::<SafeGoldClientError>().await?,
            )),
            _ => Err(SafeGoldError::ServiceUnavailable),
        }
    }
}

impl SafeGold {
    fn handle_register_user_bad_request(r: SafeGoldClientError) -> SafeGoldError {
        match r.code {
            1 => SafeGoldError::MissingRequiredInformation(r.message),
            _ => SafeGoldError::BadRequest(r.message),
        }
    }
    fn handle_get_user_bad_request(r: SafeGoldClientError) -> SafeGoldError {
        match r.code {
            1 => SafeGoldError::UserDoesNotExist(r.message),
            _ => SafeGoldError::BadRequest(r.message),
        }
    }
    fn handle_buy_verify_bad_request(r: SafeGoldClientError) -> SafeGoldError {
        match r.code {
            1 => SafeGoldError::MissingRequiredInformation(r.message),
            2 => SafeGoldError::RateMismatch,
            4 => SafeGoldError::GoldAmountDoesNotMatch,
            6 => SafeGoldError::BalanceAboveKYCLimit,
            7 => SafeGoldError::BalanceAbovePANLimit,
            8 => SafeGoldError::InvalidRate,
            _ => SafeGoldError::BadRequest(r.message),
        }
    }
    fn handle_sell_verify_bad_request(r: SafeGoldClientError) -> SafeGoldError {
        match r.code {
            1 => SafeGoldError::MissingRequiredInformation(r.message),
            2 => SafeGoldError::RateMismatch,
            3 => SafeGoldError::UserDoesNotExist(r.message),
            4 => SafeGoldError::InsufficientGoldBalance,
            5 => SafeGoldError::GoldAmountDoesNotMatch,
            6 => SafeGoldError::InvalidRate,
            _ => SafeGoldError::BadRequest(r.message),
        }
    }
    fn handle_buy_confirm_bad_request(r: SafeGoldClientError) -> SafeGoldError {
        match r.code {
            1 => SafeGoldError::MissingRequiredInformation(r.message),
            2 => SafeGoldError::InvalidTransaction,
            3 => SafeGoldError::VendorUserMismatch,
            5 => SafeGoldError::UserIdMissingInTransaction,
            _ => SafeGoldError::BadRequest(r.message),
        }
    }
    fn handle_sell_confirm_bad_request(r: SafeGoldClientError) -> SafeGoldError {
        match r.code {
            1 => SafeGoldError::MissingRequiredInformation(r.message),
            2 => SafeGoldError::InvalidTransaction,
            3 => SafeGoldError::UserIdMissingInTransaction,
            7 => SafeGoldError::InsufficientGoldBalance,
            _ => SafeGoldError::BadRequest(r.message),
        }
    }
    fn handle_buy_status_bad_request(r: SafeGoldClientError) -> SafeGoldError {
        match r.code {
            1 => SafeGoldError::MissingRequiredInformation(r.message),
            _ => SafeGoldError::BadRequest(r.message),
        }
    }
    fn handle_sell_status_bad_request(r: SafeGoldClientError) -> SafeGoldError {
        match r.code {
            1 => SafeGoldError::InvalidTransaction,
            _ => SafeGoldError::BadRequest(r.message),
        }
    }
    fn handle_get_user_transactions_bad_request(r: SafeGoldClientError) -> SafeGoldError {
        match r.code {
            1 => SafeGoldError::MissingRequiredInformation(r.message),
            _ => SafeGoldError::BadRequest(r.message),
        }
    }
    fn handle_get_invoice_bad_request(r: SafeGoldClientError) -> SafeGoldError {
        match r.code {
            1 => SafeGoldError::InvalidTransaction,
            2 => SafeGoldError::VendorUserMismatch,
            _ => SafeGoldError::BadRequest(r.message),
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
    fn handle_validate_pincode_bad_request(r: SafeGoldClientError) -> SafeGoldError {
        match r.code {
            1 => SafeGoldError::MissingRequiredInformation(r.message),
            _ => SafeGoldError::BadRequest(r.message),
        }
    }
    fn handle_redeem_verify_bad_request(r: SafeGoldClientError) -> SafeGoldError {
        match r.code {
            1 => SafeGoldError::MissingRequiredInformation(r.message),
            2 => SafeGoldError::InvalidProductCode,
            4 => SafeGoldError::ProductOutOfStock,
            5 => SafeGoldError::UserDoesNotExist(r.message),
            7 => SafeGoldError::InsufficientGoldBalance,
            _ => SafeGoldError::BadRequest(r.message),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        Address, BuyConfirmRequest, BuyVerifyRequest, RedeemVerifyRequest, RegisterUser, SafeGold,
        SafeGoldError, SellConfirmRequest, SellVerifyRequest, ValidatePincodeRequest,
    };
    use chrono::Utc;
    use lazy_static::lazy_static;
    use rust_decimal::{Decimal, RoundingStrategy};
    use std::ops::{Add, Mul};

    const USER_ID: usize = 275567;
    const OLD_BUY_TX_ID: usize = 1288969;
    const OLD_SELL_TX_ID: usize = 1289253;

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
        assert!(matches!(
            user_response.err().unwrap(),
            SafeGoldError::UserDoesNotExist(_)
        ));
    }

    #[tokio::test]
    async fn test_register_user() {
        let safegold = SafeGold::new(&BASE_URL, &TOKEN).unwrap();
        let user_response = safegold
            .register_user(&RegisterUser {
                name: "SafeGold".to_string(),
                mobile_no: "1234567890".to_string(),
                pin_code: 110052,
                email: Some("asdasda".to_string()),
                gstin: None,
            })
            .await;
        assert!(user_response.is_err());
        assert!(matches!(
            user_response.err().unwrap(),
            SafeGoldError::ValidationError(_)
        ));

        // mobile_no is required
        let user_response = safegold
            .register_user(&RegisterUser {
                name: "SafeGold".to_string(),
                mobile_no: "".to_string(),
                pin_code: 110052,
                email: Some("a@a.com".to_string()),
                gstin: None,
            })
            .await;
        assert!(user_response.is_err());
        assert!(matches!(
            user_response.err().unwrap(),
            SafeGoldError::MissingRequiredInformation(_)
        ));

        let user_response = safegold
            .register_user(&RegisterUser {
                name: "SafeGold".to_string(),
                mobile_no: "1234567890".to_string(),
                pin_code: 110052,
                email: Some("a@a.com".to_string()),
                gstin: None,
            })
            .await;
        assert!(user_response.is_ok());
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
            rate_id: buy_price_response.rate_id + 1000,
        };
        let buy_verify = safegold.buy_verify(USER_ID, &buy_verify_request).await;
        assert!(buy_verify.is_err());
        assert!(matches!(
            buy_verify.err().unwrap(),
            SafeGoldError::InvalidRate
        ));
    }

    #[tokio::test]
    async fn test_sell_verify() {
        let safegold = SafeGold::new(&BASE_URL, &TOKEN).unwrap();
        let user = safegold.get_user(USER_ID).await.unwrap();
        let sell_price_response = safegold.get_sell_price().await.unwrap();

        let sell_verify_request = SellVerifyRequest {
            sell_price: sell_price_response.current_price.mul(user.gold_balance),
            gold_amount: user.gold_balance,
            rate_id: sell_price_response.rate_id,
        };
        let sell_verify = safegold.sell_verify(USER_ID, &sell_verify_request).await;
        assert!(sell_verify.is_ok());

        // Rate invalid
        let sell_verify_request = SellVerifyRequest {
            sell_price: sell_price_response
                .current_price
                .round_dp_with_strategy(2, RoundingStrategy::RoundUp),
            gold_amount: Decimal::new(1, 0).round_dp_with_strategy(4, RoundingStrategy::RoundDown),
            rate_id: sell_price_response.rate_id - 100,
        };
        let sell_verify = safegold.sell_verify(USER_ID, &sell_verify_request).await;
        assert!(sell_verify.is_err());
        assert!(matches!(
            sell_verify.err().unwrap(),
            SafeGoldError::InvalidRate
        ));

        // Gold Mismatch
        let sell_verify_request = SellVerifyRequest {
            sell_price: sell_price_response
                .current_price
                .round_dp_with_strategy(2, RoundingStrategy::RoundUp),
            gold_amount: Decimal::new(1, 0)
                .add(Decimal::new(1, 2))
                .round_dp_with_strategy(4, RoundingStrategy::RoundDown),
            rate_id: sell_price_response.rate_id,
        };
        let sell_verify = safegold.sell_verify(USER_ID, &sell_verify_request).await;
        assert!(sell_verify.is_err());
        assert!(matches!(
            sell_verify.err().unwrap(),
            SafeGoldError::GoldAmountDoesNotMatch
        ));

        // Try to sell more gold than in balance
        let sell_verify_request = SellVerifyRequest {
            sell_price: user
                .gold_balance
                .add(Decimal::new(100, 0))
                .round_dp_with_strategy(0, RoundingStrategy::RoundUp)
                .mul(sell_price_response.current_price),
            gold_amount: user
                .gold_balance
                .round_dp_with_strategy(0, RoundingStrategy::RoundUp)
                .add(Decimal::new(100, 0)),
            rate_id: sell_price_response.rate_id,
        };
        let sell_verify = safegold.sell_verify(USER_ID, &sell_verify_request).await;
        assert!(sell_verify.is_err());
        assert!(matches!(
            sell_verify.err().unwrap(),
            SafeGoldError::InsufficientGoldBalance
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
    async fn test_sell_confirm() {
        let safegold = SafeGold::new(&BASE_URL, &TOKEN).unwrap();
        let sell_price_response = safegold.get_sell_price().await.unwrap();
        let sell_verify = safegold
            .sell_verify(
                USER_ID,
                &SellVerifyRequest {
                    sell_price: sell_price_response.current_price,
                    gold_amount: Decimal::new(1, 0),
                    rate_id: sell_price_response.rate_id,
                },
            )
            .await
            .unwrap();

        let sell_confirm_request = SellConfirmRequest {
            date: Utc::now().naive_utc().date(),
            tx_id: sell_verify.tx_id,
        };
        let sell_confirm = safegold.sell_confirm(USER_ID, &sell_confirm_request).await;
        assert!(sell_confirm.is_ok());

        let sell_confirm_request = SellConfirmRequest {
            date: Utc::now().naive_utc().date(),
            tx_id: 11111111111,
        };
        let sell_confirm = safegold.sell_confirm(USER_ID, &sell_confirm_request).await;
        assert!(sell_confirm.is_err());
        assert!(matches!(
            sell_confirm.unwrap_err(),
            SafeGoldError::InvalidTransaction
        ));

        let sell_confirm_request = SellConfirmRequest {
            date: Utc::now().naive_utc().date(),
            tx_id: sell_verify.tx_id,
        };
        let sell_confirm = safegold.sell_confirm(12345, &sell_confirm_request).await;
        assert!(sell_confirm.is_err());
        assert!(matches!(
            sell_confirm.unwrap_err(),
            SafeGoldError::UserIdMissingInTransaction
        ));

        // Gold balance lower than sell amount
        // To test this, we must create two requests
        // If we only create one request with gold amount higher than the balance,
        // the request will fail in SellVerify call
        let user = safegold.get_user(USER_ID).await.unwrap();
        let sell_verify_1 = safegold
            .sell_verify(
                USER_ID,
                &SellVerifyRequest {
                    sell_price: sell_price_response.current_price,
                    gold_amount: Decimal::new(1, 0),
                    rate_id: sell_price_response.rate_id,
                },
            )
            .await
            .unwrap();
        let sell_verify_2 = safegold
            .sell_verify(
                USER_ID,
                &SellVerifyRequest {
                    sell_price: sell_price_response.current_price.mul(user.gold_balance),
                    gold_amount: user.gold_balance,
                    rate_id: sell_price_response.rate_id,
                },
            )
            .await
            .unwrap();
        // 1st should pass
        let sell_confirm_request_1 = SellConfirmRequest {
            date: Utc::now().naive_utc().date(),
            tx_id: sell_verify_1.tx_id,
        };
        let sell_confirm_1 = safegold
            .sell_confirm(USER_ID, &sell_confirm_request_1)
            .await;
        assert!(sell_confirm_1.is_ok());
        // 2nd should fail
        let sell_confirm_request_2 = SellConfirmRequest {
            date: Utc::now().naive_utc().date(),
            tx_id: sell_verify_2.tx_id,
        };
        let sell_confirm_2 = safegold
            .sell_confirm(USER_ID, &sell_confirm_request_2)
            .await;
        assert!(sell_confirm_2.is_err());
        assert!(matches!(
            sell_confirm_2.unwrap_err(),
            SafeGoldError::InsufficientGoldBalance
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
                    tx_id: OLD_BUY_TX_ID,
                    date: Utc::now().naive_utc().date(),
                },
            )
            .await;
        assert!(buy_confirm.is_err());
        let buy_status_response = safegold.buy_status(OLD_BUY_TX_ID).await;
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
    async fn test_sell_status() {
        let safegold = SafeGold::new(&BASE_URL, &TOKEN).unwrap();
        let sell_price_response = safegold.get_sell_price().await.unwrap();
        let sell_verify = safegold
            .sell_verify(
                USER_ID,
                &SellVerifyRequest {
                    sell_price: sell_price_response.current_price,
                    gold_amount: Decimal::new(1, 0),
                    rate_id: sell_price_response.rate_id,
                },
            )
            .await
            .unwrap();

        let sell_status_response = safegold.sell_status(sell_verify.tx_id).await;
        assert!(sell_status_response.is_ok());
        assert_eq!(sell_status_response.unwrap().status, 0);

        let _sell_confirm = safegold
            .sell_confirm(
                USER_ID,
                &SellConfirmRequest {
                    tx_id: sell_verify.tx_id,
                    date: Utc::now().naive_utc().date(),
                },
            )
            .await
            .unwrap();

        let sell_status_response = safegold.sell_status(sell_verify.tx_id).await;
        assert!(sell_status_response.is_ok());
        assert_eq!(sell_status_response.unwrap().status, 1);

        let sell_confirm = safegold
            .sell_confirm(
                USER_ID,
                &SellConfirmRequest {
                    tx_id: OLD_SELL_TX_ID,
                    date: Utc::now().naive_utc().date(),
                },
            )
            .await;
        assert!(sell_confirm.is_err());
        let sell_status_response = safegold.sell_status(OLD_SELL_TX_ID).await;
        assert!(sell_status_response.is_ok());
        assert_eq!(sell_status_response.unwrap().status, 2);

        let sell_status_response = safegold.buy_status(11111111).await;
        assert!(sell_status_response.is_err());
        assert!(matches!(
            sell_status_response.err().unwrap(),
            SafeGoldError::TransactionNotFound(11111111)
        ));
    }

    #[tokio::test]
    async fn test_get_user_transactions() {
        let safegold = SafeGold::new(&BASE_URL, &TOKEN).unwrap();

        // Page None should get page 1
        let user_transactions_response_page_none =
            safegold.get_user_transactions(USER_ID, None).await;
        assert!(user_transactions_response_page_none.is_ok());
        let user_transactions = user_transactions_response_page_none.unwrap();
        assert!(!user_transactions.transactions.is_empty());
        assert!(user_transactions.meta.previous.is_none());
        assert!(user_transactions.meta.next.is_some());

        // Page 0 should get page 1
        let user_transactions_response_page_0 =
            safegold.get_user_transactions(USER_ID, Some(0)).await;
        assert!(user_transactions_response_page_0.is_ok());
        let user_transactions = user_transactions_response_page_0.unwrap();
        assert!(!user_transactions.transactions.is_empty());
        assert!(user_transactions.meta.previous.is_none());
        assert!(user_transactions.meta.next.is_some());

        // Page 1 should get page 1
        let user_transactions_response_page_1 =
            safegold.get_user_transactions(USER_ID, Some(1)).await;
        assert!(user_transactions_response_page_1.is_ok());
        let user_transactions = user_transactions_response_page_1.unwrap();
        assert!(!user_transactions.transactions.is_empty());
        assert!(user_transactions.meta.previous.is_none());
        assert!(user_transactions.meta.next.is_some());

        assert_eq!(
            user_transactions
                .transactions
                .iter()
                .filter(|x| x.r#type == "buy")
                .count(),
            33
        );
        assert_eq!(
            user_transactions
                .transactions
                .iter()
                .filter(|x| x.r#type == "sell")
                .count(),
            5
        );

        // Page 2 should get page 2
        let user_transactions_response_page_2 =
            safegold.get_user_transactions(USER_ID, Some(2)).await;
        assert!(user_transactions_response_page_2.is_ok());
        let user_transactions = user_transactions_response_page_2.unwrap();
        assert!(user_transactions.meta.previous.is_some());
        assert!(user_transactions.meta.next.is_some());
    }

    #[tokio::test]
    async fn test_get_invoice() {
        let safegold = SafeGold::new(&BASE_URL, &TOKEN).unwrap();
        let invoice_repsonse = safegold.get_invoice(1289107).await;
        assert!(invoice_repsonse.is_ok());

        let invoice_repsonse = safegold.get_invoice(12345).await;
        assert!(invoice_repsonse.is_err());
        assert!(matches!(
            invoice_repsonse.err().unwrap(),
            SafeGoldError::InvalidTransaction
        ));
    }

    #[tokio::test]
    async fn test_get_sell_price() {
        let safegold = SafeGold::new(&BASE_URL, &TOKEN).unwrap();
        let sell_price_response = safegold.get_sell_price().await;
        assert!(sell_price_response.is_ok());
    }

    #[tokio::test]
    async fn test_validate_pincode() {
        let safegold = SafeGold::new(&BASE_URL, &TOKEN).unwrap();
        let pincode_status = safegold
            .validate_pincode(&ValidatePincodeRequest { pin_code: 110052 })
            .await;
        assert!(pincode_status.is_ok());
        let pincode_status = pincode_status.unwrap();
        assert_eq!(pincode_status.status, 1);
        assert_eq!(pincode_status.city, Some("Ashok vihar".to_string()));
        assert_eq!(pincode_status.state, Some("Delhi".to_string()));
        assert_eq!(pincode_status.pin_code, Some(110052));

        let pincode_status = safegold
            .validate_pincode(&ValidatePincodeRequest { pin_code: 0 })
            .await;
        assert!(pincode_status.is_ok());
        let pincode_status = pincode_status.unwrap();
        assert_eq!(pincode_status.status, 0);
        assert_eq!(pincode_status.city, None);
        assert_eq!(pincode_status.state, None);
        assert_eq!(pincode_status.pin_code, None);
    }

    #[tokio::test]
    async fn test_get_gold_products() {
        let safegold = SafeGold::new(&BASE_URL, &TOKEN).unwrap();
        let gold_products_response = safegold.get_gold_products().await;
        assert!(gold_products_response.is_ok());
    }

    #[tokio::test]
    async fn test_redeem_verify() {
        let safegold = SafeGold::new(&BASE_URL, &TOKEN).unwrap();
        let redeem_verify_request = RedeemVerifyRequest {
            product_code: 1,
            name: None,
            phone_no: None,
            address: Address {
                state: "".to_string(),
                city: "".to_string(),
                address: "".to_string(),
                pincode: 0,
                landmark: None,
            },
        };
        let redeem_verify_response = safegold
            .redeem_verify(USER_ID, &redeem_verify_request)
            .await;
        assert!(redeem_verify_response.is_err());
        assert!(matches!(
            redeem_verify_response.err().unwrap(),
            SafeGoldError::MissingRequiredInformation(_)
        ));

        let redeem_verify_request = RedeemVerifyRequest {
            product_code: 1,
            name: None,
            phone_no: None,
            address: Address {
                state: "Delhi".to_string(),
                city: "Ashok Vihar".to_string(),
                address: "asdadada".to_string(),
                pincode: 110052,
                landmark: None,
            },
        };
        let redeem_verify_response = safegold
            .redeem_verify(USER_ID, &redeem_verify_request)
            .await;
        assert!(redeem_verify_response.is_err());
        assert!(matches!(
            redeem_verify_response.err().unwrap(),
            SafeGoldError::InvalidProductCode,
        ));
    }
}
