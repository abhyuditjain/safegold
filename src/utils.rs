pub mod custom_date_time_format {
    use chrono::{DateTime, Utc, TimeZone, FixedOffset};
    use serde::{self, Deserialize, Serializer, Deserializer};

    const FORMAT: &str = "%Y-%m-%d %H:%M:%S";

    pub fn serialize<S>(
        date: &DateTime<Utc>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
    {
        let s = format!("{}", date.format(FORMAT));
        serializer.serialize_str(&s)
    }

    pub fn deserialize<'de, D>(
        deserializer: D,
    ) -> Result<DateTime<Utc>, D::Error>
        where
            D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let offset = FixedOffset::east(19800);
        let date_time_local = offset.datetime_from_str(&s, FORMAT).map_err(serde::de::Error::custom)?;

        Ok(Utc.from_utc_datetime(&date_time_local.naive_utc()))
    }
}