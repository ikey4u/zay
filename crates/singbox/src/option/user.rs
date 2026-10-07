#[derive(Debug, Default, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "full", derive(serde::Serialize, serde::Deserialize))]
pub struct User {
    #[cfg_attr(
        feature = "full",
        serde(default, rename = "username", alias = "Username")
    )]
    pub username: String,
    #[cfg_attr(
        feature = "full",
        serde(default, rename = "password", alias = "Password")
    )]
    pub password: String,
}
