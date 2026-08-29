mod assurance;
mod capability;
mod contract;
mod economics;
mod id;
mod output_validation;
mod policy;
mod request;
mod reuse;
mod validation;

pub use assurance::*;
pub use capability::*;
pub use contract::*;
pub use economics::*;
pub use id::*;
pub use output_validation::*;
pub use policy::*;
pub use request::*;
pub use reuse::*;
pub use validation::*;

pub const ACTION_FORMAT_REVISION: u16 = 1;
pub const ACTION_REQUEST_FORMAT_REVISION: u16 = 2;
pub const ACTION_REQUEST_PARAMETERIZED_FORMAT_REVISION: u16 = 3;

#[cfg(test)]
mod tests;
