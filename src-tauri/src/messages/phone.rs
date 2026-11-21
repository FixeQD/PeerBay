use super::AppMessageType;
use proto::MessageType;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PhoneMessageType {
    PrivilegeState,
    PrivilegeRequest,
    PrivilegeCancel,
    PrivilegeCapabilities,
}

message_type_strings!(PhoneMessageType, {
    PrivilegeState => "phone.privilege.state",
    PrivilegeRequest => "phone.privilege.request",
    PrivilegeCancel => "phone.privilege.cancel",
    PrivilegeCapabilities => "phone.privilege.capabilities",
});

impl From<PhoneMessageType> for MessageType {
    fn from(value: PhoneMessageType) -> Self {
        Self::from(AppMessageType::Phone(value))
    }
}
