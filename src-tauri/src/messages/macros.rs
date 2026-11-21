macro_rules! message_type_strings {
    ($type:ty, { $( $variant:ident => $wire:literal ),+ $(,)? }) => {
        impl $type {
            pub const fn as_str(self) -> &'static str {
                match self {
                    $( Self::$variant => $wire, )+
                }
            }

            pub fn from_wire(value: &str) -> Option<Self> {
                match value {
                    $( $wire => Some(Self::$variant), )+
                    _ => None,
                }
            }
        }
    };
}
