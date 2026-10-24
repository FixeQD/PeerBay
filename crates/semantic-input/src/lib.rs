//! Semantic pointer, keyboard, touch, and gesture types.

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Point {
    pub x: f64,
    pub y: f64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ButtonState {
    Down,
    Up,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PointerButton {
    Primary,
    Secondary,
    Middle,
    Back,
    Forward,
    Other(u16),
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PointerMove {
    pub position: Point,
    pub relative: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PointerButtonEvent {
    pub button: PointerButton,
    pub state: ButtonState,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WheelPhase {
    Started,
    Changed,
    Ended,
    None,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Wheel {
    pub delta_x: f64,
    pub delta_y: f64,
    pub phase: WheelPhase,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Modifiers(u8);

impl Modifiers {
    pub const NONE: Self = Self(0);
    pub const SHIFT: Self = Self(1 << 0);
    pub const CONTROL: Self = Self(1 << 1);
    pub const ALT: Self = Self(1 << 2);
    pub const META: Self = Self(1 << 3);

    pub const fn empty() -> Self {
        Self::NONE
    }

    pub const fn with(self, modifier: Self) -> Self {
        Self(self.0 | modifier.0)
    }

    pub const fn contains(self, modifier: Self) -> bool {
        self.0 & modifier.0 == modifier.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyState {
    Down,
    Up,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyCode {
    Physical(u32),
    Enter,
    Escape,
    Tab,
    Backspace,
    Space,
    ArrowUp,
    ArrowDown,
    ArrowLeft,
    ArrowRight,
    Function(u8),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyEvent {
    pub code: KeyCode,
    pub state: KeyState,
    pub modifiers: Modifiers,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TouchPhase {
    Started,
    Moved,
    Ended,
    Cancelled,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Touch {
    pub pointer_id: u64,
    pub phase: TouchPhase,
    pub position: Point,
    pub pressure: f32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GestureKind {
    Pinch,
    Rotate,
    Swipe,
    Custom(u16),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GesturePhase {
    Started,
    Changed,
    Ended,
    Cancelled,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Gesture {
    pub kind: GestureKind,
    pub phase: GesturePhase,
    pub value: f32,
}
