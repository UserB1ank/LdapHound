//! Shared button styles.
//!
//! iced 0.14 has no `theme::Button::Primary` enum (it moved to a StyleSheet
//! trait). We hand-roll two style functions: plain (default text button)
//! and selected (highlighted background for the currently selected row).

use iced::widget::button::{Status, Style};
use iced::{Background, Border, Color, Theme};

/// Default text-button look: transparent background, no border.
pub fn plain(_theme: &Theme, _status: Status) -> Style {
    Style {
        background: Some(Background::Color(Color::TRANSPARENT)),
        text_color: Color::WHITE,
        border: Border::default(),
        shadow: iced::Shadow::default(),
        snap: false,
    }
}

/// Selected-row look: solid accent background so the highlight is obvious
/// without needing a glyph prefix.
pub fn selected(_theme: &Theme, _status: Status) -> Style {
    Style {
        background: Some(Background::Color(Color::from_rgb(
            0x1F as f32 / 255.0,
            0x6F as f32 / 255.0,
            0xB5 as f32 / 255.0,
        ))),
        text_color: Color::WHITE,
        border: Border::default(),
        shadow: iced::Shadow::default(),
        snap: false,
    }
}
