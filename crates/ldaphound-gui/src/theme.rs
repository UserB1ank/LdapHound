//! Button and container styles.
//!
//! Mirrors halloy's pattern: style functions (not `theme::Button` enum) that
//! pull colors from a small palette. iced 0.14 stable has no `theme::Base`
//! trait, so we use the default `iced::Theme` and choose colors manually.

use iced::widget::button::{Status, Style};
use iced::{Background, Border, Color, Shadow, Theme};

// --- Palette ---------------------------------------------------------------
// Color::from_rgb8 takes 0-255 u8 and converts internally.

const BG: Color = Color::from_rgb8(0x18, 0x18, 0x1C);
const BG_ELEVATED: Color = Color::from_rgb8(0x22, 0x22, 0x28);
const BG_HOVER: Color = Color::from_rgb8(0x2C, 0x2C, 0x34);
const BG_SELECTED: Color = Color::from_rgb8(0x09, 0x44, 0x6F);
const TEXT: Color = Color::from_rgb8(0xE6, 0xE6, 0xE6);
const TEXT_DIM: Color = Color::from_rgb8(0x99, 0x99, 0x9E);
const ACCENT: Color = Color::from_rgb8(0x35, 0x9B, 0xF3);

// --- Buttons ---------------------------------------------------------------

/// Flat transparent button with a subtle hover. Used for sidebar tree rows
/// that are NOT selected.
pub fn bare(_theme: &Theme, status: Status) -> Style {
    match status {
        Status::Active | Status::Pressed => Style {
            background: Some(Background::Color(Color::TRANSPARENT)),
            text_color: TEXT,
            border: Border::default(),
            shadow: Shadow::default(),
            snap: false,
        },
        Status::Hovered => Style {
            background: Some(Background::Color(BG_HOVER)),
            text_color: TEXT,
            border: Border::default(),
            shadow: Shadow::default(),
            snap: false,
        },
        Status::Disabled => Style {
            background: Some(Background::Color(Color::TRANSPARENT)),
            text_color: TEXT_DIM,
            border: Border::default(),
            shadow: Shadow::default(),
            snap: false,
        },
    }
}

/// Sidebar tree row button. Selected variant paints a solid accent
/// background (no glyph needed).
pub fn sidebar_buffer(_theme: &Theme, status: Status, is_selected: bool) -> Style {
    let background = match (status, is_selected) {
        (_, true) => Background::Color(BG_SELECTED),
        (Status::Hovered, false) => Background::Color(BG_HOVER),
        _ => Background::Color(Color::TRANSPARENT),
    };
    Style {
        background: Some(background),
        text_color: TEXT,
        border: Border {
            radius: 4.0.into(),
            ..Border::default()
        },
        shadow: Shadow::default(),
        snap: false,
    }
}

/// Primary accent button (e.g. "Open .dat").
pub fn primary(_theme: &Theme, status: Status) -> Style {
    // Hover lightens the accent; pressed returns to base.
    let background = match status {
        Status::Pressed => ACCENT,
        Status::Hovered => Color::from_rgb8(0x4F, 0xAE, 0xF5),
        _ => ACCENT,
    };
    Style {
        background: Some(Background::Color(background)),
        text_color: Color::WHITE,
        border: Border {
            radius: 4.0.into(),
            ..Border::default()
        },
        shadow: Shadow::default(),
        snap: false,
    }
}

/// Secondary subtle button (used for inline actions like "Copy").
pub fn secondary(_theme: &Theme, status: Status) -> Style {
    let background = match status {
        Status::Active | Status::Pressed => BG_ELEVATED,
        Status::Hovered => BG_HOVER,
        Status::Disabled => BG,
    };
    Style {
        background: Some(Background::Color(background)),
        text_color: TEXT,
        border: Border {
            radius: 4.0.into(),
            width: 1.0,
            color: TEXT_DIM,
        },
        shadow: Shadow::default(),
        snap: false,
    }
}

// --- Container styles ------------------------------------------------------

pub fn pane_body(_theme: &Theme) -> iced::widget::container::Style {
    iced::widget::container::Style {
        background: Some(Background::Color(BG)),
        text_color: Some(TEXT),
        border: Border {
            radius: 4.0.into(),
            width: 1.0,
            color: BG_ELEVATED,
        },
        ..Default::default()
    }
}

pub fn pane_title_bar(_theme: &Theme) -> iced::widget::container::Style {
    iced::widget::container::Style {
        background: Some(Background::Color(BG_ELEVATED)),
        text_color: Some(TEXT),
        border: Border {
            radius: 4.0.into(),
            width: 0.0,
            color: Color::TRANSPARENT,
        },
        ..Default::default()
    }
}

pub fn sidebar_background(_theme: &Theme) -> iced::widget::container::Style {
    iced::widget::container::Style {
        background: Some(Background::Color(BG_ELEVATED)),
        text_color: Some(TEXT),
        ..Default::default()
    }
}

pub fn dim_text() -> Color {
    TEXT_DIM
}
