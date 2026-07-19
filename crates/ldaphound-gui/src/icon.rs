//! Bootstrap Icons glyph helpers.
//!
//! The `bootstrap-icons.ttf` (MIT, twbs/icons) is bundled at
//! `assets/bootstrap-icons.ttf` and loaded by `main.rs` via `iced::font`.
//! Each helper returns a `Text` widget rendered in that font.
//!
//! Codepoints sourced from `bootstrap-icons.json` (v1.11.3).

use iced::Font;
use iced::widget::Text;

/// The Bootstrap Icons font, registered under its family name.
pub static ICON_FONT: Font = Font::with_name("bootstrap-icons");

/// Icon size used for inline glyphs.
pub const ICON_SIZE: f32 = 14.0;

fn glyph(codepoint: char) -> Text<'static> {
    iced::widget::text(codepoint.to_string())
        .font(ICON_FONT)
        .size(ICON_SIZE)
}

pub fn search() -> Text<'static>       { glyph('\u{F52A}') }
pub fn folder() -> Text<'static>       { glyph('\u{F3B7}') }
pub fn person() -> Text<'static>       { glyph('\u{F4D9}') }
pub fn people() -> Text<'static>       { glyph('\u{F4D0}') }
pub fn chevron_down() -> Text<'static> { glyph('\u{F282}') }
pub fn chevron_right() -> Text<'static>{ glyph('\u{F285}') }
pub fn clipboard() -> Text<'static>    { glyph('\u{F290}') }
pub fn house() -> Text<'static>        { glyph('\u{F425}') }
pub fn gear() -> Text<'static>         { glyph('\u{F3E5}') }
pub fn close() -> Text<'static>        { glyph('\u{F659}') }
pub fn dots_vertical() -> Text<'static>{ glyph('\u{F5C3}') }
pub fn refresh() -> Text<'static>      { glyph('\u{F101}') }

/// Pick an icon for a coarse AD object type.
pub fn for_object_type(t: ldaphound_core::filter::ObjectType) -> Text<'static> {
    use ldaphound_core::filter::ObjectType;
    match t {
        ObjectType::User | ObjectType::Group => person(),
        ObjectType::Computer => house(),
        ObjectType::Domain | ObjectType::Ou | ObjectType::Container | ObjectType::Gpo => folder(),
        ObjectType::Other => dots_vertical(),
    }
}
