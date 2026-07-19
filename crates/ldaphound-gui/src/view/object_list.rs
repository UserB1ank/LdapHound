//! Left pane — searchable, scrollable list of objects.

use iced::widget::{button, column, container, row, scrollable, text, text_input};
use iced::{Alignment, Element, Length};

use ldaphound_core::{Object, Snapshot};

use crate::message::Message;

/// Render the object list pane.
pub fn view<'a>(
    snap: &'a Snapshot,
    filter: &str,
    filtered_indices: &[usize],
    _selected: Option<usize>,
) -> Element<'a, Message> {
    // Header with count + filter input.
    let header = column![
        text(format!("{} objects", snap.objects.len())),
        text_input("Filter by DN or name…", filter).on_input(Message::FilterChanged),
        text(format!("{} match", filtered_indices.len())),
    ]
    .spacing(4);

    // Rows. Limit to first N to keep rendering tractable on huge snapshots;
    // a virtualized table is a follow-up.
    const MAX_ROWS: usize = 2000;
    let mut rows: Vec<Element<'a, Message>> = Vec::new();
    for &i in filtered_indices.iter().take(MAX_ROWS) {
        let o = &snap.objects[i];
        let label = row_label(o);
        let btn = button(label).on_press(Message::ObjectSelected(i));
        rows.push(btn.into());
    }
    if filtered_indices.len() > MAX_ROWS {
        rows.push(
            text(format!("… ({} more not shown)", filtered_indices.len() - MAX_ROWS)).into(),
        );
    }

    let list = column![header, column(rows).spacing(2)].spacing(8);
    container(scrollable(list))
        .width(Length::FillPortion(2))
        .height(Length::Fill)
        .padding(4)
        .into()
}

fn row_label(o: &Object) -> Element<'_, Message> {
    let primary = o
        .object_classes()
        .last()
        .map(|s| s.as_str().to_string())
        .unwrap_or_else(|| "?".into());
    let dn = o.dn().unwrap_or("");
    row![
        iced::widget::text(format!("{primary:<16}")),
        iced::widget::text(dn),
    ]
    .spacing(8)
    .align_y(Alignment::Center)
    .into()
}
