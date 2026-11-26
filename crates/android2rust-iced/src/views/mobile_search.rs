use crate::app::App;
use crate::message::{Message, WpdSourceMode};
use crate::views::{page_header, section_card};
use android2rust_wpd::mobile_file_search_schema;
use guap_export::ExportFormat;
use guap_table::SortDirection;
use iced::widget::{button, checkbox, column, container, pick_list, row, rule, scrollable, text, text_input};
use iced::{Alignment, Color, Element, Font, Length};

pub fn view_mobile_search(app: &App) -> Element<'_, Message> {
    let hdr_controls = row![
        button(
            text(if app.wpd_scanning {
                "Scanning..."
            } else {
                "List Devices"
            })
            .size(12)
        )
        .on_press_maybe((!app.wpd_scanning).then_some(Message::WpdListDevices))
        .style(button::secondary),
        button(text(if app.wpd_scanning { "Searching..." } else { "Search WPD" }).size(12))
            .on_press_maybe((!app.wpd_scanning).then_some(Message::WpdRunSearch))
            .style(button::primary),
        button(text("Copy Out...").size(12))
            .on_press_maybe((!app.wpd_results.is_empty() && !app.wpd_scanning).then_some(Message::WpdCopyOutSelected))
            .style(button::secondary),
        button(text("CSV").size(12))
            .on_press_maybe((!app.wpd_results.is_empty()).then_some(Message::WpdExport(ExportFormat::Csv)))
            .style(button::secondary),
        button(text("JSON").size(12))
            .on_press_maybe((!app.wpd_results.is_empty()).then_some(Message::WpdExport(ExportFormat::Json)))
            .style(button::secondary),
        button(text("HTML").size(12))
            .on_press_maybe((!app.wpd_results.is_empty()).then_some(Message::WpdExport(ExportFormat::Html)))
            .style(button::secondary),
        button(text("MD").size(12))
            .on_press_maybe((!app.wpd_results.is_empty()).then_some(Message::WpdExport(ExportFormat::Markdown)))
            .style(button::secondary),
    ]
    .spacing(6)
    .align_y(Alignment::Center);

    let header = page_header("WPD/MTP File Search", hdr_controls);

    let source_card = section_card(
        "WPD / MTP Source & Query Filters",
        column![
            row![
                pick_list(
                    WpdSourceMode::ALL,
                    Some(app.wpd_source_mode),
                    Message::WpdSourceModeChanged,
                )
                .text_size(12)
                .width(Length::Fixed(230.0)),
                text_input("Offline synthetic directory fixture...", &app.wpd_fixture_dir)
                    .on_input(Message::WpdFixtureDirChanged)
                    .size(12)
                    .width(Length::Fill),
                button(text("Browse Dir...").size(12))
                    .on_press(Message::WpdBrowseFixtureDir)
                    .style(button::secondary),
                text_input("Device filter (optional)", &app.wpd_device_filter)
                    .on_input(Message::WpdDeviceFilterChanged)
                    .size(12)
                    .width(Length::Fixed(170.0)),
            ]
            .spacing(8)
            .align_y(Alignment::Center),
            row![
                text_input("Pattern (*.jpg, IMG_????.*, or regex)", &app.wpd_pattern)
                    .on_input(Message::WpdPatternChanged)
                    .size(12)
                    .width(Length::FillPortion(2)),
                checkbox(app.wpd_use_regex)
                    .label("Regex")
                    .on_toggle(Message::WpdToggleRegex)
                    .size(14),
                text_input("Min bytes", &app.wpd_min_size)
                    .on_input(Message::WpdMinSizeChanged)
                    .size(12)
                    .width(Length::Fixed(95.0)),
                text_input("Max bytes", &app.wpd_max_size)
                    .on_input(Message::WpdMaxSizeChanged)
                    .size(12)
                    .width(Length::Fixed(95.0)),
                text_input("MIME or ext", &app.wpd_mime_filter)
                    .on_input(Message::WpdMimeFilterChanged)
                    .size(12)
                    .width(Length::Fixed(130.0)),
                text_input("Max results", &app.wpd_max_results)
                    .on_input(Message::WpdMaxResultsChanged)
                    .size(12)
                    .width(Length::Fixed(90.0)),
            ]
            .spacing(8)
            .align_y(Alignment::Center),
            row![
                text_input("Created >= (YYYY-MM-DD or RFC3339)", &app.wpd_created_after)
                    .on_input(Message::WpdCreatedAfterChanged)
                    .size(12)
                    .width(Length::Fill),
                text_input("Modified >= (YYYY-MM-DD or RFC3339)", &app.wpd_modified_after)
                    .on_input(Message::WpdModifiedAfterChanged)
                    .size(12)
                    .width(Length::Fill),
            ]
            .spacing(8)
            .align_y(Alignment::Center),
        ]
        .spacing(8),
    );

    let status_banner = container(text(&app.wpd_status).size(12).color(
        if app.wpd_status.to_ascii_lowercase().contains("error")
            || app.wpd_status.to_ascii_lowercase().contains("no wpd")
            || app.wpd_status.to_ascii_lowercase().contains("unsupported")
        {
            Color::from_rgb(0.95, 0.72, 0.30)
        } else {
            Color::from_rgb(0.75, 0.85, 0.95)
        },
    ))
    .width(Length::Fill)
    .padding([6, 10])
    .style(container::bordered_box);

    let schema = mobile_file_search_schema();
    let mut header_row = row![].spacing(8).align_y(Alignment::Center);
    for (idx, col) in schema.columns.iter().enumerate() {
        let mut lbl = col.label.clone();
        if app.wpd_sort_col == Some(idx) {
            lbl.push_str(match app.wpd_sort_dir {
                SortDirection::Asc => " ^",
                SortDirection::Desc => " v",
            });
        }
        header_row = header_row.push(
            button(text(lbl).size(11))
                .on_press(Message::WpdSortColumn(idx))
                .style(button::text)
                .width(Length::Fixed(col.width_hint as f32)),
        );
    }

    let mut table_col = column![header_row, rule::horizontal(1)].spacing(3);
    if app.wpd_table_data.rows.is_empty() {
        table_col = table_col.push(
            container(
                text("No WPD/MTP entries loaded. Click 'Search WPD' or choose an Offline Directory Fixture.").size(12),
            )
            .padding(10),
        );
    } else {
        for (row_idx, row_item) in app.wpd_table_data.rows.iter().enumerate() {
            let mut cells_row = row![].spacing(8).align_y(Alignment::Center);
            for (col_idx, col) in schema.columns.iter().enumerate() {
                let val = row_item
                    .cells
                    .get(col_idx)
                    .map(|c| c.format_human(col.col_type))
                    .unwrap_or_default();
                cells_row = cells_row.push(
                    text(val)
                        .size(11)
                        .font(Font::MONOSPACE)
                        .width(Length::Fixed(col.width_hint as f32)),
                );
            }
            let selected = app.wpd_selected_row == Some(row_idx);
            table_col = table_col.push(
                button(cells_row)
                    .on_press(Message::WpdSelectRow(Some(row_idx)))
                    .style(if selected { button::primary } else { button::text }),
            );
        }
    }

    let grid_card = section_card(
        format!("Results ({} matched)", app.wpd_results.len()),
        scrollable(table_col)
            .direction(scrollable::Direction::Both {
                vertical: scrollable::Scrollbar::default(),
                horizontal: scrollable::Scrollbar::default(),
            })
            .width(Length::Fill)
            .height(Length::Fill),
    );

    let inspector_text = app
        .wpd_selected_row
        .and_then(|idx| app.wpd_table_data.rows.get(idx))
        .and_then(|r| r.detail_json.as_ref())
        .and_then(|v| serde_json::to_string_pretty(v).ok())
        .unwrap_or_else(|| "Select a row above to inspect its full WPD/MTP metadata JSON.".to_string());

    let inspector_card = section_card(
        "Object Inspector",
        scrollable(text(inspector_text).size(11).font(Font::MONOSPACE)).height(Length::Fixed(110.0)),
    );

    column![
        header,
        source_card,
        status_banner,
        container(grid_card).height(Length::Fill),
        inspector_card,
    ]
    .spacing(10)
    .height(Length::Fill)
    .into()
}
