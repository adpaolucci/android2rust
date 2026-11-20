use crate::app::App;
use crate::message::{ActionFilter, ConsoleSubTab, Message};
use crate::views::{page_header, section_card};
use android2rust_core::format::{format_bytes, format_duration};
use android2rust_report::ReportFormat;
use android2rust_runner::FileActionKind;
use iced::widget::{button, column, container, progress_bar, row, scrollable, text, text_input};
use iced::{Alignment, Color, Element, Font, Length};

pub fn view_live_console(app: &App) -> Element<'_, Message> {
    let right_hdr: Element<'_, Message> = if let Some(res) = &app.last_result {
        row![
            button(text("Export HTML...").size(12))
                .on_press(Message::ExportReport(ReportFormat::Html))
                .style(button::secondary),
            button(text("Export All (HTML+JSON+MD)...").size(12))
                .on_press(Message::ExportReport(ReportFormat::All))
                .style(button::secondary),
            text(format!("Duration: {}", format_duration(res.duration_secs))).size(12),
        ]
        .spacing(6)
        .align_y(Alignment::Center)
        .into()
    } else {
        text("Idle").size(12).into()
    };

    let header = page_header("Live Execution Monitor, Parsed Records & Console Stream", right_hdr);

    let active_item = app
        .live_current_file
        .as_deref()
        .unwrap_or("Waiting for device/artifact telemetry...");

    let sum = &app.live_summary;
    let kpis = row![
        kpi_box("Devices", sum.devices_seen.to_string()),
        kpi_box("Properties", sum.properties_seen.to_string()),
        kpi_box("Packages", sum.packages_seen.to_string()),
        kpi_box("Transfers", sum.files_transferred.to_string()),
        kpi_box("Bytes", format_bytes(sum.bytes_processed)),
        kpi_box("Errors", sum.errors_seen.to_string()),
    ]
    .spacing(8);

    let mut progress_col = column![
        row![
            progress_bar(0.0..=100.0, app.live_progress_pct).length(Length::Fixed(260.0)),
            text(format!("{:.0}%", app.live_progress_pct)).size(13),
            text(active_item).size(12).font(Font::MONOSPACE).width(Length::Fill),
        ]
        .spacing(10)
        .align_y(Alignment::Center),
        kpis,
    ]
    .spacing(8);

    if let Some(res) = &app.last_result {
        let color = if res.status_info.is_success {
            Color::from_rgb(0.08, 0.50, 0.24)
        } else {
            Color::from_rgb(0.75, 0.14, 0.14)
        };
        progress_col = progress_col.push(
            container(
                text(format!(
                    "Status {}: {} — {}",
                    res.exit_code, res.status_info.short_label, res.status_info.summary
                ))
                .size(13)
                .color(color),
            )
            .padding(8)
            .width(Length::Fill)
            .style(container::bordered_box),
        );
    }

    let subtab_bar = row![
        button(text(format!("Parsed Records ({})", app.live_file_actions.len())).size(12))
            .on_press(Message::SwitchConsoleSubTab(ConsoleSubTab::ParsedRecords))
            .style(if app.console_subtab == ConsoleSubTab::ParsedRecords {
                button::primary
            } else {
                button::secondary
            }),
        button(text(format!("Raw Console Stream ({} lines)", app.live_log_lines.len())).size(12))
            .on_press(Message::SwitchConsoleSubTab(ConsoleSubTab::RawLog))
            .style(if app.console_subtab == ConsoleSubTab::RawLog {
                button::primary
            } else {
                button::secondary
            }),
    ]
    .spacing(6)
    .height(Length::Shrink)
    .align_y(Alignment::Center);

    let sub_controls: Element<'_, Message> = if app.console_subtab == ConsoleSubTab::ParsedRecords {
        let mut r = row![].spacing(6).align_y(Alignment::Center);
        for (af, lbl) in [
            (ActionFilter::All, "All"),
            (ActionFilter::DevicesPackages, "Devices/Pkgs/Props"),
            (ActionFilter::TransfersForensics, "Transfers/Forensics"),
            (ActionFilter::Errors, "Errors"),
        ] {
            r = r.push(button(text(lbl).size(12)).on_press(Message::SetActionFilter(af)).style(
                if app.action_filter == af {
                    button::primary
                } else {
                    button::secondary
                },
            ));
        }
        r = r.push(
            text_input("Filter key or detail...", &app.action_search)
                .on_input(Message::ActionSearchChanged)
                .size(12)
                .width(Length::Fixed(220.0)),
        );
        r.into()
    } else {
        row![
            text_input("Filter log lines...", &app.log_search)
                .on_input(Message::LogSearchChanged)
                .size(12)
                .width(Length::Fixed(220.0)),
            button(text("Copy Log").size(12))
                .on_press(Message::CopyLogToClipboard)
                .style(button::secondary),
        ]
        .spacing(6)
        .align_y(Alignment::Center)
        .into()
    };

    let body: Element<'_, Message> = match app.console_subtab {
        ConsoleSubTab::ParsedRecords => view_records_list(app),
        ConsoleSubTab::RawLog => view_raw_log(app),
    };

    column![
        header,
        section_card("Live Execution & Telemetry Summary", progress_col),
        row![subtab_bar, sub_controls].spacing(8).align_y(Alignment::Center),
        container(body)
            .width(Length::Fill)
            .height(Length::Fill)
            .padding(8)
            .style(container::bordered_box),
    ]
    .spacing(8)
    .height(Length::Fill)
    .into()
}

fn view_records_list(app: &App) -> Element<'_, Message> {
    let q = app.action_search.trim().to_ascii_lowercase();
    let mut rows = column![].spacing(4);
    let mut shown = 0usize;

    for rec in app.live_file_actions.iter().rev() {
        let matches_filter = match app.action_filter {
            ActionFilter::All => true,
            ActionFilter::DevicesPackages => rec.kind.is_device_or_pkg(),
            ActionFilter::TransfersForensics => rec.kind.is_transfer_or_forensic(),
            ActionFilter::Errors => rec.kind.is_error(),
        };
        if !matches_filter {
            continue;
        }
        if !q.is_empty()
            && !rec.path.to_ascii_lowercase().contains(&q)
            && !rec.detail.to_ascii_lowercase().contains(&q)
            && !rec.kind.label().to_ascii_lowercase().contains(&q)
        {
            continue;
        }
        let sz = rec.size_bytes.map(format_bytes).unwrap_or_else(|| "-".to_string());
        let col = match rec.kind {
            FileActionKind::Error => Color::from_rgb(0.75, 0.14, 0.14),
            FileActionKind::Forensic | FileActionKind::Transfer => Color::from_rgb(0.08, 0.50, 0.24),
            _ => Color::from_rgb(0.11, 0.45, 0.72),
        };
        rows = rows.push(
            row![
                text(rec.kind.label()).size(12).color(col).width(Length::Fixed(85.0)),
                text(sz).size(12).width(Length::Fixed(85.0)),
                text(&rec.path)
                    .size(12)
                    .font(Font::MONOSPACE)
                    .width(Length::FillPortion(2)),
                text(&rec.detail)
                    .size(12)
                    .font(Font::MONOSPACE)
                    .width(Length::FillPortion(3)),
            ]
            .spacing(8),
        );
        shown += 1;
        if shown >= 500 {
            break;
        }
    }

    if shown == 0 {
        return text("No matching records yet. Execute an ADB, Fastboot, or Offline Forensic job.")
            .size(13)
            .into();
    }

    scrollable(rows).height(Length::Fill).into()
}

fn view_raw_log(app: &App) -> Element<'_, Message> {
    let q = app.log_search.trim().to_ascii_lowercase();
    let mut lines = column![].spacing(2);
    let mut shown = 0usize;
    for l in app.live_log_lines.iter().rev() {
        if !q.is_empty() && !l.to_ascii_lowercase().contains(&q) {
            continue;
        }
        lines = lines.push(text(l).size(12).font(Font::MONOSPACE));
        shown += 1;
        if shown >= 1500 {
            break;
        }
    }
    if shown == 0 {
        return text("Console output stream is empty.").size(13).into();
    }
    scrollable(lines).height(Length::Fill).into()
}

fn kpi_box<'a>(label: &'a str, val: String) -> Element<'a, Message> {
    container(column![text(label).size(11), text(val).size(15)].spacing(2))
        .padding(8)
        .width(Length::Fill)
        .style(container::bordered_box)
        .into()
}
