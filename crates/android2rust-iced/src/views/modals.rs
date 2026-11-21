use crate::app::App;
use crate::message::{ActiveModal, CadenceChoice, Message};
use android2rust_core::{ScheduleCadence, build_schtasks_command, decode_status_code};
use iced::widget::{button, checkbox, column, container, mouse_area, pick_list, row, rule, text, text_input};
use iced::{Alignment, Color, Element, Font, Length};

pub fn view_modal(app: &App) -> Element<'_, Message> {
    let inner: Element<'_, Message> = match app.active_modal {
        ActiveModal::None => column![].into(),
        ActiveModal::ConfirmDestructive => view_confirm_destructive(app),
        ActiveModal::ImportCommand => view_import_command(app),
        ActiveModal::SaveProfile => view_save_profile(app),
        ActiveModal::TaskScheduler => view_task_scheduler(app),
        ActiveModal::StatusCodeReference => view_status_code_modal(app),
        ActiveModal::About => view_about_modal(app),
    };

    mouse_area(
        container(inner)
            .padding(18)
            .width(Length::Fixed(580.0))
            .style(container::rounded_box),
    )
    .on_press(Message::OpenModal(app.active_modal))
    .into()
}

fn view_confirm_destructive(app: &App) -> Element<'_, Message> {
    let Some(pending) = &app.pending_destructive_job else {
        return column![].into();
    };
    let reasons = pending.destructive_reasons().join(", ");
    let heading = if app.pending_destructive_batch {
        "Confirm Destructive Batch Queue Execution"
    } else {
        "Confirm Destructive Android Operation"
    };
    let trigger_line = if app.pending_destructive_batch {
        format!("Batch queue includes destructive operation(s): {reasons}")
    } else {
        format!("Destructive trigger(s): {reasons}")
    };
    let exec_label = if app.pending_destructive_batch {
        "Execute Destructive Queue"
    } else {
        "Execute Destructive Job"
    };

    column![
        text(heading).size(17).color(Color::from_rgb(0.75, 0.14, 0.14)),
        rule::horizontal(1),
        text(trigger_line).size(13),
        text("Device partitions, bootloader state, or application user data may be permanently altered or erased.")
            .size(13),
        text(format!("Serial/Target: {} | {}", pending.serial, pending.target_path))
            .size(12)
            .font(Font::MONOSPACE),
        text(format!("Source/Image : {}", pending.source_path))
            .size(12)
            .font(Font::MONOSPACE),
        row![
            button(text("Run Safe Dry-Run First").size(13))
                .on_press(Message::DryRunPendingInstead)
                .style(button::success),
            button(text("Cancel").size(13))
                .on_press(Message::CloseModal)
                .style(button::secondary),
            button(text(exec_label).size(13))
                .on_press(Message::ConfirmDestructiveExecute)
                .style(button::danger),
        ]
        .spacing(8),
    ]
    .spacing(10)
    .into()
}

fn view_import_command(app: &App) -> Element<'_, Message> {
    column![
        text("Import / Parse ADB or Fastboot Command Line").size(17),
        rule::horizontal(1),
        text("Paste any raw adb or fastboot command string to populate the Designer:").size(13),
        text_input(
            r#"adb -s R58M123 install -r -g "C:\Apps\demo.apk""#,
            &app.import_cmd_text
        )
        .on_input(Message::ImportCmdTextChanged)
        .on_submit(Message::ApplyImportCmd)
        .font(Font::MONOSPACE)
        .size(12)
        .padding(8),
        row![
            button(text("Parse & Load into Designer").size(13))
                .on_press(Message::ApplyImportCmd)
                .style(button::primary),
            button(text("Cancel").size(13))
                .on_press(Message::CloseModal)
                .style(button::secondary),
        ]
        .spacing(8),
    ]
    .spacing(10)
    .into()
}

fn view_save_profile(app: &App) -> Element<'_, Message> {
    let valid = !app.save_profile_name.trim().is_empty();
    column![
        text("Save Android2Rust Job Profile").size(17),
        rule::horizontal(1),
        row![
            text("Name:").size(13).width(Length::Fixed(90.0)),
            text_input("Profile Name", &app.save_profile_name)
                .on_input(Message::SaveProfileNameChanged)
                .size(13)
                .width(Length::Fill),
        ]
        .spacing(8)
        .align_y(Alignment::Center),
        row![
            text("Description:").size(13).width(Length::Fixed(90.0)),
            text_input("Optional notes", &app.save_profile_desc)
                .on_input(Message::SaveProfileDescChanged)
                .size(13)
                .width(Length::Fill),
        ]
        .spacing(8)
        .align_y(Alignment::Center),
        row![
            button(text("Save Profile").size(13))
                .on_press_maybe(valid.then_some(Message::ConfirmSaveProfile))
                .style(button::primary),
            button(text("Cancel").size(13))
                .on_press(Message::CloseModal)
                .style(button::secondary),
        ]
        .spacing(8),
    ]
    .spacing(10)
    .into()
}

fn view_task_scheduler(app: &App) -> Element<'_, Message> {
    let generated = build_schtasks_command(&app.task_sched_name, &app.task_sched_target, &app.task_sched_spec);

    let mut col = column![
        text("Windows Task Scheduler (schtasks) Generator").size(17),
        rule::horizontal(1),
        row![
            text("Task Name:").size(13).width(Length::Fixed(95.0)),
            text_input("Android2Rust_DailyPull", &app.task_sched_name)
                .on_input(Message::TaskNameChanged)
                .size(13)
                .width(Length::Fill),
        ]
        .spacing(8)
        .align_y(Alignment::Center),
        row![
            text("Cadence:").size(13).width(Length::Fixed(95.0)),
            pick_list(
                CadenceChoice::ALL,
                Some(CadenceChoice(app.task_sched_spec.cadence)),
                Message::TaskCadenceChanged,
            )
            .text_size(13),
            text("Time (HH:MM):").size(13),
            text_input("02:00", &app.task_sched_spec.start_time)
                .on_input(Message::TaskStartTimeChanged)
                .size(13)
                .width(Length::Fixed(75.0)),
        ]
        .spacing(8)
        .align_y(Alignment::Center),
        checkbox(app.task_sched_spec.run_highest)
            .label("Run with highest privileges (/RL HIGHEST)")
            .on_toggle(Message::TaskRunHighestToggled),
    ]
    .spacing(10);

    if app.task_sched_spec.cadence == ScheduleCadence::Weekly {
        col = col.push(
            row![
                text("Days (/D):").size(13).width(Length::Fixed(95.0)),
                text_input("MON,WED,FRI", app.task_sched_spec.days.as_deref().unwrap_or(""))
                    .on_input(Message::TaskDaysChanged)
                    .size(13)
                    .width(Length::Fill),
            ]
            .spacing(8)
            .align_y(Alignment::Center),
        );
    }

    col = col
        .push(
            row![
                text("Target (/TR):").size(13).width(Length::Fixed(95.0)),
                text_input("Command or script path", &app.task_sched_target)
                    .on_input(Message::TaskTargetChanged)
                    .font(Font::MONOSPACE)
                    .size(12)
                    .width(Length::Fill),
            ]
            .spacing(8)
            .align_y(Alignment::Center),
        )
        .push(text("Generated schtasks Command:").size(13))
        .push(text_input("", &generated).font(Font::MONOSPACE).size(12).padding(6))
        .push(
            row![
                button(text("Copy schtasks Command").size(13))
                    .on_press(Message::CopySchtasksCmd)
                    .style(button::primary),
                button(text("Close").size(13))
                    .on_press(Message::CloseModal)
                    .style(button::secondary),
            ]
            .spacing(8),
        );

    col.into()
}

fn view_status_code_modal(app: &App) -> Element<'_, Message> {
    let info = decode_status_code(&app.status_code_input);
    let col_status = if info.is_success {
        Color::from_rgb(0.08, 0.50, 0.24)
    } else {
        Color::from_rgb(0.75, 0.14, 0.14)
    };

    let mut quick = row![
        text("Status:").size(13),
        text_input("DEVICE_UNAUTHORIZED", &app.status_code_input)
            .on_input(Message::StatusCodeInputChanged)
            .font(Font::MONOSPACE)
            .size(12)
            .width(Length::Fixed(230.0)),
    ]
    .spacing(6)
    .align_y(Alignment::Center);

    for q in [
        "0",
        "DEVICE_UNAUTHORIZED",
        "INSTALL_FAILED_VERSION_DOWNGRADE",
        "FASTBOOT_LOCKED",
    ] {
        quick = quick.push(
            button(text(q).size(11))
                .on_press(Message::SelectQuickStatusCode(q.to_string()))
                .style(button::secondary),
        );
    }

    let mut details = column![].spacing(4);
    for d in info.details {
        details = details.push(text(format!("• {d}")).size(12));
    }

    column![
        text("Android / ADB / Fastboot Status Code Decoder").size(17),
        rule::horizontal(1),
        quick,
        text(info.short_label).size(15).color(col_status),
        text(info.summary).size(13),
        rule::horizontal(1),
        details,
        button(text("Close").size(13))
            .on_press(Message::CloseModal)
            .style(button::secondary),
    ]
    .spacing(8)
    .into()
}

fn view_about_modal(app: &App) -> Element<'_, Message> {
    let adb_path = app
        .env
        .adb_path
        .as_ref()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "Not found on host OS".to_string());
    let fb_path = app
        .env
        .fastboot_path
        .as_ref()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "Not found on host OS".to_string());

    column![
        text(concat!(
            "Android2Rust Management & Forensics Console v",
            env!("CARGO_PKG_VERSION")
        ))
        .size(17),
        rule::horizontal(1),
        text("Cross-Platform Iced 0.14 Edition (wgpu + tiny-skia CPU fallback)").size(13),
        text("Part of the GUAP Ecosystem (guap.ca) • Licensed under Apache-2.0").size(12),
        text(format!("Host OS: {}", app.env.os)).size(12),
        text(format!("ADB Path: {adb_path}")).size(12),
        text(format!("Fastboot Path: {fb_path}")).size(12),
        text(format!("Config Store: {}", app.env.config_dir.display())).size(12),
        button(text("Close").size(13))
            .on_press(Message::CloseModal)
            .style(button::primary),
    ]
    .spacing(8)
    .into()
}
