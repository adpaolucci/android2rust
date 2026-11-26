use std::fs;

use android2rust_wpd::{
    CopyOutOptions, DirectoryMtpSource, MobileFileQuery, MobileFileSearchProvider, MockErrorKind, MockWpdSource,
    WpdDeviceInfo, WpdError, WpdObjectEntry, WpdStorageInfo, copy_out, search_devices, write_wpd_entries_export,
};
use chrono::{TimeZone, Utc};
use guap_export::{ExportFormat, ExportOptions};
use guap_table::{CellValue, CompareOp, FilterExpr, SortDirection, TableProvider, TableQuery};
use tempfile::TempDir;

fn make_mock_entry(
    device_id: &str,
    device_name: &str,
    storage_name: &str,
    object_id: &str,
    full_path: &str,
    size_bytes: u64,
    content_type: &str,
) -> WpdObjectEntry {
    let filename = full_path.rsplit(['/', '\\']).next().unwrap_or(full_path).to_string();
    let extension = android2rust_wpd::infer_extension(&filename);
    WpdObjectEntry {
        device_id: device_id.to_string(),
        device_name: device_name.to_string(),
        storage_name: storage_name.to_string(),
        object_id: object_id.to_string(),
        parent_id: "PARENT".to_string(),
        full_path: full_path.to_string(),
        filename,
        extension,
        size_bytes,
        created_time: Some(Utc.with_ymd_and_hms(2026, 3, 15, 12, 0, 0).unwrap()),
        modified_time: Some(Utc.with_ymd_and_hms(2026, 3, 16, 8, 30, 0).unwrap()),
        content_type: content_type.to_string(),
        is_folder: false,
        can_delete: false,
    }
}

#[test]
fn directory_source_enumerates_nested_tree_and_filters() {
    let tmp = TempDir::new().unwrap();
    let dcim = tmp.path().join("DCIM").join("Camera");
    let dl = tmp.path().join("Download");
    let docs = tmp.path().join("Documents");
    fs::create_dir_all(&dcim).unwrap();
    fs::create_dir_all(&dl).unwrap();
    fs::create_dir_all(&docs).unwrap();

    fs::write(dcim.join("IMG_0001.jpg"), vec![0xFFu8; 1024]).unwrap();
    fs::write(dl.join("notes.txt"), b"hello mtp").unwrap();
    fs::write(docs.join("report.pdf"), b"%PDF-1.7 test").unwrap();

    let src = DirectoryMtpSource::new(tmp.path());
    let all = search_devices(&src, &MobileFileQuery::default()).unwrap();
    assert_eq!(all.len(), 3);

    let jpg = all.iter().find(|e| e.filename == "IMG_0001.jpg").unwrap();
    assert_eq!(jpg.full_path, "/DCIM/Camera/IMG_0001.jpg");
    assert_eq!(jpg.extension, "jpg");
    assert_eq!(jpg.size_bytes, 1024);
    assert_eq!(jpg.content_type, "image/jpeg");

    let q_multi = MobileFileQuery {
        pattern: Some("*.JPG;*.pdf".to_string()),
        ..Default::default()
    };
    let matched = search_devices(&src, &q_multi).unwrap();
    assert_eq!(matched.len(), 2);
}

#[test]
fn directory_source_respects_max_depth_cap() {
    let tmp = TempDir::new().unwrap();
    let mut deep = tmp.path().to_path_buf();
    for i in 0..8 {
        deep = deep.join(format!("d{i}"));
    }
    fs::create_dir_all(&deep).unwrap();
    fs::write(deep.join("deep.txt"), b"deep").unwrap();
    fs::write(tmp.path().join("top.txt"), b"top").unwrap();

    let src = DirectoryMtpSource::new(tmp.path()).with_max_depth(3);
    let entries = search_devices(&src, &MobileFileQuery::default()).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].filename, "top.txt");
}

#[test]
fn mock_source_multi_device_storage_and_error_injection() {
    let mock = MockWpdSource::new()
        .with_device(WpdDeviceInfo {
            id: "dev-pixel".to_string(),
            friendly_name: "Pixel 9".to_string(),
            manufacturer: "Google".to_string(),
            description: "Android MTP".to_string(),
            storages: vec![
                WpdStorageInfo {
                    object_id: "s1".to_string(),
                    name: "Internal shared storage".to_string(),
                    file_system: "Generic".to_string(),
                    capacity_bytes: Some(128_000_000_000),
                    free_bytes: Some(64_000_000_000),
                },
                WpdStorageInfo {
                    object_id: "s2".to_string(),
                    name: "SD Card".to_string(),
                    file_system: "FAT32".to_string(),
                    capacity_bytes: Some(64_000_000_000),
                    free_bytes: Some(32_000_000_000),
                },
            ],
        })
        .with_device(WpdDeviceInfo {
            id: "dev-galaxy".to_string(),
            friendly_name: "Galaxy S25".to_string(),
            manufacturer: "Samsung".to_string(),
            description: "Android MTP".to_string(),
            storages: vec![],
        });

    mock.add_entry(
        make_mock_entry(
            "dev-pixel",
            "Pixel 9",
            "Internal shared storage",
            "o1",
            "/DCIM/IMG_1001.jpg",
            4096,
            "image/jpeg",
        ),
        vec![1, 2, 3, 4],
    );
    mock.add_entry(
        make_mock_entry(
            "dev-pixel",
            "Pixel 9",
            "SD Card",
            "o2",
            "/Music/track.mp3",
            8192,
            "audio/mpeg",
        ),
        vec![5, 6, 7],
    );
    mock.add_entry(
        make_mock_entry(
            "dev-galaxy",
            "Galaxy S25",
            "Internal shared storage",
            "o3",
            "/Download/file+(1)[test].txt",
            128,
            "text/plain",
        ),
        b"metachars".to_vec(),
    );

    let q_sd = MobileFileQuery {
        device_filter: Some("Pixel".to_string()),
        storage_filter: Some("SD Card".to_string()),
        ..Default::default()
    };
    let sd_hits = search_devices(&mock, &q_sd).unwrap();
    assert_eq!(sd_hits.len(), 1);
    assert_eq!(sd_hits[0].object_id, "o2");

    // Regex metacharacters escaped in glob mode
    let q_glob_meta = MobileFileQuery {
        pattern: Some("file+(1)[test].txt".to_string()),
        use_regex: false,
        ..Default::default()
    };
    let meta_hits = search_devices(&mock, &q_glob_meta).unwrap();
    assert_eq!(meta_hits.len(), 1);
    assert_eq!(meta_hits[0].object_id, "o3");

    // Error injection
    mock.set_list_error(Some(MockErrorKind::AccessDenied("device locked".to_string())));
    assert!(matches!(
        search_devices(&mock, &MobileFileQuery::default()),
        Err(WpdError::AccessDenied(_))
    ));
}

#[test]
fn query_validation_and_edge_cases() {
    let bad_regex = MobileFileQuery {
        pattern: Some("[unclosed".to_string()),
        use_regex: true,
        ..Default::default()
    };
    assert!(matches!(bad_regex.validate(), Err(WpdError::InvalidQuery(_))));

    let bad_size = MobileFileQuery {
        min_size: Some(500),
        max_size: Some(100),
        ..Default::default()
    };
    assert!(matches!(bad_size.validate(), Err(WpdError::InvalidQuery(_))));

    let bad_dates = MobileFileQuery {
        created_after: Some(Utc.with_ymd_and_hms(2026, 5, 1, 0, 0, 0).unwrap()),
        created_before: Some(Utc.with_ymd_and_hms(2026, 4, 1, 0, 0, 0).unwrap()),
        ..Default::default()
    };
    assert!(matches!(bad_dates.validate(), Err(WpdError::InvalidQuery(_))));

    let mock = MockWpdSource::new().with_device(WpdDeviceInfo {
        id: "d1".to_string(),
        friendly_name: "Test".to_string(),
        ..Default::default()
    });
    let mut no_ts = make_mock_entry("d1", "Test", "Internal", "o1", "/DCIM/a.jpg", 100, "image/jpeg");
    no_ts.created_time = None;
    no_ts.modified_time = None;
    mock.add_entry(no_ts, b"a".to_vec());
    mock.add_entry(
        make_mock_entry("d1", "Test", "Internal", "o2", "/DCIM/b.png", 200, "image/png"),
        b"b".to_vec(),
    );

    // max_results = Some(0) returns 0 rows cleanly
    let zero = search_devices(
        &mock,
        &MobileFileQuery {
            max_results: Some(0),
            ..Default::default()
        },
    )
    .unwrap();
    assert!(zero.is_empty());

    // Date filter excludes entries with None timestamp, includes inclusive boundary
    let date_hits = search_devices(
        &mock,
        &MobileFileQuery {
            created_after: Some(Utc.with_ymd_and_hms(2026, 3, 15, 12, 0, 0).unwrap()),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(date_hits.len(), 1);
    assert_eq!(date_hits[0].object_id, "o2");

    // MIME wildcard image/*
    let img_hits = search_devices(
        &mock,
        &MobileFileQuery {
            content_type: Some("image/*".to_string()),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(img_hits.len(), 2);
}

#[test]
fn live_wpd_source_handles_missing_hardware_or_non_windows_gracefully() {
    let live = android2rust_wpd::LiveWpdSource::new();
    let res = search_devices(&live, &MobileFileQuery::default());
    // On CI/dev hosts without a phone attached (or non-Windows), returns NoDevices or UnsupportedPlatform cleanly.
    if let Err(err) = res {
        assert!(
            matches!(
                err,
                WpdError::NoDevices | WpdError::UnsupportedPlatform | WpdError::AccessDenied(_)
            ),
            "unexpected live error: {err}"
        );
    }
}

#[test]
fn copy_out_rejects_traversal_and_disarms_reserved_names_and_collisions() {
    let tmp = TempDir::new().unwrap();
    let dest = tmp.path().join("out");
    let mock = MockWpdSource::new().with_device(WpdDeviceInfo {
        id: "d1".to_string(),
        friendly_name: "Pixel".to_string(),
        ..Default::default()
    });

    let payloads = [
        ("../../Windows/System32/evil.dll", "evil.dll"),
        ("..\\evil.exe", "evil.exe"),
        ("C:\\evil.txt", "evil.txt"),
        ("\\\\srv\\share\\x", "x"),
        ("/a\0b.txt", "a\0b.txt"),
        ("/\u{202E}gpj.exe", "\u{202E}gpj.exe"),
        ("/file.txt:Zone.Identifier", "file.txt:Zone.Identifier"),
        (".", "."),
        ("..", ".."),
        ("", ""),
    ];
    for (idx, (fp, fname)) in payloads.iter().enumerate() {
        let oid = format!("bad-{idx}");
        let mut entry = make_mock_entry("d1", "Pixel", "Internal", &oid, fp, 4, "text/plain");
        entry.filename = (*fname).to_string();
        mock.add_entry(entry.clone(), b"bad!".to_vec());
        let err = copy_out(&mock, &[entry], &dest, &CopyOutOptions::default()).unwrap_err();
        assert!(
            matches!(err, WpdError::PathTraversal(_)),
            "expected PathTraversal for '{fp}' / '{fname}', got {err:?}"
        );
    }

    // Reserved Windows names + flat collision handling
    let e_con = make_mock_entry(
        "d1",
        "Pixel",
        "Internal",
        "ok-con",
        "/Download/CON.txt",
        3,
        "text/plain",
    );
    let e_dup1 = make_mock_entry("d1", "Pixel", "Internal", "ok-dup1", "/DCIM/photo.jpg", 3, "image/jpeg");
    let e_dup2 = make_mock_entry(
        "d1",
        "Pixel",
        "SD Card",
        "ok-dup2",
        "/Download/photo.jpg",
        4,
        "image/jpeg",
    );
    mock.add_entry(e_con.clone(), b"con".to_vec());
    mock.add_entry(e_dup1.clone(), b"jpg".to_vec());
    mock.add_entry(e_dup2.clone(), b"jpg2".to_vec());

    let flat_opts = CopyOutOptions {
        preserve_tree: false,
        overwrite: false,
        max_copy_bytes: None,
    };
    let copied = copy_out(&mock, &[e_con, e_dup1, e_dup2], &dest, &flat_opts).unwrap();
    assert_eq!(copied.len(), 3);
    assert!(dest.join("_CON.txt").is_file());
    assert!(dest.join("photo.jpg").is_file());
    assert!(dest.join("photo (1).jpg").is_file());
    assert_eq!(fs::read(dest.join("photo.jpg")).unwrap(), b"jpg");
    assert_eq!(fs::read(dest.join("photo (1).jpg")).unwrap(), b"jpg2");
}

#[test]
fn table_provider_and_guap_export_with_csv_neutralization_and_merkle() {
    let tmp = TempDir::new().unwrap();
    let mut e1 = make_mock_entry(
        "d1",
        "Pixel 9",
        "Internal",
        "1",
        "/DCIM/formula.jpg",
        2048,
        "image/jpeg",
    );
    e1.filename = "=CMD|'/C calc'!A0.jpg".to_string();
    let e2 = make_mock_entry(
        "d1",
        "Pixel 9",
        "Internal",
        "2",
        "/Download/<script>alert(1)</script>.txt",
        512,
        "text/plain",
    );
    let entries = vec![e1, e2];

    let provider = MobileFileSearchProvider::new(&entries);
    assert_eq!(provider.schema().columns.len(), 10);

    let sorted = provider
        .query(&TableQuery {
            filter: Some(FilterExpr::Compare {
                column: "size_bytes".to_string(),
                op: CompareOp::Gt,
                value: CellValue::Bytes(100),
            }),
            sort: vec![(6, SortDirection::Desc)],
            columns: None,
            offset: 0,
            limit: Some(1),
        })
        .unwrap();
    assert_eq!(sorted.total_rows, 2);
    assert_eq!(sorted.rows.len(), 1);
    assert_eq!(sorted.rows[0].cells[2].to_string(), "1");

    let csv_path = tmp.path().join("wpd.csv");
    let manifest = write_wpd_entries_export(&entries, &csv_path, ExportFormat::Csv, &ExportOptions::default()).unwrap();
    assert_eq!(manifest.merkle_root_sha256.len(), 64);
    assert_eq!(manifest.merkle_root_sha512.len(), 128);
    let csv_text = fs::read_to_string(&csv_path).unwrap();
    assert!(csv_text.contains("'=CMD|'/C calc'!A0.jpg"));

    let html_path = tmp.path().join("wpd.html");
    write_wpd_entries_export(&entries, &html_path, ExportFormat::Html, &ExportOptions::default()).unwrap();
    let html_text = fs::read_to_string(&html_path).unwrap();
    assert!(!html_text.contains("<script>alert(1)</script>"));
    assert!(html_text.contains("&lt;script&gt;"));
}

#[test]
fn regex_escapes_windows_globs_and_path_prefix_segment_boundaries() {
    let mock = MockWpdSource::new().with_device(WpdDeviceInfo {
        id: "d1".to_string(),
        friendly_name: "GalaxyS24".to_string(),
        ..Default::default()
    });
    let img = make_mock_entry(
        "d1",
        "GalaxyS24",
        "SDCard",
        "o-img",
        "/DCIM/Camera/IMG_0042.jpg",
        4096,
        "image/jpeg",
    );
    let backup_img = make_mock_entry(
        "d1",
        "GalaxyS24",
        "SDCard",
        "o-backup",
        "/DCIM_backup/a.jpg",
        2048,
        "image/jpeg",
    );
    let readme = make_mock_entry(
        "d1",
        "GalaxyS24",
        "SDCard",
        "o-readme",
        "/GalaxyS24/SDCard/Documents/readme.txt",
        512,
        "text/plain",
    );
    let formula = make_mock_entry(
        "d1",
        "GalaxyS24",
        "SDCard",
        "o-formula",
        "/Documents/=cmd_formula.txt",
        256,
        "text/plain",
    );

    mock.add_entry(img.clone(), b"img".to_vec());
    mock.add_entry(backup_img.clone(), b"bak".to_vec());
    mock.add_entry(readme.clone(), b"txt".to_vec());
    mock.add_entry(formula.clone(), b"cmd".to_vec());

    // 1. Anchored regex with backslash escapes matches filename, not full_path
    let q_regex = MobileFileQuery {
        pattern: Some(r"^IMG_\d{4}\.jpg$".to_string()),
        use_regex: true,
        ..Default::default()
    };
    let hits = search_devices(&mock, &q_regex).unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].object_id, "o-img");

    // Formula regex with backslash escapes matches filename
    let q_formula_regex = MobileFileQuery {
        pattern: Some(r"^(=|\+|-|@).*\.txt$".to_string()),
        use_regex: true,
        ..Default::default()
    };
    let formula_hits = search_devices(&mock, &q_formula_regex).unwrap();
    assert_eq!(formula_hits.len(), 1);
    assert_eq!(formula_hits[0].object_id, "o-formula");

    // 2. Unanchored \d+ regex must NOT false-match digits in parent path segments (/GalaxyS24/...)
    let q_digits = MobileFileQuery {
        pattern: Some(r"\d+".to_string()),
        use_regex: true,
        ..Default::default()
    };
    let digit_hits = search_devices(&mock, &q_digits).unwrap();
    assert_eq!(digit_hits.len(), 1);
    assert_eq!(digit_hits[0].object_id, "o-img");
    assert!(!q_digits.matches(&readme).unwrap());

    // 3. Windows backslash path glob `DCIM\*.jpg` and forward-slash `DCIM/*.jpg` both match `/DCIM/Camera/IMG_0042.jpg`
    let q_win_glob = MobileFileQuery {
        pattern: Some(r"DCIM\*.jpg".to_string()),
        use_regex: false,
        ..Default::default()
    };
    let win_hits = search_devices(&mock, &q_win_glob).unwrap();
    assert_eq!(win_hits.len(), 1);
    assert_eq!(win_hits[0].object_id, "o-img");

    let q_unix_glob = MobileFileQuery {
        pattern: Some("DCIM/*.jpg".to_string()),
        use_regex: false,
        ..Default::default()
    };
    let unix_hits = search_devices(&mock, &q_unix_glob).unwrap();
    assert_eq!(unix_hits.len(), 1);
    assert_eq!(unix_hits[0].object_id, "o-img");

    // 4. path_prefix = "/DCIM" enforces segment boundary and excludes "/DCIM_backup/a.jpg"
    let q_prefix = MobileFileQuery {
        path_prefix: Some("/DCIM".to_string()),
        ..Default::default()
    };
    let prefix_hits = search_devices(&mock, &q_prefix).unwrap();
    assert_eq!(prefix_hits.len(), 1);
    assert_eq!(prefix_hits[0].object_id, "o-img");
    assert!(!q_prefix.matches(&backup_img).unwrap());

    // Exact folder entry `/DCIM` still matches when include_folders = true
    let mut dcim_folder = make_mock_entry("d1", "GalaxyS24", "SDCard", "o-dir", "/DCIM", 0, "inode/directory");
    dcim_folder.is_folder = true;
    let q_prefix_folder = MobileFileQuery {
        path_prefix: Some("/DCIM".to_string()),
        include_folders: true,
        ..Default::default()
    };
    assert!(q_prefix_folder.matches(&dcim_folder).unwrap());
}
