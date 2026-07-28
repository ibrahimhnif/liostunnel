use std::path::PathBuf;

fn tmp(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("lios-cli-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn load_accepts_a_portable_profile_and_moves_its_secrets_to_disk() {
    let dir = tmp("portable");
    let path = dir.join("p.liostunnel.json");
    std::fs::write(
        &path,
        r#"{"id":"00000000-0000-0000-0000-000000000000","name":"lab",
            "protocol":"ssh","host":"198.51.100.7","port":22,
            "auth":{"type":"password","password":"hunter2"},
            "dns":["1.1.1.1"],"split_tunnel":{"type":"all_traffic"},
            "kill_switch":false}"#,
    )
    .unwrap();

    let p = liostunnel_cli::profile_io::load(&path, &dir.join("secrets")).unwrap();
    assert_eq!(p.name, "lab");

    // The in-memory profile must not carry the password inline.
    let json = serde_json::to_string(&p).unwrap();
    assert!(!json.contains("hunter2"), "secret leaked: {json}");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn load_accepts_a_ref_bearing_server_profile_unchanged() {
    let dir = tmp("refform");
    let path = dir.join("p.json");
    std::fs::write(
        &path,
        r#"{"id":"00000000-0000-0000-0000-000000000000","name":"lab",
            "protocol":"ssh","host":"198.51.100.7","port":22,
            "auth":{"type":"password","password":{"source":"env","var":"PW"}},
            "dns":["1.1.1.1"],"split_tunnel":{"type":"all_traffic"},
            "kill_switch":false}"#,
    )
    .unwrap();

    let p = liostunnel_cli::profile_io::load(&path, &dir.join("secrets")).unwrap();
    assert_eq!(p.host, "198.51.100.7");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn load_reports_a_useful_error_for_malformed_json() {
    let dir = tmp("bad");
    let path = dir.join("p.json");
    std::fs::write(&path, "{ not json").unwrap();
    let e = liostunnel_cli::profile_io::load(&path, &dir.join("secrets")).unwrap_err();
    assert!(
        e.to_string().contains("p.json"),
        "error should name the file: {e}"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn load_never_echoes_a_misplaced_secret_looking_value_in_its_error() {
    // `port` expects a u16 in both `ServerProfile` and `PortableProfile`, so a
    // string value there fails both parse attempts. serde_json's own
    // `invalid_type` message echoes the offending value verbatim when it's a
    // scalar (unlike a map/object) -- a user who fat-fingers a secret string
    // into the wrong field must not have it echoed back to their terminal in
    // the resulting error.
    let dir = tmp("misplaced-secret");
    let path = dir.join("p.json");
    std::fs::write(
        &path,
        r#"{"id":"00000000-0000-0000-0000-000000000000","name":"lab",
            "protocol":"ssh","host":"198.51.100.7","port":"hunter2",
            "auth":{"type":"password","password":"unrelated"},
            "dns":["1.1.1.1"],"split_tunnel":{"type":"all_traffic"},
            "kill_switch":false}"#,
    )
    .unwrap();

    let e = liostunnel_cli::profile_io::load(&path, &dir.join("secrets")).unwrap_err();
    assert!(
        !e.to_string().contains("hunter2"),
        "secret-looking value leaked into error text: {e}"
    );
    std::fs::remove_dir_all(&dir).ok();
}
