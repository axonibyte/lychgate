use super::*;

#[test]
fn an_inventory_with_no_hosts_parses_to_an_empty_host_list() {
    let inv = Inventory::parse("").unwrap();
    assert_eq!(inv.hosts, Vec::new());
}

#[test]
fn a_single_host_with_its_fields_parses_intact() {
    let inv = Inventory::parse(
        r#"
        [[hosts]]
        name = "db-01"
        address = "10.0.4.11"
        os = "freebsd"
        channels = ["vnc"]

        [hosts.vnc]
        agent_user = "lychgate"
        rfb_port = 5900
        local_port = 5959
        target = "vm-01"
        set_password_cmd = "cbsd bhyve-vnc jname={target} vncpasswordfile={password_file} apply=1"
        clear_password_cmd = "cbsd bhyve-vnc jname={target} vncpassword=none apply=1"
        "#,
    )
    .unwrap();
    assert_eq!(
        inv.hosts,
        vec![Host {
            name: "db-01".into(),
            address: "10.0.4.11".into(),
            os: Os::Freebsd,
            channels: vec![Channel::Vnc],
            ssh: None,
            bmc: None,
            // Defaults fill what the config omits.
            vnc: Some(VncConfig {
                agent_user: "lychgate".into(),
                port: 22,
                identity_file: None,
                become_cmd: None,
                rfb_host: "127.0.0.1".into(),
                rfb_port: 5900,
                local_port: 5959,
                target: "vm-01".into(),
                set_password_cmd:
                    "cbsd bhyve-vnc jname={target} vncpasswordfile={password_file} apply=1".into(),
                clear_password_cmd: "cbsd bhyve-vnc jname={target} vncpassword=none apply=1".into(),
                password_len: 8,
                password_file: None,
            }),
            http: None,
            mqtt: None,
            serial: None,
            device: None,
            access: None,
            drill: false,
        }]
    );
}

#[test]
fn multiple_hosts_parse_in_declaration_order() {
    let inv = Inventory::parse(
        r#"
        [[hosts]]
        name = "web-02"
        address = "10.0.4.12"
        os = "linux"
        channels = ["vnc"]

        [hosts.vnc]
        agent_user = "lychgate"
        rfb_port = 5900
        local_port = 5959
        target = "web"
        set_password_cmd = "set {target} {password_file}"
        clear_password_cmd = "clear {target}"

        [[hosts]]
        name = "db-01"
        address = "10.0.4.11"
        os = "freebsd"
        channels = ["vnc"]

        [hosts.vnc]
        agent_user = "lychgate"
        rfb_port = 5900
        local_port = 5960
        target = "db"
        set_password_cmd = "set {target} {password_file}"
        clear_password_cmd = "clear {target}"
        "#,
    )
    .unwrap();
    let names: Vec<&str> = inv.hosts.iter().map(|h| h.name.as_str()).collect();
    assert_eq!(names, ["web-02", "db-01"]);
}

fn host_with(name: &str, address: &str, channels: &str) -> String {
    format!(
        r#"
        [[hosts]]
        name = "{name}"
        address = "{address}"
        os = "linux"
        channels = {channels}
        "#
    )
}

// A fully-valid vnc host: since every channel now requires config, tests that
// need a host to pass coupling (so a *later* check can fire) use this.
fn host_with_vnc(name: &str, address: &str, local_port: u16) -> String {
    format!(
        r#"
        [[hosts]]
        name = "{name}"
        address = "{address}"
        os = "linux"
        channels = ["vnc"]

        [hosts.vnc]
        agent_user = "lychgate"
        rfb_port = 5900
        local_port = {local_port}
        target = "guest"
        set_password_cmd = "set {{target}} {{password_file}}"
        clear_password_cmd = "clear {{target}}"
        "#
    )
}

#[test]
fn two_hosts_with_the_same_name_are_rejected() {
    // The first host validates fully; the duplicate name on the second is
    // caught before its own coupling runs.
    let toml =
        host_with_vnc("db-01", "10.0.4.11", 5959) + &host_with_vnc("db-01", "10.0.4.12", 5960);
    assert_eq!(
        Inventory::parse(&toml),
        Err(InventoryError::DuplicateHostName("db-01".into()))
    );
}

#[test]
fn a_host_with_an_empty_name_is_rejected() {
    let toml = host_with("", "10.0.4.11", r#"["vnc"]"#);
    assert_eq!(Inventory::parse(&toml), Err(InventoryError::EmptyHostName));
}

#[test]
fn a_host_with_an_empty_address_is_rejected() {
    let toml = host_with("db-01", "", r#"["vnc"]"#);
    assert_eq!(
        Inventory::parse(&toml),
        Err(InventoryError::EmptyAddress {
            host: "db-01".into()
        })
    );
}

#[test]
fn a_host_with_no_channels_is_rejected() {
    let toml = host_with("db-01", "10.0.4.11", "[]");
    assert_eq!(
        Inventory::parse(&toml),
        Err(InventoryError::NoChannels {
            host: "db-01".into()
        })
    );
}

#[test]
fn a_host_listing_the_same_channel_twice_is_rejected() {
    let toml = host_with("db-01", "10.0.4.11", r#"["vnc", "vnc"]"#);
    assert_eq!(
        Inventory::parse(&toml),
        Err(InventoryError::DuplicateChannel {
            host: "db-01".into()
        })
    );
}

#[test]
fn an_unknown_channel_name_is_rejected() {
    let toml = host_with("db-01", "10.0.4.11", r#"["telepathy"]"#);
    assert!(matches!(
        Inventory::parse(&toml),
        Err(InventoryError::Toml(_))
    ));
}

#[test]
fn an_unknown_operating_system_is_rejected() {
    let toml = r#"
        [[hosts]]
        name = "db-01"
        address = "10.0.4.11"
        os = "plan9"
        channels = ["vnc"]
    "#;
    assert!(matches!(
        Inventory::parse(toml),
        Err(InventoryError::Toml(_))
    ));
}

#[test]
fn an_unrecognized_field_is_rejected_rather_than_ignored() {
    // A typo like "chanels" must fail at load, not silently strip a host of
    // its channels.
    let toml = r#"
        [[hosts]]
        name = "db-01"
        address = "10.0.4.11"
        os = "linux"
        channels = ["vnc"]
        favourite_colour = "red"
    "#;
    assert!(matches!(
        Inventory::parse(toml),
        Err(InventoryError::Toml(_))
    ));
}

// --- [hosts.ssh] coupling (M4) ---------------------------------------------

const SSH_HOST: &str = r#"
[[hosts]]
name = "db-01"
address = "10.0.4.11"
os = "freebsd"
channels = ["ssh", "authorized-keys"]

[hosts.ssh]
agent_user = "lychgate"
port = 2222
root_posture_default = "no"
root_posture_emergency = "prohibit-password"
authorized_keys_path = "/root/.ssh/authorized_keys"
emergency_keys = ["ssh-ed25519 EMERG claude-breakglass"]
become_cmd = "doas"
"#;

#[test]
fn a_full_ssh_config_parses_with_its_fields_intact() {
    let inv = Inventory::parse(SSH_HOST).unwrap();
    let ssh = inv.hosts[0].ssh.as_ref().unwrap();
    assert_eq!(ssh.agent_user, "lychgate");
    assert_eq!(ssh.port, 2222);
    assert_eq!(ssh.root_posture_default, crate::ssh::Posture::No);
    assert_eq!(
        ssh.root_posture_emergency,
        crate::ssh::Posture::ProhibitPassword
    );
    assert_eq!(ssh.emergency_keys, ["ssh-ed25519 EMERG claude-breakglass"]);
    assert_eq!(ssh.become_cmd.as_deref(), Some("doas"));
    // Defaults fill what the config omits.
    assert_eq!(ssh.identity_file, None);
    assert_eq!(ssh.reload_cmd, None);
}

#[test]
fn an_ssh_channel_without_ssh_config_is_refused() {
    let toml = r#"
        [[hosts]]
        name = "db-01"
        address = "10.0.4.11"
        os = "freebsd"
        channels = ["ssh"]
    "#;
    assert_eq!(
        Inventory::parse(toml),
        Err(InventoryError::SshConfigMissing {
            host: "db-01".into()
        })
    );
}

#[test]
fn ssh_config_on_a_host_without_ssh_channels_is_refused_as_dead_config() {
    let toml = r#"
        [[hosts]]
        name = "db-01"
        address = "10.0.4.11"
        os = "freebsd"
        channels = ["vnc"]

        [hosts.ssh]
        agent_user = "lychgate"
        root_posture_default = "no"
        root_posture_emergency = "yes"
    "#;
    assert_eq!(
        Inventory::parse(toml),
        Err(InventoryError::SshConfigUnused {
            host: "db-01".into()
        })
    );
}

#[test]
fn the_authorized_keys_channel_without_emergency_keys_is_refused() {
    let toml = r#"
        [[hosts]]
        name = "db-01"
        address = "10.0.4.11"
        os = "freebsd"
        channels = ["authorized-keys"]

        [hosts.ssh]
        agent_user = "lychgate"
        root_posture_default = "no"
        root_posture_emergency = "yes"
    "#;
    assert_eq!(
        Inventory::parse(toml),
        Err(InventoryError::NoEmergencyKeys {
            host: "db-01".into()
        })
    );
}

#[test]
fn a_bad_emergency_key_is_refused_at_load_not_at_three_am() {
    let toml = r#"
        [[hosts]]
        name = "db-01"
        address = "10.0.4.11"
        os = "freebsd"
        channels = ["authorized-keys"]

        [hosts.ssh]
        agent_user = "lychgate"
        root_posture_default = "no"
        root_posture_emergency = "yes"
        emergency_keys = ["contains LYCHGATE text"]
    "#;
    match Inventory::parse(toml) {
        Err(InventoryError::BadEmergencyKey { host, message }) => {
            assert_eq!(host, "db-01");
            assert!(message.contains("marker"), "{message}");
        }
        other => panic!("wanted BadEmergencyKey, got {other:?}"),
    }
}

#[test]
fn an_unknown_posture_is_refused() {
    let toml = r#"
        [[hosts]]
        name = "db-01"
        address = "10.0.4.11"
        os = "freebsd"
        channels = ["ssh"]

        [hosts.ssh]
        agent_user = "lychgate"
        root_posture_default = "maybe"
        root_posture_emergency = "yes"
    "#;
    assert!(matches!(
        Inventory::parse(toml),
        Err(InventoryError::Toml(_))
    ));
}

#[test]
fn an_ssh_channel_whose_emergency_posture_equals_the_default_is_refused() {
    let toml = r#"
        [[hosts]]
        name = "db-01"
        address = "10.0.4.11"
        os = "freebsd"
        channels = ["ssh"]

        [hosts.ssh]
        agent_user = "lychgate"
        root_posture_default = "no"
        root_posture_emergency = "no"
    "#;
    assert_eq!(
        Inventory::parse(toml),
        Err(InventoryError::PostureUnchanged {
            host: "db-01".into()
        })
    );
}

// --- [hosts.bmc] coupling (M6) ---------------------------------------------

const BMC_HOST: &str = r#"
[[hosts]]
name = "idrac-01"
address = "10.0.9.5"
os = "linux"
channels = ["bmc"]

[hosts.bmc]
endpoint = "https://10.0.9.5"
method = "redfish"
account_user = "breakglass"
account_id = "4"
auth_user = "admin"
auth_password_file = "/etc/lychgate/bmc.pw"
tls = { mode = "ca-file", path = "/etc/ssl/idrac-ca.pem" }
"#;

#[test]
fn a_full_bmc_config_parses_with_its_fields_intact() {
    let inv = Inventory::parse(BMC_HOST).unwrap();
    let bmc = inv.hosts[0].bmc.as_ref().unwrap();
    assert_eq!(bmc.endpoint, "https://10.0.9.5");
    assert_eq!(bmc.method, crate::inventory::BmcMethod::Redfish);
    assert_eq!(bmc.account_user, "breakglass");
    assert_eq!(bmc.account_id, "4");
    assert_eq!(
        bmc.tls,
        crate::inventory::BmcTls::CaFile {
            path: "/etc/ssl/idrac-ca.pem".into()
        }
    );
}

#[test]
fn a_bmc_channel_without_bmc_config_is_refused() {
    let toml = r#"
        [[hosts]]
        name = "idrac-01"
        address = "10.0.9.5"
        os = "linux"
        channels = ["bmc"]
    "#;
    assert_eq!(
        Inventory::parse(toml),
        Err(InventoryError::BmcConfigMissing {
            host: "idrac-01".into()
        })
    );
}

#[test]
fn bmc_config_on_a_host_without_a_bmc_channel_is_refused_as_dead_config() {
    let toml = r#"
        [[hosts]]
        name = "idrac-01"
        address = "10.0.9.5"
        os = "linux"
        channels = ["vnc"]

        [hosts.bmc]
        endpoint = "https://10.0.9.5"
        method = "redfish"
        account_user = "breakglass"
        account_id = "4"
        auth_user = "admin"
        auth_password_file = "/etc/lychgate/bmc.pw"
        tls = { mode = "insecure" }
    "#;
    assert_eq!(
        Inventory::parse(toml),
        Err(InventoryError::BmcConfigUnused {
            host: "idrac-01".into()
        })
    );
}

#[test]
fn racadm_and_ipmitool_methods_parse_but_are_refused_as_unimplemented() {
    for method in ["racadm", "ipmitool"] {
        let toml = format!(
            r#"
            [[hosts]]
            name = "idrac-01"
            address = "10.0.9.5"
            os = "linux"
            channels = ["bmc"]

            [hosts.bmc]
            endpoint = "https://10.0.9.5"
            method = "{method}"
            account_user = "breakglass"
            account_id = "4"
            auth_user = "admin"
            auth_password_file = "/etc/lychgate/bmc.pw"
            tls = {{ mode = "insecure" }}
            "#
        );
        match Inventory::parse(&toml) {
            Err(InventoryError::BmcMethodUnimplemented { host, method: m }) => {
                assert_eq!(host, "idrac-01");
                assert_eq!(m, method);
            }
            other => panic!("wanted BmcMethodUnimplemented for {method}, got {other:?}"),
        }
    }
}

#[test]
fn insecure_tls_must_be_spelled_out_and_ca_file_needs_its_path() {
    // A bmc config with no tls key at all is refused: TLS trust is never
    // defaulted for a break-glass control channel.
    let toml = r#"
        [[hosts]]
        name = "idrac-01"
        address = "10.0.9.5"
        os = "linux"
        channels = ["bmc"]

        [hosts.bmc]
        endpoint = "https://10.0.9.5"
        method = "redfish"
        account_user = "breakglass"
        account_id = "4"
        auth_user = "admin"
        auth_password_file = "/etc/lychgate/bmc.pw"
    "#;
    assert!(matches!(
        Inventory::parse(toml),
        Err(InventoryError::Toml(_))
    ));
}

// --- [hosts.vnc] coupling (M7) ---------------------------------------------

const VNC_HOST: &str = r#"
[[hosts]]
name = "hv-01"
address = "10.0.5.20"
os = "freebsd"
channels = ["vnc"]

[hosts.vnc]
agent_user = "lychgate"
port = 2222
identity_file = "/etc/lychgate/id_vnc"
become_cmd = "doas"
rfb_host = "127.0.0.1"
rfb_port = 5900
local_port = 5959
target = "guest-01"
set_password_cmd = "cbsd bhyve-vnc jname={target} vncpasswordfile={password_file} apply=1"
clear_password_cmd = "cbsd bhyve-vnc jname={target} vncpassword=none apply=1"
password_len = 12
"#;

// A vnc host with customizable command templates and ports, for the coupling
// refusals. The `set`/`clear` values are inserted verbatim into the TOML, so
// their `{target}`/`{password_file}` placeholders pass through unescaped.
fn vnc_host_with(
    set: &str,
    clear: &str,
    rfb_port: u16,
    local_port: u16,
    password_len: u32,
) -> String {
    format!(
        r#"
        [[hosts]]
        name = "hv-01"
        address = "10.0.5.20"
        os = "freebsd"
        channels = ["vnc"]

        [hosts.vnc]
        agent_user = "lychgate"
        rfb_port = {rfb_port}
        local_port = {local_port}
        target = "guest-01"
        set_password_cmd = "{set}"
        clear_password_cmd = "{clear}"
        password_len = {password_len}
        "#
    )
}

fn vnc_host_named(name: &str, local_port: u16) -> String {
    format!(
        r#"
        [[hosts]]
        name = "{name}"
        address = "10.0.5.20"
        os = "freebsd"
        channels = ["vnc"]

        [hosts.vnc]
        agent_user = "lychgate"
        rfb_port = 5900
        local_port = {local_port}
        target = "guest"
        set_password_cmd = "set {{target}} {{password_file}}"
        clear_password_cmd = "clear {{target}}"
        "#
    )
}

#[test]
fn a_full_vnc_config_parses_with_its_fields_intact() {
    let inv = Inventory::parse(VNC_HOST).unwrap();
    let vnc = inv.hosts[0].vnc.as_ref().unwrap();
    assert_eq!(vnc.agent_user, "lychgate");
    assert_eq!(vnc.port, 2222);
    assert_eq!(vnc.identity_file.as_deref(), Some("/etc/lychgate/id_vnc"));
    assert_eq!(vnc.become_cmd.as_deref(), Some("doas"));
    assert_eq!(vnc.rfb_host, "127.0.0.1");
    assert_eq!(vnc.rfb_port, 5900);
    assert_eq!(vnc.local_port, 5959);
    assert_eq!(vnc.target, "guest-01");
    assert_eq!(vnc.password_len, 12);
    assert_eq!(vnc.password_file, None);
}

#[test]
fn a_vnc_channel_without_vnc_config_is_refused() {
    let toml = r#"
        [[hosts]]
        name = "hv-01"
        address = "10.0.5.20"
        os = "freebsd"
        channels = ["vnc"]
    "#;
    assert_eq!(
        Inventory::parse(toml),
        Err(InventoryError::VncConfigMissing {
            host: "hv-01".into()
        })
    );
}

#[test]
fn vnc_config_on_a_host_without_a_vnc_channel_is_refused_as_dead_config() {
    let toml = r#"
        [[hosts]]
        name = "hv-01"
        address = "10.0.5.20"
        os = "freebsd"
        channels = ["ssh"]

        [hosts.ssh]
        agent_user = "lychgate"
        root_posture_default = "no"
        root_posture_emergency = "yes"

        [hosts.vnc]
        agent_user = "lychgate"
        rfb_port = 5900
        local_port = 5959
        target = "guest"
        set_password_cmd = "set {target} {password_file}"
        clear_password_cmd = "clear {target}"
    "#;
    assert_eq!(
        Inventory::parse(toml),
        Err(InventoryError::VncConfigUnused {
            host: "hv-01".into()
        })
    );
}

#[test]
fn a_set_password_cmd_without_the_password_file_placeholder_is_refused() {
    let toml = vnc_host_with(
        "cbsd jname={target} apply=1",
        "clear {target}",
        5900,
        5959,
        8,
    );
    assert_eq!(
        Inventory::parse(&toml),
        Err(InventoryError::VncMissingPasswordFile {
            host: "hv-01".into()
        })
    );
}

#[test]
fn a_clear_password_cmd_referencing_the_password_file_is_refused() {
    let toml = vnc_host_with(
        "set {target} {password_file}",
        "wipe {target} {password_file}",
        5900,
        5959,
        8,
    );
    assert_eq!(
        Inventory::parse(&toml),
        Err(InventoryError::VncClearHasPasswordFile {
            host: "hv-01".into()
        })
    );
}

#[test]
fn a_quoted_set_command_template_is_refused_at_load() {
    let toml = vnc_host_with(
        "set {target} '{password_file}'",
        "clear {target}",
        5900,
        5959,
        8,
    );
    assert_eq!(
        Inventory::parse(&toml),
        Err(InventoryError::VncCommandQuoted {
            host: "hv-01".into(),
            which: "set_password_cmd"
        })
    );
}

#[test]
fn an_unknown_placeholder_in_a_set_command_is_refused_naming_it() {
    let toml = vnc_host_with(
        "set {targett} {password_file}",
        "clear {target}",
        5900,
        5959,
        8,
    );
    match Inventory::parse(&toml) {
        Err(InventoryError::VncUnknownPlaceholder {
            host,
            which,
            placeholder,
        }) => {
            assert_eq!(host, "hv-01");
            assert_eq!(which, "set_password_cmd");
            assert_eq!(placeholder, "targett");
        }
        other => panic!("wanted VncUnknownPlaceholder, got {other:?}"),
    }
}

#[test]
fn a_zero_rfb_port_is_refused() {
    let toml = vnc_host_with("set {target} {password_file}", "clear {target}", 0, 5959, 8);
    assert_eq!(
        Inventory::parse(&toml),
        Err(InventoryError::VncBadPort {
            host: "hv-01".into(),
            field: "rfb_port"
        })
    );
}

#[test]
fn a_zero_local_port_is_refused() {
    let toml = vnc_host_with("set {target} {password_file}", "clear {target}", 5900, 0, 8);
    assert_eq!(
        Inventory::parse(&toml),
        Err(InventoryError::VncBadPort {
            host: "hv-01".into(),
            field: "local_port"
        })
    );
}

#[test]
fn a_zero_password_length_is_refused() {
    let toml = vnc_host_with(
        "set {target} {password_file}",
        "clear {target}",
        5900,
        5959,
        0,
    );
    assert_eq!(
        Inventory::parse(&toml),
        Err(InventoryError::VncBadPasswordLen {
            host: "hv-01".into()
        })
    );
}

#[test]
fn two_vnc_hosts_sharing_a_local_port_are_refused() {
    let toml = vnc_host_named("hv-01", 5959) + &vnc_host_named("hv-02", 5959);
    assert_eq!(
        Inventory::parse(&toml),
        Err(InventoryError::VncLocalPortConflict {
            host: "hv-02".into(),
            other: "hv-01".into(),
            port: 5959,
        })
    );
}

#[test]
fn an_unrecognized_vnc_field_is_rejected_rather_than_ignored() {
    let toml = r#"
        [[hosts]]
        name = "hv-01"
        address = "10.0.5.20"
        os = "freebsd"
        channels = ["vnc"]

        [hosts.vnc]
        agent_user = "lychgate"
        rfb_port = 5900
        local_port = 5959
        target = "guest"
        set_password_cmd = "set {target} {password_file}"
        clear_password_cmd = "clear {target}"
        favourite_colour = "red"
    "#;
    assert!(matches!(
        Inventory::parse(toml),
        Err(InventoryError::Toml(_))
    ));
}

// --- [approval] config (M8) ------------------------------------------------

const APPROVER_KEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIOBaP66AKPs9nRYDzUrJjGJMYxn0rIWv/tNftYWIu25 alice";

// The deployment-wide [approval] policy: one ed25519 authenticator and a
// threshold-1 profile that trusts it. Engine-level validation (cycles, dangling
// refs, unsatisfiable thresholds, unimplemented kinds) is proven in
// authority/tests.rs; here we prove the inventory wires it up and validates each
// host's access against it.
fn approval_toml() -> String {
    format!(
        r#"
        [[approval.authenticator]]
        id = "alice"
        kind = "ed25519"
        public-key = "{APPROVER_KEY}"
        [[approval.profile]]
        id = "claude"
        threshold = 1
        factor = [ {{ authenticator = "alice", weight = 1 }} ]
        "#
    )
}

/// An ssh host with the given `[hosts.access]` block spliced in.
fn ssh_host(access: &str) -> String {
    format!(
        r#"
        [[hosts]]
        name = "db-01"
        address = "10.0.4.11"
        os = "linux"
        channels = ["ssh"]
        [hosts.ssh]
        agent_user = "lychgate"
        root_posture_default = "no"
        root_posture_emergency = "yes"
        {access}
        "#
    )
}

fn with_approval(access: &str) -> String {
    format!("{}\n{}", ssh_host(access), approval_toml())
}

#[test]
fn a_full_approval_policy_parses_and_builds_a_model() {
    let inv = Inventory::parse(&approval_toml()).unwrap();
    let model = inv
        .approval_model()
        .unwrap()
        .expect("a policy is configured");
    assert!(model.profile("claude").is_some());
}

#[test]
fn an_invalid_approval_policy_surfaces_as_an_inventory_error() {
    // A profile referencing a group that does not exist — the engine refuses it,
    // and the inventory surfaces that as InventoryError::Approval.
    let toml = r#"
        [[approval.profile]]
        id = "claude"
        threshold = 1
        factor = [ { group = "nope", weight = 1 } ]
    "#;
    assert!(matches!(
        Inventory::parse(toml),
        Err(InventoryError::Approval(_))
    ));
}

#[test]
fn host_access_without_an_approval_policy_is_refused() {
    let toml = ssh_host("[hosts.access]\n        profiles = [\"claude\"]");
    assert!(matches!(
        Inventory::parse(&toml),
        Err(InventoryError::AccessWithoutApproval { .. })
    ));
}

#[test]
fn host_access_permitting_no_profiles_is_refused() {
    let toml = with_approval("[hosts.access]\n        profiles = []");
    assert!(matches!(
        Inventory::parse(&toml),
        Err(InventoryError::AccessNoProfiles { .. })
    ));
}

#[test]
fn a_host_permitting_an_unknown_profile_is_refused() {
    let toml = with_approval("[hosts.access]\n        profiles = [\"ghost\"]");
    match Inventory::parse(&toml) {
        Err(InventoryError::UnknownProfile { profile, .. }) => assert_eq!(profile, "ghost"),
        other => panic!("wanted UnknownProfile, got {other:?}"),
    }
}

#[test]
fn an_override_for_an_unpermitted_profile_is_refused() {
    let access = "[hosts.access]\n        profiles = [\"claude\"]\n        \
                  [hosts.access.override.other]\n        threshold = 1\n        \
                  factor = [ { authenticator = \"alice\", weight = 1 } ]";
    match Inventory::parse(&with_approval(access)) {
        Err(InventoryError::OverrideForUnpermittedProfile { profile, .. }) => {
            assert_eq!(profile, "other")
        }
        other => panic!("wanted OverrideForUnpermittedProfile, got {other:?}"),
    }
}

#[test]
fn a_valid_host_override_parses() {
    let access = "[hosts.access]\n        profiles = [\"claude\"]\n        \
                  [hosts.access.override.claude]\n        threshold = 1\n        \
                  factor = [ { authenticator = \"alice\", weight = 1 } ]";
    Inventory::parse(&with_approval(access)).expect("a valid override should parse");
}

#[test]
fn an_unrecognized_approval_field_is_rejected() {
    let toml = format!(
        r#"
        [[approval.authenticator]]
        id = "alice"
        kind = "ed25519"
        public-key = "{APPROVER_KEY}"
        favourite_colour = "red"
        "#
    );
    assert!(matches!(
        Inventory::parse(&toml),
        Err(InventoryError::Toml(_))
    ));
}

#[test]
fn a_host_is_not_a_drill_canary_by_default() {
    let inv = Inventory::parse(&ssh_host("")).unwrap();
    assert!(
        !inv.hosts[0].drill,
        "drill must default false (only a canary is drillable)"
    );
}

#[test]
fn a_host_can_be_marked_a_drill_canary() {
    let text = r#"
        [[hosts]]
        name = "canary"
        address = "10.0.4.99"
        os = "linux"
        channels = ["ssh"]
        drill = true
        [hosts.ssh]
        agent_user = "lychgate"
        root_posture_default = "no"
        root_posture_emergency = "yes"
    "#;
    let inv = Inventory::parse(text).unwrap();
    assert!(inv.hosts[0].drill, "drill = true must parse as a canary");
}

// --- generic channels (http / mqtt / serial), E2 ---------------------------
//
// Mutation notes: delete any single validation arm in validate_generic (a
// Missing/Unused pair, the verify-"none" literal check, a placeholder check,
// the password-auth refusal, a zero-timeout or status check) or the embedded
// channel restriction, and its named test below fails.

fn http_host_full(verify_inline: &str, verify_table: &str) -> String {
    format!(
        r#"
        [[hosts]]
        name = "cam-1"
        address = "10.0.9.31"
        os = "embedded"
        channels = ["http"]
        [hosts.http]
        endpoint = "https://10.0.9.31:8443"
        tls = {{ mode = "insecure" }}
        {verify_inline}
        [hosts.http.open]
        method = "POST"
        path = "/api/maint"
        body = '{{"debug_uart": true}}'
        expect_status = 200
        [hosts.http.revert]
        method = "POST"
        path = "/api/maint"
        body = '{{"debug_uart": false}}'
        expect_status = 200
        {verify_table}
    "#
    )
}

fn http_host(verify_table: &str) -> String {
    http_host_full("", verify_table)
}

const HTTP_VERIFY: &str = r#"
        [hosts.http.verify]
        method = "GET"
        path = "/api/maint"
        expect_status = 200
        open_marker = '"debug_uart": true'
        closed_marker = '"debug_uart": false'
"#;

#[test]
fn a_full_http_host_parses_with_its_fields_intact() {
    let inv = Inventory::parse(&http_host(HTTP_VERIFY)).unwrap();
    let http = inv.hosts[0].http.as_ref().unwrap();
    assert_eq!(http.open.method, "POST");
    assert_eq!(http.open.expect_status, 200);
    match &http.verify {
        VerifyMode::Probe(v) => assert_eq!(v.open_marker, r#""debug_uart": true"#),
        other => panic!("expected a probe verify, got {other:?}"),
    }
}

#[test]
fn http_verify_none_parses_as_the_named_narrowing() {
    let inv = Inventory::parse(&http_host_full(r#"verify = "none""#, "")).unwrap();
    match &inv.hosts[0].http.as_ref().unwrap().verify {
        VerifyMode::None(s) => assert_eq!(s, "none"),
        other => panic!("expected the none narrowing, got {other:?}"),
    }
}

#[test]
fn http_verify_any_other_string_is_refused() {
    assert_eq!(
        Inventory::parse(&http_host_full(r#"verify = "nah""#, "")),
        Err(InventoryError::GenericVerifyNotNone {
            host: "cam-1".into(),
            channel: "http",
            got: "nah".into(),
        })
    );
}

#[test]
fn http_verify_absent_entirely_is_refused_at_parse() {
    // Silence about verification is not an option: the field is required, so
    // omitting it fails serde's missing-field check.
    assert!(matches!(
        Inventory::parse(&http_host("")),
        Err(InventoryError::Toml(_))
    ));
}

#[test]
fn an_http_channel_without_config_and_config_without_channel_are_refused() {
    let toml = r#"
        [[hosts]]
        name = "cam-1"
        address = "a"
        os = "embedded"
        channels = ["http"]
    "#;
    assert_eq!(
        Inventory::parse(toml),
        Err(InventoryError::GenericConfigMissing {
            host: "cam-1".into(),
            channel: "http",
        })
    );

    let toml = http_host(HTTP_VERIFY).replace(r#"channels = ["http"]"#, r#"channels = ["bmc"]"#);
    // (bmc then has no config either, but the http dead-config refusal is
    // deliberately checked in channel order after bmc — use a channel with
    // config instead.)
    let _ = toml;
    let toml = format!(
        "{}\n{}",
        http_host(HTTP_VERIFY).replace(r#"channels = ["http"]"#, r#"channels = ["serial"]"#),
        r#"
        [hosts.serial]
        device = "/dev/null"
        verify = "none"
        [hosts.serial.open]
        send = "on\n"
        expect = "OK"
        [hosts.serial.revert]
        send = "off\n"
        expect = "OK"
    "#
    );
    assert_eq!(
        Inventory::parse(&toml),
        Err(InventoryError::GenericConfigUnused {
            host: "cam-1".into(),
            channel: "http",
        })
    );
}

#[test]
fn a_placeholder_in_a_generic_template_is_refused() {
    let bad = http_host(HTTP_VERIFY).replace(
        r#"body = '{"debug_uart": true}'"#,
        r#"body = 'enable {token} now'"#,
    );
    match Inventory::parse(&bad) {
        Err(InventoryError::GenericPlaceholder {
            host,
            channel,
            field,
            ..
        }) => {
            assert_eq!(host, "cam-1");
            assert_eq!(channel, "http");
            assert_eq!(field, "body");
        }
        other => panic!("expected a placeholder refusal, got {other:?}"),
    }
}

#[test]
fn a_json_http_body_is_not_a_placeholder() {
    // The whole point of the {name}-run definition: JSON bodies parse clean.
    Inventory::parse(&http_host(HTTP_VERIFY)).unwrap();
}

#[test]
fn an_http_expect_status_outside_the_http_range_is_refused() {
    let bad = http_host(HTTP_VERIFY).replacen("expect_status = 200", "expect_status = 42", 1);
    assert_eq!(
        Inventory::parse(&bad),
        Err(InventoryError::GenericBadStatus {
            host: "cam-1".into(),
            which: "open",
        })
    );
}

fn mqtt_host(auth: &str, verify: &str) -> String {
    format!(
        r#"
        [[hosts]]
        name = "iot-7"
        address = "10.0.9.20"
        os = "embedded"
        channels = ["mqtt"]
        [hosts.mqtt]
        broker = "10.0.9.20:1883"
        {auth}
        [hosts.mqtt.open]
        topic = "dev/7/cmd"
        payload = "maint-on"
        [hosts.mqtt.revert]
        topic = "dev/7/cmd"
        payload = "maint-off"
        {verify}
    "#
    )
}

const MQTT_VERIFY: &str = r#"
        [hosts.mqtt.verify]
        topic = "dev/7/state"
        open_marker = "maint-on"
        closed_marker = "maint-off"
"#;

#[test]
fn a_full_mqtt_host_parses_and_the_verify_timeout_defaults() {
    let inv = Inventory::parse(&mqtt_host("", MQTT_VERIFY)).unwrap();
    match &inv.hosts[0].mqtt.as_ref().unwrap().verify {
        VerifyMode::Probe(v) => assert_eq!(v.timeout_secs, 5),
        other => panic!("expected a probe verify, got {other:?}"),
    }
}

#[test]
fn mqtt_tls_client_cert_auth_parses() {
    let auth = r#"auth = { mode = "tls-client-cert", certfile = "c.pem", keyfile = "k.pem", cafile = "ca.pem" }"#;
    Inventory::parse(&mqtt_host(auth, MQTT_VERIFY)).unwrap();
}

#[test]
fn mqtt_password_auth_is_refused_with_the_argv_reason() {
    let auth = r#"auth = { mode = "password", username = "lychgate" }"#;
    let err = Inventory::parse(&mqtt_host(auth, MQTT_VERIFY)).unwrap_err();
    assert_eq!(
        err,
        InventoryError::MqttPasswordAuth {
            host: "iot-7".into()
        }
    );
    assert!(
        err.to_string().contains("argv"),
        "the refusal must name the argv leak: {err}"
    );
}

#[test]
fn a_zero_mqtt_verify_timeout_is_refused() {
    let verify = format!("{MQTT_VERIFY}        timeout_secs = 0\n");
    assert_eq!(
        Inventory::parse(&mqtt_host("", &verify)),
        Err(InventoryError::GenericZeroTimeout {
            host: "iot-7".into(),
            channel: "mqtt",
        })
    );
}

fn serial_host(extra: &str, verify: &str) -> String {
    format!(
        r#"
        [[hosts]]
        name = "bench-1"
        address = "n/a-serial"
        os = "embedded"
        channels = ["serial"]
        [hosts.serial]
        device = "/dev/cuaU0"
        {extra}
        [hosts.serial.open]
        send = "maint on\n"
        expect = "OK MAINT ON"
        [hosts.serial.revert]
        send = "maint off\n"
        expect = "OK MAINT OFF"
        {verify}
    "#
    )
}

const SERIAL_VERIFY: &str = r#"
        [hosts.serial.verify]
        send = "maint?\n"
        open_marker = "MAINT ON"
        closed_marker = "MAINT OFF"
"#;

#[test]
fn a_full_serial_host_parses_with_defaults() {
    let inv = Inventory::parse(&serial_host("", SERIAL_VERIFY)).unwrap();
    let serial = inv.hosts[0].serial.as_ref().unwrap();
    assert_eq!(serial.timeout_secs, 5);
    assert_eq!(serial.baud, None);
}

#[test]
fn a_zero_serial_timeout_is_refused() {
    assert_eq!(
        Inventory::parse(&serial_host("timeout_secs = 0", SERIAL_VERIFY)),
        Err(InventoryError::GenericZeroTimeout {
            host: "bench-1".into(),
            channel: "serial",
        })
    );
}

#[test]
fn a_serial_channel_without_config_is_refused() {
    let toml = r#"
        [[hosts]]
        name = "bench-1"
        address = "n/a"
        os = "embedded"
        channels = ["serial"]
    "#;
    assert_eq!(
        Inventory::parse(toml),
        Err(InventoryError::GenericConfigMissing {
            host: "bench-1".into(),
            channel: "serial",
        })
    );
}

#[test]
fn an_mqtt_channel_without_config_is_refused() {
    let toml = r#"
        [[hosts]]
        name = "iot-7"
        address = "b"
        os = "embedded"
        channels = ["mqtt"]
    "#;
    assert_eq!(
        Inventory::parse(toml),
        Err(InventoryError::GenericConfigMissing {
            host: "iot-7".into(),
            channel: "mqtt",
        })
    );
}

#[test]
fn an_embedded_host_may_not_declare_shell_borne_channels() {
    // This restriction is what guards the unreachable!() arms at the Os match
    // sites (core/src/ssh.rs): delete it and those arms become reachable —
    // this test failing first is the tripwire.
    for (channel, config) in [
        (
            "vnc",
            r#"
            [hosts.vnc]
            agent_user = "lychgate"
            rfb_port = 5900
            local_port = 5959
            target = "vm-01"
            set_password_cmd = "set {target} {password_file}"
            clear_password_cmd = "clear {target}"
        "#,
        ),
        (
            "ssh",
            r#"
            [hosts.ssh]
            agent_user = "root"
            root_posture_default = "prohibit-password"
            root_posture_emergency = "yes"
        "#,
        ),
        (
            "authorized-keys",
            r#"
            [hosts.ssh]
            agent_user = "root"
            root_posture_default = "prohibit-password"
            root_posture_emergency = "yes"
            emergency_keys = ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGb0Vf1XY6cQ4kQ9Ky6+0AaK1Or1v9d3q1Xh4Y5s6z7A x"]
        "#,
        ),
    ] {
        let toml = format!(
            r#"
            [[hosts]]
            name = "dev-1"
            address = "a"
            os = "embedded"
            channels = ["{channel}"]
            {config}
        "#
        );
        assert_eq!(
            Inventory::parse(&toml),
            Err(InventoryError::EmbeddedChannelUnsupported {
                host: "dev-1".into(),
                channel: channel.into(),
            }),
            "channel {channel} must be refused on an embedded host"
        );
    }
}

#[test]
fn an_embedded_host_with_only_deviceless_channels_is_accepted() {
    Inventory::parse(&http_host(HTTP_VERIFY)).unwrap();
    Inventory::parse(&mqtt_host("", MQTT_VERIFY)).unwrap();
    Inventory::parse(&serial_host("", SERIAL_VERIFY)).unwrap();
}

// --- [hosts.device] + [signing] (E4) ---------------------------------------
//
// Mutation notes: delete any validate_device arm (id length, transport
// match, signing-key requirement) or the SigningUnused check — the named
// test below fails.

fn device_host(extra: &str, transport: &str, subtable: &str) -> String {
    format!(
        r#"
        [signing]
        key_file = "/etc/lychgate/device-signing.hex"
        p256_key_file = "/etc/lychgate/device-signing-p256.hex"

        [[hosts]]
        name = "esp-1"
        address = "local-serial"
        os = "embedded"
        channels = ["device"]
        [hosts.device]
        device_id = "000102030405060708090a0b0c0d0e0f"
        transport = "{transport}"
        {extra}
        {subtable}
    "#
    )
}

const DEV_SERIAL: &str = r#"
        [hosts.device.serial]
        device = "/dev/cuaU0"
"#;

#[test]
fn a_full_device_host_parses_with_defaults() {
    let inv = Inventory::parse(&device_host("", "serial", DEV_SERIAL)).unwrap();
    let device = inv.hosts[0].device.as_ref().unwrap();
    assert_eq!(device.alg, DeviceAlg::Ed25519);
    assert_eq!(device.capability, 1);
    assert_eq!(
        device.device_id_bytes().unwrap(),
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
    );
    assert_eq!(device.serial.as_ref().unwrap().timeout_secs, 5);
}

#[test]
fn a_bad_device_id_is_refused() {
    for bad in ["shorty", "zz0102030405060708090a0b0c0d0e0f"] {
        let toml =
            device_host("", "serial", DEV_SERIAL).replace("000102030405060708090a0b0c0d0e0f", bad);
        assert_eq!(
            Inventory::parse(&toml),
            Err(InventoryError::DeviceBadId {
                host: "esp-1".into()
            }),
            "{bad}"
        );
    }
}

#[test]
fn the_transport_and_its_subtable_must_agree_exactly() {
    // transport = "http" with a serial sub-table: mismatch.
    assert_eq!(
        Inventory::parse(&device_host("", "http", DEV_SERIAL)),
        Err(InventoryError::DeviceTransportMismatch {
            host: "esp-1".into()
        })
    );
    // A second, extra sub-table: also a mismatch (dead config).
    let extra = format!(
        "{DEV_SERIAL}\n        [hosts.device.http]\n        endpoint = \"http://x\"\n        tls = {{ mode = \"insecure\" }}\n"
    );
    assert_eq!(
        Inventory::parse(&device_host("", "serial", &extra)),
        Err(InventoryError::DeviceTransportMismatch {
            host: "esp-1".into()
        })
    );
}

#[test]
fn a_device_channel_without_its_alg_key_is_refused() {
    let toml = device_host("", "serial", DEV_SERIAL)
        .replace("key_file = \"/etc/lychgate/device-signing.hex\"\n", "");
    assert_eq!(
        Inventory::parse(&toml),
        Err(InventoryError::SigningKeyMissing {
            host: "esp-1".into(),
            which: "key_file",
        })
    );
    // alg = p256 requires the p256 key specifically.
    let toml = device_host("alg = \"p256\"", "serial", DEV_SERIAL).replace(
        "p256_key_file = \"/etc/lychgate/device-signing-p256.hex\"\n",
        "",
    );
    assert_eq!(
        Inventory::parse(&toml),
        Err(InventoryError::SigningKeyMissing {
            host: "esp-1".into(),
            which: "p256_key_file",
        })
    );
}

#[test]
fn signing_without_any_device_channel_is_dead_config() {
    let toml = r#"
        [signing]
        key_file = "/etc/lychgate/device-signing.hex"

        [[hosts]]
        name = "cam-1"
        address = "a"
        os = "embedded"
        channels = ["http"]
        [hosts.http]
        endpoint = "http://x"
        tls = { mode = "insecure" }
        verify = "none"
        [hosts.http.open]
        method = "POST"
        path = "/m"
        expect_status = 200
        [hosts.http.revert]
        method = "POST"
        path = "/m"
        expect_status = 200
    "#;
    assert_eq!(Inventory::parse(toml), Err(InventoryError::SigningUnused));
}

#[test]
fn a_device_channel_without_config_is_refused() {
    let toml = r#"
        [[hosts]]
        name = "esp-1"
        address = "a"
        os = "embedded"
        channels = ["device"]
    "#;
    assert_eq!(
        Inventory::parse(toml),
        Err(InventoryError::GenericConfigMissing {
            host: "esp-1".into(),
            channel: "device",
        })
    );
}

#[test]
fn device_mqtt_password_auth_is_refused_here_too() {
    let sub = r#"
        [hosts.device.mqtt]
        broker = "10.0.9.20:1883"
        auth = { mode = "password", username = "x" }
        cmd_topic = "dev/1/cmd"
        reply_topic = "dev/1/rsp"
    "#;
    assert_eq!(
        Inventory::parse(&device_host("", "mqtt", sub)),
        Err(InventoryError::MqttPasswordAuth {
            host: "esp-1".into()
        })
    );
}
