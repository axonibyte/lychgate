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

        [[hosts]]
        name = "db-01"
        address = "10.0.4.11"
        os = "freebsd"
        channels = ["vnc"]
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

#[test]
fn two_hosts_with_the_same_name_are_rejected() {
    let toml = host_with("db-01", "10.0.4.11", r#"["vnc"]"#)
        + &host_with("db-01", "10.0.4.12", r#"["vnc"]"#);
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
