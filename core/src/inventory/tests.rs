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
        channels = ["ssh", "authorized-keys", "bmc"]
        "#,
    )
    .unwrap();
    assert_eq!(
        inv.hosts,
        vec![Host {
            name: "db-01".into(),
            address: "10.0.4.11".into(),
            os: Os::Freebsd,
            channels: vec![Channel::Ssh, Channel::AuthorizedKeys, Channel::Bmc],
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
        channels = ["ssh"]
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
    let toml = host_with("db-01", "10.0.4.11", r#"["ssh"]"#)
        + &host_with("db-01", "10.0.4.12", r#"["vnc"]"#);
    assert_eq!(
        Inventory::parse(&toml),
        Err(InventoryError::DuplicateHostName("db-01".into()))
    );
}

#[test]
fn a_host_with_an_empty_name_is_rejected() {
    let toml = host_with("", "10.0.4.11", r#"["ssh"]"#);
    assert_eq!(Inventory::parse(&toml), Err(InventoryError::EmptyHostName));
}

#[test]
fn a_host_with_an_empty_address_is_rejected() {
    let toml = host_with("db-01", "", r#"["ssh"]"#);
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
    let toml = host_with("db-01", "10.0.4.11", r#"["ssh", "ssh"]"#);
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
        channels = ["ssh"]
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
        channels = ["ssh"]
        favourite_colour = "red"
    "#;
    assert!(matches!(
        Inventory::parse(toml),
        Err(InventoryError::Toml(_))
    ));
}
