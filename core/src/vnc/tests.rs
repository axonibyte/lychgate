use super::*;

#[test]
fn check_set_command_accepts_both_known_placeholders() {
    assert_eq!(
        check_set_command("cbsd bhyve-vnc jname={target} vncpasswordfile={password_file} apply=1"),
        Ok(())
    );
}

#[test]
fn check_set_command_requires_the_password_file_placeholder() {
    // Without {password_file} the fresh password has nowhere to land.
    assert_eq!(
        check_set_command("cbsd bhyve-vnc jname={target} apply=1"),
        Err(VncTemplateError::MissingPasswordFile)
    );
}

#[test]
fn check_clear_command_accepts_target_only() {
    assert_eq!(
        check_clear_command("cbsd bhyve-vnc jname={target} vncpassword=none apply=1"),
        Ok(())
    );
}

#[test]
fn a_clear_command_referencing_the_password_file_is_refused() {
    assert_eq!(
        check_clear_command("wipe {target} {password_file}"),
        Err(VncTemplateError::ClearHasPasswordFile)
    );
}

#[test]
fn a_single_quote_anywhere_in_a_set_template_is_refused() {
    assert_eq!(
        check_set_command("set {target} '{password_file}'"),
        Err(VncTemplateError::Quoted)
    );
}

#[test]
fn a_single_quote_anywhere_in_a_clear_template_is_refused() {
    assert_eq!(
        check_clear_command("clear '{target}'"),
        Err(VncTemplateError::Quoted)
    );
}

#[test]
fn an_unknown_placeholder_in_a_set_template_names_itself() {
    // A typo like {targett} would be left in the command literally.
    assert_eq!(
        check_set_command("set {targett} {password_file}"),
        Err(VncTemplateError::UnknownPlaceholder("targett".into()))
    );
}

#[test]
fn an_unknown_placeholder_in_a_clear_template_names_itself() {
    assert_eq!(
        check_clear_command("clear {vm}"),
        Err(VncTemplateError::UnknownPlaceholder("vm".into()))
    );
}

#[test]
fn a_shell_variable_expansion_is_not_mistaken_for_a_placeholder() {
    // ${HOME} is the operator's, not lychgate's — it must pass through.
    assert_eq!(
        check_set_command("set {target} ${HOME}/{password_file}"),
        Ok(())
    );
    assert_eq!(check_clear_command("clear {target} ${HOME}"), Ok(()));
}

#[test]
fn brace_expansion_is_left_for_the_shell_not_flagged() {
    // {a,b} is not a {name} run (the comma breaks it), so it is not a
    // placeholder and must not be refused.
    assert_eq!(check_clear_command("cmd {target} x{a,b}y"), Ok(()));
}

#[test]
fn the_underscore_is_a_legal_placeholder_character() {
    // Guards against the extractor stopping at '_': {password_file} itself
    // depends on it.
    assert_eq!(placeholders("{password_file}"), vec!["password_file"]);
    assert_eq!(placeholders("{a_b}"), vec!["a_b"]);
}
