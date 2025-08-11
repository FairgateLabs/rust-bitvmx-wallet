use assert_cmd::Command;
use predicates::prelude::*;

const PROJECT_NAME: &str = "bitvmx-wallet";

#[test]
fn test_with_output() {
    let mut cmd = Command::cargo_bin(PROJECT_NAME).unwrap();
    cmd.arg("some_argument");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("expected output"));
}

#[test]
fn test_with_error() {
    let mut cmd = Command::cargo_bin(PROJECT_NAME).unwrap();
    cmd.arg("invalid_argument");
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("error message"));
}