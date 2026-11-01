//! A traffic leg measures the process, not the codec: gates 3 to 11 time one operation against a
//! reference and are only readable on a runner with no neighbours, which is what a matrix cell is
//! not. This drives the shipped binary far enough to see which legs it ran.

use std::process::Command;

#[test]
fn a_traffic_leg_runs_the_identity_gates_and_no_codec_timing() {
    let output = Command::new(env!("CARGO_BIN_EXE_ferrox-bench"))
        .args(["--engine", "ferrox=target/not-a-real-engine"])
        .output()
        .expect("the bench binary runs");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "one engine is a measurement, not a comparison: {stdout}"
    );
    assert_eq!(
        output.status.code(),
        Some(2),
        "the leg refuses on the missing comparator, not on a codec row: {stderr}"
    );
    assert!(
        stdout.contains("gate 1 passed"),
        "the identity gate still witnesses the binary: {stdout}"
    );
    assert!(
        stdout.contains("gate 2 passed"),
        "the integer gates still run: {stdout}"
    );
    for skipped in ["gate 3 passed", "gate 6 passed", "gate 9 passed"] {
        assert!(
            !stdout.contains(skipped),
            "a loaded cell must not read a codec ratio: {stdout} ran {skipped}"
        );
    }
    assert!(
        stderr.contains("Gates 3 to 11 are a bare run's to measure"),
        "and the refusal says where they are measured: {stderr}"
    );
}
