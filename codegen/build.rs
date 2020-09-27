use std::process::Command;

fn main() -> Result<(), String> {
    // Update the timestamp of build.rs if feature is set
    //
    if cfg!(feature = "force-build") {
        #[cfg(target_os = "linux")]
        let command = Command::new("touch").args(&["build.rs"]).output();

        #[cfg(target_os = "windows")]
        let command = Command::new("copy").args(&["/b", "build.rs", "+,,"]).output();

        // Check if successful
        //
        let output = command.map_err(|e| e.to_string())?;
        if !output.status.success() {
            let out = String::from_utf8_lossy(&output.stderr);

            Err(format!("{}", out))
        } else {
            Ok(())
        }
    } else {
        Ok(())
    }
}
