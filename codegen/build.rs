fn main() -> Result<(), String> {
    // Update the timestamp of build.rs if feature is set
    //
    #[cfg(feature = "force-build")]
    {
        use std::process::Command;

        #[cfg(unix)]
        let command = Command::new("touch").args(&["build.rs"]).output();

        #[cfg(windows)]
        let command = Command::new("cmd").args(&["/k", "\"copy /b build.rs +,\""]).output();

        // Check if successful
        //
        let output = command.map_err(|e| e.to_string())?;
        if !output.status.success() {
            let out = String::from_utf8_lossy(&output.stderr);

            Err(format!("{}", out))
        } else {
            Ok(())
        }
    }

    #[cfg(not(feature = "force-build"))]
    Ok(())
}
