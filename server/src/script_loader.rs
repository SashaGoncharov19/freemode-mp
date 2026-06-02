//! Script Loader — loads JavaScript/TypeScript scripts from resources directory.
//! 
//! Implements FiveM-style resource loading:
//! - Scans resources directory for resource folders (with manifest.json)
//! - Loads script files (JS) from resource folders
//! - Registers loaded scripts with JsHost

use std::fs;
use std::path::Path;

/// Entry for a discovered resource.
pub struct ResourceEntry {
    /// Resource folder name.
    pub name: String,
    /// Full path to resource folder.
    pub path: String,
}

/// Loads all scripts from a resources directory and registers them with the JsHost.
/// 
/// Walks through each subdirectory of `resources_dir`. For each resource folder,
/// it looks for `client/index.js` or `server/index.js` (FiveM-style manifest).
/// If no manifest is found, loads any `*.js` file in the root of the resource.
pub fn load_all_scripts(host: &mut crate::js_host::JsHost, resources_dir: &str) -> Result<Vec<ResourceEntry>, String> {
    let path = Path::new(resources_dir);
    
    if !path.exists() {
        // Create the directory so it's ready for resources.
        fs::create_dir_all(path).map_err(|e| format!("Failed to create resources dir: {}", e))?;
        log::info!("Created resources directory: {}", resources_dir);
        return Ok(Vec::new());
    }

    let mut loaded_resources = Vec::new();

    // Read top-level entries (resource folders).
    for entry in fs::read_dir(path).map_err(|e| format!("Failed to read resources dir: {}", e))? {
        let entry = entry.map_err(|e| format!("Failed to read directory entry: {}", e))?;
        let dir_path = entry.path();
        
        if !dir_path.is_dir() {
            continue;
        }

        let resource_name = dir_path.file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();

        // Check for manifest file (FiveM-style fxmanifest.lua or standalone manifest.json).
        let has_manifest = dir_path.join("fxmanifest.lua").exists()
            || dir_path.join("manifest.json").exists();

        if has_manifest {
            // Load client/index.js and server/index.js if they exist.
            for side in &["client", "server"] {
                let script_path = dir_path.join(side).join("index.js");
                if script_path.exists() {
                    let source = fs::read_to_string(&script_path)
                        .map_err(|e| format!("Failed to read {}: {}", script_path.display(), e))?;
                    
                    host.load_script(
                        &format!("{}:{}", resource_name, side),
                        &source,
                        &script_path.to_string_lossy(),
                    )?;
                }
            }
        } else {
            // Fallback: load any *.js files in the resource folder root.
            let js_files = fs::read_dir(&dir_path)
                .map_err(|e| format!("Failed to read resource dir: {}", e))?;
            
            for js_entry in js_files {
                let js_entry = js_entry.map_err(|e| format!("Failed to read file entry: {}", e))?;
                let js_path = js_entry.path();
                
                if js_path.extension().map_or(false, |ext| ext == "js") {
                    let source = fs::read_to_string(&js_path)
                        .map_err(|e| format!("Failed to read {}: {}", js_path.display(), e))?;
                    
                    let script_name = js_path.file_stem()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .to_string();
                    
                    host.load_script(&script_name, &source, &js_path.to_string_lossy())?;
                }
            }
        }

        loaded_resources.push(ResourceEntry {
            name: resource_name.clone(),
            path: dir_path.to_string_lossy().to_string(),
        });
    }

    log::info!("Loaded {} resources from {}", loaded_resources.len(), resources_dir);
    Ok(loaded_resources)
}

/// Writes a manifest.json for a resource (used by launcher or runtime config).
pub fn write_manifest(resource_dir: &str, name: &str, scripts: &[&str]) -> Result<(), String> {
    let dir = Path::new(resource_dir);
    let manifest_path = dir.join("manifest.json");
    
    // Build minimal manifest.
    let mut script_list = Vec::new();
    for script in scripts {
        script_list.push(format!("    \"{}\"", script));
    }
    
    let manifest = format!(
        "{{\n  \"name\": \"{}\",\n  \"scripts\": [\n{}\n  ]\n}}\n",
        name,
        script_list.join(",\n")
    );

    fs::write(&manifest_path, &manifest)
        .map_err(|e| format!("Failed to write manifest: {}", e))?;

    log::info!("Wrote manifest for resource: {}", name);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn test_load_scripts_creates_dir() {
        let mut host = crate::js_host::JsHost::new();
        
        // Use a temp dir that doesn't exist.
        let temp_dir = env::temp_dir().join("freemode_test_resources");
        let _ = fs::remove_dir_all(&temp_dir); // Clean up first.
        
        let result = load_all_scripts(&mut host, temp_dir.to_str().unwrap());
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty()); // No resources yet.
    }
}