use std::{env, error::Error, path::PathBuf};

fn main() -> Result<(), Box<dyn Error>> {
    compile_cloudflared_capnp()?;
    compile_apple_http();

    let protoc = protoc_bin_vendored::protoc_bin_path()?;
    // SAFETY: build scripts run in their own process before rustc starts and
    // do not concurrently access this process environment.
    unsafe { env::set_var("PROTOC", protoc) };

    let descriptor_path =
        PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR is set by Cargo"))
            .join("singbox_daemon_descriptor.bin");
    tonic_prost_build::configure()
        .generate_default_stubs(true)
        .file_descriptor_set_path(descriptor_path)
        .compile_protos(
            &["proto/managed_service.proto", "proto/started_service.proto"],
            &["proto"],
        )?;

    println!("cargo:rerun-if-changed=proto/managed_service.proto");
    println!("cargo:rerun-if-changed=proto/started_service.proto");
    Ok(())
}

fn compile_apple_http() {
    println!("cargo:rerun-if-changed=src/common/apple_http.h");
    println!("cargo:rerun-if-changed=src/common/apple_http.m");
    println!("cargo:rerun-if-changed=src/common/apple_tls_platform.h");
    println!("cargo:rerun-if-changed=src/common/apple_tls_platform.m");
    if env::var("CARGO_CFG_TARGET_VENDOR").as_deref() != Ok("apple") {
        return;
    }
    cc::Build::new()
        .files(["src/common/apple_http.m", "src/common/apple_tls_platform.m"])
        .flag("-fobjc-arc")
        .compile("singbox_apple_http");
    println!("cargo:rustc-link-lib=framework=Foundation");
    println!("cargo:rustc-link-lib=framework=Security");
    println!("cargo:rustc-link-lib=framework=CoreFoundation");
    println!("cargo:rustc-link-lib=framework=Network");
}

fn compile_cloudflared_capnp() -> Result<(), Box<dyn Error>> {
    for schema in [
        "proto/cloudflared_quic_metadata.capnp",
        "proto/cloudflared_tunnelrpc.capnp",
    ] {
        let request = capnpc_embedded::CompileCommand::new()
            .file(schema)
            .src_prefix("proto")
            .compile()?;
        capnpc::codegen::CodeGenerationCommand::new()
            .output_directory(
                env::var_os("OUT_DIR").expect("OUT_DIR is set by Cargo"),
            )
            .run(request.as_slice())?;
        println!("cargo:rerun-if-changed={schema}");
    }
    Ok(())
}
