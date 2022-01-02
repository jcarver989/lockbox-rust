use std::io::Result;

fn main() -> Result<()> {
    prost_build::compile_protos(&["src/protobufs/lockbox.proto"], &["src/protobufs/"])?;
    Ok(())
}
