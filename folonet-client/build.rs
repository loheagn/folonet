fn main() {
    tonic_build::compile_protos("../folonet.proto").unwrap();
}
