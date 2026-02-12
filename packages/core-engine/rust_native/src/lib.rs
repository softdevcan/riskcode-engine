use pyo3::prelude::*;

/// A simple test function to verify the Rust-Python bridge is working
#[pyfunction]
fn hello_from_rust(name: &str) -> PyResult<String> {
    Ok(format!("Hello from Rust, {}!", name))
}

/// Python module initialization
#[pymodule]
fn rust_native(_py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(hello_from_rust, m)?)?;
    Ok(())
}
