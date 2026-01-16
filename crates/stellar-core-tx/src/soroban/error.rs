use soroban_env_host_p24 as soroban_env_host24;
use soroban_env_host_p25 as soroban_env_host25;

pub(crate) fn convert_host_error_p24_to_p25(
    err: soroban_env_host24::HostError,
) -> soroban_env_host25::HostError {
    let sc_error = soroban_env_host24::xdr::ScError::try_from(&err).unwrap_or(
        soroban_env_host24::xdr::ScError::Context(
            soroban_env_host24::xdr::ScErrorCode::InternalError,
        ),
    );
    let sc_error = convert_sc_error_p24_to_p25(sc_error);
    soroban_env_host25::HostError::from(sc_error)
}

fn convert_sc_error_code_p24_to_p25(
    code: soroban_env_host24::xdr::ScErrorCode,
) -> soroban_env_host25::xdr::ScErrorCode {
    soroban_env_host25::xdr::ScErrorCode::try_from(code as i32)
        .unwrap_or(soroban_env_host25::xdr::ScErrorCode::InternalError)
}

fn convert_sc_error_p24_to_p25(
    sc_error: soroban_env_host24::xdr::ScError,
) -> soroban_env_host25::xdr::ScError {
    use soroban_env_host24::xdr::ScError as ScError24;
    use soroban_env_host25::xdr::ScError as ScError25;

    match sc_error {
        ScError24::Contract(code) => ScError25::Contract(code),
        ScError24::WasmVm(code) => ScError25::WasmVm(convert_sc_error_code_p24_to_p25(code)),
        ScError24::Context(code) => ScError25::Context(convert_sc_error_code_p24_to_p25(code)),
        ScError24::Storage(code) => ScError25::Storage(convert_sc_error_code_p24_to_p25(code)),
        ScError24::Object(code) => ScError25::Object(convert_sc_error_code_p24_to_p25(code)),
        ScError24::Crypto(code) => ScError25::Crypto(convert_sc_error_code_p24_to_p25(code)),
        ScError24::Events(code) => ScError25::Events(convert_sc_error_code_p24_to_p25(code)),
        ScError24::Budget(code) => ScError25::Budget(convert_sc_error_code_p24_to_p25(code)),
        ScError24::Value(code) => ScError25::Value(convert_sc_error_code_p24_to_p25(code)),
        ScError24::Auth(code) => ScError25::Auth(convert_sc_error_code_p24_to_p25(code)),
    }
}
