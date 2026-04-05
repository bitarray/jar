/// Single-run ecrecover timing: native, grey interpreter, grey recompiler, polkavm.
/// Each backend is run in a child thread and killed after 10s if it doesn't finish.
use grey_bench::*;
use std::time::{Duration, Instant};

const TIMEOUT: Duration = Duration::from_secs(10);
const GAS: u64 = i64::MAX as u64;

fn run_with_timeout<F: FnOnce() + Send + 'static>(name: &str, f: F) {
    let name = name.to_string();
    let (tx, rx) = std::sync::mpsc::channel();
    let handle = std::thread::spawn(move || {
        f();
        let _ = tx.send(());
    });
    match rx.recv_timeout(TIMEOUT) {
        Ok(()) => {
            let _ = handle.join();
        }
        Err(_) => {
            eprintln!("{name:20} KILLED after {}s", TIMEOUT.as_secs());
        }
    }
}

fn main() {
    // ---- Native baseline ----
    run_with_timeout("native", || {
        use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
        let msg: [u8; 32] = [
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
            0x66, 0x77, 0x88, 0x99,
        ];
        let sig_bytes: [u8; 64] = [
            0xff, 0x65, 0x1c, 0x65, 0xee, 0xde, 0xd4, 0x63, 0x83, 0xa4, 0xbd, 0xcd, 0x91, 0x70,
            0xff, 0x65, 0x9a, 0x4f, 0x61, 0x7b, 0xb6, 0x58, 0xa4, 0x6d, 0xd4, 0x56, 0xc5, 0x1e,
            0xc8, 0xcc, 0x21, 0x1a, 0x7d, 0xc4, 0xde, 0x91, 0xd0, 0xc8, 0x47, 0xbf, 0x5d, 0xef,
            0x99, 0x5b, 0xd0, 0x43, 0x65, 0x81, 0x36, 0xfe, 0x21, 0x35, 0xaf, 0xe6, 0x92, 0x82,
            0xf7, 0xde, 0x87, 0x39, 0x90, 0xda, 0xcb, 0x77,
        ];
        let t = Instant::now();
        let sig = Signature::from_slice(&sig_bytes).unwrap();
        let recid = RecoveryId::new(true, false);
        let key = VerifyingKey::recover_from_prehash(&msg, &sig, recid).unwrap();
        let _ = std::hint::black_box(key);
        eprintln!(
            "{:20} {:>10.3} ms",
            "native",
            t.elapsed().as_secs_f64() * 1000.0
        );
    });

    let grey_blob = grey_ecrecover_blob();
    let pvm_blob = polkavm_ecrecover_blob();

    // ---- Grey interpreter ----
    {
        let blob = grey_blob;
        run_with_timeout("grey-interpreter", move || {
            let t = Instant::now();
            let (result, gas_used) =
                run_kernel_with_backend(blob, GAS, javm::PvmBackend::ForceInterpreter);
            eprintln!(
                "{:20} {:>10.3} ms  a0={result} gas_used={gas_used} ({:.1}M inst)",
                "grey-interpreter",
                t.elapsed().as_secs_f64() * 1000.0,
                gas_used as f64 / 1e6
            );
        });
    }

    // ---- Grey recompiler ----
    {
        let blob = grey_blob;
        run_with_timeout("grey-recompiler", move || {
            let t = Instant::now();
            let (result, gas_used) =
                run_kernel_with_backend(blob, GAS, javm::PvmBackend::ForceRecompiler);
            eprintln!(
                "{:20} {:>10.3} ms  a0={result} gas_used={gas_used}",
                "grey-recompiler",
                t.elapsed().as_secs_f64() * 1000.0
            );
        });
    }

    // ---- PolkaVM compiler ----
    {
        let blob = pvm_blob;
        run_with_timeout("polkavm", move || {
            use polkavm::*;
            use polkavm_common::program::Reg as PReg;

            let mut config = Config::from_env().unwrap_or_else(|_| Config::new());
            config.set_backend(Some(BackendKind::Compiler));
            config.set_allow_experimental(true);
            config.set_sandboxing_enabled(false);
            #[cfg(feature = "polkavm-generic-sandbox")]
            config.set_sandbox(Some(SandboxKind::Generic));
            let engine = Engine::new(&config).unwrap();

            let t = Instant::now();
            let mut mc = ModuleConfig::new();
            mc.set_gas_metering(Some(GasMeteringKind::Sync));
            let module = Module::new(&engine, &mc, blob.into()).unwrap();
            let mut inst = module.instantiate().unwrap();
            inst.set_gas(GAS as i64);
            if let Some(export) = module.exports().next() {
                inst.set_next_program_counter(export.program_counter());
            }
            inst.set_reg(PReg::SP, module.default_sp());
            loop {
                match inst.run().unwrap() {
                    InterruptKind::Finished | InterruptKind::Trap => {
                        eprintln!(
                            "{:20} {:>10.3} ms  a0={}",
                            "polkavm",
                            t.elapsed().as_secs_f64() * 1000.0,
                            inst.reg(PReg::A0)
                        );
                        return;
                    }
                    InterruptKind::Ecalli(_) => continue,
                    InterruptKind::NotEnoughGas => {
                        eprintln!("polkavm: OOG");
                        return;
                    }
                    other => {
                        eprintln!("polkavm: {:?}", other);
                        return;
                    }
                }
            }
        });
    }

    std::process::exit(0);
}
