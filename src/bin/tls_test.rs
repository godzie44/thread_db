use nix::sys::signal;
use nix::sys::signal::raise;
use std::cell::Cell;

thread_local! {
    static TLS_VAR: Cell<i32> = Cell::new(3);
}

fn main() {
    let thread = std::thread::spawn(|| {
        TLS_VAR.with(|iv| iv.set(4));
        std::thread::sleep(std::time::Duration::from_millis(4000))
    });

    TLS_VAR.with(|iv| {
        println!("I is {}", iv.get());
    });

    raise(signal::SIGSTOP).unwrap();

    thread.join().unwrap();

    std::process::exit(0);
}
