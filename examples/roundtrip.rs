extern crate rs_munge;

use rs_munge::{encode, decode};

fn main() {
    let orig_payload = "abc";
    let message = decode(&encode(Some(orig_payload)).unwrap()).unwrap();
    let payload = message.payload();
    
    assert_eq!(payload, &Some(String::from(orig_payload)));
    assert!(message.uid() > 0);
    assert!(message.gid() > 0);

    println!("{:?}", message);
}
