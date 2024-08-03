extern crate secp256k1;

use core::ffi;

use secp256k1::{Keypair, PublicKey, Secp256k1, SecretKey};
use secp256k1::silentpayments::{silentpayments_test_outputs, SilentpaymentsRecipient};

fn main() {

    let secp = Secp256k1::new();
    let mut rng = rand::thread_rng();

    // let recipient_scan_seckey = SecretKey::new(&mut rng);
    // let recipient_scan_pubkey = PublicKey::from_secret_key(&secp, &recipient_scan_seckey);

    // let recipient_spend_seckey = SecretKey::new(&mut rng);
    // let recipient_spend_pubkey = PublicKey::from_secret_key(&secp, &recipient_spend_seckey);

    // let recipient_index = 0;   

    let smallest_outpoint: [u8; 36] = [
        0x16, 0x9e, 0x1e, 0x83, 0xe9, 0x30, 0x85, 0x33, 0x91,
        0xbc, 0x6f, 0x35, 0xf6, 0x05, 0xc6, 0x75, 0x4c, 0xfe,
        0xad, 0x57, 0xcf, 0x83, 0x87, 0x63, 0x9d, 0x3b, 0x40,
        0x96, 0xc5, 0x4f, 0x18, 0xf4, 0x00, 0x00, 0x00, 0x00
    ];

    // let sr = SilentpaymentsRecipient::new(&recipient_scan_pubkey, &recipient_spend_pubkey, recipient_index);
    
    let mut srl = Vec::<SilentpaymentsRecipient>::new();

    for i in 0..4 {

        let recipient_scan_seckey = SecretKey::new(&mut rng);
        let recipient_scan_pubkey = PublicKey::from_secret_key(&secp, &recipient_scan_seckey);
    
        let recipient_spend_seckey = SecretKey::new(&mut rng);
        let recipient_spend_pubkey = PublicKey::from_secret_key(&secp, &recipient_spend_seckey);
    
        print!("{}:", "recipient_scan_pubkey");
    
        for i in recipient_scan_pubkey.serialize().iter().cloned() {
            print!("{:02x}", i);
        }
        println!();
        
        let recipient_index = i;   

        let sr = SilentpaymentsRecipient::new(&recipient_scan_pubkey, &recipient_spend_pubkey, recipient_index);

        srl.push(sr);
    }
    
    // let recipients = [sr];

    let recipients = srl.as_slice();
    // println!("recipient_scan_pubkey: {:?}", recipient_scan_pubkey);
    // println!("recipient_spend_pubkey: {:?}", recipient_spend_pubkey);
    // println!("sr: {:?}", sr);
    
    // silentpayments_sender_create_outputs(&secp, &recipients, &smallest_outpoint, None, Some(&plain_seckeys));

    

    // print!("{}:", "recipient_spend_pubkey");

    // for i in recipient_spend_pubkey.serialize().iter().cloned() {
    //     print!("{:02x}", i);
    // }
    // println!();

    let taproot_seckey1 = Keypair::new(&secp, &mut rng);
    let taproot_seckey2 = Keypair::new(&secp, &mut rng);
    let taproot_seckeys = [taproot_seckey1, taproot_seckey2];

    taproot_seckey1.x_only_public_key().0;

    print!("{}: ", "taproot_seckey1");
    for i in taproot_seckey1.x_only_public_key().0.serialize().iter().cloned() {
        print!("{:02x}", i);
    }
    println!();

    print!("{}: ", "taproot_seckey2");
    for i in taproot_seckey2.x_only_public_key().0.serialize().iter().cloned() {
        print!("{:02x}", i);
    }
    println!();

    let seckey1 = SecretKey::new(&mut rng);
    let seckey2 = SecretKey::new(&mut rng);
    let plain_seckeys = [seckey1, seckey2];

    print!("{}: ", "plain_pubkey1");
    let plain_pubkey1 = PublicKey::from_secret_key(&secp, &seckey1);
    for i in plain_pubkey1.serialize().iter().cloned() {
        print!("{:02x}", i);
    }

    println!();

    print!("{}: ", "plain_pubkey2");
    let plain_pubkey2 = PublicKey::from_secret_key(&secp, &seckey2);
    for i in plain_pubkey2.serialize().iter().cloned() {
        print!("{:02x}", i);
    }

    println!();

    let out_pubkeys = silentpayments_test_outputs(
        &secp, 
        recipients,
        &smallest_outpoint,
        &taproot_seckeys,
        &plain_seckeys
    ).unwrap();

    println!("{}:", "out_pubkeys");
    for i in out_pubkeys.iter() {
        for i in i.serialize().iter().cloned() {
            print!("{:02x}", i);
        }
        println!();
    }

}