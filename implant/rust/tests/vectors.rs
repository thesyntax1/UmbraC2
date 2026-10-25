//! Cross-language conformance tests.
//!
//! These read the same contracts/vectors.json that the Go server and the Python
//! operator validate, so any drift in the encoding or key schedule fails here
//! first.

use serde_json::Value as J;
use umbra_beacon::config::{hex_decode, hex_encode};
use umbra_beacon::crypto;
use umbra_beacon::session::Session;
use umbra_beacon::upk::{self, Value};
use umbra_beacon::wire;

fn vectors() -> J {
    let raw = include_str!("../../../contracts/vectors.json");
    serde_json::from_str(raw).expect("vectors.json must be valid JSON")
}

fn unhex(s: &str) -> Vec<u8> {
    hex_decode(s).expect("valid hex in vectors")
}

fn to_upk(v: &J) -> Value {
    match v {
        J::Null => Value::Null,
        J::Bool(b) => Value::Bool(*b),
        J::Number(n) => {
            if let Some(u) = n.as_u64() {
                Value::Uint(u)
            } else if let Some(i) = n.as_i64() {
                Value::Int(i)
            } else {
                Value::F64(n.as_f64().unwrap())
            }
        }
        J::String(s) => Value::Str(s.clone()),
        J::Array(items) => Value::Arr(items.iter().map(to_upk).collect()),
        J::Object(map) => {
            if let (Some(bin), 1) = (map.get("$bin"), map.len()) {
                return Value::Bin(unhex(bin.as_str().unwrap()));
            }
            let mut out = std::collections::BTreeMap::new();
            for (k, val) in map {
                out.insert(k.clone(), to_upk(val));
            }
            Value::Map(out)
        }
    }
}

#[test]
fn upk_encoding_matches_vectors() {
    let v = vectors();
    for case in v["upk"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let want = case["hex"].as_str().unwrap();
        let got = upk::encode(&to_upk(&case["json"])).unwrap();
        assert_eq!(hex_encode(&got), want, "upk encode mismatch for {name}");

        // and the reverse direction must reproduce the same bytes
        let decoded = upk::decode_exact(&got).unwrap();
        let again = upk::encode(&decoded).unwrap();
        assert_eq!(hex_encode(&again), want, "upk roundtrip mismatch for {name}");
    }
}

#[test]
fn upk_rejects_invalid_encodings() {
    let v = vectors();
    for key in [
        "upk_trailing",
        "upk_unknown_tag",
        "upk_nonminimal",
        "upk_unsorted_map",
        "upk_depth_exceeded",
    ] {
        let raw = unhex(v["rejects"][key].as_str().unwrap());
        assert!(upk::decode_exact(&raw).is_err(), "{key} should be rejected");
    }
}

#[test]
fn bootstrap_keys_match_vectors() {
    let v = vectors();
    let psk = unhex(v["psk"].as_str().unwrap());
    let suite = v["bootstrap"]["suite"].as_u64().unwrap() as u8;

    let c2s = crypto::derive_bootstrap_key(&psk, "c2s", suite).unwrap();
    let s2c = crypto::derive_bootstrap_key(&psk, "s2c", suite).unwrap();
    assert_eq!(hex_encode(&c2s), v["bootstrap"]["c2s_key"].as_str().unwrap());
    assert_eq!(hex_encode(&s2c), v["bootstrap"]["s2c_key"].as_str().unwrap());
    assert_eq!(
        hex_encode(&crypto::bootstrap_nonce_prefix(&c2s).unwrap()),
        v["bootstrap"]["c2s_prefix"].as_str().unwrap()
    );
    assert_eq!(
        hex_encode(&crypto::bootstrap_nonce_prefix(&s2c).unwrap()),
        v["bootstrap"]["s2c_prefix"].as_str().unwrap()
    );
}

#[test]
fn session_and_rekey_keys_match_vectors() {
    let v = vectors();
    let shared = unhex(v["session"]["shared"].as_str().unwrap());
    let cn = unhex(v["session"]["client_nonce"].as_str().unwrap());
    let sn = unhex(v["session"]["server_nonce"].as_str().unwrap());

    let (prk, km) = crypto::derive_session(&shared, &cn, &sn).unwrap();
    assert_eq!(hex_encode(&prk), v["session"]["prk"].as_str().unwrap());
    assert_eq!(hex_encode(&km.c2s_key), v["session"]["c2s_key"].as_str().unwrap());
    assert_eq!(hex_encode(&km.s2c_key), v["session"]["s2c_key"].as_str().unwrap());
    assert_eq!(hex_encode(&km.c2s_prefix), v["session"]["c2s_prefix"].as_str().unwrap());
    assert_eq!(hex_encode(&km.s2c_prefix), v["session"]["s2c_prefix"].as_str().unwrap());

    let (prk2, km2) = crypto::derive_rekey(&prk, &unhex(v["rekey"]["seed"].as_str().unwrap())).unwrap();
    assert_eq!(hex_encode(&prk2), v["rekey"]["prk_out"].as_str().unwrap());
    assert_eq!(hex_encode(&km2.c2s_key), v["rekey"]["c2s_key"].as_str().unwrap());
    assert_eq!(hex_encode(&km2.s2c_key), v["rekey"]["s2c_key"].as_str().unwrap());
    assert_eq!(hex_encode(&km2.s2c_prefix), v["rekey"]["s2c_prefix"].as_str().unwrap());
}

#[test]
fn handshake_transcript_matches_vectors() {
    let v = vectors();
    let psk = unhex(v["psk"].as_str().unwrap());
    let a = &v["auth"];

    let hello = crypto::hello_auth(
        &psk,
        a["role"].as_u64().unwrap() as u8,
        a["ident"].as_str().unwrap().as_bytes(),
        &unhex(a["client_pub"].as_str().unwrap()),
        &unhex(a["client_nonce"].as_str().unwrap()),
        a["timestamp"].as_u64().unwrap(),
        a["suite"].as_u64().unwrap() as u8,
    )
    .unwrap();
    assert_eq!(hex_encode(&hello), a["hello"].as_str().unwrap());

    let ack = crypto::ack_auth(
        &psk,
        a["ident"].as_str().unwrap().as_bytes(),
        &unhex(a["client_pub"].as_str().unwrap()),
        &unhex(a["server_pub"].as_str().unwrap()),
        &unhex(a["client_nonce"].as_str().unwrap()),
        &unhex(a["server_nonce"].as_str().unwrap()),
        &unhex(a["session_id"].as_str().unwrap()),
        a["suite"].as_u64().unwrap() as u8,
    )
    .unwrap();
    assert_eq!(hex_encode(&ack), a["ack"].as_str().unwrap());
}

#[test]
fn frames_match_vectors() {
    let v = vectors();
    for case in v["frames"].as_array().unwrap() {
        let suite = case["suite"].as_u64().unwrap() as u8;
        let key = unhex(case["key"].as_str().unwrap());
        let prefix_bytes = unhex(case["prefix"].as_str().unwrap());
        let counter = case["counter"].as_u64().unwrap();
        let plain = unhex(case["plaintext_hex"].as_str().unwrap());
        let want = case["frame_hex"].as_str().unwrap();

        let mut prefix = [0u8; 4];
        prefix.copy_from_slice(&prefix_bytes);
        let nonce = wire::make_nonce(&prefix, counter);
        assert_eq!(hex_encode(&nonce), case["nonce"].as_str().unwrap());

        let msg_type = case["type"].as_u64().unwrap() as u8;
        let header = wire::build_header(0, msg_type, suite, plain.len());
        match crypto::aead_encrypt(suite, &key, &nonce, &header, &plain) {
            Ok(sealed) => {
                let mut frame = Vec::with_capacity(header.len() + nonce.len() + sealed.len());
                frame.extend_from_slice(&header);
                frame.extend_from_slice(&nonce);
                frame.extend_from_slice(&sealed);
                assert_eq!(hex_encode(&frame), want, "frame bytes mismatch");
            }
            Err(crypto::CryptoError::UnsupportedSuite(_)) => {
                // Built without the chacha feature; the suite id still matches.
                assert_eq!(suite, wire::SUITE_CHACHA20_POLY1305);
            }
            Err(e) => panic!("seal failed: {e}"),
        }
    }
}

#[test]
fn session_accepts_vector_frames_and_rejects_replay() {
    let v = vectors();
    let km = crypto::KeyMaterial {
        c2s_key: {
            let mut k = [0u8; 32];
            k.copy_from_slice(&unhex(v["session"]["c2s_key"].as_str().unwrap()));
            k
        },
        s2c_key: {
            let mut k = [0u8; 32];
            k.copy_from_slice(&unhex(v["session"]["s2c_key"].as_str().unwrap()));
            k
        },
        c2s_prefix: {
            let mut p = [0u8; 4];
            p.copy_from_slice(&unhex(v["session"]["c2s_prefix"].as_str().unwrap()));
            p
        },
        s2c_prefix: {
            let mut p = [0u8; 4];
            p.copy_from_slice(&unhex(v["session"]["s2c_prefix"].as_str().unwrap()));
            p
        },
    };
    let prk = {
        let mut p = [0u8; 32];
        p.copy_from_slice(&unhex(v["session"]["prk"].as_str().unwrap()));
        p
    };
    let mut server = Session::new(wire::SUITE_AES256_GCM, km, true, false, Some(prk)).unwrap();
    let frame = unhex(v["frames"][0]["frame_hex"].as_str().unwrap());
    let (msg_type, _) = server.open(&frame).expect("vector frame must authenticate");
    assert_eq!(msg_type, wire::MSG_CHECKIN);
    assert!(server.open(&frame).is_err(), "replay must be rejected");
}
