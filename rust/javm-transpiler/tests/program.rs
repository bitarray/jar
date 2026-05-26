use javm_transpiler::program::*;

fn make_test_blob() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    // CODE blob: 4 bytes of PVM code
    let code_data = vec![0x00, 0x01, 0x02, 0x03]; // trap, fallthrough, unlikely, ...
    // RO data: 8 bytes
    let ro_data = vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE];

    // Combined data section: code_data + ro_data
    let mut data_section = Vec::new();
    data_section.extend_from_slice(&code_data);
    data_section.extend_from_slice(&ro_data);

    (code_data, ro_data, data_section)
}

#[test]
fn test_roundtrip() {
    let (_code_data, _ro_data, data_section) = make_test_blob();

    let caps = vec![
        CapManifestEntry {
            cap_index: 64,
            cap_type: CapEntryType::Code,
            page_count: 0,
            data_offset: 0,
            data_len: 4, // code blob
        },
        CapManifestEntry {
            cap_index: 65,
            cap_type: CapEntryType::Data,
            page_count: 1,
            data_offset: 0,
            data_len: 0, // zero-filled stack
        },
        CapManifestEntry {
            cap_index: 66,
            cap_type: CapEntryType::Data,
            page_count: 1,
            data_offset: 4,
            data_len: 8, // ro_data
        },
    ];

    let blob = build_blob(10, 64, &caps, &data_section);
    let parsed = parse_blob(&blob).expect("parse failed");

    assert_eq!(parsed.header.memory_pages, 10);
    assert_eq!(parsed.header.cap_count, 3);
    assert_eq!(parsed.header.init_cap, 64);
    assert_eq!(parsed.caps.len(), 3);

    // CODE cap
    assert_eq!(parsed.caps[0].cap_index, 64);
    assert_eq!(parsed.caps[0].cap_type, CapEntryType::Code);
    assert_eq!(parsed.caps[0].data_len, 4);
    let code = cap_data(&parsed.caps[0], parsed.data_section);
    assert_eq!(code, &[0x00, 0x01, 0x02, 0x03]);

    // Stack DATA cap (zero-filled)
    assert_eq!(parsed.caps[1].cap_index, 65);
    assert_eq!(parsed.caps[1].cap_type, CapEntryType::Data);
    assert_eq!(parsed.caps[1].page_count, 1);
    assert_eq!(parsed.caps[1].data_len, 0);

    // RO DATA cap
    assert_eq!(parsed.caps[2].cap_index, 66);
    assert_eq!(parsed.caps[2].cap_type, CapEntryType::Data);
    assert_eq!(parsed.caps[2].page_count, 1);
    let ro = cap_data(&parsed.caps[2], parsed.data_section);
    assert_eq!(ro, &[0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE]);
}

#[test]
fn test_bad_magic() {
    let blob = build_blob(10, 64, &[], &[]);
    let mut bad = blob.clone();
    bad[3] = 0x99; // corrupt version byte
    assert!(parse_blob(&bad).is_none());
}

#[test]
fn test_truncated_blob() {
    // Too short for header
    assert!(parse_blob(&[0; 5]).is_none());

    // Header says 1 cap but blob is too short
    let blob = build_blob(10, 64, &[], &[]);
    let mut bad = blob;
    bad[8] = 1; // cap_count = 1 but no cap entries follow
    assert!(parse_blob(&bad).is_none());
}

#[test]
fn test_bad_data_reference() {
    let caps = vec![CapManifestEntry {
        cap_index: 64,
        cap_type: CapEntryType::Code,
        page_count: 0,
        data_offset: 0,
        data_len: 100, // references 100 bytes but data section is empty
    }];
    let blob = build_blob(10, 64, &caps, &[]);
    assert!(parse_blob(&blob).is_none());
}

#[test]
fn test_empty_manifest() {
    let blob = build_blob(0, 0, &[], &[]);
    let parsed = parse_blob(&blob).unwrap();
    assert_eq!(parsed.caps.len(), 0);
    assert_eq!(parsed.data_section.len(), 0);
}

#[test]
fn test_code_sub_blob_with_jump_table() {
    // Build a code sub-blob: jump_len=2, entry_size=4, code=[0,1], bitmask=[1,1], jt=[0,1]
    let mut code_data = Vec::new();
    code_data.extend_from_slice(&2u32.to_le_bytes()); // jump_len
    code_data.push(4); // entry_size
    code_data.extend_from_slice(&2u32.to_le_bytes()); // code_len
    // jump table: 2 entries × 4 bytes
    code_data.extend_from_slice(&0u32.to_le_bytes());
    code_data.extend_from_slice(&1u32.to_le_bytes());
    // code bytes
    code_data.push(0); // trap
    code_data.push(1); // fallthrough
    // packed bitmask: 1 byte for 2 bits = 0b11 = 3
    code_data.push(0x03);

    let blob = parse_code_blob(&code_data);
    assert!(blob.is_some(), "code sub-blob should parse");
    let blob = blob.unwrap();
    assert_eq!(blob.code, vec![0, 1]);
    assert_eq!(blob.bitmask, vec![1, 1]);
    assert_eq!(blob.jump_table, vec![0, 1]);
}

#[test]
fn test_build_simple_blob_roundtrip() {
    let blob = build_simple_blob(&[0, 1, 0], &[1, 1, 1], &[]);
    let parsed = parse_blob(&blob).expect("should parse");
    assert_eq!(parsed.caps.len(), 1); // 1 CODE cap
    let code_cap = &parsed.caps[0];
    assert_eq!(code_cap.cap_type, CapEntryType::Code);
    let code_blob = parse_code_blob(cap_data(code_cap, parsed.data_section)).unwrap();
    assert_eq!(code_blob.code, vec![0, 1, 0]);
    assert_eq!(code_blob.bitmask, vec![1, 1, 1]);
}
