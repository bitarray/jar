use javm_exec::{InstructionCategory, Opcode};

#[test]
fn valid_opcodes() {
    assert_eq!(Opcode::from_byte(0), Some(Opcode::Trap));
    assert_eq!(Opcode::from_byte(1), Some(Opcode::Fallthrough));
    assert_eq!(Opcode::from_byte(10), Some(Opcode::Ecalli));
    assert_eq!(Opcode::from_byte(40), Some(Opcode::Jump));
    assert_eq!(Opcode::from_byte(200), Some(Opcode::Add64));
    assert_eq!(Opcode::from_byte(230), Some(Opcode::MinU));
}

#[test]
fn invalid_opcodes() {
    assert_eq!(Opcode::from_byte(2), Some(Opcode::Unlikely)); // JAR v0.8.0
    assert_eq!(Opcode::from_byte(15), None);
    assert_eq!(Opcode::from_byte(255), None);
}

#[test]
fn categories() {
    assert_eq!(Opcode::Trap.category(), InstructionCategory::NoArgs);
    assert_eq!(Opcode::Ecalli.category(), InstructionCategory::OneImm);
    assert_eq!(
        Opcode::LoadImm64.category(),
        InstructionCategory::OneRegExtImm
    );
    assert_eq!(Opcode::StoreImmU8.category(), InstructionCategory::TwoImm);
    assert_eq!(Opcode::Jump.category(), InstructionCategory::OneOffset);
    assert_eq!(
        Opcode::LoadImm.category(),
        InstructionCategory::OneRegOneImm
    );
    assert_eq!(
        Opcode::StoreImmIndU8.category(),
        InstructionCategory::OneRegTwoImm
    );
    assert_eq!(
        Opcode::LoadImmJump.category(),
        InstructionCategory::OneRegImmOffset
    );
    assert_eq!(Opcode::MoveReg.category(), InstructionCategory::TwoReg);
    assert_eq!(
        Opcode::AddImm32.category(),
        InstructionCategory::TwoRegOneImm
    );
    assert_eq!(
        Opcode::BranchEq.category(),
        InstructionCategory::TwoRegOneOffset
    );
    assert_eq!(
        Opcode::LoadImmJumpInd.category(),
        InstructionCategory::TwoRegTwoImm
    );
    assert_eq!(Opcode::Add64.category(), InstructionCategory::ThreeReg);
}
