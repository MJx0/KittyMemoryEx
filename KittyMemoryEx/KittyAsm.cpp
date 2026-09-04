#include "KittyAsm.hpp"

// refs to
// https://github.com/CAS-Atlantic/AArch64-Encoding
// https://github.com/bminor/binutils-gdb
// https://github.com/capstone-engine/capstone
// https://github.com/qemu/QEMU
// https://reverseengineering.stackexchange.com/questions/15418/getting-function-address-by-reading-adrp-and-add-instruction-values
// https://stackoverflow.com/questions/41906688/what-are-the-semantics-of-adrp-and-adrl-instructions-in-arm-assembly

namespace KittyAsm
{
    /// Extracts bits [hi:lo] of a word. The one place the shift/mask pair is
    /// written, so an off-by-one in a field extraction has a single home.
    uint32_t bits(uint32_t v, int hi, int lo)
    {
        // An inverted range or an out-of-word `lo` selects nothing; a `hi` past
        // the top of the word is clamped to it, so bits(v, 40, 8) is every bit
        // from 8 up rather than an error. Every in-tree call site passes
        // constants inside the word, but this is public API and the guard costs
        // one comparison on a path the compiler folds away for those constants.
        if (hi < lo || lo < 0 || lo > 31)
            return 0u;

        // Clamped before `width` is computed, not after: `hi` arrives unbounded
        // from a caller, and hi - lo + 1 below overflows int - itself undefined
        // behaviour - for a hi anywhere near INT_MAX, before the width>=32 case
        // further down ever gets a chance to apply the same clamp to the result.
        if (hi > 31)
            hi = 31;

        // Guarded against shifting by 32 or more, which is undefined behaviour.
        const int width = hi - lo + 1;
        if (width >= 32)
            return v >> lo;

        const uint32_t mask = (1u << width) - 1u;
        return (v >> lo) & mask;
    }
} // namespace KittyAsm

using namespace KittyAsm;

namespace KittyArm32
{
    // ──── Register naming ─────────────────────────────────────────────────────

    /// Reverses regName(). A linear match on the spelled name rather than a table:
    /// the alias registers (sp/lr/pc, and fp/ip/sb on ARM32) have to be recognised
    /// alongside the plain rN/xN forms, and a table would have to encode both.
    int regIndex(const std::string &name)
    {
        if (name.empty())
            return -1;
        if (name == "sp")
            return 13;
        if (name == "lr")
            return 14;
        if (name == "pc")
            return 15;
        if (name.size() < 2 || name[0] != 'r')
            return -1;

        // Bounded as it goes: an unbounded accumulate would overflow - undefined
        // behaviour - on a long digit string, and no valid name has three digits.
        int v = 0;
        for (size_t i = 1; i < name.size(); ++i)
        {
            if (name[i] < '0' || name[i] > '9' || v > 15)
                return -1;
            v = v * 10 + (name[i] - '0');
        }
        return v < 16 ? v : -1;
    }

    // ──── Instruction classification ──────────────────────────────────────────

    /// One case per enumerator, with no default: adding a type and forgetting to
    /// name it is then a compiler warning rather than a silent "UNKNOWN" in reports.
    std::string typeToString(EKittyInsnTypeArm32 t)
    {
#define CASE(x)                                                                                                        \
    case EKittyInsnTypeArm32::x:                                                                                       \
        return #x;
        switch (t)
        {
            CASE(UNKNOWN)
            CASE(ADR)
            CASE(ADR_REG)
            CASE(ADD)
            CASE(SUB)
            CASE(SUB_SP_IMM)
            CASE(MOV_IMM)
            CASE(MOV_REG)
            CASE(MOV_SHIFTED)
            CASE(LDR)
            CASE(STR)
            CASE(LDRB)
            CASE(STRB)
            CASE(LDRH)
            CASE(STRH)
            CASE(LDRSH)
            CASE(LDRSB)
            CASE(LDR_LITERAL)
            CASE(LDR_PC_REG)
            CASE(B)
            CASE(BL)
            CASE(B_COND)
            CASE(BX)
            CASE(PUSH_SP)
            CASE(POP_PC)
            CASE(MOVW)
            CASE(MOVT)
        case EKittyInsnTypeArm32::COUNT: break; // sentinel, never a decoded type
        }
#undef CASE
        return "UNKNOWN";
    }

    /// Width is a property of the *type*, not of the encoding, so it is answered
    /// here rather than being recomputed at each call site - which is how byte-wide
    /// accesses once came to be counted as pointer-width.
    uint8_t loadStoreWidth(EKittyInsnTypeArm32 t)
    {
        switch (t)
        {
        case EKittyInsnTypeArm32::LDRB:
        case EKittyInsnTypeArm32::STRB:
        case EKittyInsnTypeArm32::LDRSB:
            return 1;
        case EKittyInsnTypeArm32::LDRH:
        case EKittyInsnTypeArm32::STRH:
        case EKittyInsnTypeArm32::LDRSH:
            return 2;
        case EKittyInsnTypeArm32::LDR:
        case EKittyInsnTypeArm32::STR:
        case EKittyInsnTypeArm32::LDR_LITERAL:
        case EKittyInsnTypeArm32::LDR_PC_REG:
            return 4;
        default:
            return 0;
        }
    }

    /// Membership, listed explicitly rather than inferred from the name: LDR_LITERAL
    /// is a load and PUSH_SP is not, and neither follows from its spelling.
    bool isLoad(EKittyInsnTypeArm32 t)
    {
        switch (t)
        {
        case EKittyInsnTypeArm32::LDR:
        case EKittyInsnTypeArm32::LDRB:
        case EKittyInsnTypeArm32::LDRH:
        case EKittyInsnTypeArm32::LDRSB:
        case EKittyInsnTypeArm32::LDRSH:
        case EKittyInsnTypeArm32::LDR_LITERAL:
        case EKittyInsnTypeArm32::LDR_PC_REG:
            return true;
        default:
            return false;
        }
    }

    /// The store half of isLoad's split. Kept separate because several types are
    /// neither, and a consumer must be able to tell "store" from "not a load".
    bool isStore(EKittyInsnTypeArm32 t)
    {
        switch (t)
        {
        case EKittyInsnTypeArm32::STR:
        case EKittyInsnTypeArm32::STRB:
        case EKittyInsnTypeArm32::STRH:
            return true;
        default:
            return false;
        }
    }

    // ──── Decoding ────────────────────────────────────────────────────────────

    /// Classifies a word by encoding space, most specific first. Order is load-
    /// bearing: the literal and PC-relative forms have to be recognised before the
    /// general shapes they are special cases of, or they decode as those instead.
    EKittyInsnTypeArm32 decodeInsnType(uint32_t instr)
    {
        // cond == 0b1111 is not a condition at all: it marks the unconditional
        // instruction space (BLX immediate, PLD, RFE, and the whole of Advanced
        // SIMD). Those encodings are unrelated to the ones decoded below, so
        // decoding them with the same masks produced pure fiction - `vqsub.u8`
        // read as MOVT, `rfeia` as POP_PC, and BLX's halfword-offset form read as
        // BL with a target two bytes off.
        if (bits(instr, 31, 28) == 0xF)
            return EKittyInsnTypeArm32::UNKNOWN;

        // Bit 25 means opposite things either side of bits 27-26: in
        // data-processing it selects an *immediate* operand, in load/store it
        // selects a *register* offset. Named for the bit rather than for either
        // meaning, so neither reading can be misapplied to the other space.
        const bool bBit25 = bit(instr, 25);

        // Bits 27-26 == 00 is shared between data-processing, the multiplies and
        // the "extra load/store" (halfword / doubleword / signed) encodings. Bit
        // 4 and bit 7 are what separate them: with a register operand and both
        // set, this is not data-processing at all. Without that test
        // `STRH R0,[R0],-R6` and `UMULL` both decoded as ADD, and the
        // destination register then received a fabricated address.
        const bool bExtraSpace = !bBit25 && bit(instr, 4) && bit(instr, 7);

        if ((instr & 0x0C000000) == 0x00000000 && !bExtraSpace)
        {
            // Against PC these are ADR, and the register form is its own type:
            // its target needs Rm, so nothing here can resolve it.
            const bool bAgainstPc = bits(instr, 19, 16) == 15;
            const bool bAdrReg    = bAgainstPc && !bBit25;

            if ((instr & 0x01E00000) == 0x00800000)
                return bAdrReg      ? EKittyInsnTypeArm32::ADR_REG
                       : bAgainstPc ? EKittyInsnTypeArm32::ADR
                                    : EKittyInsnTypeArm32::ADD;

            if ((instr & 0x01E00000) == 0x00400000)
            {
                if (bAdrReg)
                    return EKittyInsnTypeArm32::ADR_REG;
                if (bAgainstPc)
                    return EKittyInsnTypeArm32::ADR;
                // SUB SP,SP,#imm - stack allocation, and one of the two A32
                // prologue idioms. Unlike AArch64 there is no XZR ambiguity to
                // work around: r13 is unconditionally SP.
                if (bBit25 && bits(instr, 15, 12) == 13 && bits(instr, 19, 16) == 13)
                    return EKittyInsnTypeArm32::SUB_SP_IMM;
                return EKittyInsnTypeArm32::SUB;
            }

            // MOV encodes no first source operand: bits 19-16 must be zero. With
            // them set this is not a move at all, and LLVM refuses the word.
            if ((instr & 0x01E00000) == 0x01A00000 && bits(instr, 19, 16) == 0)
            {
                if (bBit25)
                    return EKittyInsnTypeArm32::MOV_IMM;
                // A32 spells the shifts as MOV; a shifted operand is not a copy.
                return bits(instr, 11, 4) != 0 ? EKittyInsnTypeArm32::MOV_SHIFTED
                                               : EKittyInsnTypeArm32::MOV_REG;
            }
        }

        // Load/Store (immediate or register offset). In this space - unlike
        // data-processing above - bit 25 set means a *register* offset, and bit 4
        // set alongside it means the media instructions (SADD16, UQADD8, ...),
        // which share the encoding and must not be read as loads.
        if ((instr & 0x0C000000) == 0x04000000 && !(bBit25 && bit(instr, 4)))
        {
            if ((instr & 0x00500000) == 0x00100000)
            {
                if (bits(instr, 19, 16) != 15)
                    return EKittyInsnTypeArm32::LDR;
                if (!bBit25)
                    return EKittyInsnTypeArm32::LDR_LITERAL;
                // [PC,Rm]: only the unshifted, adding form addresses PC+Rm.
                // Anything else is an ordinary register-offset load through a
                // base a consumer cannot follow.
                const bool bPlainAdd = bits(instr, 11, 4) == 0 && bit(instr, 23);
                return bPlainAdd ? EKittyInsnTypeArm32::LDR_PC_REG : EKittyInsnTypeArm32::LDR;
            }

            if ((instr & 0x00500000) == 0x00000000)
                return EKittyInsnTypeArm32::STR;

            // A byte load through PC is still a byte load: reporting it as
            // LDR_LITERAL gave it a 4-byte access width.
            if ((instr & 0x00500000) == 0x00500000)
                return EKittyInsnTypeArm32::LDRB;

            if ((instr & 0x00500000) == 0x00400000)
                return EKittyInsnTypeArm32::STRB;
        }

        // Extra load/store: halfword, signed byte and signed halfword. Bit 24 (P)
        // is deliberately not constrained - fixing it to 1 lost every
        // post-indexed form, which then fell through to the data-processing
        // branch above and decoded as ADD or SUB.
        //
        // The unprivileged (T) variants - post-indexed with W set - additionally
        // require bits 11-8 to be zero in their register form; LLVM and capstone
        // both refuse those words, so accepting them would be inventing an
        // instruction. The ordinary forms tolerate a non-zero should-be-zero
        // field, and are decoded rather than dropped.
        const bool bUnprivileged = !bit(instr, 24) && bit(instr, 21);
        const bool bExtraOk = bit(instr, 22) || !bUnprivileged || bits(instr, 11, 8) == 0;

        if ((instr & 0x0E0000F0) == 0x000000B0 && bExtraOk)
            return bit(instr, 20) ? EKittyInsnTypeArm32::LDRH : EKittyInsnTypeArm32::STRH;

        if ((instr & 0x0E1000F0) == 0x001000D0 && bExtraOk)
            return EKittyInsnTypeArm32::LDRSB;

        if ((instr & 0x0E1000F0) == 0x001000F0 && bExtraOk)
            return EKittyInsnTypeArm32::LDRSH;

        if ((instr & 0x0F000000) == 0x0A000000)
            return bits(instr, 31, 28) == 0xE ? EKittyInsnTypeArm32::B : EKittyInsnTypeArm32::B_COND;

        if ((instr & 0x0F000000) == 0x0B000000)
            return EKittyInsnTypeArm32::BL;

        // BX Rm - "cond 0001 0010 1111 1111 1111 0001 Rm". ARM32 has no RET
        // opcode; BX LR is how functions return, and this is not modelled by the
        // decoder above at all.
        if ((instr & 0x0FFFFFF0u) == 0x012FFF10u)
            return EKittyInsnTypeArm32::BX;

        // STMDB SP!,{reglist} (STMFD) - "cond 100 1 0 0 1 Rn=SP reglist". The
        // ARM32 frame-push idiom; STM/LDM have no generic decode here at all, so
        // this is narrowly recognised rather than modelled in general.
        if ((instr & 0x0FFF0000u) == 0x092D0000u)
            return EKittyInsnTypeArm32::PUSH_SP;

        // LDMIA SP!,{reglist} (LDMFD) with PC in the register list (bit 15) -
        // "cond 100 0 1 0 1 Rn=SP reglist". Without the PC bit this is a
        // mid-function restore, not a return, and is deliberately left UNKNOWN.
        if ((instr & 0x0FFF0000u) == 0x08BD0000u && (instr & 0x8000u) != 0)
            return EKittyInsnTypeArm32::POP_PC;

        // MOVW/MOVT Rd, #imm16 - "cond 0011 000/100 imm4 Rd imm12". The
        // dominant modern (ARMv7+) address-formation idiom; not modelled above.
        if ((instr & 0x0FF00000u) == 0x03000000u)
            return EKittyInsnTypeArm32::MOVW;
        if ((instr & 0x0FF00000u) == 0x03400000u)
            return EKittyInsnTypeArm32::MOVT;

        return EKittyInsnTypeArm32::UNKNOWN;
    }

    /// Fills in the operand detail for an already-classified word. Split by type
    /// rather than by encoding space, so each case reads as the instruction it
    /// serves; anything left UNKNOWN returns with only `word` and `address` set.
    KittyInsnArm32 decodeInsn(uint32_t instr, uint32_t address)
    {
        KittyInsnArm32 insn{};

        EKittyInsnTypeArm32 insn_type = decodeInsnType(instr);
        if (insn_type == EKittyInsnTypeArm32::UNKNOWN)
            return insn;

        insn.word = instr;
        insn.address = address;
        insn.type = insn_type;

        // Naming happens on demand, in ToString() or at a caller's own
        // request - nothing here computes a string. regName is the
        // identity on ARM32 - every r0-r15 maps to itself, aliases
        // included - so the index is the encoded field unchanged.
        const auto SetRd = [&](uint32_t reg) { insn.rd = static_cast<int>(reg); };
        const auto SetRn = [&](uint32_t reg) { insn.rn = static_cast<int>(reg); };
        const auto SetRt = [&](uint32_t reg) { insn.rt = static_cast<int>(reg); };

        switch (insn_type)
        {
        case EKittyInsnTypeArm32::UNKNOWN:
        case EKittyInsnTypeArm32::COUNT: // sentinel; decodeInsnType never yields it
            return insn;

        case EKittyInsnTypeArm32::ADD:
        case EKittyInsnTypeArm32::SUB:
        case EKittyInsnTypeArm32::SUB_SP_IMM:
        case EKittyInsnTypeArm32::MOV_IMM:
        case EKittyInsnTypeArm32::MOV_REG:
        case EKittyInsnTypeArm32::MOV_SHIFTED:
        case EKittyInsnTypeArm32::ADR:
        case EKittyInsnTypeArm32::ADR_REG:
        {
            bool I = bit(instr, 25);
            uint32_t rn = bits(instr, 19, 16);
            uint32_t rd = bits(instr, 15, 12);
            uint32_t imm12 = bits(instr, 11, 0);
            uint32_t imm8 = bits(imm12, 7, 0);
            uint32_t rot = bits(imm12, 11, 8) * 2u;
            uint32_t imm32 = ror32(imm8, rot);
            SetRd(rd);
            insn.registerForm = !I;

            const bool bIsMove = insn_type == EKittyInsnTypeArm32::MOV_IMM ||
                                 insn_type == EKittyInsnTypeArm32::MOV_REG ||
                                 insn_type == EKittyInsnTypeArm32::MOV_SHIFTED;
            if (!bIsMove)
                SetRn(rn);

            if (!I)
            {
                // Register operand: Rm is bits[3:0], not the whole 12-bit shifter
                // operand. Bits 11-4 hold the shift; when they are non-zero this
                // is LSL/LSR/ASR/ROR rather than a plain use of Rm, and the result
                // is not Rm's value.
                SetRt(bits(imm12, 3, 0));
                insn.shiftedOperand = bits(instr, 11, 4) != 0;
            }
            else
            {
                insn.immediate = imm32;
            }

            // ADR is ADD or SUB against PC, and the two go opposite ways: a
            // SUB-formed ADR that added its immediate landed 2*imm past the
            // literal it was pointing at. The opcode field is what separates
            // them, and it is reported so the register form - whose target
            // cannot be computed here - is not read as an addition either.
            constexpr uint32_t kDataOpcodeSub = 0x2;
            insn.subtractsOffset = insn_type == EKittyInsnTypeArm32::SUB ||
                                   insn_type == EKittyInsnTypeArm32::SUB_SP_IMM ||
                                   ((insn_type == EKittyInsnTypeArm32::ADR ||
                                     insn_type == EKittyInsnTypeArm32::ADR_REG) &&
                                    bits(instr, 24, 21) == kDataOpcodeSub);

            insn.pcRelative = rn == 15;
            // Only the immediate form has a resolvable target; ADR_REG needs Rm.
            if (insn.pcRelative && !insn.registerForm)
            {
                insn.target = insn.subtractsOffset ? address + kPcBias - (uint32_t)insn.immediate
                                                   : address + kPcBias + (uint32_t)insn.immediate;
            }

            break;
        }

        case EKittyInsnTypeArm32::LDRH:
        case EKittyInsnTypeArm32::LDRSH:
        case EKittyInsnTypeArm32::LDRSB:
        case EKittyInsnTypeArm32::STRH:
        {
            const bool P = bit(instr, 24);
            const bool U = bit(instr, 23);
            const bool I = bit(instr, 22); // immediate offset, not register
            const bool W = bit(instr, 21);
            uint32_t rn = bits(instr, 19, 16);
            uint32_t rd = bits(instr, 15, 12);
            SetRd(rd);
            SetRn(rn);
            // Post-indexed (P == 0) always writes back; pre-indexed does so only
            // when W is set.
            insn.postIndexed = !P;
            insn.writeback = !P || W;

            if (I)
            {
                uint32_t offset = (bits(instr, 11, 8) << 4) | bits(instr, 3, 0);
                insn.immediate = U ? (int32_t)offset : -((int32_t)offset);
            }
            else
            {
                // Register offset: the displacement is Rm, unknowable from the
                // instruction alone. Reporting the Rm/SBZ bits as an immediate -
                // which is what reading them unconditionally did - invented an
                // offset out of a register number.
                insn.registerOffset = true;
                SetRt(bits(instr, 3, 0));
                insn.immediate = 0;
                // These forms have no shift field at all; only the direction can
                // differ, and the immediate that would have carried it is 0.
                insn.subtractsOffset = !U;
            }
            insn.pcRelative = rn == 15;
            break;
        }

        case EKittyInsnTypeArm32::LDR:
        case EKittyInsnTypeArm32::LDRB:
        case EKittyInsnTypeArm32::STR:
        case EKittyInsnTypeArm32::STRB:
        case EKittyInsnTypeArm32::LDR_LITERAL:
        case EKittyInsnTypeArm32::LDR_PC_REG:
        {
            const bool P = bit(instr, 24);
            const bool U = bit(instr, 23);
            const bool W = bit(instr, 21);
            uint32_t rn = bits(instr, 19, 16);
            uint32_t rd = bits(instr, 15, 12);
            SetRd(rd);
            SetRn(rn);
            insn.postIndexed = !P;
            insn.writeback = !P || W;

            if (bit(instr, 25))
            {
                // Register offset (bit 25 set means the opposite of what it means
                // in the data-processing space): the low bits are Rm and a shift,
                // never an immediate.
                insn.registerOffset = true;
                SetRt(bits(instr, 3, 0));
                insn.immediate = 0;
                // Bits 11-4 are the shift applied to Rm. Non-zero means the
                // address is Rn + (Rm shifted), which is not Rn + Rm, so a
                // consumer that can only add registers must reject it.
                insn.shiftedOperand = bits(instr, 11, 4) != 0;
                insn.subtractsOffset = !U;
            }
            else
            {
                uint32_t imm12 = bits(instr, 11, 0);
                insn.immediate = U ? (int32_t)imm12 : -((int32_t)imm12);
                if (rn == 15)
                    insn.target = address + 8u + insn.immediate;
            }
            insn.pcRelative = rn == 15;
            break;
        }

        case EKittyInsnTypeArm32::B:
        case EKittyInsnTypeArm32::BL:
        case EKittyInsnTypeArm32::B_COND:
        {
            uint32_t cond = bits(instr, 31, 28);
            uint32_t imm24 = bits(instr, 23, 0);
            int32_t simm = signExtend(imm24, 24) << 2;
            insn.immediate = simm;
            insn.target = address + 8u + simm;
            if (insn_type == EKittyInsnTypeArm32::B_COND)
                insn.cond = static_cast<EKittyArmCond>(cond);
            break;
        }

        case EKittyInsnTypeArm32::BX:
        {
            // The operand register - almost always LR for a real return, but
            // decoded generally; the caller decides what to do with it.
            SetRn(bits(instr, 3, 0));
            break;
        }

        case EKittyInsnTypeArm32::PUSH_SP:
        case EKittyInsnTypeArm32::POP_PC:
            // Nothing downstream needs the register list, only the
            // classification - same as AArch64's STP_PRE_SP/SUB_SP_IMM.
            break;

        case EKittyInsnTypeArm32::MOVW:
        case EKittyInsnTypeArm32::MOVT:
        {
            uint32_t rd = bits(instr, 15, 12);
            uint32_t imm4 = bits(instr, 19, 16);
            uint32_t imm12 = bits(instr, 11, 0);
            uint32_t imm16 = (imm4 << 12) | imm12;
            SetRd(rd);
            // MOVT always targets the upper half; pre-shifting here matches the
            // composition convention AArch64's MOVK decode already uses (Value
            // is ready to OR into an accumulated immediate as-is).
            insn.immediate = insn_type == EKittyInsnTypeArm32::MOVT
                                  ? (int64_t)((uint64_t)imm16 << 16)
                                  : (int64_t)imm16;
            break;
        }
        }

        return insn;
    }
} // namespace KittyArm32

namespace
{
    /// Bracket-form memory operand shared by every ARM32 load/store shape:
    /// `[Rn, off]!` pre-indexed, `[Rn], off` post-indexed, else `[Rn, off]`.
    /// `off` is either `#imm` or a (possibly negated) register, never both.
    std::string MemOperand32(const KittyInsnArm32& I, const std::string& Offset)
    {
        const std::string Rn = KittyArm32::regName(static_cast<unsigned>(I.rn));
        if (I.postIndexed)
            return "[" + Rn + "], " + Offset;
        if (I.writeback)
            return "[" + Rn + ", " + Offset + "]!";
        return "[" + Rn + ", " + Offset + "]";
    }
} // namespace

std::string KittyInsnArm32::ToString() const
{
    const std::string mnem = KittyArm32::typeToString(type);
    switch (type)
    {
    case EKittyInsnTypeArm32::ADR:
    case EKittyInsnTypeArm32::ADR_REG:
    case EKittyInsnTypeArm32::ADD:
    case EKittyInsnTypeArm32::SUB:
    case EKittyInsnTypeArm32::SUB_SP_IMM:
        return mnem + " " + KittyArm32::regName(static_cast<unsigned>(rd)) + ", " +
               KittyArm32::regName(static_cast<unsigned>(rn)) + ", " +
               (registerForm ? KittyArm32::regName(static_cast<unsigned>(rt))
                              : "#" + toHexString(static_cast<uint32_t>(immediate)));

    case EKittyInsnTypeArm32::MOV_IMM:
        return mnem + " " + KittyArm32::regName(static_cast<unsigned>(rd)) + ", #" +
               toHexString(static_cast<uint32_t>(immediate));

    case EKittyInsnTypeArm32::MOV_REG:
    case EKittyInsnTypeArm32::MOV_SHIFTED:
        return mnem + " " + KittyArm32::regName(static_cast<unsigned>(rd)) + ", " +
               KittyArm32::regName(static_cast<unsigned>(rt));

    // The halfword/signed family: same bracket shape as the byte/word family
    // below, just without a shift on the register-offset form.
    case EKittyInsnTypeArm32::LDRH:
    case EKittyInsnTypeArm32::STRH:
    case EKittyInsnTypeArm32::LDRSB:
    case EKittyInsnTypeArm32::LDRSH:
    case EKittyInsnTypeArm32::LDR:
    case EKittyInsnTypeArm32::STR:
    case EKittyInsnTypeArm32::LDRB:
    case EKittyInsnTypeArm32::STRB:
    case EKittyInsnTypeArm32::LDR_LITERAL:
    case EKittyInsnTypeArm32::LDR_PC_REG:
    {
        const std::string Offset =
            registerOffset
                ? std::string(subtractsOffset ? "-" : "") + KittyArm32::regName(static_cast<unsigned>(rt))
                : "#" + toHexString(static_cast<uint32_t>(immediate));
        return mnem + " " + KittyArm32::regName(static_cast<unsigned>(rd)) + ", " + MemOperand32(*this, Offset);
    }

    case EKittyInsnTypeArm32::B:
    case EKittyInsnTypeArm32::BL:
        return mnem + " " + toHexString(target);

    case EKittyInsnTypeArm32::B_COND:
        return "B." + KittyArm32::branchCondName(static_cast<uint32_t>(cond)) + " " + toHexString(target);

    case EKittyInsnTypeArm32::BX:
        return mnem + " " + KittyArm32::regName(static_cast<unsigned>(rn));

    case EKittyInsnTypeArm32::PUSH_SP:
    case EKittyInsnTypeArm32::POP_PC:
        return mnem;

    case EKittyInsnTypeArm32::MOVW:
        return mnem + " " + KittyArm32::regName(static_cast<unsigned>(rd)) + ", #" +
               toHexString(static_cast<uint32_t>(immediate));

    case EKittyInsnTypeArm32::MOVT:
        return mnem + " " + KittyArm32::regName(static_cast<unsigned>(rd)) + ", #" +
               toHexString(static_cast<uint32_t>(immediate) >> 16) + ", LSL #16";

    case EKittyInsnTypeArm32::UNKNOWN:
    case EKittyInsnTypeArm32::COUNT:
    default:
        return "UNKNOWN";
    }
}

namespace KittyArm64
{
    /// Names the transfer register of a load/store at its true width.
    ///
    /// Width is not `size == 3`. The signed loads carry it in opc (bits
    /// 23-22): LDRSB/LDRSH with opc == 10 write an X register and only opc ==
    /// 11 writes a W one, and LDRSW - opc == 10 by definition - is always X.
    /// Reading it off `size` alone named every LDRSW destination "Wn".
    ///
    /// Not anonymous-namespace-private: ToString() needs this exact rule too,
    /// re-deriving a transfer register's width from the stored `.word` the same
    /// way decode did, so it is a shared two-caller contract rather than a
    /// decode-only implementation detail.
    std::string transferRegName(uint32_t instr, uint32_t rt)
    {
        const uint32_t size = bits(instr, 31, 30);
        const uint32_t opc  = bits(instr, 23, 22);
        const bool bSigned  = opc >= 2 && size != 3;
        const bool b64      = bSigned ? (opc == 2) : (size == 3);
        return b64 ? xRegName(rt, EZeroRegOrStackPointer::ZeroRegister) : wRegName(rt, EZeroRegOrStackPointer::ZeroRegister);
    }

    /// The `sf` bit (31) - AArch64's own name for it - selects the X-vs-W
    /// register bank for the several types where width is not implied by
    /// `type` alone: ADD/SUB (immediate), MOVZ/MOVN/MOVK, MOV, CBZ/CBNZ,
    /// TBZ/TBNZ. None of these have per-width enum variants the way LDR/LDRW
    /// do, so ToString() re-reads this bit from the stored `.word` rather than
    /// guessing from `type`.
    inline bool sf64(uint32_t instr) { return bit(instr, 31); }

    // ──── Register naming ─────────────────────────────────────────────────────

    int regIndex(const std::string &name)
    {
        if (name.empty())
            return -1;
        if (name == "SP")
            return 31;
        if (name == "XZR" || name == "WZR")
            return -1; // the zero register never holds a base

        const char c = name[0];
        if (name.size() < 2 || (c != 'X' && c != 'x' && c != 'W' && c != 'w'))
            return -1;

        // Bounded as it goes: an unbounded accumulate would overflow - undefined
        // behaviour - on a long digit string, and no valid name has three digits.
        int v = 0;
        for (size_t i = 1; i < name.size(); ++i)
        {
            if (name[i] < '0' || name[i] > '9' || v > kNumGPRegisters)
                return -1;
            v = v * 10 + (name[i] - '0');
        }
        return v < kNumGPRegisters ? v : -1;
    }

    // ──── Instruction classification ──────────────────────────────────────────

    /// One case per enumerator, with no default, for the reason given on the ARM32
    /// twin: a missing name should fail the build, not the report.
    std::string typeToString(EKittyInsnTypeArm64 t)
    {
#define CASE(x)                                                                                                        \
    case EKittyInsnTypeArm64::x:                                                                                       \
        return #x;
        switch (t)
        {
            CASE(UNKNOWN)
            CASE(ADR)
            CASE(ADRP)
            CASE(ADD)
            CASE(SUB)
            CASE(MOVZ)
            CASE(MOVN)
            CASE(MOVK)
            CASE(LDR)
            CASE(STR)
            CASE(LDRW)
            CASE(STRW)
            CASE(LDRB)
            CASE(STRB)
            CASE(LDRH)
            CASE(STRH)
            CASE(LDRSB)
            CASE(LDRSH)
            CASE(LDRSW)
            CASE(LDR_PRE)
            CASE(STR_PRE)
            CASE(LDRW_PRE)
            CASE(STRW_PRE)
            CASE(LDRW_POST)
            CASE(STRW_POST)
            CASE(LDRB_PRE)
            CASE(STRB_PRE)
            CASE(LDRH_PRE)
            CASE(STRH_PRE)
            CASE(LDRSB_PRE)
            CASE(LDRSH_PRE)
            CASE(LDRSW_PRE)
            CASE(LDR_POST)
            CASE(STR_POST)
            CASE(LDRB_POST)
            CASE(STRB_POST)
            CASE(LDRH_POST)
            CASE(STRH_POST)
            CASE(LDRSB_POST)
            CASE(LDRSH_POST)
            CASE(LDRSW_POST)
            CASE(LDUR)
            CASE(STUR)
            CASE(LDURW)
            CASE(STURW)
            CASE(LDURB)
            CASE(STURB)
            CASE(LDURH)
            CASE(STURH)
            CASE(LDURSB)
            CASE(LDURSH)
            CASE(LDURSW)
            CASE(LDR_LITERAL)
            CASE(LDRW_LITERAL)
            CASE(LDRSW_LITERAL)
            CASE(B)
            CASE(BL)
            CASE(B_COND)
            CASE(CBZ)
            CASE(CBNZ)
            CASE(TBZ)
            CASE(TBNZ)
            CASE(RET)
            CASE(STP_PRE_SP)
            CASE(SUB_SP_IMM)
            CASE(MOV)
        case EKittyInsnTypeArm64::COUNT: break; // sentinel, never a decoded type
        }
#undef CASE
        return "UNKNOWN";
    }

    /// As the ARM32 twin. The pair/atomic forms report the width of one element,
    /// since that is what a consumer reading a field actually sees.
    uint8_t loadStoreWidth(EKittyInsnTypeArm64 t)
    {
        // The pre/post-indexed and literal forms are listed explicitly. They used
        // to fall through to the 8-byte default, so every byte and halfword
        // access written as `LDRB Wt,[Xn,#imm]!` was reported as pointer-width -
        // which is exactly the signal the object-array scoring is built on.
        switch (t)
        {
        case EKittyInsnTypeArm64::LDRB:
        case EKittyInsnTypeArm64::STRB:
        case EKittyInsnTypeArm64::LDRSB:
        case EKittyInsnTypeArm64::LDURB:
        case EKittyInsnTypeArm64::STURB:
        case EKittyInsnTypeArm64::LDURSB:
        case EKittyInsnTypeArm64::LDRB_PRE:
        case EKittyInsnTypeArm64::STRB_PRE:
        case EKittyInsnTypeArm64::LDRSB_PRE:
        case EKittyInsnTypeArm64::LDRB_POST:
        case EKittyInsnTypeArm64::STRB_POST:
        case EKittyInsnTypeArm64::LDRSB_POST:
            return 1;
        case EKittyInsnTypeArm64::LDRH:
        case EKittyInsnTypeArm64::STRH:
        case EKittyInsnTypeArm64::LDRSH:
        case EKittyInsnTypeArm64::LDURH:
        case EKittyInsnTypeArm64::STURH:
        case EKittyInsnTypeArm64::LDURSH:
        case EKittyInsnTypeArm64::LDRH_PRE:
        case EKittyInsnTypeArm64::STRH_PRE:
        case EKittyInsnTypeArm64::LDRSH_PRE:
        case EKittyInsnTypeArm64::LDRH_POST:
        case EKittyInsnTypeArm64::STRH_POST:
        case EKittyInsnTypeArm64::LDRSH_POST:
            return 2;
        case EKittyInsnTypeArm64::LDRW:
        case EKittyInsnTypeArm64::STRW:
        case EKittyInsnTypeArm64::LDRSW:
        case EKittyInsnTypeArm64::LDURW:
        case EKittyInsnTypeArm64::STURW:
        case EKittyInsnTypeArm64::LDURSW:
        case EKittyInsnTypeArm64::LDRSW_PRE:
        case EKittyInsnTypeArm64::LDRSW_POST:
        case EKittyInsnTypeArm64::LDRW_LITERAL:
        case EKittyInsnTypeArm64::LDRSW_LITERAL:
        case EKittyInsnTypeArm64::LDRW_PRE:
        case EKittyInsnTypeArm64::STRW_PRE:
        case EKittyInsnTypeArm64::LDRW_POST:
        case EKittyInsnTypeArm64::STRW_POST:
            return 4;
        // The 64-bit forms, listed rather than left to a default. They used to
        // *be* the default, which is why every non-access type answered
        // "pointer-width" - a trap for any caller that reads the width without
        // first asking isLoad/isStore.
        case EKittyInsnTypeArm64::LDR:
        case EKittyInsnTypeArm64::STR:
        case EKittyInsnTypeArm64::LDUR:
        case EKittyInsnTypeArm64::STUR:
        case EKittyInsnTypeArm64::LDR_PRE:
        case EKittyInsnTypeArm64::STR_PRE:
        case EKittyInsnTypeArm64::LDR_POST:
        case EKittyInsnTypeArm64::STR_POST:
        case EKittyInsnTypeArm64::LDR_LITERAL:
            return 8;
        default:
            return 0;
        }
    }

    /// As the ARM32 twin, including the pair and acquire/release forms.
    bool isLoad(EKittyInsnTypeArm64 t)
    {
        // Includes the pre/post-indexed and literal forms. Leaving them out did
        // not merely lose those accesses: the only consumer of this predicate
        // treats "neither load nor store" as an instruction it cannot model at
        // all, so a `LDR Xt,[Xn,#imm]!` left a stale tracked value in Xt instead
        // of invalidating it.
        switch (t)
        {
        case EKittyInsnTypeArm64::LDR:
        case EKittyInsnTypeArm64::LDRW:
        case EKittyInsnTypeArm64::LDRB:
        case EKittyInsnTypeArm64::LDRH:
        case EKittyInsnTypeArm64::LDRSB:
        case EKittyInsnTypeArm64::LDRSH:
        case EKittyInsnTypeArm64::LDRSW:
        case EKittyInsnTypeArm64::LDUR:
        case EKittyInsnTypeArm64::LDURW:
        case EKittyInsnTypeArm64::LDURB:
        case EKittyInsnTypeArm64::LDURH:
        case EKittyInsnTypeArm64::LDURSB:
        case EKittyInsnTypeArm64::LDURSH:
        case EKittyInsnTypeArm64::LDURSW:
        case EKittyInsnTypeArm64::LDR_PRE:
        case EKittyInsnTypeArm64::LDRW_PRE:
        case EKittyInsnTypeArm64::LDRW_POST:
        case EKittyInsnTypeArm64::LDRB_PRE:
        case EKittyInsnTypeArm64::LDRH_PRE:
        case EKittyInsnTypeArm64::LDRSB_PRE:
        case EKittyInsnTypeArm64::LDRSH_PRE:
        case EKittyInsnTypeArm64::LDRSW_PRE:
        case EKittyInsnTypeArm64::LDR_POST:
        case EKittyInsnTypeArm64::LDRB_POST:
        case EKittyInsnTypeArm64::LDRH_POST:
        case EKittyInsnTypeArm64::LDRSB_POST:
        case EKittyInsnTypeArm64::LDRSH_POST:
        case EKittyInsnTypeArm64::LDRSW_POST:
        case EKittyInsnTypeArm64::LDR_LITERAL:
        case EKittyInsnTypeArm64::LDRW_LITERAL:
        case EKittyInsnTypeArm64::LDRSW_LITERAL:
            return true;
        default:
            return false;
        }
    }

    /// As the ARM32 twin, including the pair and release forms.
    bool isStore(EKittyInsnTypeArm64 t)
    {
        switch (t)
        {
        case EKittyInsnTypeArm64::STR:
        case EKittyInsnTypeArm64::STRW:
        case EKittyInsnTypeArm64::STRB:
        case EKittyInsnTypeArm64::STRH:
        case EKittyInsnTypeArm64::STUR:
        case EKittyInsnTypeArm64::STURW:
        case EKittyInsnTypeArm64::STURB:
        case EKittyInsnTypeArm64::STURH:
        case EKittyInsnTypeArm64::STR_PRE:
        case EKittyInsnTypeArm64::STRW_PRE:
        case EKittyInsnTypeArm64::STRW_POST:
        case EKittyInsnTypeArm64::STRB_PRE:
        case EKittyInsnTypeArm64::STRH_PRE:
        case EKittyInsnTypeArm64::STR_POST:
        case EKittyInsnTypeArm64::STRB_POST:
        case EKittyInsnTypeArm64::STRH_POST:
            return true;
        default:
            return false;
        }
    }

    // ──── Decoding ────────────────────────────────────────────────────────────

    /// Classifies a word by encoding space. As on ARM32, the specific forms are
    /// tested before the general ones they would otherwise be swallowed by.
    EKittyInsnTypeArm64 decodeInsnType(uint32_t instr)
    {
        // RET Xn - "1101 0110 0101 1111 0000 00 Rn 00000". Rn is decoded
        // generally in decodeInsn rather than assumed to be X30.
        if ((instr & 0xFFFFFC1Fu) == 0xD65F0000u)
        {
            return EKittyInsnTypeArm64::RET;
        }
        // RETAA / RETAB - the pointer-authenticated returns. Both have Rn and Rm
        // fixed to 11111 rather than encoding a register, so they are two exact
        // words rather than a masked family. They matter: arm64e (iOS) binaries
        // end most functions with RETAB, and without this every one of those
        // functions runs past its end.
        if (instr == 0xD65F0BFFu || instr == 0xD65F0FFFu)
        {
            return EKittyInsnTypeArm64::RET;
        }

        // STP <Xt1>,<Xt2>, [SP, #-imm]! - pre-indexed store pair with SP as
        // base. Narrowly recognised (SP-based, pre-indexed only); nothing
        // downstream needs Rt/Rt2/imm7 for any other STP shape.
        if ((instr & 0xFFC003E0u) == 0xA98003E0u)
        {
            return EKittyInsnTypeArm64::STP_PRE_SP;
        }

        // MOV Xd,Xm / Wd,Wm - the ORR Xd,XZR,Xm alias (Rn fixed to the zero
        // register). Checked before ADD/SUB below since it lives in the
        // "logical (shifted register)" encoding space, not immediate.
        if ((instr & 0xFFE0FFE0u) == 0xAA0003E0u || (instr & 0xFFE0FFE0u) == 0x2A0003E0u)
        {
            return EKittyInsnTypeArm64::MOV;
        }

        // ADR
        if ((instr & 0x9F000000u) == 0x10000000u)
        {
            return EKittyInsnTypeArm64::ADR;
        }
        // ADRP
        if ((instr & 0x9F000000u) == 0x90000000u)
        {
            return EKittyInsnTypeArm64::ADRP;
        }

        // SUB SP, SP, #imm - a strict subset of the generic SUB pattern below,
        // so it must be checked first. The other AArch64 function-prologue
        // idiom alongside STP_PRE_SP (plain stack allocation instead of a push).
        if ((instr & 0xFFC003FFu) == 0xD10003FFu)
        {
            return EKittyInsnTypeArm64::SUB_SP_IMM;
        }

        // ADD / SUB (immediate). Bit 23 is part of the opcode and must be 0:
        // with it set these are ADDG/SUBG (MTE) or an unallocated encoding, and
        // matching on bits 31-24 alone accepted ~49k invalid words per 500k as
        // ADD - each one then corrupting a tracked register with a fabricated
        // value. Bit 22 stays free; it is the "shift by 12" flag.
        if ((instr & 0xFF800000u) == 0x11000000u || (instr & 0xFF800000u) == 0x91000000u)
        {
            return EKittyInsnTypeArm64::ADD;
        }
        if ((instr & 0xFF800000u) == 0x51000000u || (instr & 0xFF800000u) == 0xD1000000u)
        {
            return EKittyInsnTypeArm64::SUB;
        }

        // MOVZ / MOVK / MOVN. A 32-bit form can only shift by 0 or 16, so hw > 1
        // with sf clear is unallocated rather than a wide-shift move; accepting
        // it invented a constant out of an invalid word.
        if ((instr & 0x1F800000u) == 0x12800000u && (bit(instr, 31) || bits(instr, 22, 21) <= 1))
        {
            switch (bits(instr, 30, 29))
            {
            case 0: return EKittyInsnTypeArm64::MOVN;
            case 2: return EKittyInsnTypeArm64::MOVZ;
            case 3: return EKittyInsnTypeArm64::MOVK;
            default: break; // opc == 01 is unallocated
            }
        }

        // Load/Store (immediate offset)
        {
            if ((instr & 0xFFC00000) == 0xF9400000)
                return EKittyInsnTypeArm64::LDR;
            if ((instr & 0xFFC00000) == 0xF9000000)
                return EKittyInsnTypeArm64::STR;
            if ((instr & 0xFFC00000) == 0xB9400000)
                return EKittyInsnTypeArm64::LDRW;
            if ((instr & 0xFFC00000) == 0xB9000000)
                return EKittyInsnTypeArm64::STRW;

            if ((instr & 0xFFC00000) == 0x39400000)
                return EKittyInsnTypeArm64::LDRB;
            if ((instr & 0xFFC00000) == 0x39000000)
                return EKittyInsnTypeArm64::STRB;

            if ((instr & 0xFFC00000) == 0x79400000)
                return EKittyInsnTypeArm64::LDRH;
            if ((instr & 0xFFC00000) == 0x79000000)
                return EKittyInsnTypeArm64::STRH;

            if ((instr & 0xFFC00000) == 0x39C00000 || (instr & 0xFFC00000) == 0x39800000)
                return EKittyInsnTypeArm64::LDRSB;
            if ((instr & 0xFFC00000) == 0x79C00000 || (instr & 0xFFC00000) == 0x79800000)
                return EKittyInsnTypeArm64::LDRSH;
            if ((instr & 0xFFC00000) == 0xB9800000)
                return EKittyInsnTypeArm64::LDRSW;
        }

        // Load/Store (post-indexed)
        {
            if ((instr & 0xFFE00C00) == 0xF8400400)
                return EKittyInsnTypeArm64::LDR_POST;
            if ((instr & 0xFFE00C00) == 0xB8400400)
                return EKittyInsnTypeArm64::LDRW_POST;
            if ((instr & 0xFFE00C00) == 0xF8000400)
                return EKittyInsnTypeArm64::STR_POST;
            if ((instr & 0xFFE00C00) == 0xB8000400)
                return EKittyInsnTypeArm64::STRW_POST;

            if ((instr & 0xFFE00C00) == 0x38400400)
                return EKittyInsnTypeArm64::LDRB_POST;
            if ((instr & 0xFFE00C00) == 0x38000400)
                return EKittyInsnTypeArm64::STRB_POST;

            if ((instr & 0xFFE00C00) == 0x78400400)
                return EKittyInsnTypeArm64::LDRH_POST;
            if ((instr & 0xFFE00C00) == 0x78000400)
                return EKittyInsnTypeArm64::STRH_POST;

            if ((instr & 0xFFE00C00) == 0x38C00400 || (instr & 0xFFE00C00) == 0x38800400)
                return EKittyInsnTypeArm64::LDRSB_POST;
            if ((instr & 0xFFE00C00) == 0x78C00400 || (instr & 0xFFE00C00) == 0x78800400)
                return EKittyInsnTypeArm64::LDRSH_POST;
            if ((instr & 0xFFE00C00) == 0xB8800400)
                return EKittyInsnTypeArm64::LDRSW_POST;
        }

        // Load/Store (pre-indexed)
        {
            if ((instr & 0xFFE00C00) == 0xF8400C00)
                return EKittyInsnTypeArm64::LDR_PRE;
            if ((instr & 0xFFE00C00) == 0xB8400C00)
                return EKittyInsnTypeArm64::LDRW_PRE;
            if ((instr & 0xFFE00C00) == 0xF8000C00)
                return EKittyInsnTypeArm64::STR_PRE;
            if ((instr & 0xFFE00C00) == 0xB8000C00)
                return EKittyInsnTypeArm64::STRW_PRE;

            if ((instr & 0xFFE00C00) == 0x38400C00)
                return EKittyInsnTypeArm64::LDRB_PRE;
            if ((instr & 0xFFE00C00) == 0x38000C00)
                return EKittyInsnTypeArm64::STRB_PRE;

            if ((instr & 0xFFE00C00) == 0x78400C00)
                return EKittyInsnTypeArm64::LDRH_PRE;
            if ((instr & 0xFFE00C00) == 0x78000C00)
                return EKittyInsnTypeArm64::STRH_PRE;

            if ((instr & 0xFFE00C00) == 0x38C00C00 || (instr & 0xFFE00C00) == 0x38800C00)
                return EKittyInsnTypeArm64::LDRSB_PRE;
            if ((instr & 0xFFE00C00) == 0x78C00C00 || (instr & 0xFFE00C00) == 0x78800C00)
                return EKittyInsnTypeArm64::LDRSH_PRE;
            if ((instr & 0xFFE00C00) == 0xB8800C00)
                return EKittyInsnTypeArm64::LDRSW_PRE;
        }

        // === Load/Store (unscaled)
        //
        // Mask 0xFFE00C00, not 0xFFC00000: bit 21 and bits 11-10 are what
        // separate the unscaled forms from their neighbours in the same encoding
        // space. Leaving them free made LDUR swallow the register-offset form
        // (bit 21 = 1, bits 11-10 = 10) - decoding Rm as part of an immediate
        // offset, so `LDR X1,[X2,X3]` became "load at X2 + garbage" - and the
        // unprivileged LDTR/STTR family (bits 11-10 = 10).
        {
            if ((instr & 0xFFE00C00) == 0xF8400000)
                return EKittyInsnTypeArm64::LDUR;
            if ((instr & 0xFFE00C00) == 0xF8000000)
                return EKittyInsnTypeArm64::STUR;
            if ((instr & 0xFFE00C00) == 0xB8400000)
                return EKittyInsnTypeArm64::LDURW;
            if ((instr & 0xFFE00C00) == 0xB8000000)
                return EKittyInsnTypeArm64::STURW;
            if ((instr & 0xFFE00C00) == 0x38400000)
                return EKittyInsnTypeArm64::LDURB;
            if ((instr & 0xFFE00C00) == 0x38000000)
                return EKittyInsnTypeArm64::STURB;
            if ((instr & 0xFFE00C00) == 0x78400000)
                return EKittyInsnTypeArm64::LDURH;
            if ((instr & 0xFFE00C00) == 0x78000000)
                return EKittyInsnTypeArm64::STURH;
            if ((instr & 0xFFE00C00) == 0xB8800000)
                return EKittyInsnTypeArm64::LDURSW;
            if ((instr & 0xFFE00C00) == 0x38800000u || (instr & 0xFFE00C00) == 0x38C00000u)
                return EKittyInsnTypeArm64::LDURSB;
            if ((instr & 0xFFE00C00) == 0x78800000u || (instr & 0xFFE00C00) == 0x78C00000u)
                return EKittyInsnTypeArm64::LDURSH;
        }

        // Load/Store (register offset) - "[Xn, Xm{,extend}]". Bit 21 set and bits
        // 11-10 == 10 in the same space as the unscaled forms. The offset is a
        // runtime register value, so nothing here can resolve the address; they
        // are decoded anyway so that a consumer invalidates the destination
        // instead of leaving a stale tracked value behind it.
        {
            EKittyInsnTypeArm64 t = EKittyInsnTypeArm64::UNKNOWN;
            // The extend field only allocates UXTW/LSL/SXTW/SXTX (010/011/110/111),
            // every one of which has bit 14 set; the rest is unallocated space.
            switch (bit(instr, 14) ? (instr & 0xFFE00C00u) : 0u)
            {
            case 0xF8600800u: t = EKittyInsnTypeArm64::LDR; break;
            case 0xF8200800u: t = EKittyInsnTypeArm64::STR; break;
            case 0xB8600800u: t = EKittyInsnTypeArm64::LDRW; break;
            case 0xB8200800u: t = EKittyInsnTypeArm64::STRW; break;
            case 0x38600800u: t = EKittyInsnTypeArm64::LDRB; break;
            case 0x38200800u: t = EKittyInsnTypeArm64::STRB; break;
            case 0x78600800u: t = EKittyInsnTypeArm64::LDRH; break;
            case 0x78200800u: t = EKittyInsnTypeArm64::STRH; break;
            case 0x38A00800u:
            case 0x38E00800u: t = EKittyInsnTypeArm64::LDRSB; break;
            case 0x78A00800u:
            case 0x78E00800u: t = EKittyInsnTypeArm64::LDRSH; break;
            case 0xB8A00800u: t = EKittyInsnTypeArm64::LDRSW; break;
            default: break;
            }
            if (t != EKittyInsnTypeArm64::UNKNOWN)
                return t;
        }

        // Load/Store (Literal)
        //
        // Mask 0xFF000000, not 0xFFC00000: bits 23-22 are the top of imm19, not
        // opcode. Constraining them to 0 accepted only small forward offsets and
        // rejected every backward one - measured against capstone, 14k of 565k
        // random words were literal loads the decoder could not see, including
        // the entire negative half of the range.
        {
            if ((instr & 0xFF000000) == 0x18000000)
                return EKittyInsnTypeArm64::LDRW_LITERAL;
            if ((instr & 0xFF000000) == 0x58000000)
                return EKittyInsnTypeArm64::LDR_LITERAL;
            if ((instr & 0xFF000000) == 0x98000000)
                return EKittyInsnTypeArm64::LDRSW_LITERAL;
        }

        // B
        if ((instr & 0xFC000000u) == 0x14000000u)
        {
            return EKittyInsnTypeArm64::B;
        }

        // BL
        if ((instr & 0xFC000000u) == 0x94000000u)
        {
            return EKittyInsnTypeArm64::BL;
        }

        // B.Cond
        if ((instr & 0xFF000010u) == 0x54000000u)
        {
            return EKittyInsnTypeArm64::B_COND;
        }

        // CBZ/CBNZ
        {
            if ((instr & 0x7F000000u) == 0x34000000u)
                return EKittyInsnTypeArm64::CBZ;
            if ((instr & 0x7F000000u) == 0x35000000u)
                return EKittyInsnTypeArm64::CBNZ;
        }

        // TBZ/TBNZ
        {
            if ((instr & 0x7F000000u) == 0x36000000u)
                return EKittyInsnTypeArm64::TBZ;
            if ((instr & 0x7F000000u) == 0x37000000u)
                return EKittyInsnTypeArm64::TBNZ;
        }

        return EKittyInsnTypeArm64::UNKNOWN;
    }

    /// Fills in the operand detail for an already-classified word, as the ARM32
    /// twin. Register names are rendered at their true width here, which is why the
    /// transfer register goes through transferRegName() rather than being assumed.
    KittyInsnArm64 decodeInsn(uint32_t instr, uint64_t address)
    {
        KittyInsnArm64 insn{};

        EKittyInsnTypeArm64 insn_type = decodeInsnType(instr);
        if (insn_type == EKittyInsnTypeArm64::UNKNOWN)
            return insn;

        insn.word = instr;
        insn.address = address;
        insn.type = insn_type;

        // Naming happens on demand, in ToString() or at a caller's own
        // request - nothing here computes a string.
        const auto SetRd = [&](uint32_t reg, EZeroRegOrStackPointer at31)
        { insn.rd = resolveRegIndex(reg, at31); };
        const auto SetRn = [&](uint32_t reg, EZeroRegOrStackPointer at31)
        { insn.rn = resolveRegIndex(reg, at31); };
        const auto SetRt = [&](uint32_t reg, EZeroRegOrStackPointer at31)
        { insn.rt = resolveRegIndex(reg, at31); };
        const auto SetRm = [&](uint32_t reg, EZeroRegOrStackPointer at31)
        { insn.rm = resolveRegIndex(reg, at31); };
        // Transfer register width comes off opc/size, not the operand class -
        // ToString() re-derives it from `.word` via transferRegName() when it
        // needs to name this field, the same way decode does here.
        const auto SetRtTransfer = [&](uint32_t reg)
        { insn.rt = resolveRegIndex(reg, EZeroRegOrStackPointer::ZeroRegister); };

        switch (insn_type)
        {
        case EKittyInsnTypeArm64::UNKNOWN:
        case EKittyInsnTypeArm64::COUNT: // sentinel; decodeInsnType never yields it
            return insn;

    case EKittyInsnTypeArm64::ADR:
    case EKittyInsnTypeArm64::ADRP:
    {
        uint32_t rd = bits(instr, 4, 0);
        uint32_t immlo = bits(instr, 30, 29);
        uint32_t immhi = bits(instr, 23, 5);
        uint64_t imm = (uint64_t)((immhi << 2) | immlo);
        SetRd(rd, EZeroRegOrStackPointer::ZeroRegister);
        if (insn_type == EKittyInsnTypeArm64::ADR)
        {

            int64_t simm = signExtend(imm, 21);
            insn.immediate = simm;
            insn.target = address + simm;
        }
        else
        {
            int64_t simm = signExtend(imm, 21) << 12;
            insn.immediate = simm;
            insn.target = (address & ~0xFFFULL) + simm;
        }
        break;
    }

    case EKittyInsnTypeArm64::MOVZ:
    case EKittyInsnTypeArm64::MOVK:
    case EKittyInsnTypeArm64::MOVN:
    {
        bool is64 = bit(instr, 31);
        uint32_t rd = bits(instr, 4, 0);
        uint32_t imm16 = bits(instr, 20, 5);
        uint32_t hw = bits(instr, 22, 21);
        uint64_t imm = (uint64_t)imm16 << (hw * 16);
        SetRd(rd, EZeroRegOrStackPointer::ZeroRegister);
        // MOVN inverts, and the result is only as wide as the destination:
        // `MOVN W0,#0` produces 0xFFFFFFFF, not 0xFFFFFFFFFFFFFFFF. Without
        // the mask a 32-bit MOVN handed every consumer a value with 32 bogus
        // high bits set.
        const uint64_t inverted = is64 ? ~imm : (~imm & 0xFFFFFFFFull);
        insn.immediate = insn_type != EKittyInsnTypeArm64::MOVN ? (int64_t)imm : (int64_t)inverted;
        break;
    }

    case EKittyInsnTypeArm64::ADD:
    case EKittyInsnTypeArm64::SUB:
    {
        uint32_t rd = bits(instr, 4, 0);
        uint32_t rn = bits(instr, 9, 5);
        uint32_t imm12 = bits(instr, 21, 10);
        uint32_t sh = bits(instr, 23, 22);
        uint64_t imm = (uint64_t)(sh == 1 ? imm12 << 12 : imm12);
        // Rd, unlike almost every other AArch64 register field, means SP at
        // 31 here rather than the zero register - the "add/subtract
        // (immediate)" class is one of the few where there is no "ADD
        // XZR, ..." encoding.
        SetRd(rd, EZeroRegOrStackPointer::StackPointer);
        SetRn(rn, EZeroRegOrStackPointer::StackPointer);
        insn.immediate = imm;
        break;
    }

    // ldr/str uimm12
    case EKittyInsnTypeArm64::LDR:
    case EKittyInsnTypeArm64::STR:
    case EKittyInsnTypeArm64::LDRW:
    case EKittyInsnTypeArm64::STRW:
    case EKittyInsnTypeArm64::LDRB:
    case EKittyInsnTypeArm64::STRB:
    case EKittyInsnTypeArm64::LDRH:
    case EKittyInsnTypeArm64::STRH:
    case EKittyInsnTypeArm64::LDRSB:
    case EKittyInsnTypeArm64::LDRSH:
    case EKittyInsnTypeArm64::LDRSW:
    {
        uint32_t size = bits(instr, 31, 30);
        uint32_t rn = bits(instr, 9, 5);
        uint32_t rt = bits(instr, 4, 0);
        SetRn(rn, EZeroRegOrStackPointer::StackPointer);
        SetRtTransfer(rt);

        // The register-offset forms share these types. They live in the other
        // load/store class - bit 24 clear - and are marked there by bit 21 with
        // bits 11-10 == 10. Bit 24 is what must be tested first: inside the
        // scaled class those same bits are part of imm12, so testing them
        // alone threw away every large displacement as if it were an Rm.
        if (!bit(instr, 24) && bit(instr, 21) && bits(instr, 11, 10) == 2)
        {
            insn.registerOffset = true;
            SetRm(bits(instr, 20, 16), EZeroRegOrStackPointer::ZeroRegister);
            insn.immediate = 0;
        }
        else
        {
            uint32_t imm12 = bits(instr, 21, 10);
            insn.immediate = (int64_t)((uint64_t)imm12 << size);
        }
        break;
    }

    // ldr/str post/pre indexed imm9
    case EKittyInsnTypeArm64::LDR_PRE:
    case EKittyInsnTypeArm64::STR_PRE:
    case EKittyInsnTypeArm64::LDRW_PRE:
    case EKittyInsnTypeArm64::STRW_PRE:
    case EKittyInsnTypeArm64::LDRW_POST:
    case EKittyInsnTypeArm64::STRW_POST:
    case EKittyInsnTypeArm64::LDRB_PRE:
    case EKittyInsnTypeArm64::STRB_PRE:
    case EKittyInsnTypeArm64::LDRH_PRE:
    case EKittyInsnTypeArm64::STRH_PRE:
    case EKittyInsnTypeArm64::LDRSB_PRE:
    case EKittyInsnTypeArm64::LDRSH_PRE:
    case EKittyInsnTypeArm64::LDRSW_PRE:
    case EKittyInsnTypeArm64::LDR_POST:
    case EKittyInsnTypeArm64::STR_POST:
    case EKittyInsnTypeArm64::LDRB_POST:
    case EKittyInsnTypeArm64::STRB_POST:
    case EKittyInsnTypeArm64::LDRH_POST:
    case EKittyInsnTypeArm64::STRH_POST:
    case EKittyInsnTypeArm64::LDRSB_POST:
    case EKittyInsnTypeArm64::LDRSH_POST:
    case EKittyInsnTypeArm64::LDRSW_POST:
    {
        uint32_t rn = bits(instr, 9, 5);
        uint32_t rt = bits(instr, 4, 0);
        uint32_t imm9 = bits(instr, 20, 12);
        int64_t simm = signExtend(imm9, 9);
        SetRn(rn, EZeroRegOrStackPointer::StackPointer);
        SetRtTransfer(rt);
        insn.immediate = simm;
        // Both forms move Rn. Post-indexed accesses [Rn] and applies the
        // immediate afterwards, so its immediate is not an access offset -
        // reporting it as one placed every post-indexed access at the wrong
        // address.
        insn.writeback = true;
        insn.postIndexed = bits(instr, 11, 10) == 1;
        break;
    }

    // imm9 unscaled ldr/str
    case EKittyInsnTypeArm64::LDUR:
    case EKittyInsnTypeArm64::STUR:
    case EKittyInsnTypeArm64::LDURW:
    case EKittyInsnTypeArm64::STURW:
    case EKittyInsnTypeArm64::LDURB:
    case EKittyInsnTypeArm64::STURB:
    case EKittyInsnTypeArm64::LDURH:
    case EKittyInsnTypeArm64::STURH:
    case EKittyInsnTypeArm64::LDURSB:
    case EKittyInsnTypeArm64::LDURSH:
    case EKittyInsnTypeArm64::LDURSW:
    {
        uint32_t rn = bits(instr, 9, 5);
        uint32_t rt = bits(instr, 4, 0);
        uint32_t imm9 = bits(instr, 20, 12);
        int64_t simm = signExtend(imm9, 9);
        SetRn(rn, EZeroRegOrStackPointer::StackPointer);
        SetRtTransfer(rt);
        insn.immediate = simm;
        break;
    }

    case EKittyInsnTypeArm64::LDR_LITERAL:
    case EKittyInsnTypeArm64::LDRW_LITERAL:
    case EKittyInsnTypeArm64::LDRSW_LITERAL:
    {
        uint32_t rt = bits(instr, 4, 0);
        uint32_t imm19 = bits(instr, 23, 5);
        int64_t simm = signExtend(imm19, 19) << 2;
        insn.rn = -1; // PC is not an encoded register; ToString() prints it by type
        SetRt(rt, EZeroRegOrStackPointer::ZeroRegister);
        insn.immediate = simm;
        insn.target = address + simm;
        break;
    }

    case EKittyInsnTypeArm64::B:
    case EKittyInsnTypeArm64::BL:
    {
        uint32_t imm26 = bits(instr, 25, 0);
        int64_t simm = signExtend(imm26, 26) << 2;
        insn.immediate = simm;
        insn.target = address + simm;
        break;
    }

    case EKittyInsnTypeArm64::B_COND:
    {
        uint32_t cond = bits(instr, 3, 0);
        uint32_t imm19 = bits(instr, 23, 5);
        int64_t simm = signExtend(imm19, 19) << 2;
        insn.immediate = simm;
        insn.target = address + simm;
        insn.cond = static_cast<EKittyArmCond>(cond);
        break;
    }

    case EKittyInsnTypeArm64::CBZ:
    case EKittyInsnTypeArm64::CBNZ:
    {
        uint32_t imm19 = bits(instr, 23, 5);
        uint32_t rt = bits(instr, 4, 0);
        int64_t simm = signExtend(imm19, 19) << 2;
        SetRt(rt, EZeroRegOrStackPointer::ZeroRegister);
        insn.immediate = simm;
        insn.target = address + simm;
        break;
    }

    case EKittyInsnTypeArm64::TBZ:
    case EKittyInsnTypeArm64::TBNZ:
    {
        uint32_t rt = bits(instr, 4, 0);
        uint32_t bit5 = (bits(instr, 31, 31) & 1) << 5;
        uint32_t bit_lo = bits(instr, 23, 19);
        uint32_t bitpos = bit5 | bit_lo;
        uint32_t imm14 = bits(instr, 18, 5);
        int64_t simm = signExtend(imm14, 14) << 2;
        SetRt(rt, EZeroRegOrStackPointer::ZeroRegister);
        insn.immediate = simm;
        insn.bitpos = bitpos;
        insn.target = address + simm;
        break;
    }

    case EKittyInsnTypeArm64::RET:
    {
        // RETAA/RETAB encode no register - both fields read 11111 - but they
        // return through LR like any other RET, so naming them XZR from the
        // field would be a decode of something that is not there.
        const bool bAuth = instr == 0xD65F0BFFu || instr == 0xD65F0FFFu;
        if (bAuth)
        {
            insn.rn = 30; // always X30; ToString() names it, not decoded from a field
        }
        else
        {
            SetRn(bits(instr, 9, 5), EZeroRegOrStackPointer::ZeroRegister);
        }
        break;
    }

    case EKittyInsnTypeArm64::STP_PRE_SP:
    case EKittyInsnTypeArm64::SUB_SP_IMM:
        // Nothing downstream needs the operands, only the classification.
        break;

    case EKittyInsnTypeArm64::MOV:
    {
        uint32_t rd = bits(instr, 4, 0);
        uint32_t rm = bits(instr, 20, 16);
        SetRd(rd, EZeroRegOrStackPointer::ZeroRegister);
        SetRm(rm, EZeroRegOrStackPointer::ZeroRegister);
        break;
    }
        }

        return insn;
    }
} // namespace KittyArm64

namespace
{
    /// idx as resolveRegIndex() left it, folded back to the raw 0-31 field
    /// xRegName()/wRegName()/transferRegName() expect. Only sound for a field
    /// this codebase always populates through a Zero-register context for the
    /// type at hand; see ToString()'s own per-type cases for which those are.
    uint32_t RawZeroCtxReg(int idx)
    {
        return idx < 0 ? 31u : static_cast<uint32_t>(idx);
    }

    std::string ZReg(int idx, bool b64)
    {
        const uint32_t reg = RawZeroCtxReg(idx);
        return b64 ? KittyArm64::xRegName(reg, KittyArm64::EZeroRegOrStackPointer::ZeroRegister)
                   : KittyArm64::wRegName(reg, KittyArm64::EZeroRegOrStackPointer::ZeroRegister);
    }

    /// Bracket-form memory operand for the scaled/pre/post/unscaled load-store
    /// family: `[Xn, off]!` pre-indexed, `[Xn], off` post-indexed, else
    /// `[Xn, off]`. `off` is either `#imm` or an X register, never both.
    std::string MemOperand64(const KittyInsnArm64& I, const std::string& Offset)
    {
        const std::string Rn =
            KittyArm64::xRegName(static_cast<unsigned>(I.rn), KittyArm64::EZeroRegOrStackPointer::StackPointer);
        if (I.postIndexed)
            return "[" + Rn + "], " + Offset;
        if (I.writeback)
            return "[" + Rn + ", " + Offset + "]!";
        return "[" + Rn + ", " + Offset + "]";
    }
} // namespace

std::string KittyInsnArm64::ToString() const
{
    const std::string mnem = KittyArm64::typeToString(type);
    switch (type)
    {
    case EKittyInsnTypeArm64::ADR:
    case EKittyInsnTypeArm64::ADRP:
        return mnem + " " + ZReg(rd, true) + ", " + toHexString(target);

    case EKittyInsnTypeArm64::MOVZ:
    case EKittyInsnTypeArm64::MOVN:
    case EKittyInsnTypeArm64::MOVK:
    {
        // Re-read straight from `.word`, matching decode's own field positions:
        // `immediate` is already composed (and MOVN already inverted), so it
        // cannot be un-shifted back into the imm16+LSL form real syntax uses.
        const uint32_t imm16 = bits(word, 20, 5);
        const uint32_t hw    = bits(word, 22, 21);
        return mnem + " " + ZReg(rd, KittyArm64::sf64(word)) + ", #" + toHexString(imm16) +
               (hw ? ", LSL #" + std::to_string(hw * 16) : "");
    }

    case EKittyInsnTypeArm64::ADD:
    case EKittyInsnTypeArm64::SUB:
    {
        // Width is not implied by `type` here - re-read the `sf` bit, matching
        // decode's own rule, rather than always naming the X form.
        const bool b64 = KittyArm64::sf64(word);
        const auto NameSp = [b64](unsigned reg)
        {
            return b64 ? KittyArm64::xRegName(reg, KittyArm64::EZeroRegOrStackPointer::StackPointer)
                       : KittyArm64::wRegName(reg, KittyArm64::EZeroRegOrStackPointer::StackPointer);
        };
        return mnem + " " + NameSp(static_cast<unsigned>(rd)) + ", " + NameSp(static_cast<unsigned>(rn)) + ", #" +
               toHexString(static_cast<uint64_t>(immediate));
    }

    // Scaled/pre/post-indexed/unscaled load-store family: same bracket shape,
    // differing only in whether writeback/postIndexed/registerOffset apply.
    case EKittyInsnTypeArm64::LDR:
    case EKittyInsnTypeArm64::STR:
    case EKittyInsnTypeArm64::LDRW:
    case EKittyInsnTypeArm64::STRW:
    case EKittyInsnTypeArm64::LDRB:
    case EKittyInsnTypeArm64::STRB:
    case EKittyInsnTypeArm64::LDRH:
    case EKittyInsnTypeArm64::STRH:
    case EKittyInsnTypeArm64::LDRSB:
    case EKittyInsnTypeArm64::LDRSH:
    case EKittyInsnTypeArm64::LDRSW:
    case EKittyInsnTypeArm64::LDR_PRE:
    case EKittyInsnTypeArm64::STR_PRE:
    case EKittyInsnTypeArm64::LDRW_PRE:
    case EKittyInsnTypeArm64::STRW_PRE:
    case EKittyInsnTypeArm64::LDRW_POST:
    case EKittyInsnTypeArm64::STRW_POST:
    case EKittyInsnTypeArm64::LDRB_PRE:
    case EKittyInsnTypeArm64::STRB_PRE:
    case EKittyInsnTypeArm64::LDRH_PRE:
    case EKittyInsnTypeArm64::STRH_PRE:
    case EKittyInsnTypeArm64::LDRSB_PRE:
    case EKittyInsnTypeArm64::LDRSH_PRE:
    case EKittyInsnTypeArm64::LDRSW_PRE:
    case EKittyInsnTypeArm64::LDR_POST:
    case EKittyInsnTypeArm64::STR_POST:
    case EKittyInsnTypeArm64::LDRB_POST:
    case EKittyInsnTypeArm64::STRB_POST:
    case EKittyInsnTypeArm64::LDRH_POST:
    case EKittyInsnTypeArm64::STRH_POST:
    case EKittyInsnTypeArm64::LDRSB_POST:
    case EKittyInsnTypeArm64::LDRSH_POST:
    case EKittyInsnTypeArm64::LDRSW_POST:
    case EKittyInsnTypeArm64::LDUR:
    case EKittyInsnTypeArm64::STUR:
    case EKittyInsnTypeArm64::LDURW:
    case EKittyInsnTypeArm64::STURW:
    case EKittyInsnTypeArm64::LDURB:
    case EKittyInsnTypeArm64::STURB:
    case EKittyInsnTypeArm64::LDURH:
    case EKittyInsnTypeArm64::STURH:
    case EKittyInsnTypeArm64::LDURSB:
    case EKittyInsnTypeArm64::LDURSH:
    case EKittyInsnTypeArm64::LDURSW:
    {
        const std::string Rt = KittyArm64::transferRegName(word, RawZeroCtxReg(rt));
        const std::string Offset =
            registerOffset
                ? KittyArm64::xRegName(static_cast<unsigned>(rm), KittyArm64::EZeroRegOrStackPointer::ZeroRegister)
                : "#" + toHexString(static_cast<uint64_t>(immediate));
        return mnem + " " + Rt + ", " + MemOperand64(*this, Offset);
    }

    case EKittyInsnTypeArm64::LDR_LITERAL:
    case EKittyInsnTypeArm64::LDRW_LITERAL:
    case EKittyInsnTypeArm64::LDRSW_LITERAL:
    {
        const bool b64 = type != EKittyInsnTypeArm64::LDRW_LITERAL;
        return mnem + " " + ZReg(rt, b64) + ", [PC, #" + toHexString(static_cast<uint64_t>(immediate)) + "]  ; -> " +
               toHexString(target);
    }

    case EKittyInsnTypeArm64::B:
    case EKittyInsnTypeArm64::BL:
        return mnem + " " + toHexString(target);

    case EKittyInsnTypeArm64::B_COND:
        return "B." + KittyArm64::branchCondName(static_cast<uint32_t>(cond)) + " " + toHexString(target);

    case EKittyInsnTypeArm64::CBZ:
    case EKittyInsnTypeArm64::CBNZ:
        return mnem + " " + ZReg(rt, KittyArm64::sf64(word)) + ", " + toHexString(target);

    case EKittyInsnTypeArm64::TBZ:
    case EKittyInsnTypeArm64::TBNZ:
        return mnem + " " + ZReg(rt, KittyArm64::sf64(word)) + ", #" + std::to_string(bitpos) + ", " + toHexString(target);

    case EKittyInsnTypeArm64::RET:
        return mnem + " " + ZReg(rn, true);

    case EKittyInsnTypeArm64::STP_PRE_SP:
    case EKittyInsnTypeArm64::SUB_SP_IMM:
        return mnem;

    case EKittyInsnTypeArm64::MOV:
    {
        const bool b64 = KittyArm64::sf64(word);
        return mnem + " " + ZReg(rd, b64) + ", " + ZReg(rm, b64);
    }

    case EKittyInsnTypeArm64::UNKNOWN:
    case EKittyInsnTypeArm64::COUNT:
    default:
        return "UNKNOWN";
    }
}
