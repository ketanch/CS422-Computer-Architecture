#include "pin.H"
#include <iostream>
#include <fstream>
#include <set>

using std::cerr;
using std::string;
using std::endl;
std::ostream* out = &cerr;

#define MEM_LATENCY 50
#define GRANULARITY 32
#define INS_TO_ANALYSE 1000000000

typedef enum {
    MEM_LOAD,
    MEM_STORE,
    NOP,
    DIRECT_CALL,
    INDIRECT_CALL,
    RET,
    UNCOND_BRANCH,
    COND_BRANCH,
    LOGICAL,
    ROTATE_SHIFT,
    FLAGOP,
    VECTOR,
    CMOVE,
    MMX_SSE,
    SYSCALL,
    FLOAT,
    OTHERS
} ins_cnt_index_enum;

static UINT64 fast_forward_count = 0;         //Fast forward count
static UINT64 icount = 0;                     //Total instructions executed

static UINT64 insAnalysed = 0;                //Total instructions analysed
static UINT64 insAnalysedTotal = 0;           //Total instructions analysed (including load store micro-instructions)
static UINT64 latency = 0;                    //Total latency of the program
static UINT64 insWithMemOp = 0;               //Total instructions with atleast one memory operand
static UINT64 totalInsMemAccess = 0;          //Total memory access by all the instructions analysed
static UINT64 bblAnalysed = 0;                //Total number of basic blocks analysed

static UINT64 insTypeCnt[17];                 //Instructions classification based on category. Its index are defined in ins_cnt_index_enum enum
static UINT64 insLenCnt[16];                  //Length count of different instructions
static UINT64 insOpCnt[16];                   //Operands counts
static UINT64 insRegOpRCnt[16];               //Register read operand count
static UINT64 insRegOpWCnt[16];               //Register write operand count
static UINT64 insMemOpCnt[16];                //Memory operand count
static UINT64 insMemOpRCnt[16];               //Memory read operand count
static UINT64 insMemOpWCnt[16];               //Memory write operand count

std::set <ADDRINT> insAddrs;                  //Store instruction footprint
std::set <ADDRINT> dataAddrs;                 //Store data footprint

static UINT32 maxInsLen = 0;
static UINT32 maxOpCnt = 0;
static UINT32 maxRegOpRCnt = 0;
static UINT32 maxRegOpWCnt = 0;
static UINT32 maxMemOpCnt = 0;
static UINT32 maxMemOpRCnt = 0;
static UINT32 maxMemOpWCnt = 0;
static UINT32 maxBytesTouched = 0;
static INT32 maxImmediate = INT32_MIN;
static INT32 minImmediate = INT32_MAX;
static ADDRDELTA maxDisplacement = 0;
static ADDRDELTA minDisplacement = 0;
static UINT32 maxBblSize = 0;
static UINT32 minBblSize = INT32_MAX;

KNOB< string > KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "HW1.out", "specify file name for HW1 output");
KNOB< UINT64 > KnobFastForwardCount(KNOB_MODE_WRITEONCE, "pintool", "f", "0", "Number of instructions to fast forward");

void print_output() {
    //Part A
    for ( int i = 0; i < 17; i++ ) 
        insAnalysedTotal += insTypeCnt[i];
    *out << "-------------------------------------------------------------------------\n";
    *out << "PART - A :\n\n";
    *out << "Total instructions executed = " << icount << "\n";
    *out << "Total instructions analysed = " << insAnalysed << "\n";
    *out << "Total ins analysed (including load-store micro-ins) = " << insAnalysedTotal << "\n";
    *out << "1. Load instructions executed = " << insTypeCnt[MEM_LOAD] << " [" <<  (float)(insTypeCnt[MEM_LOAD]*100)/insAnalysedTotal << "%]\n";
    *out << "2. Store instructions executed = " << insTypeCnt[MEM_STORE] << " [" <<  (float)(insTypeCnt[MEM_STORE]*100)/insAnalysedTotal << "%]\n";
    *out << "3. NOP instructions executed = " << insTypeCnt[NOP] << " [" <<  (float)(insTypeCnt[NOP]*100)/insAnalysedTotal << "%]\n";
    *out << "4. Direct Call instructions executed = " << insTypeCnt[DIRECT_CALL] << " [" <<  (float)(insTypeCnt[DIRECT_CALL]*100)/insAnalysedTotal << "%]\n";
    *out << "5. Indirect Call instructions executed = " << insTypeCnt[INDIRECT_CALL] << " [" <<  (float)(insTypeCnt[INDIRECT_CALL]*100)/insAnalysedTotal << "%]\n";
    *out << "6. Return instructions executed = " << insTypeCnt[RET] << " [" <<  (float)(insTypeCnt[RET]*100)/insAnalysedTotal << "%]\n";
    *out << "7. Unconditional Branch instructions executed = " << insTypeCnt[UNCOND_BRANCH] << " [" <<  (float)(insTypeCnt[UNCOND_BRANCH]*100)/insAnalysedTotal << "%]\n";
    *out << "8. Conditional Branch instructions executed = " << insTypeCnt[COND_BRANCH] << " [" <<  (float)(insTypeCnt[COND_BRANCH]*100)/insAnalysedTotal << "%]\n";
    *out << "9. Logical instructions executed = " << insTypeCnt[LOGICAL] << " [" <<  (float)(insTypeCnt[LOGICAL]*100)/insAnalysedTotal << "%]\n";
    *out << "10. Rotate and Shift instructions executed = " << insTypeCnt[ROTATE_SHIFT] << " [" <<  (float)(insTypeCnt[ROTATE_SHIFT]*100)/insAnalysedTotal << "%]\n";
    *out << "11. Flag instructions executed = " << insTypeCnt[FLAGOP] << " [" <<  (float)(insTypeCnt[FLAGOP]*100)/insAnalysedTotal << "%]\n";
    *out << "12. Vector instructions executed = " << insTypeCnt[VECTOR] << " [" <<  (float)(insTypeCnt[VECTOR]*100)/insAnalysedTotal << "%]\n";
    *out << "13. Conditional moves instructions executed = " << insTypeCnt[CMOVE] << " [" <<  (float)(insTypeCnt[CMOVE]*100)/insAnalysedTotal << "%]\n";
    *out << "14. MMX and SSE instructions executed = " << insTypeCnt[MMX_SSE] << " [" <<  (float)(insTypeCnt[MMX_SSE]*100)/insAnalysedTotal << "%]\n";
    *out << "15. Syscall instructions executed = " << insTypeCnt[SYSCALL] << " [" <<  (float)(insTypeCnt[SYSCALL]*100)/insAnalysedTotal << "%]\n";
    *out << "16. Floating point instructions executed = " << insTypeCnt[FLOAT] << " [" <<  (float)(insTypeCnt[FLOAT]*100)/insAnalysedTotal << "%]\n";
    *out << "17. Others instructions executed = " << insTypeCnt[OTHERS] << " [" <<  (float)(insTypeCnt[OTHERS]*100)/insAnalysedTotal << "%]\n";

    //Part B
    *out << "-------------------------------------------------------------------------\n";
    *out << "PART - B :\n\n";
    *out << "Total cycles executed = " << latency << "\n";
    *out << "CPI = " << (float)latency/insAnalysed << "\n";

    //Part C
    *out << "-------------------------------------------------------------------------\n";
    *out << "PART - C :\n\n";
    *out << "Total memory footprint = " << (insAddrs.size()+dataAddrs.size()) << "\n";
    *out << "Total instruction footprint = " << insAddrs.size() << "\n";
    *out << "Total data footprint = " << dataAddrs.size() << "\n";

    //Part D
    *out << "-------------------------------------------------------------------------\n";
    *out << "PART - D :\n\n";
    *out << "1. Instruction length distribution:\n";
    for ( UINT32 i = 1; i <= maxInsLen; i++ )
        *out << "Instructions with length " << i << " = " <<  insLenCnt[i] << "\n";
    
    *out << "\n2. Number of operands distribution:\n";
    for ( UINT32 i = 0; i <= maxOpCnt; i++ )
        *out << "Instructions with " << i << " operands = " << insOpCnt[i] << "\n";

    *out << "\n3. Number of register read operands distribution:\n";
    for ( UINT32 i = 0; i <= maxRegOpRCnt; i++ )
        *out << "Instructions with " << i << " register read operands = " << insRegOpRCnt[i] << "\n";

    *out << "\n4. Number of register write operands distribution:\n";
    for ( UINT32 i = 0; i <= maxRegOpWCnt; i++ )
        *out << "Instructions with " << i << " register write operands = " << insRegOpWCnt[i] << "\n";

    *out << "\n5. Number of memory operands distribution:\n";
    for ( UINT32 i = 0; i <= maxMemOpCnt; i++ ) {
        *out << "Instructions with " << i <<" memory operands = " << insMemOpCnt[i]  << "\n";
        if ( i != 0 )
            insWithMemOp += insMemOpCnt[i];
    }

    *out << "\n6. Number of memory read operands distribution:\n";
    for ( UINT32 i = 0; i <= maxMemOpRCnt; i++ )
        *out << "Instructions with " << i <<" memory read operands = " << insMemOpRCnt[i]  << "\n";

    *out << "\n7. Number of memory write operands distribution:\n";
    for ( UINT32 i = 0; i <= maxMemOpWCnt; i++ )
        *out << "Instructions with " << i <<" memory write operands = " << insMemOpWCnt[i]  << "\n";

    *out << "\n8. Maximum number of bytes touched by any memory instruction = " << maxBytesTouched << "\n";
    *out <<   "   Total number of instructions with atleast 1 memory operand = " << insWithMemOp << "\n";
    *out <<   "   Average number of bytes touched by memory instructions = " << (float)totalInsMemAccess/insWithMemOp << "\n\n";

    *out << "9. Maximum immediate field in an instruction = " << maxImmediate << "\n";
    *out << "   Minimum immediate field in an instruction = " << minImmediate << "\n\n";

    *out << "10. Maximum value of displacement field = " << maxDisplacement << "\n";
    *out << "    Minimum value of displacement field = " << minDisplacement << "\n";

    //Extra
    *out << "-------------------------------------------------------------------------\n";
    *out << "Other details :\n\n";
    *out << "Maxmimum basic block size = " << maxBblSize;
    *out << "\nMinimum basic block size = " << minBblSize;
    *out << "\nTotal basic blocks analysed = " << bblAnalysed;
    *out << "\nAverage basic block size = " << (float)insAnalysed/bblAnalysed << endl;
}

VOID InsCount(UINT32 no_ins) {
    icount += no_ins;
}

ADDRINT Terminate(void) {
    return (icount >= fast_forward_count + INS_TO_ANALYSE);
}

ADDRINT FastForward(void) {
    return (icount >= fast_forward_count && icount);
}

void MyExitRoutine() {
    print_output();
    exit(0);
}

VOID MemDisplacement(ADDRDELTA dispVal) {
    if ( maxDisplacement < dispVal )
        maxDisplacement = dispVal;
    if ( minDisplacement > dispVal )
        minDisplacement = dispVal;
}

//Analysis of a predicated instruction
VOID Analyse_Predicated(INT32 ins_type_index, UINT32 ins_mem_loads, UINT32 ins_mem_stores, \
                        UINT32 ins_mem_read_ops, UINT32 ins_mem_write_ops, UINT32 ins_max_bytes_touched, UINT32 ins_mem_acc)
{
    insTypeCnt[ins_type_index]++;
    insTypeCnt[MEM_LOAD] += ins_mem_loads;
    insTypeCnt[MEM_STORE] += ins_mem_stores;
    latency += (ins_mem_loads + ins_mem_stores) * MEM_LATENCY;
    latency++;
    insMemOpCnt[ins_mem_read_ops + ins_mem_write_ops]++;
    insMemOpRCnt[ins_mem_read_ops]++;
    insMemOpWCnt[ins_mem_write_ops]++;
    if ( (ins_mem_read_ops+ins_mem_write_ops) > maxMemOpCnt )
        maxMemOpCnt = ins_mem_read_ops+ins_mem_write_ops;
    if ( ins_mem_read_ops > maxMemOpRCnt )
        maxMemOpRCnt = ins_mem_read_ops;
    if ( ins_mem_write_ops > maxMemOpWCnt )
        maxMemOpWCnt = ins_mem_write_ops;
    totalInsMemAccess += ins_mem_acc;
    if ( ins_max_bytes_touched > maxBytesTouched ){
        maxBytesTouched = ins_max_bytes_touched;
    }
}

void ComputeInsFootprint(ADDRINT bbl_addr, UINT32 bbl_size) {
    ADDRINT min_addr = bbl_addr - bbl_addr % GRANULARITY;
    ADDRINT max_addr = (bbl_addr + bbl_size) - (bbl_addr + bbl_size) % GRANULARITY + GRANULARITY;
    for ( ADDRINT i = min_addr; i < max_addr; i = i+GRANULARITY ) {
        insAddrs.insert(i);
    }
}

void ComputeDataFootprint(ADDRINT data_addr, UINT32 data_size) {
    ADDRINT min_addr = data_addr - data_addr % GRANULARITY;
    ADDRINT max_addr = (data_addr + data_size) - (data_addr + data_size) % GRANULARITY + GRANULARITY;
    for ( ADDRINT i = min_addr; i < max_addr; i = i+GRANULARITY ) {
        dataAddrs.insert(i);
    }
}

//Analysis of basic blocks which uses results precomputed at time of instrumentation
//Precomputed results only include non-predicated instructions
VOID Bbl_Analysis(UINT64* bbl_ins_type_cnt, UINT64 bbl_latency, UINT32 bbl_ins_cnt, ADDRINT bbl_addr, \
                  UINT32 bbl_size, UINT64* bbl_ins_len_cnt, UINT64* bbl_op_cnt, UINT64* bbl_regr_cnt, \
                  UINT64* bbl_regw_cnt,  UINT64* bbl_memop_cnt, UINT64* bbl_memopr_cnt, UINT64* bbl_memopw_cnt, \
                  UINT32 bbl_mem_acc, UINT32 bbl_max_bytes_touched, INT32 bbl_max_imm, INT32 bbl_min_imm)
{
    bblAnalysed++;
    if ( maxBblSize < bbl_ins_cnt )
        maxBblSize = bbl_ins_cnt;
    if ( minBblSize > bbl_ins_cnt )
        minBblSize = bbl_ins_cnt;
    for ( UINT32 i = 0; i < 17; i++) {
        insTypeCnt[i] += bbl_ins_type_cnt[i];
        if ( i != 16 ) {
            insLenCnt[i] += bbl_ins_len_cnt[i];
            if ( bbl_ins_len_cnt[i] > 0 && i > maxInsLen )
                maxInsLen = i;
            insOpCnt[i] += bbl_op_cnt[i];
            if ( bbl_op_cnt[i] > 0 && i > maxOpCnt )
                maxOpCnt = i;
            insRegOpRCnt[i] += bbl_regr_cnt[i];
            if ( bbl_regr_cnt[i] > 0 && i > maxRegOpRCnt )
                maxRegOpRCnt = i;
            insRegOpWCnt[i] += bbl_regw_cnt[i];
            if ( bbl_regw_cnt[i] > 0 && i > maxRegOpWCnt )
                maxRegOpWCnt = i;
            insMemOpCnt[i] += bbl_memop_cnt[i];
            insMemOpRCnt[i] += bbl_memopr_cnt[i];
            insMemOpWCnt[i] += bbl_memopw_cnt[i];
            if ( bbl_memopr_cnt[i] > 0 && i > maxMemOpRCnt )
                maxMemOpRCnt = i;
            if ( bbl_memopw_cnt[i] > 0 && i > maxMemOpWCnt )
                maxMemOpWCnt = i;
            if ( bbl_memop_cnt[i] > 0 && i > maxMemOpCnt )
                maxMemOpCnt = i;
        }
    }
    latency += bbl_latency;
    insAnalysed += bbl_ins_cnt;
    ComputeInsFootprint(bbl_addr, bbl_size);
    totalInsMemAccess += bbl_mem_acc;
    if ( bbl_max_bytes_touched > maxBytesTouched ) maxBytesTouched = bbl_max_bytes_touched;
    if ( maxImmediate < bbl_max_imm ) maxImmediate = bbl_max_imm;
    if ( minImmediate > bbl_min_imm ) minImmediate = bbl_min_imm;

}

//Variables contining property of basic block starts with bbl_ and those of instruction starts with ins_
VOID Trace(TRACE trace, VOID* v) {

    for ( BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl) ) {

        UINT64 bbl_latency = 0;
        UINT64* bbl_ins_type_cnt = (UINT64*) malloc(17 * sizeof(UINT64));
        UINT64* bbl_ins_len_cnt = (UINT64*) malloc(16 * sizeof(UINT64));
        UINT64* bbl_op_cnt = (UINT64*) malloc(16 * sizeof(UINT64));
        UINT64* bbl_regr_cnt = (UINT64*) malloc(16 * sizeof(UINT64));
        UINT64* bbl_regw_cnt = (UINT64*) malloc(16 * sizeof(UINT64));
        UINT64* bbl_memop_cnt = (UINT64*) malloc(16 * sizeof(UINT64));
        UINT64* bbl_memopr_cnt = (UINT64*) malloc(16 * sizeof(UINT64));
        UINT64* bbl_memopw_cnt = (UINT64*) malloc(16 * sizeof(UINT64));
        memset(bbl_ins_type_cnt, 0, 17*sizeof(UINT64));
        memset(bbl_ins_len_cnt, 0, 16*sizeof(UINT64));
        memset(bbl_op_cnt, 0, 16*sizeof(UINT64));
        memset(bbl_regr_cnt, 0, 16*sizeof(UINT64));
        memset(bbl_regw_cnt, 0, 16*sizeof(UINT64));
        memset(bbl_memop_cnt, 0, 16*sizeof(UINT64));
        memset(bbl_memopr_cnt, 0, 16*sizeof(UINT64));
        memset(bbl_memopw_cnt, 0, 16*sizeof(UINT64));
        UINT32 bbl_mem_acc = 0;
        INT32 bbl_max_immediate = INT32_MIN;
        INT32 bbl_min_immediate = INT32_MAX;
        UINT32 bbl_max_bytes_touched = 0;

        for ( INS ins = BBL_InsHead(bbl); INS_Valid(ins) ; ins = INS_Next(ins) ) {

            INT32 ins_category = INS_Category(ins);
            UINT32 ins_type_index;

            if ( ins_category == XED_CATEGORY_NOP )
                ins_type_index = NOP;
            else if ( ins_category == XED_CATEGORY_CALL ) {
                if( INS_IsDirectCall(ins) )
                    ins_type_index = DIRECT_CALL;
                else
                    ins_type_index = INDIRECT_CALL;
            }
            else if ( ins_category == XED_CATEGORY_RET )
                ins_type_index = RET;
            else if ( ins_category == XED_CATEGORY_UNCOND_BR )
                ins_type_index = UNCOND_BRANCH;
            else if ( ins_category == XED_CATEGORY_COND_BR )
                ins_type_index = COND_BRANCH;
            else if ( ins_category == XED_CATEGORY_LOGICAL )
                ins_type_index = LOGICAL;
            else if ( ins_category == XED_CATEGORY_ROTATE || ins_category == XED_CATEGORY_SHIFT )
                ins_type_index = ROTATE_SHIFT;
            else if ( ins_category == XED_CATEGORY_FLAGOP )
                ins_type_index = FLAGOP;
            else if ( ins_category == XED_CATEGORY_AVX || ins_category == XED_CATEGORY_AVX2 || ins_category == XED_CATEGORY_AVX2GATHER || ins_category == XED_CATEGORY_AVX512 )
                ins_type_index = VECTOR;
            else if ( ins_category == XED_CATEGORY_CMOV )
                ins_type_index = CMOVE;
            else if ( ins_category == XED_CATEGORY_MMX || ins_category == XED_CATEGORY_SSE )
                ins_type_index = MMX_SSE;
            else if ( ins_category == XED_CATEGORY_SYSCALL )
                ins_type_index = SYSCALL;
            else if ( ins_category == XED_CATEGORY_X87_ALU )
                ins_type_index = FLOAT;
            else
                ins_type_index = OTHERS;

            UINT32 ins_mem_loads = 0;
            UINT32 ins_mem_stores = 0;
            UINT32 ins_mem_read_ops = 0;
            UINT32 ins_mem_write_ops = 0;

            bbl_ins_len_cnt[INS_Size(ins)]++;
            bbl_op_cnt[INS_OperandCount(ins)]++;
            bbl_regr_cnt[INS_MaxNumRRegs(ins)]++;
            bbl_regw_cnt[INS_MaxNumWRegs(ins)]++;

            INT32 immediateVal;
            UINT32 cnt_allOp = INS_OperandCount(ins);
            for ( UINT32 op = 0; op < cnt_allOp; op++ ) {
                if ( INS_OperandIsImmediate(ins, op) ) {
                    immediateVal = (INT32) INS_OperandImmediate(ins, op);
                    if ( bbl_max_immediate < immediateVal ) bbl_max_immediate = immediateVal;
                    if ( bbl_min_immediate > immediateVal ) bbl_min_immediate = immediateVal;
                }
            }

            //Type B
            //Here computing count of load-store operations, displacement results, memory access and data footprint
            UINT32 cnt_memOp = INS_MemoryOperandCount(ins);
            UINT32 ins_max_bytes_touched = 0;
            UINT32 ins_mem_acc = 0;
            for (UINT32 memOp = 0; memOp < cnt_memOp; memOp++) {
                UINT32 op_mem_acc = INS_MemoryOperandSize(ins, memOp);
                ins_mem_acc += op_mem_acc;
                if ( op_mem_acc > ins_max_bytes_touched ) ins_max_bytes_touched = op_mem_acc;
                UINT32 no_of_access = (op_mem_acc/4) + (op_mem_acc%4 != 0);
                if ( INS_MemoryOperandIsRead(ins, memOp) ) {
                    ins_mem_loads += no_of_access;
                    ins_mem_read_ops++;
                }
                if ( INS_MemoryOperandIsWritten(ins, memOp) ) {
                    ins_mem_stores += no_of_access;
                    ins_mem_write_ops++;
                }

                ADDRDELTA displacementVal = INS_OperandMemoryDisplacement(ins, memOp);

                INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)FastForward, IARG_END);
                INS_InsertThenPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) ComputeDataFootprint, IARG_MEMORYOP_EA, memOp, IARG_UINT32, op_mem_acc, IARG_END);
                INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)FastForward, IARG_END);
                INS_InsertThenPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)MemDisplacement , IARG_ADDRINT, (ADDRINT) displacementVal, IARG_END);
            }
            //Type A
            //If instruction is predicated then do not include it in bbl analysis
            if ( INS_IsPredicated(ins) ) {
                INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)FastForward, IARG_END);
                INS_InsertThenPredicatedCall( \
                    ins, IPOINT_BEFORE, (AFUNPTR)Analyse_Predicated, \
                    IARG_UINT32, ins_type_index, \
                    IARG_UINT32, ins_mem_loads, \
                    IARG_UINT32, ins_mem_stores, \
                    IARG_UINT32, ins_mem_read_ops, \
                    IARG_UINT32, ins_mem_write_ops, \
                    IARG_UINT32, ins_max_bytes_touched, \
                    IARG_UINT32, ins_mem_acc, \
                    IARG_END \
                );
            }
            //Precomputing analysis results for the basic block
            else {
                bbl_ins_type_cnt[ins_type_index]++;
                bbl_ins_type_cnt[MEM_LOAD] += ins_mem_loads;
                bbl_ins_type_cnt[MEM_STORE] += ins_mem_stores;
                bbl_latency += (ins_mem_loads + ins_mem_stores) * MEM_LATENCY;
                bbl_latency++;
                bbl_memop_cnt[ins_mem_read_ops + ins_mem_write_ops]++;
                bbl_memopr_cnt[ins_mem_read_ops]++;
                bbl_memopw_cnt[ins_mem_write_ops]++;
                if ( ins_max_bytes_touched > bbl_max_bytes_touched )
                    bbl_max_bytes_touched = ins_max_bytes_touched;
                bbl_mem_acc += ins_mem_acc;
            }

        }
        BBL_InsertIfCall(bbl, IPOINT_BEFORE, (AFUNPTR) Terminate, IARG_END);
        BBL_InsertThenCall(bbl, IPOINT_BEFORE, MyExitRoutine, IARG_END);
        BBL_InsertIfCall(bbl, IPOINT_BEFORE, (AFUNPTR) FastForward, IARG_END);
        BBL_InsertThenCall( \
            bbl, IPOINT_BEFORE, (AFUNPTR)Bbl_Analysis, \
            IARG_PTR, bbl_ins_type_cnt, \
            IARG_UINT64, bbl_latency, 
            IARG_UINT32, BBL_NumIns(bbl), \
            IARG_ADDRINT, BBL_Address(bbl), \
            IARG_UINT32, BBL_Size(bbl), \
            IARG_PTR, bbl_ins_len_cnt, \
            IARG_PTR, bbl_op_cnt, \
            IARG_PTR, bbl_regr_cnt, \
            IARG_PTR, bbl_regw_cnt, \
            IARG_PTR, bbl_memop_cnt, \
            IARG_PTR, bbl_memopr_cnt, \
            IARG_PTR, bbl_memopw_cnt, \
            IARG_UINT32, bbl_mem_acc, \
            IARG_UINT32, bbl_max_bytes_touched, \
            IARG_ADDRINT, bbl_max_immediate, \
            IARG_ADDRINT, bbl_min_immediate, \
            IARG_END \
        );
        BBL_InsertCall(bbl, IPOINT_BEFORE, (AFUNPTR) InsCount, IARG_UINT32, BBL_NumIns(bbl), IARG_END);
    }
}

VOID Fini(INT32 code, VOID *v)
{
    cerr << "FINISHED\n" << endl;
    print_output();
}

INT32 Usage()
{
    PIN_ERROR("This Pintool prints the IPs of every instruction executed\n" 
              + KNOB_BASE::StringKnobSummary() + "\n");
    return -1;
}

int main(int argc, char * argv[])
{
    if (PIN_Init(argc, argv)) return Usage();
    
    string fileName = KnobOutputFile.Value();

    if (!fileName.empty()) {
        out = new std::ofstream(fileName.c_str());
    }

    fast_forward_count = 1000000000 * KnobFastForwardCount.Value();

    memset(insTypeCnt, 0, 17 * sizeof(UINT64));
    memset(insLenCnt, 0, 16*sizeof(UINT64));
    memset(insOpCnt, 0, 16*sizeof(UINT64));
    memset(insRegOpRCnt, 0, 16*sizeof(UINT64));
    memset(insRegOpWCnt, 0, 16*sizeof(UINT64));
    memset(insMemOpCnt, 0, 16*sizeof(UINT64));
    memset(insMemOpRCnt, 0, 16*sizeof(UINT64));
    memset(insMemOpWCnt, 0, 16*sizeof(UINT64));

    TRACE_AddInstrumentFunction(Trace, 0);

    PIN_AddFiniFunction(Fini, 0);

    cerr << "===============================================" << endl;
    cerr << "This application is instrumented by HW1" << endl;
    if (!KnobOutputFile.Value().empty())
    {
        cerr << "See file " << KnobOutputFile.Value() << " for analysis results" << endl;
    }
    cerr << "===============================================" << endl;

    PIN_StartProgram();
    
    return 0;
}