#include "pin.H"
#include <iostream>
#include <fstream>
#include <cstdlib>

using std::cerr;
using std::endl;

#define BILLION 1000000000

std::ostream* out = &cerr;
UINT64 fastForwardIns; // number of instruction to fast forward
UINT64 maxIns; // maximum number of instructions to simulate
UINT64 icount = 0; //number of dynamically executed instructions

KNOB< std::string > KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "HW1.out", "specify file name for HW1 output");
KNOB< UINT64 > KnobFastForwardCount(KNOB_MODE_WRITEONCE, "pintool", "f", "0", "Number of instructions to fast forward");

UINT64 x = 0;
int ctr = 0;
//Fast-forward logic
VOID InsCount(void)
{
    if ( x>=BILLION ){
        ctr++;
        cerr << "COUNT = " << ctr << endl;
        x = 0;
    }
    x++;
	icount++;
}

ADDRINT FastForward(void)
{
	return (icount >= fastForwardIns && icount < maxIns);
}

ADDRINT Terminate(void)
{
    return (icount >= maxIns);
}

void MyExitRoutine() {
    *out << "Total ins = " << icount << endl;
    exit(0);
}

// Print a memory read record
VOID RecordMemRead(VOID * addr, UINT32 size)
{
    *out << (ADDRINT)addr << " " << size << "\n";
}

// Print a memory write record
VOID RecordMemWrite(VOID * addr, UINT32 size)
{
    *out << (ADDRINT)addr << " " << size << "\n";
}

// Is called for every instruction and instruments reads and writes
VOID Instruction(INS ins, VOID *v)
{
    // Instruments memory accesses using a predicated call, i.e.
    // the instrumentation is called iff the instruction will actually be executed.
    //
    // On the IA-32 and Intel(R) 64 architectures conditional moves and REP 
    // prefixed instructions appear as predicated instructions in Pin.
    INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR) Terminate, IARG_END);
    INS_InsertThenCall(ins, IPOINT_BEFORE, (AFUNPTR) MyExitRoutine, IARG_END);
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) InsCount, IARG_END);

    UINT32 memOperands = INS_MemoryOperandCount(ins);

    // Iterate over each memory operand of the instruction.
    for (UINT32 memOp = 0; memOp < memOperands; memOp++)
    {
        if (INS_MemoryOperandIsRead(ins, memOp))
        {
            INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR) FastForward, IARG_END);
            INS_InsertThenPredicatedCall(
                ins, IPOINT_BEFORE, (AFUNPTR)RecordMemRead,
                IARG_MEMORYOP_EA, memOp,
                IARG_UINT32, INS_MemoryOperandSize(ins, memOp),
                IARG_END);
        }
        // Note that in some architectures a single memory operand can be 
        // both read and written (for instance incl (%eax) on IA-32)
        // In that case we instrument it once for read and once for write.
        if (INS_MemoryOperandIsWritten(ins, memOp))
        {
            INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR) FastForward, IARG_END);
            INS_InsertThenPredicatedCall(
                ins, IPOINT_BEFORE, (AFUNPTR)RecordMemWrite,
                IARG_MEMORYOP_EA, memOp,
                IARG_UINT32, INS_MemoryOperandSize(ins, memOp),
                IARG_END);
        }
    }
}

VOID Fini(INT32 code, VOID *v)
{
    cerr << "FINISHED" << endl;
}

/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */
   
INT32 Usage()
{
    PIN_ERROR( "This Pintool prints a trace of memory addresses\n" 
              + KNOB_BASE::StringKnobSummary() + "\n");
    return -1;
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int main(int argc, char *argv[])
{
    if (PIN_Init(argc, argv)) return Usage();

    fastForwardIns = KnobFastForwardCount.Value() * BILLION;
	maxIns = fastForwardIns + BILLION;
    std::string fileName = KnobOutputFile.Value();

    if (!fileName.empty()) {
        out = new std::ofstream(fileName.c_str());
    }

    INS_AddInstrumentFunction(Instruction, 0);
    PIN_AddFiniFunction(Fini, 0);

    // Never returns
    PIN_StartProgram();
    
    return 0;
}
