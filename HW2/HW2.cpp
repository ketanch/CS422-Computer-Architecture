#include "pin.H"
#include <iostream>
#include <fstream>
#include <time.h>

using std::cerr;
using std::string;
using std::endl;
std::ostream* out = &cerr;

typedef unsigned long ULONG;
enum {
    SAg, GAg, GSHARE
};

#define INS_TO_ANALYSE 1000000000
#define NOT_TAKEN 0
#define TAKEN 1
#define power_2(x) (1 << (x))

#define BIMODAL_PHT_SIZE 512
#define BIMODAL_PHT_WIDTH 2

#define SAG_BHT_WIDTH 9
#define SAG_BHT_SIZE 1024
#define SAG_PHT_SIZE power_2(SAG_BHT_WIDTH)
#define SAG_PHT_WIDTH 2

#define GAG_GHR_WIDTH 9
#define GAG_PHT_SIZE power_2(GAG_GHR_WIDTH)
#define GAG_PHT_WIDTH 3

#define GSHARE_GHR_WIDTH 9
#define GSHARE_PHT_SIZE power_2(GAG_GHR_WIDTH)
#define GSHARE_PHT_WIDTH 3

#define HYBRID_PHT_WIDTH 2

#define BTB_SET_BITS 7
#define BTB_TOTAL_SETS power_2(BTB_SET_BITS)
#define BTB_SET_ASSOSIATIVITY 4
#define BTB_TOTAL_ENTRIES (BTB_TOTAL_SETS * BTB_SET_ASSOSIATIVITY)

#define BTB_PRED2_GHR_WIDTH 7

class Predictor_FNBT {
public:
    UINT64 mispredicted;
    UINT64 total_predicted;

    Predictor_FNBT() {
        mispredicted = 0;
        total_predicted = 0;
    }

    void update(bool is_taken, bool is_fwd_br) {
        total_predicted++;
        if ( (is_taken && is_fwd_br) || (!is_taken && !is_fwd_br) ) {
            mispredicted++;
        }
    }

};

class PHT_Counter {
public:
    ULONG ctr;
    int bits_len;

    PHT_Counter( int ctr_bits_len, ULONG initial_ctr ) {
        bits_len = ctr_bits_len;
        ctr = initial_ctr;
    }

    void update_counter(bool inc) {
        if ( inc ) {
            ULONG upp_bound = (ULONG) power_2(bits_len) - 1;
            if ( ctr >= upp_bound ) return;
            ctr++;
        }
        else {
            if ( ctr == 0 ) return;
            ctr--;
        }
    }

    bool predict() {
        ULONG midpoint = (ULONG) power_2(bits_len-1);
        if ( ctr < midpoint ) return NOT_TAKEN;
        return TAKEN;
    }

};

class BHT_History_Register {
public:
    ULONG history;
    int bits_len;

    BHT_History_Register( int bht_bits_len ) {
        history = 0;
        bits_len = bht_bits_len;
    }

    void update_history(bool result) {
        ULONG max_history = (ULONG) power_2(bits_len) - 1;
        history = ((history << 1) | result ) & max_history;
    }
};

class Predictor_Bimodal {
public:
    PHT_Counter* pht_ctrs = (PHT_Counter*) malloc(sizeof(PHT_Counter) * BIMODAL_PHT_SIZE);
    UINT64 mispredicted;
    UINT64 total_predicted;
    
    Predictor_Bimodal( int initial_ctr_val ) {
        for ( int i = 0; i < BIMODAL_PHT_SIZE; i++ ) {
            pht_ctrs[i] = PHT_Counter(BIMODAL_PHT_WIDTH, initial_ctr_val);
        }
    }

    void update(ADDRINT ins_ptr, bool result) {
        int index = ins_ptr % BIMODAL_PHT_SIZE;
        total_predicted++;
        if ( result != this->predict(ins_ptr) ) {
            mispredicted++;
        }
        pht_ctrs[index].update_counter(result);
    }

    bool predict(ADDRINT ins_ptr) {
        int index = ins_ptr % BIMODAL_PHT_SIZE;
        return pht_ctrs[index].predict();
    }

};

class Predictor_SAg {
public:
    PHT_Counter* pht_ctrs = (PHT_Counter*) malloc(sizeof(PHT_Counter) * SAG_PHT_SIZE);
    BHT_History_Register* bht_registers = (BHT_History_Register*) malloc(sizeof(BHT_History_Register) * SAG_BHT_SIZE);
    UINT64 mispredicted;
    UINT64 total_predicted;

    Predictor_SAg( int initial_ctr_val ) {
        mispredicted = 0;
        total_predicted = 0;
        for ( int i = 0; i < SAG_PHT_SIZE; i++ ) {
            pht_ctrs[i] = PHT_Counter(SAG_PHT_WIDTH, initial_ctr_val);
        }

        for ( int i = 0; i < SAG_BHT_SIZE; i++ ) {
            bht_registers[i] = BHT_History_Register(SAG_BHT_WIDTH);
        }

    }

    void update(ADDRINT ins_ptr, bool result) {
        int index = ins_ptr % SAG_BHT_SIZE;
        total_predicted++;
        if ( result != this->predict(ins_ptr) ) {
            mispredicted++;
        }
        int pht_index = bht_registers[index].history % SAG_PHT_SIZE;
        pht_ctrs[pht_index].update_counter(result);
        bht_registers[index].update_history(result);
    }

    bool predict(ADDRINT ins_ptr) {
        int index = ins_ptr % SAG_BHT_SIZE;
        return pht_ctrs[bht_registers[index].history % SAG_PHT_SIZE].predict();
    }

};

class Predictor_GAg {
public:
    PHT_Counter* pht_ctrs = (PHT_Counter*) malloc(sizeof(PHT_Counter) * GAG_PHT_SIZE);
    BHT_History_Register* ghr_register;
    UINT64 mispredicted;
    UINT64 total_predicted;

    Predictor_GAg( int initial_ctr_val ) {
        mispredicted = 0;
        total_predicted = 0;
        ghr_register = new BHT_History_Register(GAG_GHR_WIDTH);

        for ( int i = 0; i < GAG_PHT_SIZE; i++ ) {
            pht_ctrs[i] = PHT_Counter(GAG_PHT_WIDTH, initial_ctr_val);
        }
    }

    void update(bool result) {
        total_predicted++;
        if ( result != this->predict()) {
            mispredicted++;
        }
        pht_ctrs[ghr_register->history % GAG_PHT_SIZE].update_counter(result);
        ghr_register->update_history(result);
    }

    bool predict() {
        return pht_ctrs[ghr_register->history % GAG_PHT_SIZE].predict();
    }

};

class Predictor_gshare {
public:
    PHT_Counter* pht_ctrs = (PHT_Counter*) malloc(sizeof(PHT_Counter) * GSHARE_PHT_SIZE);
    BHT_History_Register* ghr_register;
    UINT64 mispredicted;
    UINT64 total_predicted;

    Predictor_gshare( int initial_ctr_val ) {
        mispredicted = 0;
        total_predicted = 0;
        ghr_register = new BHT_History_Register(GSHARE_GHR_WIDTH);

        for ( int i = 0; i < GSHARE_PHT_SIZE; i++ ) {
            pht_ctrs[i] = PHT_Counter(GSHARE_PHT_WIDTH, initial_ctr_val);
        }
    }

    void update(ADDRINT ins_ptr, bool result) {
        total_predicted++;
        if ( result != this->predict(ins_ptr) ) {
            mispredicted++;
        }
        int pht_index = (ghr_register->history ^ ins_ptr) % GSHARE_PHT_SIZE;
        pht_ctrs[pht_index].update_counter(result);
        ghr_register->update_history(result);
    }

    bool predict(ADDRINT ins_ptr) {
        return pht_ctrs[(ghr_register->history ^ ins_ptr) % GSHARE_PHT_SIZE].predict();
    }

};

class Predictor_Hybrid_All {
public:
    Predictor_SAg* p_sag;
    Predictor_GAg* p_gag;
    Predictor_gshare* p_gshare;
    PHT_Counter* pht_ctrs_sg = (PHT_Counter*) malloc(sizeof(PHT_Counter) * GAG_PHT_SIZE);
    PHT_Counter* pht_ctrs_ggsh = (PHT_Counter*) malloc(sizeof(PHT_Counter) * GAG_PHT_SIZE);
    PHT_Counter* pht_ctrs_gshs = (PHT_Counter*) malloc(sizeof(PHT_Counter) * GAG_PHT_SIZE);
    UINT64 mispredicted_maj;
    UINT64 mispredicted_sag_gag;
    UINT64 mispredicted_tournament;
    UINT64 total_predicted;

    Predictor_Hybrid_All(Predictor_SAg* sag, Predictor_GAg* gag, Predictor_gshare* gs, int initial_ctr_val) {
        mispredicted_maj = 0;
        mispredicted_sag_gag = 0;
        mispredicted_tournament = 0;
        total_predicted = 0;
        p_sag = sag;
        p_gag = gag;
        p_gshare = gs;

        for ( int i = 0; i < GAG_PHT_SIZE; i++ ) {
            pht_ctrs_sg[i] = PHT_Counter(HYBRID_PHT_WIDTH, initial_ctr_val);
            pht_ctrs_ggsh[i] = PHT_Counter(HYBRID_PHT_WIDTH, initial_ctr_val);
            pht_ctrs_gshs[i] = PHT_Counter(HYBRID_PHT_WIDTH, initial_ctr_val);
        }
    }

    void update(ADDRINT ins_ptr, bool result) {
        total_predicted++;
        bool pred_sag = p_sag->predict(ins_ptr);
        bool pred_gag = p_gag->predict();
        bool pred_gshare = p_gshare->predict(ins_ptr);
        bool majority = (pred_sag + pred_gag + pred_gshare) / 2;
        if ( majority != result ) {
            mispredicted_maj++;
        }

        ASSERT(p_gag->ghr_register->history % GAG_PHT_SIZE == p_gshare->ghr_register->history % GAG_PHT_SIZE, "GAg and gshare history not same");
        int index = p_gag->ghr_register->history % GAG_PHT_SIZE;
        bool multiplex_inp;
        bool final_prediction;

        //SAg GAg winner
        multiplex_inp = pht_ctrs_sg[index].predict();
        bool sag_gag_prediction = (multiplex_inp & pred_gag) | ((!multiplex_inp) & pred_sag);
        int W = (multiplex_inp & GAg) | ((!multiplex_inp) & SAg);
        if ( sag_gag_prediction != result ) {
            mispredicted_sag_gag++;
        }

        //GAg gshare winner
        multiplex_inp = pht_ctrs_ggsh[index].predict();
        bool W2 = (multiplex_inp & pred_gshare) | ((!multiplex_inp) & pred_gag);

        //gshare SAg winner
        multiplex_inp = pht_ctrs_gshs[index].predict();
        bool W3 = (multiplex_inp & pred_sag) | ((!multiplex_inp) & pred_gshare);

        if ( W == SAg ) {
            final_prediction = W3;
        }
        else {
            final_prediction = W2;
        }
        if (final_prediction != result) {
            mispredicted_tournament++;
        }

        if ( pred_sag != pred_gag )
            pht_ctrs_sg[index].update_counter(pred_sag ^ result);
        if ( pred_gag != pred_gshare )
            pht_ctrs_ggsh[index].update_counter(pred_gag ^ result);
        if ( pred_gshare != pred_sag )
            pht_ctrs_gshs[index].update_counter(pred_gshare ^ result);

    }

}; 

typedef struct {
    ADDRINT target;
    ADDRINT tag;
    time_t ref_time;
    bool is_valid;
} BTB_Entry;

class BTBBuffer {
public:
    BTB_Entry** btb_entry;
    BTB_Entry** btb_entry_ad;
    BHT_History_Register* btb_ghr;
    UINT64 total_predicted;
    UINT64 cache_miss;
    UINT64 mispredicted;
    UINT64 cache_miss_ad;
    UINT64 mispredicted_ad;

    BTBBuffer(BHT_History_Register* ghr_reg) {
        cache_miss = 0;
        total_predicted = 0;
        mispredicted = 0;
        cache_miss_ad = 0;
        mispredicted_ad = 0;
        btb_ghr = ghr_reg;

        btb_entry = (BTB_Entry**) malloc( BTB_TOTAL_ENTRIES * sizeof(BTB_Entry*));
        for ( int i = 0; i < BTB_TOTAL_ENTRIES; i++) {
            btb_entry[i] = (BTB_Entry*) malloc(sizeof(BTB_Entry));
            memset(btb_entry[i], 0, sizeof(BTB_Entry));
        }

        btb_entry_ad = (BTB_Entry**) malloc( BTB_TOTAL_ENTRIES * sizeof(BTB_Entry*));
        for ( int i = 0; i < BTB_TOTAL_ENTRIES; i++) {
            btb_entry_ad[i] = (BTB_Entry*) malloc(sizeof(BTB_Entry));
            memset(btb_entry_ad[i], 0, sizeof(BTB_Entry));
        }

    }

    ADDRINT predict(ADDRINT ins_ptr, ADDRINT next_ins_ptr) {
        int set_index = ins_ptr % BTB_TOTAL_SETS;
        ADDRINT temp_tag = ins_ptr >> BTB_SET_BITS;
        for ( int i = 0; i < BTB_SET_ASSOSIATIVITY; i++ ) {
            BTB_Entry* temp_entry = btb_entry[BTB_SET_ASSOSIATIVITY * set_index + i];
            if ( temp_entry->is_valid && temp_entry->tag == temp_tag ) {
                return temp_entry->target;
            }
        }
        this->cache_miss++;
        return next_ins_ptr;
    }

    void update(ADDRINT ins_ptr, ADDRINT next_ins_ptr, ADDRINT target, bool is_taken) {
        total_predicted++;
        UINT64 temp_cache_miss = cache_miss;
        if ( target != this->predict(ins_ptr, next_ins_ptr) ) {
            mispredicted++;
        }
        bool is_cache_miss = cache_miss > temp_cache_miss;

        if ( is_cache_miss && !is_taken ) return;

        int set_index = ins_ptr % BTB_TOTAL_SETS;
        ADDRINT temp_tag = ins_ptr >> BTB_SET_BITS;
        int index;
        time_t min_time = INT32_MAX;
        for ( int i = 0; i < BTB_SET_ASSOSIATIVITY; i++ ) {
            BTB_Entry* temp_entry = btb_entry[BTB_SET_ASSOSIATIVITY * set_index + i];
            if ( is_cache_miss && !temp_entry->is_valid ) {
                index = BTB_SET_ASSOSIATIVITY * set_index + i;
                break;
            }
            if ( temp_entry->tag == temp_tag  ) {
                if ( !is_taken )
                    temp_entry->is_valid = false;
                else
                    temp_entry->target = target;
                return;
            }
            else {
                if ( temp_entry->ref_time < min_time ) {
                    index = BTB_SET_ASSOSIATIVITY * set_index + i;
                    min_time = temp_entry->ref_time;
                }
            }
        }
        btb_entry[index]->is_valid = true;
        btb_entry[index]->ref_time = time(NULL);
        btb_entry[index]->tag = temp_tag;
        btb_entry[index]->target = target;
    }

    ADDRINT predict_ad(ADDRINT ins_ptr, ADDRINT next_ins_ptr) {
        UINT32 history = btb_ghr->history & (power_2(BTB_PRED2_GHR_WIDTH)-1);
        UINT32 set_index = ( history ^ ins_ptr ) & (power_2(BTB_PRED2_GHR_WIDTH)-1) ;
        ADDRINT temp_tag = ins_ptr;
        for ( int i = 0; i < BTB_SET_ASSOSIATIVITY; i++ ) {
            BTB_Entry* temp_entry = btb_entry_ad[BTB_SET_ASSOSIATIVITY * set_index + i];
            if ( temp_entry->is_valid && temp_entry->tag == temp_tag ) {
                return temp_entry->target;
            }
        }
        this->cache_miss_ad++;
        return next_ins_ptr;
    }

    void update_ad(ADDRINT ins_ptr, ADDRINT next_ins_ptr, ADDRINT target, bool is_taken) {
        UINT64 temp_cache_miss_ad = cache_miss_ad;
        if ( target != this->predict_ad(ins_ptr, next_ins_ptr) ) {
            mispredicted_ad++;
        }
        bool is_cache_miss_ad = cache_miss_ad > temp_cache_miss_ad;

        if ( is_cache_miss_ad && !is_taken ) return;

        UINT32 history = btb_ghr->history & (power_2(BTB_PRED2_GHR_WIDTH)-1);
        UINT32 set_index = (history ^ ins_ptr) & (power_2(BTB_PRED2_GHR_WIDTH)-1);
        ADDRINT temp_tag = ins_ptr;
        int index;
        time_t min_time = INT32_MAX;
        for ( int i = 0; i < BTB_SET_ASSOSIATIVITY; i++ ) {
            BTB_Entry* temp_entry = btb_entry_ad[BTB_SET_ASSOSIATIVITY * set_index + i];
            if ( is_cache_miss_ad && !temp_entry->is_valid ) {
                index = BTB_SET_ASSOSIATIVITY * set_index + i;
                break;
            }
            if ( temp_entry->tag == temp_tag  ) {
                if ( !is_taken )
                    temp_entry->is_valid = false;
                else
                    temp_entry->target = target;
                return;
            }
            else {
                if ( temp_entry->ref_time < min_time ) {
                    index = BTB_SET_ASSOSIATIVITY * set_index + i;
                    min_time = temp_entry->ref_time;
                }
            }
        }
        btb_entry_ad[index]->is_valid = true;
        btb_entry_ad[index]->ref_time = time(NULL);
        btb_entry_ad[index]->tag = temp_tag;
        btb_entry_ad[index]->target = target;
    }

};

Predictor_FNBT pred_fnbt;
Predictor_Bimodal pred_bimodal(0);
Predictor_SAg pred_sag(0);
Predictor_GAg pred_gag(0);
Predictor_gshare pred_gshare(0);
Predictor_Hybrid_All pread_hdb_all(&pred_sag, &pred_gag, &pred_gshare, 0);
BTBBuffer btb_cache(pred_gag.ghr_register);

static UINT64 fast_forward_count = 0;         //Fast forward count
static UINT64 icount = 0;                     //Total instructions executed

KNOB< string > KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "A.out", "specify file name for HW1 output");
KNOB< UINT64 > KnobFastForwardCount(KNOB_MODE_WRITEONCE, "pintool", "f", "0", "Number of instructions to fast forward");

VOID InsCount() {
    icount++;
}

ADDRINT Terminate(void) {
    return (icount >= fast_forward_count + INS_TO_ANALYSE);
}

ADDRINT FastForward(void) {
    return (icount >= fast_forward_count && icount);
}

void print_output() {
    *out << "FNBT: Total = " << pred_fnbt.total_predicted << ", Mispredicted = " << pred_fnbt.mispredicted << "[" << (float)(pred_fnbt.mispredicted*100)/pred_fnbt.total_predicted << "%]\n" ;
    *out << "Bimodal: Total = " << pred_bimodal.total_predicted << ", Mispredicted = " << pred_bimodal.mispredicted << "[" << (float)(pred_bimodal.mispredicted*100)/pred_bimodal.total_predicted << "%]\n" ;
    *out << "SAg: Total = " << pred_sag.total_predicted << ", Mispredicted = " << pred_sag.mispredicted << "[" << (float)(pred_sag.mispredicted*100)/pred_sag.total_predicted << "%]\n" ;
    *out << "GAg: Total = " << pred_gag.total_predicted << ", Mispredicted = " << pred_gag.mispredicted << "[" << (float)(pred_gag.mispredicted*100)/pred_gag.total_predicted << "%]\n" ;
    *out << "gshare: Total = " << pred_gshare.total_predicted << ", Mispredicted = " << pred_gshare.mispredicted << "[" << (float)(pred_gshare.mispredicted*100)/pred_gshare.total_predicted << "%]\n" ;
    *out << "Hybrid SAg GAg: Total = " << pread_hdb_all.total_predicted << ", Mispredicted = " << pread_hdb_all.mispredicted_sag_gag << "[" << (float)(pread_hdb_all.mispredicted_sag_gag*100)/pread_hdb_all.total_predicted << "%]\n" ;
    *out << "Hybrid SAg GAg gshare majority: Total = " << pread_hdb_all.total_predicted << ", Mispredicted = " << pread_hdb_all.mispredicted_maj << "[" << (float)(pread_hdb_all.mispredicted_maj*100)/pread_hdb_all.total_predicted << "%]\n" ;
    *out << "Hybrid SAg GAg gshare tournament: Total = " << pread_hdb_all.total_predicted << ", Mispredicted = " << pread_hdb_all.mispredicted_tournament << "[" << (float)(pread_hdb_all.mispredicted_tournament*100)/pread_hdb_all.total_predicted << "%]\n" ;
    *out << "BTB(PC indexed): Total = " << btb_cache.total_predicted << ", Mispredicted = " << btb_cache.mispredicted << "[" << (float)(btb_cache.mispredicted*100)/btb_cache.total_predicted << "%]" << ", Cache miss = " << btb_cache.cache_miss << "\n" ;
    *out << "BTB Ad(PC indexed): Total = " << btb_cache.total_predicted << ", Mispredicted = " << btb_cache.mispredicted_ad << "[" << (float)(btb_cache.mispredicted_ad*100)/btb_cache.total_predicted << "%]" << ", Cache miss = " << btb_cache.cache_miss_ad << endl ;
}

void MyExitRoutine() {
    print_output();
    exit(0);
}

VOID MakePrediction( ADDRINT current_addr, ADDRINT target_addr, bool is_branch_taken ) {
    bool is_fwd_br = target_addr > current_addr;
    //if ( current_addr != 4198749 ) return;
    //*out << current_addr << " " << target_addr << " " << is_branch_taken << endl ;
    pred_fnbt.update(is_branch_taken, is_fwd_br);
    pred_bimodal.update(current_addr, is_branch_taken);
    pread_hdb_all.update(current_addr, is_branch_taken);
    pred_sag.update(current_addr, is_branch_taken);
    pred_gag.update(is_branch_taken);
    pred_gshare.update(current_addr, is_branch_taken);
}

VOID MakeBTBPrediction( ADDRINT current_addr, ADDRINT target_addr, UINT32 ins_size, bool is_branch_taken ) {
    ADDRINT actual_target;
    ADDRINT next_addr = current_addr + ins_size;
    if ( is_branch_taken ) actual_target = target_addr;
    else actual_target = next_addr;
    btb_cache.update(current_addr, next_addr, actual_target, is_branch_taken);
    btb_cache.update_ad(current_addr, next_addr, actual_target, is_branch_taken);
}

VOID Instruction(INS ins, VOID* v) {
    INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR) Terminate, IARG_END);
    INS_InsertThenCall(ins, IPOINT_BEFORE, (AFUNPTR) MyExitRoutine, IARG_END);

    if ( INS_Category(ins) == XED_CATEGORY_COND_BR ) {
        INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR) FastForward, IARG_END);
        INS_InsertThenPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) MakePrediction, IARG_INST_PTR, IARG_BRANCH_TARGET_ADDR, IARG_BRANCH_TAKEN, IARG_END);
    }

    if ( INS_IsIndirectControlFlow(ins) ) {
        INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR) FastForward, IARG_END);
        INS_InsertThenPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) MakeBTBPrediction,
                                IARG_INST_PTR,
                                IARG_BRANCH_TARGET_ADDR,
                                IARG_UINT32, INS_Size(ins),
                                IARG_BRANCH_TAKEN, IARG_END
                                );
    }
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) InsCount, IARG_END);

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

    INS_AddInstrumentFunction(Instruction, 0);

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