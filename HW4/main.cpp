#include <fstream>
#include "cache.h"

u64 clk = 0;

int main(int argc, char** argv) {

    if( argc < 2 ) {
        std::cout << "Usage: " << __FILE__ << " <memory trace file path>\n";
        exit(0);
    }

    Cache* L1 = (Cache*) malloc(sizeof(Cache) * MAX_POLICY);
    Cache* L2 = (Cache*) malloc(sizeof(Cache) * MAX_POLICY);
    for ( int i = 0; i < MAX_POLICY; i++ ) {
        L1[i] = Cache(8, 64, 64, Replace_Policy[LRU]);
        L2[i] = Cache(16, 64, 1024, Replace_Policy[i]);
    }

    std::ifstream trace;
    trace.open(argv[1]);
    if ( trace.rdstate() & std::ifstream::failbit ) {
        std::cerr << "Error opening " << argv[1] << std::endl;
        return 0;
    }

    char buff[128];
    long unsigned int addr;
    int opsize;
    trace.getline(buff, 128);

    while ( !(trace.rdstate() & std::ifstream::eofbit) ) {
        sscanf(buff, "%lu %d\n", &addr, &opsize);

        for ( int i = 0; i < MAX_POLICY; i++ ) {
            Inclusion_Policy(&L1[i], &L2[i], addr, opsize, clk);
        }
        clk++;

        trace.getline(buff, 128);
    }

    for ( int i = 0; i < MAX_POLICY; i++ ) {
        std::cout << policy_name[i] << "---------------------------------\n";
        std::cout << "------L1------\n";
        Print_Stats(&L1[i]);
        std::cout << "------L2------\n";
        Print_Stats(&L2[i]);
        std::cout << "--------------------------------------\n";
    }

    return 0;
}