#include <ENCRYPTO_utils/crypto/crypto.h>
#include <ENCRYPTO_utils/parse_options.h>

#include <abycore/aby/abyparty.h>

#include <abycore/circuit/booleancircuits.h>
#include <abycore/circuit/arithmeticcircuits.h>
#include <abycore/circuit/circuit.h>

#include <abycore/sharing/sharing.h>

#include <iostream>
#include <math.h>
#include <cassert>
#include <string>
#include <vector>

#define ALICE "ALICE"
#define BOB "BOB"

int32_t read_test_options(int32_t *argcp, char ***argvp, e_role *role,
                          uint32_t *bitlen, uint32_t *nvals, uint32_t *secparam, std::string *address,
                          uint16_t *port)
{
    uint32_t int_role = 0, int_money = 0, int_port = 0;
    parsing_ctx options[] =
        {
            {(void *)&int_role, T_NUM, "r", "Role: 0/1", true, false},
            {(void *)nvals, T_NUM, "n", "Number of parallel operation elements", false, false},
            {(void *)bitlen, T_NUM, "b", "Bit-length, default 32", false, false},
            {(void *)secparam, T_NUM, "s", "Symmetric Security Bits, default: 128", false, false},
            {(void *)address, T_STR, "a", "IP-address, default: localhost", false, false},
            {(void *)&int_port, T_NUM, "p", "Port, default: 7766", false, false}};

    if (!parse_options(argcp, argvp, options,
                       sizeof(options) / sizeof(parsing_ctx)))
    {
        print_usage(*argvp[0], options, sizeof(options) / sizeof(parsing_ctx));
        std::cout << "Exiting" << std::endl;
        exit(0);
    }

    assert(int_role < 2);
    *role = (e_role)int_role;

    if (int_port != 0)
    {
        assert(int_port < 1 << (sizeof(uint16_t) * 8));
        *port = (uint16_t)int_port;
    }
    //delete options;

    return 1;
}

void test(e_role role, const std::string &address, uint16_t port, uint32_t nvals, seclvl seclvl,
          uint32_t bitlen, uint32_t nthreads, e_mt_gen_alg mt_alg, e_sharing sharing)
{
    /* //常规内容
    bitlen = 32;
    nvals = 4;
    ABYParty *party = new ABYParty(role, address, port, seclvl, bitlen, nthreads, mt_alg);
    std::vector<Sharing *> &sharings = party->GetSharings();
    // ArithmeticCircuit *ac = (ArithmeticCircuit *)sharings[sharing]->GetCircuitBuildRoutine();
    ArithmeticCircuit *ac = (ArithmeticCircuit *)sharings[S_ARITH]->GetCircuitBuildRoutine();
    Circuit *yc = sharings[S_YAO]->GetCircuitBuildRoutine();
    BooleanCircuit *bc = (BooleanCircuit *)sharings[S_BOOL]->GetCircuitBuildRoutine();
    uint32_t in_1[nvals] = {1, 1, 1, 1}, in_2 = 2, zero = 0;
    share *s_in_1 = ac->PutSIMDINGate(nvals, in_1, bitlen, SERVER);
    // ac->PutPrintValueGate(s_in_1, "s_in_1");
    // share *s_in_2 = ac->PutINGate(in_2, bitlen, SERVER);
    share *s_ans = ac->PutSIMDCONSGate(nvals, zero, bitlen);
    // ac->PutPrintValueGate(s_ans,"s_ans");
    for (int i = 0; i < 5; i++)
    {
        share *s_temp = ac->PutADDGate(s_ans, s_in_1);
        share *s_delete = s_ans;
        delete s_delete;
        s_ans = s_temp;
        // s_ans = ac->PutADDGate(s_ans, s_in_1);
    }
    // std::cout << "s_ans: " << s_ans << std::endl;
    share *s_out = ac->PutOUTGate(s_ans, ALL);
    party->ExecCircuit();
    uint32_t out_bitlen, out_nvals;
    uint32_t *output;
    s_out->get_clear_value_vec(&output, &out_bitlen, &out_nvals);
    for (int i = 0; i < out_nvals; i++)
        printf("ans%d:%u\n", i, output[i]);
    printf("memery leak test done.\n");
    delete s_in_1;
    // delete s_in_2;
    delete s_ans;
    // delete s_temp;
    delete s_out;
    delete party; 
    free(output);*/

    int cluster = 2, dimension = 2;
    std::vector<std::vector<uint64_t>> centers;    //质心向量
    std::vector<std::vector<uint64_t>> oldCenters; //上一轮的质心向量
    for (int i = 0; i < cluster; i++)
    { //初始化填充
        std::vector<uint64_t> temp1(dimension, 0);
        std::vector<uint64_t> temp2(dimension, 0);
        centers.push_back(temp1);
        oldCenters.push_back(temp2);
    }
    for (int iC = 0; iC < cluster; iC++)
        for (int iD = 0; iD < dimension; iD++)
            printf("%lu ", centers[iC][iD]);
    // centers.clear();
    // oldCenters.clear();
    printf("memery leak test done.\n");
}

int main(int argc, char **argv)
{
    clock_t start, end;
    start = clock();
    e_role role;
    uint32_t bitlen = 64, nvals = 2, secparam = 128, nthreads = 1;
    uint16_t port = 7766;
    std::string address = "127.0.0.1";
    int32_t test_op = -1;
    e_mt_gen_alg mt_alg = MT_OT;
    read_test_options(&argc, &argv, &role, &bitlen, &nvals, &secparam, &address,
                      &port);
    seclvl seclvl = get_sec_lvl(secparam);
    test(role, address, port, nvals, seclvl, bitlen, nthreads, mt_alg, S_ARITH);
    end = clock();
    clock_t remain = (double)(end - start) / CLOCKS_PER_SEC;
    std::cout << "remain " << end - start << "clocks" << std::endl;
    std::cout << "Total time is " << remain / 60 << "m " << remain % 60 << "s" << std::endl;
    return 0;
}