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

void test_euclid_dist_circuit(e_role role, const std::string &address, uint16_t port, uint32_t nvals, seclvl seclvl,
                              uint32_t bitlen, uint32_t nthreads, e_mt_gen_alg mt_alg, e_sharing sharing)
{
    //常规内容
    ABYParty *party = new ABYParty(role, address, port, seclvl, bitlen, nthreads, mt_alg);
    std::vector<Sharing *> &sharings = party->GetSharings();
    // ArithmeticCircuit *ac = (ArithmeticCircuit *)sharings[sharing]->GetCircuitBuildRoutine();
    ArithmeticCircuit *ac = (ArithmeticCircuit *)sharings[S_ARITH]->GetCircuitBuildRoutine();
    Circuit *yc = sharings[S_YAO]->GetCircuitBuildRoutine();
    BooleanCircuit *bc = (BooleanCircuit *)sharings[S_BOOL]->GetCircuitBuildRoutine();
    srand((unsigned)100);
    uint64_t res = 0, oldRes = 0;
    int runtime = 10000, counts = 0;
    for (int i = 0; i < runtime; i++)
    {
        share *s_cx, *s_cy, *s_dx, *s_dy;
        share *s_cx_b, *s_cy_b, *s_dx_b, *s_dy_b;
        share *check_sel, *check_sel_inv, *t_a, *t_b;
        share *t_a_b, *t_b_b;
        share *s_res, *out_res, *s_ans;
        uint64_t cx = 625431, cy = 843541;
        uint64_t dx = 322196, dy = 212754;
        s_cx = ac->PutINGate(cx, bitlen, SERVER);
        s_cy = ac->PutINGate(cy, bitlen, SERVER);
        s_dx = ac->PutINGate(dx, bitlen, SERVER);
        s_dy = ac->PutINGate(dy, bitlen, SERVER);

        // s_cx_b = bc->PutINGate(cx, bitlen, SERVER);
        // s_cy_b = bc->PutINGate(cy, bitlen, SERVER);
        // s_dx_b = bc->PutINGate(dx, bitlen, SERVER);
        // s_dy_b = bc->PutINGate(dy, bitlen, SERVER);

        s_cx_b = bc->PutA2BGate(s_cx, yc);
        s_cy_b = bc->PutA2BGate(s_cy, yc);
        s_dx_b = bc->PutA2BGate(s_dx, yc);
        s_dy_b = bc->PutA2BGate(s_dy, yc);

        check_sel = bc->PutGTGate(s_cx_b, s_dx_b);
        check_sel_inv = bc->PutINVGate(check_sel);
        t_a_b = bc->PutMUXGate(s_cx_b, s_dx_b, check_sel);     //大的数
        t_b_b = bc->PutMUXGate(s_cx_b, s_dx_b, check_sel_inv); //小的数
        // std::cout << "t_a\t" << t_a->get_bitlength() << "\tt_b\t" << t_b->get_bitlength() << std::endl;
        //计算

        // bc->PutPrintValueGate(t_a_b, "t_a_b\t");
        // bc->PutPrintValueGate(t_b_b, "t_b_b\t");

        t_a = ac->PutB2AGate(t_a_b);
        t_b = ac->PutB2AGate(t_b_b);
        // ac->PutPrintValueGate(t_a, "t_a\t");
        // ac->PutPrintValueGate(t_b, "t_b\t");

        s_res = ac->PutSUBGate(t_a, t_b);
        // ac->PutPrintValueGate(s_res, "sub\t");
        s_res->set_max_bitlength(bitlen);
        // std::cout << "s_res\t" << s_res->get_bitlength() << std::endl;
        s_ans = ac->PutMULGate(s_res, s_res);
        // ac->PutPrintValueGate(s_ans, "mul\t");

        check_sel = bc->PutGTGate(s_cy_b, s_dy_b);
        check_sel_inv = bc->PutINVGate(check_sel);
        t_a_b = bc->PutMUXGate(s_cy_b, s_dy_b, check_sel);     //大的数
        t_b_b = bc->PutMUXGate(s_cy_b, s_dy_b, check_sel_inv); //小的数
        // std::cout << "t_a\t" << t_a->get_bitlength() << "\tt_b\t" << t_b->get_bitlength() << std::endl;
        //计算
        // bc->PutPrintValueGate(t_a_b, "t_a_b\t");
        // bc->PutPrintValueGate(t_b_b, "t_b_b\t");

        t_a = ac->PutB2AGate(t_a_b);
        t_b = ac->PutB2AGate(t_b_b);
        // ac->PutPrintValueGate(t_a, "t_a\t");
        // ac->PutPrintValueGate(t_b, "t_b\t");

        s_res = ac->PutSUBGate(t_a, t_b);
        // ac->PutPrintValueGate(s_res, "sub\t");
        s_res->set_max_bitlength(bitlen);
        // std::cout << "s_res\t" << s_res->get_bitlength() << std::endl;
        s_res = ac->PutMULGate(s_res, s_res);
        // ac->PutPrintValueGate(s_res, "mul\t");

        s_ans = ac->PutADDGate(s_ans, s_res);
        // ac->PutPrintValueGate(s_ans, "add\t");

        out_res = ac->PutOUTGate(s_ans, ALL);
        party->ExecCircuit();
        res = out_res->get_clear_value<uint64_t>();
        // std::cout << "res:\t" << res << std::endl;
        std::cout << (float)i / runtime * 100 << "%\r" << std::flush; //进度条
        // std::cout << "The result is:\t" << res << std::endl;
        if (i && res != oldRes)
            counts++;
        else
            oldRes = res;
        party->Reset();
    }
    delete party;
    std::cout << "The result is:\t" << counts << std::endl;
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

    test_euclid_dist_circuit(role, address, port, nvals, seclvl, bitlen, nthreads, mt_alg, S_ARITH);
    end = clock();
    clock_t remain = (double)(end - start) / CLOCKS_PER_SEC;
    std::cout << "remain " << end - start << "clocks" << std::endl;
    std::cout << "Total time is " << remain / 60 << "m " << remain % 60 << "s" << std::endl;
    return 0;
}