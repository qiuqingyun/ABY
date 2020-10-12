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
    //测试浮点数转换门

    uint32_t sum = 84543;
    uint32_t counts = 19;

    uint32_t shiftN = 20;
    counts = (float)pow((float)2,(float)shiftN) / counts*100;//将除数转换为倒数，放大为整数，放大倍数足够大保证精度
    share *s_sum = ac->PutINGate((uint64_t)sum, bitlen, SERVER);

    share *s_counts = ac->PutCONSGate((uint64_t)counts, bitlen);//将簇中数据点个数加密

    share *s_divAns = ac->PutMULGate(s_sum, s_counts);//乘法代替除法
    share *s_divAns_b = bc->PutA2BGate(s_divAns, yc);//转换为布尔电路
    share *s_shiftN = bc->PutINGate((uint64_t)shiftN, 64, SERVER);
    share *s_shiftedR = bc->PutBarrelRightShifterGate(s_divAns_b, s_shiftN);//对结果进行右移处理，保留小数点后两位
    share *s_out = bc->PutSharedOUTGate(s_shiftedR);//以share后的加密明文输出，保存结果
    party->ExecCircuit();
    uint64_t out = s_out->get_clear_value<uint64_t>();
    
    std::cout << "div_share:" << out << std::endl;
    /* srand((unsigned)100);
    uint64_t res = 0, oldRes = 0;
    nvals = 0; //数据个数
    int counts = 0;
    // uint64_t dx1 = 625431, dy1 = 843541;
    // uint64_t dx1 = 2, dy1 = 2;
    // uint64_t dx2 = 128461, dy2 = 245161;
    uint64_t center[2][2] = {{2000, 2000}, {8000, 8000}};

    std::vector<std::vector<uint64_t>> list;
    uint32_t dimension = 2;
    std::string path;
    if (role == SERVER)
    {
        path = "./ALICE";
    }
    else
    {
        path = "./BOB";
    }
    char *pathPtr = const_cast<char *>(path.c_str());
    FILE *fpIn = fopen(pathPtr, "r");
    if (!fpIn)
    {
        printf("error!\n");
        exit(0);
    }
    uint64_t inTemp;
    //读入数据
    for (int iD = 0; iD < dimension; iD++)
    { //list{[dimendion1],[dimendion2],...}
        std::vector<uint64_t> tempVector;
        list.push_back(tempVector);
    }
    while (fscanf(fpIn, "%lu", &inTemp) != EOF)
    {
        // uint64_t *node = (uint64_t *)malloc(sizeof(uint64_t) * dimension);
        // node[0] = inTemp;
        list[0].push_back(inTemp);
        for (int iD = 1; iD < dimension; iD++)
        {
            fscanf(fpIn, "%lu", &inTemp);
            list[iD].push_back(inTemp);
        }
        // list.push_back(node);
    }
    fclose(fpIn);

    nvals = list[0].size();
    uint64_t zero = 0, max = ULONG_MAX;
    share *s_ans[3];
    share *s_minDis_b = bc->PutSIMDCONSGate(nvals, max, bitlen);
    share *s_minIndex_b = bc->PutSIMDCONSGate(nvals, zero, bitlen);
    for (int iC = 0; iC < 2; iC++)
    {
        share *s_addAns_a = ac->PutSIMDCONSGate(nvals, zero, bitlen);
        for (int iD = 0; iD < dimension; iD++)
        { //对每个维度,(x2-x1)*(x2-x1)
            share *s_dataPoint_a = ac->PutSharedSIMDINGate(nvals, &list[iD][0], bitlen);
            share *s_centerPoint_a = ac->PutSIMDCONSGate(nvals, center[iC][iD], bitlen);
            share *s_dataPoint_b = bc->PutA2BGate(s_dataPoint_a, yc);
            share *s_centerPoint_b = bc->PutA2BGate(s_centerPoint_a, yc);

            //保证结果为正
            share *check_sel_b = bc->PutGTGate(s_dataPoint_b, s_centerPoint_b);             //BC
            share *check_sel_inv_b = bc->PutINVGate(check_sel_b);                           //BC
            share *t_a_b = bc->PutMUXGate(s_dataPoint_b, s_centerPoint_b, check_sel_b);     //大的数,BC
            share *t_b_b = bc->PutMUXGate(s_dataPoint_b, s_centerPoint_b, check_sel_inv_b); //小的数,BC

            //计算
            //B2A:t_a_a,t_b_a
            share *t_a_a = ac->PutB2AGate(t_a_b);
            share *t_b_a = ac->PutB2AGate(t_b_b);

            share *s_sub_a = ac->PutSUBGate(t_a_a, t_b_a); //AC,SUB

            share *s_sqr_a = ac->PutMULGate(s_sub_a, s_sub_a); //AC,MUL（有问题）

            //各维度累加
            s_addAns_a = ac->PutADDGate(s_addAns_a, s_sqr_a); //AC

            // share *s_mulAns_a = ac->PutMULGate(s_dataPoint_a, s_centerPoint_a);
            // s_addAns_a = ac->PutADDGate(s_addAns_a, s_mulAns_a);
        }

        share *s_index_b = bc->PutSIMDCONSGate(nvals, iC, bitlen); //BCin
        share *s_addAns_b = bc->PutA2BGate(s_addAns_a, yc);

        share *check_ans_b = bc->PutGTGate(s_addAns_b, s_minDis_b);          //BC
        s_minDis_b = bc->PutMUXGate(s_minDis_b, s_addAns_b, check_ans_b);    //小的数,BC
        s_minIndex_b = bc->PutMUXGate(s_minIndex_b, s_index_b, check_ans_b); //小的序号,BC
        s_ans[iC] = s_minDis_b;
        s_ans[2] = s_minIndex_b;
        // s_ans = s_minDis_b;
    }

    share *s_out1 = bc->PutOUTGate(s_ans[0], ALL);
    share *s_out2 = bc->PutOUTGate(s_ans[1], ALL);
    share *s_out3 = bc->PutOUTGate(s_ans[2], ALL);
    // share *s_out = bc->PutOUTGate(s_ans, ALL);

    party->ExecCircuit();
    uint32_t out_bitlen, out_nvals;
    uint32_t *output1, *output2,*output3;
    s_out1->get_clear_value_vec(&output1, &out_bitlen, &out_nvals);
    s_out2->get_clear_value_vec(&output2, &out_bitlen, &out_nvals);
    s_out3->get_clear_value_vec(&output3, &out_bitlen, &out_nvals);

    for (int i = 0; i < out_nvals; i++)
    {
        printf("No.%d:\t", i);
        printf("%u   \t   %u   \t   %u", output1[i], output2[i],output3[i]);
        printf("\n");
        // for (int j = 0; j < dimension; j++)
        // {
        //     printf("%lu\t", list[j][i]);
        // }
        // share *s_cx, *s_cy, *s_dx, *s_dy;
        // share *s_cx_b, *s_cy_b, *s_dx_b, *s_dy_b;
        // share *check_sel, *check_sel_inv, *t_a, *t_b;
        // share *t_a_b, *t_b_b;
        // share *s_res, *out_res, *s_ans;
        // // uint64_t cx = 625431, cy = 843541;
        // // uint64_t dx = 322196, dy = 212754;
        // s_cx = ac->PutINGate(cx, bitlen, SERVER);
        // s_cy = ac->PutINGate(cy, bitlen, SERVER);
        // s_dx = ac->PutINGate(dx, bitlen, SERVER);
        // s_dy = ac->PutINGate(dy, bitlen, SERVER);

        // // s_cx_b = bc->PutINGate(cx, bitlen, SERVER);
        // // s_cy_b = bc->PutINGate(cy, bitlen, SERVER);
        // // s_dx_b = bc->PutINGate(dx, bitlen, SERVER);
        // // s_dy_b = bc->PutINGate(dy, bitlen, SERVER);

        // s_cx_b = bc->PutA2BGate(s_cx, yc);
        // s_cy_b = bc->PutA2BGate(s_cy, yc);
        // s_dx_b = bc->PutA2BGate(s_dx, yc);
        // s_dy_b = bc->PutA2BGate(s_dy, yc);

        // check_sel = bc->PutGTGate(s_cx_b, s_dx_b);
        // check_sel_inv = bc->PutINVGate(check_sel);
        // t_a_b = bc->PutMUXGate(s_cx_b, s_dx_b, check_sel);     //大的数
        // t_b_b = bc->PutMUXGate(s_cx_b, s_dx_b, check_sel_inv); //小的数
        // // std::cout << "t_a\t" << t_a->get_bitlength() << "\tt_b\t" << t_b->get_bitlength() << std::endl;
        // //计算

        // // bc->PutPrintValueGate(t_a_b, "t_a_b\t");
        // // bc->PutPrintValueGate(t_b_b, "t_b_b\t");

        // t_a = ac->PutB2AGate(t_a_b);
        // t_b = ac->PutB2AGate(t_b_b);
        // // ac->PutPrintValueGate(t_a, "t_a\t");
        // // ac->PutPrintValueGate(t_b, "t_b\t");

        // s_res = ac->PutSUBGate(t_a, t_b);
        // // ac->PutPrintValueGate(s_res, "sub\t");
        // s_res->set_max_bitlength(bitlen);
        // // std::cout << "s_res\t" << s_res->get_bitlength() << std::endl;
        // s_ans = ac->PutMULGate(s_res, s_res);
        // // ac->PutPrintValueGate(s_ans, "mul\t");

        // check_sel = bc->PutGTGate(s_cy_b, s_dy_b);
        // check_sel_inv = bc->PutINVGate(check_sel);
        // t_a_b = bc->PutMUXGate(s_cy_b, s_dy_b, check_sel);     //大的数
        // t_b_b = bc->PutMUXGate(s_cy_b, s_dy_b, check_sel_inv); //小的数
        // // std::cout << "t_a\t" << t_a->get_bitlength() << "\tt_b\t" << t_b->get_bitlength() << std::endl;
        // //计算
        // // bc->PutPrintValueGate(t_a_b, "t_a_b\t");
        // // bc->PutPrintValueGate(t_b_b, "t_b_b\t");

        // t_a = ac->PutB2AGate(t_a_b);
        // t_b = ac->PutB2AGate(t_b_b);
        // // ac->PutPrintValueGate(t_a, "t_a\t");
        // // ac->PutPrintValueGate(t_b, "t_b\t");

        // s_res = ac->PutSUBGate(t_a, t_b);
        // // ac->PutPrintValueGate(s_res, "sub\t");
        // s_res->set_max_bitlength(bitlen);
        // // std::cout << "s_res\t" << s_res->get_bitlength() << std::endl;
        // s_res = ac->PutMULGate(s_res, s_res);
        // // ac->PutPrintValueGate(s_res, "mul\t");

        // s_ans = ac->PutADDGate(s_ans, s_res);
        // // ac->PutPrintValueGate(s_ans, "add\t");

        // out_res = ac->PutOUTGate(s_ans, ALL);
        // party->ExecCircuit();
        // res = out_res->get_clear_value<uint64_t>();
        // // std::cout << "res:\t" << res << std::endl;
        // std::cout << (float)i / runtime * 100 << "%\r" << std::flush; //进度条
        // // std::cout << "The result is:\t" << res << std::endl;
        // if (i && res != oldRes)
        //     counts++;
        // else
        //     oldRes = res;
        // party->Reset();
    } */
    delete party;
    // std::cout << "The result is:\t" << counts << std::endl;
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