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

//将明文数据转换为share数据，并以加密的明文形式保存
void aby(e_role role, uint32_t inTemp, FILE *fpOut, ABYParty *party, ArithmeticCircuit *circ, uint32_t bitlen)
{
    share *s_in;
    share *s_out;
    // printf("ok1 ");
    s_in = circ->PutINGate(inTemp, bitlen, SERVER);
    // printf("ok2 ");
    s_out = circ->PutSharedOUTGate(s_in); //一个share数据被shared输出，变成双方各持有一部分的加密明文数据
    // printf("ok3 ");
    party->ExecCircuit();
    uint64_t int_shared = s_out->get_clear_value<uint64_t>();
    // printf("ok4 ");
    fprintf(fpOut, "%lu\t", int_shared);
    party->Reset(); //重置电路
    // printf("ok5\n");
}

//模拟用户输入，将明文数据转换为share数据，分发给两台服务器
void userSim(e_role role, uint32_t dimension, std::string path, uint32_t times, const std::string &address, uint16_t port,
             seclvl seclvl, uint32_t bitlen, uint32_t nthreads, e_mt_gen_alg mt_alg, e_sharing sharing)
{
    // ABYParty *party = new ABYParty(role, address, port, seclvl, bitlen, nthreads, mt_alg);
    // std::vector<Sharing *> &sharings = party->GetSharings();
    // ArithmeticCircuit *circ = (ArithmeticCircuit *)sharings[sharing]->GetCircuitBuildRoutine();
    //输入文件
    char *pathPtr = const_cast<char *>(path.c_str());
    FILE *fpIn = fopen(pathPtr, "r");
    if (!fpIn)
    {
        printf("error!\n");
        exit(0);
    }
    std::cout << "Encrypting" << std::endl;
    //输出文件
    std::string fileName = role ? BOB : ALICE;
    char *namePtr = const_cast<char *>(fileName.c_str());
    FILE *fpOut = fopen(namePtr, "w");
    int inTemp;
    int counts = 0;
    // int times = 1000;
    //读入数据
    ABYParty *party;
    ArithmeticCircuit *circ;
    while (fscanf(fpIn, "%d", &inTemp) != EOF)
    {
        if (counts % times == 0)
        {
            party = new ABYParty(role, address, port, seclvl, bitlen, nthreads, mt_alg);
            std::vector<Sharing *> &sharings = party->GetSharings();
            circ = (ArithmeticCircuit *)sharings[sharing]->GetCircuitBuildRoutine();
        }
        aby(role, inTemp, fpOut, party, circ, bitlen);
        // printf("ok1 ");
        fflush(stdout);
        for (int indexJ = 1; indexJ < dimension; indexJ++)
        {
            fscanf(fpIn, "%d", &inTemp);
            aby(role, inTemp, fpOut, party, circ, bitlen);
            // printf("ok2\n");
        }
        fprintf(fpOut, "\n");
        std::cout << "\rNo." << ++counts << std::flush; //进度条
        // std::cout << "." << std::flush; //进度条
        if (counts % times == 0)
            delete party;
    }
    fclose(fpIn);
    fclose(fpOut);
    printf("\nfinished!\n");
    // delete party;
}

//读取参数
void read_test_options(int32_t *argcp, char ***argvp, e_role *role, std::string *path, e_sharing *sharing,
                       uint32_t *dimension, uint32_t *bitlen, uint32_t *secparam, std::string *address,
                       uint16_t *port, int32_t *test_op, uint32_t *times)
{
    uint32_t int_role = 0, int_port = 0, int_testbit = 0, int_dimension = 2, int_sharing = 2, int_times = 10000;
    std::string str_path;
    parsing_ctx options[] =
        {{(void *)&int_role, T_NUM, "r", "Role: 0/1", true, false},
         {(void *)&str_path, T_STR, "f", "file path", true, false},
         {(void *)&int_times, T_NUM, "t", "reset time", false, false},
         {(void *)&int_sharing, T_NUM, "w", "Sharing: BOOL/0 YAO/1 ARITH/2", false, false},
         {(void *)&int_dimension, T_NUM, "d", "dimension, default 2", false, false},
         {(void *)&int_testbit, T_NUM, "i", "test bit", false, false},
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
    *path = str_path;
    *dimension = int_dimension;
    *times = int_times;
    switch (int_sharing)
    {
    case 0:
        *sharing = S_BOOL;
        break;
    case 1:
        *sharing = S_YAO;
        break;
    case 2:
        *sharing = S_ARITH;
        break;
    default:
        break;
    }
}

int main(int argc, char **argv)
{
    clock_t start, end;
    start = clock();
    e_role role;
    uint32_t bitlen = 64, secparam = 128, nthreads = 1;
    uint16_t port = 7766;
    std::string address = "127.0.0.1";
    int32_t test_op = -1;
    e_mt_gen_alg mt_alg = MT_OT;
    uint32_t test_bit = 0, dimension = 2, times = 10000;
    std::string path;
    seclvl seclvl = get_sec_lvl(secparam);
    e_sharing sharing = S_ARITH;
    read_test_options(&argc, &argv, &role, &path, &sharing, &dimension,
                      &bitlen, &secparam, &address, &port, &test_op, &times);
    userSim(role, dimension, path, times, address, port, seclvl, bitlen, nthreads, mt_alg, sharing);
    end = clock();
    clock_t remain = (double)(end - start) / CLOCKS_PER_SEC;
    std::cout << "Total time is " << remain / 60 << "m " << remain % 60 << "s" << std::endl;
    return 0;
}