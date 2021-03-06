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
void aby(e_role role, float inTemp, FILE *fpOut, ABYParty *party, ArithmeticCircuit *circ, uint32_t bitlen)
{
    share *s_in;
    share *s_out;
    if (role == SERVER)
    {
        s_in = circ->PutINGate(inTemp, bitlen, SERVER);
    }
    else if (role == CLIENT)
    {
        s_in = circ->PutDummyINGate(bitlen);
    }
    s_out = circ->PutSharedOUTGate(s_in); //一个share数据被shared输出，变成双方各持有一部分的加密明文数据
    party->ExecCircuit();
    uint32_t int_shared = s_out->get_clear_value<uint32_t>();
    fprintf(fpOut, "%u\t", int_shared);
    party->Reset(); //重置电路
}

//模拟用户输入，将明文数据转换为share数据，分发给两台服务器
void userSim(e_role role, uint32_t dimension, std::string path, const std::string &address, uint16_t port,
                seclvl seclvl, uint32_t bitlen, uint32_t nthreads, e_mt_gen_alg mt_alg, e_sharing sharing)
{
    ABYParty *party = new ABYParty(role, address, port, seclvl, bitlen, nthreads, mt_alg);
    std::vector<Sharing *> &sharings = party->GetSharings();
    ArithmeticCircuit *circ = (ArithmeticCircuit *)sharings[sharing]->GetCircuitBuildRoutine();
    //输入文件
    char *pathPtr = const_cast<char *>(path.c_str());
    FILE *fpIn = fopen(pathPtr, "r");
    if (!fpIn)
    {
        printf("error!\n");
        exit(0);
    }
    std::cout << "running";
    //输出文件
    std::string fileName = role ? BOB : ALICE;
    char *namePtr = const_cast<char *>(fileName.c_str());
    FILE *fpOut = fopen(namePtr, "w");
    float inTemp;
    //读入数据
    while (fscanf(fpIn, "%f", &inTemp) != EOF)
    {
        aby(role, inTemp, fpOut, party, circ, bitlen);
        for (int indexJ = 1; indexJ < dimension; indexJ++)
        {
            fscanf(fpIn, "%f", &inTemp);
            aby(role, inTemp, fpOut, party, circ, bitlen);
        }
        fprintf(fpOut, "\n");
        std::cout << "." << std::flush; //进度条
    }
    fclose(fpIn);
    fclose(fpOut);
    printf("\nfinished!\n");
    delete party;
}

//读取参数
void read_test_options(int32_t *argcp, char ***argvp, e_role *role, std::string *path, uint32_t *dimension,
                       uint32_t *bitlen, uint32_t *secparam, std::string *address,
                       uint16_t *port, int32_t *test_op, uint32_t *test_bit)
{
    uint32_t int_role = 0, int_port = 0, int_testbit = 0, int_dimension = 2;
    std::string str_path;
    parsing_ctx options[] =
        {{(void *)&int_role, T_NUM, "r", "Role: 0/1", true, false},
         {(void *)&str_path, T_STR, "f", "file path", true, false},
         {(void *)&int_dimension, T_NUM, "d", "dimension, default 2", false, false},
         {(void *)&int_testbit, T_NUM, "i", "test bit", false, false},
         {(void *)bitlen, T_NUM, "b", "Bit-length, default 32", false, false},
         {(void *)secparam, T_NUM, "s", "Symmetric Security Bits, default: 128", false, false},
         {(void *)address, T_STR, "a", "IP-address, default: localhost", false, false},
         {(void *)&int_port, T_NUM, "p", "Port, default: 7766", false, false},
         {(void *)test_op, T_NUM, "t", "Single test (leave out for all operations), default: off", false, false}};
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
    *test_bit = int_testbit;
    *dimension = int_dimension;
}

int main(int argc, char **argv)
{
    e_role role;
    uint32_t bitlen = 1, secparam = 128, nthreads = 1;
    uint16_t port = 7766;
    std::string address = "127.0.0.1";
    int32_t test_op = -1;
    e_mt_gen_alg mt_alg = MT_OT;
    uint32_t test_bit = 0, dimension = 2;
    std::string path;
    seclvl seclvl = get_sec_lvl(secparam);
    read_test_options(&argc, &argv, &role, &path, &dimension,
                      &bitlen, &secparam, &address, &port, &test_op, &test_bit);
    userSim(role, dimension, path, address, port, seclvl, bitlen, nthreads, mt_alg, S_ARITH);
    return 0;
}