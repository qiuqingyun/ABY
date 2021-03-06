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
#include <time.h>

#define ALICE "ALICEout"
#define BOB "BOBout"

#define LOG 1
clock_t start, end;
//等待输入
void press()
{
    printf("press any key...");
    std::cin.get();
}

//读取输入
void read_test_options(int32_t *argcp, char ***argvp, e_role *role, std::string *path, uint32_t *dimension,
                       uint32_t *cluster, uint32_t *maxtime, uint32_t *diff,
                       uint32_t *bitlen, uint32_t *nvals, uint32_t *secparam, std::string *address,
                       uint16_t *port, int32_t *test_op, uint32_t *test_bit)
{
    uint32_t int_role = 0, int_port = 0, int_testbit = 0, int_dimension = 2, int_cluster = 2, int_maxtime = 100;
    uint32_t int_diff = 10;
    std::string str_path;
    parsing_ctx options[] =
        {{(void *)&int_role, T_NUM, "r", "Role: 0/1", true, false},
         {(void *)&str_path, T_STR, "f", "file path", true, false},
         {(void *)&int_dimension, T_NUM, "d", "dimension, default 2", false, false},
         {(void *)&int_cluster, T_NUM, "c", "cluster, default 2", false, false},
         {(void *)&int_maxtime, T_NUM, "m", "maximum number of executions, default 100", false, false},
         {(void *)&int_diff, T_NUM, "x", "number of difference, default 10", false, false},
         {(void *)&int_testbit, T_NUM, "i", "test bit", false, false},
         {(void *)nvals, T_NUM, "n", "Number of parallel operation elements", false, false},
         {(void *)bitlen, T_NUM, "b", "Bit-length, default 64", false, false},
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
    *cluster = int_cluster;
    *maxtime = int_maxtime;
    *diff = int_diff;
}

//输入数据文件，将数据保存到list中
void dataIn(std::vector<std::vector<uint64_t>> &list, uint32_t dimension, std::string path)
{
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
        list[0].push_back(inTemp);
        for (int iD = 1; iD < dimension; iD++)
        {
            fscanf(fpIn, "%lu", &inTemp);
            list[iD].push_back(inTemp);
        }
    }
    fclose(fpIn);
    std::cout << list[0].size() << " datas has been read in!" << std::endl;
}

//对每个簇，找出其质心
void findCenters(std::vector<std::vector<uint64_t>> list, std::vector<std::vector<uint64_t>> &centers, std::vector<uint32_t> classInfo,
                 std::vector<std::vector<uint64_t>> &oldCenters, uint32_t cluster,
                 e_role role, uint32_t dimension, const std::string &address, uint16_t port, seclvl seclvl,
                 uint32_t bitlen, uint32_t nthreads, e_mt_gen_alg mt_alg)
{
    uint32_t shiftN = 20; //倒数放大位数
    ABYParty *party = new ABYParty(role, address, port, seclvl, bitlen, nthreads, mt_alg, 4000000);
    std::vector<Sharing *> &sharings = party->GetSharings();
    ArithmeticCircuit *ac = (ArithmeticCircuit *)sharings[S_ARITH]->GetCircuitBuildRoutine();
    BooleanCircuit *bc = (BooleanCircuit *)sharings[S_BOOL]->GetCircuitBuildRoutine();
    Circuit *yc = sharings[S_YAO]->GetCircuitBuildRoutine();

    //对每个簇，选出属于这个簇的数据点，每个维度进行求和，再除以数据点个数
    for (int iC = 0; iC < cluster; iC++)
    { //遍历簇
        for (int iD = 0; iD < dimension; iD++)
        { //遍历维数
            uint32_t temp = 0;
            share *s_sum = ac->PutINGate(temp, bitlen, SERVER);
            uint32_t counts = 0;
            for (int iL = 0; iL < list[0].size(); iL++)
            { //遍历数
                if (classInfo[iL] == iC)
                {                                                                 //若数属于簇
                    share *s_in_temp = ac->PutSharedINGate(list[iD][iL], bitlen); //将数输入电路
                    share *s_temp_sum = ac->PutADDGate(s_sum, s_in_temp); //累加
                    share *d_delete_sum = s_sum;
                    s_sum = s_temp_sum;
                    counts++;
                    delete s_in_temp;
                    delete d_delete_sum;
                }
            }
            //累加结果乘以数据点个数的倒数
            //计算得到的质心坐标放大100倍后截断取整,保留小数点后两位
            counts = (float)pow((float)2, (float)shiftN) / counts * 100; //将除数转换为倒数，放大为整数，放大倍数足够大保证精度
            share *s_shiftN_b = bc->PutINGate((uint64_t)shiftN, 64, SERVER);
            share *s_counts_a = ac->PutCONSGate((uint64_t)counts, bitlen);               //将簇中数据点个数加密
            share *s_divAns_a = ac->PutMULGate(s_sum, s_counts_a);                       //乘法代替除法
            share *s_divAns_b = bc->PutA2BGate(s_divAns_a, yc);                          //转换为布尔电路
            share *s_shiftedR_b = bc->PutBarrelRightShifterGate(s_divAns_b, s_shiftN_b); //对结果进行右移处理，保留小数点后两位
            share *s_shiftedR_a = ac->PutB2AGate(s_shiftedR_b);                          //转换为算数电路
            share *s_out_a = ac->PutSharedOUTGate(s_shiftedR_a); //以share后的加密明文输出，保存结果
            party->ExecCircuit();
            uint64_t out = s_out_a->get_clear_value<uint64_t>();
            oldCenters[iC][iD] = centers[iC][iD]; //保存上一次的质心
            centers[iC][iD] = out;                //更新质心
            delete s_sum;
            delete s_shiftN_b;
            delete s_counts_a;
            delete s_divAns_a;
            delete s_divAns_b;
            delete s_shiftedR_b;
            delete s_shiftedR_a;
            delete s_out_a;
            party->Reset(); //重置电路
        }
    }
    delete party;
}

//每个数据点找到与自己欧氏距离最近的质心，并归类
void eDistance(std::vector<std::vector<uint64_t>> list, std::vector<std::vector<uint64_t>> centers, std::vector<uint32_t> &classInfo,
               e_role role, uint32_t dimension, const std::string &address, uint16_t port, seclvl seclvl,
               uint32_t bitlen, uint32_t nthreads, e_mt_gen_alg mt_alg)
{
    ABYParty *party = new ABYParty(role, address, port, seclvl, bitlen, nthreads, mt_alg, 4000000);
    std::vector<Sharing *> &sharings = party->GetSharings();
    ArithmeticCircuit *ac = (ArithmeticCircuit *)sharings[S_ARITH]->GetCircuitBuildRoutine();
    BooleanCircuit *bc = (BooleanCircuit *)sharings[S_BOOL]->GetCircuitBuildRoutine();
    Circuit *yc = sharings[S_YAO]->GetCircuitBuildRoutine();

    uint32_t nvals = list[0].size();
    int counts = 0;
    uint64_t zero = 0, max = ULONG_MAX, hundred = 100;
    share *s_minDis_b = bc->PutSIMDCONSGate(nvals, max, bitlen);
    share *s_minIndex_b = bc->PutSIMDCONSGate(nvals, zero, bitlen);
    for (int iC = 0; iC < centers.size(); iC++)
    {
        share *s_addAns_a = ac->PutSIMDCONSGate(nvals, zero, bitlen);
        for (int iD = 0; iD < dimension; iD++)
        { //对每个维度,(x2-x1)*(x2-x1)
            share *s_cons_100_a = ac->PutSIMDCONSGate(nvals, hundred, bitlen);
            share *s_dataPoint_a_original = ac->PutSharedSIMDINGate(nvals, &list[iD][0], bitlen); //输入数据点
            share *s_dataPoint_a = ac->PutMULGate(s_dataPoint_a_original, s_cons_100_a);          //数据点配合质心，放大100倍,AC
            share *s_centerPoint_a_original = ac->PutSharedINGate(centers[iC][iD], bitlen);       //输入质心
            share *s_centerPoint_a = ac->PutRepeaterGate(nvals, s_centerPoint_a_original);        //转换为SIMD

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
            share *s_sub_a = ac->PutSUBGate(t_a_a, t_b_a);     //AC,SUB
            share *s_sqr_a = ac->PutMULGate(s_sub_a, s_sub_a); //AC,MUL
            //各维度累加
            share *s_tempaddAns_a = ac->PutADDGate(s_addAns_a, s_sqr_a); //AC
            share *s_delete = s_addAns_a;
            s_addAns_a = s_tempaddAns_a;

            delete s_delete;
            delete s_cons_100_a;
            delete s_dataPoint_a_original;
            delete s_dataPoint_a;
            delete s_centerPoint_a_original;
            delete s_centerPoint_a;
            delete s_dataPoint_b;
            delete s_centerPoint_b;
            delete check_sel_b;
            delete check_sel_inv_b;
            delete t_a_b;
            delete t_b_b;
            delete t_a_a;
            delete t_b_a;
            delete s_sub_a;
            delete s_sqr_a;
        }
        share *s_index_b = bc->PutSIMDCONSGate(nvals, iC, bitlen); //BCin
        share *s_addAns_b = bc->PutA2BGate(s_addAns_a, yc);

        share *check_ans_b = bc->PutGTGate(s_addAns_b, s_minDis_b); //BC

        share *s_temp_minDis_b = bc->PutMUXGate(s_minDis_b, s_addAns_b, check_ans_b); //小的数,BC
        share *s_delete_minDis_b = s_minDis_b;
        s_minDis_b = s_temp_minDis_b;
        share *s_temp_minIndex_b = bc->PutMUXGate(s_minIndex_b, s_index_b, check_ans_b); //小的序号,BC
        share *s_delete_minIndex_b = s_minIndex_b;
        s_minIndex_b = s_temp_minIndex_b;

        delete s_delete_minDis_b;
        delete s_delete_minIndex_b;
        delete s_index_b;
        delete s_addAns_b;
        delete check_ans_b;
        delete s_addAns_a;
    }
    share *s_minDis_a = ac->PutB2AGate(s_minDis_b);
    share *s_minIndex_a = ac->PutB2AGate(s_minIndex_b);
    share *s_minDis_out = ac->PutOUTGate(s_minDis_a, ALL);
    share *s_minIndex_out = ac->PutOUTGate(s_minIndex_a, ALL);

    party->ExecCircuit();

    uint32_t out_bitlen, out_nvals, minIndex, oldIndex;
    uint32_t *output_dis, *output_index;
    s_minDis_out->get_clear_value_vec(&output_dis, &out_bitlen, &out_nvals);
    s_minIndex_out->get_clear_value_vec(&output_index, &out_bitlen, &out_nvals);

    delete s_minDis_a;
    delete s_minIndex_a;
    delete s_minDis_out;
    delete s_minIndex_out;
    delete s_minDis_b;
    delete s_minIndex_b;

    // std::vector<int> changedIndex;
    for (int iL = 0; iL < list[0].size(); iL++)
    {
        oldIndex = classInfo[iL];
        classInfo[iL] = output_index[iL];
        if (oldIndex != output_index[iL])
        {
            counts++;
        }
    }
    printf("\n%d points changed.\n", counts);
    delete party;
    free(output_dis);
    free(output_index);
}

//与上一轮相比质心的移动,若每个维度均小于临界值，则退出
uint32_t minDis(std::vector<std::vector<uint64_t>> centers, std::vector<std::vector<uint64_t>> oldCenters, uint32_t diff,
                e_role role, uint32_t dimension, const std::string &address, uint16_t port, seclvl seclvl,
                uint32_t bitlen, uint32_t nthreads, e_mt_gen_alg mt_alg)
{
    ABYParty *party = new ABYParty(role, address, port, seclvl, bitlen, nthreads, mt_alg, 4000000);
    std::vector<Sharing *> &sharings = party->GetSharings();
    ArithmeticCircuit *ac = (ArithmeticCircuit *)sharings[S_ARITH]->GetCircuitBuildRoutine();
    BooleanCircuit *bc = (BooleanCircuit *)sharings[S_BOOL]->GetCircuitBuildRoutine();
    Circuit *yc = sharings[S_YAO]->GetCircuitBuildRoutine();

    uint32_t flag = 1, ans;
    for (int iC = 0; iC < centers.size(); iC++) //对每个簇
        for (int iD = 0; iD < dimension; iD++)  //对每个维度
        {
            share *center_a = ac->PutSharedINGate(centers[iC][iD], bitlen);
            share *oldCenter_a = ac->PutSharedINGate(oldCenters[iC][iD], bitlen);
            share *center_b = bc->PutA2BGate(center_a, yc);
            share *oldCenter_b = bc->PutA2BGate(oldCenter_a, yc);

            share *check_sel_b = bc->PutGTGate(center_b, oldCenter_b);             //BC
            share *check_sel_inv_b = bc->PutINVGate(check_sel_b);                  //BC
            share *t_a_b = bc->PutMUXGate(center_b, oldCenter_b, check_sel_b);     //大的数,BC
            share *t_b_b = bc->PutMUXGate(center_b, oldCenter_b, check_sel_inv_b); //小的数,BC
            share *s_sub_b = bc->PutSUBGate(t_a_b, t_b_b);                         //AC,SUB
            share *s_diff_b = bc->PutCONSGate((uint64_t)diff, bitlen);

            share *check_sel_2_b = bc->PutGTGate(s_diff_b, s_sub_b);
            share *s_out = bc->PutOUTGate(check_sel_2_b, ALL);
            party->ExecCircuit();
            uint32_t ans = s_out->get_clear_value<uint32_t>();
            flag = flag && ans;

            delete center_a;
            delete oldCenter_a;
            delete center_b;
            delete oldCenter_b;
            delete check_sel_b;
            delete check_sel_inv_b;
            delete t_a_b;
            delete t_b_b;
            delete s_sub_b;
            delete s_diff_b;
            delete check_sel_2_b;
            delete s_out;
            party->Reset();
        }
    delete party;
    return flag ? 0 : 1; //每个维度均小于临界值，则返回0
}

//kmeans安全计算
void kmeans(e_role role, uint32_t dimension, uint32_t cluster, std::string path, uint32_t maxtime,
            float diff, const std::string &address, uint16_t port, seclvl seclvl,
            uint32_t bitlen, uint32_t nthreads, e_mt_gen_alg mt_alg)
{
    std::vector<std::vector<uint64_t>> list; //数据向量,所有明文加密数据保存于此
    dataIn(list, dimension, path);           //输入文件
    std::vector<uint32_t> classInfo;         //数据分类信息
    //数据初始化，随机分类
    srand((unsigned)20); //应随机生成后共享
    for (uint32_t i = 0; i < cluster * 2; i++)
        classInfo.push_back(i % cluster);
    for (int i = cluster * 2; i < list[0].size(); i++)
        classInfo.push_back(rand() % cluster);

    std::vector<std::vector<uint64_t>> centers;    //质心向量
    std::vector<std::vector<uint64_t>> oldCenters; //上一轮的质心向量
    for (int i = 0; i < cluster; i++)
    { //初始化填充
        std::vector<uint64_t> temp1(dimension, 0);
        std::vector<uint64_t> temp2(dimension, 0);
        centers.push_back(temp1);
        oldCenters.push_back(temp2);
    }
    //循环
    uint32_t times = 0, flag = 1;
    while (maxtime > times++ && flag)
    {
        //对每个簇，找出其质心
        findCenters(list, centers, classInfo, oldCenters, cluster, role, dimension, address, port, seclvl, bitlen, nthreads, mt_alg);
        //与上一轮相比质心的移动,若每个维度均小于临界值，则退出
        printf("Round%d: Find centers!\n", times);
        flag = minDis(centers, oldCenters, diff, role, dimension, address, port, seclvl, bitlen, nthreads, mt_alg);
        if (!flag)
        {
            printf("Cluster completed!\n");
            break;
        }
        //每个数据点找到与自己欧氏距离最近的质心，并归类
        printf("Calculating...");
        fflush(stdout);
        eDistance(list, centers, classInfo, role, dimension, address, port, seclvl, bitlen, nthreads, mt_alg);
        printf("Calculation completed!\n");
        end = clock();
        clock_t remain = (double)(end - start) / CLOCKS_PER_SEC;
        std::cout << "Time is " << remain / 60 << "m " << remain % 60 << "s" << std::endl;
        printf("\n");
        // press();
    }
    //输出结果
    printf("\nPrinting...");
    fflush(stdout);
    std::string fileName = role ? BOB : ALICE;
    char *namePtr = const_cast<char *>(fileName.c_str());
    FILE *fp = fopen(namePtr, "w");
    if (!fp)
    {
        printf("error!\n");
        exit(0);
    }
    for (int iL = 0; iL < list[0].size(); iL++)                  //对每个数
        for (int iC = 0; iC < cluster; iC++)                     //对每个簇
            if (classInfo[iL] == iC)                             //如果属于这个簇
                fprintf(fp, "USER %d:\tCLASS %d\n", iL + 1, iC); //输出该数据点所属的簇编号
    fclose(fp);
    printf("Printing is complete!\n");
}

int main(int argc, char **argv)
{
    start = clock();
    e_role role;
    uint32_t bitlen = 64, nvals = 4, secparam = 128, nthreads = 1;
    uint16_t port = 7766;
    std::string address = "127.0.0.1";
    int32_t test_op = -1;
    e_mt_gen_alg mt_alg = MT_OT;
    uint32_t test_bit = 0;
    uint32_t dimension = 2, cluster = 2, maxtime = 100;
    uint32_t diff = 10;
    std::string path;
    seclvl seclvl = get_sec_lvl(secparam);
    read_test_options(&argc, &argv, &role, &path, &dimension, &cluster, &maxtime, &diff,
                      &bitlen, &nvals, &secparam, &address, &port, &test_op, &test_bit);
    kmeans(role, dimension, cluster, path, maxtime, diff, address, port, seclvl, bitlen, nthreads, mt_alg);
    end = clock();
    clock_t remain = (double)(end - start) / CLOCKS_PER_SEC;
    std::cout << "Total time is " << remain / 60 << "m " << remain % 60 << "s" << std::endl;
    return 0;
}