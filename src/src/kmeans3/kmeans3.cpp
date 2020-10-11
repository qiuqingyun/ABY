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

//生成范围内的随机数
uint32_t randInt(uint32_t begin, uint32_t end)
{
    if (end - begin <= 0)
        return 0;
    time_t t;
    uint32_t randNum;
    srand((unsigned)2);
    randNum = rand() % (end - begin + 1) + begin;
    return randNum - 1;
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
    std::cout<<list[0].size() << " datas has been read in!" << std::endl;
}

//对每个簇，找出其质心
void findCenters(std::vector<std::vector<uint64_t>> list, std::vector<uint32_t *> &centers, std::vector<uint32_t> classInfo,
                 std::vector<uint32_t *> &oldCenters, uint32_t cluster,
                 e_role role, uint32_t dimension, const std::string &address, uint16_t port, seclvl seclvl,
                 uint32_t bitlen, uint32_t nthreads, e_mt_gen_alg mt_alg)
{
    ABYParty *party = new ABYParty(role, address, port, seclvl, bitlen, nthreads, mt_alg, 4000000);
    std::vector<Sharing *> &sharings = party->GetSharings();
    //大部分计算使用算术电路，部分比较，反转及选择使用布尔电路
    ArithmeticCircuit *ac = (ArithmeticCircuit *)sharings[S_ARITH]->GetCircuitBuildRoutine();

    //对每个簇，选出属于这个簇的数据点，每个维度进行求和，再除以数据点个数
    for (int iC = 0; iC < cluster; iC++)
    { //遍历簇
        printf("cluster%d:\t",iC);
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
                    // ac->PutPrintValueGate(s_in_temp, "s_in_temp");
                    s_sum = ac->PutADDGate(s_sum, s_in_temp); //累加
                    counts++;
                    // bc->PutPrintValueGate(s_sum, "s_sum");
                }
            }
            //累加结果恢复成明文后再进行除法(不确定安全性)
            //计算得到的质心坐标放大100倍后截断取整
            share *out_sum = ac->PutOUTGate(s_sum, ALL);
            party->ExecCircuit();
            // press();
            uint32_t sum = out_sum->get_clear_value<uint32_t>();
            uint32_t ans = (float)sum / counts * 100;
            oldCenters[iC][iD] = centers[iC][iD];
            centers[iC][iD] = ans;
            party->Reset(); //重置电路
            printf("%u\t",ans);
        }
        printf("\n");
    }
    delete party;
}

//每个数据点找到与自己欧氏距离最近的质心，并归类
void eDistance(std::vector<std::vector<uint64_t>> list, std::vector<uint32_t *> centers, std::vector<uint32_t> &classInfo,
               e_role role, uint32_t dimension, const std::string &address, uint16_t port, seclvl seclvl,
               uint32_t bitlen, uint32_t nthreads, e_mt_gen_alg mt_alg)
{
    ABYParty *party = new ABYParty(role, address, port, seclvl, bitlen, nthreads, mt_alg, 4000000);
    std::vector<Sharing *> &sharings = party->GetSharings();
    //大部分计算使用算术电路，部分比较，反转及选择使用布尔电路
    ArithmeticCircuit *ac = (ArithmeticCircuit *)sharings[S_ARITH]->GetCircuitBuildRoutine();
    BooleanCircuit *bc = (BooleanCircuit *)sharings[S_BOOL]->GetCircuitBuildRoutine();
    Circuit *yc = sharings[S_YAO]->GetCircuitBuildRoutine();

    share *s_dis[2], *s_inx[2];
    int nvals = list[0].size();
    int counts = 0;
    uint64_t zero = 0, max = ULONG_MAX, hundred = 100;
    // share *s_minIndex,*s_minIndex;
    share *s_cons_100_a = ac->PutSIMDCONSGate(nvals, hundred, bitlen);
    share *s_minDis_b = bc->PutSIMDCONSGate(nvals, max, bitlen);
    share *s_minIndex_b = bc->PutSIMDCONSGate(nvals, zero, bitlen);
    for (int iC = 0; iC < centers.size(); iC++)
    {
        share *s_addAns_a = ac->PutSIMDCONSGate(nvals, zero, bitlen);
        for (int iD = 0; iD < dimension; iD++)
        { //对每个维度,(x2-x1)*(x2-x1)
            share *s_dataPoint_a = ac->PutSharedSIMDINGate(nvals, &list[iD][0], bitlen);
            s_dataPoint_a = ac->PutMULGate(s_dataPoint_a, s_cons_100_a); //数据点配合质心，放大100倍,AC
            share *s_centerPoint_a = ac->PutSIMDCONSGate(nvals, (uint64_t)centers[iC][iD], bitlen);
            share *s_dataPoint_b = bc->PutA2BGate(s_dataPoint_a, yc);
            share *s_centerPoint_b = bc->PutA2BGate(s_centerPoint_a, yc);
            // ac->PutPrintValueGate(s_dataPoint_a, "dataPoint\t");
            // ac->PutPrintValueGate(s_centerPoint_a, "centerPoint\t");
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
            // ac->PutPrintValueGate(s_sub_a, "sub\t");
            share *s_sqr_a = ac->PutMULGate(s_sub_a, s_sub_a); //AC,MUL
            // ac->PutPrintValueGate(s_sqr_a, "sqr\t");
            //各维度累加
            s_addAns_a = ac->PutADDGate(s_addAns_a, s_sqr_a); //AC
        }
        share *s_index_b = bc->PutSIMDCONSGate(nvals, iC, bitlen); //BCin
        share *s_addAns_b = bc->PutA2BGate(s_addAns_a, yc);

        share *check_ans_b = bc->PutGTGate(s_addAns_b, s_minDis_b);          //BC
        s_minDis_b = bc->PutMUXGate(s_minDis_b, s_addAns_b, check_ans_b);    //小的数,BC
        s_minIndex_b = bc->PutMUXGate(s_minIndex_b, s_index_b, check_ans_b); //小的序号,BC
        s_dis[iC] = s_minDis_b;
        s_inx[iC] = s_minIndex_b;
    }
    share *s_minDis_out = bc->PutOUTGate(s_minDis_b, ALL);
    share *s_minIndex_out = bc->PutOUTGate(s_minIndex_b, ALL);
    share *s_out_dis1 = bc->PutOUTGate(s_dis[0], ALL);
    share *s_out_dis2 = bc->PutOUTGate(s_dis[1], ALL);
    share *s_out_inx1 = bc->PutOUTGate(s_inx[0], ALL);
    share *s_out_inx2 = bc->PutOUTGate(s_inx[1], ALL);

    party->ExecCircuit();

    uint32_t out_bitlen, out_nvals, minIndex, oldIndex;
    uint32_t *output_dis, *output_index;
    uint32_t *output_dis1, *output_index1;
    uint32_t *output_dis2, *output_index2;
    s_minDis_out->get_clear_value_vec(&output_dis, &out_bitlen, &out_nvals);
    s_minIndex_out->get_clear_value_vec(&output_index, &out_bitlen, &out_nvals);

    s_out_dis1->get_clear_value_vec(&output_dis1, &out_bitlen, &out_nvals);
    s_out_dis2->get_clear_value_vec(&output_dis2, &out_bitlen, &out_nvals);
    s_out_inx1->get_clear_value_vec(&output_index1, &out_bitlen, &out_nvals);
    s_out_inx2->get_clear_value_vec(&output_index2, &out_bitlen, &out_nvals);

    for (int iL = 0; iL < list[0].size(); iL++)
    {
        // printf("No.%d: \t %u \t %u \t %u \t %u\n", iL, output_index1[iL], output_dis1[iL], output_index2[iL], output_dis2[iL]);
        oldIndex = classInfo[iL];
        classInfo[iL] = output_index[iL];
        if (oldIndex != output_index[iL])
            counts++;
    }
    printf("\n%d points changed.\n", counts);
    delete party;
    printf("ok\n");
    // press();
}

//与上一轮相比质心的移动,若每个维度均小于临界值，则退出
uint32_t minDis(std::vector<uint32_t *> centers, std::vector<uint32_t *> oldCenters,
                uint32_t dimension, uint32_t diff)
{
    uint32_t flag = 1, ans;
    // std::cout << "diff " << diff << "\tans";
    for (int iC = 0; iC < centers.size(); iC++) //对每个簇
        for (int iD = 0; iD < dimension; iD++)  //对每个维度
        {
            if (centers[iC][iD] > oldCenters[iC][iD])
                ans = centers[iC][iD] - oldCenters[iC][iD];
            else
                ans = oldCenters[iC][iD] - centers[iC][iD];
            flag = flag && (ans <= diff);
            // std::cout << "\t" << ans;
        }
    // std::cout << "\tFLAG: " << flag << std::endl;
    return flag ? 0 : 1; //每个维度均小于临界值，则返回0
}

//kmeans安全计算
void kmeans(e_role role, uint32_t dimension, uint32_t cluster, std::string path, uint32_t maxtime,
            float diff, const std::string &address, uint16_t port, seclvl seclvl,
            uint32_t bitlen, uint32_t nthreads, e_mt_gen_alg mt_alg)
{
    std::vector<std::vector<uint64_t>> list; //数据向量,所有明文加密数据保存于此
    dataIn(list, dimension, path);           //输入文件
    

    std::vector<uint32_t> classInfo; //数据分类信息
    //数据初始化，随机分类
    srand((unsigned)20); //应随机生成后共享
    for (uint32_t i = 0; i < dimension * 2; i++)
        classInfo.push_back(i % dimension);
    for (int i = dimension * 2; i < list[0].size(); i++)
        classInfo.push_back(rand() % dimension);

    std::vector<uint32_t *> centers;    //质心向量
    std::vector<uint32_t *> oldCenters; //上一轮的质心向量
    for (int i = 0; i < cluster; i++)
    { //初始化填充
        // uint32_t *temp1 = (uint32_t *)malloc(sizeof(uint32_t) * dimension);
        // uint32_t *temp2 = (uint32_t *)malloc(sizeof(uint32_t) * dimension);
        uint32_t *temp1=new uint32_t [dimension];
        uint32_t *temp2=new uint32_t [dimension];
        for (int j = 0; j < dimension; j++)
        {
            temp1[j] = 0;
            temp2[j] = 0;
        }
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
        flag = minDis(centers, oldCenters, dimension, diff);
        if (!flag)
            break;
        //每个数据点找到与自己欧氏距离最近的质心，并归类
        eDistance(list, centers, classInfo, role, dimension, address, port, seclvl, bitlen, nthreads, mt_alg);
        printf("                     \r");
        printf("Calculating is complete!\nRound%d: finished!\n", times);
        end = clock();
        clock_t remain = (double)(end - start) / CLOCKS_PER_SEC;
        std::cout << "Time is " << remain / 60 << "m " << remain % 60 << "s" << std::endl;
        printf("\n");
        // press();
    }
    //输出结果
    printf("\n");
    int index = 0;
    std::string fileName = role ? BOB : ALICE;
    char *namePtr = const_cast<char *>(fileName.c_str());
    FILE *fp = fopen(namePtr, "w");
    if (!fp)
    {
        printf("error!\n");
        exit(0);
    }
    // printf("print out");
    for (int iL = 0; iL < list[0].size(); iL++)
    { //对每个数
        for (int iC = 0; iC < cluster; iC++)
        { //对每个簇
            if (classInfo[iL] == iC)
            { //如果属于这个簇
                fprintf(fp, "USER %d:\tCLASS %d\n", ++index, iC);
                // std::cout << "." << std::flush;                                                     //进度条
            }
        }
        std::cout << "Printing  " << (float)iL / list[0].size() * 100 << "%\r" << std::flush; //进度条
    }
    fclose(fp);
    printf("Printing is complete!\n");
}

int main(int argc, char **argv)
{
    // clock_t start, end;
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