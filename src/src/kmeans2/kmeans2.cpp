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
void dataIn(std::vector<uint64_t *> &list, uint32_t dimension, std::string path)
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
    while (fscanf(fpIn, "%lu", &inTemp) != EOF)
    {
        uint64_t *node = (uint64_t *)malloc(sizeof(uint64_t) * dimension);
        node[0] = inTemp;
        for (int indexJ = 1; indexJ < dimension; indexJ++)
        {
            fscanf(fpIn, "%lu", &inTemp);
            node[indexJ] = inTemp;
        }
        list.push_back(node);
    }
    fclose(fpIn);
}

//对每个簇，找出其质心
void findCenters(std::vector<uint64_t *> list, std::vector<uint32_t *> &centers, std::vector<uint32_t> classInfo,
                 std::vector<uint32_t *> &oldCenters, uint32_t dimension, uint32_t cluster, ABYParty *party,
                 ArithmeticCircuit *ac, uint32_t bitlen)
{
    //对每个簇，选出属于这个簇的数据点，每个维度进行求和，再除以数据点个数
    for (int iC = 0; iC < cluster; iC++)
    { //遍历簇
        for (int iD = 0; iD < dimension; iD++)
        { //遍历维数
            uint32_t temp = 0;
            share *s_sum = ac->PutINGate(temp, bitlen, SERVER);
            uint32_t counts = 0;
            for (int iL = 0; iL < list.size(); iL++)
            { //遍历数
                if (classInfo[iL] == iC)
                {                                                                 //若数属于簇
                    share *s_in_temp = ac->PutSharedINGate(list[iL][iD], bitlen); //将数输入电路
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
            // std::cout << "cluster\t" << iC << "\t"
            //           << "dimension\t" << iD << "\t" << ans << std::endl;
            party->Reset(); //重置电路
            // printf("%u ", ans);
            // std::cout << "." << std::flush; //进度条
            // std::cout << "sum: " << sum << "\tcounts: " << counts << std::endl;
        }
        // printf("\n");
        // press();
        // std::cout << "cluster" << iC << ":\t" << centers[iC][0] << "\t" << centers[iC][1] << std::endl;
    }
}

//每个数据点找到与自己欧氏距离最近的质心，并归类
void eDistance(std::vector<uint64_t *> list, std::vector<uint32_t *> centers, std::vector<uint32_t> &classInfo,
               uint32_t dimension, uint32_t bitlen, ABYParty *party, ArithmeticCircuit *ac, BooleanCircuit *bc, Circuit *yc, e_role role)
{
    int counts = 0, wrong = 0, errorCount = 3;
    std::vector<uint32_t> index;
    for (int iL = 0; iL < list.size(); iL++)
    { //对每个数

        uint64_t cons_100 = 100, minDis = ULONG_MAX, minIndex = 0, temp = 0;
        share *s_minDis_b = bc->PutINGate(minDis, bitlen, SERVER);     //BCin
        share *s_minIndex_b = bc->PutINGate(minIndex, bitlen, SERVER); //BCin

        // if (LOG && role == SERVER)
        // {
        //     fprintf(fp, "No.%d:\t", iL);
        //     fflush(fp);
        // }

        // std::cout << "\nNo." << iL + 1 << ":" << std::endl;
        for (int iC = 0; iC < centers.size(); iC++)
        { //对每个簇

            share *s_cons_100_a = ac->PutCONSGate(cons_100, bitlen); //ACin
            share *s_add_a = ac->PutINGate(temp, bitlen, SERVER);    //ACin
            share *s_add_b, *check_ans_b;
            //对每个维度,(x2-x1)*(x2-x1)
            for (int iD = 0; iD < dimension; iD++)
            {
                share *s_dataPoint_a, *s_centerPoint_a;
                share *s_dataPoint_b, *s_centerPoint_b;
                share *check_sel_b, *check_sel_inv_b;
                share *t_a_b, *t_b_b;
                share *t_a_a, *t_b_a;
                share *s_sub_a, *s_sqr_a;
                s_dataPoint_a = ac->PutSharedINGate((uint64_t)list[iL][iD], bitlen); //ACin
                // ac->PutPrintValueGate(s_cons_100_a, "s_cons_100\t");
                s_dataPoint_a = ac->PutMULGate(s_dataPoint_a, s_cons_100_a);                //数据点配合质心，放大100倍,AC
                s_centerPoint_a = ac->PutINGate((uint64_t)centers[iC][iD], bitlen, SERVER); //ACin
                // ac->PutPrintValueGate(s_dataPoint_a, "dataPoint\t");
                // ac->PutPrintValueGate(s_centerPoint_a, "centerPoint\t");

                //A2B:s_dataPoint_b,s_centerPoint_b
                s_dataPoint_b = bc->PutA2BGate(s_dataPoint_a, yc);
                s_centerPoint_b = bc->PutA2BGate(s_centerPoint_a, yc);

                // std::cout << centers[iC][iD] << std::endl;
                // bc->PutPrintValueGate(s_dataPoint, "s_dataPoint\t");
                // bc->PutPrintValueGate(s_centerPoint, "s_centerPoint\t");
                //保证结果为正
                check_sel_b = bc->PutGTGate(s_dataPoint_b, s_centerPoint_b);             //BC
                check_sel_inv_b = bc->PutINVGate(check_sel_b);                           //BC
                t_a_b = bc->PutMUXGate(s_dataPoint_b, s_centerPoint_b, check_sel_b);     //大的数,BC
                t_b_b = bc->PutMUXGate(s_dataPoint_b, s_centerPoint_b, check_sel_inv_b); //小的数,BC

                // std::cout << "t_a\t" << t_a->get_bitlength() << "\tt_b\t" << t_b->get_bitlength() << std::endl;
                // bc->PutPrintValueGate(t_a_b, "t_a\t");
                // bc->PutPrintValueGate(t_b_b, "t_b\t");
                //计算

                //B2A:t_a_a,t_b_a
                t_a_a = ac->PutB2AGate(t_a_b);
                t_b_a = ac->PutB2AGate(t_b_b);

                s_sub_a = ac->PutSUBGate(t_a_a, t_b_a); //AC
                // ac->PutPrintValueGate(s_sub_a, "sub\t");
                // std::cout << "s_res=\t" << s_res_a->get_bitlength() << std::endl;
                // s_res_a->set_bitlength(bitlen);
                // s_res_a->set_max_bitlength(bitlen);
                s_sqr_a = ac->PutMULGate(s_sub_a, s_sub_a); //AC（有问题）

                // ac->PutPrintValueGate(s_sqr_a, "sqr\t");
                //各维度累加
                s_add_a = ac->PutADDGate(s_add_a, s_sqr_a); //AC
                // ac->PutPrintValueGate(s_ans_a, "add\t");
            }
            // ac->PutPrintValueGate(s_add_a, "res\t");
            share *s_index_b = bc->PutINGate((uint64_t)iC, bitlen, SERVER); //BCin
            // if (iL == 210 || iL == 617 || iL == 868 || iL == 1856)
            // {
            //     printf("point%d cluster%d: \n", iL, iC);
            //     ac->PutPrintValueGate(s_ans_a, "ans\t");
            // }

            // if (LOG && role == SERVER)
            // {
            //     fprintf(fp, "%d:\t", iL);
            //     fflush(fp);
            // }

            //A2B:s_ans_b
            s_add_b = bc->PutA2BGate(s_add_a, yc);

            check_ans_b = bc->PutGTGate(s_add_b, s_minDis_b);                    //BC
            s_minDis_b = bc->PutMUXGate(s_minDis_b, s_add_b, check_ans_b);       //小的数,BC
            s_minIndex_b = bc->PutMUXGate(s_minIndex_b, s_index_b, check_ans_b); //小的序号,BC
            // bc->PutPrintValueGate(check_ans, "check_ans\t");
            // bc->PutPrintValueGate(s_minDis, "s_minDis\t");
            // bc->PutPrintValueGate(s_minIndex, "s_minIndex\t");
        }

        share *out_minIndex = bc->PutOUTGate(s_minIndex_b, ALL); //BCout
        share *out_minDis = bc->PutOUTGate(s_minDis_b, ALL);     //BCout
        // bc->PutPrintValueGate(out_minDis, "minDis\t");
        party->ExecCircuit();
        minIndex = out_minIndex->get_clear_value<uint64_t>();
        minDis = out_minDis->get_clear_value<uint64_t>();
        uint32_t oldIndex = classInfo[iL];
        // printf("ans: %lu\n", minDis);
        if (minDis < 100000000000000000) //防止乘法门计算错误
        {
            classInfo[iL] = minIndex;
            errorCount = 3;
        }
        else
        {
            if (!errorCount--)
            {
                printf("Wrong!\n");
                exit(0);
            }
            iL--;
            party->Reset();
            continue;
        }
        classInfo[iL] = minIndex;
        if (oldIndex != minIndex)
        {
            counts++;
            index.push_back(iL + 1);
        }
        // std::cout << oldIndex << " -> " << minIndex << std::endl;
        // if (iL == 210 || iL == 617 || iL == 868 || iL == 1856)
        // {
        //     printf("point%d -> cluster%d: \n", iL, minIndex);
        // }
        // std::cout << "point\t" << iL << "\tindex\t" << minIndex << "\tmindis\t" << minDis << std::endl;
        party->Reset();

        // std::cout << "No." << iL << " " << std::flush; //进度条                                                         //设置输出精度

        std::cout << "Calculating: " << (float)iL / list.size() * 100 << "%\r" << std::flush; //进度条

        // printf("Running  %.2f%%\r", (float)iL / list.size() * 100);
        // press();
    }
    printf("\n%d points changed.\n", counts);
    // if (counts < list.size() / 3)
    // {
    //     printf("Point: ");
    //     for (int i = 0; i < index.size(); i++)
    //         printf("%u ", index[i]);
    //     printf("\n");
    // }
    // fclose(fp);
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
    // std::string circuit_dir = "../../bin/circ/"; //浮点运算电路
    // ABYParty *party = new ABYParty(role, address, port, seclvl, bitlen, nthreads, mt_alg, 4000000, circuit_dir);
    ABYParty *party = new ABYParty(role, address, port, seclvl, bitlen, nthreads, mt_alg, 4000000);
    std::vector<Sharing *> &sharings = party->GetSharings();
    //大部分计算使用算术电路，部分比较，反转及选择使用布尔电路
    ArithmeticCircuit *ac = (ArithmeticCircuit *)sharings[S_ARITH]->GetCircuitBuildRoutine();
    BooleanCircuit *bc = (BooleanCircuit *)sharings[S_BOOL]->GetCircuitBuildRoutine();
    Circuit *yc = sharings[S_YAO]->GetCircuitBuildRoutine();
    std::vector<uint64_t *> list;  //数据向量,所有明文加密数据保存于此
    dataIn(list, dimension, path); //输入文件
    std::cout << "Data has been read in!" << std::endl;

    std::vector<uint32_t> classInfo; //数据分类信息
    //数据初始化，随机分类
    srand((unsigned)20); //应随机生成后共享
    for (uint32_t i = 0; i < dimension * 2; i++)
        classInfo.push_back(i % dimension);
    for (int i = dimension * 2; i < list.size(); i++)
        classInfo.push_back(rand() % dimension);

    std::vector<uint32_t *> centers;    //质心向量
    std::vector<uint32_t *> oldCenters; //上一轮的质心向量
    for (int i = 0; i < cluster; i++)
    { //初始化填充
        uint32_t *temp1 = (uint32_t *)malloc(sizeof(uint32_t) * dimension);
        uint32_t *temp2 = (uint32_t *)malloc(sizeof(uint32_t) * dimension);
        for (int j = 0; j < dimension; j++)
        {
            temp1[j] = 0;
            temp2[j] = 0;
        }
        centers.push_back(temp1);
        oldCenters.push_back(temp2);
    }

    // for (int i = 0; i < classInfo.size(); i++)
    //     printf("%d  ", classInfo[i]);
    // printf("\n");

    //循环
    uint32_t times = 0, flag = 1;
    while (maxtime > times++ && flag)
    {
        //对每个簇，找出其质心
        findCenters(list, centers, classInfo, oldCenters, dimension, cluster, party, ac, bitlen);
        //与上一轮相比质心的移动,若每个维度均小于临界值，则退出
        printf("Round%d: Find centers!\n", times);
        flag = minDis(centers, oldCenters, dimension, diff);
        if (!flag)
            break;
        //每个数据点找到与自己欧氏距离最近的质心，并归类
        eDistance(list, centers, classInfo, dimension, bitlen, party, ac, bc, yc, role);

        // for (int i = 0; i < classInfo.size(); i++)
        //     printf("%d  ", classInfo[i]);
        // printf("\n");
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
    for (int iL = 0; iL < list.size(); iL++)
    { //对每个数
        for (int iC = 0; iC < cluster; iC++)
        { //对每个簇
            if (classInfo[iL] == iC)
            { //如果属于这个簇
                fprintf(fp, "USER %d:\tCLASS %d\n", ++index, iC);
                // std::cout << "." << std::flush;                                                     //进度条
            }
        }
        std::cout << "Printing  " << (float)iL / list.size() * 100 << "%\r" << std::flush; //进度条
    }
    fclose(fp);
    delete party;
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