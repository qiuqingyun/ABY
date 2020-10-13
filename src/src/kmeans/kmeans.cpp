#include <ENCRYPTO_utils/parse_options.h>
#include <iostream>
#include <math.h>
#include <string>
#include <vector>
#include <time.h>

//读取输入
void read_test_options(int32_t *argcp, char ***argvp, std::string *path, int *dimension,
                       int *cluster, int *maxtime, float *diff)
{
    int int_dimension = 2, int_cluster = 2, int_maxtime = 100;
    float f_diff = 10;
    std::string str_path;
    parsing_ctx options[] =
        {{(void *)&str_path, T_STR, "f", "file path", true, false},
         {(void *)&int_dimension, T_NUM, "d", "dimension, default 2", false, false},
         {(void *)&int_cluster, T_NUM, "c", "cluster, default 2", false, false},
         {(void *)&int_maxtime, T_NUM, "m", "maximum number of executions, default 100", false, false},
         {(void *)&f_diff, T_NUM, "x", "number of difference, default 10", false, false}};
    if (!parse_options(argcp, argvp, options,
                       sizeof(options) / sizeof(parsing_ctx)))
    {
        print_usage(*argvp[0], options, sizeof(options) / sizeof(parsing_ctx));
        std::cout << "Exiting" << std::endl;
        exit(0);
    }
    *path = str_path;
    *dimension = int_dimension;
    *cluster = int_cluster;
    *maxtime = int_maxtime;
    *diff = f_diff;
}

//kmeans明文计算
void kmeans(int dimension, int cluster, std::string path, int maxtime, float diff)
{
    //读入数据
    std::vector<std::vector<int>> list;
    char *pathPtr = const_cast<char *>(path.c_str());
    FILE *fpIn = fopen(pathPtr, "r");
    if (!fpIn)
    {
        printf("error!\n");
        exit(0);
    }
    int inTemp;
    //读入数据
    for (int iD = 0; iD < dimension; iD++)
    { //list{[dimendion1],[dimendion2],...}
        std::vector<int> tempVector;
        list.push_back(tempVector);
    }
    while (fscanf(fpIn, "%d", &inTemp) != EOF)
    {
        list[0].push_back(inTemp);
        for (int iD = 1; iD < dimension; iD++)
        {
            fscanf(fpIn, "%d", &inTemp);
            list[iD].push_back(inTemp);
        }
    }
    fclose(fpIn);
    std::cout << list[0].size() << " datas has been read in!" << std::endl;
    std::vector<int *> centers; //质心向量
    std::vector<int> classInfo; //数据分类信息
    for (int i = 0; i < cluster; i++)
    { //质心向量初始化
        int *temp1 = new int[dimension];
        for (int j = 0; j < dimension; j++)
            temp1[j] = 0;
        centers.push_back(temp1);
    }
    for (int iC = 0; iC < cluster; iC++) //选前cluster个数据作为质心
        for (int iD = 0; iD < dimension; iD++)
            centers[iC][iD] = list[iD][iC];
    for (int iL = 0; iL < list[0].size(); iL++) //数据分类信息初始化
        classInfo.push_back(-1);

    int times = 0;
    while (maxtime > times++)
    { //进行N次循环，涉及比较操作
        int flag = 0;
        for (int iL = 0; iL < list[0].size(); iL++)
            classInfo[iL] = -1; //将所有点的归属清零
        for (int iL = 0; iL < list[0].size(); iL++)
        { //对每个点，寻找距离最近的中心，归队
            float mindist = -1;
            int minIndex = -1;
            for (int iC = 0; iC < cluster; iC++)
            { //每个簇
                float dist = 0;
                for (int iD = 0; iD < dimension; iD++)
                {
                    dist += pow(list[iD][iL] - centers[iC][iD], 2);
                }
                if (mindist < 0 || dist < mindist)
                {
                    mindist = dist;
                    minIndex = iC;
                }
            }
            classInfo[iL] = minIndex;
        }
        for (int iC = 0; iC < cluster; iC++)
        { //对每个类重新计算中心，涉及除法操作
            int flag1 = 0;
            for (int iD = 0; iD < dimension; iD++)
            { //对每个维度
                float sum = 0, newCenter;
                int nums = 0;
                for (int iL = 0; iL < list[0].size(); iL++)
                { //遍历所有点
                    if (classInfo[iL] == iC)
                    { //找出属于这个类的点
                        sum += list[iD][iL];
                        nums++;
                    }
                }
                newCenter = sum / nums;
                if (fabsf(newCenter - centers[iC][iD]) <= diff)
                    flag1++;
                centers[iC][iD] = newCenter;
            }
            if (flag1 == dimension)
                flag++;
        }
        if (flag == cluster)
            break;
    }
    //输出结果
    FILE *fp = fopen("KmeansOut", "w");
    for (int iL = 0; iL < list[0].size(); iL++)
        for (int iC = 0; iC < cluster; iC++)
            if (classInfo[iL] == iC)                             //如果属于这个簇
                fprintf(fp, "USER %d:\tCLASS %d\n", iL + 1, iC); //输出该数据点所属的簇编号
    fclose(fp);
}

int main(int argc, char **argv)
{
    clock_t start, end;
    start = clock();
    int dimension = 2, cluster = 2, maxtime = 100;
    float diff = 0.00001;
    std::string path;
    read_test_options(&argc, &argv, &path, &dimension, &cluster, &maxtime, &diff);
    kmeans(dimension, cluster, path, maxtime, diff);
    end = clock();
    clock_t remain = (double)(end - start) / CLOCKS_PER_SEC;
    std::cout << "Total time is " << remain / 60 << "m " << remain % 60 << "s" << std::endl;
    return 0;
}