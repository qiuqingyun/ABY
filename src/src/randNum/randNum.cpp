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
    std::string str_path="./list.txt";
    parsing_ctx options[] =
        {{(void *)&str_path, T_STR, "f", "file path", false, false},
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

int *randList(int n, int a, int b, int flag)
{
    if (n > b - a && flag)
        return NULL;
    time_t t;
    /* 初始化随机数发生器 */
    srand((unsigned)time(&t) * rand());
    int *list = (int *)malloc(sizeof(int) * n);
    int *listEmpty = (int *)malloc(sizeof(int) * n);
    for (int i = 0; i < n; i++)
        listEmpty[i] = 0;
    /* 输出 a 到 b 之间的 n 个随机数 */
    for (int i = 0; i < n; i++)
    {
        int randNum = rand() % (b - a + 1) + a;
        while (flag && listEmpty[randNum])
            randNum = rand() % (b - a + 1) + a;
        list[i] = randNum;
    }
    return list;
}

int main()
{
    FILE *fp = fopen("user.txt", "w+");
    int num1 = 60000;
    int num2 = 40000;
    int *a[2];
    int *b[2];
    a[0] = randList(num1, 0, 5000, 0);
    a[1] = randList(num1, 0, 4990, 0);
    b[0] = randList(num2, 0, 5000, 0);
    b[1] = randList(num2, 5010, 10000, 0);
    for (int i = 0; i < num1; i++)
    {
        for (int j = 0; j < 2; j++)
            fprintf(fp, "%d\t", a[j][i]);
        fprintf(fp, "\n");
    }
    for (int i = 0; i < num2; i++)
    {
        for (int j = 0; j < 2; j++)
            fprintf(fp, "%d\t", b[j][i]);
        fprintf(fp, "\n");
    }
    fclose(fp);
    printf("ok\n");
    return 0;
}