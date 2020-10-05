#include <ENCRYPTO_utils/crypto/crypto.h>
#include <ENCRYPTO_utils/parse_options.h>
#include <abycore/aby/abyparty.h>
#include <abycore/circuit/booleancircuits.h>
#include <abycore/circuit/arithmeticcircuits.h>
#include <abycore/circuit/circuit.h>
#include <abycore/circuit/share.h>
#include <abycore/sharing/sharing.h>
#include <cassert>
#include <iomanip>
#include <iostream>
#include <math.h>
#include <string>
#include <stdlib.h>

#define ALICE "ALICE"
#define BOB "BOB"

//读取输入
void read_test_options(int32_t *argcp, char ***argvp, e_role *role, std::string *path, uint32_t *dimension,
					   uint32_t *cluster, uint32_t *maxtime, float *diff,
					   uint32_t *bitlen, uint32_t *nvals, uint32_t *secparam, std::string *address,
					   uint16_t *port, int32_t *test_op, uint32_t *test_bit)
{
	uint32_t int_role = 0, int_port = 0, int_testbit = 0, int_dimension = 2, int_cluster = 2, int_maxtime = 100;
	float flo_diff = 0.00001;
	std::string str_path;
	parsing_ctx options[] =
		{{(void *)&int_role, T_NUM, "r", "Role: 0/1", true, false},
		 {(void *)&str_path, T_STR, "f", "file path", true, false},
		 {(void *)&int_dimension, T_NUM, "d", "dimension, default 2", false, false},
		 {(void *)&int_cluster, T_NUM, "c", "cluster, default 2", false, false},
		 {(void *)&int_maxtime, T_NUM, "m", "maximum number of executions, default 100", false, false},
		 {(void *)&flo_diff, T_NUM, "x", "number of difference, default 0.00001", false, false},
		 {(void *)&int_testbit, T_NUM, "i", "test bit", false, false},
		 {(void *)nvals, T_NUM, "n", "Number of parallel operation elements", false, false},
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
	*cluster = int_cluster;
	*maxtime = int_maxtime;
	*diff = flo_diff;
}
//生成范围内的随机数
uint32_t randInt(uint32_t begin, uint32_t end)
{
	if (end - begin <= 0)
		return 0;
	time_t t;
	uint32_t randNum;
	srand((unsigned)time(&t) * rand());
	randNum = rand() % (end - begin + 1) + begin;
	return randNum - 1;
}

//每个数据点找到与自己欧氏距离最近的质心，并归类
void eDistance(std::vector<float *> list, std::vector<float *> centers,
			   std::vector<uint32_t> &nodes, uint32_t dimension)
{
	for (int iL = 0; iL < list.size(); iL++)
	{ //对每个数
		uint32_t minIndex = -1;
		float minDis = -1;
		for (int iC = 0; iC < centers.size(); iC++)
		{ //对每个簇
			float dis = 0;
			for (int iD = 0; iD < dimension; iD++)
			{ //对每个维度
				dis += pow(list[iL][iD] - centers[iC][iD], 2);
			}
			if (minDis < 0 || dis < minDis)
			{ //找到最近的质心
				minDis = dis;
				minIndex = iC;
			}
		}
		nodes[iL] = minIndex;
	}
}

//与上一轮相比质心的移动,若每个维度均小于临界值，则退出
uint32_t minDis(std::vector<float *> centers, std::vector<float *> oldCenters,
				uint32_t dimension, float diff)
{
	uint32_t flag = 1;
	for (int iC = 0; iC < centers.size(); iC++) //对每个簇
		for (int iD = 0; iD < dimension; iD++)	//对每个维度
		{

			flag = flag && (abs(centers[iC][iD] - oldCenters[iC][iD]) <= diff);
		}
	return flag ? 0 : 1; //每个维度均小于临界值，则返回0
}

//与对方进行交互，计算出真正的簇质心
void aby(e_role role, std::vector<float *> &centers, uint32_t dimension,
		 const std::string &address, uint16_t port, seclvl seclvl, uint32_t nvals, uint32_t nthreads,
		 e_mt_gen_alg mt_alg, e_sharing sharing)
{
	for (int iC = 0; iC < centers.size(); iC++)
	{ //对每个簇,使用SIMD门，相加然后除以2
		// 初始化
		share *s_num1, *s_num2, *s_cons, *s_out;
		uint32_t bitlen = 64;
		std::string circuit_dir = "../../bin/circ/"; //浮点运算电路
		ABYParty *party = new ABYParty(role, address, port, seclvl, bitlen, nthreads, mt_alg, 100000, circuit_dir);
		std::vector<Sharing *> &sharings = party->GetSharings();
		BooleanCircuit *circ = (BooleanCircuit *)sharings[sharing]->GetCircuitBuildRoutine();
		uint64_t *out_vals_add;
		uint32_t out_bitlen_add, out_nvals;
		uint64_t vals[dimension];
		for (int i = 0; i < dimension; i++)
		{
			double temp = (double)centers[iC][i];
			vals[i] = *(uint64_t *)&temp;
		}

		//将数据输入SIMD门中
		share *ain = circ->PutSIMDINGate(nvals, vals, bitlen, SERVER);
		share *bin = circ->PutSIMDINGate(nvals, vals, bitlen, CLIENT);
		// 浮点加法
		share *sum = circ->PutFPGate(ain, bin, ADD, bitlen, nvals, no_status);
		// 输出配置
		share *add_out = circ->PutOUTGate(sum, ALL);
		// 运行电路
		party->ExecCircuit();
		add_out->get_clear_value_vec(&out_vals_add, &out_bitlen_add, &out_nvals);
		for (uint32_t iD = 0; iD < dimension; iD++)
		{ //提取明文数据
			double val = *((double *)&out_vals_add[iD]);
			if (isnan(val) || isinf(val))
			{ //计算错误
				printf("\nerror!\n");
				exit(0);
			}
			centers[iC][iD] = val / 2;
		}
		delete party, s_num1, s_num2, s_cons, s_out, sum, add_out;
		std::cout << "." << std::flush; //进度条
	}
}

//对每个簇，找出其质心
void findCenters(std::vector<float *> list, std::vector<float *> &centers,
				 std::vector<uint32_t> nodes, std::vector<float *> &oldCenters,
				 uint32_t dimension, uint32_t cluster)
{
	for (int iC = 0; iC < cluster; iC++)
	{ //对每个簇
		for (int iD = 0; iD < dimension; iD++)
		{ //对每个维度
			float old = centers[iC][iD];
			oldCenters[iC][iD] = old;
			float sum = 0, num = 0;
			for (int iS = 0; iS < list.size(); iS++)
			{ //若该数据点属于这个簇，则求和
				if (nodes[iS] == iC)
				{
					sum += list[iS][iD];
					num++;
				}
			}
			centers[iC][iD] = sum / num; //计算质心
		}
	}
}

int main(int argc, char **argv)
{ //主函数，ABY基础定义
	e_role role;
	uint32_t bitlen = 64, nvals = 4, secparam = 128, nthreads = 1;
	uint16_t port = 7766;
	std::string address = "127.0.0.1";
	int32_t test_op = -1;
	e_mt_gen_alg mt_alg = MT_OT;
	uint32_t test_bit = 0;
	uint32_t dimension = 2, cluster = 2, maxtime = 100;
	float diff = 0.00001;
	std::string path;
	seclvl seclvl = get_sec_lvl(secparam);
	read_test_options(&argc, &argv, &role, &path, &dimension, &cluster, &maxtime, &diff,
					  &bitlen, &nvals, &secparam, &address, &port, &test_op, &test_bit);

	//从文件获取数据
	char *pathPtr = const_cast<char *>(path.c_str());
	FILE *fp = fopen(pathPtr, "r");
	float inTemp;
	std::vector<float *> list;	  //数据向量
	std::vector<float *> centers; //质心向量
	for (int i = 0; i < cluster; i++)
	{
		float *temp = (float *)malloc(sizeof(float) * dimension);
		for (int j = 0; j < dimension; j++)
			temp[j] = 0;
		centers.push_back(temp);
	}
	std::vector<float *> oldCenters; //上一轮的质心向量
	for (int i = 0; i < cluster; i++)
	{
		float *temp = (float *)malloc(sizeof(float) * dimension);
		for (int j = 0; j < dimension; j++)
			temp[j] = 0;
		oldCenters.push_back(temp);
	}
	assert(fp != NULL);
	//读入数据
	while (fscanf(fp, "%f", &inTemp) != EOF)
	{
		float *node = (float *)malloc(sizeof(float) * dimension);
		node[0] = inTemp;
		for (int indexJ = 1; indexJ < dimension; indexJ++)
			fscanf(fp, "%f", &node[indexJ]);
		list.push_back(node);
	}
	fclose(fp);
	std::cout << "running";

	std::vector<uint32_t> nodes; //储存归类信息
	//第一次随机归类
	for (int i = 0; i < dimension; i++)
		nodes.push_back(i);
	for (int i = dimension; i < list.size(); i++)
		nodes.push_back(randInt(1, cluster));

	/*	
	对数据进行循环运算
	1.计算出每个簇在自己样本中的质心
	2.运用安全计算，共同计算出每个簇在大样本中的质心
	3.对每一个数据点进行归类
	*/
	uint32_t times = 0, flag = 1;
	while (maxtime > times++ && flag)
	{
		//对每个簇，找出其质心
		findCenters(list, centers, nodes, oldCenters, dimension, cluster);
		//与对方进行交流，计算出真正的簇质心
		aby(role, centers, dimension, address, port, seclvl, nvals, nthreads, mt_alg, S_BOOL);
		//与上一轮相比质心的移动,若每个维度均小于临界值，则退出
		flag = minDis(centers, oldCenters, dimension, diff);
		//每个数据点找到与自己欧氏距离最近的质心，并归类
		eDistance(list, centers, nodes, dimension);
	}

	//输出结果
	std::string fileName = role ? BOB : ALICE;
	for (int iC = 0; iC < cluster; iC++)
	{ //对每个簇
		std::string indexNum = std::to_string(iC);
		std::string fileNameTemp = fileName + indexNum;
		char *namePtr = const_cast<char *>(fileNameTemp.c_str());
		FILE *fp = fopen(namePtr, "w");
		for (int iL = 0; iL < list.size(); iL++)
		{ //对每个数
			if (nodes[iL] == iC)
			{ //如果属于这个簇
				for (int iD = 0; iD < dimension; iD++)
					fprintf(fp, "%f ", list[iL][iD]);
				fprintf(fp, "\n");
			}
		}
		fclose(fp);
	}
	printf("\nfinished!\n");
	return 0;
}
