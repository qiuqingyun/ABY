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

int32_t test_euclid_dist_circuit(e_role role, const std::string &address, uint16_t port, uint32_t nvals, seclvl seclvl,
								 uint32_t bitlen, uint32_t nthreads, e_mt_gen_alg mt_alg, e_sharing sharing)
{
	//常规内容
	ABYParty *party = new ABYParty(role, address, port, seclvl, bitlen, nthreads, mt_alg);
	std::vector<Sharing *> &sharings = party->GetSharings();
	Circuit *circ = sharings[sharing]->GetCircuitBuildRoutine();
	//
	uint8_t *x1 = new uint8_t[nvals];
	uint8_t *x2 = new uint8_t[nvals];
	uint8_t *y1 = new uint8_t[nvals];
	uint8_t *y2 = new uint8_t[nvals];
	srand(100); //设定随机种子
	for (uint32_t i = 0; i < nvals; i++)
	{
		x1[i] = rand();
		x2[i] = rand();
		y1[i] = rand();
		y2[i] = rand();
	}
	share *s_x1, *s_x2, *s_y1, *s_y2, *s_out;
	//role == CLIENT / SERVER
	if (role == SERVER) //Alice
	{
		s_x1 = circ->PutSIMDINGate(nvals, x1, 8, SERVER);
		s_y1 = circ->PutSIMDINGate(nvals, y1, 8, SERVER);
		s_x2 = circ->PutDummySIMDINGate(nvals, 8);
		s_y2 = circ->PutDummySIMDINGate(nvals, 8);
	}
	else //Bob
	{
		s_x1 = circ->PutDummySIMDINGate(nvals, 8);
		s_y1 = circ->PutDummySIMDINGate(nvals, 8);
		s_x2 = circ->PutSIMDINGate(nvals, x2, 8, CLIENT);
		s_y2 = circ->PutSIMDINGate(nvals, y2, 8, CLIENT);
	}
	//(x2-x1)^2+(y2-y1)^2
	share *res_x, *res_y;
	res_x = circ->PutSUBGate(s_x1, s_x2);
	res_x = circ->PutMULGate(res_x, res_x);
	res_y = circ->PutSUBGate(s_y1, s_y2);
	res_y = circ->PutMULGate(res_y, res_y);
	s_out = circ->PutADDGate(res_x, res_y);

	s_out = circ->PutOUTGate(s_out, ALL);
	party->ExecCircuit();

	uint32_t *output;
	uint32_t out_bitlen, out_nvals;
	s_out->get_clear_value_vec(&output, &out_bitlen, &out_nvals);

	std::cout << "Testing Euclidean Distance in " << get_sharing_name(sharing)
			  << " sharing, out_bitlen=" << out_bitlen << " and out_nvals=" << out_nvals << ":" << std::endl;

	for (uint32_t i = 0; i < nvals; ++i)
	{
		std::cout << "x1: " << (int)x1[i] << ", y1: " << (int)y1[i] << "; x2: " << (int)x2[i] << ", y2: " << (int)y2[i] << std::endl;
		std::cout << "Circuit result: " << sqrt(output[i]);

		std::cout << " Verification: " << sqrt((pow((double)abs(y2[i] - y1[i]), (double)2) + pow((double)abs(x2[i] - x1[i]), (double)2))) << std::endl;
	}

	delete party;
	return 0;
}

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

int main(int argc, char **argv)
{
	e_role role;
	uint32_t bitlen = 32, nvals = 31, secparam = 128, nthreads = 1;
	uint16_t port = 7766;
	std::string address = "127.0.0.1";
	int32_t test_op = -1;
	e_mt_gen_alg mt_alg = MT_OT;

	read_test_options(&argc, &argv, &role, &bitlen, &nvals, &secparam, &address,
					  &port);
	seclvl seclvl = get_sec_lvl(secparam);

	test_euclid_dist_circuit(role, address, port, nvals, seclvl, bitlen, nthreads, mt_alg, S_YAO);

	return 0;
}