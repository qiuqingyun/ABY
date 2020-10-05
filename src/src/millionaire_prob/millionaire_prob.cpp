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

int32_t test_millionaire_prob_circuit(e_role role, uint32_t money, const std::string &address, uint16_t port, seclvl seclvl,
									  uint32_t bitlen, uint32_t nthreads, e_mt_gen_alg mt_alg, e_sharing sharing)
{
	ABYParty *party = new ABYParty(role, address, port, seclvl, bitlen, nthreads, mt_alg);
	std::vector<Sharing *> &sharings = party->GetSharings();
	Circuit *circ = sharings[sharing]->GetCircuitBuildRoutine();
	share *s_alice_money, *s_bob_money, *s_out;
	uint32_t alice_money = 0, bob_money = 0, output;
	printf("your money is %d\n", money);
	if (role == CLIENT)
	{
		s_alice_money = circ->PutDummyINGate(bitlen);
		s_bob_money = circ->PutINGate(money, bitlen, CLIENT);
	} 
	else
	{ //role == CLIENT / SERVER
		s_alice_money = circ->PutINGate(money, bitlen, SERVER);
		s_bob_money = circ->PutDummyINGate(bitlen);
	}
	s_out = circ->PutGTGate(s_alice_money, s_bob_money);
	s_out = circ->PutOUTGate(s_out, ALL);
	party->ExecCircuit();
	output = s_out->get_clear_value<uint32_t>();
	if ((output && role == SERVER) || (!output && role == CLIENT))
		printf("You win!\n");
	else
		printf("You lose!\n");
	delete party;
	return 0;
}

int32_t read_test_options(int32_t *argcp, char ***argvp, e_role *role, uint32_t *money,
						  uint32_t *bitlen, uint32_t *nvals, uint32_t *secparam, std::string *address,
						  uint16_t *port, int32_t *test_op)
{

	uint32_t int_role = 0, int_money = 0, int_port = 0;
	parsing_ctx options[] =
		{
			{(void *)&int_role, T_NUM, "r", "Role: 0/1", true, false},
			{(void *)&int_money, T_NUM, "m", "Number of money", true, false},
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
	*money = (uint32_t)int_money;

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
	uint32_t money;
	uint32_t bitlen = 32, nvals = 31, secparam = 128, nthreads = 1;
	uint16_t port = 7766;
	std::string address = "127.0.0.1";
	int32_t test_op = -1;
	e_mt_gen_alg mt_alg = MT_OT;

	read_test_options(&argc, &argv, &role, &money, &bitlen, &nvals, &secparam, &address,
					  &port, &test_op);
	seclvl seclvl = get_sec_lvl(secparam);

	test_millionaire_prob_circuit(role, money, address, port, seclvl, 32, nthreads, mt_alg, S_YAO);

	return 0;
}