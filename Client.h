//#include<iostream>
using namespace std;
//#include<string>
//#include<gmp.h>
//#include <gmpxx.h>
//#include<cstring>
//#include<iostream>
//#include<fstream>
#include "Server.h"
//#include <stdlib.h>
//#include "Hashtable.h"

typedef mpz_t bigint;
/*
//#include "Polynomial.h"
#include <NTL/ZZ.h>
#include <NTL/ZZXFactoring.h>
#include <NTL/ZZ_pXFactoring.h>
#include <NTL/ZZ_pEX.h>
#include <NTL/RR.h>
#include <NTL/tools.h>
using namespace NTL;

#include <NTL/vec_ZZVec.h>
#include <NTL/fileio.h>
#include <NTL/FacVec.h>
#include <NTL/new.h>
#include <vector>
*/

class Client{

public:
	Client();
	Client (Server*serv, bigint *, int elem_size,int hash_len);
	void outsource_poly(string & poly_ID);
	CompPerm_Request * gen_compPerm_req();
	GrantComp_Info * grant_comp(CompPerm_Request * ,bigint **&qq, bool);
	void find_intersection(Server_Result *,int*& size,bigint**q);// size: number of roots found. q=blinding factor remover
	void extract(char* source,char* destination);


private:
	//bool is_occupied(int i);// checks whether its original elements are in a bucket i.
	void get_tablesize();

	bigint* encode(bigint* a,int a_size);
	void get_NoElem_in_bucket();

	bigint ** decode(bigint *a,int a_size);
	bool verify(bigint* a);// veryfies whether hash(a[0])=a[1]
	void get_pubModuli(); 
	void get_xpoints(int&size);

	bigint *elem;
	int elem_size;
	string outpoly_ID;
	bigint* interpolate(int size,bigint* a,bigint* b,bigint N);//XXXX uncmment it
	Server*serv;
	bigint * xpoints;
	bigint  pubmoduli;
	int xpoint_size;
	bigint seed;

	int NoElem_in_bucket;// maximum number of elements in a bucket
	//int *oc_buckets; //index of occupied buckets.
	//int oc_buk_size;
	int table_size;
	int hash_length;// length of hash value cancatenated with the actual element for encoding
};




