#include<iostream>
#include"Server.h"
#include<gmp.h>
#include <gmpxx.h>
#include<sstream>
using namespace std;
#include<iomanip>
#include <string>
#include<cstring>
#include<fstream>
//#include <openssl/rand.h>
/*
#include "cryptopp/cryptlib.h"
#include"cryptopp/hmac.h"
#include"cryptopp/secblock.h"
#include <cryptopp/sha.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>


*/
#include<math.h>
#include <stdio.h>
#include <stdlib.h>
#include <cstdlib>
//#include <cryptopp/rsa.h>
//#include <cryptopp/dh.h>
//#include <cryptopp/sha.h>
//#include <cryptopp/aes.h>
//#include <cryptopp/cryptlib.h>
//#include <cryptopp/hex.h>
//#include <cryptopp/filters.h>
//#include <cryptopp/des.h>
//#include<cryptopp/integer.h>
//#include <cryptopp/files.h>
//#include <cryptopp/osrng.h>
//#include <cryptopp/randpool.h>
//#include <cryptopp/integer.h>
//#include <cryptopp/aes.h>
//#include <cryptopp/ccm.h>
#include <assert.h>


Server::Server(){}


Server::Server(int num_xpoints, int dbs_size,int pu_mod_bitsize,int maxSetsize,int NoEl_bucket,int tb_size)
{

	max_setsize=maxSetsize;
	NoElem_in_bucket=NoEl_bucket;
	pu_moduli_bitsize=pu_mod_bitsize;
	xpoint_size=num_xpoints;

	xpoints= gen_randSet(num_xpoints,80);   // the last parameter size depends of the element and field size.
	// Therfore, for smaller set (and field) sie it shoudl be smaller.

	pu_moduli=gen_randSet(1,pu_moduli_bitsize);// 512 the size of public moduli=max|element's domain|
	mpz_nextprime(pu_moduli[0],pu_moduli[0]);
	db_size=dbs_size;

	count=0;// no dbs is stored now
	db=new Client_Dataset[dbs_size];
	table_size=tb_size;
}



bigint* Server::gen_randSet (int size, int max_bitsize){ // the 2nd argument allows us 1-to set xpoints less than public moduli 2-to set public moduli smaller than N for each clients so they do not need to compare it with N.
	Random rd;
	mpz_t *pr_val;
	pr_val=(mpz_t*)malloc(size*sizeof(mpz_t));
	int max_bytesize=max_bitsize;
	gmp_randstate_t rand;
	bigint ran;
	//ran=(paillier_random_seed*)malloc(sizeof(paillier_random_seed));
	rd.init_rand3(rand, ran, max_bytesize);


	for(int i=0;i<size;i++){
		mpz_init(pr_val[i]);
		mpz_urandomb(pr_val[i],rand,max_bitsize);// The last argument is in bit
	}
	return pr_val;
}


bigint* Server::get_xpoints(int&size){

	size=xpoint_size;
	bigint *ptr=xpoints;
	return ptr;
}


bigint*  Server::send_pubModuli(){

	bigint *ptr;
	ptr=(mpz_t*)malloc(1*sizeof(mpz_t));
	ptr=pu_moduli;
	return ptr;
}

int Server::get_maxSetsize(){

	return max_setsize;
}

int Server::get_NoElem_in_bucket(){

	return NoElem_in_bucket;
}

void Server::set_db(int index, Client_Dataset &p){
	db[index]=p;
}

void Server::store_poly(Client_Dataset& p){
	if(count<=db_size){
		if(p.poly[0].get_poly_ID()=="B_ID")
			set_db(0,p);
		else {++count;set_db(count,p);}
	}
	else {
		cout<<"\n Error: No space to store anymore Dataset."<<endl;
		return;
	}
}

 Server_Result * Server::compute_result (GrantComp_Info * grantComp_info){

	Server_Result*ptr;
	ptr=new Server_Result;
	int b_index=find_db_index(grantComp_info->id[0]);
	int a_index=find_db_index(grantComp_info->id[1]);
	if(b_index==1000000 || a_index==1000000){
		return ptr=NULL;}
	bigint *a, *Sw1, *Sw2, **t, *temp;
	bigint *PassWord_C, **passW;
	PassWord_C=(mpz_t*)malloc(table_size*sizeof(mpz_t));
	a=(mpz_t*)malloc(xpoint_size*sizeof(mpz_t));
	Sw1=(mpz_t*)malloc(NoElem_in_bucket*sizeof(mpz_t));
	Sw2=(mpz_t*)malloc(NoElem_in_bucket*sizeof(mpz_t));
	t=(mpz_t**)malloc(table_size*sizeof(mpz_t));
	for(int i=0;i<table_size;i++)
		t[i]=(mpz_t*)malloc(xpoint_size*sizeof(mpz_t));
	temp=(mpz_t*)malloc(xpoint_size*sizeof(mpz_t));
	Client_Dataset db_B=get_db(b_index);
	Client_Dataset db_A=get_db(a_index);
	passW=(mpz_t**)malloc(table_size*sizeof(mpz_t));
	gmp_randstate_t rand1,rand2,rand3,randC,rand_Pas_C;
	gmp_randinit_default(rand1);
	gmp_randinit_default(rand2);
	gmp_randinit_default(rand3);
	gmp_randinit_default(randC);
	gmp_randinit_default(rand_Pas_C);
	string w_1,w_2;
	for(int k=0;k<NoElem_in_bucket;k++){
			mpz_init(Sw1[k]);
			mpz_init(Sw2[k]);
	}
	for(int j=0;j<xpoint_size;j++){
		mpz_init(a[j]);
		mpz_init(temp[j]);
	}
	gmp_randseed(randC,grantComp_info->seed);


	for(int i=0;i<table_size;i++){
		//regen key for a[i]
		mpz_init(PassWord_C[i]);
		mpz_urandomb(PassWord_C[i],randC,115);
		gmp_randseed(rand_Pas_C,PassWord_C[i]);
		passW[i]=(mpz_t*)malloc(3*sizeof(mpz_t));
		for(int j=0;j<3;j++){// we need three seeds for each bucket.
			//1:to geenrate a[i] 2,3:to generate sw1 and sw2
			mpz_init(passW[i][j]);
			mpz_urandomb(passW[i][j],rand_Pas_C,115);
		}

  gmp_randseed(rand1,passW[i][0]);
	gmp_randseed(rand2,passW[i][1]);
  gmp_randseed(rand3,passW[i][2]);
	for(int k=0;k<NoElem_in_bucket;k++){
			mpz_urandomb(Sw1[k],rand2,115);
			mpz_urandomb(Sw2[k],rand3,115);}

	Polynomial w1(Sw1, w_1, xpoints,NoElem_in_bucket, xpoint_size, pu_moduli[0]);
		Polynomial w2(Sw2, w_2, xpoints,NoElem_in_bucket, xpoint_size, pu_moduli[0]);
		bigint *temp_a=db_A.poly[i].get_values();
		bigint *temp_w1=w1.get_values();
		bigint *temp_b=db_B.poly[i].get_values();
		bigint *temp_w2=w2.get_values();

		for(int j=0;j<xpoint_size;j++){
			mpz_urandomb(a[j],rand1,115);//regen a[i]
			mpz_init(t[i][j]);
			mpz_mul(temp[j],temp_a[j],temp_w1[j]);
			mpz_mul(t[i][j],temp_b[j],temp_w2[j]);
			mpz_add(t[i][j],t[i][j],a[j]);
			mpz_add(t[i][j],t[i][j],temp[j]);
			mpz_mod(t[i][j],t[i][j],pu_moduli[0]);
		}
	}

       	ptr->result= t;
	return ptr;
}


 int Server::find_db_index(string id){
	 int i;
	 string s;
	 for(i=0;i<db_size;i++){
		 Client_Dataset p=get_db(i);
		 if(p.poly[0].get_poly_ID()==id){
			 return i;
			 }
	 }
	 if(i==db_size){
		 cout<<"There is exist no poly. in server with ID:"<<id<<endl;
		 return i=1000000;// the value only is used to indicate NULL
	 }
}
