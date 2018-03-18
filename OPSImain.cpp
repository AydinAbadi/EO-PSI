/*
#include<iostream>
#include<gmp.h>
#include <gmpxx.h>
#include<sstream>
using namespace std;
#include<iomanip>
#include <string>
#include<cstring>
#include<fstream>
#include<math.h>
#include <stdio.h>
#include <stdlib.h>
#include <cstdlib>
#include <assert.h>

*/

//#include "cryptopp/pwdbased.h"
//#include <cryptopp/pwdbased.h>
//#include "cryptopp/hmac.h"

//#include <cryptopp/hmac.h>
//#include <cryptopp/cryptlib.h>
#include "OPSImain.h"
#include <time.h>
#include <chrono>
#include <stdio.h>
typedef mpz_t bigint;

int get_size(char* a_sou){
	int count=0;
	ifstream rd(a_sou);
	//bigint temp;
	char c[1024];
	//count number of elem
	while(rd>>c){
		count++;
	}
	rd.close();
	return count;
}

bigint* get_vals(char* a_sou,int & size){

	int count=0;
	ifstream rd1(a_sou);
	//bigint temp;
	char c1[1024];
	//count number of elem
	while(rd1>>c1){
		count++;
	}
	rd1.close();
	size=count;

	char c2[1024];
	bigint *vals;
	int h=0;
	vals=(mpz_t*)malloc(count*sizeof(mpz_t));
	ifstream rd2(a_sou);
	//copy to bigint array
	while(rd2>>c2){
		mpz_init_set_str(vals[h],c2,10);
		h++;
	}
	rd2.close();
	return vals;

}



bool exits(string a,bigint *b,int size){
	bigint d;
	char*c_con=new char[a.length()];
		strcpy(c_con,a.c_str());
		mpz_init_set_str(d,c_con,10);
	for(int i=0;i<size;i++){

		if(mpz_cmp(d,b[i])==0){return true;break;}
	}
	return  false;
}


bool exits2(bigint a,bigint *b,int size){

	for(int i=0;i<size;i++){

		if(mpz_cmp(a,b[i])==0){return true;break;}
	}
	return  false;
}



int main(){
int xsize=101;//242	//***** Note that the number of x is determined by bucket_max_load
int pub_mod_bitsize=40;
int max_setsize=10;//
int bucket_max_load=50;
int table_length=104858;
int hash_len=0;
int elem_bit_size=32;
// make sure hash_len+Elem_bit_size<pub_mod_bitsize.
if (hash_len+elem_bit_size>pub_mod_bitsize || hash_len+elem_bit_size==pub_mod_bitsize){
  cout<< "XXXXXX hash_len+elem_bit_size must be smaller than pub_mod_bitsize"<<endl;
  return 0;
}
if(xsize< (2*bucket_max_load)+1) {cout<<"\nxsize must be greater than 2*bucket_max_load)+1, reset it\n";return 0;}
double exp=1;//Number of experiments

double outsource=0;
double auth=0;
double cloudcomp=0;
double clientresultret=0;
int count=1;
for(int l=0;l<exp;l++){
Server serv(xsize,2,pub_mod_bitsize,max_setsize, bucket_max_load,table_length);// generates random xpoints// For now max_setsize make no sense but I left it there as I may find an accurate formula with which the server can set HT parameters
Server * serv_ptr (& serv);

// Assigning random values to two sets a and b.


mpz_t *aa,*bb;
int size_a=10;
int size_b=10;
aa=(mpz_t*)malloc(size_a*sizeof(mpz_t));
bb=(mpz_t*)malloc(size_b*sizeof(mpz_t));
aa=serv.gen_randSet (size_a, elem_bit_size);
bb=serv.gen_randSet (size_b, elem_bit_size);
int interSec_size=1;
cout<<"\n("<<count<<")"<<endl;
cout<<"\nElem in common:"<<endl;
for(int i=0;i< interSec_size;i++){
mpz_set(bb[i],aa[i]);
cout<<"\t\t"<<bb[i]<<endl;
}



/*

bigint *aa,*bb;

int a_size,b_size;
string a_source="a.txt";
string b_source="b.txt";

char *a_sou=new char[a_source.length()];
char *b_sou=new char[b_source.length()];

strcpy( a_sou,a_source.c_str());
strcpy(b_sou,b_source.c_str());

int size_a,size_b;

aa=get_vals(a_sou,size_a);
bb=get_vals(b_sou,size_b);

*/

cout<<"\n----------------------------------------------------------------\n";
cout<<"\t Set_a_size:       "<<size_a<<endl;
cout<<"\t Set_b_size:       "<<size_b<<endl;
cout<<"\t Pub_mod_bitsize:  "<<pub_mod_bitsize<<endl;
cout<<"\t Bucket_max_load:  "<<bucket_max_load<<endl;
cout<<"\t Table_length:     "<<table_length<<endl;
//cout<<"\t Elem_bit_size:    "<<elem_bit_size<<endl;
cout<<"\n----------------------------------------------------------------\n";



//double start000=clock();
auto start000 = std::chrono::high_resolution_clock::now();
Client A(serv_ptr,aa,size_a,hash_len);
string as="A_ID";


cout<<"Client A outsourcing..."<<endl;
A.outsource_poly(as);

//double end000=omp_get_wtime();
//double end000=clock();
auto end000 = std::chrono::high_resolution_clock::now();
std::chrono::duration<double> elapsed = end000 - start000;
cout<<"\nOutsource Time :"<<elapsed.count()<<endl;

outsource+=elapsed.count();

//Client B(serv_ptr,bb,set_size,hash_len);
cout<<"Client B outsourcing..."<<endl;

Client B(serv_ptr,bb,size_b,hash_len);
string bs="B_ID";

B.outsource_poly(bs);
cout<<"\n----------------"<<endl;
auto start5 = std::chrono::high_resolution_clock::now();
auto start1 = std::chrono::high_resolution_clock::now();

CompPerm_Request*req=B.gen_compPerm_req();
//double end1=clock();
auto end1 = std::chrono::high_resolution_clock::now();
std::chrono::duration<double> elapsed1 = end1 - start1;
//float tk1=elapsed1.count();
cout<<"\nTime to compute comp_request:"<<elapsed1.count()<<endl;
cout<<"\n----------------"<<endl;
bigint **q;

//double start2=clock();
auto start2 = std::chrono::high_resolution_clock::now();

GrantComp_Info*ptr1=A.grant_comp(req,q,true);
//double end2=clock();
auto end2 = std::chrono::high_resolution_clock::now();
std::chrono::duration<double> elapsed2 = end2 - start2;
cout<<"\nTime to  Grant computation:"<<elapsed2.count()<<endl;
auth+=elapsed2.count();
cout<<"\n----------------"<<endl;

//double start3=clock();
auto start3 = std::chrono::high_resolution_clock::now();

Server_Result*res=serv.compute_result(ptr1);
//double end3=clock();
auto end3 = std::chrono::high_resolution_clock::now();
std::chrono::duration<double> elapsed3 = end3 - start3;
float tk2=elapsed3.count();
cout<<"\nTime to run Serv.comput():"<<elapsed3.count()<<endl;
cloudcomp+=elapsed3.count();
cout<<"\n----------------"<<endl;
string **values;
int* sz;
auto start4 = std::chrono::high_resolution_clock::now();
B.find_intersection(res,sz,q);
cout<<"\n----------------"<<endl;
auto end5 = std::chrono::high_resolution_clock::now();
std::chrono::duration<double> elapsed5 = end5-start5;
float tk3=elapsed5.count();
cout<<"\nTotal Computation Time Excluding outsource Time:"<<elapsed5.count()<<endl;
cout<<endl;
cout<<endl;
cout<<"\nExtracting VALID roots\n";
string sou="temproots.txt";
string des="roots.txt";
char *c_sou=new char[sou.length()];
char *c_des=new char[des.length()];
strcpy( c_sou, sou.c_str());
strcpy(c_des,des.c_str());
B.extract(c_sou,c_des);
auto end4 = std::chrono::high_resolution_clock::now();
std::chrono::duration<double> elapsed4 = end4 - start4;
cout<<"\nTime to find intersection:"<<elapsed4.count()<<endl;
clientresultret+=elapsed4.count();
count++;
}
cout<<endl;
cout<<"\n====================================\n"<<endl;
cout<<"\n\n\nAverage Outsource Time:"<<outsource/exp<<endl;
cout<<"\n\n\nAverage authorization Time:"<<auth/exp<<endl;
cout<<"\n\n\nAverage Cloud-side Computation Time:"<<cloudcomp/exp<<endl;
cout<<"\n\n\nClient side result retieval Time:"<<clientresultret/exp<<endl;
return 0;

}
//cd UEO-PSI-new/latest-EO-PSI/For-test
//g++ Rand.o Hashtable.o Polynomial.o  Client.o  Server.o OPSImain.cpp -o vt  -lgmpxx -lntl -lgmp -lm  -lcryptopp
//$ g++ -I$home/win7/include  polynomial.o server.o client.o OPSImain.cpp -lgomp  -L/cygdrive/c/cygwin/home/Win7/libpaillier -l:libpaillier.a  -L$home/win7/lib -lntl -lgmpxx -lgmp -lm
