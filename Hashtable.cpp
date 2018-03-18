/*

#include<gmp.h>
#include <gmpxx.h>
#include<sstream>
using namespace std;
#include<iomanip>
#include <string>
#include<math.h>
#include <stdio.h>
#include <cstdlib>
#include <assert.h>
#include <omp.h>
#include <time.h>

*/
#include"Hashtable.h"
typedef mpz_t bigint;

//#include"Polynomial.h"



bigint * Hashtable::get_bucket(int index){return T[index];}


Hashtable::Hashtable ( int NoElem_in_bucket, bigint* elem, int elem_size,int table_size){

	int indx[elem_size];
// convert z to bigint zz, where zz will be used as a moduli
	bigint zz;
	mpz_init(zz);
	mpz_set_ui(zz,table_size);

	T= (mpz_t**)malloc(table_size*sizeof(mpz_t));
	for(int i=0;i<table_size;i++){
		T[i]=(mpz_t*)malloc(NoElem_in_bucket*sizeof(mpz_t));}

	for(int i=0;i<table_size;i++){
		for(int k=0;k<NoElem_in_bucket;k++)
			mpz_init_set_str(T[i][k],"-1",10);}
	bigint *b;// a temporary array
	b= (mpz_t*)malloc(elem_size*sizeof(mpz_t));

       	string s_val;
	CryptoPP::SHA512 hash2;

	for(int i=0;i<elem_size;i++){

		 s_val=mpz_get_str(NULL,10,elem[i]);

		 unsigned int nDataLen = s_val.length();
		CryptoPP::byte  digest[CryptoPP::SHA512::DIGESTSIZE];
	        hash2.CalculateDigest(digest,( CryptoPP::byte*)s_val.c_str(), nDataLen);
		s_val.clear();

       		mpz_init(b[i]);
		mpz_import(b[i],sizeof(digest),1,sizeof(digest[0]),0,0,digest);

		mpz_mod(b[i],b[i],zz);
		indx[i]=mpz_get_ui (b[i]);
		mpz_clear(b[i]);

	}

	//finds the occupied buckets and sets (1)oc_buckets (2)oc_buk_size
	int new_size;

	oc_buckets=find_oc_buckets(indx,elem_size,new_size);
	oc_buk_size=new_size;
	bigint minus_one;
	mpz_init_set_str(minus_one,"-1",10);

	for(int i=0;i<elem_size;i++){
		for(int j=0;j<NoElem_in_bucket;){
			if(mpz_cmp(T[indx[i]][j],minus_one)==0)
			{
				mpz_set(T[indx[i]][j],elem[i]);break;
			}
			else{
				j++;
				if(j==NoElem_in_bucket){cout<<"\n===== OVERFLLOW; Value:"<<elem[i]<< ", was not inserted into HT"<<endl;}}
		}
	}

	T_size=table_size;
	max_bucket_load=NoElem_in_bucket;
	mpz_clear(zz);

}

bool Hashtable::exits(int b,int *a,int size){

	for(int i=0;i<size;i++){
		if(b==a[i]){return true;break;}
	}
	return  false;
}

int* Hashtable::find_oc_buckets(int*b, int size,int&new_size){

	int*a;
	int k=0;
	a=new int[size];

	for(int i=0;i<size;i++){a[i]=-1;}
	for(int i=0;i<size;i++){
		if(!exits(b[i],a,size)){
			a[k]=b[i];
			k++;
		}
	}

// k can be smaller than size, thus we need aa to return a smaller sized array than
	int *aa;
	aa=new int[k];
	for(int i=0;i<k;i++){
	aa[i]=a[i];
	}

	new_size=k;
	delete[]a;
	return aa;
}
