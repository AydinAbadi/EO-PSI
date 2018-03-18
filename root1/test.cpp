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
using namespace std;
typedef mpz_t bigint;
#include <omp.h>
#include <time.h>




bool exist(bigint a,bigint *b,int size){
	
	for(int i=0;i<size;i++){

		if(mpz_cmp(a,b[i])==0){return true;break;}
	}
	return  false;
}









int main(){


bigint a;
mpz_init(a);
int aa=10;
mpz_set_ui(a,aa);

cout<<a<<endl;



/*

  int a_size=1000000;
int b_size=1000000;


	ifstream rd1("a.txt");
	char c1[1024];

	bigint *a;
	//int h=0;
	a=(mpz_t*)malloc(a_size*sizeof(mpz_t));
	int i=0;
	while(rd1>>c1){
		mpz_init_set_str(a[i],c1,10);
		i++;}
	
	rd1.close();


	ifstream rd2("b.txt");
	char c2[1024];
	bigint *b;
	int j=0;
	b=(mpz_t*)malloc(b_size*sizeof(mpz_t));
	//copy to bigint array
	while(rd2>>c2){
		mpz_init_set_str(b[j],c2,10);
		j++;}
	
	rd2.close();



// count roots0 elements
	ifstream rd3("roots2.txt");
	int root0_size=0;
	char c3[1024];
	while(rd3>>c3){
	root0_size++;
	}
	rd3.close();


// count roots1 elements
	ifstream rd6("roots1.txt");
	int root1_size=0;
	char c6[1024];
	while(rd6>>c6){
	root1_size++;
	}
	rd6.close();





	ifstream rd4("roots2.txt");

	char c4[1024];
	bigint *c0;
	int h=0;
	cout<<"\nroot0_size:"<<root0_size<<endl;
	c0=(mpz_t*)malloc(root0_size*sizeof(mpz_t));
	//copy to bigint array
	while(rd4>>c4){
		mpz_init_set_str(c0[h],c4,10);
		h++;
	}
	rd4.close();

	cout<<"\nroot1_size:"<<root1_size<<endl;


	ifstream rd5("roots1.txt");
	char c5[1024];
	bigint *c1;
	int hh=0;
	cout<<"\nroot1_size:"<<root1_size<<endl;
	c1=(mpz_t*)malloc(root1_size*sizeof(mpz_t));
	//copy to bigint array
	while(rd5>>c5){
		mpz_init_set_str(c1[hh],c5,10);
		hh++;
	}
	rd5.close();









int co_a=0;
int co_b=0;





for(int k=0;k<root0_size;k++){
	if(exist(c0[k],c1,root1_size)){co_a++;}
}


	for(int p=0;p<root1_size;p++){
	if(exist(c1[p],c0,root0_size)){co_b++;}
}


cout<<"\ncount1:"<<co_a<<endl;

cout<<"\ncount2:"<<co_b<<endl;

*/


}



