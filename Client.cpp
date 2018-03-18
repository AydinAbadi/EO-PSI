#include"Client.h"
bigint* Client::encode(bigint* a,int a_size){

	bigint *res;
	res=(mpz_t*)malloc(a_size*sizeof(mpz_t));
	string bin_val, bin_hash,bin_enc;
	bigint hash;
	string s_val;
	CryptoPP::SHA1 hash2;
	string tmpk;

	for(int i=0;i<a_size;i++){
		CryptoPP::byte digest[CryptoPP::SHA1::DIGESTSIZE];
// converts each element to string
		s_val=mpz_get_str(NULL, 10,a[i]);
// computes hash value
		hash2.CalculateDigest(digest,( CryptoPP::byte*)s_val.c_str(), s_val.length());
		mpz_init(hash);
//converts hash value to big integer
		mpz_import(hash,sizeof(digest),1,sizeof(digest[0]),0,0,digest);
// converts hash to string of binary
		bin_hash=mpz_get_str(NULL,2,hash);//xxxxx In order to have smaller size encoded value we can reduce the hash

// fixes has to 160-bit
		if(bin_hash.length() < 160){ // the Sha1 output length varies between 158 and 160. Here we make sure the output is 160-bit string by padding 0.
			int dif=160-bin_hash.length();
			for (int j=0;j<dif;j++){tmpk+="0";}
			}
		bin_hash=tmpk+bin_hash;
		if(hash_length<160){bin_hash=bin_hash.substr(0,hash_length);}
// converts element to string of binary
		bin_val=mpz_get_str(NULL, 2,a[i]);
// concatenates value with hash value (both are in form of string of binary)
		bin_enc=bin_val+bin_hash;//the result contains the encoded file in binary
// converts the encoded binary string to big integer
		char tmp[bin_enc.length()];//XXXXX thie size should be smaller, revise it
		strcpy(tmp,bin_enc.c_str());
		mpz_init_set_str(res[i],tmp,2);
			s_val.clear();
			mpz_clear(hash);
			bin_val.clear();
			bin_hash.clear();
			bin_enc.clear();
			tmpk.clear();

	}
return res;

}


bigint ** Client::decode(bigint *a,int a_size){

	bigint** res;
	string s_val;
	res= (mpz_t**)malloc(a_size*sizeof(mpz_t));
	string bin_enc;
	for(int i=0;i<a_size;i++){
		res[i]=(mpz_t*)malloc(2*sizeof(mpz_t));
// converts encoded value to bit string
		bin_enc=mpz_get_str(NULL, 2, a[i]);
// extracts element
		s_val=bin_enc.substr(0,bin_enc.length()-hash_length);//outputs [0,bin_enc.length()-hash_output_size)
// converts it to bigint
		char c_val[s_val.length()];
		strcpy(c_val,s_val.c_str());
		mpz_init_set_str(res[i][0],c_val,2);
// extracts hash value (the remaining part of encoded value)
		string s_hash=bin_enc.substr(bin_enc.length()-hash_length,bin_enc.length());
// converts it to bigint
		char c_hash[s_hash.length()];
		strcpy(c_hash,s_hash.c_str());
		mpz_init_set_str(res[i][1],c_hash,2);
		s_val.clear();
		bin_enc.clear();
	}
bin_enc.clear();

return res;

}



void Client::extract(char* source,char* destination){

	int count=0;
	bigint** dec;
	int h=0;
	ifstream rd1(source);
	//bigint temp;
// counts the number of elements from source file (a file contaiing roots and some errors)
	char c1[1024];
	//count number of elem
	while(rd1>>c1){
		count++;
	}
	rd1.close();
	char c2[1024];
	bigint *vals;
	vals=(mpz_t*)malloc(count*sizeof(mpz_t));
	ifstream rd2(source);
	//copy to bigint array
// fetch the elements from the file and store them in an array 	of big int
	while(rd2>>c2){
		mpz_init_set_str(vals[h],c2,10);
		h++;
	}
	rd2.close();
 	ofstream wr(destination);
// separates the last len bits of encoded value and put the last len-bit in dec[i][1] and the rest of that in dec[i][0]
	dec=decode(vals, count);
// stores those value that hash(dec[i][1])=dec[i][0]
	for(int i=0;i<count;i++){
		if(verify(dec[i])){// veryfies whether hash(dec[i][0])=dec[i][1]
			wr<<dec[i][0];
			wr<<"\r"<<endl;
			mpz_clear(dec[i][0]);
		}
	}
	wr.close();
}


// it checks whether hash(a[1])=a[0]; if yes return true
bool Client::verify(bigint* a){

	bigint hash;
	CryptoPP::SHA1 hash1;
// converts bigint to string
	string	s_val=mpz_get_str(NULL, 10,a[0]);
// compute the value's hash
	CryptoPP::byte  digest[CryptoPP::SHA1::DIGESTSIZE];
	hash1.CalculateDigest(digest,( CryptoPP::byte*)s_val.c_str(), s_val.length());
	s_val.clear();
	mpz_init(hash);
// converts hash to bigint and fixed its size to 160
	mpz_import(hash,sizeof(digest),1,sizeof(digest[0]),0,0,digest);
	if(hash_length<160){
		string bin_hash=mpz_get_str(NULL,2,hash);
		string tmpk;
		if(bin_hash.length() < 160){
			int dif=160-bin_hash.length();
			for (int j=0;j<dif;j++){tmpk+="0";}
		}

		bin_hash=tmpk+bin_hash;
// extract the required len of hash (if its smaller than 160)
		bin_hash=bin_hash.substr(0,hash_length);
		char c[bin_hash.length()];
		strcpy(c,bin_hash.c_str());
		mpz_init_set_str(hash,c,2);
		bin_hash.clear();
		tmpk.clear();
	}
// checks whether h(a[1])=a[0]
	if(mpz_cmp(hash,a[1])==0){mpz_clear(hash); return true;}
	else {mpz_clear(hash);return false;}
}


Client::Client(){}

Client::Client(Server*server, bigint *elemenets, int el_size, int hash_len){

	hash_length=hash_len;
// encode set element
	elem=(mpz_t*)malloc(el_size*sizeof(mpz_t));
	elem=encode(elemenets,el_size);
	serv=server;
	//keep size;
	elem_size=el_size;
	//seed is generated
	Random rd;
	gmp_randstate_t rand;
	bigint ran;
	rd.init_rand3(rand, ran, 8);
	mpz_init_set(seed, ran);

	int size;
	get_xpoints(size);
	xpoint_size=size;
	get_pubModuli();
	get_NoElem_in_bucket();
	get_tablesize();
}



void Client::get_NoElem_in_bucket(){
	NoElem_in_bucket=serv->get_NoElem_in_bucket();
}

void Client::get_xpoints(int&size){
	xpoints=serv->get_xpoints (size);
	xpoint_size=size;
}

void Client::get_pubModuli(){
	bigint *ptr=(mpz_t*)malloc(1*sizeof(mpz_t));
	ptr=serv->send_pubModuli();
	mpz_init_set(pubmoduli, ptr[0]);
}

void Client::get_tablesize(){
	table_size=serv->get_table_size();
}


void Client::outsource_poly(string & poly_ID){
	Client_Dataset db;
 // contructs a hash table
	Hashtable HT(NoElem_in_bucket, elem, elem_size,table_size);
	bigint minus_one;
	mpz_init_set_str(minus_one,"-1",10);
	Polynomial *poly;
	poly=new Polynomial [table_size];
	outpoly_ID=poly_ID;
	gmp_randstate_t rand2;
	gmp_randinit_default(rand2);
	gmp_randseed(rand2,seed);
	bigint Der_pass;//derived seed. So seed is the master key to generate the other seeds
	mpz_init(Der_pass);
	//bigint DerSeed;
	//mpz_init(DerSeed);
// for every index in hash table contruct a polynomial (in poly is decided whether dummy values shuold be used
	for(int i=0;i<table_size;i++){
		Polynomial pol(HT.get_bucket(i), poly_ID, xpoints,NoElem_in_bucket, xpoint_size,pubmoduli);
		poly[i]=pol;
// assign a seed to every index of HT.	Each seed is used to blind corresponding poly.
		mpz_urandomb(Der_pass,rand2,115);
		poly[i].blind_poly(Der_pass,pubmoduli);
        }
	db.poly=poly;
	serv->store_poly(db);
}


CompPerm_Request * Client::gen_compPerm_req(){

	CompPerm_Request* ptr;
	ptr=new CompPerm_Request;
	mpz_init_set(ptr->seed,seed);
	ptr->id=outpoly_ID;
	return ptr;
}







GrantComp_Info * Client::grant_comp(CompPerm_Request * com_req,bigint **&qq, bool accept){
	GrantComp_Info * ptr;
	ptr=new GrantComp_Info;
		if(!accept){
	ptr=NULL;
	return ptr;}
	bigint **passW,*a,*Sw1,*Sw2,*z_A,*z_B,**q;
	bigint*PassWord_A,*PassWord_B,*PassWord_C;
	// the seeds s_k in PassWord_A, is used to re-generate z^A_i for bucket k
	PassWord_A=(mpz_t*)malloc(table_size*sizeof(mpz_t));
	PassWord_B=(mpz_t*)malloc(table_size*sizeof(mpz_t));
	PassWord_C=(mpz_t*)malloc(table_size*sizeof(mpz_t));
	gmp_randstate_t randA,randB,randC,rand_Pas_C;
	gmp_randinit_default(randA);
	gmp_randinit_default(randB);
	gmp_randinit_default(randC);
	gmp_randinit_default(rand_Pas_C);
	gmp_randseed(randA,seed);
	gmp_randseed(randB,com_req->seed);

	q=(mpz_t**)malloc(table_size*sizeof(mpz_t));
	passW=(mpz_t**)malloc(table_size*sizeof(mpz_t));

	z_A=(mpz_t*)malloc(xpoint_size*sizeof(mpz_t));
	z_B=(mpz_t*)malloc(xpoint_size*sizeof(mpz_t));
	a=(mpz_t*)malloc(xpoint_size*sizeof(mpz_t));
	Sw1=(mpz_t*)malloc(NoElem_in_bucket*sizeof(mpz_t));
	Sw2=(mpz_t*)malloc(NoElem_in_bucket*sizeof(mpz_t));

	gmp_randstate_t rand00,rand01,rand02,rand03,rand04,rand05;
	gmp_randinit_default(rand00);
	gmp_randinit_default(rand01);
	gmp_randinit_default(rand02);
	gmp_randinit_default(rand03);
	gmp_randinit_default(rand04);

	bigint ran1;
	string w_1;
	string w_2;
	Random rd;
	for(int i=0;i<xpoint_size;i++){
		mpz_init(z_A[i]);
		mpz_init(a[i]);
		mpz_init(z_B[i]);
	}
	for(int j=0;j<NoElem_in_bucket;j++){
		mpz_init(Sw1[j]);
		mpz_init(Sw2[j]);
	}
	gmp_randstate_t rand;
	bigint ran;
	//ran=(paillier_random_seed*)malloc(sizeof(paillier_random_seed));

	rd.init_rand3(rand,ran,8);// generate a fresh master seed. ran->seed contains a fresh seed
	gmp_randseed(randC,ran);//************************** Client A need to send only ran->seed to the server. XXXXX Apply the change
	for(int i=0;i<table_size;i++){
		q[i]=(mpz_t*)malloc(xpoint_size*sizeof(mpz_t));

		mpz_init(PassWord_A[i]);
		mpz_init(PassWord_B[i]);
		mpz_init(PassWord_C[i]);
		mpz_urandomb(PassWord_A[i],randA,115);
		mpz_urandomb(PassWord_B[i],randB,115);
		mpz_urandomb(PassWord_C[i],randC,115);
		gmp_randseed(rand_Pas_C,PassWord_C[i]);
		passW[i]=(mpz_t*)malloc(3*sizeof(mpz_t));

		for(int j=0;j<3;j++){// we need three seeds for each bucket.
			//1:to geenrate a[i] 2,3:to generate sw1 and sw2
			mpz_init(passW[i][j]);
			mpz_urandomb(passW[i][j],rand_Pas_C,115);
		}
		gmp_randseed(rand00,PassWord_A[i]);
		//re-gen seed for each bucket of client B
		gmp_randseed(rand01,PassWord_B[i]);
		gmp_randseed(rand02,passW[i][0]);
		//gen sw1  // picks a set of pr-values
		gmp_randseed(rand03,passW[i][1]);
		//gensw2
		gmp_randseed(rand04,passW[i][2]);

		for(int j=0;j<NoElem_in_bucket;j++){
			mpz_urandomb(Sw1[j],rand03,115);
			mpz_urandomb(Sw2[j],rand04,115);}
			//gen w1
			Polynomial w1(Sw1,w_1,xpoints,NoElem_in_bucket,xpoint_size,pubmoduli);
			//gen w2
			Polynomial w2(Sw2,w_2,xpoints,NoElem_in_bucket,xpoint_size,pubmoduli);
			//compute q[i]
			bigint* temp_w1=w1.get_values();
			bigint* temp_w2=w2.get_values();
			for(int j=0;j<xpoint_size;j++){

				mpz_urandomb(z_A[j],rand00,115);
				mpz_urandomb(a[j],rand02,115);
				mpz_urandomb(z_B[j],rand01,115);
				mpz_init(q[i][j]);
				//mpz_mul(z_A[j],z_A[j],w1.values[j]);
				mpz_mul(z_A[j],z_A[j],temp_w1[j]);
				mpz_mul(z_B[j],z_B[j],temp_w2[j]);
				mpz_add(z_A[j],z_A[j],z_B[j]);
				mpz_add(q[i][j],z_A[j],a[j]);
				mpz_mod(q[i][j],q[i][j],pubmoduli);
			}
	}

	// it needs to compute (1) qi  (2) store the three seeds in GrantComp_Info (3) store
	qq=q;
	mpz_init_set(ptr->seed,ran);
	ptr->id=new string[2];
	ptr->id[0]=com_req->id;
	ptr->id[1]=outpoly_ID;
	return ptr;
}


void Client::find_intersection(Server_Result * res,int*& size,bigint**q){

	bigint *un_bl;
	//bigint zero;
	//mpz_init_set_str(zero,"0",10);
	//bigint one;
	//mpz_init_set_str(one,"1",10);

	char * tmp_mod = mpz_get_str(NULL,10,pubmoduli);
	ZZ p=to_ZZ(tmp_mod);
	ZZ_p::init(p);
	ZZ_pX P;
	un_bl=(mpz_t*)malloc(xpoint_size*sizeof(mpz_t));
	ZZ one(1);
	//bigint temp2;
	//mpz_init(temp2);


	//fmpz_t n;
	//fmpz_init_set_readonly(n, pubmoduli);
	//fmpz_mod_poly_t x;
	//fmpz_mod_poly_init(x, n);



	ofstream wr("temproots.txt");
	for(int i=0;i<table_size;i++){

			// removes the blinding factors

				for(int j=0;j<xpoint_size;j++){
				mpz_init(un_bl[j]);
				mpz_sub(un_bl[j],pubmoduli,q[i][j]);
				mpz_add(un_bl[j],un_bl[j],res->result[i][j]);
				//mpz_mod(un_bl[j],un_bl[j],pubmoduli);
			}
			//interpolate
			bigint *values=interpolate(xpoint_size,xpoints,un_bl,pubmoduli);

			//find the roots
			for(int j=0;j<xpoint_size;j++){
			char * tmp = mpz_get_str(NULL,10,values[j]);
			//mpz_clear(values[j]);
			ZZ_p dd=to_ZZ_p(conv<ZZ> (tmp));
			SetCoeff(P,j,dd);
			//fmpz_mod_poly_set_coeff_mpz(x ,i,  values[i]);
			}
			//P.normalize();
			ZZ_p a=LeadCoeff(P);
			ZZ aa=rep(a);
			if(aa>one){ MakeMonic(P);}
			Vec< Pair< ZZ_pX, long > > factors;
			CanZass(factors, P);
			vec_ZZ_p root;
			//int cn=0;
			for(int j=0;j<factors.length() ;j++){
				if(factors[j].a.rep.length()==2){
					root=FindRoots(factors[j].a);
					for(int k=0;k<root.length();k++){

						wr<<root[k];
						wr<<"\r"<<endl;
					}
				}
			}
	}
	wr.close();
	//mpz_clear(temp2);

}

bigint* Client::interpolate(int size, bigint* a, bigint* b,bigint N)// a:x, b:y-coordinate
{
   long m = size;
   bigint* prod;
      prod=(mpz_t*)malloc(size*sizeof(mpz_t));
	  for(int i=0;i<size;i++){
		  mpz_init_set(prod[i],a[i]);
	  }
   //prod = a;
   bigint t1, t2;
   mpz_init(t1);
   mpz_init(t2);
   int k, i;
   bigint* res;
   res=(mpz_t*)malloc(size*sizeof(mpz_t));
	   bigint aa;
   for (k = 0; k < m; k++) {
      mpz_init_set(aa ,a[k]);
      mpz_init_set_str(t1,"1",10);
      for (i = k-1; i >= 0; i--) {
         mpz_mul(t1, t1, aa);
		 mpz_mod(t1, t1,N);//xxx
         mpz_add(t1, t1, prod[i]);
      }
      mpz_init_set_str(t2,"0",10);
      for (i = k-1; i >= 0; i--) {
         mpz_mul(t2, t2, aa);
		 mpz_mod(t2, t2,N);//xxx
         mpz_add(t2, t2, res[i]);
      }
      mpz_invert(t1, t1,N);
      mpz_sub(t2, b[k], t2);
      mpz_mul(t1, t1, t2);

      for (i = 0; i < k; i++) {
         mpz_mul(t2, prod[i], t1);
		 mpz_mod(t2, t2,N);//xxx

         mpz_add(res[i], res[i], t2);
		 mpz_mod(res[i], res[i],N);
      }
      mpz_init_set(res[k], t1);
	  mpz_mod(res[k], res[k],N);
      if (k < m-1) {
         if (k == 0)
            mpz_neg(prod[0], prod[0]);
         else {
            mpz_neg(t1, a[k]);
            mpz_add(prod[k], t1, prod[k-1]);
            for (i = k-1; i >= 1; i--) {
               mpz_mul(t2, prod[i], t1);
			   mpz_mod(t2, t2,N);//xxx
               mpz_add(prod[i], t2, prod[i-1]);
            }
            mpz_mul(prod[0], prod[0], t1);
			mpz_mod(prod[0], prod[0],N);//xxx
         }
      }
   }

   while (m > 0 && (res[m-1]==0)) m--;

   mpz_clear(t1);
   mpz_clear(t2);
   return res;
}
