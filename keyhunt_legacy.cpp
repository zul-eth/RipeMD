#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <vector>
#include <inttypes.h>
#include "base58/libbase58.h"
#include "oldbloom/oldbloom.h"
#include "bloom/bloom.h"
#include "util.h"
#include "hashing.h"
#include "gmp256k1/GMP256K1.h"
#include "gmp256k1/Point.h"
#include "gmp256k1/Int.h"
#include "gmp256k1/IntGroup.h"
#include "gmp256k1/Random.h"
#if defined(_WIN64) && !defined(__CYGWIN__)
#include "getopt.h"
#include <windows.h>
#else
#include <unistd.h>
#include <pthread.h>
#include <sys/random.h>
#endif
#ifdef __unix__
#ifdef __CYGWIN__
#else
#include <linux/random.h>
#endif
#endif
#define CRYPTO_NONE 0
#define CRYPTO_BTC 1
#define MODE_XPOINT 0
#define MODE_ADDRESS 1
#define MODE_BSGS 2
#define MODE_RMD160 3
#define MODE_PUB2RMD 4
#define MODE_MINIKEYS 5
#define MODE_VANITY 6
#define SEARCH_UNCOMPRESS 0
#define SEARCH_COMPRESS 1
#define SEARCH_BOTH 2
uint32_t  THREADBPWORKLOAD = 1048576;
struct checksumsha256	{
	char data[32];
	char backup[32];
};

struct bsgs_xvalue	{
	uint8_t value[6];
	uint64_t index;
};

struct address_value	{
	uint8_t value[20];
};

struct tothread {
	int nt;     //Number thread
	char *rs;   //range start
	char *rpt;  //rng per thread
};
struct bPload	{
	uint32_t threadid;
	uint64_t from;
	uint64_t to;
	uint64_t counter;
	uint64_t workload;
	uint32_t aux;
	uint32_t finished;
};

#if defined(_WIN64) && !defined(__CYGWIN__)
#define PACK( __Declaration__ ) __pragma( pack(push, 1) ) __Declaration__ __pragma( pack(pop))
PACK(struct publickey
{
	uint8_t parity;
	union {
		uint8_t data8[32];
		uint32_t data32[8];
		uint64_t data64[4];
	} X;
});
#else
struct __attribute__((__packed__)) publickey {
  uint8_t parity;
	union	{
		uint8_t data8[32];
		uint32_t data32[8];
		uint64_t data64[4];
	} X;
};
#endif
const char *Ccoinbuffer_default = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
char *Ccoinbuffer = (char*) Ccoinbuffer_default;
char *str_baseminikey = NULL;
char *raw_baseminikey = NULL;
char *minikeyN = NULL;
int minikey_n_limit;
#define CPU_GRP_SIZE 1024
std::vector<Point> Gn;
Point _2Gn;
std::vector<Point> GSn;
Point _2GSn;
void init_generator();
void sleep_ms(int milliseconds);
void writekey(bool compressed,Int *key);
void checkpointer(void *ptr,const char *file,const char *function,const  char *name,int line);
bool isBase58(char c);
bool isValidBase58String(char *str);
bool readFileAddress(char *fileName);
bool forceReadFileAddress(char *fileName);
bool initBloomFilter(struct bloom *bloom_arg,uint64_t items_bloom);
void writeFileIfNeeded(const char *fileName);
void calcualteindex(int i,Int *key);
#if defined(_WIN64) && !defined(__CYGWIN__)
DWORD WINAPI thread_process(LPVOID vargp);
#else
void *thread_process(void *vargp);
#endif
char *pubkeytopubaddress(char *pkey,int length);
void pubkeytopubaddress_dst(char *pkey,int length,char *dst);
void rmd160toaddress_dst(char *rmd,char *dst);
int THREADOUTPUT = 0;
char *bit_range_str_min;
char *bit_range_str_max;
const char *modes[7] = {"rmd160"};
#if defined(_WIN64) && !defined(__CYGWIN__)
HANDLE* tid = NULL;
HANDLE write_keys;
HANDLE write_random;
HANDLE bsgs_thread;
HANDLE *bPload_mutex;
#else
pthread_t *tid = NULL;
pthread_mutex_t write_keys;
pthread_mutex_t write_random;
pthread_mutex_t bsgs_thread;
pthread_mutex_t *bPload_mutex;
#endif
uint64_t FINISHED_THREADS_COUNTER = 0;
uint64_t FINISHED_THREADS_BP = 0;
uint64_t THREADCYCLES = 0;
uint64_t THREADCOUNTER = 0;
uint64_t FINISHED_ITEMS = 0;
uint64_t OLDFINISHED_ITEMS = -1;
uint8_t byte_encode_crypto = 0x00;
struct bloom bloom;
uint64_t *steps = NULL;
unsigned int *ends = NULL;
uint64_t N = 0;
uint64_t N_SEQUENTIAL_MAX = 0x100000000;
uint64_t DEBUGCOUNT = 0x400;
uint64_t u64range;
Int OUTPUTSECONDS;

// Membaca langsung 
int FLAGREADEDFILE1 = 0;



int FLAGSKIPCHECKSUM = 0;
int FLAGENDOMORPHISM = 0;
int FLAGBLOOMMULTIPLIER = 1;

int FLAGQUIET = 0;
int FLAGMATRIX = 0;
int KFACTOR = 1;
int MAXLENGTHADDRESS = -1;
int NTHREADS = 1;

int FLAGSTRIDE = 0;
int FLAGSEARCH = 2;
int FLAGBITRANGE = 0;
int FLAGRANGE = 0;
int FLAGFILE = 0;
int FLAGMODE = MODE_ADDRESS;
int FLAGCRYPTO = 0;
int FLAGRAWDATA	= 0;
int FLAGRANDOM = 0;
int FLAG_N = 0;
int FLAGPRECALCUTED_P_FILE = 0;
int bitrange;
char *str_N;
char *range_start;
char *range_end;
char *str_stride;
Int stride;
uint64_t BSGS_XVALUE_RAM = 6;
uint64_t BSGS_BUFFERXPOINTLENGTH = 32;
uint64_t BSGS_BUFFERREGISTERLENGTH = 36;
int *bsgs_found;
std::vector<Point> OriginalPointsBSGS;
bool *OriginalPointsBSGScompressed;
uint64_t bytes;
char checksum[32],checksum_backup[32];
char buffer_bloom_file[1024];
struct bsgs_xvalue *bPtable;
struct address_value *addressTable;
struct oldbloom oldbloom_bP;
const char *str_limits_prefixs[7] = {"Mkeys/s","Gkeys/s","Tkeys/s","Pkeys/s","Ekeys/s","Zkeys/s","Ykeys/s"};
const char *str_limits[7] = {"1000000","1000000000","1000000000000","1000000000000000","1000000000000000000","1000000000000000000000","1000000000000000000000000"};
Int int_limits[7];
Int BSGS_GROUP_SIZE;
Int BSGS_CURRENT;
Int BSGS_R;
Int BSGS_AUX;
Int BSGS_N;
Int BSGS_N_double;
Int BSGS_M;
Int BSGS_M_double;
Int BSGS_M2;
Int BSGS_M2_double;
Int BSGS_M3;
Int BSGS_M3_double;
Int ONE;
Int ZERO;
Int MPZAUX;
std::vector<Point> BSGS_AMP2;
std::vector<Point> BSGS_AMP3;
Point point_temp,point_temp2;
Int n_range_start;
Int n_range_end;
Int n_range_diff;
Int n_range_aux;
Int lambda,lambda2,beta,beta2;
Secp256K1 *secp;
int main(int argc, char **argv)	{
	char buffer[2048];
	char rawvalue[32];
	struct tothread *tt;
	Tokenizer t,tokenizerbsgs;
	char *fileName = NULL;
	char *hextemp = NULL;
	char *aux = NULL;
	char *aux2 = NULL;
	char *str_seconds = NULL;
	char *str_total = NULL;
	char *str_pretotal = NULL;
	char *str_divpretotal = NULL;
	char *bf_ptr = NULL;
	char *bPload_threads_available;
	FILE *fd,*fd_aux1,*fd_aux2,*fd_aux3;
	uint64_t BASE,PERTHREAD_R,itemsbloom,itemsbloom2,itemsbloom3;
	uint32_t finished;
	int i,readed,continue_flag,check_flag,c,salir,index_value;
	Int total,pretotal,debugcount_mpz,seconds,div_pretotal,int_aux,int_r,int_q,int58;
	struct bPload *bPload_temp_ptr;
	size_t rsize;

	
#if defined(_WIN64) && !defined(__CYGWIN__)
	DWORD s;
	write_keys = CreateMutex(NULL, FALSE, NULL);
	write_random = CreateMutex(NULL, FALSE, NULL);
	bsgs_thread = CreateMutex(NULL, FALSE, NULL);
#else
	pthread_mutex_init(&write_keys,NULL);
	pthread_mutex_init(&write_random,NULL);
	pthread_mutex_init(&bsgs_thread,NULL);
	int s;
#endif

	srand(time(NULL));

	secp = new Secp256K1();
	secp->Init();
	OUTPUTSECONDS.SetInt32(30);
	ZERO.SetInt32(0);
	ONE.SetInt32(1);
	BSGS_GROUP_SIZE.SetInt32(CPU_GRP_SIZE);
	int_randominit();
	printf("[+] Version v.0.01 \n");
	while ((c = getopt(argc, argv, "deh6MqRSB:b:c:C:E:f:I:k:l:m:N:n:p:r:s:t:v:G:8:z:")) != -1) {
    switch(c) {
        case 'b':
            bitrange = strtol(optarg,NULL,10);
            if(bitrange > 0 && bitrange <=256 ) {
                MPZAUX.Set(&ONE);
                MPZAUX.ShiftL(bitrange-1);
                bit_range_str_min = MPZAUX.GetBase16();
                checkpointer((void *)bit_range_str_min,__FILE__,"malloc","bit_range_str_min" ,__LINE__ -1);
                MPZAUX.Set(&ONE);
                MPZAUX.ShiftL(bitrange);
                if(MPZAUX.IsGreater(&secp->order)) {
                    MPZAUX.Set(&secp->order);
                }
                bit_range_str_max = MPZAUX.GetBase16();
                checkpointer((void *)bit_range_str_max,__FILE__,"malloc","bit_range_str_min" ,__LINE__ -1);
                FLAGBITRANGE = 1;
            }
            else {
                fprintf(stderr,"[E] invalid bits param: %s.\n",optarg);
            }
        break;
        case 'f':
            FLAGFILE = 1;
            fileName = optarg;
        break;
        
        case 'k':
            KFACTOR = (int)strtol(optarg,NULL,10);
            if(KFACTOR <= 0) {
                KFACTOR = 1;
            }
            printf("[+] K factor %i\n",KFACTOR);
        break;

        case 'l':
            FLAGSEARCH = SEARCH_COMPRESS;
            printf("[+] Search compress only\n");
        break;
        case 'M':
            FLAGMATRIX = 1;
            printf("[+] Matrix screen\n");
        break;
        case 'm':
        case MODE_RMD160:
            FLAGMODE = MODE_RMD160;
            FLAGCRYPTO = CRYPTO_BTC;
            printf("[+] Mode rmd160\n");
        break;
        case 'n':
            FLAG_N = 1;
            str_N = optarg;
        break;
        case 'q':
            FLAGQUIET    = 1;
            printf("[+] Quiet thread output\n");
        break;
    }
}

	if(FLAGSTRIDE)	{
		if(str_stride[0] == '0' && str_stride[1] == 'x')	{
			stride.SetBase16(str_stride+2);
		}
		else{
			stride.SetBase10(str_stride);
		}
		printf("[+] Stride : %s\n",stride.GetBase10());
	}
	else	{
		FLAGSTRIDE = 1;
		stride.Set(&ONE);
	}
	init_generator();
// Batas Range
	if(FLAGMODE != MODE_BSGS && FLAGMODE != MODE_MINIKEYS)	{
		BSGS_N.SetInt32(DEBUGCOUNT);
		if(FLAGRANGE == 0 && FLAGBITRANGE == 0)	{
			n_range_start.SetInt32(1);
			n_range_end.Set(&secp->order);
			n_range_diff.Set(&n_range_end);
			n_range_diff.Sub(&n_range_start);
		}
		else	{
			if(FLAGBITRANGE)	{
				n_range_start.SetBase16(bit_range_str_min);
				n_range_end.SetBase16(bit_range_str_max);
				n_range_diff.Set(&n_range_end);
				n_range_diff.Sub(&n_range_start);
			}
			else	{
				if(FLAGRANGE == 0)	{
					fprintf(stderr,"[W] WTF!\n");
				}
			}
		}
	}
	N = 0;
// Tentukan
	if(FLAGMODE != MODE_BSGS )	{
		if(FLAG_N){
			if(str_N[0] == '0' && str_N[1] == 'x')	{
				N_SEQUENTIAL_MAX =strtol(str_N,NULL,16);
			}
			else	{
				N_SEQUENTIAL_MAX =strtol(str_N,NULL,10);
			}
			
			if(N_SEQUENTIAL_MAX < 1024)	{
				fprintf(stderr,"[I] n value need to be equal or great than 1024, back to defaults\n");
				FLAG_N = 0;
				N_SEQUENTIAL_MAX = 0x100000000;
			}
			if(N_SEQUENTIAL_MAX % 1024 != 0)	{
				fprintf(stderr,"[I] n value need to be multiplier of  1024\n");
				FLAG_N = 0;
				N_SEQUENTIAL_MAX = 0x100000000;
			}
		}
		printf("[+] N = %p\n",(void*)N_SEQUENTIAL_MAX);
		switch(FLAGMODE)	{
			case MODE_RMD160:
				if(!readFileAddress(fileName))	{
					fprintf(stderr,"[E] Unenexpected error\n");
					exit(EXIT_FAILURE);
				}
			break;
		}
	
	}
	if(FLAGMODE != MODE_BSGS)	{
	
		steps = (uint64_t *) calloc(NTHREADS,sizeof(uint64_t));
		checkpointer((void *)steps,__FILE__,"calloc","steps" ,__LINE__ -1 );
		ends = (unsigned int *) calloc(NTHREADS,sizeof(int));
		checkpointer((void *)ends,__FILE__,"calloc","ends" ,__LINE__ -1 );
#if defined(_WIN64) && !defined(__CYGWIN__)
		tid = (HANDLE*)calloc(NTHREADS, sizeof(HANDLE));
#else
		tid = (pthread_t *) calloc(NTHREADS,sizeof(pthread_t));
#endif
		checkpointer((void *)tid,__FILE__,"calloc","tid" ,__LINE__ -1 );
	
		for(i= 0;i < NTHREADS; i++)	{
			tt = (tothread*) malloc(sizeof(struct tothread));
			checkpointer((void *)tt,__FILE__,"malloc","tt" ,__LINE__ -1 );
			tt->nt = i;
			steps[i] = 0;
			s = 0;
			switch(FLAGMODE)	{
#if defined(_WIN64) && !defined(__CYGWIN__)
				case MODE_RMD160:
				
					tid[i] = CreateThread(NULL, 0, thread_process, (void*)tt, 0, &s);
				break;
#else
				case MODE_RMD160:
					s = pthread_create(&tid[i],NULL,thread_process,(void *)tt);
				break;
#endif
			}
#if defined(_WIN64) && !defined(__CYGWIN__)
			if (tid[i] == NULL) {
#else
			if(s != 0)	{
#endif
				fprintf(stderr,"[E] pthread_create thread_process\n");
				exit(EXIT_FAILURE);
			}
		}
	}
	i = 0;
	
	while(i < 7)	{
		int_limits[i].SetBase10((char*)str_limits[i]);
		i++;
	}
	
	continue_flag = 1;
	total.SetInt32(0);
	pretotal.SetInt32(0);
	debugcount_mpz.Set(&BSGS_N);
	seconds.SetInt32(0);
	do	{
		sleep_ms(1000);
		seconds.AddOne();
		check_flag = 1;
		for(i = 0; i <NTHREADS && check_flag; i++) {
			check_flag &= ends[i];
		}
		if(check_flag)	{
			continue_flag = 0;
		}
		if(OUTPUTSECONDS.IsGreater(&ZERO) ){
			MPZAUX.Set(&seconds);
			MPZAUX.Mod(&OUTPUTSECONDS);
			if(MPZAUX.IsZero()) {
				total.SetInt32(0);
				i = 0;
				while(i < NTHREADS) {
					pretotal.Set(&debugcount_mpz);
					pretotal.Mult(steps[i]);					
					total.Add(&pretotal);
					i++;
				}
				
				if(FLAGENDOMORPHISM)	{
					if(FLAGMODE == MODE_XPOINT)	{
						total.Mult(3);
					}
					else	{
						total.Mult(6);
					}
				}
				else	{
					if(FLAGSEARCH == SEARCH_COMPRESS)	{
						total.Mult(2);
					}
				}
				
#ifdef _WIN64
				WaitForSingleObject(bsgs_thread, INFINITE);
#else
				pthread_mutex_lock(&bsgs_thread);
#endif			
				pretotal.Set(&total);
				pretotal.Div(&seconds);
				str_seconds = seconds.GetBase10();
				str_pretotal = pretotal.GetBase10();
				str_total = total.GetBase10();
				
				if(pretotal.IsLower(&int_limits[0]))	{
					if(FLAGMATRIX)	{
						sprintf(buffer,"[+] Total %s keys in %s seconds: %s keys/s\n",str_total,str_seconds,str_pretotal);
					}
					else	{
						sprintf(buffer,"\r[+] Total %s keys in %s seconds: %s keys/s\r",str_total,str_seconds,str_pretotal);
					}
				}
				else	{
					i = 0;
					salir = 0;
					while( i < 6 && !salir)	{
						if(pretotal.IsLower(&int_limits[i+1]))	{
							salir = 1;
						}
						else	{
							i++;
						}
					}

					div_pretotal.Set(&pretotal);
					div_pretotal.Div(&int_limits[salir ? i : i-1]);
					str_divpretotal = div_pretotal.GetBase10();
					if(FLAGMATRIX)	{
						sprintf(buffer,"[+] Total %s keys in %s seconds: ~%s %s (%s keys/s)\n",str_total,str_seconds,str_divpretotal,str_limits_prefixs[salir ? i : i-1],str_pretotal);
					}
					else	{
						if(THREADOUTPUT == 1)	{
							sprintf(buffer,"\r[+] Total %s keys in %s seconds: ~%s %s (%s keys/s)\r",str_total,str_seconds,str_divpretotal,str_limits_prefixs[salir ? i : i-1],str_pretotal);
						}
						else	{
							sprintf(buffer,"\r[+] Total %s keys in %s seconds: ~%s %s (%s keys/s)\r",str_total,str_seconds,str_divpretotal,str_limits_prefixs[salir ? i : i-1],str_pretotal);
						}
					}
					free(str_divpretotal);

				}
				printf("%s",buffer);
				fflush(stdout);
				THREADOUTPUT = 0;			
#ifdef _WIN64
				ReleaseMutex(bsgs_thread);
#else
				pthread_mutex_unlock(&bsgs_thread);
#endif

				free(str_seconds);
				free(str_pretotal);
				free(str_total);
			}
		}
	}while(continue_flag);
	printf("\nEnd\n");
#ifdef _WIN64
	CloseHandle(write_keys);
	CloseHandle(write_random);
	CloseHandle(bsgs_thread);
#endif
}

void rmd160toaddress_dst(char *rmd,char *dst){
	char digest[60];
	size_t pubaddress_size = 40;
	digest[0] = byte_encode_crypto;
	memcpy(digest+1,rmd,20);
	sha256((uint8_t*)digest, 21,(uint8_t*) digest+21);
	sha256((uint8_t*)digest+21, 32,(uint8_t*) digest+21);
	if(!b58enc(dst,&pubaddress_size,digest,25)){
		fprintf(stderr,"error b58enc\n");
	}
}
char *pubkeytopubaddress(char *pkey,int length)	{
	char *pubaddress = (char*) calloc(MAXLENGTHADDRESS+10,1);
	char *digest = (char*) calloc(60,1);
	size_t pubaddress_size = MAXLENGTHADDRESS+10;
	checkpointer((void *)pubaddress,__FILE__,"malloc","pubaddress" ,__LINE__ -1 );
	checkpointer((void *)digest,__FILE__,"malloc","digest" ,__LINE__ -1 );
 	sha256((uint8_t*)pkey, length,(uint8_t*) digest);
	rmd160((const unsigned char*)digest,32, (unsigned char*)digest+1);
	digest[0] = 0;
	sha256((uint8_t*)digest, 21,(uint8_t*) digest+21);
	sha256((uint8_t*)digest+21, 32,(uint8_t*) digest+21);
	if(!b58enc(pubaddress,&pubaddress_size,digest,25)){
		fprintf(stderr,"error b58enc\n");
	}
	free(digest);
	return pubaddress;
}
int searchbinary(struct address_value *buffer,char *data,int64_t array_length) {
	int64_t half,min,max,current;
	int r = 0,rcmp;
	min = 0;
	current = 0;
	max = array_length;
	half = array_length;
	while(!r && half >= 1) {
		half = (max - min)/2;
		rcmp = memcmp(data,buffer[current+half].value,20);
		if(rcmp == 0)	{
			r = 1;
		}
		else	{
			if(rcmp < 0) {
				max = (max-half);
			}
			else	{
				min = (min+half);
			}
			current = min;
		}
	}
	return r;
}

#if defined(_WIN64) && !defined(__CYGWIN__)
DWORD WINAPI thread_process(LPVOID vargp) {
#else
void *thread_process(void *vargp)	{
#endif
	struct tothread *tt;
	Point pts[CPU_GRP_SIZE];
	Point endomorphism_beta[CPU_GRP_SIZE];
	Point endomorphism_beta2[CPU_GRP_SIZE];
	Point endomorphism_negeted_point[4];
	Int dx[CPU_GRP_SIZE / 2 + 1];
	IntGroup *grp = new IntGroup(CPU_GRP_SIZE / 2 + 1);
	Point startP;
	Int dy;
	Int dyn;
	Int _s;
	Int _p;
	Point pp;
	Point pn;
	int l,pp_offset,pn_offset;
	int i,hLength = (CPU_GRP_SIZE / 2 - 1);
	uint64_t j,count;
	Point R,temporal,publickey;
	int r,thread_number,continue_flag = 1,k;
	char *hextemp = NULL;
	char publickeyhashrmd160[20];
	char publickeyhashrmd160_uncompress[4][20];
	char rawvalue[32];
	char publickeyhashrmd160_endomorphism[12][4][20];
	bool calculate_y = FLAGSEARCH == SEARCH_UNCOMPRESS || FLAGSEARCH == SEARCH_BOTH;
	Int key_mpz,keyfound,temp_stride;
	tt = (struct tothread *)vargp;
	thread_number = tt->nt;
	free(tt);
	grp->Set(dx);
// Kunci Private



	do {

			if(n_range_start.IsLower(&n_range_end))	{
#if defined(_WIN64) && !defined(__CYGWIN__)
				WaitForSingleObject(write_random, INFINITE);
				key_mpz.Set(&n_range_start);
				n_range_start.Add(N_SEQUENTIAL_MAX);
				ReleaseMutex(write_random);
#else
				pthread_mutex_lock(&write_random);
				key_mpz.Set(&n_range_start);
				n_range_start.Add(N_SEQUENTIAL_MAX);
				pthread_mutex_unlock(&write_random);
#endif
			}
			else	{
				continue_flag = 0;
			}
		
		if(continue_flag)	{
			count = 0;
			if(FLAGMATRIX)	{
			    // Jika FLAGMATRIX aktif, cetak base key ke layar
					hextemp = key_mpz.GetBase16();
					printf("Base key: %s thread %i\n",hextemp,thread_number);
					fflush(stdout);
					free(hextemp);
			}
			else	{
				if(FLAGQUIET == 0){
				  // Jika tidak, cetak base key dengan overwrite ke layar
					hextemp = key_mpz.GetBase16();
					printf("\rBase key: %s     \r",hextemp);
					fflush(stdout);
					free(hextemp);
					THREADOUTPUT = 1;
				}
			}
			do {
				temp_stride.SetInt32(CPU_GRP_SIZE / 2);
				temp_stride.Mult(&stride);
				key_mpz.Add(&temp_stride);
	 			startP = secp->ComputePublicKey(&key_mpz);
				key_mpz.Sub(&temp_stride);

				for(i = 0; i < hLength; i++) {
					dx[i].ModSub(&Gn[i].x,&startP.x);
				}
				dx[i].ModSub(&Gn[i].x,&startP.x);
				dx[i + 1].ModSub(&_2Gn.x,&startP.x); 
				grp->ModInv();
				pts[CPU_GRP_SIZE / 2] = startP;
				for(i = 0; i<hLength; i++) {
					pp = startP;
					pn = startP;
					dy.ModSub(&Gn[i].y,&pp.y);
					_s.ModMulK1(&dy,&dx[i]);
					_p.ModSquareK1(&_s);
					pp.x.ModNeg();
					pp.x.ModAdd(&_p);
					pp.x.ModSub(&Gn[i].x);
					if(calculate_y)	{
						pp.y.ModSub(&Gn[i].x,&pp.x);
						pp.y.ModMulK1(&_s);
						pp.y.ModSub(&Gn[i].y);
					}
					dyn.Set(&Gn[i].y);
					dyn.ModNeg();
					dyn.ModSub(&pn.y);
					_s.ModMulK1(&dyn,&dx[i]);
					_p.ModSquareK1(&_s);
					pn.x.ModNeg();
					pn.x.ModAdd(&_p);
					pn.x.ModSub(&Gn[i].x);
					if(calculate_y)	{
						pn.y.ModSub(&Gn[i].x,&pn.x);
						pn.y.ModMulK1(&_s);
						pn.y.ModAdd(&Gn[i].y);
					}
					pp_offset = CPU_GRP_SIZE / 2 + (i + 1);
					pn_offset = CPU_GRP_SIZE / 2 - (i + 1);
					pts[pp_offset] = pp;
					pts[pn_offset] = pn;
					
					if(FLAGENDOMORPHISM)	{
						if( calculate_y  )	{
							endomorphism_beta[pp_offset].y.Set(&pp.y);
							endomorphism_beta[pn_offset].y.Set(&pn.y);
							endomorphism_beta2[pp_offset].y.Set(&pp.y);
							endomorphism_beta2[pn_offset].y.Set(&pn.y);
						}
						endomorphism_beta[pp_offset].x.ModMulK1(&pp.x, &beta);
						endomorphism_beta[pn_offset].x.ModMulK1(&pn.x, &beta);
						endomorphism_beta2[pp_offset].x.ModMulK1(&pp.x, &beta2);
						endomorphism_beta2[pn_offset].x.ModMulK1(&pn.x, &beta2);
					}
				}

				if(FLAGENDOMORPHISM)	{
					if( calculate_y  )	{

						endomorphism_beta[CPU_GRP_SIZE / 2].y.Set(&pts[CPU_GRP_SIZE / 2].y);
						endomorphism_beta2[CPU_GRP_SIZE / 2].y.Set(&pts[CPU_GRP_SIZE / 2].y);
					}
					endomorphism_beta[CPU_GRP_SIZE / 2].x.ModMulK1(&pts[CPU_GRP_SIZE / 2].x, &beta);
					endomorphism_beta2[CPU_GRP_SIZE / 2].x.ModMulK1(&pts[CPU_GRP_SIZE / 2].x, &beta2);
				}
				// First point (startP - (GRP_SZIE/2)*G)
				pn = startP;
				dyn.Set(&Gn[i].y);
				dyn.ModNeg();
				dyn.ModSub(&pn.y);
				_s.ModMulK1(&dyn,&dx[i]);
				_p.ModSquareK1(&_s);
				pn.x.ModNeg();
				pn.x.ModAdd(&_p);
				pn.x.ModSub(&Gn[i].x);
				if(calculate_y)	{
					pn.y.ModSub(&Gn[i].x,&pn.x);
					pn.y.ModMulK1(&_s);
					pn.y.ModAdd(&Gn[i].y);
				}
				pts[0] = pn;
				if(FLAGENDOMORPHISM)	{
					if( calculate_y  )	{
						endomorphism_beta[0].y.Set(&pn.y);
						endomorphism_beta2[0].y.Set(&pn.y);
					}
					endomorphism_beta[0].x.ModMulK1(&pn.x, &beta);
					endomorphism_beta2[0].x.ModMulK1(&pn.x, &beta2);
				}

				for(j = 0; j < CPU_GRP_SIZE/4;j++){
					switch(FLAGMODE)	{
						case MODE_RMD160:
							if(FLAGCRYPTO == CRYPTO_BTC){
								if(FLAGSEARCH == SEARCH_COMPRESS || FLAGSEARCH == SEARCH_BOTH ){
									if(FLAGENDOMORPHISM)	{
										secp->GetHash160_fromX(P2PKH,0x02,&pts[(j*4)].x,&pts[(j*4)+1].x,&pts[(j*4)+2].x,&pts[(j*4)+3].x,(uint8_t*)publickeyhashrmd160_endomorphism[0][0],(uint8_t*)publickeyhashrmd160_endomorphism[0][1],(uint8_t*)publickeyhashrmd160_endomorphism[0][2],(uint8_t*)publickeyhashrmd160_endomorphism[0][3]);
										secp->GetHash160_fromX(P2PKH,0x03,&pts[(j*4)].x,&pts[(j*4)+1].x,&pts[(j*4)+2].x,&pts[(j*4)+3].x,(uint8_t*)publickeyhashrmd160_endomorphism[1][0],(uint8_t*)publickeyhashrmd160_endomorphism[1][1],(uint8_t*)publickeyhashrmd160_endomorphism[1][2],(uint8_t*)publickeyhashrmd160_endomorphism[1][3]);

										secp->GetHash160_fromX(P2PKH,0x02,&endomorphism_beta[(j*4)].x,&endomorphism_beta[(j*4)+1].x,&endomorphism_beta[(j*4)+2].x,&endomorphism_beta[(j*4)+3].x,(uint8_t*)publickeyhashrmd160_endomorphism[2][0],(uint8_t*)publickeyhashrmd160_endomorphism[2][1],(uint8_t*)publickeyhashrmd160_endomorphism[2][2],(uint8_t*)publickeyhashrmd160_endomorphism[2][3]);
										secp->GetHash160_fromX(P2PKH,0x03,&endomorphism_beta[(j*4)].x,&endomorphism_beta[(j*4)+1].x,&endomorphism_beta[(j*4)+2].x,&endomorphism_beta[(j*4)+3].x,(uint8_t*)publickeyhashrmd160_endomorphism[3][0],(uint8_t*)publickeyhashrmd160_endomorphism[3][1],(uint8_t*)publickeyhashrmd160_endomorphism[3][2],(uint8_t*)publickeyhashrmd160_endomorphism[3][3]);
										secp->GetHash160_fromX(P2PKH,0x02,&endomorphism_beta2[(j*4)].x,&endomorphism_beta2[(j*4)+1].x,&endomorphism_beta2[(j*4)+2].x,&endomorphism_beta2[(j*4)+3].x,(uint8_t*)publickeyhashrmd160_endomorphism[4][0],(uint8_t*)publickeyhashrmd160_endomorphism[4][1],(uint8_t*)publickeyhashrmd160_endomorphism[4][2],(uint8_t*)publickeyhashrmd160_endomorphism[4][3]);
										secp->GetHash160_fromX(P2PKH,0x03,&endomorphism_beta2[(j*4)].x,&endomorphism_beta2[(j*4)+1].x,&endomorphism_beta2[(j*4)+2].x,&endomorphism_beta2[(j*4)+3].x,(uint8_t*)publickeyhashrmd160_endomorphism[5][0],(uint8_t*)publickeyhashrmd160_endomorphism[5][1],(uint8_t*)publickeyhashrmd160_endomorphism[5][2],(uint8_t*)publickeyhashrmd160_endomorphism[5][3]);
									}
									else	{
										secp->GetHash160_fromX(P2PKH,0x02,&pts[(j*4)].x,&pts[(j*4)+1].x,&pts[(j*4)+2].x,&pts[(j*4)+3].x,(uint8_t*)publickeyhashrmd160_endomorphism[0][0],(uint8_t*)publickeyhashrmd160_endomorphism[0][1],(uint8_t*)publickeyhashrmd160_endomorphism[0][2],(uint8_t*)publickeyhashrmd160_endomorphism[0][3]);
										secp->GetHash160_fromX(P2PKH,0x03,&pts[(j*4)].x,&pts[(j*4)+1].x,&pts[(j*4)+2].x,&pts[(j*4)+3].x,(uint8_t*)publickeyhashrmd160_endomorphism[1][0],(uint8_t*)publickeyhashrmd160_endomorphism[1][1],(uint8_t*)publickeyhashrmd160_endomorphism[1][2],(uint8_t*)publickeyhashrmd160_endomorphism[1][3]);
									}
								}
							}
						break;
					}
					switch(FLAGMODE)	{
						case MODE_RMD160:
							if( FLAGCRYPTO  == CRYPTO_BTC) {
								for(k = 0; k < 4;k++)	{
									if(FLAGSEARCH == SEARCH_COMPRESS || FLAGSEARCH == SEARCH_BOTH){
										if(FLAGENDOMORPHISM)	{
											for(l = 0;l < 6; l++)	{
												r = bloom_check(&bloom,publickeyhashrmd160_endomorphism[l][k],MAXLENGTHADDRESS);
												if(r) {
													r = searchbinary(addressTable,publickeyhashrmd160_endomorphism[l][k],N);
													if(r) {
														keyfound.SetInt32(k);
														keyfound.Mult(&stride);
														keyfound.Add(&key_mpz);
														publickey = secp->ComputePublicKey(&keyfound);
														switch(l)	{
															case 0:
																if(publickey.y.IsOdd())	{
																	keyfound.Neg();
																	keyfound.Add(&secp->order);
																}
															break;
															case 1:
																if(publickey.y.IsEven())	{	
																	keyfound.Neg();
																	keyfound.Add(&secp->order);
																}
															break;
															case 2:	
																keyfound.ModMulK1order(&lambda);
																if(publickey.y.IsOdd())	{	
																	keyfound.Neg();
																	keyfound.Add(&secp->order);
																}
															break;
															case 3:											
																keyfound.ModMulK1order(&lambda);
																if(publickey.y.IsEven())	{	
																	keyfound.Neg();
																	keyfound.Add(&secp->order);
																}
															break;
															case 4:
																keyfound.ModMulK1order(&lambda2);
																if(publickey.y.IsOdd())	{
																	keyfound.Neg();
																	keyfound.Add(&secp->order);
																}
															
															break;
															case 5:
																keyfound.ModMulK1order(&lambda2);
																if(publickey.y.IsEven())	{	
																	keyfound.Neg();
																	keyfound.Add(&secp->order);
																}
															break;
														}
														writekey(true,&keyfound);
													}
												}
											}
										}
										else	{
											for(l = 0;l < 2; l++)	{
												r = bloom_check(&bloom,publickeyhashrmd160_endomorphism[l][k],MAXLENGTHADDRESS);
												if(r) {
													r = searchbinary(addressTable,publickeyhashrmd160_endomorphism[l][k],N);
													if(r) {
														keyfound.SetInt32(k);
														keyfound.Mult(&stride);
														keyfound.Add(&key_mpz);
														
														publickey = secp->ComputePublicKey(&keyfound);
														secp->GetHash160(P2PKH,true,publickey,(uint8_t*)publickeyhashrmd160);
														if(memcmp(publickeyhashrmd160_endomorphism[l][k],publickeyhashrmd160,20) != 0)	{
															keyfound.Neg();
															keyfound.Add(&secp->order);
														}
														writekey(true,&keyfound);
													}
												}
											}
										}
									}


								}
							}
					}
					count+=4;
					temp_stride.SetInt32(4);
					temp_stride.Mult(&stride);
					key_mpz.Add(&temp_stride);
				}
				steps[thread_number]++;
				pp = startP;
				dy.ModSub(&_2Gn.y,&pp.y);
				_s.ModMulK1(&dy,&dx[i + 1]);
				_p.ModSquareK1(&_s);
				pp.x.ModNeg();
				pp.x.ModAdd(&_p);
				pp.x.ModSub(&_2Gn.x);
				pp.y.ModSub(&_2Gn.x,&pp.x);
				pp.y.ModMulK1(&_s);
				pp.y.ModSub(&_2Gn.y);
				startP = pp;
			}while(count < N_SEQUENTIAL_MAX && continue_flag);
		}
	} while(continue_flag);
	ends[thread_number] = 1;
	return NULL;
}
void sleep_ms(int milliseconds)	{ // cross-platform sleep function
#if defined(_WIN64) && !defined(__CYGWIN__)
    Sleep(milliseconds);
#elif _POSIX_C_SOURCE >= 199309L
    struct timespec ts;
    ts.tv_sec = milliseconds / 1000;
    ts.tv_nsec = (milliseconds % 1000) * 1000000;
    nanosleep(&ts, NULL);
#else
    if (milliseconds >= 1000)
      sleep(milliseconds / 1000);
    usleep((milliseconds % 1000) * 1000);
#endif
}
void init_generator()	{
	Point G = secp->ComputePublicKey(&stride);
	Point g;
	Gn.resize(CPU_GRP_SIZE / 2,g);
	g.Set(G);
	Gn[0] = g;
	g = secp->DoubleDirect(g);
	Gn[1] = g;
	for(int i = 2; i < CPU_GRP_SIZE / 2; i++) {
		g = secp->AddDirect(g,G);
		Gn[i] = g;
	}
	_2Gn = secp->DoubleDirect(Gn[CPU_GRP_SIZE / 2 - 1]);
}
void checkpointer(void *ptr,const char *file,const char *function,const  char *name,int line)	{
	if(ptr == NULL)	{
		fprintf(stderr,"[E] error in file %s, %s pointer %s on line %i\n",file,function,name,line); 
		exit(EXIT_FAILURE);
	}
}
// Menyimpan File
void writekey(bool compressed,Int *key)	{
	Point publickey;
	FILE *keys;
	char *hextemp,*hexrmd,public_key_hex[132],address[50],rmdhash[20];
	memset(address,0,50);
	memset(public_key_hex,0,132);
	hextemp = key->GetBase16();
	publickey = secp->ComputePublicKey(key);
	secp->GetPublicKeyHex(compressed,publickey,public_key_hex);
	secp->GetHash160(P2PKH,compressed,publickey,(uint8_t*)rmdhash);
	hexrmd = tohex(rmdhash,20);
	rmd160toaddress_dst(rmdhash,address);

#if defined(_WIN64) && !defined(__CYGWIN__)
	WaitForSingleObject(write_keys, INFINITE);
#else
	pthread_mutex_lock(&write_keys);
#endif
	keys = fopen("KEYFOUNDKEYFOUND.txt","a+");
	if(keys != NULL)	{
		fprintf(keys,"Private Key: %s\npubkey: %s\nAddress %s\nrmd160 %s\n",hextemp,public_key_hex,address,hexrmd);
		fclose(keys);
	}
	printf("\nHit! Private Key: %s\npubkey: %s\nAddress %s\nrmd160 %s\n",hextemp,public_key_hex,address,hexrmd);
	
#if defined(_WIN64) && !defined(__CYGWIN__)
	ReleaseMutex(write_keys);
#else
	pthread_mutex_unlock(&write_keys);
#endif
	free(hextemp);
	free(hexrmd);
}
bool isBase58(char c) {
    const char base58Set[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    return strchr(base58Set, c) != NULL;
}
bool isValidBase58String(char *str)	{
	int len = strlen(str);
	bool continuar = true;
	for (int i = 0; i < len && continuar; i++) {
		continuar = isBase58(str[i]);
	}
	return continuar;
}
bool readFileAddress(char *fileName)	{
	FILE *fileDescriptor;
	char fileBloomName[30];	
	uint8_t checksum[32],hexPrefix[9];
	char dataChecksum[32],bloomChecksum[32];
	size_t bytesRead;
	uint64_t dataSize;

	// Periksa apakah file belum dibaca
	if(!FLAGREADEDFILE1)	{
		// Lakukan baca file tanpa memeriksa mode
		return forceReadFileAddress(fileName);
	}
	return true;
}

bool forceReadFileAddress(char *fileName)	{
	/* Here we read the original file as usual */
	FILE *fileDescriptor;
	bool validAddress;
	uint64_t numberItems,i;
	size_t r,raw_value_length;
	uint8_t rawvalue[50];
	char aux[100],*hextemp;
	fileDescriptor = fopen(fileName,"r");	
	if(fileDescriptor == NULL)	{
		fprintf(stderr,"[E] Error opening the file %s, line %i\n",fileName,__LINE__ - 2);
		return false;
	}
	numberItems = 0;
	while(!feof(fileDescriptor))	{
		hextemp = fgets(aux,100,fileDescriptor);
		trim(aux," \t\n\r");
		if(hextemp == aux)	{
			r = strlen(aux);
			if(r > 20)	{ 
				numberItems++;
			}
		}
	}
	fseek(fileDescriptor,0,SEEK_SET);
	MAXLENGTHADDRESS = 20;
	
	printf("[+] Allocating memory for %" PRIu64 " elements: %.2f MB\n",numberItems,(double)(((double) sizeof(struct address_value)*numberItems)/(double)1048576));
	addressTable = (struct address_value*) malloc(sizeof(struct address_value)*numberItems);
	checkpointer((void *)addressTable,__FILE__,"malloc","addressTable" ,__LINE__ -1 );
		
	if(!initBloomFilter(&bloom,numberItems))
		return false;

	i = 0;
	while(i < numberItems)	{
		validAddress = false;
		memset(aux,0,100);
		memset(addressTable[i].value,0,sizeof(struct address_value));
		hextemp = fgets(aux,100,fileDescriptor);
		trim(aux," \t\n\r");			
		r = strlen(aux);
		if(r > 0 && r <= 40)	{
			if(r<40 && isValidBase58String(aux))	{	
				raw_value_length = 25;
				b58tobin(rawvalue,&raw_value_length,aux,r);
				if(raw_value_length == 25)	{
					bloom_add(&bloom, rawvalue+1 ,sizeof(struct address_value));
					memcpy(addressTable[i].value,rawvalue+1,sizeof(struct address_value));											
					i++;
					validAddress = true;
				}
			}
			if(r == 40 && isValidHex(aux))	{	//RMD
				hexs2bin(aux,rawvalue);				
				bloom_add(&bloom, rawvalue ,sizeof(struct address_value));
				memcpy(addressTable[i].value,rawvalue,sizeof(struct address_value));											
				i++;
				validAddress = true;
			}
		}
		if(!validAddress)	{
			fprintf(stderr,"[I] Ommiting invalid line %s\n",aux);
			numberItems--;
		}
	}
	N = numberItems;
	return true;
}
bool initBloomFilter(struct bloom *bloom_arg,uint64_t items_bloom)	{
	bool r = true;
	printf("[+] Bloom filter for %" PRIu64 " elements.\n",items_bloom);
	if(items_bloom <= 10000)	{
		if(bloom_init2(bloom_arg,10000,0.000001) == 1){
			fprintf(stderr,"[E] error bloom_init for 10000 elements.\n");
			r = false;
		}
	}
	else	{
		if(bloom_init2(bloom_arg,FLAGBLOOMMULTIPLIER*items_bloom,0.000001)	== 1){
			fprintf(stderr,"[E] error bloom_init for %" PRIu64 " elements.\n",items_bloom);
			r = false;
		}
	}
	printf("[+] Loading Boss: %.2f MB\n",(double)(((double) bloom_arg->bytes)/(double)1048576));
	return r;
}
void writeFileIfNeeded(const char *fileName)	{
}
void calcualteindex(int i,Int *key)	{
}