#ifndef CryptoPrimitivesV1
#define CryptoPrimitivesV1

#include <gmp.h>
#include <pbc/pbc.h>
#include <pbc/pbc_field.h>
#include <pbc/pbc_pairing.h>
#include <stdbool.h>
#include <sys/types.h>


/*===######### OUR IMPLEMENTATION CONTAIN BELOW CRYPTOGRAPHIC PRIMITIVES #########===
 === [1] PRF=(KeyGen,Eval), This primitve created by  a HMAC
 === [2] PRG=(SeedGen,Eval), This primitve created by  a PRF
 === [3] HASH=(Eval), This a implementation in TomCrypt (support several hash function)
 === [4] HMAC=(KeyGen,Eval), This a implementation in TomCrypt
 === [5] SKE=(KeyGen,Enc,Dec), AES Construction with Mode of Operation CBC (block_size=16)
 === [6] PKE=(KeyGen,Enc,Dec), Elgamel Construction with GroupGen in PBC
 === [7] GRP=GroupGen, Group by GMP library
 === [8] BGRP=BGroupGen, Bilinear Groups on Eleptic Curves in PBC with Below Operations:
 ====== [8-1] MUL(x,y), Where x,y in G1 or x,y in G2
 ====== [8-2] MUL(x,y), Where x,y in Z
 ====== [8-3] ADD(x,y), Where x,y in G1 or x,y in G2
 ====== [8-4] e(x,y), Where x in G1 and y in G2
 ====== [8-5] Inverse(x), Where x in Z
 ====== [8-6] Power(x,y), Where x in G1 or G2 or Gt, and y in Z
 === [9]  Thrss=(Share,ReConst), This is a threshold secret sharing primitve that created by Shamir Secret Sharing 
 scheme
 === [10] ThrCrypt=(DKeyGen,Enc,Dec), This is a cryptosystem that created by Shamir Secret Sharing scheme
 === [11] Padding=(PADDING_Message,UNPADDING_Message) (PKCS7_PADDING), this is used for padding message in 
 ske with mode cbc 
 === [12] Ds=(Gen,Sign,vrfy) (Schnorr signature scheme)
 ===######### OUR IMPLEMENTATION CONTAIN BELOW CRYPTOGRAPHIC PRIMITIVES #########=== */


//=========================================== STRUCTURE DEFINITION =================================

//##################### AES CTR 256 #################################
typedef struct Cipher{
    unsigned char ciphertext[132]; //2 bytes for m, 2 for n, 64 for Nsk_mn, 64 for beta_mn
    unsigned char iv[16];
    uint32_t Nx; //size of Nsk_i,j_x  #in bytes#
    uint32_t Ny; //size of Nsk_i,j_y
    uint32_t bx; //size of beta_i,j_y
    uint32_t by; //size of beta_i,j_y

} Cipher;
int aes_ctr_encrypt(const unsigned char *plaintext, int plaintext_len,
                    const unsigned char *key, const unsigned char *iv,
                    unsigned char *ciphertext);
int aes_ctr_decrypt(const unsigned char *ciphertext, int ciphertext_len,
                    const unsigned char *key, const unsigned char *iv,
                    unsigned char *plaintext);
/*##################################################################*/
typedef struct Polynomial{
    mpz_t a[2];
} Polynomial;
void Initialize_Polynomial(Polynomial* m);
void Free_Polynomial(Polynomial* m);
void Add_Polynomial(Polynomial* result,Polynomial* m1,Polynomial* m2);
void Convert_To_Polynomial(Polynomial* p,mpz_t* x,uint16_t size);
/*========================= Hash Struct =====================================================*/
typedef struct DscHash
{
    int secparam; /*security parameter*/
    char *plaintextInput; // plaintext (befor hash) in format string
    unsigned char *DigestOutput; // digest (after hash) in format byte
    unsigned long output_len;//this item determines digest lenght
    char *hash_name;//this item determines name of hash function that we will use
} DscHash;
/*===========================================================================================*/
/*========================= GroupGen Struct =================================================*/
typedef struct DscGrp
{
    int secparam; //This paramter is determined by number of bits.
    mpz_t prime;
    mpz_t generator;
    mpz_t order;
    gmp_randstate_t state;
}DscGrp;
/*===========================================================================================*/
/*============================== PKE Struct =================================================*/
typedef struct
{
     char *plaintextInput;
     char *plaintextOutput;
     mpz_t input;
     int secparam;
     DscGrp grp;
     mpz_t pkey;
     mpz_t skey;
     mpz_t c1;
     mpz_t c2;
     
}DscElg;
/*===========================================================================================*/
/*=============================== DS Struct =================================================*/
typedef struct 
{
    mpz_t skey; /* secret key */
    mpz_t pkey; //public key
    DscGrp grp;     //Description group
    char *plaintextInput; // plaintext (befor encryption) in format string
    mpz_t input; // input in format a point on curve
    mpz_t tag1; // signature [part1] in format a point on curve
    mpz_t tag2; // signature [part2] in format a point on curve
    DscHash hash;
    bool isValid;
}DscDS;
/*===========================================================================================*/
/*=============================== Padding Struct ============================================*/
/*Structure Definition For Padding Scheme (PKCS7_PADDING)*/
typedef struct
{
    int   blockSize;
    char *mainMessage;
    char *paddedMessage;
    char *unpaddedMessage;
}DscPADD;
/*===========================================================================================*/
/*=================================== SKE Struct ============================================*/
/*Structure Definition For SKE Scheme (AES)*/
typedef struct {
    int secparam; /*security parameter*/
    char *key; /*secret key*/
    char *iv; /*Initial vector*/
    char *plaintextInput; // plaintext (befor encryption) in format string
    char *plaintextOutput; // plaintext (after decryption) in format string
    char *ciphertextOutput; // ciphertext (after encryption) in format string
    DscPADD padd;
} DscAES;
/*===========================================================================================*/
/*=================================== PRF Struct ============================================*/
/*Structure Definition For Pseodu-Random Function*/
typedef struct {
    int secparam; /*security parameter*/
    char *key; /*secret key*/
    char *plaintextInput; // plaintext (befor encryption) in format string
    unsigned char *randomOutput; // ciphertext (after encryption) in format string
} DscPRF;
/*===========================================================================================*/
/*=================================== HMAC Struct ============================================*/
/*Structure Definition For Hash-Mac Function*/
typedef struct {
    int secparam; /*security parameter*/
    char *key; /*secret key*/
    char *plaintextInput; // plaintext (befor encryption) in format string
    unsigned char *DigestOutput; // ciphertext (after encryption) in format string
    unsigned long output_len;//this item determines digest lenght
} DscHMAC;
/*===========================================================================================*/
/*=================================== PRG Struct ============================================*/
/*Structure Definition For Pseodu-Random Generator*/
typedef struct {
    int secparam; /*security parameter*/
    unsigned char *randomOutput; // extended random value
    //unsigned long output_len;
    uint32_t size; //size of randomOutput in bytes
    DscHMAC hmac; // seed relatoed to prg is key of HMAC
} DscPRG;
/*===========================================================================================*/
/*============================== Bilinear Group Struct ======================================*/
/* Structure for an element of G1xG2 */
typedef struct __Pair_struct{
    element_t val[2];
} __Pair_struct;
typedef __Pair_struct Pair[1];

/*Structure Definition For Bilinear Group Generator*/
typedef struct { //This struct is for an asymmetric bilinear group
    Pair g1_g2;
    element_t gt; /*generator for Gt*/
    element_pp_t g1_pp; //used for raising to a power (g1^n)
    element_pp_t g2_pp; //used for raising to a power (g2^n)
    element_pp_t gt_pp; //used for raisign to a power (gt^n)

    pairing_pp_t g1_pp_pairing;
    pairing_pp_t g2_pp_pairing;

    pairing_t pairing; /*description pairing*/
    mpz_t order;/*order of bilinear group*/
    uint32_t numberOfBits;/*number of bits of q*/
    int paramSize;/*info related to type bilinear group*/
    char *paramAddress;/*info related to type bilinear group*/
}DscBGrp;
void Initialize_Pair(DscBGrp* bgrp,__Pair_struct* pair);
void Initialize_Pairs(DscBGrp* bgrp, __Pair_struct* first, ...);
void Pair_Set(__Pair_struct* pair,__Pair_struct* src);
void Pair_Set_Mpz(__Pair_struct* pair,mpz_t a,mpz_t b);
void Pair_Set_Si(__Pair_struct* pair,unsigned long a,unsigned long b);
void Pair_Set1(__Pair_struct* pair);
void Pair_Mul(__Pair_struct* result,__Pair_struct* a,__Pair_struct* b);
void Pair_Inv(__Pair_struct* result,__Pair_struct* a);
void Pair_Pow_Mpz(__Pair_struct* result ,__Pair_struct* a,mpz_ptr n);
void Pair_g1_g2_Pow(DscBGrp* bgrp,__Pair_struct* result,mpz_ptr n);
void Free_Pair(__Pair_struct* pair);
void Free_Pairs(__Pair_struct*  first, ...);
void Get_Pairing(element_t result, __Pair_struct* a);
int Pair_IsEqual(__Pair_struct*  a,__Pair_struct*  b);
/*===========================================================================================*/
/*============================ Time measurement structure ===================================*/
/*Structure Definition For Measuring Time (in terms of seconds, miliseconds, microseconds and nanoseconds)*/
typedef struct{ 
    struct timespec start;
    struct timespec end;
    long seconds;
    long milliseconds;
    long microseconds;
    long nanoseconds;
}DscTimeMeasure;
/*===========================================================================================*/
/*============================ Space measurement structure ==================================*/
/*Structure Definition For Measuring Sapace (in terms of Bits, Bytes, KiloBytes and MegaBates)*/
typedef struct{ 
    void *var;
    long sizeInBit;
    long sizeInBytes;
    double sizeInKBytes;
    double sizeInMBytes;
}DscSpaceMeasure;
/*===========================================================================================*/

/*Structure Definition For Threshold Secret Sharing Scheme (Shamir Secret Sharing)*/
typedef struct
{
    int num_shares;
    int threshold;
    int num_bits;
    
    mpz_t prime;
    mpz_t* shares_x;
    mpz_t* shares_y;
    mpz_t recovered_secret;
    mpz_t* coeffs;
}DscThss;

typedef struct{
    mpz_t* output1; // output [part1] in format a point on curve
    mpz_t* output2; // output [part2] in format a point on curve
    uint32_t blocks; //number of elements for output1 and output2
}DscCipher; //ciphertext for ThrCrypt

/*Structure Definition For Threshold Cryptosystem Scheme (Shamir Secret Sharing+Elgamal)*/
typedef struct {
    int secparam_bits;
    mpz_t skey; /* secret key */
    mpz_t pkey; //public key
    DscGrp grp;     //Description group
    DscCipher cipher;
    char *plaintextInput; // plaintext (befor encryption) in format string
    uint16_t maximumBlockSize; //maximum size of a block in bytes
    char *plaintextOutput; // plaintext (after decryption) in format string
    uint32_t sizeOfPlaintext; //in bytes
    DscThss thss;//Description Threshold Secret Sharing
} DscThrCrypt;
/*Structure Definition For Key Aggrement Protocol (Between Two parties)*/
typedef struct
{
    int uid;//Assigned in range [0..numUsers-1]
    mpz_t skey;
    mpz_t pkey;
}DscUser;

typedef struct
{
    int secparam;
    int numUsers;
    DscGrp grp;
    DscUser *user;
    mpz_t **sharedSecret;
}DscKAgree;


typedef struct
{
    int secparam;
    int numUsers;
    DscGrp grp;
    mpz_t *pkey;
    mpz_t *sharedSecret;
    mpz_t skey;
}DscKAgreeV1;

typedef struct{
   uint8_t val[32];
} Seed;
typedef struct{
   mpz_t keys[2]; //sk,pk
} KeyPair;
typedef struct{
   mpz_t val[2];
} Share;
//=========================================== STRUCTURE DEFINITION =================================
//           +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
//++++++++++                                                                                ++++++++++
//++++                                                                                            ++++
//++++++++++                                                                                ++++++++++
//     +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
//===========================================  FUNCTION PROTOTYPE  =================================

//############## Time Measurement #############################################
void Time_Measure(DscTimeMeasure *time);
/*++++++++++ Test Program - Time ++++++++++++++++ 
DscTimeMeasure timemeasure;

clock_gettime(CLOCK_MONOTONIC,(&(timemeasure.start)));

//Sample function to measure computation time
    DscBGrp bgrp;
    BGroupGen_Config(&bgrp);
    BGroupGen(&bgrp);
    printf("\n-------------------------------------------------------------");
    element_printf("\nGenerator Group G1 is:  %B\n", bgrp.g1);
    element_printf("\nGenerator Group G2 is:  %B\n", bgrp.g2);
    element_printf("\nGenerator Group Gt is:  %B\n", bgrp.gt);
    gmp_printf("\nThe order of the groups is: %Zd\n", bgrp.order);
    printf("-------------------------------------------------------------\n\n");

    printf("-------------------------------------------------------------");
    printf("\nPairing e(G1,G2)-> Gt\n");
    element_printf("x:  %B\n", bgrp.rg1);
    element_printf("y:  %B\n", bgrp.rg2);
    element_pairing(bgrp.rgt, bgrp.rg1,bgrp.rg2);
    element_printf("e(x,y):  %B\n", bgrp.rgt);
    printf("-------------------------------------------------------------\n\n");

clock_gettime(CLOCK_MONOTONIC, (&(timemeasure.end)));

Time_Measure(&timemeasure);
printf("\nElapsed Time for Selected Function is as below:\n");
printf("In Seconds: %ld\n",timemeasure.seconds);
printf("In Milliseconds: %ld\n",timemeasure.milliseconds);
printf("In Microseconds: %ld\n",timemeasure.microseconds);
printf("In Nanoseconds: %ld\n\n",timemeasure.nanoseconds);
+++++++++++++++++++++++++++++++++++++++++++++++++*/
//#############################################################################
uint32_t mpz_to_byteArray(char** rop, mpz_ptr integer);
void byteArray_to_mpz(mpz_ptr rop, char *byteArray, uint32_t size);
//############## Space Measurement #############################################
void Space_Measure(DscSpaceMeasure *space);
/*++++++++++ Test Program - Space ++++++++++++++++ 
DscSpaceMeasure spacemeasure;

//Sample function to measure computation time
    DscBGrp bgrp;
    BGroupGen_Config(&bgrp);

    BGroupGen(&bgrp);
    printf("\n-------------------------------------------------------------");
    element_printf("\nGenerator Group G1 is:  %B\n", bgrp.g1);
    element_printf("\nGenerator Group G2 is:  %B\n", bgrp.g2);
    element_printf("\nGenerator Group Gt is:  %B\n", bgrp.gt);
    gmp_printf("\nThe order of the groups is: %Zd\n", bgrp.order);
    printf("-------------------------------------------------------------\n\n");

    printf("-------------------------------------------------------------");
    printf("\nPairing e(G1,G2)-> Gt\n");
    element_printf("x:  %B\n", bgrp.rg1);
    element_printf("y:  %B\n", bgrp.rg2);
    element_pairing(bgrp.rgt, bgrp.rg1,bgrp.rg2);
    element_printf("e(x,y):  %B\n", bgrp.rgt);
    printf("-------------------------------------------------------------\n\n");

spacemeasure.var=malloc(sizeof(element_t));
element_init_GT(spacemeasure.var, bgrp.pairing);
Space_Measure(&spacemeasure);
printf("\nSpace Size for Selected Variable (GT) is as below:\n");
printf("In Bit: %ld\n",spacemeasure.sizeInBit);
printf("In Byte: %ld\n",spacemeasure.sizeInBytes);
printf("In KiloByte: %.2f\n",spacemeasure.sizeInKBytes);
printf("In MegaByte: %.2f\n\n",spacemeasure.sizeInMBytes);

element_init_G1(spacemeasure.var, bgrp.pairing);
Space_Measure(&spacemeasure);
printf("\nSpace Size for Selected Variable (G1) is as below:\n");
printf("In Bit: %ld\n",spacemeasure.sizeInBit);
printf("In Byte: %ld\n",spacemeasure.sizeInBytes);
printf("In KiloByte: %.2f\n",spacemeasure.sizeInKBytes);
printf("In MegaByte: %.2f\n\n",spacemeasure.sizeInMBytes);

element_init_G2(spacemeasure.var, bgrp.pairing);
Space_Measure(&spacemeasure);
printf("\nSpace Size for Selected Variable (G2) is as below:\n");
printf("In Bit: %ld\n",spacemeasure.sizeInBit);
printf("In Byte: %ld\n",spacemeasure.sizeInBytes);
printf("In KiloByte: %.2f\n",spacemeasure.sizeInKBytes);
printf("In MegaByte: %.2f\n\n",spacemeasure.sizeInMBytes);
+++++++++++++++++++++++++++++++++++++++++++++++++*/
//#############################################################################


//############ HMAC=(KeyGen,Eval) #############################################
void HMAC_Config(DscHMAC *hmac, int secparam);
void HMAC_KeyGen(DscHMAC *hmac);
void HMAC_Eval(DscHMAC *hmac);
void HMAC_Free(DscHMAC *hmac);
/*++++++++++ Test Program - HAMC ++++++++++++++++ 
    DscHMAC hmac;
    HMAC_Config(&hmac,16);
    
    HMAC_KeyGen(&hmac);
    printf("\nSecret Key: ");
    for (int i = 0; i < hmac.secparam; i++) {
        printf("%02x", hmac.key[i]);
    }
    printf("\n");

    printf("\nHMAC input: %s\n",hmac.plaintextInput);
    HMAC_Eval(&hmac);
    printf("\nHMAC output: ");
    for (int i = 0; i < 16; i++) {
        printf("%02x", hmac.DigestOutput[i]);
    }
    printf("\n\n");
+++++++++++++++++++++++++++++++++++++++++++++++++*/
//#############################################################################
//output in G1xG2
mpz_t* PRF_K(__Pair_struct* outputPair,Seed K[2],size_t keylen,const uint8_t* input1,size_t inputlen1,
  const uint8_t* input2,size_t inputlen2,DscBGrp* bgrp);
//output in Zq^2
void PRF_Ki(mpz_t out[2],const uint8_t* key,size_t keylen,const uint8_t* input,size_t inputlen,DscBGrp* bgrp);
   
//#############################################################################


//############ PRG=(SeedGen,Eval) #############################################
void PRG_Config(DscPRG *prg, int secparam, uint32_t size);
void PRG_SeedGen(DscPRG *prg);
void PRG_Eval(DscPRG *prg);
void PRG_Free(DscPRG *prg);
void PRG(uint8_t *out, size_t outlen, const uint8_t *seed32);
void PRF(uint8_t out[32],const uint8_t *key, size_t keylen,const uint8_t *input, size_t inputlen);
/*++++++++++ Test Program - PRG +++++++++++++++++ 
   DscPRG prg;
   PRG_Config(&prg,16,32);

   PRG_SeedGen(&prg);
   printf("\nSeed = ");
   for (int i = 0; i < prg.secparam; i++) {
       printf("%02x", prg.hmac.key[i]);
   }
   printf("\n");

   PRG_Eval(&prg);
   printf("\nPRG1(seed,size=%"PRIu32"): ", prg.size);
   for (int i = 0; i < prg.size; i++) {
       printf("%02x", prg.randomOutput[i]);
   }
   PRG_SeedGen(&prg);
   //prg.hmac.key="thisddddd";
   printf("\n\n");
   PRG_Eval(&prg);
   printf("\nPRG(seed,size=%"PRIu32"): ", prg.size);

   for (int i = 0; i < prg.size; i++) {
       printf("%02x", prg.randomOutput[i]);
   }
   PRG_Free(&prg);
+++++++++++++++++++++++++++++++++++++++++++++++++*/
//#############################################################################


//############ Hash=(Eval) ####################################################
void Hash_Config(DscHash *hash,int secparam);
void Hash_Eval(DscHash *hash,char* plaintext,uint32_t size);
void Hash_Free(DscHash* hash);
/*++++++++++ Test Program - Hash ++++++++++++++++ 
    DscHash hash;
    Hash_Config(&hash,32);
    
    Hash_Eval(&hash);

    printf("\nHash Input: %s\n",hash.plaintextInput);
    printf("\nHash Output: ");
    for (int i = 0; i < hash.output_len; i++) {
        printf("%02x", hash.DigestOutput[i]);
    }
    printf("\n\n");
+++++++++++++++++++++++++++++++++++++++++++++++++*/ 
//#############################################################################


//############ GroupGen (GMP) ##################################################
void GroupGen_Config(DscGrp *grp, uint32_t secparam);
void GroupGen(DscGrp *grp);
void GroupGen_Free(DscGrp *grp);
/*++++++++++ Test Program - GroupGen +++++++++++ 
    DscGrp grp;
    GroupGen_Config(&grp);

    GroupGen(&grp);
    printf("\n-------------------------------------------------------------");
    gmp_printf("\nGroup Generator is:  %B\n", grp.generator);
    gmp_printf("\nGroupt Order is: %Zd\n", grp.order);
    printf("-------------------------------------------------------------\n\n");
+++++++++++++++++++++++++++++++++++++++++++++++++*/
//#############################################################################


//############ BGroupGen  #####################################################
void BGroupGen_Config(DscBGrp *bgrp);
void BGroupGen(DscBGrp *bgrp);
void BGroup_Free(DscBGrp *bgrp);
/*++++++++++ Test Program - BGroupGen +++++++++++ 
    DscBGrp bgrp;
    BGroupGen_Config(&bgrp);

    BGroupGen(&bgrp);
    printf("\n-------------------------------------------------------------");
    element_printf("\nGenerator Group G1 is:  %B\n", bgrp.g1);
    element_printf("\nGenerator Group G2 is:  %B\n", bgrp.g2);
    element_printf("\nGenerator Group Gt is:  %B\n", bgrp.gt);
    gmp_printf("\nThe order of the groups is: %Zd\n", bgrp.order);
    printf("-------------------------------------------------------------\n\n");


    printf("-------------------------------------------------------------");
    printf("\nMultiplication (In G1 [for other groups is similar])\n");
    element_printf("x:  %B\n", bgrp.rg1);
    element_printf("y:  %B\n", bgrp.g1);
    element_mul(bgrp.rg1,bgrp.rg1, bgrp.g1);
    element_printf("MUL(x,y):  %B\n", bgrp.rg1);
    printf("-------------------------------------------------------------\n\n");

    printf("-------------------------------------------------------------");
    printf("\nAddition (In G1 [for other groups is similar])\n");
    element_printf("x:  %B\n", bgrp.rg1);
    element_printf("y:  %B\n", bgrp.g1);
    element_add(bgrp.rg1,bgrp.rg1, bgrp.g1);
    element_printf("ADD(x,y):  %B\n", bgrp.rg1);
    printf("-------------------------------------------------------------\n\n");

    printf("-------------------------------------------------------------");
    printf("\nPower g1^z (In G1 [for other groups is similar])\n");
    element_printf("x:  %B\n", bgrp.rg1);
    element_printf("z:  %B\n", bgrp.rz);
    element_pow_zn(bgrp.rg1, bgrp.rg1, bgrp.rz);
    element_printf("x^z:  %B\n", bgrp.rg1);
    printf("-------------------------------------------------------------\n\n");

    printf("-------------------------------------------------------------");
    printf("\nInverse (Z_q)\n");
    element_printf("x:  %B\n", bgrp.rz);
    element_invert(bgrp.rz, bgrp.rz);
    element_printf("x^{-1}:  %B\n", bgrp.rz);
    printf("-------------------------------------------------------------\n\n");

    printf("-------------------------------------------------------------");
    printf("\nMul (Z_q)\n");
    element_printf("x:  %B\n", bgrp.rz);
    element_printf("y:  %B\n", bgrp.rz);
    element_mul(bgrp.rz, bgrp.rz,bgrp.rz);
    element_printf("MUL(x,y):  %B\n", bgrp.rz);
    printf("-------------------------------------------------------------\n\n");

    printf("-------------------------------------------------------------");
    printf("\nPairing e(G1,G2)-> Gt\n");
    element_printf("x:  %B\n", bgrp.rg1);
    element_printf("y:  %B\n", bgrp.rg2);
    element_pairing(bgrp.rgt, bgrp.rg1,bgrp.rg2);
    element_printf("e(x,y):  %B\n", bgrp.rgt);
    printf("-------------------------------------------------------------\n\n");
+++++++++++++++++++++++++++++++++++++++++++++++++*/
//##################### Homomorphic Hash ###############################
mpz_t* Homomorphic_Hash(Pair* result, Polynomial* m,uint32_t numberOfElementsInm,mpz_ptr delta,DscBGrp* bgrp);
/* test program - Homomorphic_Hash
   DscBGrp bgrp;
   BGroupGen_Config(&bgrp);
   BGroupGen(&bgrp);
   Polynomial m1;
   Polynomial m2;
   Polynomial result; //m1+m2
   Initialize_Polynomial(&m1);
   Initialize_Polynomial(&m2);
   Initialize_Polynomial(&result);
   mpz_set_ui(m1.a[0],323);
   mpz_set_ui(m1.a[1],3);
   mpz_set_ui(m2.a[0],948);
   mpz_set_ui(m2.a[1],84);
   Add_Polynomial(&result, &m1, &m2);

      printf("\nm1: \n");
   gmp_printf("m1.a[0] = %Zd\n",m1.a[0]);
   gmp_printf("m1.a[1] = %Zd\n",m1.a[1]);
      printf("\nm2: \n");
   gmp_printf("m2.a[0] = %Zd\n",m2.a[0]);
   gmp_printf("m2.a[1] = %Zd\n",m2.a[1]);
   printf("\nresult: \n");
   gmp_printf("result.a[0] = %Zd\n",result.a[0]);
   gmp_printf("result.a[1] = %Zd\n",result.a[1]);

   
   Pair r1,r2,r3,r4;
   Initialize_Pairs(&bgrp,r1,r2,r3,r4,NULL);
   unsigned char buf[20];
   RAND_bytes(buf, 20);
   mpz_t delta;
   mpz_init(delta);
   byteArray_to_mpz(delta, (char*)buf, 20);
   mpz_mod(delta,delta,bgrp.order);


   Homomorphic_Hash(&r1, &result, 1, delta, &bgrp);
   Homomorphic_Hash(&r2, &m1, 1, delta, &bgrp);
   Homomorphic_Hash(&r3, &m2, 1, delta, &bgrp);

   Pair_Mul(r4, r2, r3);

   if(Pair_IsEqual(r4,r1)){
      printf("\nHomomorphic hash is correct\n");
   }
   else{
      printf("\nHomomorphic Hash is not correct\n");
   }
   element_printf("r4.x:  %B\n", r4[0].val[0]);
   element_printf("r4.y:  %B\n", r4[0].val[1]);
   element_printf("r1.x:  %B\n", r1[0].val[0]);
   element_printf("r1.y:  %B\n", r1[0].val[1]);

   Free_Pairs(r1,r2,r3,r4,NULL);
   BGroup_Free(&bgrp);

*/

//###### SKE=(KeyGen,Enc,Dec) (AES+CBC) #######################################
void SKE_Config(DscAES *aes,int secparam);
void SKE_KeyGen(DscAES *aes);
void SKE_ENC(DscAES *aes);
void SKE_DEC(DscAES *aes);
/*++++++++++++++ Test Program - SKE ++++++++++++++ 
    DscAES aes;
    SKE_Config(&aes,16);

    SKE_KeyGen(&aes);
    printf("\nAES Key:");
    for (int i = 0; i < sizeof(aes.key); i++)
    {
       printf("%02x", aes.key[i]);
    }
    printf("\n");
    
    char *str="AliReza Rafiee";
    strcpy(aes.plaintextInput,str);
    printf("PlaintextInput: %s\n",aes.plaintextInput);

    SKE_ENC(&aes);
    printf("CiphertextOutput: ");
    for (int i = 0; i < sizeof(aes.ciphertextOutput); i++) {
        printf("%0B ",aes.ciphertextOutput[i]);
    }
    printf("\n");

    SKE_DEC(&aes);
    printf("PlaintextOutput: %s\n", aes.plaintextOutput);
++++++++++++++++++++++++++++++++++++++++++++++++++++*/
//#############################################################################


//###### PKE=(KeyGen,Enc,Dec) (Elgamel) ####################################### 
void PKE_Config(DscElg *elg);
void PKE_KeyGen(DscElg *elg);
void PKE_ENC(DscElg *elg);
void PKE_DEC(DscElg *elg);
/*++++++++++++++ Test Program - PKE +++++++++++++ 
    DscElg elg;
    PKE_Config(&elg);

    char *str="Mojtaba Rafiee";

    strcpy(elg.plaintextInput,str);
    
    element_printf("\nPlainText Input is:  %s\n", elg.plaintextInput);

    PKE_KeyGen(&elg);
    gmp_printf("\nSecret key:  %B\n", elg.skey);
    gmp_printf("Public key:  %B\n\n", elg.pkey);


    //ٍEncryption
    PKE_ENC(&elg);
    gmp_printf("CipherText [Part1]:  %B\n", elg.c1);
    gmp_printf("CipherText [Part2]:  %B\n\n", elg.c2);

    //Decryption
    PKE_DEC(&elg);
    printf("PlainText Output is: %s\n",elg.plaintextOutput);     
+++++++++++++++++++++++++++++++++++++++++++++++++*/
//#############################################################################


//################ Ds=(Gen,Sign,vrfy) (Schnorr signature scheme) ##############
void DS_Config(DscDS *ds);
void DS_KeyGen(DscDS *ds);
void DS_Sign(DscDS *ds);
void DS_Vrfy(DscDS *ds);
/*++++++++++++++ Test Program - DscDS +++++++++++++*
    DscDS ds;
    DS_Config(&ds);
    DS_Gen(&ds);
    DS_Sign(&ds);
    //ds.plaintextInput="I am mojtaba";
    DS_Vrfy(&ds);

    printf("\nValidate is %d\n",ds.isValid);
+++++++++++++++++++++++++++++++++++++++++++++++++*/
//#############################################################################


//################ Padding=(PADDING_Message,UNPADDING_Message) (PKCS7_PADDING) ##############
void PADDING_Config(DscPADD *padd);
void PADDING_Message(DscPADD *padd);
void UNPADDING_Message(DscPADD *padd);
/*++++++++++++++ Test Program - DscDS +++++++++++++*
    DscPADD padd;
    PADDING_Config(&padd);

    printf("Data (Hex) with len [%ld]:          ",strlen(padd.mainMessage));
    for (unsigned int i=0; i < strlen(padd.mainMessage); ++i) {
      printf("%02X ", padd.mainMessage[i]);
    }
    printf("\n");
    
    PADDING_Message(&padd);

    printf("Padded Data (Hex) with len [%ld]:   ",strlen(padd.paddedMessage));
    for (unsigned int i=0; i < strlen(padd.paddedMessage); ++i) {
      printf("%02X ", padd.paddedMessage[i]);
    }
    printf("\n");

    UNPADDING_Message(&padd);

    printf("Unpadded Data (Hex) with len [%ld]: ",strlen(padd.unpaddedMessage));
    for (unsigned int i=0; i < strlen(padd.unpaddedMessage); ++i) {
      printf("%02X ", padd.unpaddedMessage[i]);
    }
    printf("\n");
+++++++++++++++++++++++++++++++++++++++++++++++++*/
//#############################################################################


//###### Thrss=(Share,ReConst) (Shamir Secret Sharing) ########################
void generate_random_mpz(mpz_ptr prime, mpz_ptr rndelement);
void Thss_Config(DscThss *thss, int secparam_bits, int total, int threshold);
void Thss_KeyGen(DscThss *thss, mpz_ptr prime);
void Thss_Share(DscThss *thss, mpz_ptr secret);
void Thss_ReCons(DscThss *thss); 
void Thss_Free(DscThss *thss);
/*++++++++++++++ Test Program - Thrss +++++++++++ 
    DscThss thss;
    Thss_Config(&thss,256,5,3);
    Thss_KeyGen(&thss);
            
    printf("Generated Prime (prime): ");
    mpz_out_str(stdout, 10, thss.prime);
    printf("\n");
    
    char *str1=malloc (128*sizeof(char));
    char *str2=malloc (128*sizeof(char));
    gmp_sprintf(str1,"%Zd",thss.secret);
    printf("Original Secret: %s",str1);
    //mpz_out_str(stdout, 10, thss.secret);
    printf("\n");
    
    Thss_Share(&thss);

    printf("\nShares (x, y):\n");
    for (int i = 0; i < thss.num_shares; i++) {
        printf("(x: ");
        gmp_printf("%Zd", thss.shares_x[i]);
        printf(", y: ");
        gmp_printf("%Zd", thss.shares_y[i]);
        printf(")\n");
    }
   
    Thss_ReCons(&thss);

    gmp_sprintf(str2,"%Zd",thss.recovered_secret);
    printf("Recovered Secret: %s",str2);
     printf("\n");
  
    if (mpz_cmp(thss.secret, thss.recovered_secret) == 0) {
        printf("Secret recovered successfully!\n");
    } else {
        printf("Error: Secret recovery failed!\n");
    }
+++++++++++++++++++++++++++++++++++++++++++++++++*/
//#############################################################################


//###### ThrCrypt=(DKeyGen,Enc,Dec) (Shamir Secret Sharing)####################
void ThrCrypt_Config(DscThrCrypt *thrcrypt,uint16_t secparam_bits,uint16_t total, uint16_t threshold);
void ThrCrypt_DKeyGen(DscThrCrypt *thrcrypt);
void ThrCrypt_Enc(DscThrCrypt *thrcrypt,char* plaintext, uint32_t size);
void ThrCrypt_Dec(DscThrCrypt *thrcrypt);
void ThrCrypt_Free(DscThrCrypt *thrcrypt);
void Cipher_Free(DscCipher* cipher);
/*++++++++++++++ Test Program - DscThrCrypt +++++ 

  DscThrCrypt thrcrypt;
  char secret1[] = ";dfk;aswk;aswk;asw\0\0\0\0sdfsdfjasof398rj34jff9j9*FEH(*"
                   "PHJRFEWIPUFH(*WEhfniukjesnhfdkjsdkf394\0";
  char secret2[] = ";dfk;aswk;aswk;asw\0\0*WEhfniukjesnhfdkjsdkf394\0";

  ThrCrypt_Config(&thrcrypt, 256, 5, 3);
  ThrCrypt_DKeyGen(&thrcrypt, NULL);
  ThrCrypt_Enc(&thrcrypt, secret1, sizeof(secret1));
  DscCipher cipher1 = thrcrypt.cipher;
  ThrCrypt_Enc(&thrcrypt, secret2, sizeof(secret2));
  DscCipher cipher2 = thrcrypt.cipher;

  thrcrypt.cipher = cipher1;
  ThrCrypt_Dec(&thrcrypt);
  printf("\n\ndecrypted output for secret1 hex code: \n");
  for (int i = 0; i < thrcrypt.sizeOfPlaintext; i++) {
    printf("%02x", (unsigned char)thrcrypt.plaintextOutput[i]);
  }
  printf("\n");
  printf("secret1 hex code: \n");
  for (int i = 0; i < sizeof(secret1); i++) {
    printf("%02x", (unsigned char)secret1[i]);
  }
  printf("\n");

  thrcrypt.cipher = cipher2;
  ThrCrypt_Dec(&thrcrypt);
  printf("\n\ndecrypted output for secret2 hex code: \n");
  for (int i = 0; i < thrcrypt.sizeOfPlaintext; i++) {
    printf("%02x", (unsigned char)thrcrypt.plaintextOutput[i]);
  }
  printf("\n");
  printf("secret2 hex code: \n");
  for (int i = 0; i < sizeof(secret2); i++) {
    printf("%02x", (unsigned char)secret2[i]);
  }
  printf("\n");
  ThrCrypt_Free(&(thrcrypt));

+++++++++++++++++++++++++++++++++++++++++++++++++*/
//#############################################################################
void generatePrime(mpz_ptr rop, uint32_t sizeInBits);
#endif 