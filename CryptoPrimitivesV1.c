#include "CryptoPrimitivesV1.h"
#include <gmp.h>
#include <pbc/pbc.h>
#include <pbc/pbc_field.h>
#include <pbc/pbc_pairing.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <stdint.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include "tomcrypt.h"

//turns mpz_t into an array of bytes and returns the number of bytes
uint32_t mpz_to_byteArray(char** rop, mpz_ptr integer){
    size_t count = 0;
    size_t size_in_bytes = (mpz_sizeinbase(integer, 2) + 7) / 8;
    
    *rop = (char*)malloc(size_in_bytes);
    if (!*rop) return 0;  // malloc failed
    mpz_export(*rop, &count, 1, sizeof(char), 1, 0, integer);

    return (uint32_t)count;
}
void byteArray_to_mpz(mpz_ptr rop, char *byteArray, uint32_t size) {
  mpz_import(rop, size, 1, sizeof(char), 0, 0,
              byteArray);
}

// ############ Time Measurement ############
void Time_Measure(DscTimeMeasure *time) {
  time->seconds = time->end.tv_sec - time->start.tv_sec;
  time->nanoseconds = time->end.tv_nsec - time->start.tv_nsec;

  if (time->nanoseconds < 0) {
    time->seconds -= 1;
    time->nanoseconds += 1000000000;
  }

  time->milliseconds = time->seconds * 1000 + time->nanoseconds / 1000000;
  time->microseconds = time->seconds * 1000000 + time->nanoseconds / 1000;
}
// ############################################

// ############ Space Measurement ############
void Space_Measure(DscSpaceMeasure *space) {
  space->sizeInBytes = element_length_in_bytes(space->var);
  space->sizeInBit = space->sizeInBytes * 8;
  space->sizeInKBytes = space->sizeInBytes / 1024.0;
  space->sizeInMBytes = space->sizeInBytes / (1024.0 * 1024.0);
}

// ############################################

// ############ PRG #############


/* 16 bytes key
void PRG(uint8_t *out, size_t outlen, const uint8_t *seed16) {
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  uint8_t iv[16] = {0};
  
  EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, seed16, iv);
  memset(out,0,20);
  int len;
  EVP_EncryptUpdate(ctx, out, &len, out, outlen);  // encrypt zeros
  EVP_CIPHER_CTX_free(ctx);
}
*/

//outlen is in bytes
void PRG(uint8_t *out, size_t outlen, const uint8_t *key32) {
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  uint8_t iv[16] = {0};  // 128-bit IV (can also be passed as a parameter)

  EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key32, iv);
  memset(out, 0, outlen);
  int len;
  EVP_EncryptUpdate(ctx, out, &len, out, outlen);
  EVP_CIPHER_CTX_free(ctx);
}
//############## PRF #############
//output is 32 bytes
void PRF(
    uint8_t out[32],
    const uint8_t *key, size_t keylen,
    const uint8_t *input, size_t inputlen
) {
    unsigned int outlen = 32;
    HMAC(EVP_sha256(), key, keylen, input, inputlen, out, &outlen);
}

// ###############################
// initilizes prime, generator and order and sets secparam=512 bits
void GroupGen_Config(DscGrp *grp, uint32_t secparam) {
  grp->secparam = secparam;
  mpz_init(grp->prime);
  mpz_init(grp->generator);
  mpz_init(grp->order);
}
// generates Z_p* with generator = 2, and p is a safe prime (p=2q+1 where q is a
// prime)
void GroupGen(DscGrp *grp) {
  // Generate a random safe prime number (p = 2q + 1)
  mpz_t q, test;
  gmp_randinit_default(grp->state);
  gmp_randseed_ui(grp->state, time(NULL));
  mpz_inits(q, test, NULL);

  while (1) {
    // Generate random 511-bit prime q
    mpz_urandomb(q, grp->state, grp->secparam - 1);
    mpz_setbit(q, grp->secparam - 2); // ensure it's secparam-1 bits

    mpz_nextprime(q, q);
    // q might be a secparam bit prime,if so, so p will be secparam+1 bit prime,
    // might cause buffer overlfow somewhere in the code

    mpz_mul_ui(grp->prime, q, 2);
    mpz_add_ui(grp->prime, grp->prime, 1);

    if (mpz_probab_prime_p(grp->prime, 25) > 0) {
      mpz_set_ui(test, 2);
      mpz_powm(test, test, q, grp->prime);

      if (mpz_cmp_ui(test, 1) != 0) {
        mpz_set_ui(grp->generator, 2);
        mpz_sub_ui(grp->order, grp->prime, 1);
        break;
      }
    }
  }

  mpz_clears(q, test, NULL);
}
void GroupGen_Free(DscGrp* grp){
  mpz_clears(grp->prime,grp->generator,grp->order,NULL);
  gmp_randclear(grp->state);
}

void generatePrime(mpz_ptr rop, uint32_t sizeInBits){
  gmp_randstate_t state;
  gmp_randinit_default(state);
  gmp_randseed_ui(state, time(NULL));

  mpz_urandomb(rop, state, sizeInBits);
  mpz_nextprime(rop, rop);
  gmp_randclear(state);
}
// ############ BGroupGen  ############
void BGroupGen_Config(DscBGrp *bgrp) {
  //bgrp->paramSize = 2048;
  //bgrp->paramAddress = "d224.param";
  //bgrp->paramAddress = "a.param";

}
void BGroupGen(DscBGrp *bgrp) {
  
  pbc_param_t param;
  // For 256-bit security: 512-bit group, 3072-bit field
  pbc_param_init_a_gen(param, 160, 512);
  bgrp->numberOfBits=160;
  // Initialize the pairing
  pairing_init_pbc_param(bgrp->pairing, param);
  

  mpz_init(bgrp->order);
  mpz_set(bgrp->order, (bgrp->pairing)->r);
  
  Initialize_Pair(bgrp, bgrp->g1_g2);
  element_init_GT(bgrp->gt, bgrp->pairing);
  element_random(bgrp->g1_g2[0].val[0]);
  element_random(bgrp->g1_g2[0].val[1]);
  Get_Pairing(bgrp->gt,bgrp->g1_g2);
  element_pp_init(bgrp->g1_pp, bgrp->g1_g2[0].val[0]);
  element_pp_init(bgrp->g2_pp, bgrp->g1_g2[0].val[1]);
  element_pp_init(bgrp->gt_pp, bgrp->gt);
  pairing_pp_init(bgrp->g1_pp_pairing, bgrp->g1_g2[0].val[0],bgrp->pairing);
  pairing_pp_init(bgrp->g2_pp_pairing, bgrp->g1_g2[0].val[1],bgrp->pairing);

  pbc_param_clear(param);
  // element_printf("\nGenerator Group G1 is:  %B", bgrp->g1_g2[0].val[0]);
  // element_printf("\nGenerator Group G2 is:  %B", bgrp->g1_g2[0].val[1]);
  // element_printf("\nGenerator Group Gt is:  %B", bgrp->gt);
  // gmp_printf("\nThe order of the groups is: %Zd\n", bgrp->order);s
}
void BGroup_Free(DscBGrp* bgrp){
  mpz_clear(bgrp->order);
  element_pp_clear(bgrp->g1_pp);
  element_pp_clear(bgrp->g2_pp);
  element_pp_clear(bgrp->gt_pp);
  pairing_pp_clear(bgrp->g1_pp_pairing);
  pairing_pp_clear(bgrp->g2_pp_pairing);
  Free_Pair(bgrp->g1_g2);
  element_clear(bgrp->gt);
  pairing_clear(bgrp->pairing);

}
// ############ Homomorphic Hash ##########
//returns the exponent array, the exponent[numberOfElementsInm] must be cleared with mpz_clear and freed
mpz_t* Homomorphic_Hash(Pair* result, Polynomial* m,uint32_t numberOfElementsInm,mpz_ptr delta,DscBGrp* bgrp){
  mpz_t* exponent = malloc(sizeof(mpz_t)*numberOfElementsInm);
  for(int i =0;i<numberOfElementsInm;i++){
    mpz_init(exponent[i]);
    mpz_addmul(exponent[i], m[i].a[1], delta);
    mpz_add(exponent[i],exponent[i],m[i].a[0]);
    mpz_mod(exponent[i],exponent[i],bgrp->order);
    Pair_g1_g2_Pow(bgrp,result[i], exponent[i]);
  }
  //mpz_clear(exponent);
  return exponent;
}
void Initialize_Polynomial(Polynomial* m){
  mpz_inits(m->a[0],m->a[1],NULL);
}
void Free_Polynomial(Polynomial* m){
  mpz_clears(m->a[0],m->a[1],NULL);
}
void Add_Polynomial(Polynomial* result,Polynomial* m1,Polynomial* m2){
  mpz_add(result->a[0],m1->a[0],m2->a[0]);
  mpz_add(result->a[1],m1->a[1],m2->a[1]);
}
//function initialized the polynomial, no need to initialize m
void Convert_To_Polynomial(Polynomial* m, mpz_t* x,uint16_t size){
  for(int i =0;i<size;i++){
    Initialize_Polynomial(&(m[i]));
    mpz_set((m[i]).a[0], x[i]);
    mpz_set_ui((m[i]).a[1], 1);
  }
}
void Initialize_Pair(DscBGrp* bgrp,Pair pair){
  element_init_G1(pair[0].val[0],bgrp->pairing);
  element_init_G2(pair[0].val[1],bgrp->pairing);
}
void Initialize_Pairs(DscBGrp* bgrp, Pair first, ...) {
    // initialize the first Pair directly
    element_init_G1(first[0].val[0], bgrp->pairing);
    element_init_G2(first[0].val[1], bgrp->pairing);

    va_list args;
    va_start(args, first);

    __Pair_struct *p;   // pointer to the single struct

    // retrieve subsequent arguments as pointers
    while ((p = va_arg(args, __Pair_struct *)) != NULL) {
        element_init_G1(p[0].val[0], bgrp->pairing);
        element_init_G2(p[0].val[1], bgrp->pairing);
    }

    va_end(args);
}
void Pair_Set_Mpz(__Pair_struct*  pair,mpz_t a,mpz_t b){
  element_set_mpz(pair->val[0],a);
  element_set_mpz(pair->val[1],b);
}
void Pair_Set_Si(__Pair_struct* pair,unsigned long a,unsigned long b){
  element_set_si(pair->val[0],a);
  element_set_si(pair->val[1],b);
}
void Pair_Set(__Pair_struct* pair,__Pair_struct* src){
  element_set(pair->val[0],src->val[0]);
  element_set(pair->val[1],src->val[1]);
}
//set Pair equal to the identity element of G1xG2
void Pair_Set1(__Pair_struct* pair){
  element_set1(pair->val[0]);
  element_set1(pair->val[1]);
}
//returns zero if the pairs are equal, 1 otherwise
int Pair_IsEqual(__Pair_struct*  a,__Pair_struct*  b){

  int i = element_cmp(a->val[0],b->val[0]);
  int j = element_cmp(a->val[1],b->val[1]);
  if(i==0 && j==0)
    return true;
  else
    return false;
}
void Free_Pair(__Pair_struct*  pair){
  element_clear(pair->val[0]);
  element_clear(pair->val[1]);
}
void Free_Pairs(__Pair_struct*  first, ...) {
    element_clear(first->val[0]);
    element_clear(first->val[1]);

    va_list args;
    va_start(args, first);

    __Pair_struct *p;   // pointer to the single struct

    // retrieve subsequent arguments as pointers
    while ((p = va_arg(args, __Pair_struct *)) != NULL) {
        element_clear(p->val[0]);
        element_clear(p->val[1]);
    }

    va_end(args);
}
void Pair_Mul(__Pair_struct* result,__Pair_struct* a,__Pair_struct* b){
  element_mul(result->val[0],a->val[0],b[0].val[0]);
  element_mul(result->val[1],a->val[1],b[0].val[1]);
}
void Pair_Inv(__Pair_struct* result,__Pair_struct* a){
  element_invert(result->val[0], a->val[0]);
  element_invert(result->val[1], a->val[1]);
}
void Pair_Pow_Mpz(__Pair_struct* result ,__Pair_struct* a,mpz_ptr n){
  element_pow_mpz(result->val[0], a->val[0], n);
  element_pow_mpz(result->val[1], a->val[1], n);
}
//(g1,g2)^n
void Pair_g1_g2_Pow(DscBGrp* bgrp,__Pair_struct* result,mpz_ptr n){
  element_pp_pow(result->val[0], n, bgrp->g1_pp);
  element_pp_pow(result->val[1], n, bgrp->g2_pp);
}
void Get_Pairing(element_t result,__Pair_struct* pair){
  element_pairing(result, pair[0].val[0], pair[0].val[1]);
}
// ############ pseudo random function for G1xG2 ###############
// Key,{0,1}* -> Zq^2 where q is the order of the pairing group, output will be of form (mpz_t,mpz_t) where each mpz_t
//will be in Zq
void PRF_Ki(mpz_t out[2],const uint8_t* key,size_t keylen,const uint8_t* input,size_t inputlen,DscBGrp* bgrp){
  uint8_t output[2][32];
  uint8_t* key2 = malloc(keylen); //just for test
  memcpy(key2,key,keylen);
  key2[0] = !key2[0];
  PRF(output[0],key,keylen,input,inputlen);
  PRF(output[1],key2,keylen,input,inputlen);
  byteArray_to_mpz(out[0], (char*)output[0], bgrp->numberOfBits/8);
  byteArray_to_mpz(out[1], (char*)output[1], bgrp->numberOfBits/8);
  mpz_mod(out[0],out[0],bgrp->order);
  mpz_mod(out[1],out[1],bgrp->order);
  free(key2);
}
//output of the form G1xG2, returns exponent, the exponent must be cleared with mpz_clear and then freed
mpz_t* PRF_K(__Pair_struct* outputPair,Seed K[2],size_t keylen,const uint8_t* input1,size_t inputlen1,
  const uint8_t* input2,size_t inputlen2,DscBGrp* bgrp){
    mpz_t gamma_nu_n[2];
    mpz_t gamma_nu[2];
    mpz_inits(gamma_nu_n[0],gamma_nu_n[1],gamma_nu[0],gamma_nu[1],NULL);
    PRF_Ki(gamma_nu_n,K[0].val,keylen,input1,inputlen1,bgrp);
    PRF_Ki(gamma_nu,K[1].val,keylen,input2,inputlen2,bgrp);
    mpz_t* exponent = malloc(sizeof(mpz_t));
    mpz_init(*exponent);
    mpz_mul(*exponent,gamma_nu_n[0],gamma_nu[0]);
    mpz_addmul(*exponent,gamma_nu_n[1],gamma_nu[1]);
    mpz_mod(*exponent,*exponent,bgrp->order);
    Pair_g1_g2_Pow(bgrp, outputPair, *exponent);
    mpz_clears(gamma_nu_n[0],gamma_nu_n[1],gamma_nu[0],gamma_nu[1],NULL);
    return exponent;
}
// ############ AES Encryption CTR 256. key is 32 bytes and iv is 16 bytes(must be unique per message)############
//returns ciphertext length
int aes_ctr_encrypt(const unsigned char *plaintext, int plaintext_len,
                    const unsigned char *key, const unsigned char *iv,
                    unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    int len;
    int ciphertext_len;

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len = len;

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

int aes_ctr_decrypt(const unsigned char *ciphertext, int ciphertext_len,
                    const unsigned char *key, const unsigned char *iv,
                    unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    int len;
    int plaintext_len;

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len = len;

    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}


// ###############################

// initializes rndelement with a random value less than prime
void generate_random_mpz(mpz_ptr prime, mpz_ptr rndelement) {
  // Initialize LibTomCrypt PRNG
  int prng_idx = register_prng(&sprng_desc);
  if (prng_idx == -1) {
    fprintf(stderr, "Error registering sprng\n");
  }

  prng_state prng;
  if (sprng_start(&prng) != CRYPT_OK || sprng_ready(&prng) != CRYPT_OK) {
    fprintf(stderr, "Error initializing sprng\n");
  }

  size_t num_bytes = (mpz_sizeinbase(prime, 2) + 7) / 8;
  unsigned char *buffer = malloc(num_bytes);
  if (!buffer) {
    fprintf(stderr, "Memory allocation failed\n");
  }

  mpz_t temp;
  mpz_init(temp);

  do {
    // Generate cryptographically secure random bytes
    if (sprng_read(buffer, num_bytes, NULL) != num_bytes) {
      fprintf(stderr, "sprng_read failed\n");
      free(buffer);
    }

    // Convert buffer to mpz_t
    mpz_import(temp, num_bytes, 1, 1, 0, 0, buffer);

  } while (mpz_cmp(temp, prime) > 0); // Retry if temp > q

  mpz_set(rndelement, temp);

  mpz_clear(temp);
  free(buffer);
}
// ###### Thrss=(Share,ReConst) (Shamir Secret Sharing)
void Thss_Config(DscThss *thss, int secparam_bits, int total, int threshold) {
  thss->num_bits = secparam_bits;
  thss->num_shares = total;
  thss->threshold = threshold;

  thss->shares_x = (mpz_t *)malloc(thss->num_shares * sizeof(mpz_t));
  thss->shares_y = (mpz_t *)malloc(thss->num_shares * sizeof(mpz_t));
  mpz_init(thss->recovered_secret);
  thss->coeffs = (mpz_t *)malloc((thss->threshold) * sizeof(mpz_t));
  for(int i=0;i<total;i++){
    mpz_init(thss->shares_x[i]);
    mpz_init(thss->shares_y[i]);
  }
  mpz_init(thss->prime);
}
// initilized thss->prime, if the prime argument is Null then generates a prime
void Thss_KeyGen(DscThss *thss, mpz_ptr prime) {
  // generate_random_prime(thss);
  if (prime) {
    mpz_set(thss->prime, prime);
  } else {
    gmp_randstate_t state;
    gmp_randinit_default(state);
    time_t t;
    srand((unsigned)time(&t));
    unsigned long seed = rand();
    gmp_randseed_ui(state, seed);

    mpz_t random_num;
    mpz_init(random_num);
    mpz_urandomb(random_num, state, thss->num_bits);

    mpz_nextprime(thss->prime, random_num);

    mpz_clear(random_num);
    gmp_randclear(state);
  }
}
// find (thss->num_shares) points on the polynomial, if secret is NULL then
// generates one randomly
void Thss_Share(DscThss *thss, mpz_ptr secret) {
  mpz_init(thss->coeffs[0]);
  mpz_set(thss->coeffs[0], secret);

  for (int i = 1; i < thss->threshold; i++) {
    mpz_init(thss->coeffs[i]);
    generate_random_mpz(thss->prime, thss->coeffs[i]);
  }

  mpz_t x;
  mpz_init(x);
  for (int i = 0; i < thss->num_shares; i++) {
    mpz_set_ui(x, i + 1); // مقادیر x باید منحصر به فرد باشند
    mpz_set(thss->shares_x[i], x);
    mpz_set_ui(thss->shares_y[i], 0);
    mpz_t term;
    mpz_init(term);

    for (int j = thss->threshold - 1; j >= 0; j--) {
      mpz_mul(term, thss->shares_y[i], thss->shares_x[i]);
      mpz_mod(term, term, thss->prime);
      mpz_add(thss->shares_y[i], term, thss->coeffs[j]);
      mpz_mod(thss->shares_y[i], thss->shares_y[i], thss->prime);
    }
    mpz_clear(term);
  }
  mpz_clear(x);
  for (int i = 0; i < thss->threshold; i++) {
    mpz_clear(thss->coeffs[i]);
  }
}
void Thss_ReCons(DscThss *thss) {
  mpz_set_ui(thss->recovered_secret, 0);
  mpz_t term, numerator, denominator, temp;
  mpz_inits(term, numerator, denominator, temp, NULL);

  for (int i = 0; i < thss->threshold; i++) {
    mpz_set_ui(term, 1);
    for (int j = 0; j < thss->threshold; j++) {
      if (i != j) {
        mpz_sub(numerator, thss->shares_x[j], thss->shares_x[i]);
        mpz_set(denominator, numerator);
        mpz_set_ui(temp, 0);
        mpz_add(temp, temp, thss->shares_x[j]);
        mpz_mul(term, term, temp);
        mpz_mod(term, term, thss->prime);
        mpz_invert(denominator, denominator, thss->prime);
        mpz_mul(term, term, denominator);
        mpz_mod(term, term, thss->prime);
      }
    }
    mpz_mul(term, term, thss->shares_y[i]);
    mpz_mod(term, term, thss->prime);
    mpz_add(thss->recovered_secret, thss->recovered_secret, term);
    mpz_mod(thss->recovered_secret, thss->recovered_secret, thss->prime);
  }

  mpz_clears(term, numerator, denominator, temp, NULL);
}
void Thss_Free(DscThss *thss) {
  mpz_clears(thss->prime, thss->recovered_secret, NULL);
  free(thss->coeffs);
  for (int i = 0; i < thss->num_shares; i++) {
    mpz_clear(thss->shares_x[i]);
    mpz_clear(thss->shares_y[i]);
  }
  free(thss->shares_x);
  free(thss->shares_y);

}
