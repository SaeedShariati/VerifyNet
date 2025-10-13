#include <inttypes.h>
#include <pbc/pbc.h>
#include <pbc/pbc_curve.h>
#include <pbc/pbc_field.h>
#include <pbc/pbc_pairing.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
// #include <pbc/pbc_test.h>
#include "CryptoPrimitivesV1.h"
#include <gmp.h>
#include <openssl/rand.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include <tomcrypt.h>

/********** Command for compile (FAIRSHARE (.c) + CryptoPrimitives (.c and .h))
*************************************************************

gcc VNet.c VNet.c -o VNet -I ~/.local/include/pbc -L ~/.local/lib -Wl,-rpath
~/.local/lib  -l pbc -lssl -lcrypto -lgmp -l tomcrypt -l m

*********************************************************************************************************************************************/
#define GRAD_SIZE 1000
#define USERS_SIZE 100
#define SEC_PARAM 32 // in bytes
#define Threshold 10
#define DropOut 0 // what rate of users dropout at every step
#define ITERATIONS 1

typedef struct {
  int Uid;                       // Unique ID for the user
  Share beta_shares[USERS_SIZE]; // shares of User's beta
  Share Nsk_shares[USERS_SIZE];  // shares of User's Nsk

  unsigned long plainLocalVector[GRAD_SIZE];

  mpz_t P_sk;
  mpz_t P_pk;
  mpz_t N_sk;
  mpz_t N_pk;

  mpz_t maskedLocalVector[GRAD_SIZE];

  mpz_t betaMasked; // beta_i,j
  uint32_t betaMaskedSize;

  Seed sdata[USERS_SIZE]; // s_i,j ,32 bytes each

  // output thrcrypt
  DscCipher Pt;
  DscCipher B;

} DscClient;

////////////////////////////////////
typedef struct {
  DscGrp grp;
  DscBGrp bgrp;
  DscThss thss;

  mpz_t delta_p[2];
  Seed K[2];

  DscThrCrypt thrcrypt;

  uint32_t secparam;   // Security parameter
  uint32_t numClients; // Number of clients
  uint32_t thrshld;    // Threshold
  uint32_t grdSize;
  uint32_t rndlbl;

  uint8_t Uact1[USERS_SIZE], Uact2[USERS_SIZE], Uact3[USERS_SIZE],
      Uact4[USERS_SIZE]; // which clients are active in U1,U2,
                         // and U3. 1 if active, 0 if inactive.
  uint16_t Uact1Active, Uact2Active, Uact3Active,
      Uact4Active; // number of users in each U1,U2,U3

  mpz_t *gradGlobalVector;

  DscClient Users[USERS_SIZE]; // Array of users (clients)
  Cipher Pnm[USERS_SIZE][USERS_SIZE];
  Pair AB[USERS_SIZE][GRAD_SIZE];
  Pair LQ[USERS_SIZE][GRAD_SIZE];
  uint16_t omega[USERS_SIZE];

  Pair AB_Product[GRAD_SIZE]; // product of all (A_i,B_i), i in U3
  Pair LQ_Product[GRAD_SIZE]; // product of all (L_i,Q_i), i in U3
  int omega_Product;          // product of all omega_n, n in U3

  mpz_t d;
  uint32_t tau;
  Share Nsk_nm[USERS_SIZE]
              [USERS_SIZE]; // shares of Nsk for users who were present in key
                            // sharing(U2) but dropped out for Masking(U3).
                            // share of user n given to m
  Share beta_nm[USERS_SIZE][USERS_SIZE]; // shares of beta for users who were
                                         // present in Masking(U3)
} DscVNet;

typedef struct quantity_overhead {
  double usual;
  double overhead;
} quantity_overhead;
typedef struct Time_Performance {
  double keyshare_client;
  double keyshare_server;
  quantity_overhead mask_client;
  double mask_server;
  double unmask_client;
  quantity_overhead unmask_server;
  double verification_client;
  double verification_server;
} Time_Performance;
typedef struct Communication_Overhead {
  double keyshare_client;
  double keyshare_server;
  quantity_overhead mask_client;
  quantity_overhead mask_server;
  double unmask_client;
  quantity_overhead unmask_server;
  quantity_overhead verification_client;
  double verification_server;
} Communication_Overhead;
Communication_Overhead communication_overhead;
Time_Performance time_measured;
DscTimeMeasure global_timemeasure;

static inline void generate_random_mpz_vnet(DscVNet *vnet, mpz_ptr rndelement) {
  mpz_urandomm(rndelement, vnet->grp.state, vnet->grp.prime);
}
static inline void generate_random_mpz_BGroup(DscVNet *vnet,
                                              mpz_ptr rndelement) {
  mpz_urandomm(rndelement, vnet->grp.state, vnet->bgrp.order);
}
// prints hex code
void print(char *a, uint32_t size) {
  for (int i = 0; i < size; i++) {
    printf(" %02x", (unsigned char)a[i]);
  }
  printf("\n");
}
// prints hex code
void printIndex(char *a, uint32_t size, char *name, uint32_t index) {
  printf("\n******* Debug *********");
  printf("\n%s[%d] :\n", name, index);
  for (int i = 0; i < size; i++) {
    printf("%02x", (unsigned char)a[i]);
  }
  printf("\n**********************\n");
}
void printmpz(mpz_t a, char *name) {
  printf("\n******* Debug *********");
  printf("\n%s :\n", name);
  gmp_printf("%Zx", a);
  printf("\n**********************\n");
}
// not secure, used to give random inputs for local gra
uint64_t rand_uint64() {

  static uint64_t state = 88172645463325252ull; // seed
  state = state * 6364136223846793005ULL + 1;
  return state;
}

// if originalSize<newSize then adds zeros to the end until the size of bytes*
// becomes newSize
static inline void padWithZero(char **bytes, size_t originalSize,
                               size_t newSize) {
  if (originalSize < newSize) {

    char *temp = realloc(*bytes, newSize);
    if (!temp) {
      // realloc failed, original arr is still valid
      free(bytes);
      perror("realloc");
      exit(1);
    }
    *bytes = temp;
    memset(*bytes + originalSize, 0, newSize - originalSize);
  }
}
static inline void print_timemeasure_header() {
  printf("                                             "
         " | Seconds | Miliseconds | Microseconds |  Nanoseconds  |\n"
         "                                             "
         " --------------------------------------------------------\n");
}
static inline void print_timemeasure(DscTimeMeasure *timemeasure, uint16_t iter,
                                     char *function_name) {

  printf("[iter %3d] Elapsed Time for %-15s : |%9ld|%13ld|%14ld|%15ld|\n", iter,
         function_name, timemeasure->seconds, timemeasure->milliseconds,
         timemeasure->microseconds, timemeasure->nanoseconds);
}
void VNET_Config(DscVNet *vnet) {
  // initialize all values of time_measured and memory_measured to zero
  memset(&time_measured, 0, sizeof(time_measured));
  memset(&communication_overhead, 0, sizeof(communication_overhead));

  vnet->secparam = SEC_PARAM;
  vnet->thrshld = Threshold;
  vnet->numClients = USERS_SIZE;
  vnet->grdSize = GRAD_SIZE;
  vnet->rndlbl = 1;

  memset(vnet->Uact1, 1, sizeof(vnet->Uact1));
  memset(vnet->Uact2, 0, sizeof(vnet->Uact1));
  memset(vnet->Uact3, 0, sizeof(vnet->Uact1));
  memset(vnet->Uact4, 0, sizeof(vnet->Uact1));

  vnet->Uact1Active = 0;
  vnet->Uact2Active = 0;
  vnet->Uact3Active = 0;
  vnet->Uact4Active = 0;

  memset(vnet->omega, 0, sizeof(vnet->omega));
  GroupGen_Config(&(vnet->grp), vnet->secparam * 8);
  BGroupGen_Config(&(vnet->bgrp));
  GroupGen(&(vnet->grp));
  BGroupGen(&(vnet->bgrp));
  // Initialize each user's UID and random gradients
  for (int i = 0; i < USERS_SIZE; i++) {
    vnet->Users[i].Uid = i; // Example: Assign UIDs from 0 to numClients-1

    // To initialize local data vector for each user
    srand(time(NULL));
    for (int j = 0; j < GRAD_SIZE; j++) {
      vnet->Users[i].plainLocalVector[j] = rand_uint64();
    }
  }
}

void VNET_Init(DscVNet *vnet) {
  RAND_bytes(vnet->K[0].val, 32);
  RAND_bytes(vnet->K[1].val, 32);
  mpz_init(vnet->delta_p[0]);
  mpz_init(vnet->delta_p[1]);
  mpz_init(vnet->d);
  generate_random_mpz_BGroup(vnet, vnet->delta_p[0]);
  generate_random_mpz_BGroup(vnet, vnet->delta_p[1]);
  generate_random_mpz_BGroup(vnet, vnet->d);
  RAND_bytes((unsigned char *)&(vnet->tau), sizeof(vnet->tau));

  for (int i = 0; i < USERS_SIZE; i++) {
    if (vnet->Uact1[i] == 0)
      continue;
    mpz_inits(vnet->Users[i].P_sk, vnet->Users[i].P_pk, vnet->Users[i].N_sk,
              vnet->Users[i].N_pk, NULL);
    generate_random_mpz_vnet(vnet, vnet->Users[i].P_sk);
    generate_random_mpz_vnet(vnet, vnet->Users[i].N_sk);
    mpz_powm(vnet->Users[i].N_pk, vnet->grp.generator, vnet->Users[i].N_sk,
             vnet->grp.prime);
    mpz_powm(vnet->Users[i].P_pk, vnet->grp.generator, vnet->Users[i].P_sk,
             vnet->grp.prime);
    (vnet->Uact1Active)++;
  }

  // Server
  if (vnet->Uact1Active < Threshold) {
    printf("\nVNET_Init: Not enough active users to continue\n");
    printf("Uact1 = %d\n", vnet->Uact1Active);

    exit(1);
  }
}

void VNET_KeyShare(DscVNet *vnet) {
  vnet->Uact2Active = 0;
  for (uint16_t i = 0; i < USERS_SIZE; i++) {
    if (vnet->Uact2[i] == 0)
      continue;
    clock_gettime(
        CLOCK_MONOTONIC,
        (&(global_timemeasure.start))); // measuring time takes by users
    (vnet->Uact2Active)++;
    mpz_init(vnet->Users[i].betaMasked);
    generate_random_mpz_vnet(vnet, vnet->Users[i].betaMasked);
    memset(vnet->Pnm[i], 1,
           sizeof(vnet->Pnm[i])); // initialized all ivs and ciphertexts
    Thss_Config(&(vnet->thss), SEC_PARAM, vnet->Uact1Active - 1, Threshold);
    Thss_KeyGen(&(vnet->thss), vnet->grp.prime);

    Thss_Share(&(vnet->thss), vnet->Users[i].betaMasked);
    int t = 0; // shares counter
    for (uint16_t z = 0; z < USERS_SIZE; z++) {
      if (vnet->Uact1[z] == 0 || i == z)
        continue;
      mpz_init(vnet->Users[i].beta_shares[z].val[0]);
      mpz_init(vnet->Users[i].beta_shares[z].val[1]);
      mpz_set(vnet->Users[i].beta_shares[z].val[0], vnet->thss.shares_x[t]);
      mpz_set(vnet->Users[i].beta_shares[z].val[1], vnet->thss.shares_y[t]);
      t++;
    }
    Thss_Share(&(vnet->thss), vnet->Users[i].N_sk);
    t = 0;
    for (uint16_t z = 0; z < USERS_SIZE; z++) {
      if (vnet->Uact1[z] == 0 || i == z)
        continue;

      mpz_init(vnet->Users[i].Nsk_shares[z].val[0]);
      mpz_init(vnet->Users[i].Nsk_shares[z].val[1]);
      mpz_set(vnet->Users[i].Nsk_shares[z].val[0], vnet->thss.shares_x[t]);
      mpz_set(vnet->Users[i].Nsk_shares[z].val[1], vnet->thss.shares_y[t]);
      t++;

      mpz_t secretKey;
      mpz_init(secretKey);
      mpz_powm(secretKey, vnet->Users[z].P_pk, vnet->Users[i].P_sk,
               vnet->grp.prime);
      char *key;
      int keysize = mpz_to_byteArray((char **)&key, secretKey);
      mpz_clear(secretKey);
      padWithZero(&key, keysize, 32);
      RAND_bytes(vnet->Pnm[i][z].iv, 16);
      unsigned char plaintext[132];
      char *Nsk_share_x;
      char *Nsk_share_y;
      char *beta_share_x;
      char *beta_share_y;

      vnet->Pnm[i][z].Nx =
          mpz_to_byteArray(&Nsk_share_x, vnet->Users[i].Nsk_shares[z].val[0]);
      padWithZero(&Nsk_share_x, vnet->Pnm[i][z].Nx, SEC_PARAM);
      vnet->Pnm[i][z].Ny =
          mpz_to_byteArray(&Nsk_share_y, vnet->Users[i].Nsk_shares[z].val[1]);
      padWithZero(&Nsk_share_y, vnet->Pnm[i][z].Ny, SEC_PARAM);
      vnet->Pnm[i][z].bx =
          mpz_to_byteArray(&beta_share_x, vnet->Users[i].beta_shares[z].val[0]);
      padWithZero(&beta_share_x, vnet->Pnm[i][z].bx, SEC_PARAM);

      vnet->Pnm[i][z].by =
          mpz_to_byteArray(&beta_share_y, vnet->Users[i].beta_shares[z].val[1]);
      padWithZero(&beta_share_y, vnet->Pnm[i][z].by, SEC_PARAM);

      mpz_clears(vnet->Users[i].Nsk_shares[z].val[0],
                 vnet->Users[i].Nsk_shares[z].val[1],
                 vnet->Users[i].beta_shares[z].val[0],
                 vnet->Users[i].beta_shares[z].val[1], NULL);

      memcpy(plaintext, &i, 2);
      memcpy(plaintext + 2, &z, 2);
      memcpy(plaintext + 4, Nsk_share_x, SEC_PARAM);
      memcpy(plaintext + 4 + SEC_PARAM, Nsk_share_y, SEC_PARAM);
      memcpy(plaintext + 4 + 2 * SEC_PARAM, beta_share_x, SEC_PARAM);
      memcpy(plaintext + 4 + 3 * SEC_PARAM, beta_share_y, SEC_PARAM);
      free(Nsk_share_x);
      free(Nsk_share_y);
      free(beta_share_x);
      free(beta_share_y);

      aes_ctr_encrypt(plaintext, sizeof(plaintext), (unsigned char *)key,
                      vnet->Pnm[i][z].iv, vnet->Pnm[i][z].ciphertext);
      free(key);
    }
    Thss_Free(&(vnet->thss));
    clock_gettime(CLOCK_MONOTONIC, (&(global_timemeasure.end)));
    Time_Measure(&global_timemeasure);
    time_measured.keyshare_client += global_timemeasure.milliseconds;
  } // end of user computation
  //-------------------------------------------------------------------------------------
  // Server
  clock_gettime(CLOCK_MONOTONIC, (&(global_timemeasure.start)));
  if (vnet->Uact2Active < Threshold) {
    printf("\nU2 has %u members which is less than the threshold(%u),execution "
           "is terminated.\n",
           vnet->Uact2Active, Threshold);
  }
  clock_gettime(CLOCK_MONOTONIC, (&(global_timemeasure.end)));
  Time_Measure(&global_timemeasure);
  time_measured.keyshare_server += global_timemeasure.milliseconds;
}
void VNET_Mask(DscVNet *vnet) {

  vnet->Uact3Active = 0;
  for (uint16_t i = 0; i < USERS_SIZE; i++) {
    if (vnet->Uact3[i] == 0)
      continue;
    // timing mask without the overhead
    clock_gettime(CLOCK_MONOTONIC, (&(global_timemeasure.start)));
    mpz_t s_ij;
    mpz_t exponent, dinv;
    mpz_inits(exponent, dinv, NULL);
    mpz_sub_ui(exponent, vnet->bgrp.order, 2);
    mpz_powm(dinv, vnet->d, exponent, vnet->bgrp.order);
    mpz_clear(exponent);
    mpz_init(s_ij);
    unsigned long *prgArray = malloc(GRAD_SIZE * sizeof(unsigned long));
    mpz_t *xn = malloc(sizeof(mpz_t) * GRAD_SIZE);

    for (int j = 0; j < GRAD_SIZE; j++) {
      mpz_init(xn[j]);
      mpz_init(vnet->Users[i].maskedLocalVector[j]);
    }
    // compute s_i,m for m in U2 and i=/=m
    memset(vnet->Users[i].sdata, 0, sizeof(Seed) * USERS_SIZE);
    (vnet->Uact3Active)++;
    for (uint16_t m = 0; m < USERS_SIZE; m++) {
      if (vnet->Uact2[m] == 0 || m == i)
        continue;
      mpz_powm(s_ij, vnet->Users[m].N_pk, vnet->Users[i].N_sk, vnet->grp.prime);
      char *temp;
      int tempsize = mpz_to_byteArray(&temp, s_ij);
      memcpy(vnet->Users[i].sdata[m].val, temp, tempsize);
      free(temp);
    }
    for (int z = 0; z < USERS_SIZE; z++) { // Masking
      if (z == i || vnet->Uact2[z] == 0)
        continue;
      // Mask Gradient prgArray = G(s_i,z)
      PRG((uint8_t *)prgArray, GRAD_SIZE * sizeof(unsigned long),
          vnet->Users[i].sdata[z].val);
      if (z > i) {
        for (int j = 0; j < GRAD_SIZE; j++) {

          mpz_add_ui(vnet->Users[i].maskedLocalVector[j],
                     vnet->Users[i].maskedLocalVector[j], prgArray[j]);
        }
      } else {
        for (int j = 0; j < GRAD_SIZE; j++) {

          mpz_sub_ui(vnet->Users[i].maskedLocalVector[j],
                     vnet->Users[i].maskedLocalVector[j], prgArray[j]);
        }
      }
    }
    for (int j = 0; j < GRAD_SIZE; j++) {
      mpz_set_ui(xn[j], vnet->Users[i].plainLocalVector[j]);
      mpz_add(vnet->Users[i].maskedLocalVector[j],
              vnet->Users[i].maskedLocalVector[j], xn[j]);
    }
    // generate prgArray G(beta_i) for i in U3
    char *betaMasked;
    size_t betaMaskedSize =
        mpz_to_byteArray(&betaMasked, vnet->Users[i].betaMasked);
    padWithZero(&betaMasked, betaMaskedSize, 32);
    PRG((uint8_t *)prgArray, GRAD_SIZE * sizeof(unsigned long),
        (uint8_t *)betaMasked);
    free(betaMasked);

    // add G(beta_i) to gradient
    for (int j = 0; j < GRAD_SIZE; j++) {
      mpz_add_ui(vnet->Users[i].maskedLocalVector[j],
                 vnet->Users[i].maskedLocalVector[j], prgArray[j]);
    }
    // finished timing mask for user i without the overhead
    clock_gettime(CLOCK_MONOTONIC, (&(global_timemeasure.end)));
    Time_Measure(&global_timemeasure);
    time_measured.mask_client.usual += global_timemeasure.milliseconds;

    // start timing overhead for Mask
    clock_gettime(CLOCK_MONOTONIC, (&(global_timemeasure.start)));
    // computing values used for verification
    for (int j = 0; j < GRAD_SIZE; j++) {
      Initialize_Pair(&(vnet->bgrp), vnet->AB[i][j]);
      Initialize_Pair(&(vnet->bgrp), vnet->LQ[i][j]);
    }
    vnet->omega[i] = 1;
    Polynomial *polynomial = malloc(sizeof(Polynomial) * GRAD_SIZE);
    Convert_To_Polynomial(polynomial, xn, GRAD_SIZE);
    mpz_t* AB_exponent = Homomorphic_Hash(vnet->AB[i], polynomial, GRAD_SIZE, vnet->delta_p[0],
                     &(vnet->bgrp));

    mpz_t EF_exponent;
    mpz_t gamma_nu_n[2];
    mpz_t gamma_nu[2];
    mpz_inits(gamma_nu_n[0],gamma_nu_n[1],gamma_nu[0],gamma_nu[1],NULL);
    PRF_Ki(gamma_nu_n,vnet->K[0].val,32,(uint8_t *)&i,2,&(vnet->bgrp));
    PRF_Ki(gamma_nu,vnet->K[1].val,32,(uint8_t *)&(vnet->tau),4,&(vnet->bgrp));
    mpz_init(EF_exponent);
    mpz_mul(EF_exponent,gamma_nu_n[0],gamma_nu[0]);
    mpz_addmul(EF_exponent,gamma_nu_n[1],gamma_nu[1]);
    mpz_mod(EF_exponent,EF_exponent,vnet->bgrp.order);
    mpz_clears(gamma_nu_n[0],gamma_nu_n[1],gamma_nu[0],gamma_nu[1],NULL);


    mpz_t temp_exponent;
    mpz_init(temp_exponent);
    for (int j = 0; j < GRAD_SIZE; j++) {
      mpz_sub(temp_exponent,EF_exponent,AB_exponent[j]);
      mpz_mod(temp_exponent,temp_exponent,vnet->bgrp.order);
      mpz_mul(temp_exponent,temp_exponent,dinv);
      mpz_mod(temp_exponent,temp_exponent,vnet->bgrp.order);
      Pair_g1_g2_Pow(&(vnet->bgrp), vnet->LQ[i][j],temp_exponent);
      mpz_clears(polynomial[j].a[0], polynomial[j].a[1], NULL);
      mpz_clear(AB_exponent[j]);
    }
    mpz_clear(EF_exponent);
    free(AB_exponent);
    mpz_clear(temp_exponent);
    free(polynomial);
    free(prgArray);
    mpz_clears(s_ij, dinv, NULL);
    for (int j = 0; j < GRAD_SIZE; j++) {
      mpz_clear(xn[j]);
    }
    free(xn);

    // finished timining overhead for mask
    clock_gettime(CLOCK_MONOTONIC, (&(global_timemeasure.end)));
    Time_Measure(&global_timemeasure);
    time_measured.mask_client.overhead += global_timemeasure.milliseconds;
  } // end of user computation

  for (int i = 0; i < USERS_SIZE; i++) {
    if (vnet->Uact2[i] == 0)
      continue;
    mpz_clear(vnet->Users[i].betaMasked);
  }

  clock_gettime(CLOCK_MONOTONIC, (&(global_timemeasure.start)));
  // Server
  if (vnet->Uact3Active < Threshold) {
    printf("\nU3 has %u members which is less than the threshold(%u),execution "
           "is terminated.\n",
           vnet->Uact3Active, Threshold);
  }
  clock_gettime(CLOCK_MONOTONIC, (&(global_timemeasure.end)));
  Time_Measure(&global_timemeasure);
  time_measured.mask_server += global_timemeasure.milliseconds;
}

void VNET_UNMask(DscVNet *vnet) {
  vnet->Uact4Active = 0;
  for (int i = 0; i < USERS_SIZE; i++) {
    if (vnet->Uact4[i] == 0)
      continue;
    (vnet->Uact4Active)++;

    clock_gettime(CLOCK_MONOTONIC, (&(global_timemeasure.start)));
    for (int m = 0; m < USERS_SIZE;
         m++) { // get the shares of Nsk and beta for Users in U2
      if (vnet->Uact2[m] == 0 || m == i)
        continue;

      mpz_t secretKey;
      mpz_init(secretKey);
      mpz_powm(secretKey, vnet->Users[m].P_pk, vnet->Users[i].P_sk,
               vnet->grp.prime);

      char *key;
      int keysize = mpz_to_byteArray((char **)&key, secretKey);
      mpz_clear(secretKey);
      padWithZero(&key, keysize, 32);

      unsigned char plaintext[132];
      aes_ctr_decrypt(vnet->Pnm[m][i].ciphertext, sizeof(plaintext),
                      (unsigned char *)key, vnet->Pnm[m][i].iv, plaintext);
      free(key);

      uint16_t a = 0;
      uint16_t b = 0;
      memcpy(&a, plaintext, 2);
      memcpy(&b, plaintext + 2, 2);

      char *Nsk_share_x = malloc(vnet->Pnm[a][b].Nx);
      char *Nsk_share_y = malloc(vnet->Pnm[a][b].Ny);
      char *beta_share_x = malloc(vnet->Pnm[a][b].bx);
      char *beta_share_y = malloc(vnet->Pnm[a][b].by);
      memcpy(Nsk_share_x, plaintext + 4, vnet->Pnm[a][b].Nx);
      memcpy(Nsk_share_y, plaintext + 4 + SEC_PARAM, vnet->Pnm[a][b].Ny);
      memcpy(beta_share_x, plaintext + 4 + 2 * SEC_PARAM, vnet->Pnm[a][b].bx);
      memcpy(beta_share_y, plaintext + 4 + 3 * SEC_PARAM, vnet->Pnm[a][b].by);

      if (vnet->Uact3[a] == 0) {
        mpz_inits(vnet->Nsk_nm[a][b].val[0], vnet->Nsk_nm[a][b].val[1], NULL);

        byteArray_to_mpz(vnet->Nsk_nm[a][b].val[0], Nsk_share_x,
                         vnet->Pnm[a][b].Nx);
        byteArray_to_mpz(vnet->Nsk_nm[a][b].val[1], Nsk_share_y,
                         vnet->Pnm[a][b].Ny);
      }
      mpz_inits(vnet->beta_nm[a][b].val[0], vnet->beta_nm[a][b].val[1], NULL);
      byteArray_to_mpz(vnet->beta_nm[a][b].val[0], beta_share_x,
                       vnet->Pnm[a][b].bx);
      byteArray_to_mpz(vnet->beta_nm[a][b].val[1], beta_share_y,
                       vnet->Pnm[a][b].by);
      free(Nsk_share_x);
      free(Nsk_share_y);
      free(beta_share_x);
      free(beta_share_y);
    }
    clock_gettime(CLOCK_MONOTONIC, (&(global_timemeasure.end)));
    Time_Measure(&global_timemeasure);
    time_measured.unmask_client += global_timemeasure.milliseconds;
  } // end user computation
  //__________________ Server ______________________________
  clock_gettime(CLOCK_MONOTONIC, (&(global_timemeasure.start)));
  Thss_Config(&(vnet->thss), SEC_PARAM, vnet->Uact1Active, Threshold);
  Thss_KeyGen(&(vnet->thss), vnet->grp.prime);
  if (vnet->Uact4Active < Threshold) {
    printf("\nUnmask: not enough users to continue\n");
    exit(1);
  }
  unsigned long *prgArray = malloc(vnet->grdSize * sizeof(unsigned long));
  int t; // variale for counting number of shares retrieved
  vnet->gradGlobalVector = malloc(vnet->grdSize * sizeof(mpz_t));
  for (int k = 0; k < GRAD_SIZE; k++) {
    mpz_init(vnet->gradGlobalVector[k]);
  }
  for (int i = 0; i < USERS_SIZE; i++) {
    if (vnet->Uact3[i] == 0)
      continue;

    // generate prgArray G(beta_i) for i in U3
    t = 0;
    for (int m = 0; t < Threshold && m < USERS_SIZE; m++) {
      if ((vnet->Uact4[m] == 1) && (m != i)) {

        mpz_set(vnet->thss.shares_x[t], vnet->beta_nm[i][m].val[0]);
        mpz_set(vnet->thss.shares_y[t], vnet->beta_nm[i][m].val[1]);
        t++;
      }
    }
    Thss_ReCons(&(vnet->thss));
    char *betaMasked;
    size_t betaMaskedSize = mpz_to_byteArray(
        &betaMasked,
        vnet->thss.recovered_secret); // vnet->thss.recovered_secret);//beta

    padWithZero(&betaMasked, betaMaskedSize, 32);
    PRG((uint8_t *)prgArray, GRAD_SIZE * sizeof(unsigned long),
        (uint8_t *)betaMasked);
    free(betaMasked);
    for (int j = 0; j < GRAD_SIZE; j++) {
      mpz_add(vnet->gradGlobalVector[j], vnet->gradGlobalVector[j],
              vnet->Users[i].maskedLocalVector[j]);
      mpz_clear(vnet->Users[i].maskedLocalVector[j]);

      mpz_sub_ui(vnet->gradGlobalVector[j], vnet->gradGlobalVector[j],
                 prgArray[j]);
    }
  }
  for (int i = 0; i < USERS_SIZE; i++) {
    if (vnet->Uact2[i] == 0 || vnet->Uact3[i] == 1)
      continue;
    t = 0;
    for (int m = 0; t < Threshold && m < USERS_SIZE; m++) {
      if ((vnet->Uact4[m] == 1) && (m != i)) {

        mpz_set(vnet->thss.shares_x[t], vnet->Nsk_nm[i][m].val[0]);
        mpz_set(vnet->thss.shares_y[t], vnet->Nsk_nm[i][m].val[1]);
        t++;
      }
    }
    Thss_ReCons(&(vnet->thss)); // retrieved Nsk[i]

    for (int z = 0; z < USERS_SIZE; z++) {
      if (z == i || vnet->Uact3[z] == 0)
        continue;

      mpz_t s_ij;
      mpz_init(s_ij);
      mpz_powm(s_ij, vnet->Users[z].N_pk, vnet->thss.recovered_secret,
               vnet->grp.prime);
      char *temp;
      int tempsize = mpz_to_byteArray(&temp, s_ij);
      mpz_clear(s_ij);
      memcpy(vnet->Users[i].sdata[z].val, temp, tempsize);
      free(temp);

      // Mask Gradient prgArray = G(s_i,z)
      PRG((uint8_t *)prgArray, GRAD_SIZE * sizeof(unsigned long),
          vnet->Users[i].sdata[z].val);

      if (z > i) {
        for (int j = 0; j < vnet->grdSize; j++) {
          mpz_add_ui(vnet->gradGlobalVector[j], vnet->gradGlobalVector[j],
                     prgArray[j]);
        }
      } else {

        for (int j = 0; j < vnet->grdSize; j++) {
          mpz_sub_ui(vnet->gradGlobalVector[j], vnet->gradGlobalVector[j],
                     prgArray[j]);
        }
      }
    }
  }
  free(prgArray);

  clock_gettime(CLOCK_MONOTONIC, (&(global_timemeasure.end)));
  Time_Measure(&global_timemeasure);
  time_measured.unmask_server.usual += global_timemeasure.milliseconds;

  // overheaad computation by the server used for verification
  clock_gettime(CLOCK_MONOTONIC, (&(global_timemeasure.start)));
  for (int j = 0; j < GRAD_SIZE; j++) {
    Initialize_Pair(&(vnet->bgrp), vnet->AB_Product[j]);
    Initialize_Pair(&(vnet->bgrp), vnet->LQ_Product[j]);
    Pair_Set1(vnet->AB_Product[j]);
    Pair_Set1(vnet->LQ_Product[j]);
  }

  vnet->omega_Product = 1;
  for (int i = 0; i < USERS_SIZE; i++) {

    for (int j = 0; j < GRAD_SIZE; j++) {
      if (vnet->Uact3[i] == 1) {
        Pair_Mul(vnet->AB_Product[j], vnet->AB_Product[j], vnet->AB[i][j]);
        Pair_Mul(vnet->LQ_Product[j], vnet->LQ_Product[j], vnet->LQ[i][j]);
        Free_Pair(vnet->AB[i][j]);
        Free_Pair(vnet->LQ[i][j]);
      }
    }
    vnet->omega_Product *= vnet->omega[i];
  }
  Thss_Free(&(vnet->thss));

  for (int i = 0; i < USERS_SIZE; i++) {
    if (vnet->Uact4[i] == 0)
      continue;
    for (int m = 0; m < USERS_SIZE;
         m++) { // get the shares of Nsk and beta for Users in U2
      if (vnet->Uact2[m] == 0 || m == i)
        continue;
      if (vnet->Uact3[m] == 0) {
        mpz_clears(vnet->Nsk_nm[m][i].val[0], vnet->Nsk_nm[m][i].val[1], NULL);
      }
      mpz_clears(vnet->beta_nm[m][i].val[0], vnet->beta_nm[m][i].val[1], NULL);
    }
  }
  clock_gettime(CLOCK_MONOTONIC, (&(global_timemeasure.end)));
  Time_Measure(&global_timemeasure);
  time_measured.unmask_server.overhead += global_timemeasure.milliseconds;
}

void VNET_Vrfy(DscVNet *vnet) {
  for (uint16_t i = 0; i < USERS_SIZE; i++) {
    if (vnet->Uact4[i] == 0)
      continue;
  
    clock_gettime(CLOCK_MONOTONIC, (&(global_timemeasure.start)));
    mpz_t gamma_nu_n[2], gamma_nu[2];
    mpz_inits(gamma_nu[0], gamma_nu[1], gamma_nu_n[0], gamma_nu_n[1], NULL);
    PRF_Ki(gamma_nu, vnet->K[1].val, sizeof(vnet->K[1].val),
           (uint8_t *)&vnet->tau, sizeof(vnet->tau), &(vnet->bgrp));
    mpz_t phi;
    mpz_init(phi);
    element_t Phi, Phip;
    element_init_GT(Phi, vnet->bgrp.pairing);
    element_init_GT(Phip, vnet->bgrp.pairing);

    for (uint16_t m = 0; m < USERS_SIZE; m++) {
      if (vnet->Uact3[m] == 0)
        continue;
      PRF_Ki(gamma_nu_n, vnet->K[0].val, sizeof(vnet->K[0].val), (uint8_t *)&m,
             sizeof(m), &(vnet->bgrp));
      mpz_addmul(phi, gamma_nu[0], gamma_nu_n[0]);
      mpz_addmul(phi, gamma_nu[1], gamma_nu_n[1]);
    }
    mpz_clears(gamma_nu[0], gamma_nu[1], gamma_nu_n[0], gamma_nu_n[1], NULL);

    mpz_mod(phi, phi, vnet->bgrp.order);
    element_pp_pow(Phi, phi, vnet->bgrp.gt_pp);
    mpz_clear(phi);
    Pair ABp[GRAD_SIZE]; //(A',B')

    Polynomial m[GRAD_SIZE];
    element_t eAh, egB, eLh, egQ;
    element_init_GT(eAh, vnet->bgrp.pairing);
    element_init_GT(egB, vnet->bgrp.pairing);
    element_init_GT(eLh, vnet->bgrp.pairing);
    element_init_GT(egQ, vnet->bgrp.pairing);
    element_t temp;
    element_init_GT(temp, vnet->bgrp.pairing);
    Convert_To_Polynomial(m, vnet->gradGlobalVector, GRAD_SIZE);
    for (int j = 0; j < GRAD_SIZE; j++) {
      Initialize_Pair(&(vnet->bgrp), ABp[j]);
      mpz_set_ui(m[j].a[1], vnet->Uact3Active);
    }
    mpz_t* ABp_exponents = Homomorphic_Hash(ABp, m, GRAD_SIZE, vnet->delta_p[0], &(vnet->bgrp));
    for (int j = 0; j < GRAD_SIZE; j++) {

      if (!Pair_IsEqual(vnet->AB_Product[j], ABp[j])) {
        printf("[User %d]Verification failed because: (A',B') =/= (A,B)\n", i);
        exit(1);
      }
      Free_Pair(ABp[j]);
      Free_Polynomial(&(m[j]));
      mpz_clear(ABp_exponents[j]);

      pairing_pp_apply(eAh, vnet->AB_Product[j][0].val[0], vnet->bgrp.g2_pp_pairing);
      pairing_pp_apply(egB, vnet->AB_Product[j][0].val[1], vnet->bgrp.g1_pp_pairing);

      if (element_cmp(eAh, egB)) {
        printf("[User %d]Verification failed because: e(A,h) =/= e(g,B)\n", i);
        exit(1);
      }

      pairing_pp_apply(eLh, vnet->LQ_Product[j][0].val[0], vnet->bgrp.g2_pp_pairing);
      pairing_pp_apply(egQ, vnet->LQ_Product[j][0].val[1], vnet->bgrp.g1_pp_pairing);

      if (element_cmp(eLh, egQ)) {
        printf("[User %d]Verification failed because: e(L,h) =/= e(g,Q)\n", i);
        exit(1);
      }

      // computing  e(A,h).e(L,h)^d
      element_pow_mpz(temp, eLh, vnet->d);
      element_mul(Phip, eAh, temp);
      if (element_cmp(Phi, Phip)) {
        printf(
            "[User %d]Verification failed because: Phi =/= e(A,h).e(L,h)^d\n",
            i);
        exit(1);
      }
    }
    free(ABp_exponents);
    element_clear(temp);
    element_clear(eAh);
    element_clear(egB);
    element_clear(eLh);
    element_clear(egQ);
    element_clear(Phi);
    element_clear(Phip);

  clock_gettime(CLOCK_MONOTONIC, (&(global_timemeasure.end)));
  Time_Measure(&global_timemeasure);
  time_measured.verification_client += global_timemeasure.milliseconds;
  }
  
  
  for (int j = 0; j < GRAD_SIZE; j++) {
    Free_Pairs(vnet->AB_Product[j], vnet->LQ_Product[j], NULL);
    mpz_clear(vnet->gradGlobalVector[j]);
  }
  free(vnet->gradGlobalVector);
}

void randomly_zero_out(uint8_t *dest, uint8_t *src, size_t size,
                       double percentage) {
  size_t count = (size_t)(size * percentage); // Number of elements to set to 0
  size_t i, selected;

  // Copy src to dest
  for (i = 0; i < USERS_SIZE; i++) {
    dest[i] = src[i]; // Copy previous array
  }

  // Randomly select 'count' indices where src[i] is 1
  srand(time(NULL));
  for (i = 0; i < count; i++) {
    do {
      selected = rand() % size; // Pick a random index
    } while (dest[selected] == 0); // Ensure we only zero out once
    dest[selected] = 0;
  }
}

int main() {

  DscVNet *vnet;
  DscTimeMeasure timemeasure;
  vnet = malloc(sizeof(DscVNet));
  uint32_t size = GRAD_SIZE * sizeof(unsigned long);

  printf("\n** Dropout = %f, n = %d, gradient size: %d, iterations: %d**\n",
         (float)DropOut, USERS_SIZE, GRAD_SIZE, ITERATIONS);
  clock_gettime(CLOCK_MONOTONIC, (&(timemeasure.start)));
  VNET_Config(vnet);
  clock_gettime(CLOCK_MONOTONIC, (&(timemeasure.end)));
  Time_Measure(&timemeasure);
  print_timemeasure_header();
  print_timemeasure(&timemeasure, 0, "Config");

  randomly_zero_out(vnet->Uact1, vnet->Uact1, vnet->numClients, DropOut);
  randomly_zero_out(vnet->Uact2, vnet->Uact1, (1 - DropOut) * USERS_SIZE,
                    DropOut);
  randomly_zero_out(vnet->Uact3, vnet->Uact2,
                    (1 - DropOut) * (1 - DropOut) * USERS_SIZE, DropOut);
  randomly_zero_out(vnet->Uact4, vnet->Uact3,
                    (1 - DropOut) * (1 - DropOut) * (1 - DropOut) * USERS_SIZE,
                    DropOut);

  clock_gettime(CLOCK_MONOTONIC, (&(timemeasure.start)));
  VNET_Init(vnet);
  clock_gettime(CLOCK_MONOTONIC, (&(timemeasure.end)));
  Time_Measure(&timemeasure);
  print_timemeasure(&timemeasure, 0, "Init");
  const int show_iteration = 5; // how many iterations to show
  for (int iter = 0; iter < ITERATIONS; iter++) {

    clock_gettime(CLOCK_MONOTONIC, (&(timemeasure.start)));
    VNET_KeyShare(vnet);
    clock_gettime(CLOCK_MONOTONIC, (&(timemeasure.end)));
    Time_Measure(&timemeasure);
    if (iter < show_iteration)
      print_timemeasure(&timemeasure, iter, "KeyShare");

    clock_gettime(CLOCK_MONOTONIC, (&(timemeasure.start)));
    VNET_Mask(vnet);
    clock_gettime(CLOCK_MONOTONIC, (&(timemeasure.end)));
    Time_Measure(&timemeasure);
    if (iter < show_iteration)
      print_timemeasure(&timemeasure, iter, "Mask");

    clock_gettime(CLOCK_MONOTONIC, (&(timemeasure.start)));
    VNET_UNMask(vnet);
    clock_gettime(CLOCK_MONOTONIC, (&(timemeasure.end)));
    Time_Measure(&timemeasure);
    if (iter < show_iteration)
      print_timemeasure(&timemeasure, iter, "UnMask");

    clock_gettime(CLOCK_MONOTONIC, (&(timemeasure.start)));
    VNET_Vrfy(vnet);
    clock_gettime(CLOCK_MONOTONIC, (&(timemeasure.end)));
    Time_Measure(&timemeasure);
    if (iter < show_iteration) {
      print_timemeasure(&timemeasure, iter, "Verify");
      printf("\n*************************************************************"
             "****"
             "**********************\n");
    }
    if (iter >= show_iteration)
      printf("\r[iter:%d]calculating the rest", iter);
    if ((iter >= show_iteration) && ((iter % 2) == 1)) {
      switch ((iter / 2) % 5) {
      case 0:
        printf(" #     ");
        fflush(stdout);
        break;
      case 1:
        printf(" ##    ");
        fflush(stdout);
        break;
      case 2:
        printf(" ###   ");
        fflush(stdout);
        break;
      case 3:
        printf(" ####  ");
        fflush(stdout);
        break;
      case 4:
        printf(" ##### ");
        fflush(stdout);
        break;
      }
    }

    if ((iter < (ITERATIONS - 1)) && iter < (show_iteration - 1))
      print_timemeasure_header();
  }
  printf("\r***Verification Successful for all users and iterations***\n");
  GroupGen_Free(&(vnet->grp));
  BGroup_Free(&(vnet->bgrp));
  for (int i = 0; i < USERS_SIZE; i++) {
    if (vnet->Uact1[i] == 0)
      continue;
    mpz_clears(vnet->Users[i].P_sk, vnet->Users[i].P_pk, vnet->Users[i].N_sk,
               vnet->Users[i].N_pk, NULL);
  }
  mpz_clears(vnet->delta_p[0], vnet->d, vnet->delta_p[1], NULL);


  //print time result
  // take the average
  time_measured.keyshare_client = time_measured.keyshare_client / (ITERATIONS*(vnet->Uact2Active));
  time_measured.keyshare_server = time_measured.keyshare_server / ITERATIONS;

  time_measured.mask_client.usual =
      time_measured.mask_client.usual / (ITERATIONS*(vnet->Uact3Active));
  time_measured.mask_client.overhead =
      time_measured.mask_client.overhead / (ITERATIONS*(vnet->Uact3Active));
  time_measured.mask_server = time_measured.mask_server / ITERATIONS;

  time_measured.unmask_client = time_measured.unmask_client / (ITERATIONS*(vnet->Uact4Active));
  time_measured.unmask_server.usual =
      time_measured.unmask_server.usual / (ITERATIONS*(vnet->Uact4Active));
  time_measured.unmask_server.overhead =
      time_measured.unmask_server.overhead / ITERATIONS;

  time_measured.verification_client =
      time_measured.verification_client / (ITERATIONS*(vnet->Uact4Active));
  time_measured.verification_server =
      time_measured.verification_server / ITERATIONS;

  double total_client = time_measured.keyshare_client+
      time_measured.mask_client.usual+time_measured.mask_client.overhead+time_measured.unmask_client
      +time_measured.verification_client;
  double total_server = time_measured.keyshare_server+time_measured.mask_server
      +time_measured.unmask_server.usual+time_measured.unmask_server.overhead+
      time_measured.verification_server;
  // print the result
  printf("\nDropout = %3.2f, n = %4d, gradient size: %4d, iterations: %4d, threshold: %4d\n",
         (float)DropOut, USERS_SIZE, GRAD_SIZE, ITERATIONS,Threshold);
  printf("\n");
  printf("================================ Time Result In Miliseconds ================== \n");
  printf("|              |            Client            |            Server            |\n");
  printf("------------------------------------------------------------------------------\n");
  printf("|   KeyShare   |  %26.2f  |  %26.2f  |\n", time_measured.keyshare_client,time_measured.keyshare_server);
  printf("------------------------------------------------------------------------------\n");
  printf("|     Mask     |  %12.2f+%-13.2f  |  %26.2f  |\n", time_measured.mask_client.usual,time_measured.mask_client.overhead,time_measured.mask_server);
  printf("------------------------------------------------------------------------------\n");
  printf("|    Unmask    |  %26.2f  |  %12.2f+%-13.2f  |\n", time_measured.unmask_client,time_measured.unmask_server.usual,time_measured.unmask_server.overhead);
  printf("------------------------------------------------------------------------------\n");
  printf("|    Verify    |  %26.2f  |  %26.2f  |\n", time_measured.verification_client,time_measured.verification_server);
  printf("------------------------------------------------------------------------------\n");
  printf("|    Total     |  %26.2f  |  %26.2f  |\n", total_client,total_server);
  printf("------------------------------------------------------------------------------\n");


  free(vnet);
  return 0;
}