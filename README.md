## Description

This proof-of-concept demonstration exploits the observation that compiling the
[Kyber reference implementation](https://github.com/pq-crystals/kyber/tree/b628ba78711bc28327dc7d2d5c074a00f061884e)
with Clang may result in the emission of a secret-dependent branch.

Despite the source-level constant-time implementation of `poly_frommsg`, Clang
has been observed to produce [insecure assembly](https://godbolt.org/#z:OYLghAFBqRAWIDGB7AJgUwKKoJYBdkAnAGhxAgDMcAbdAOwEMBbdEAcgEY3iLk68Ayoga0QHACw8%2BeAKoBndAAUAHuwAM3AFZji1BnVAB9Y4mILaiPDj7l6qAMLJqAVyZ0QAJmJ2AMjjroAHKuAEbohJ4cxAAOyHL41nSOLm6eMXEJfH4BwUxhER5R5uiWiQJ4DIR4ya7uXsWlfOWVeNlBoeGRZhVVNan1Pa3%2B7XmdhQCUZsjOhIisbACkHgDM/oguGADUC8v2cni4/AB0cDuYC2oAghfXKxhUAZsA0gCaAEKYAEqGgZseAKwANhuS2W92Gz3eX0MAEVNstlh4AJwgq54ACe0XQ902%2B0IzksCwA7G8bptNv48BxAYY8JsUOgKBQ5At/m9Xh9voFWQARHakq7EnmbWLUdH81GXABuyBwqBFTnRhgohGQTCYcmAEFF6M2ACoSPS%2BPtNs5KQAOWmbDXAVlvRG88Ygklk010eLAALyykU4iaCVXcmU6lWpgMOQAawD10Dm14hAgOB2PLU/KTuw50MCAHpzWmlqSPG9xtsXbHyfGIP7lin%2BdX7Hnlm9/UWCyXiQLLuTu9bwxHtjXNgBaRP8EN4cZQG12pP/YVnM6bTROjyAjhOpuunuEIdnBlMlls816pNF/1zgfCsOR7arzZQTPfGEF9fZjwbzs9oWu7%2BCok8thJmodh/m4dxOG4ZB2HsXFplmdBb2WLhiDwdRAOIeAkDVaIaHCUhyBQJgcNoCJEHWfRgFpfE6AjHgaDwcI5HIEI0OIEJ/EqdF2GQ9jGEIdEAHkQk0EpUIg4hCJYfgBLoMVWIwEJnGAewRGoJjxIwMMDFENgNGIXBCFEnApXQdS9PQZQSmcBjuO4Sl0GA3TuGoHAQkITjHAwVi8EIHAmFs4gTMIEI4nQHl0C04AXIMNDJgoPRgDkAA1HB0AAdwErFwOQ3h%2BCEERWAkKR%2BHkJRVCcv0dD0GLjEMUwXJCJjIEmZBoisY12CHAS5EgoLfIwJqIEmaJ9CCZh5k2ZRzUBIdAXEelquAe8fOcGiSy6nqzAcoybAgOw%2BncKJfGGXJ8h0WJ4napInFqc6MiutpTs6IptsaOhml6G7Uheiwro%2BoYcg6CIikGA6dH2FpHqBsRJjkOC5hh3QQLA1ioLYSbptm%2BbyIMZbqIjdbuu4MSNEmTDCOIvCyAgCncNInHKJWmi6OoBjCCYiAWIq3jOICnn%2BKEkTLACyT6DwGS5IqhSlJU6g1ICzSKJ0vSDKMkyzO4CyrJs8T7McvSGvc/jPPmPSfL8gKgpChRwsi6LQCcuKEuS1KMqygLcsEYRRCKz3SpUVjtGWXQKJAWr6tcwaWraxJ1K65DkD6uVTPAIaYlGwJxvYDGZrmhaKLx1aCc2ATkIaK7bDoBwvsO7wq6h0ZgfSS7EjBqILsyOgG7On6dve0Ga/B16/sGbvnu6Fo24nqox%2BB2H4cKoDkeIcC9LRnOsfz3GICZ4vS%2BJ2KMIQWmSPwmnsLppAGaoouWbZjmub0/muPE5/BdEkW1Sk8XZJflX0EUspVS6lkKK20qbbgqtSjq1YlrRA1l5jIT1qxQ2Hk0AQJQr5fy4krahVtkrfwDtSY8GdildKmV6Ae2kPlH2kg/YKADhVbQRIQ41RMLoSOqdo5XTjgJDww4KB0GQEOEylgiA4AAF7oF6uEfqKdmrpxyFndGU1c7Y0WoXNaJd%2BFCJEaJcRUjuDl0SJXauKRa7HUBo3O6Lc%2BBTw7g9E60Ne5vX%2BlPYxTRR5OOsSDSeg9fEz28T3eeMwEbriRmwUCK9UbZ1UZvBmmi946OEaIggvlDEoUPuTC%2Bp9qYn06GRRaN9mZUFZoxZirFn58w4gLYSH9xKi2kr/eSACZbAIVhFJWGCoFWBgRVOBCCArIIqqg426DvJYMtuEa2YVOnaUIYfeKDBEpkLdpQ8SnsaGFTodIf25U9LaEBKwow7CGpR2IK1HhnUBLLAEbo1JBjpEXKTgNLhiixosFiZjPOCSd74xLDczY9z9HpKeR49we0q5T0sSMHuzdO72PuokWeQ9fplAHuY1Ffd/oooCdUfx08AawueiE%2BCiNHJRNXpBL5ait5LT%2BUXAFtzgViNBQfR2kwIxiDUGoCJ4gUYVTRkYkAvKSaAUmEFeINhxBAA) for at least the following configurations:
- ISA: x86
- Clang versions: v15-18
- Clang options:
    - `-Os`
    - `-O1`
    - `-O2 -fno-vectorize`
    - `-O3 -fno-vectorize`

On an Intel Core i7-13700H (Clang 16.0.6), it takes between 5-10 minutes to leak
the entire ML-KEM 512 secret key using end-to-end decapsulation timing
measurements.

The attack strategy is a plaintext-checking oracle attack a la
[Ravi et al.](https://eprint.iacr.org/2019/948)
and [Ueno et al.](https://eprint.iacr.org/2021/849)

## Running the PoC

```
# Pull pqcrystals/kyber standard branch (though attack also affects main branch)
git submodule init && git submodule update

# Modify compiler options and produce shared library
sed -i 's/-O3/-Os/g' kyber/ref/Makefile
CC=clang make -C kyber/ref shared

# Build the key recovery PoC
make

# Run the key recovery PoC
./clangover
```

## Remarks

If the PoC doesn't produce the correct key guesses on your machine, here is some
guidance:

1. Check that you are running on x86 
2. Check that you are using `clang` version 15 or later 
(latest is 18.1 at time of writing)
3. This PoC contains some parameters in `attack.c`. Consider tweaking them for
your machine. Of special interest are:
    - `CONFIDENCE_HIGH`: the higher, the more robust
    - `EVALUATE_EVERY_N_ITERATIONS`: the higher, the more robust
    - `OUTLIER_THRESHOLD`: can go either way
