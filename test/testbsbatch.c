/*

    This file is part of libdvbcsa.

    libdvbcsa is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published
    by the Free Software Foundation; either version 2 of the License,
    or (at your option) any later version.

    libdvbcsa is distributed in the hope that it will be useful, but
    WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with libdvbcsa; if not, see <https://www.gnu.org/licenses/>.

    Bitslice batch test: dvbcsa_bs_decrypt() and dvbcsa_bs_encrypt()
    must give the same result as the single packet functions for random
    control words, every batch size up to dvbcsa_bs_batch_size(), short
    packets, packets longer than maxlen and payloads at any alignment,
    and must not touch memory outside the payloads.

*/

#include <stdio.h>

#include <dvbcsa/dvbcsa.h>
#include "dvbcsa_pv.h"

#ifdef HAVE_ASSERT_H
#include <assert.h>
#endif

#define TS_SIZE		184	/* max payload of a TS packet */
#define SLOT_SIZE	256	/* per packet buffer, payload at a random offset */
#define GUARD		0x5a	/* fill value around each payload */

static unsigned int		gs;
static uint8_t			*slots, *refs;
static struct dvbcsa_bs_batch_s	*pcks;
static struct dvbcsa_key_s	*key;
static struct dvbcsa_bs_key_s	*bskey;
static unsigned int		n_tests, n_failed;

/* xorshift32: deterministic, so a failure can be reproduced */
static uint32_t
rnd (void)
{
  static uint32_t	x = 0x2545f491;

  x ^= x << 13;
  x ^= x >> 17;
  x ^= x << 5;
  return x;
}

static unsigned int
rnd_len (unsigned int max)
{
  switch (rnd() % 8)
    {
    case 0:
    case 1:
      return max;			/* full packets are the common case */
    case 2:
      return rnd() % (max < 16 ? max + 1 : 16);	/* no block, one block, residue */
    default:
      return rnd() % (max + 1);
    }
}

/* Process n packets with payloads of up to lenmax bytes in one bitslice
   call and compare with the single packet implementation, which is given
   the first maxlen bytes of each payload. */
static void
run_test (const char *what, unsigned int n, unsigned int maxlen,
	  unsigned int lenmax, int encrypt)
{
  dvbcsa_cw_t	cw;
  unsigned int	i;

  for (i = 0; i < sizeof(cw); i++)
    cw[i] = (unsigned char)rnd();

  dvbcsa_key_set(cw, key);
  dvbcsa_bs_key_set(cw, bskey);

  for (i = 0; i < n; i++)
    {
      uint8_t		*slot = slots + i * SLOT_SIZE;
      uint8_t		*ref = refs + i * SLOT_SIZE;
      unsigned int	len = rnd_len(lenmax);
      unsigned int	off = rnd() % (SLOT_SIZE - len + 1);
      unsigned int	j;

      memset(slot, GUARD, SLOT_SIZE);
      for (j = 0; j < len; j++)
	slot[off + j] = (uint8_t)rnd();
      memcpy(ref, slot, SLOT_SIZE);

      if (encrypt)
	dvbcsa_encrypt(key, ref + off, len < maxlen ? len : maxlen);
      else
	dvbcsa_decrypt(key, ref + off, len < maxlen ? len : maxlen);

      pcks[i].data = slot + off;
      pcks[i].len = len;
    }

  pcks[n].data = NULL;

  if (encrypt)
    dvbcsa_bs_encrypt(bskey, pcks, maxlen);
  else
    dvbcsa_bs_decrypt(bskey, pcks, maxlen);

  n_tests++;

  for (i = 0; i < n; i++)
    if (memcmp(slots + i * SLOT_SIZE, refs + i * SLOT_SIZE, SLOT_SIZE) != 0)
      {
	printf(" - %s: %s of %u packets, maxlen %u: packet %u (len %u) differs\n",
	       what, encrypt ? "encryption" : "decryption", n, maxlen,
	       i, pcks[i].len);
	n_failed++;
	return;
      }
}

static void
run_both (const char *what, unsigned int n, unsigned int maxlen,
	  unsigned int lenmax)
{
  run_test(what, n, maxlen, lenmax, 0);
  run_test(what, n, maxlen, lenmax, 1);
}

int
main (void)
{
  unsigned int	i;

  gs = dvbcsa_bs_batch_size();

  key = dvbcsa_key_alloc();
  bskey = dvbcsa_bs_key_alloc();
  slots = malloc(gs * SLOT_SIZE);
  refs = malloc(gs * SLOT_SIZE);
  pcks = malloc((gs + 1) * sizeof(*pcks));

#ifdef HAVE_ASSERT_H
  assert(gs > 0 && key && bskey && slots && refs && pcks);
#endif

  printf("* DVBCSA bitslice batch test, batch size %u *\n", gs);

  /* every batch size, which puts a packet in every lane */
  for (i = 0; i <= gs; i++)
    run_both("batch size", i, TS_SIZE, TS_SIZE);

  /* shorter maxlen, and payloads longer than maxlen */
  for (i = 0; i <= TS_SIZE; i += 8)
    {
      run_both("maxlen", 1 + rnd() % gs, i, i);
      run_both("len > maxlen", 1 + rnd() % gs, i, TS_SIZE);
    }

  /* payloads longer than DVBCSA_BS_MAX_PACKET_LEN */
  run_both("len > 184", 1 + rnd() % gs, TS_SIZE, SLOT_SIZE - 16);

  for (i = 0; i < 200; i++)
    run_both("random", rnd() % (gs + 1), 8 * (rnd() % (TS_SIZE / 8 + 1)), TS_SIZE);

  free(pcks);
  free(refs);
  free(slots);
  dvbcsa_bs_key_free(bskey);
  dvbcsa_key_free(key);

  if (n_failed)
    printf("%u out of %u tests FAILED.\n", n_failed, n_tests);
  else
    printf("OK! All %u tests passed.\n", n_tests);

  return n_failed != 0;
}
