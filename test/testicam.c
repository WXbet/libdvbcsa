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

    iCAM test for dvbcsa_bs_key_set_ecm(). The expected clear payloads
    were computed with FFdecsa as shipped with vdr-plugin-dvbapi, an
    independent implementation of the ecm mode 4 key schedule.

*/

#include <stdio.h>

#include <dvbcsa/dvbcsa.h>
#include "dvbcsa_pv.h"

#ifdef HAVE_ASSERT_H
#include <assert.h>
#endif

#define TS_SIZE		184

static const dvbcsa_cw_t	icam_cw = {0x07, 0xe0, 0x1b, 0x02, 0xc9, 0xe0, 0x45, 0xee};

/* scrambled payload byte i is i * 7 + 3 + test number, see scrambled() */
static const struct
{
  unsigned int	len;
  uint8_t	clear[TS_SIZE];
} icam_tests[2] =
  {
    { 184,
      {
	0xf4, 0x7a, 0x21, 0xbe, 0x2f, 0xc3, 0xea, 0x4f, 0xb1, 0xa5, 0xf6, 0x90,
	0x81, 0xdb, 0xce, 0x34, 0x12, 0xac, 0x1a, 0xbe, 0x6e, 0x51, 0xd3, 0x79,
	0xa6, 0xad, 0x9c, 0xf6, 0x8f, 0x1a, 0x02, 0xad, 0x4a, 0x6a, 0x1b, 0x2f,
	0xa9, 0xfc, 0x9e, 0xa0, 0xc1, 0xd5, 0x51, 0xb0, 0xc1, 0xc3, 0x83, 0xa5,
	0x56, 0xd8, 0x9d, 0xb2, 0x97, 0x4c, 0x63, 0x02, 0xa5, 0xeb, 0x88, 0x6c,
	0x24, 0x84, 0x98, 0xc3, 0xbd, 0xd3, 0x16, 0xff, 0x29, 0x84, 0xdc, 0xfd,
	0xc8, 0x11, 0xc1, 0xdd, 0x27, 0xc4, 0x48, 0xec, 0xa7, 0x17, 0x68, 0xd9,
	0xbc, 0x0c, 0xcd, 0xbc, 0xee, 0xff, 0x35, 0x2b, 0xe6, 0x67, 0x19, 0x7e,
	0x15, 0x0a, 0xf4, 0x62, 0x0e, 0xff, 0xc7, 0xb8, 0x5f, 0xbc, 0x64, 0x94,
	0xd0, 0xc5, 0x10, 0x61, 0xc5, 0x86, 0x5a, 0xd4, 0xaa, 0x64, 0x38, 0xf2,
	0xd0, 0x93, 0xd9, 0x46, 0xdb, 0xaa, 0x93, 0xc5, 0x12, 0xa9, 0xa6, 0x2c,
	0x02, 0x84, 0xd1, 0xbf, 0xd2, 0xb5, 0x61, 0x8d, 0xe4, 0x7b, 0xc4, 0xd0,
	0x66, 0x2c, 0xf9, 0xc6, 0x81, 0x5e, 0x60, 0xc9, 0x27, 0x07, 0xef, 0x75,
	0xbc, 0x7e, 0xec, 0x50, 0x4c, 0x40, 0x45, 0xcd, 0xe7, 0xaa, 0x20, 0xef,
	0x28, 0x39, 0x14, 0xfe, 0xe1, 0xd5, 0x0d, 0x28, 0x64, 0x16, 0xfc, 0xc4,
	0x9a, 0xc1, 0x92, 0x65,
      }
    },
    { 61,				/* 7 blocks and a 5 byte residue */
      {
	0x8c, 0xbe, 0x78, 0xe3, 0x3a, 0x3d, 0x0a, 0xf9, 0x49, 0x48, 0x26, 0xbb,
	0x1f, 0x31, 0x72, 0x05, 0x07, 0xf6, 0xd7, 0x29, 0x72, 0xe4, 0xcb, 0x33,
	0xff, 0xc8, 0xff, 0xda, 0xcd, 0x60, 0xc8, 0xa1, 0x62, 0xa7, 0xef, 0x26,
	0xe9, 0xbf, 0x2b, 0x41, 0x48, 0xdd, 0xc9, 0x99, 0xed, 0xdb, 0xdb, 0x8e,
	0x6d, 0x73, 0xbd, 0x6e, 0xdd, 0xfe, 0x65, 0x37, 0x05, 0xb6, 0x3a, 0xcb,
	0x88,
      }
    },
  };

static void
scrambled (unsigned int t, uint8_t *data)
{
  unsigned int	i;

  for (i = 0; i < icam_tests[t].len; i++)
    data[i] = (uint8_t)(i * 7 + 3 + t);
}

int
main (void)
{
  struct dvbcsa_bs_key_s	*key = dvbcsa_bs_key_alloc();
  struct dvbcsa_bs_key_s	*plain = dvbcsa_bs_key_alloc();
  unsigned int			gs = dvbcsa_bs_batch_size();
  struct dvbcsa_bs_batch_s	*pcks = malloc((gs + 1) * sizeof(*pcks));
  uint8_t			*data = malloc(gs * TS_SIZE);
  uint8_t			*ref = malloc(gs * TS_SIZE);
  unsigned int			t, i, pos, ecm, failed = 0;

#ifdef HAVE_ASSERT_H
  assert(key && plain && pcks && data && ref);
#endif

  puts("* iCAM ecm key schedule *");

  dvbcsa_bs_key_set_ecm(4, icam_cw, key);

  /* known answers, in every lane of a batch of random packets */
  for (t = 0; t < sizeof(icam_tests) / sizeof(icam_tests[0]); t++)
    {
      printf(" test %u, %u bytes\n", t + 1, icam_tests[t].len);

      for (pos = 0; pos < gs; pos++)
	{
	  for (i = 0; i < gs; i++)
	    {
	      unsigned int	j;

	      pcks[i].data = data + i * TS_SIZE;
	      pcks[i].len = TS_SIZE;
	      for (j = 0; j < TS_SIZE; j++)
		pcks[i].data[j] = (unsigned char)rand();
	    }

	  scrambled(t, pcks[pos].data);
	  pcks[pos].len = icam_tests[t].len;
	  pcks[pos + 1].data = NULL;		/* batch of pos + 1 packets */

	  dvbcsa_bs_decrypt(key, pcks, TS_SIZE);

	  if (memcmp(pcks[pos].data, icam_tests[t].clear, icam_tests[t].len) != 0)
	    {
	      printf(" - failed in lane %u\n", pos);
	      failed++;
	      break;
	    }
	}
    }

  /* every other ecm value selects the regular key schedule */
  puts(" ecm != 4");

  for (ecm = 0; ecm < 256; ecm++)
    {
      dvbcsa_cw_t	cw;

      for (i = 0; i < sizeof(cw); i++)
	cw[i] = (unsigned char)rand();
      cw[0] = 0x07;			/* not a fixed point of the permutation */

      dvbcsa_bs_key_set(cw, plain);
      dvbcsa_bs_key_set_ecm((unsigned char)ecm, cw, key);

      for (i = 0; i < gs; i++)
	{
	  unsigned int	j;

	  pcks[i].data = data + i * TS_SIZE;
	  pcks[i].len = TS_SIZE;
	  for (j = 0; j < TS_SIZE; j++)
	    pcks[i].data[j] = (unsigned char)rand();
	}
      pcks[gs].data = NULL;
      memcpy(ref, data, gs * TS_SIZE);

      dvbcsa_bs_decrypt(key, pcks, TS_SIZE);
      for (i = 0; i < gs; i++)
	pcks[i].data = ref + i * TS_SIZE;
      dvbcsa_bs_decrypt(plain, pcks, TS_SIZE);

      /* ecm 4 must change the result, all others must not */
      if ((memcmp(data, ref, gs * TS_SIZE) == 0) != (ecm != 4))
	{
	  printf(" - ecm %u: unexpected result\n", ecm);
	  failed++;
	}
    }

  /* bs_encrypt with an iCAM key is the inverse of bs_decrypt */
  puts(" round trip");

  dvbcsa_bs_key_set_ecm(4, icam_cw, key);

  for (i = 0; i < gs; i++)
    {
      unsigned int	j;

      pcks[i].data = data + i * TS_SIZE;
      pcks[i].len = (unsigned int)rand() % (TS_SIZE + 1);
      for (j = 0; j < TS_SIZE; j++)
	pcks[i].data[j] = (unsigned char)rand();
    }
  pcks[gs].data = NULL;
  memcpy(ref, data, gs * TS_SIZE);

  dvbcsa_bs_encrypt(key, pcks, TS_SIZE);
  dvbcsa_bs_decrypt(key, pcks, TS_SIZE);

  if (memcmp(data, ref, gs * TS_SIZE) != 0)
    {
      puts(" - failed");
      failed++;
    }

  free(ref);
  free(data);
  free(pcks);
  dvbcsa_bs_key_free(plain);
  dvbcsa_bs_key_free(key);

  puts(failed ? "* FAILED *" : "* Done *");

  return failed != 0;
}
