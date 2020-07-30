#include <stdio.h>
#include <stdint.h>
#include <openssl/x509.h>
#include <openssl/objects.h>
#include <string.h>
#include <unistd.h>
#include "efivars.h"


char buf[1048576];

//#define offsetof(st, m)  ((size_t)&(((st *)0)->m))

EFI_GUID x509_guid = EFI_CERT_X509_GUID;
EFI_GUID sha256_guid = EFI_CERT_SHA256_GUID;

int x509_dump (const char *prefix, void *cert, size_t l)
{
  BIO *bio = BIO_new_mem_buf (cert, l);
  X509 *x509;
  char *p;
  unsigned len;

  if (!bio) return -1;

  x509 = d2i_X509_bio (bio, NULL);
  BIO_free (bio);

  if (!x509)
    return -1;

  p = X509_NAME_oneline (X509_get_subject_name (x509), NULL, 0);
  printf ("%s subject: %s\n", prefix, p);
  OPENSSL_free (p);

  p = X509_NAME_oneline (X509_get_issuer_name (x509), NULL, 0);
  printf ("%s issuer: %s\n", prefix, p);
  OPENSSL_free (p);

  bio = BIO_new (BIO_s_mem());

  if (!bio) return -1;

  printf ("%s expires: ", prefix);

  ASN1_TIME_print (bio, X509_get_notAfter (x509));
  len = BIO_get_mem_data (bio, &p);
  fwrite (p, len, 1, stdout);
  BIO_free (bio);
  printf ("\n");

  X509_free (x509);
  return 0;
}


void
hexdump (const char *p, const void *_buf, uint64_t os, uint64_t oe)
{
  const uint8_t *d = (const uint8_t *) _buf;

  uint64_t s, e;
  uint64_t i, j, k;

  s = os & ~15;
  e = (oe - 1) | 15;
  e++;

  for (i = s; i < e; i += 16) {
    printf ("%s%016llx:", p, (long long unsigned) i);

    for (j = 0; j < 16; ++j) {
      k = i + j;

      if ((k < os) || (k >= oe))
        printf ("   ");
      else
        printf (" %02x", d[k]);

      if (j == 7)
        printf (" ");
    }

    printf (" ");

    for (j = 0; j < 16; ++j) {
      k = i + j;

      if ((k < os) || (k >= oe))
        printf (" ");
      else if ((d[k] > 0x20) && (d[k] < 0x7f))
        printf ("%c", d[k]);
      else
        printf (".");

      if (j == 7)
        printf (" ");
    }

    printf ("\n");
  }
}



int main (int argc, char *argv[])
{
  EFI_VARIABLE_AUTHENTICATION_2 *a;
  size_t l, ls;
  EFI_SIGNATURE_LIST *s;
  EFI_SIGNATURE_DATA *d;
  uint8_t *p;


  a = (EFI_VARIABLE_AUTHENTICATION_2 *) buf;

  read (0, a, sizeof (*a));

  l = a->AuthInfo.Hdr.dwLength + offsetof (EFI_VARIABLE_AUTHENTICATION_2, AuthInfo.Hdr.dwLength);

  read (0, a + 1, l - sizeof (*a));

  p = (void *) (char *) &a->AuthInfo.CertData;
  l -= offsetof (EFI_VARIABLE_AUTHENTICATION_2, AuthInfo.CertData);

  hexdump ("Authority> ", p, 0, l > 16 ? 16 : l);
  printf ("Authority> ...\n");
  x509_dump ("Authority> ", p, l);


  s = (EFI_SIGNATURE_LIST *) buf;

  while (read (0, s, sizeof (*s)) == sizeof (*s)) {

    l = s->SignatureListSize;
    l -= sizeof (*s);

    if (read (0, s + 1, l) != l)
      printf ("Short read\n");

    p = (void *) (char *) (s + 1);

    printf ("Signature:\n");

    if (s->SignatureHeaderSize) {
      hexdump ("  Header> ", p, 0, s->SignatureHeaderSize);
      p += s->SignatureHeaderSize;
    }

    d = (void *) (char *) p;

    printf ("  Owner> %08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x\n",
            d->SignatureOwner.Data1,
            d->SignatureOwner.Data2,
            d->SignatureOwner.Data3,
            d->SignatureOwner.Data4[0],
            d->SignatureOwner.Data4[1],
            d->SignatureOwner.Data4[2],
            d->SignatureOwner.Data4[3],
            d->SignatureOwner.Data4[4],
            d->SignatureOwner.Data4[5],
            d->SignatureOwner.Data4[6],
            d->SignatureOwner.Data4[7]);

    ls = s->SignatureListSize;
    ls -= sizeof (EFI_SIGNATURE_LIST);




    while (ls) {
      p += offsetof (EFI_SIGNATURE_DATA, SignatureData);
      l = s->SignatureSize - offsetof (EFI_SIGNATURE_DATA, SignatureData);
      ls -= s->SignatureSize;



      if (!memcmp (&s->SignatureType, &x509_guid, sizeof (EFI_GUID))) {
        printf ("  Type> x509\n");
        x509_dump ("  x509> ", p, l);

      } else if (!memcmp (&s->SignatureType, &sha256_guid, sizeof (EFI_GUID))) {
        printf ("  Type> sha256\n");

        printf ("  Hash> ");

        while (l--)
          printf ("%02x", * (p++));

        printf ("\n");
      }

    }


  }

  return 0;
}





