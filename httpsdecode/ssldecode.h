#ifndef SSLDECODE_H
#define SSLDECODE_H

#include <glib.h>
#include <gnutls/x509.h>
#include <gnutls/pkcs12.h>



/* RFC 5246, section 8.1 says that the master secret is always 48 bytes */
#define SSL_MASTER_SECRET_LENGTH        48

/* XXX Should we use GByteArray instead? */
typedef struct _StringInfo {
    guchar  *data;      /* Backing storage which may be larger than data_len */
    guint    data_len;  /* Length of the meaningful part of data */
} StringInfo;

#define SSLV3_VERSION          0x300
#define TLSV1_VERSION          0x301
#define TLSV1DOT1_VERSION      0x302
#define TLSV1DOT2_VERSION      0x303
#define TLSV1DOT3_VERSION      0x304
#define DTLSV1DOT0_VERSION     0xfeff
#define DTLSV1DOT0_OPENSSL_VERSION 0x100
#define DTLSV1DOT2_VERSION     0xfefd

typedef enum {
    SSL_HND_HELLO_REQUEST          = 0,
    SSL_HND_CLIENT_HELLO           = 1,
    SSL_HND_SERVER_HELLO           = 2,
    SSL_HND_HELLO_VERIFY_REQUEST   = 3,
    SSL_HND_NEWSESSION_TICKET      = 4,
    SSL_HND_END_OF_EARLY_DATA      = 5,
    SSL_HND_HELLO_RETRY_REQUEST    = 6,
    SSL_HND_ENCRYPTED_EXTENSIONS   = 8,
    SSL_HND_CERTIFICATE            = 11,
    SSL_HND_SERVER_KEY_EXCHG       = 12,
    SSL_HND_CERT_REQUEST           = 13,
    SSL_HND_SVR_HELLO_DONE         = 14,
    SSL_HND_CERT_VERIFY            = 15,
    SSL_HND_CLIENT_KEY_EXCHG       = 16,
    SSL_HND_FINISHED               = 20,
    SSL_HND_CERT_URL               = 21,
    SSL_HND_CERT_STATUS            = 22,
    SSL_HND_SUPPLEMENTAL_DATA      = 23,
    SSL_HND_KEY_UPDATE             = 24,
    /* Encrypted Extensions was NextProtocol in draft-agl-tls-nextprotoneg-03
     * and changed in draft 04. Not to be confused with TLS 1.3 EE. */
    SSL_HND_ENCRYPTED_EXTS         = 67
} HandshakeType;

#define SSL_CLIENT_RANDOM       (1<<0)
#define SSL_SERVER_RANDOM       (1<<1)
#define SSL_CIPHER              (1<<2)
#define SSL_HAVE_SESSION_KEY    (1<<3)
#define SSL_VERSION             (1<<4)
#define SSL_MASTER_SECRET       (1<<5)
#define SSL_PRE_MASTER_SECRET   (1<<6)
#define SSL_CLIENT_EXTENDED_MASTER_SECRET (1<<7)
#define SSL_SERVER_EXTENDED_MASTER_SECRET (1<<8)
#define SSL_NEW_SESSION_TICKET  (1<<10)
#define SSL_ENCRYPT_THEN_MAC    (1<<11)

#define SSL_EXTENDED_MASTER_SECRET_MASK (SSL_CLIENT_EXTENDED_MASTER_SECRET|SSL_SERVER_EXTENDED_MASTER_SECRET)

/* TODO inline this now that Libgcrypt is mandatory? */
#define SSL_CIPHER_CTX gcry_cipher_hd_t
#define SSL_DECRYPT_DEBUG

/* SSL Cipher Suite modes */
typedef enum {
    MODE_STREAM,    /* GenericStreamCipher */
    MODE_CBC,       /* GenericBlockCipher */
    MODE_GCM,       /* GenericAEADCipher */
    MODE_CCM,       /* AEAD_AES_{128,256}_CCM with 16 byte auth tag */
    MODE_CCM_8,     /* AEAD_AES_{128,256}_CCM with 8 byte auth tag */
    MODE_POLY1305,  /* AEAD_CHACHA20_POLY1305 with 16 byte auth tag (RFC 7905) */
} ssl_cipher_mode_t;

typedef struct _SslCipherSuite {
    gint number;
    gint kex;
    gint enc;
    gint dig;
    ssl_cipher_mode_t mode;
} SslCipherSuite;

/*
typedef struct _SslFlow {
    guint32 byte_seq;
    guint16 flags;
    wmem_tree_t *multisegment_pdus;
} SslFlow;*/

typedef struct _SslDecompress SslDecompress;


typedef struct _SslDecoder {
    const SslCipherSuite *cipher_suite;
    gint compression;
    guchar _mac_key_or_write_iv[48];
    StringInfo mac_key; /* for block and stream ciphers */
    StringInfo write_iv; /* for AEAD ciphers (at least GCM, CCM) */
    SSL_CIPHER_CTX evp;
    SslDecompress *decomp;
    guint64 seq;    /**< Implicit (TLS) or explicit (DTLS) record sequence number. */
    guint16 epoch;
   // SslFlow *flow;
    StringInfo app_traffic_secret;  /**< TLS 1.3 application traffic secret (if applicable), wmem file scope. */
} SslDecoder;

typedef struct {
    const gchar *name;
    guint len;
} SslDigestAlgo;


gcry_sexp_t private_key;

void init_decode();
void load_server_rsa_pri_keyfile();
gboolean
ssl_generate_master_secret(unsigned char *pre_master_secret,unsigned char *client_random,unsigned char *server_random,unsigned char *out);
void ssl_get_pre_master_secret_key(unsigned char *encrypted_data,int len);
const SslCipherSuite *ssl_find_cipher(int num);
void wmk_decrypt_everything(SslCipherSuite *cipher_suite,unsigned char *master,unsigned char *client_random,unsigned char *server_random);
gint wmk_decrypt(guchar * out, gint outl,  guchar * in, gint inl);




#endif
