// #include <stdio.h>
// #include <sys/time.h>












typedef struct ssl_session_st SSL_SESSION;



typedef long int ptrdiff_t;

typedef long unsigned int size_t;

typedef int wchar_t;


struct aes_key_st {



    unsigned int rd_key[4 *(14 + 1)];

    int rounds;
};
typedef struct aes_key_st AES_KEY;

const char *AES_options(void);

int AES_set_encrypt_key(const unsigned char *userKey, const int bits,
 AES_KEY *key);
int AES_set_decrypt_key(const unsigned char *userKey, const int bits,
 AES_KEY *key);

int private_AES_set_encrypt_key(const unsigned char *userKey, const int bits,
 AES_KEY *key);
int private_AES_set_decrypt_key(const unsigned char *userKey, const int bits,
 AES_KEY *key);

void AES_encrypt(const unsigned char *in, unsigned char *out,
 const AES_KEY *key);
void AES_decrypt(const unsigned char *in, unsigned char *out,
 const AES_KEY *key);

void AES_ecb_encrypt(const unsigned char *in, unsigned char *out,
 const AES_KEY *key, const int enc);
void AES_cbc_encrypt(const unsigned char *in, unsigned char *out,
 size_t length, const AES_KEY *key,
 unsigned char *ivec, const int enc);
void AES_cfb128_encrypt(const unsigned char *in, unsigned char *out,
 size_t length, const AES_KEY *key,
 unsigned char *ivec, int *num, const int enc);
void AES_cfb1_encrypt(const unsigned char *in, unsigned char *out,
 size_t length, const AES_KEY *key,
 unsigned char *ivec, int *num, const int enc);
void AES_cfb8_encrypt(const unsigned char *in, unsigned char *out,
 size_t length, const AES_KEY *key,
 unsigned char *ivec, int *num, const int enc);
void AES_ofb128_encrypt(const unsigned char *in, unsigned char *out,
 size_t length, const AES_KEY *key,
 unsigned char *ivec, int *num);
void AES_ctr128_encrypt(const unsigned char *in, unsigned char *out,
 size_t length, const AES_KEY *key,
 unsigned char ivec[16],
 unsigned char ecount_buf[16],
 unsigned int *num);

void AES_ige_encrypt(const unsigned char *in, unsigned char *out,
       size_t length, const AES_KEY *key,
       unsigned char *ivec, const int enc);

void AES_bi_ige_encrypt(const unsigned char *in, unsigned char *out,
   size_t length, const AES_KEY *key,
   const AES_KEY *key2, const unsigned char *ivec,
   const int enc);

int AES_wrap_key(AES_KEY *key, const unsigned char *iv,
  unsigned char *out,
  const unsigned char *in, unsigned int inlen);
int AES_unwrap_key(AES_KEY *key, const unsigned char *iv,
  unsigned char *out,
  const unsigned char *in, unsigned int inlen);










































typedef unsigned char __u_char;
typedef unsigned short int __u_short;
typedef unsigned int __u_int;
typedef unsigned long int __u_long;


typedef signed char __int8_t;
typedef unsigned char __uint8_t;
typedef signed short int __int16_t;
typedef unsigned short int __uint16_t;
typedef signed int __int32_t;
typedef unsigned int __uint32_t;

typedef signed long int __int64_t;
typedef unsigned long int __uint64_t;







typedef long int __quad_t;
typedef unsigned long int __u_quad_t;





typedef unsigned long int __dev_t;
typedef unsigned int __uid_t;
typedef unsigned int __gid_t;
typedef unsigned long int __ino_t;
typedef unsigned long int __ino64_t;
typedef unsigned int __mode_t;
typedef unsigned long int __nlink_t;
typedef long int __off_t;
typedef long int __off64_t;
typedef int __pid_t;
typedef struct { int __val[2]; } __fsid_t;
typedef long int __clock_t;
typedef unsigned long int __rlim_t;
typedef unsigned long int __rlim64_t;
typedef unsigned int __id_t;
typedef long int __time_t;
typedef unsigned int __useconds_t;
typedef long int __suseconds_t;

typedef int __daddr_t;
typedef int __key_t;


typedef int __clockid_t;


typedef void * __timer_t;


typedef long int __blksize_t;




typedef long int __blkcnt_t;
typedef long int __blkcnt64_t;


typedef unsigned long int __fsblkcnt_t;
typedef unsigned long int __fsblkcnt64_t;


typedef unsigned long int __fsfilcnt_t;
typedef unsigned long int __fsfilcnt64_t;


typedef long int __fsword_t;

typedef long int __ssize_t;


typedef long int __syscall_slong_t;

typedef unsigned long int __syscall_ulong_t;



typedef __off64_t __loff_t;
typedef __quad_t *__qaddr_t;
typedef char *__caddr_t;


typedef long int __intptr_t;


typedef unsigned int __socklen_t;




typedef __clock_t clock_t;






typedef __time_t time_t;




typedef __clockid_t clockid_t;

typedef __timer_t timer_t;

struct timespec
  {
    __time_t tv_sec;
    __syscall_slong_t tv_nsec;
  };








struct tm
{
  int tm_sec;
  int tm_min;
  int tm_hour;
  int tm_mday;
  int tm_mon;
  int tm_year;
  int tm_wday;
  int tm_yday;
  int tm_isdst;


  long int tm_gmtoff;
  const char *tm_zone;




};








struct itimerspec
  {
    struct timespec it_interval;
    struct timespec it_value;
  };


struct sigevent;





typedef __pid_t pid_t;




extern clock_t clock (void) ;


extern time_t time (time_t *__timer) ;


extern double difftime (time_t __time1, time_t __time0)
      ;


extern time_t mktime (struct tm *__tp) ;





extern size_t strftime (char *__restrict __s, size_t __maxsize,
   const char *__restrict __format,
   const struct tm *__restrict __tp) ;




typedef struct __locale_struct
{

  struct __locale_data *__locales[13];


  const unsigned short int *__ctype_b;
  const int *__ctype_tolower;
  const int *__ctype_toupper;


  const char *__names[13];
} *__locale_t;


typedef __locale_t locale_t;


extern size_t strftime_l (char *__restrict __s, size_t __maxsize,
     const char *__restrict __format,
     const struct tm *__restrict __tp,
     __locale_t __loc) ;




extern struct tm *gmtime (const time_t *__timer) ;



extern struct tm *localtime (const time_t *__timer) ;





extern struct tm *gmtime_r (const time_t *__restrict __timer,
       struct tm *__restrict __tp) ;



extern struct tm *localtime_r (const time_t *__restrict __timer,
          struct tm *__restrict __tp) ;





extern char *asctime (const struct tm *__tp) ;


extern char *ctime (const time_t *__timer) ;







extern char *asctime_r (const struct tm *__restrict __tp,
   char *__restrict __buf) ;


extern char *ctime_r (const time_t *__restrict __timer,
        char *__restrict __buf) ;




extern char *__tzname[2];
extern int __daylight;
extern long int __timezone;




extern char *tzname[2];



extern void tzset (void) ;



extern int daylight;
extern long int timezone;





extern int stime (const time_t *__when) ;

extern time_t timegm (struct tm *__tp) ;


extern time_t timelocal (struct tm *__tp) ;


extern int dysize (int __year)  ;

extern int nanosleep (const struct timespec *__requested_time,
        struct timespec *__remaining);



extern int clock_getres (clockid_t __clock_id, struct timespec *__res) ;


extern int clock_gettime (clockid_t __clock_id, struct timespec *__tp) ;


extern int clock_settime (clockid_t __clock_id, const struct timespec *__tp)
     ;






extern int clock_nanosleep (clockid_t __clock_id, int __flags,
       const struct timespec *__req,
       struct timespec *__rem);


extern int clock_getcpuclockid (pid_t __pid, clockid_t *__clock_id) ;




extern int timer_create (clockid_t __clock_id,
    struct sigevent *__restrict __evp,
    timer_t *__restrict __timerid) ;


extern int timer_delete (timer_t __timerid) ;


extern int timer_settime (timer_t __timerid, int __flags,
     const struct itimerspec *__restrict __value,
     struct itimerspec *__restrict __ovalue) ;


extern int timer_gettime (timer_t __timerid, struct itimerspec *__value)
     ;


extern int timer_getoverrun (timer_t __timerid) ;














extern char *ecvt (double __value, int __ndigit, int *__restrict __decpt,
     int *__restrict __sign)   ;




extern char *fcvt (double __value, int __ndigit, int *__restrict __decpt,
     int *__restrict __sign)   ;




extern char *gcvt (double __value, int __ndigit, char *__buf)
       ;




extern char *qecvt (long double __value, int __ndigit,
      int *__restrict __decpt, int *__restrict __sign)
       ;
extern char *qfcvt (long double __value, int __ndigit,
      int *__restrict __decpt, int *__restrict __sign)
       ;
extern char *qgcvt (long double __value, int __ndigit, char *__buf)
       ;




extern int ecvt_r (double __value, int __ndigit, int *__restrict __decpt,
     int *__restrict __sign, char *__restrict __buf,
     size_t __len)  ;
extern int fcvt_r (double __value, int __ndigit, int *__restrict __decpt,
     int *__restrict __sign, char *__restrict __buf,
     size_t __len)  ;

extern int qecvt_r (long double __value, int __ndigit,
      int *__restrict __decpt, int *__restrict __sign,
      char *__restrict __buf, size_t __len)
      ;
extern int qfcvt_r (long double __value, int __ndigit,
      int *__restrict __decpt, int *__restrict __sign,
      char *__restrict __buf, size_t __len)
      ;






extern int mblen (const char *__s, size_t __n) ;


extern int mbtowc (wchar_t *__restrict __pwc,
     const char *__restrict __s, size_t __n) ;


extern int wctomb (char *__s, wchar_t __wchar) ;



extern size_t mbstowcs (wchar_t *__restrict __pwcs,
   const char *__restrict __s, size_t __n) ;

extern size_t wcstombs (char *__restrict __s,
   const wchar_t *__restrict __pwcs, size_t __n)
     ;








extern int rpmatch (const char *__response)   ;

extern int getsubopt (char **__restrict __optionp,
        char *const *__restrict __tokens,
        char **__restrict __valuep)
       ;

extern int getloadavg (double __loadavg[], int __nelem)
      ;




















typedef struct stack_st
 {
 int num;
 char **data;
 int sorted;

 int num_alloc;
 int (*comp)(const void *, const void *);
 } _STACK;




int sk_num(const _STACK *);
void *sk_value(const _STACK *, int);

void *sk_set(_STACK *, int, void *);

_STACK *sk_new(int (*cmp)(const void *, const void *));
_STACK *sk_new_null(void);
void sk_free(_STACK *);
void sk_pop_free(_STACK *st, void (*func)(void *));
int sk_insert(_STACK *sk, void *data, int where);
void *sk_delete(_STACK *st, int loc);
void *sk_delete_ptr(_STACK *st, void *p);
int sk_find(_STACK *st, void *data);
int sk_find_ex(_STACK *st, void *data);
int sk_push(_STACK *st, void *data);
int sk_unshift(_STACK *st, void *data);
void *sk_shift(_STACK *st);
void *sk_pop(_STACK *st);
void sk_zero(_STACK *st);
int (*sk_set_cmp_func(_STACK *sk, int (*c)(const void *, const void *)))
 (const void *, const void *);
_STACK *sk_dup(_STACK *st);
void sk_sort(_STACK *st);
int sk_is_sorted(const _STACK *st);



typedef char *OPENSSL_STRING;

typedef const char *OPENSSL_CSTRING;

struct stack_st_OPENSSL_STRING { _STACK stack; };





typedef void *OPENSSL_BLOCK;
struct stack_st_OPENSSL_BLOCK { _STACK stack; };











typedef struct asn1_string_st ASN1_INTEGER;
typedef struct asn1_string_st ASN1_ENUMERATED;
typedef struct asn1_string_st ASN1_BIT_STRING;
typedef struct asn1_string_st ASN1_OCTET_STRING;
typedef struct asn1_string_st ASN1_PRINTABLESTRING;
typedef struct asn1_string_st ASN1_T61STRING;
typedef struct asn1_string_st ASN1_IA5STRING;
typedef struct asn1_string_st ASN1_GENERALSTRING;
typedef struct asn1_string_st ASN1_UNIVERSALSTRING;
typedef struct asn1_string_st ASN1_BMPSTRING;
typedef struct asn1_string_st ASN1_UTCTIME;
typedef struct asn1_string_st ASN1_TIME;
typedef struct asn1_string_st ASN1_GENERALIZEDTIME;
typedef struct asn1_string_st ASN1_VISIBLESTRING;
typedef struct asn1_string_st ASN1_UTF8STRING;
typedef struct asn1_string_st ASN1_STRING;
typedef int ASN1_BOOLEAN;
typedef int ASN1_NULL;


typedef struct ASN1_ITEM_st ASN1_ITEM;
typedef struct asn1_pctx_st ASN1_PCTX;

typedef struct bignum_st BIGNUM;
typedef struct bignum_ctx BN_CTX;
typedef struct bn_blinding_st BN_BLINDING;
typedef struct bn_mont_ctx_st BN_MONT_CTX;
typedef struct bn_recp_ctx_st BN_RECP_CTX;
typedef struct bn_gencb_st BN_GENCB;

typedef struct buf_mem_st BUF_MEM;

typedef struct evp_cipher_st EVP_CIPHER;
typedef struct evp_cipher_ctx_st EVP_CIPHER_CTX;
typedef struct env_md_st EVP_MD;
typedef struct env_md_ctx_st EVP_MD_CTX;
typedef struct evp_pkey_st EVP_PKEY;

typedef struct evp_pkey_asn1_method_st EVP_PKEY_ASN1_METHOD;

typedef struct evp_pkey_method_st EVP_PKEY_METHOD;
typedef struct evp_pkey_ctx_st EVP_PKEY_CTX;

typedef struct dh_st DH;
typedef struct dh_method DH_METHOD;

typedef struct dsa_st DSA;
typedef struct dsa_method DSA_METHOD;

typedef struct rsa_st RSA;
typedef struct rsa_meth_st RSA_METHOD;

typedef struct rand_meth_st RAND_METHOD;

typedef struct ecdh_method ECDH_METHOD;
typedef struct ecdsa_method ECDSA_METHOD;

typedef struct x509_st X509;
typedef struct X509_algor_st X509_ALGOR;
typedef struct X509_crl_st X509_CRL;
typedef struct x509_crl_method_st X509_CRL_METHOD;
typedef struct x509_revoked_st X509_REVOKED;
typedef struct X509_name_st X509_NAME;
typedef struct X509_pubkey_st X509_PUBKEY;
typedef struct x509_store_st X509_STORE;
typedef struct x509_store_ctx_st X509_STORE_CTX;

typedef struct pkcs8_priv_key_info_st PKCS8_PRIV_KEY_INFO;

typedef struct v3_ext_ctx X509V3_CTX;
typedef struct conf_st CONF;

typedef struct store_st STORE;
typedef struct store_method_st STORE_METHOD;

typedef struct ui_st UI;
typedef struct ui_method_st UI_METHOD;

typedef struct st_ERR_FNS ERR_FNS;

typedef struct engine_st ENGINE;
typedef struct ssl_st SSL;
typedef struct ssl_ctx_st SSL_CTX;

typedef struct X509_POLICY_NODE_st X509_POLICY_NODE;
typedef struct X509_POLICY_LEVEL_st X509_POLICY_LEVEL;
typedef struct X509_POLICY_TREE_st X509_POLICY_TREE;
typedef struct X509_POLICY_CACHE_st X509_POLICY_CACHE;

typedef struct AUTHORITY_KEYID_st AUTHORITY_KEYID;
typedef struct DIST_POINT_st DIST_POINT;
typedef struct ISSUING_DIST_POINT_st ISSUING_DIST_POINT;
typedef struct NAME_CONSTRAINTS_st NAME_CONSTRAINTS;





typedef struct crypto_ex_data_st CRYPTO_EX_DATA;

typedef int CRYPTO_EX_new(void *parent, void *ptr, CRYPTO_EX_DATA *ad,
     int idx, long argl, void *argp);
typedef void CRYPTO_EX_free(void *parent, void *ptr, CRYPTO_EX_DATA *ad,
     int idx, long argl, void *argp);
typedef int CRYPTO_EX_dup(CRYPTO_EX_DATA *to, CRYPTO_EX_DATA *from, void *from_d,
     int idx, long argl, void *argp);

typedef struct ocsp_req_ctx_st OCSP_REQ_CTX;
typedef struct ocsp_response_st OCSP_RESPONSE;
typedef struct ocsp_responder_id_st OCSP_RESPID;

















typedef struct openssl_item_st
 {
 int code;
 void *value;
 size_t value_size;
 size_t *value_length;
 } OPENSSL_ITEM;

typedef struct
 {
 int references;
 struct CRYPTO_dynlock_value *data;
 } CRYPTO_dynlock;

typedef struct bio_st BIO_dummy;

struct crypto_ex_data_st
 {
 struct stack_st_void *sk;
 int dummy;
 };
struct stack_st_void { _STACK stack; };




typedef struct crypto_ex_data_func_st
 {
 long argl;
 void *argp;
 CRYPTO_EX_new *new_func;
 CRYPTO_EX_free *free_func;
 CRYPTO_EX_dup *dup_func;
 } CRYPTO_EX_DATA_FUNCS;

struct stack_st_CRYPTO_EX_DATA_FUNCS { _STACK stack; };

int CRYPTO_mem_ctrl(int mode);
int CRYPTO_is_mem_check_on(void);

const char *SSLeay_version(int type);
unsigned long SSLeay(void);

int OPENSSL_issetugid(void);


typedef struct st_CRYPTO_EX_DATA_IMPL CRYPTO_EX_DATA_IMPL;

const CRYPTO_EX_DATA_IMPL *CRYPTO_get_ex_data_implementation(void);

int CRYPTO_set_ex_data_implementation(const CRYPTO_EX_DATA_IMPL *i);

int CRYPTO_ex_data_new_class(void);

int CRYPTO_get_ex_new_index(int class_index, long argl, void *argp,
  CRYPTO_EX_new *new_func, CRYPTO_EX_dup *dup_func,
  CRYPTO_EX_free *free_func);


int CRYPTO_new_ex_data(int class_index, void *obj, CRYPTO_EX_DATA *ad);
int CRYPTO_dup_ex_data(int class_index, CRYPTO_EX_DATA *to,
  CRYPTO_EX_DATA *from);
void CRYPTO_free_ex_data(int class_index, void *obj, CRYPTO_EX_DATA *ad);


int CRYPTO_set_ex_data(CRYPTO_EX_DATA *ad, int idx, void *val);
void *CRYPTO_get_ex_data(const CRYPTO_EX_DATA *ad,int idx);


void CRYPTO_cleanup_all_ex_data(void);

int CRYPTO_get_new_lockid(char *name);

int CRYPTO_num_locks(void);
void CRYPTO_lock(int mode, int type,const char *file,int line);
void CRYPTO_set_locking_callback(void (*func)(int mode,int type,
           const char *file,int line));
void (*CRYPTO_get_locking_callback(void))(int mode,int type,const char *file,
  int line);
void CRYPTO_set_add_lock_callback(int (*func)(int *num,int mount,int type,
           const char *file, int line));
int (*CRYPTO_get_add_lock_callback(void))(int *num,int mount,int type,
       const char *file,int line);


typedef struct crypto_threadid_st
 {
 void *ptr;
 unsigned long val;
 } CRYPTO_THREADID;

void CRYPTO_THREADID_set_numeric(CRYPTO_THREADID *id, unsigned long val);
void CRYPTO_THREADID_set_pointer(CRYPTO_THREADID *id, void *ptr);
int CRYPTO_THREADID_set_callback(void (*threadid_func)(CRYPTO_THREADID *));
void (*CRYPTO_THREADID_get_callback(void))(CRYPTO_THREADID *);
void CRYPTO_THREADID_current(CRYPTO_THREADID *id);
int CRYPTO_THREADID_cmp(const CRYPTO_THREADID *a, const CRYPTO_THREADID *b);
void CRYPTO_THREADID_cpy(CRYPTO_THREADID *dest, const CRYPTO_THREADID *src);
unsigned long CRYPTO_THREADID_hash(const CRYPTO_THREADID *id);

void CRYPTO_set_id_callback(unsigned long (*func)(void));
unsigned long (*CRYPTO_get_id_callback(void))(void);
unsigned long CRYPTO_thread_id(void);


const char *CRYPTO_get_lock_name(int type);
int CRYPTO_add_lock(int *pointer,int amount,int type, const char *file,
      int line);

int CRYPTO_get_new_dynlockid(void);
void CRYPTO_destroy_dynlockid(int i);
struct CRYPTO_dynlock_value *CRYPTO_get_dynlock_value(int i);
void CRYPTO_set_dynlock_create_callback(struct CRYPTO_dynlock_value *(*dyn_create_function)(const char *file, int line));
void CRYPTO_set_dynlock_lock_callback(void (*dyn_lock_function)(int mode, struct CRYPTO_dynlock_value *l, const char *file, int line));
void CRYPTO_set_dynlock_destroy_callback(void (*dyn_destroy_function)(struct CRYPTO_dynlock_value *l, const char *file, int line));
struct CRYPTO_dynlock_value *(*CRYPTO_get_dynlock_create_callback(void))(const char *file,int line);
void (*CRYPTO_get_dynlock_lock_callback(void))(int mode, struct CRYPTO_dynlock_value *l, const char *file,int line);
void (*CRYPTO_get_dynlock_destroy_callback(void))(struct CRYPTO_dynlock_value *l, const char *file,int line);



int CRYPTO_set_mem_functions(void *(*m)(size_t),void *(*r)(void *,size_t), void (*f)(void *));
int CRYPTO_set_locked_mem_functions(void *(*m)(size_t), void (*free_func)(void *));
int CRYPTO_set_mem_ex_functions(void *(*m)(size_t,const char *,int),
                                void *(*r)(void *,size_t,const char *,int),
                                void (*f)(void *));
int CRYPTO_set_locked_mem_ex_functions(void *(*m)(size_t,const char *,int),
                                       void (*free_func)(void *));
int CRYPTO_set_mem_debug_functions(void (*m)(void *,int,const char *,int,int),
       void (*r)(void *,void *,int,const char *,int,int),
       void (*f)(void *,int),
       void (*so)(long),
       long (*go)(void));
void CRYPTO_get_mem_functions(void *(**m)(size_t),void *(**r)(void *, size_t), void (**f)(void *));
void CRYPTO_get_locked_mem_functions(void *(**m)(size_t), void (**f)(void *));
void CRYPTO_get_mem_ex_functions(void *(**m)(size_t,const char *,int),
                                 void *(**r)(void *, size_t,const char *,int),
                                 void (**f)(void *));
void CRYPTO_get_locked_mem_ex_functions(void *(**m)(size_t,const char *,int),
                                        void (**f)(void *));
void CRYPTO_get_mem_debug_functions(void (**m)(void *,int,const char *,int,int),
        void (**r)(void *,void *,int,const char *,int,int),
        void (**f)(void *,int),
        void (**so)(long),
        long (**go)(void));

void *CRYPTO_malloc_locked(int num, const char *file, int line);
void CRYPTO_free_locked(void *ptr);
void *CRYPTO_malloc(int num, const char *file, int line);
char *CRYPTO_strdup(const char *str, const char *file, int line);
void CRYPTO_free(void *ptr);
void *CRYPTO_realloc(void *addr,int num, const char *file, int line);
void *CRYPTO_realloc_clean(void *addr,int old_num,int num,const char *file,
      int line);
void *CRYPTO_remalloc(void *addr,int num, const char *file, int line);

void OPENSSL_cleanse(void *ptr, size_t len);

void CRYPTO_set_mem_debug_options(long bits);
long CRYPTO_get_mem_debug_options(void);



int CRYPTO_push_info_(const char *info, const char *file, int line);
int CRYPTO_pop_info(void);
int CRYPTO_remove_all_info(void);

void CRYPTO_dbg_malloc(void *addr,int num,const char *file,int line,int before_p);
void CRYPTO_dbg_realloc(void *addr1,void *addr2,int num,const char *file,int line,int before_p);
void CRYPTO_dbg_free(void *addr,int before_p);

void CRYPTO_dbg_set_options(long bits);
long CRYPTO_dbg_get_options(void);



void CRYPTO_mem_leaks_fp(FILE *);

void CRYPTO_mem_leaks(struct bio_st *bio);

typedef void *CRYPTO_MEM_LEAK_CB(unsigned long, const char *, int, int, void *);
void CRYPTO_mem_leaks_cb(CRYPTO_MEM_LEAK_CB *cb);


void OpenSSLDie(const char *file,int line,const char *assertion);


unsigned long *OPENSSL_ia32cap_loc(void);

int OPENSSL_isservice(void);

int FIPS_mode(void);
int FIPS_mode_set(int r);

void OPENSSL_init(void);

int CRYPTO_memcmp(const void *a, const void *b, size_t len);





void ERR_load_CRYPTO_strings(void);


typedef struct bio_st BIO;

void BIO_set_flags(BIO *b, int flags);
int BIO_test_flags(const BIO *b, int flags);
void BIO_clear_flags(BIO *b, int flags);

long (*BIO_get_callback(const BIO *b)) (struct bio_st *,int,const char *,int, long,long);
void BIO_set_callback(BIO *b,
 long (*callback)(struct bio_st *,int,const char *,int, long,long));
char *BIO_get_callback_arg(const BIO *b);
void BIO_set_callback_arg(BIO *b, char *arg);

const char * BIO_method_name(const BIO *b);
int BIO_method_type(const BIO *b);

typedef void bio_info_cb(struct bio_st *, int, const char *, int, long, long);

typedef struct bio_method_st
 {
 int type;
 const char *name;
 int (*bwrite)(BIO *, const char *, int);
 int (*bread)(BIO *, char *, int);
 int (*bputs)(BIO *, const char *);
 int (*bgets)(BIO *, char *, int);
 long (*ctrl)(BIO *, int, long, void *);
 int (*create)(BIO *);
 int (*destroy)(BIO *);
        long (*callback_ctrl)(BIO *, int, bio_info_cb *);
 } BIO_METHOD;

struct bio_st
 {
 BIO_METHOD *method;

 long (*callback)(struct bio_st *,int,const char *,int, long,long);
 char *cb_arg;

 int init;
 int shutdown;
 int flags;
 int retry_reason;
 int num;
 void *ptr;
 struct bio_st *next_bio;
 struct bio_st *prev_bio;
 int references;
 unsigned long num_read;
 unsigned long num_write;

 CRYPTO_EX_DATA ex_data;
 };

struct stack_st_BIO { _STACK stack; };

typedef struct bio_f_buffer_ctx_struct
 {

 int ibuf_size;
 int obuf_size;

 char *ibuf;
 int ibuf_len;
 int ibuf_off;

 char *obuf;
 int obuf_len;
 int obuf_off;
 } BIO_F_BUFFER_CTX;


typedef int asn1_ps_func(BIO *b, unsigned char **pbuf, int *plen, void *parg);

size_t BIO_ctrl_pending(BIO *b);
size_t BIO_ctrl_wpending(BIO *b);

size_t BIO_ctrl_get_write_guarantee(BIO *b);
size_t BIO_ctrl_get_read_request(BIO *b);
int BIO_ctrl_reset_read_request(BIO *b);

int BIO_set_ex_data(BIO *bio,int idx,void *data);
void *BIO_get_ex_data(BIO *bio,int idx);
int BIO_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func,
 CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func);
unsigned long BIO_number_read(BIO *bio);
unsigned long BIO_number_written(BIO *bio);


int BIO_asn1_set_prefix(BIO *b, asn1_ps_func *prefix,
     asn1_ps_func *prefix_free);
int BIO_asn1_get_prefix(BIO *b, asn1_ps_func **pprefix,
     asn1_ps_func **pprefix_free);
int BIO_asn1_set_suffix(BIO *b, asn1_ps_func *suffix,
     asn1_ps_func *suffix_free);
int BIO_asn1_get_suffix(BIO *b, asn1_ps_func **psuffix,
     asn1_ps_func **psuffix_free);


BIO_METHOD *BIO_s_file(void );
BIO *BIO_new_file(const char *filename, const char *mode);
BIO *BIO_new_fp(FILE *stream, int close_flag);


BIO * BIO_new(BIO_METHOD *type);
int BIO_set(BIO *a,BIO_METHOD *type);
int BIO_free(BIO *a);
void BIO_vfree(BIO *a);
int BIO_read(BIO *b, void *data, int len);
int BIO_gets(BIO *bp,char *buf, int size);
int BIO_write(BIO *b, const void *data, int len);
int BIO_puts(BIO *bp,const char *buf);
int BIO_indent(BIO *b,int indent,int max);
long BIO_ctrl(BIO *bp,int cmd,long larg,void *parg);
long BIO_callback_ctrl(BIO *b, int cmd, void (*fp)(struct bio_st *, int, const char *, int, long, long));
char * BIO_ptr_ctrl(BIO *bp,int cmd,long larg);
long BIO_int_ctrl(BIO *bp,int cmd,long larg,int iarg);
BIO * BIO_push(BIO *b,BIO *append);
BIO * BIO_pop(BIO *b);
void BIO_free_all(BIO *a);
BIO * BIO_find_type(BIO *b,int bio_type);
BIO * BIO_next(BIO *b);
BIO * BIO_get_retry_BIO(BIO *bio, int *reason);
int BIO_get_retry_reason(BIO *bio);
BIO * BIO_dup_chain(BIO *in);

int BIO_nread0(BIO *bio, char **buf);
int BIO_nread(BIO *bio, char **buf, int num);
int BIO_nwrite0(BIO *bio, char **buf);
int BIO_nwrite(BIO *bio, char **buf, int num);

long BIO_debug_callback(BIO *bio,int cmd,const char *argp,int argi,
 long argl,long ret);

BIO_METHOD *BIO_s_mem(void);
BIO *BIO_new_mem_buf(void *buf, int len);
BIO_METHOD *BIO_s_socket(void);
BIO_METHOD *BIO_s_connect(void);
BIO_METHOD *BIO_s_accept(void);
BIO_METHOD *BIO_s_fd(void);

BIO_METHOD *BIO_s_log(void);

BIO_METHOD *BIO_s_bio(void);
BIO_METHOD *BIO_s_null(void);
BIO_METHOD *BIO_f_null(void);
BIO_METHOD *BIO_f_buffer(void);



BIO_METHOD *BIO_f_nbio_test(void);

BIO_METHOD *BIO_s_datagram(void);







int BIO_sock_should_retry(int i);
int BIO_sock_non_fatal_error(int error);
int BIO_dgram_non_fatal_error(int error);

int BIO_fd_should_retry(int i);
int BIO_fd_non_fatal_error(int error);
int BIO_dump_cb(int (*cb)(const void *data, size_t len, void *u),
  void *u, const char *s, int len);
int BIO_dump_indent_cb(int (*cb)(const void *data, size_t len, void *u),
         void *u, const char *s, int len, int indent);
int BIO_dump(BIO *b,const char *bytes,int len);
int BIO_dump_indent(BIO *b,const char *bytes,int len,int indent);

int BIO_dump_fp(FILE *fp, const char *s, int len);
int BIO_dump_indent_fp(FILE *fp, const char *s, int len, int indent);

struct hostent *BIO_gethostbyname(const char *name);

int BIO_sock_error(int sock);
int BIO_socket_ioctl(int fd, long type, void *arg);
int BIO_socket_nbio(int fd,int mode);
int BIO_get_port(const char *str, unsigned short *port_ptr);
int BIO_get_host_ip(const char *str, unsigned char *ip);
int BIO_get_accept_socket(char *host_port,int mode);
int BIO_accept(int sock,char **ip_port);
int BIO_sock_init(void );
void BIO_sock_cleanup(void);
int BIO_set_tcp_ndelay(int sock,int turn_on);

BIO *BIO_new_socket(int sock, int close_flag);
BIO *BIO_new_dgram(int fd, int close_flag);

BIO *BIO_new_fd(int fd, int close_flag);
BIO *BIO_new_connect(char *host_port);
BIO *BIO_new_accept(char *host_port);

int BIO_new_bio_pair(BIO **bio1, size_t writebuf1,
 BIO **bio2, size_t writebuf2);





void BIO_copy_next_retry(BIO *b);

int BIO_printf(BIO *bio, const char *format, ...);
int BIO_vprintf(BIO *bio, const char *format, va_list args);
int BIO_snprintf(char *buf, size_t n, const char *format, ...);
int BIO_vsnprintf(char *buf, size_t n, const char *format, va_list args);






void ERR_load_BIO_strings(void);













































struct bignum_st
 {
 unsigned long *d;
 int top;

 int dmax;
 int neg;
 int flags;
 };


struct bn_mont_ctx_st
 {
 int ri;
 BIGNUM RR;
 BIGNUM N;
 BIGNUM Ni;

 unsigned long n0[2];

 int flags;
 };




struct bn_recp_ctx_st
 {
 BIGNUM N;
 BIGNUM Nr;
 int num_bits;
 int shift;
 int flags;
 };


struct bn_gencb_st
 {
 unsigned int ver;
 void *arg;
 union
  {

  void (*cb_1)(int, int, void *);

  int (*cb_2)(int, int, BN_GENCB *);
  } cb;
 };

int BN_GENCB_call(BN_GENCB *cb, int a, int b);

const BIGNUM *BN_value_one(void);
char * BN_options(void);
BN_CTX *BN_CTX_new(void);

void BN_CTX_init(BN_CTX *c);

void BN_CTX_free(BN_CTX *c);
void BN_CTX_start(BN_CTX *ctx);
BIGNUM *BN_CTX_get(BN_CTX *ctx);
void BN_CTX_end(BN_CTX *ctx);
int BN_rand(BIGNUM *rnd, int bits, int top,int bottom);
int BN_pseudo_rand(BIGNUM *rnd, int bits, int top,int bottom);
int BN_rand_range(BIGNUM *rnd, const BIGNUM *range);
int BN_pseudo_rand_range(BIGNUM *rnd, const BIGNUM *range);
int BN_num_bits(const BIGNUM *a);
int BN_num_bits_word(unsigned long);
BIGNUM *BN_new(void);
void BN_init(BIGNUM *);
void BN_clear_free(BIGNUM *a);
BIGNUM *BN_copy(BIGNUM *a, const BIGNUM *b);
void BN_swap(BIGNUM *a, BIGNUM *b);
BIGNUM *BN_bin2bn(const unsigned char *s,int len,BIGNUM *ret);
int BN_bn2bin(const BIGNUM *a, unsigned char *to);
BIGNUM *BN_mpi2bn(const unsigned char *s,int len,BIGNUM *ret);
int BN_bn2mpi(const BIGNUM *a, unsigned char *to);
int BN_sub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
int BN_usub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
int BN_uadd(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
int BN_add(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
int BN_mul(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx);
int BN_sqr(BIGNUM *r, const BIGNUM *a,BN_CTX *ctx);




void BN_set_negative(BIGNUM *b, int n);






int BN_div(BIGNUM *dv, BIGNUM *rem, const BIGNUM *m, const BIGNUM *d,
 BN_CTX *ctx);

int BN_nnmod(BIGNUM *r, const BIGNUM *m, const BIGNUM *d, BN_CTX *ctx);
int BN_mod_add(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *m, BN_CTX *ctx);
int BN_mod_add_quick(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *m);
int BN_mod_sub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *m, BN_CTX *ctx);
int BN_mod_sub_quick(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *m);
int BN_mod_mul(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
 const BIGNUM *m, BN_CTX *ctx);
int BN_mod_sqr(BIGNUM *r, const BIGNUM *a, const BIGNUM *m, BN_CTX *ctx);
int BN_mod_lshift1(BIGNUM *r, const BIGNUM *a, const BIGNUM *m, BN_CTX *ctx);
int BN_mod_lshift1_quick(BIGNUM *r, const BIGNUM *a, const BIGNUM *m);
int BN_mod_lshift(BIGNUM *r, const BIGNUM *a, int n, const BIGNUM *m, BN_CTX *ctx);
int BN_mod_lshift_quick(BIGNUM *r, const BIGNUM *a, int n, const BIGNUM *m);

unsigned long BN_mod_word(const BIGNUM *a, unsigned long w);
unsigned long BN_div_word(BIGNUM *a, unsigned long w);
int BN_mul_word(BIGNUM *a, unsigned long w);
int BN_add_word(BIGNUM *a, unsigned long w);
int BN_sub_word(BIGNUM *a, unsigned long w);
int BN_set_word(BIGNUM *a, unsigned long w);
unsigned long BN_get_word(const BIGNUM *a);

int BN_cmp(const BIGNUM *a, const BIGNUM *b);
void BN_free(BIGNUM *a);
int BN_is_bit_set(const BIGNUM *a, int n);
int BN_lshift(BIGNUM *r, const BIGNUM *a, int n);
int BN_lshift1(BIGNUM *r, const BIGNUM *a);
int BN_exp(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,BN_CTX *ctx);

int BN_mod_exp(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
 const BIGNUM *m,BN_CTX *ctx);
int BN_mod_exp_mont(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
 const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx);
int BN_mod_exp_mont_consttime(BIGNUM *rr, const BIGNUM *a, const BIGNUM *p,
 const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *in_mont);
int BN_mod_exp_mont_word(BIGNUM *r, unsigned long a, const BIGNUM *p,
 const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx);
int BN_mod_exp2_mont(BIGNUM *r, const BIGNUM *a1, const BIGNUM *p1,
 const BIGNUM *a2, const BIGNUM *p2,const BIGNUM *m,
 BN_CTX *ctx,BN_MONT_CTX *m_ctx);
int BN_mod_exp_simple(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
 const BIGNUM *m,BN_CTX *ctx);

int BN_mask_bits(BIGNUM *a,int n);

int BN_print_fp(FILE *fp, const BIGNUM *a);


int BN_print(BIO *fp, const BIGNUM *a);



int BN_reciprocal(BIGNUM *r, const BIGNUM *m, int len, BN_CTX *ctx);
int BN_rshift(BIGNUM *r, const BIGNUM *a, int n);
int BN_rshift1(BIGNUM *r, const BIGNUM *a);
void BN_clear(BIGNUM *a);
BIGNUM *BN_dup(const BIGNUM *a);
int BN_ucmp(const BIGNUM *a, const BIGNUM *b);
int BN_set_bit(BIGNUM *a, int n);
int BN_clear_bit(BIGNUM *a, int n);
char * BN_bn2hex(const BIGNUM *a);
char * BN_bn2dec(const BIGNUM *a);
int BN_hex2bn(BIGNUM **a, const char *str);
int BN_dec2bn(BIGNUM **a, const char *str);
int BN_asc2bn(BIGNUM **a, const char *str);
int BN_gcd(BIGNUM *r,const BIGNUM *a,const BIGNUM *b,BN_CTX *ctx);
int BN_kronecker(const BIGNUM *a,const BIGNUM *b,BN_CTX *ctx);
BIGNUM *BN_mod_inverse(BIGNUM *ret,
 const BIGNUM *a, const BIGNUM *n,BN_CTX *ctx);
BIGNUM *BN_mod_sqrt(BIGNUM *ret,
 const BIGNUM *a, const BIGNUM *n,BN_CTX *ctx);

void BN_consttime_swap(unsigned long swap, BIGNUM *a, BIGNUM *b, int nwords);



BIGNUM *BN_generate_prime(BIGNUM *ret,int bits,int safe,
 const BIGNUM *add, const BIGNUM *rem,
 void (*callback)(int,int,void *),void *cb_arg);
int BN_is_prime(const BIGNUM *p,int nchecks,
 void (*callback)(int,int,void *),
 BN_CTX *ctx,void *cb_arg);
int BN_is_prime_fasttest(const BIGNUM *p,int nchecks,
 void (*callback)(int,int,void *),BN_CTX *ctx,void *cb_arg,
 int do_trial_division);



int BN_generate_prime_ex(BIGNUM *ret,int bits,int safe, const BIGNUM *add,
  const BIGNUM *rem, BN_GENCB *cb);
int BN_is_prime_ex(const BIGNUM *p,int nchecks, BN_CTX *ctx, BN_GENCB *cb);
int BN_is_prime_fasttest_ex(const BIGNUM *p,int nchecks, BN_CTX *ctx,
  int do_trial_division, BN_GENCB *cb);

int BN_X931_generate_Xpq(BIGNUM *Xp, BIGNUM *Xq, int nbits, BN_CTX *ctx);

int BN_X931_derive_prime_ex(BIGNUM *p, BIGNUM *p1, BIGNUM *p2,
   const BIGNUM *Xp, const BIGNUM *Xp1, const BIGNUM *Xp2,
   const BIGNUM *e, BN_CTX *ctx, BN_GENCB *cb);
int BN_X931_generate_prime_ex(BIGNUM *p, BIGNUM *p1, BIGNUM *p2,
   BIGNUM *Xp1, BIGNUM *Xp2,
   const BIGNUM *Xp,
   const BIGNUM *e, BN_CTX *ctx,
   BN_GENCB *cb);

BN_MONT_CTX *BN_MONT_CTX_new(void );
void BN_MONT_CTX_init(BN_MONT_CTX *ctx);
int BN_mod_mul_montgomery(BIGNUM *r,const BIGNUM *a,const BIGNUM *b,
 BN_MONT_CTX *mont, BN_CTX *ctx);


int BN_from_montgomery(BIGNUM *r,const BIGNUM *a,
 BN_MONT_CTX *mont, BN_CTX *ctx);
void BN_MONT_CTX_free(BN_MONT_CTX *mont);
int BN_MONT_CTX_set(BN_MONT_CTX *mont,const BIGNUM *mod,BN_CTX *ctx);
BN_MONT_CTX *BN_MONT_CTX_copy(BN_MONT_CTX *to,BN_MONT_CTX *from);
BN_MONT_CTX *BN_MONT_CTX_set_locked(BN_MONT_CTX **pmont, int lock,
     const BIGNUM *mod, BN_CTX *ctx);





BN_BLINDING *BN_BLINDING_new(const BIGNUM *A, const BIGNUM *Ai, BIGNUM *mod);
void BN_BLINDING_free(BN_BLINDING *b);
int BN_BLINDING_update(BN_BLINDING *b,BN_CTX *ctx);
int BN_BLINDING_convert(BIGNUM *n, BN_BLINDING *b, BN_CTX *ctx);
int BN_BLINDING_invert(BIGNUM *n, BN_BLINDING *b, BN_CTX *ctx);
int BN_BLINDING_convert_ex(BIGNUM *n, BIGNUM *r, BN_BLINDING *b, BN_CTX *);
int BN_BLINDING_invert_ex(BIGNUM *n, const BIGNUM *r, BN_BLINDING *b, BN_CTX *);

unsigned long BN_BLINDING_get_thread_id(const BN_BLINDING *);
void BN_BLINDING_set_thread_id(BN_BLINDING *, unsigned long);

CRYPTO_THREADID *BN_BLINDING_thread_id(BN_BLINDING *);
unsigned long BN_BLINDING_get_flags(const BN_BLINDING *);
void BN_BLINDING_set_flags(BN_BLINDING *, unsigned long);
BN_BLINDING *BN_BLINDING_create_param(BN_BLINDING *b,
 const BIGNUM *e, BIGNUM *m, BN_CTX *ctx,
 int (*bn_mod_exp)(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
     const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx),
 BN_MONT_CTX *m_ctx);


void BN_set_params(int mul,int high,int low,int mont);
int BN_get_params(int which);


void BN_RECP_CTX_init(BN_RECP_CTX *recp);
BN_RECP_CTX *BN_RECP_CTX_new(void);
void BN_RECP_CTX_free(BN_RECP_CTX *recp);
int BN_RECP_CTX_set(BN_RECP_CTX *recp,const BIGNUM *rdiv,BN_CTX *ctx);
int BN_mod_mul_reciprocal(BIGNUM *r, const BIGNUM *x, const BIGNUM *y,
 BN_RECP_CTX *recp,BN_CTX *ctx);
int BN_mod_exp_recp(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
 const BIGNUM *m, BN_CTX *ctx);
int BN_div_recp(BIGNUM *dv, BIGNUM *rem, const BIGNUM *m,
 BN_RECP_CTX *recp, BN_CTX *ctx);

int BN_GF2m_add(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);

int BN_GF2m_mod(BIGNUM *r, const BIGNUM *a, const BIGNUM *p);
int BN_GF2m_mod_mul(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
 const BIGNUM *p, BN_CTX *ctx);
int BN_GF2m_mod_sqr(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
 BN_CTX *ctx);
int BN_GF2m_mod_inv(BIGNUM *r, const BIGNUM *b, const BIGNUM *p,
 BN_CTX *ctx);
int BN_GF2m_mod_div(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
 const BIGNUM *p, BN_CTX *ctx);
int BN_GF2m_mod_exp(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
 const BIGNUM *p, BN_CTX *ctx);
int BN_GF2m_mod_sqrt(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
 BN_CTX *ctx);
int BN_GF2m_mod_solve_quad(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
 BN_CTX *ctx);






int BN_GF2m_mod_arr(BIGNUM *r, const BIGNUM *a, const int p[]);

int BN_GF2m_mod_mul_arr(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
 const int p[], BN_CTX *ctx);
int BN_GF2m_mod_sqr_arr(BIGNUM *r, const BIGNUM *a, const int p[],
 BN_CTX *ctx);
int BN_GF2m_mod_inv_arr(BIGNUM *r, const BIGNUM *b, const int p[],
 BN_CTX *ctx);
int BN_GF2m_mod_div_arr(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
 const int p[], BN_CTX *ctx);
int BN_GF2m_mod_exp_arr(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
 const int p[], BN_CTX *ctx);
int BN_GF2m_mod_sqrt_arr(BIGNUM *r, const BIGNUM *a,
 const int p[], BN_CTX *ctx);
int BN_GF2m_mod_solve_quad_arr(BIGNUM *r, const BIGNUM *a,
 const int p[], BN_CTX *ctx);
int BN_GF2m_poly2arr(const BIGNUM *a, int p[], int max);
int BN_GF2m_arr2poly(const int p[], BIGNUM *a);





int BN_nist_mod_192(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, BN_CTX *ctx);
int BN_nist_mod_224(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, BN_CTX *ctx);
int BN_nist_mod_256(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, BN_CTX *ctx);
int BN_nist_mod_384(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, BN_CTX *ctx);
int BN_nist_mod_521(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, BN_CTX *ctx);

const BIGNUM *BN_get0_nist_prime_192(void);
const BIGNUM *BN_get0_nist_prime_224(void);
const BIGNUM *BN_get0_nist_prime_256(void);
const BIGNUM *BN_get0_nist_prime_384(void);
const BIGNUM *BN_get0_nist_prime_521(void);

BIGNUM *bn_expand2(BIGNUM *a, int words);

BIGNUM *bn_dup_expand(const BIGNUM *a, int words);

unsigned long bn_mul_add_words(unsigned long *rp, const unsigned long *ap, int num, unsigned long w);
unsigned long bn_mul_words(unsigned long *rp, const unsigned long *ap, int num, unsigned long w);
void bn_sqr_words(unsigned long *rp, const unsigned long *ap, int num);
unsigned long bn_div_words(unsigned long h, unsigned long l, unsigned long d);
unsigned long bn_add_words(unsigned long *rp, const unsigned long *ap, const unsigned long *bp,int num);
unsigned long bn_sub_words(unsigned long *rp, const unsigned long *ap, const unsigned long *bp,int num);


BIGNUM *get_rfc2409_prime_768(BIGNUM *bn);
BIGNUM *get_rfc2409_prime_1024(BIGNUM *bn);


BIGNUM *get_rfc3526_prime_1536(BIGNUM *bn);
BIGNUM *get_rfc3526_prime_2048(BIGNUM *bn);
BIGNUM *get_rfc3526_prime_3072(BIGNUM *bn);
BIGNUM *get_rfc3526_prime_4096(BIGNUM *bn);
BIGNUM *get_rfc3526_prime_6144(BIGNUM *bn);
BIGNUM *get_rfc3526_prime_8192(BIGNUM *bn);

int BN_bntest_rand(BIGNUM *rnd, int bits, int top,int bottom);





void ERR_load_BN_strings(void);


struct X509_algor_st;
struct stack_st_X509_ALGOR { _STACK stack; };

typedef struct asn1_ctx_st
 {
 unsigned char *p;
 int eos;
 int error;
 int inf;
 int tag;
 int xclass;
 long slen;
 unsigned char *max;
 unsigned char *q;
 unsigned char **pp;
 int line;
 } ASN1_CTX;

typedef struct asn1_const_ctx_st
 {
 const unsigned char *p;
 int eos;
 int error;
 int inf;
 int tag;
 int xclass;
 long slen;
 const unsigned char *max;
 const unsigned char *q;
 const unsigned char **pp;
 int line;
 } ASN1_const_CTX;







typedef struct asn1_object_st
 {
 const char *sn,*ln;
 int nid;
 int length;
 const unsigned char *data;
 int flags;
 } ASN1_OBJECT;

struct asn1_string_st
 {
 int length;
 int type;
 unsigned char *data;




 long flags;
 };






typedef struct ASN1_ENCODING_st
 {
 unsigned char *enc;
 long len;
 int modified;
 } ASN1_ENCODING;

typedef struct asn1_string_table_st {
 int nid;
 long minsize;
 long maxsize;
 unsigned long mask;
 unsigned long flags;
} ASN1_STRING_TABLE;

struct stack_st_ASN1_STRING_TABLE { _STACK stack; };

typedef struct ASN1_TEMPLATE_st ASN1_TEMPLATE;
typedef struct ASN1_TLC_st ASN1_TLC;

typedef struct ASN1_VALUE_st ASN1_VALUE;

typedef void *d2i_of_void(void **,const unsigned char **,long); typedef int i2d_of_void(void *,unsigned char **);

typedef const ASN1_ITEM ASN1_ITEM_EXP;

struct stack_st_ASN1_INTEGER { _STACK stack; };


struct stack_st_ASN1_GENERALSTRING { _STACK stack; };

typedef struct asn1_type_st
 {
 int type;
 union {
  char *ptr;
  ASN1_BOOLEAN boolean;
  ASN1_STRING * asn1_string;
  ASN1_OBJECT * object;
  ASN1_INTEGER * integer;
  ASN1_ENUMERATED * enumerated;
  ASN1_BIT_STRING * bit_string;
  ASN1_OCTET_STRING * octet_string;
  ASN1_PRINTABLESTRING * printablestring;
  ASN1_T61STRING * t61string;
  ASN1_IA5STRING * ia5string;
  ASN1_GENERALSTRING * generalstring;
  ASN1_BMPSTRING * bmpstring;
  ASN1_UNIVERSALSTRING * universalstring;
  ASN1_UTCTIME * utctime;
  ASN1_GENERALIZEDTIME * generalizedtime;
  ASN1_VISIBLESTRING * visiblestring;
  ASN1_UTF8STRING * utf8string;


  ASN1_STRING * set;
  ASN1_STRING * sequence;
  ASN1_VALUE * asn1_value;
  } value;
 } ASN1_TYPE;

struct stack_st_ASN1_TYPE { _STACK stack; };


typedef struct stack_st_ASN1_TYPE ASN1_SEQUENCE_ANY;

ASN1_SEQUENCE_ANY *d2i_ASN1_SEQUENCE_ANY(ASN1_SEQUENCE_ANY **a, const unsigned char **in, long len); int i2d_ASN1_SEQUENCE_ANY(const ASN1_SEQUENCE_ANY *a, unsigned char **out); extern const ASN1_ITEM ASN1_SEQUENCE_ANY_it;
ASN1_SEQUENCE_ANY *d2i_ASN1_SET_ANY(ASN1_SEQUENCE_ANY **a, const unsigned char **in, long len); int i2d_ASN1_SET_ANY(const ASN1_SEQUENCE_ANY *a, unsigned char **out); extern const ASN1_ITEM ASN1_SET_ANY_it;

typedef struct NETSCAPE_X509_st
 {
 ASN1_OCTET_STRING *header;
 X509 *cert;
 } NETSCAPE_X509;


typedef struct BIT_STRING_BITNAME_st {
 int bitnum;
 const char *lname;
 const char *sname;
} BIT_STRING_BITNAME;

ASN1_TYPE *ASN1_TYPE_new(void); void ASN1_TYPE_free(ASN1_TYPE *a); ASN1_TYPE *d2i_ASN1_TYPE(ASN1_TYPE **a, const unsigned char **in, long len); int i2d_ASN1_TYPE(ASN1_TYPE *a, unsigned char **out); extern const ASN1_ITEM ASN1_ANY_it;

int ASN1_TYPE_get(ASN1_TYPE *a);
void ASN1_TYPE_set(ASN1_TYPE *a, int type, void *value);
int ASN1_TYPE_set1(ASN1_TYPE *a, int type, const void *value);
int ASN1_TYPE_cmp(const ASN1_TYPE *a, const ASN1_TYPE *b);

ASN1_OBJECT * ASN1_OBJECT_new(void );
void ASN1_OBJECT_free(ASN1_OBJECT *a);
int i2d_ASN1_OBJECT(ASN1_OBJECT *a,unsigned char **pp);
ASN1_OBJECT * c2i_ASN1_OBJECT(ASN1_OBJECT **a,const unsigned char **pp,
   long length);
ASN1_OBJECT * d2i_ASN1_OBJECT(ASN1_OBJECT **a,const unsigned char **pp,
   long length);

extern const ASN1_ITEM ASN1_OBJECT_it;

struct stack_st_ASN1_OBJECT { _STACK stack; };


ASN1_STRING * ASN1_STRING_new(void);
void ASN1_STRING_free(ASN1_STRING *a);
int ASN1_STRING_copy(ASN1_STRING *dst, const ASN1_STRING *str);
ASN1_STRING * ASN1_STRING_dup(const ASN1_STRING *a);
ASN1_STRING * ASN1_STRING_type_new(int type );
int ASN1_STRING_cmp(const ASN1_STRING *a, const ASN1_STRING *b);


int ASN1_STRING_set(ASN1_STRING *str, const void *data, int len);
void ASN1_STRING_set0(ASN1_STRING *str, void *data, int len);
int ASN1_STRING_length(const ASN1_STRING *x);
void ASN1_STRING_length_set(ASN1_STRING *x, int n);
int ASN1_STRING_type(ASN1_STRING *x);
unsigned char * ASN1_STRING_data(ASN1_STRING *x);

ASN1_BIT_STRING *ASN1_BIT_STRING_new(void); void ASN1_BIT_STRING_free(ASN1_BIT_STRING *a); ASN1_BIT_STRING *d2i_ASN1_BIT_STRING(ASN1_BIT_STRING **a, const unsigned char **in, long len); int i2d_ASN1_BIT_STRING(ASN1_BIT_STRING *a, unsigned char **out); extern const ASN1_ITEM ASN1_BIT_STRING_it;
int i2c_ASN1_BIT_STRING(ASN1_BIT_STRING *a,unsigned char **pp);
ASN1_BIT_STRING *c2i_ASN1_BIT_STRING(ASN1_BIT_STRING **a,const unsigned char **pp,
   long length);
int ASN1_BIT_STRING_set(ASN1_BIT_STRING *a, unsigned char *d,
   int length );
int ASN1_BIT_STRING_set_bit(ASN1_BIT_STRING *a, int n, int value);
int ASN1_BIT_STRING_get_bit(ASN1_BIT_STRING *a, int n);
int ASN1_BIT_STRING_check(ASN1_BIT_STRING *a,
                                     unsigned char *flags, int flags_len);


int ASN1_BIT_STRING_name_print(BIO *out, ASN1_BIT_STRING *bs,
    BIT_STRING_BITNAME *tbl, int indent);

int ASN1_BIT_STRING_num_asc(char *name, BIT_STRING_BITNAME *tbl);
int ASN1_BIT_STRING_set_asc(ASN1_BIT_STRING *bs, char *name, int value,
    BIT_STRING_BITNAME *tbl);

int i2d_ASN1_BOOLEAN(int a,unsigned char **pp);
int d2i_ASN1_BOOLEAN(int *a,const unsigned char **pp,long length);

ASN1_INTEGER *ASN1_INTEGER_new(void); void ASN1_INTEGER_free(ASN1_INTEGER *a); ASN1_INTEGER *d2i_ASN1_INTEGER(ASN1_INTEGER **a, const unsigned char **in, long len); int i2d_ASN1_INTEGER(ASN1_INTEGER *a, unsigned char **out); extern const ASN1_ITEM ASN1_INTEGER_it;
int i2c_ASN1_INTEGER(ASN1_INTEGER *a,unsigned char **pp);
ASN1_INTEGER *c2i_ASN1_INTEGER(ASN1_INTEGER **a,const unsigned char **pp,
   long length);
ASN1_INTEGER *d2i_ASN1_UINTEGER(ASN1_INTEGER **a,const unsigned char **pp,
   long length);
ASN1_INTEGER * ASN1_INTEGER_dup(const ASN1_INTEGER *x);
int ASN1_INTEGER_cmp(const ASN1_INTEGER *x, const ASN1_INTEGER *y);

ASN1_ENUMERATED *ASN1_ENUMERATED_new(void); void ASN1_ENUMERATED_free(ASN1_ENUMERATED *a); ASN1_ENUMERATED *d2i_ASN1_ENUMERATED(ASN1_ENUMERATED **a, const unsigned char **in, long len); int i2d_ASN1_ENUMERATED(ASN1_ENUMERATED *a, unsigned char **out); extern const ASN1_ITEM ASN1_ENUMERATED_it;

int ASN1_UTCTIME_check(ASN1_UTCTIME *a);
ASN1_UTCTIME *ASN1_UTCTIME_set(ASN1_UTCTIME *s,time_t t);
ASN1_UTCTIME *ASN1_UTCTIME_adj(ASN1_UTCTIME *s, time_t t,
    int offset_day, long offset_sec);
int ASN1_UTCTIME_set_string(ASN1_UTCTIME *s, const char *str);
int ASN1_UTCTIME_cmp_time_t(const ASN1_UTCTIME *s, time_t t);




int ASN1_GENERALIZEDTIME_check(ASN1_GENERALIZEDTIME *a);
ASN1_GENERALIZEDTIME *ASN1_GENERALIZEDTIME_set(ASN1_GENERALIZEDTIME *s,time_t t);
ASN1_GENERALIZEDTIME *ASN1_GENERALIZEDTIME_adj(ASN1_GENERALIZEDTIME *s,
      time_t t, int offset_day, long offset_sec);
int ASN1_GENERALIZEDTIME_set_string(ASN1_GENERALIZEDTIME *s, const char *str);

ASN1_OCTET_STRING *ASN1_OCTET_STRING_new(void); void ASN1_OCTET_STRING_free(ASN1_OCTET_STRING *a); ASN1_OCTET_STRING *d2i_ASN1_OCTET_STRING(ASN1_OCTET_STRING **a, const unsigned char **in, long len); int i2d_ASN1_OCTET_STRING(ASN1_OCTET_STRING *a, unsigned char **out); extern const ASN1_ITEM ASN1_OCTET_STRING_it;
ASN1_OCTET_STRING * ASN1_OCTET_STRING_dup(const ASN1_OCTET_STRING *a);
int ASN1_OCTET_STRING_cmp(const ASN1_OCTET_STRING *a, const ASN1_OCTET_STRING *b);
int ASN1_OCTET_STRING_set(ASN1_OCTET_STRING *str, const unsigned char *data, int len);

ASN1_VISIBLESTRING *ASN1_VISIBLESTRING_new(void); void ASN1_VISIBLESTRING_free(ASN1_VISIBLESTRING *a); ASN1_VISIBLESTRING *d2i_ASN1_VISIBLESTRING(ASN1_VISIBLESTRING **a, const unsigned char **in, long len); int i2d_ASN1_VISIBLESTRING(ASN1_VISIBLESTRING *a, unsigned char **out); extern const ASN1_ITEM ASN1_VISIBLESTRING_it;
ASN1_UNIVERSALSTRING *ASN1_UNIVERSALSTRING_new(void); void ASN1_UNIVERSALSTRING_free(ASN1_UNIVERSALSTRING *a); ASN1_UNIVERSALSTRING *d2i_ASN1_UNIVERSALSTRING(ASN1_UNIVERSALSTRING **a, const unsigned char **in, long len); int i2d_ASN1_UNIVERSALSTRING(ASN1_UNIVERSALSTRING *a, unsigned char **out); extern const ASN1_ITEM ASN1_UNIVERSALSTRING_it;
ASN1_UTF8STRING *ASN1_UTF8STRING_new(void); void ASN1_UTF8STRING_free(ASN1_UTF8STRING *a); ASN1_UTF8STRING *d2i_ASN1_UTF8STRING(ASN1_UTF8STRING **a, const unsigned char **in, long len); int i2d_ASN1_UTF8STRING(ASN1_UTF8STRING *a, unsigned char **out); extern const ASN1_ITEM ASN1_UTF8STRING_it;
ASN1_NULL *ASN1_NULL_new(void); void ASN1_NULL_free(ASN1_NULL *a); ASN1_NULL *d2i_ASN1_NULL(ASN1_NULL **a, const unsigned char **in, long len); int i2d_ASN1_NULL(ASN1_NULL *a, unsigned char **out); extern const ASN1_ITEM ASN1_NULL_it;
ASN1_BMPSTRING *ASN1_BMPSTRING_new(void); void ASN1_BMPSTRING_free(ASN1_BMPSTRING *a); ASN1_BMPSTRING *d2i_ASN1_BMPSTRING(ASN1_BMPSTRING **a, const unsigned char **in, long len); int i2d_ASN1_BMPSTRING(ASN1_BMPSTRING *a, unsigned char **out); extern const ASN1_ITEM ASN1_BMPSTRING_it;

int UTF8_getc(const unsigned char *str, int len, unsigned long *val);
int UTF8_putc(unsigned char *str, int len, unsigned long value);

ASN1_STRING *ASN1_PRINTABLE_new(void); void ASN1_PRINTABLE_free(ASN1_STRING *a); ASN1_STRING *d2i_ASN1_PRINTABLE(ASN1_STRING **a, const unsigned char **in, long len); int i2d_ASN1_PRINTABLE(ASN1_STRING *a, unsigned char **out); extern const ASN1_ITEM ASN1_PRINTABLE_it;

ASN1_STRING *DIRECTORYSTRING_new(void); void DIRECTORYSTRING_free(ASN1_STRING *a); ASN1_STRING *d2i_DIRECTORYSTRING(ASN1_STRING **a, const unsigned char **in, long len); int i2d_DIRECTORYSTRING(ASN1_STRING *a, unsigned char **out); extern const ASN1_ITEM DIRECTORYSTRING_it;
ASN1_STRING *DISPLAYTEXT_new(void); void DISPLAYTEXT_free(ASN1_STRING *a); ASN1_STRING *d2i_DISPLAYTEXT(ASN1_STRING **a, const unsigned char **in, long len); int i2d_DISPLAYTEXT(ASN1_STRING *a, unsigned char **out); extern const ASN1_ITEM DISPLAYTEXT_it;
ASN1_PRINTABLESTRING *ASN1_PRINTABLESTRING_new(void); void ASN1_PRINTABLESTRING_free(ASN1_PRINTABLESTRING *a); ASN1_PRINTABLESTRING *d2i_ASN1_PRINTABLESTRING(ASN1_PRINTABLESTRING **a, const unsigned char **in, long len); int i2d_ASN1_PRINTABLESTRING(ASN1_PRINTABLESTRING *a, unsigned char **out); extern const ASN1_ITEM ASN1_PRINTABLESTRING_it;
ASN1_T61STRING *ASN1_T61STRING_new(void); void ASN1_T61STRING_free(ASN1_T61STRING *a); ASN1_T61STRING *d2i_ASN1_T61STRING(ASN1_T61STRING **a, const unsigned char **in, long len); int i2d_ASN1_T61STRING(ASN1_T61STRING *a, unsigned char **out); extern const ASN1_ITEM ASN1_T61STRING_it;
ASN1_IA5STRING *ASN1_IA5STRING_new(void); void ASN1_IA5STRING_free(ASN1_IA5STRING *a); ASN1_IA5STRING *d2i_ASN1_IA5STRING(ASN1_IA5STRING **a, const unsigned char **in, long len); int i2d_ASN1_IA5STRING(ASN1_IA5STRING *a, unsigned char **out); extern const ASN1_ITEM ASN1_IA5STRING_it;
ASN1_GENERALSTRING *ASN1_GENERALSTRING_new(void); void ASN1_GENERALSTRING_free(ASN1_GENERALSTRING *a); ASN1_GENERALSTRING *d2i_ASN1_GENERALSTRING(ASN1_GENERALSTRING **a, const unsigned char **in, long len); int i2d_ASN1_GENERALSTRING(ASN1_GENERALSTRING *a, unsigned char **out); extern const ASN1_ITEM ASN1_GENERALSTRING_it;
ASN1_UTCTIME *ASN1_UTCTIME_new(void); void ASN1_UTCTIME_free(ASN1_UTCTIME *a); ASN1_UTCTIME *d2i_ASN1_UTCTIME(ASN1_UTCTIME **a, const unsigned char **in, long len); int i2d_ASN1_UTCTIME(ASN1_UTCTIME *a, unsigned char **out); extern const ASN1_ITEM ASN1_UTCTIME_it;
ASN1_GENERALIZEDTIME *ASN1_GENERALIZEDTIME_new(void); void ASN1_GENERALIZEDTIME_free(ASN1_GENERALIZEDTIME *a); ASN1_GENERALIZEDTIME *d2i_ASN1_GENERALIZEDTIME(ASN1_GENERALIZEDTIME **a, const unsigned char **in, long len); int i2d_ASN1_GENERALIZEDTIME(ASN1_GENERALIZEDTIME *a, unsigned char **out); extern const ASN1_ITEM ASN1_GENERALIZEDTIME_it;
ASN1_TIME *ASN1_TIME_new(void); void ASN1_TIME_free(ASN1_TIME *a); ASN1_TIME *d2i_ASN1_TIME(ASN1_TIME **a, const unsigned char **in, long len); int i2d_ASN1_TIME(ASN1_TIME *a, unsigned char **out); extern const ASN1_ITEM ASN1_TIME_it;

extern const ASN1_ITEM ASN1_OCTET_STRING_NDEF_it;

ASN1_TIME *ASN1_TIME_set(ASN1_TIME *s,time_t t);
ASN1_TIME *ASN1_TIME_adj(ASN1_TIME *s,time_t t,
    int offset_day, long offset_sec);
int ASN1_TIME_check(ASN1_TIME *t);
ASN1_GENERALIZEDTIME *ASN1_TIME_to_generalizedtime(ASN1_TIME *t, ASN1_GENERALIZEDTIME **out);
int ASN1_TIME_set_string(ASN1_TIME *s, const char *str);

int i2d_ASN1_SET(struct stack_st_OPENSSL_BLOCK *a, unsigned char **pp,
   i2d_of_void *i2d, int ex_tag, int ex_class,
   int is_set);
struct stack_st_OPENSSL_BLOCK *d2i_ASN1_SET(struct stack_st_OPENSSL_BLOCK **a,
         const unsigned char **pp,
         long length, d2i_of_void *d2i,
         void (*free_func)(OPENSSL_BLOCK), int ex_tag,
         int ex_class);


int i2a_ASN1_INTEGER(BIO *bp, ASN1_INTEGER *a);
int a2i_ASN1_INTEGER(BIO *bp,ASN1_INTEGER *bs,char *buf,int size);
int i2a_ASN1_ENUMERATED(BIO *bp, ASN1_ENUMERATED *a);
int a2i_ASN1_ENUMERATED(BIO *bp,ASN1_ENUMERATED *bs,char *buf,int size);
int i2a_ASN1_OBJECT(BIO *bp,ASN1_OBJECT *a);
int a2i_ASN1_STRING(BIO *bp,ASN1_STRING *bs,char *buf,int size);
int i2a_ASN1_STRING(BIO *bp, ASN1_STRING *a, int type);

int i2t_ASN1_OBJECT(char *buf,int buf_len,ASN1_OBJECT *a);

int a2d_ASN1_OBJECT(unsigned char *out,int olen, const char *buf, int num);
ASN1_OBJECT *ASN1_OBJECT_create(int nid, unsigned char *data,int len,
 const char *sn, const char *ln);

int ASN1_INTEGER_set(ASN1_INTEGER *a, long v);
long ASN1_INTEGER_get(const ASN1_INTEGER *a);
ASN1_INTEGER *BN_to_ASN1_INTEGER(const BIGNUM *bn, ASN1_INTEGER *ai);
BIGNUM *ASN1_INTEGER_to_BN(const ASN1_INTEGER *ai,BIGNUM *bn);

int ASN1_ENUMERATED_set(ASN1_ENUMERATED *a, long v);
long ASN1_ENUMERATED_get(ASN1_ENUMERATED *a);
ASN1_ENUMERATED *BN_to_ASN1_ENUMERATED(BIGNUM *bn, ASN1_ENUMERATED *ai);
BIGNUM *ASN1_ENUMERATED_to_BN(ASN1_ENUMERATED *ai,BIGNUM *bn);



int ASN1_PRINTABLE_type(const unsigned char *s, int max);

int i2d_ASN1_bytes(ASN1_STRING *a, unsigned char **pp, int tag, int xclass);
ASN1_STRING *d2i_ASN1_bytes(ASN1_STRING **a, const unsigned char **pp,
 long length, int Ptag, int Pclass);
unsigned long ASN1_tag2bit(int tag);

ASN1_STRING *d2i_ASN1_type_bytes(ASN1_STRING **a,const unsigned char **pp,
  long length,int type);


int asn1_Finish(ASN1_CTX *c);
int asn1_const_Finish(ASN1_const_CTX *c);


int ASN1_get_object(const unsigned char **pp, long *plength, int *ptag,
 int *pclass, long omax);
int ASN1_check_infinite_end(unsigned char **p,long len);
int ASN1_const_check_infinite_end(const unsigned char **p,long len);
void ASN1_put_object(unsigned char **pp, int constructed, int length,
 int tag, int xclass);
int ASN1_put_eoc(unsigned char **pp);
int ASN1_object_size(int constructed, int length, int tag);


void *ASN1_dup(i2d_of_void *i2d, d2i_of_void *d2i, void *x);

void *ASN1_item_dup(const ASN1_ITEM *it, void *x);

void *ASN1_d2i_fp(void *(*xnew)(void), d2i_of_void *d2i, FILE *in, void **x);







void *ASN1_item_d2i_fp(const ASN1_ITEM *it, FILE *in, void *x);
int ASN1_i2d_fp(i2d_of_void *i2d,FILE *out,void *x);

int ASN1_item_i2d_fp(const ASN1_ITEM *it, FILE *out, void *x);
int ASN1_STRING_print_ex_fp(FILE *fp, ASN1_STRING *str, unsigned long flags);


int ASN1_STRING_to_UTF8(unsigned char **out, ASN1_STRING *in);


void *ASN1_d2i_bio(void *(*xnew)(void), d2i_of_void *d2i, BIO *in, void **x);







void *ASN1_item_d2i_bio(const ASN1_ITEM *it, BIO *in, void *x);
int ASN1_i2d_bio(i2d_of_void *i2d,BIO *out, unsigned char *x);

int ASN1_item_i2d_bio(const ASN1_ITEM *it, BIO *out, void *x);
int ASN1_UTCTIME_print(BIO *fp, const ASN1_UTCTIME *a);
int ASN1_GENERALIZEDTIME_print(BIO *fp, const ASN1_GENERALIZEDTIME *a);
int ASN1_TIME_print(BIO *fp, const ASN1_TIME *a);
int ASN1_STRING_print(BIO *bp, const ASN1_STRING *v);
int ASN1_STRING_print_ex(BIO *out, ASN1_STRING *str, unsigned long flags);
int ASN1_bn_print(BIO *bp, const char *number, const BIGNUM *num,
    unsigned char *buf, int off);
int ASN1_parse(BIO *bp,const unsigned char *pp,long len,int indent);
int ASN1_parse_dump(BIO *bp,const unsigned char *pp,long len,int indent,int dump);

const char *ASN1_tag2str(int tag);



NETSCAPE_X509 *NETSCAPE_X509_new(void); void NETSCAPE_X509_free(NETSCAPE_X509 *a); NETSCAPE_X509 *d2i_NETSCAPE_X509(NETSCAPE_X509 **a, const unsigned char **in, long len); int i2d_NETSCAPE_X509(NETSCAPE_X509 *a, unsigned char **out); extern const ASN1_ITEM NETSCAPE_X509_it;

int ASN1_UNIVERSALSTRING_to_string(ASN1_UNIVERSALSTRING *s);

int ASN1_TYPE_set_octetstring(ASN1_TYPE *a,
 unsigned char *data, int len);
int ASN1_TYPE_get_octetstring(ASN1_TYPE *a,
 unsigned char *data, int max_len);
int ASN1_TYPE_set_int_octetstring(ASN1_TYPE *a, long num,
 unsigned char *data, int len);
int ASN1_TYPE_get_int_octetstring(ASN1_TYPE *a,long *num,
 unsigned char *data, int max_len);

struct stack_st_OPENSSL_BLOCK *ASN1_seq_unpack(const unsigned char *buf, int len,
     d2i_of_void *d2i, void (*free_func)(OPENSSL_BLOCK));
unsigned char *ASN1_seq_pack(struct stack_st_OPENSSL_BLOCK *safes, i2d_of_void *i2d,
        unsigned char **buf, int *len );
void *ASN1_unpack_string(ASN1_STRING *oct, d2i_of_void *d2i);
void *ASN1_item_unpack(ASN1_STRING *oct, const ASN1_ITEM *it);
ASN1_STRING *ASN1_pack_string(void *obj, i2d_of_void *i2d,
         ASN1_OCTET_STRING **oct);






ASN1_STRING *ASN1_item_pack(void *obj, const ASN1_ITEM *it, ASN1_OCTET_STRING **oct);

void ASN1_STRING_set_default_mask(unsigned long mask);
int ASN1_STRING_set_default_mask_asc(const char *p);
unsigned long ASN1_STRING_get_default_mask(void);
int ASN1_mbstring_copy(ASN1_STRING **out, const unsigned char *in, int len,
     int inform, unsigned long mask);
int ASN1_mbstring_ncopy(ASN1_STRING **out, const unsigned char *in, int len,
     int inform, unsigned long mask,
     long minsize, long maxsize);

ASN1_STRING *ASN1_STRING_set_by_NID(ASN1_STRING **out,
  const unsigned char *in, int inlen, int inform, int nid);
ASN1_STRING_TABLE *ASN1_STRING_TABLE_get(int nid);
int ASN1_STRING_TABLE_add(int, long, long, unsigned long, unsigned long);
void ASN1_STRING_TABLE_cleanup(void);




ASN1_VALUE *ASN1_item_new(const ASN1_ITEM *it);
void ASN1_item_free(ASN1_VALUE *val, const ASN1_ITEM *it);
ASN1_VALUE * ASN1_item_d2i(ASN1_VALUE **val, const unsigned char **in, long len, const ASN1_ITEM *it);
int ASN1_item_i2d(ASN1_VALUE *val, unsigned char **out, const ASN1_ITEM *it);
int ASN1_item_ndef_i2d(ASN1_VALUE *val, unsigned char **out, const ASN1_ITEM *it);

void ASN1_add_oid_module(void);

ASN1_TYPE *ASN1_generate_nconf(char *str, CONF *nconf);
ASN1_TYPE *ASN1_generate_v3(char *str, X509V3_CTX *cnf);

int ASN1_item_print(BIO *out, ASN1_VALUE *ifld, int indent,
    const ASN1_ITEM *it, const ASN1_PCTX *pctx);
ASN1_PCTX *ASN1_PCTX_new(void);
void ASN1_PCTX_free(ASN1_PCTX *p);
unsigned long ASN1_PCTX_get_flags(ASN1_PCTX *p);
void ASN1_PCTX_set_flags(ASN1_PCTX *p, unsigned long flags);
unsigned long ASN1_PCTX_get_nm_flags(ASN1_PCTX *p);
void ASN1_PCTX_set_nm_flags(ASN1_PCTX *p, unsigned long flags);
unsigned long ASN1_PCTX_get_cert_flags(ASN1_PCTX *p);
void ASN1_PCTX_set_cert_flags(ASN1_PCTX *p, unsigned long flags);
unsigned long ASN1_PCTX_get_oid_flags(ASN1_PCTX *p);
void ASN1_PCTX_set_oid_flags(ASN1_PCTX *p, unsigned long flags);
unsigned long ASN1_PCTX_get_str_flags(ASN1_PCTX *p);
void ASN1_PCTX_set_str_flags(ASN1_PCTX *p, unsigned long flags);

BIO_METHOD *BIO_f_asn1(void);

BIO *BIO_new_NDEF(BIO *out, ASN1_VALUE *val, const ASN1_ITEM *it);

int i2d_ASN1_bio_stream(BIO *out, ASN1_VALUE *val, BIO *in, int flags,
    const ASN1_ITEM *it);
int PEM_write_bio_ASN1_stream(BIO *out, ASN1_VALUE *val, BIO *in, int flags,
    const char *hdr,
    const ASN1_ITEM *it);
int SMIME_write_ASN1(BIO *bio, ASN1_VALUE *val, BIO *data, int flags,
    int ctype_nid, int econt_nid,
    struct stack_st_X509_ALGOR *mdalgs,
    const ASN1_ITEM *it);
ASN1_VALUE *SMIME_read_ASN1(BIO *bio, BIO **bcont, const ASN1_ITEM *it);
int SMIME_crlf_copy(BIO *in, BIO *out, int flags);
int SMIME_text(BIO *in, BIO *out);





void ERR_load_ASN1_strings(void);



int asn1_GetSequence(ASN1_const_CTX *c, long *length);
void asn1_add_error(const unsigned char *address,int offset);











struct ASN1_TEMPLATE_st {
unsigned long flags;
long tag;
unsigned long offset;

const char *field_name;

ASN1_ITEM_EXP *item;
};






typedef struct ASN1_ADB_TABLE_st ASN1_ADB_TABLE;
typedef struct ASN1_ADB_st ASN1_ADB;

struct ASN1_ADB_st {
 unsigned long flags;
 unsigned long offset;
 struct stack_st_ASN1_ADB_TABLE **app_items;
 const ASN1_ADB_TABLE *tbl;
 long tblcount;
 const ASN1_TEMPLATE *default_tt;
 const ASN1_TEMPLATE *null_tt;
};

struct ASN1_ADB_TABLE_st {
 long value;
 const ASN1_TEMPLATE tt;
};

struct ASN1_ITEM_st {
char itype;
long utype;
const ASN1_TEMPLATE *templates;
long tcount;
const void *funcs;
long size;

const char *sname;

};

struct ASN1_TLC_st{
 char valid;
 int ret;
 long plen;
 int ptag;
 int pclass;
 int hdrlen;
};



typedef ASN1_VALUE * ASN1_new_func(void);
typedef void ASN1_free_func(ASN1_VALUE *a);
typedef ASN1_VALUE * ASN1_d2i_func(ASN1_VALUE **a, const unsigned char ** in, long length);
typedef int ASN1_i2d_func(ASN1_VALUE * a, unsigned char **in);

typedef int ASN1_ex_d2i(ASN1_VALUE **pval, const unsigned char **in, long len, const ASN1_ITEM *it,
     int tag, int aclass, char opt, ASN1_TLC *ctx);

typedef int ASN1_ex_i2d(ASN1_VALUE **pval, unsigned char **out, const ASN1_ITEM *it, int tag, int aclass);
typedef int ASN1_ex_new_func(ASN1_VALUE **pval, const ASN1_ITEM *it);
typedef void ASN1_ex_free_func(ASN1_VALUE **pval, const ASN1_ITEM *it);

typedef int ASN1_ex_print_func(BIO *out, ASN1_VALUE **pval,
      int indent, const char *fname,
      const ASN1_PCTX *pctx);

typedef int ASN1_primitive_i2c(ASN1_VALUE **pval, unsigned char *cont, int *putype, const ASN1_ITEM *it);
typedef int ASN1_primitive_c2i(ASN1_VALUE **pval, const unsigned char *cont, int len, int utype, char *free_cont, const ASN1_ITEM *it);
typedef int ASN1_primitive_print(BIO *out, ASN1_VALUE **pval, const ASN1_ITEM *it, int indent, const ASN1_PCTX *pctx);

typedef struct ASN1_COMPAT_FUNCS_st {
 ASN1_new_func *asn1_new;
 ASN1_free_func *asn1_free;
 ASN1_d2i_func *asn1_d2i;
 ASN1_i2d_func *asn1_i2d;
} ASN1_COMPAT_FUNCS;

typedef struct ASN1_EXTERN_FUNCS_st {
 void *app_data;
 ASN1_ex_new_func *asn1_ex_new;
 ASN1_ex_free_func *asn1_ex_free;
 ASN1_ex_free_func *asn1_ex_clear;
 ASN1_ex_d2i *asn1_ex_d2i;
 ASN1_ex_i2d *asn1_ex_i2d;
 ASN1_ex_print_func *asn1_ex_print;
} ASN1_EXTERN_FUNCS;

typedef struct ASN1_PRIMITIVE_FUNCS_st {
 void *app_data;
 unsigned long flags;
 ASN1_ex_new_func *prim_new;
 ASN1_ex_free_func *prim_free;
 ASN1_ex_free_func *prim_clear;
 ASN1_primitive_c2i *prim_c2i;
 ASN1_primitive_i2c *prim_i2c;
 ASN1_primitive_print *prim_print;
} ASN1_PRIMITIVE_FUNCS;

typedef int ASN1_aux_cb(int operation, ASN1_VALUE **in, const ASN1_ITEM *it,
    void *exarg);

typedef struct ASN1_AUX_st {
 void *app_data;
 int flags;
 int ref_offset;
 int ref_lock;
 ASN1_aux_cb *asn1_cb;
 int enc_offset;
} ASN1_AUX;


typedef struct ASN1_PRINT_ARG_st {
 BIO *out;
 int indent;
 const ASN1_PCTX *pctx;
} ASN1_PRINT_ARG;


typedef struct ASN1_STREAM_ARG_st {

 BIO *out;

 BIO *ndef_bio;

 unsigned char **boundary;
} ASN1_STREAM_ARG;

extern const ASN1_ITEM ASN1_BOOLEAN_it;
extern const ASN1_ITEM ASN1_TBOOLEAN_it;
extern const ASN1_ITEM ASN1_FBOOLEAN_it;
extern const ASN1_ITEM ASN1_SEQUENCE_it;
extern const ASN1_ITEM CBIGNUM_it;
extern const ASN1_ITEM BIGNUM_it;
extern const ASN1_ITEM LONG_it;
extern const ASN1_ITEM ZLONG_it;

struct stack_st_ASN1_VALUE { _STACK stack; };



int ASN1_item_ex_new(ASN1_VALUE **pval, const ASN1_ITEM *it);
void ASN1_item_ex_free(ASN1_VALUE **pval, const ASN1_ITEM *it);
int ASN1_template_new(ASN1_VALUE **pval, const ASN1_TEMPLATE *tt);
int ASN1_primitive_new(ASN1_VALUE **pval, const ASN1_ITEM *it);

void ASN1_template_free(ASN1_VALUE **pval, const ASN1_TEMPLATE *tt);
int ASN1_template_d2i(ASN1_VALUE **pval, const unsigned char **in, long len, const ASN1_TEMPLATE *tt);
int ASN1_item_ex_d2i(ASN1_VALUE **pval, const unsigned char **in, long len, const ASN1_ITEM *it,
    int tag, int aclass, char opt, ASN1_TLC *ctx);

int ASN1_item_ex_i2d(ASN1_VALUE **pval, unsigned char **out, const ASN1_ITEM *it, int tag, int aclass);
int ASN1_template_i2d(ASN1_VALUE **pval, unsigned char **out, const ASN1_TEMPLATE *tt);
void ASN1_primitive_free(ASN1_VALUE **pval, const ASN1_ITEM *it);

int asn1_ex_i2c(ASN1_VALUE **pval, unsigned char *cont, int *putype, const ASN1_ITEM *it);
int asn1_ex_c2i(ASN1_VALUE **pval, const unsigned char *cont, int len, int utype, char *free_cont, const ASN1_ITEM *it);

int asn1_get_choice_selector(ASN1_VALUE **pval, const ASN1_ITEM *it);
int asn1_set_choice_selector(ASN1_VALUE **pval, int value, const ASN1_ITEM *it);

ASN1_VALUE ** asn1_get_field_ptr(ASN1_VALUE **pval, const ASN1_TEMPLATE *tt);

const ASN1_TEMPLATE *asn1_do_adb(ASN1_VALUE **pval, const ASN1_TEMPLATE *tt, int nullerr);

int asn1_do_lock(ASN1_VALUE **pval, int op, const ASN1_ITEM *it);

void asn1_enc_init(ASN1_VALUE **pval, const ASN1_ITEM *it);
void asn1_enc_free(ASN1_VALUE **pval, const ASN1_ITEM *it);
int asn1_enc_restore(int *len, unsigned char **out, ASN1_VALUE **pval, const ASN1_ITEM *it);
int asn1_enc_save(ASN1_VALUE **pval, const unsigned char *in, int inlen, const ASN1_ITEM *it);










typedef struct bf_key_st
 {
 unsigned int P[16 +2];
 unsigned int S[4*256];
 } BF_KEY;




void BF_set_key(BF_KEY *key, int len, const unsigned char *data);

void BF_encrypt(unsigned int *data,const BF_KEY *key);
void BF_decrypt(unsigned int *data,const BF_KEY *key);

void BF_ecb_encrypt(const unsigned char *in, unsigned char *out,
 const BF_KEY *key, int enc);
void BF_cbc_encrypt(const unsigned char *in, unsigned char *out, long length,
 const BF_KEY *schedule, unsigned char *ivec, int enc);
void BF_cfb64_encrypt(const unsigned char *in, unsigned char *out, long length,
 const BF_KEY *schedule, unsigned char *ivec, int *num, int enc);
void BF_ofb64_encrypt(const unsigned char *in, unsigned char *out, long length,
 const BF_KEY *schedule, unsigned char *ivec, int *num);
const char *BF_options(void);







struct buf_mem_st
 {
 size_t length;
 char *data;
 size_t max;
 };

BUF_MEM *BUF_MEM_new(void);
void BUF_MEM_free(BUF_MEM *a);
int BUF_MEM_grow(BUF_MEM *str, size_t len);
int BUF_MEM_grow_clean(BUF_MEM *str, size_t len);
char * BUF_strdup(const char *str);
char * BUF_strndup(const char *str, size_t siz);
void * BUF_memdup(const void *data, size_t siz);
void BUF_reverse(unsigned char *out, const unsigned char *in, size_t siz);


size_t BUF_strlcpy(char *dst,const char *src,size_t siz);
size_t BUF_strlcat(char *dst,const char *src,size_t siz);






void ERR_load_BUF_strings(void);













typedef unsigned int KEY_TABLE_TYPE[(272 / 4)];

struct camellia_key_st
 {
 union {
  double d;
  KEY_TABLE_TYPE rd_key;
  } u;
 int grand_rounds;
 };
typedef struct camellia_key_st CAMELLIA_KEY;





int Camellia_set_key(const unsigned char *userKey, const int bits,
 CAMELLIA_KEY *key);

void Camellia_encrypt(const unsigned char *in, unsigned char *out,
 const CAMELLIA_KEY *key);
void Camellia_decrypt(const unsigned char *in, unsigned char *out,
 const CAMELLIA_KEY *key);

void Camellia_ecb_encrypt(const unsigned char *in, unsigned char *out,
 const CAMELLIA_KEY *key, const int enc);
void Camellia_cbc_encrypt(const unsigned char *in, unsigned char *out,
 size_t length, const CAMELLIA_KEY *key,
 unsigned char *ivec, const int enc);
void Camellia_cfb128_encrypt(const unsigned char *in, unsigned char *out,
 size_t length, const CAMELLIA_KEY *key,
 unsigned char *ivec, int *num, const int enc);
void Camellia_cfb1_encrypt(const unsigned char *in, unsigned char *out,
 size_t length, const CAMELLIA_KEY *key,
 unsigned char *ivec, int *num, const int enc);
void Camellia_cfb8_encrypt(const unsigned char *in, unsigned char *out,
 size_t length, const CAMELLIA_KEY *key,
 unsigned char *ivec, int *num, const int enc);
void Camellia_ofb128_encrypt(const unsigned char *in, unsigned char *out,
 size_t length, const CAMELLIA_KEY *key,
 unsigned char *ivec, int *num);
void Camellia_ctr128_encrypt(const unsigned char *in, unsigned char *out,
 size_t length, const CAMELLIA_KEY *key,
 unsigned char ivec[16],
 unsigned char ecount_buf[16],
 unsigned int *num);






typedef struct cast_key_st
 {
 unsigned int data[32];
 int short_key;
 } CAST_KEY;




void CAST_set_key(CAST_KEY *key, int len, const unsigned char *data);
void CAST_ecb_encrypt(const unsigned char *in, unsigned char *out, const CAST_KEY *key,
        int enc);
void CAST_encrypt(unsigned int *data, const CAST_KEY *key);
void CAST_decrypt(unsigned int *data, const CAST_KEY *key);
void CAST_cbc_encrypt(const unsigned char *in, unsigned char *out, long length,
        const CAST_KEY *ks, unsigned char *iv, int enc);
void CAST_cfb64_encrypt(const unsigned char *in, unsigned char *out,
   long length, const CAST_KEY *schedule, unsigned char *ivec,
   int *num, int enc);
void CAST_ofb64_encrypt(const unsigned char *in, unsigned char *out,
   long length, const CAST_KEY *schedule, unsigned char *ivec,
   int *num);













typedef struct obj_name_st
 {
 int type;
 int alias;
 const char *name;
 const char *data;
 } OBJ_NAME;




int OBJ_NAME_init(void);
int OBJ_NAME_new_index(unsigned long (*hash_func)(const char *),
         int (*cmp_func)(const char *, const char *),
         void (*free_func)(const char *, int, const char *));
const char *OBJ_NAME_get(const char *name,int type);
int OBJ_NAME_add(const char *name,int type,const char *data);
int OBJ_NAME_remove(const char *name,int type);
void OBJ_NAME_cleanup(int type);
void OBJ_NAME_do_all(int type,void (*fn)(const OBJ_NAME *,void *arg),
       void *arg);
void OBJ_NAME_do_all_sorted(int type,void (*fn)(const OBJ_NAME *,void *arg),
       void *arg);

ASN1_OBJECT * OBJ_dup(const ASN1_OBJECT *o);
ASN1_OBJECT * OBJ_nid2obj(int n);
const char * OBJ_nid2ln(int n);
const char * OBJ_nid2sn(int n);
int OBJ_obj2nid(const ASN1_OBJECT *o);
ASN1_OBJECT * OBJ_txt2obj(const char *s, int no_name);
int OBJ_obj2txt(char *buf, int buf_len, const ASN1_OBJECT *a, int no_name);
int OBJ_txt2nid(const char *s);
int OBJ_ln2nid(const char *s);
int OBJ_sn2nid(const char *s);
int OBJ_cmp(const ASN1_OBJECT *a,const ASN1_OBJECT *b);
const void * OBJ_bsearch_(const void *key,const void *base,int num,int size,
        int (*cmp)(const void *, const void *));
const void * OBJ_bsearch_ex_(const void *key,const void *base,int num,
    int size,
    int (*cmp)(const void *, const void *),
    int flags);

int OBJ_new_nid(int num);
int OBJ_add_object(const ASN1_OBJECT *obj);
int OBJ_create(const char *oid,const char *sn,const char *ln);
void OBJ_cleanup(void );
int OBJ_create_objects(BIO *in);

int OBJ_find_sigid_algs(int signid, int *pdig_nid, int *ppkey_nid);
int OBJ_find_sigid_by_algs(int *psignid, int dig_nid, int pkey_nid);
int OBJ_add_sigid(int signid, int dig_id, int pkey_id);
void OBJ_sigid_free(void);

extern int obj_cleanup_defer;
void check_defer(int nid);





void ERR_load_OBJ_strings(void);


struct evp_pkey_st
 {
 int type;
 int save_type;
 int references;
 const EVP_PKEY_ASN1_METHOD *ameth;
 ENGINE *engine;
 union {
  char *ptr;

  struct rsa_st *rsa;


  struct dsa_st *dsa;


  struct dh_st *dh;


  struct ec_key_st *ec;

  } pkey;
 int save_parameters;
 struct stack_st_X509_ATTRIBUTE *attributes;
 } ;







struct env_md_st
 {
 int type;
 int pkey_type;
 int md_size;
 unsigned long flags;
 int (*init)(EVP_MD_CTX *ctx);
 int (*update)(EVP_MD_CTX *ctx,const void *data,size_t count);
 int (*final)(EVP_MD_CTX *ctx,unsigned char *md);
 int (*copy)(EVP_MD_CTX *to,const EVP_MD_CTX *from);
 int (*cleanup)(EVP_MD_CTX *ctx);


 int (*sign)(int type, const unsigned char *m, unsigned int m_length,
      unsigned char *sigret, unsigned int *siglen, void *key);
 int (*verify)(int type, const unsigned char *m, unsigned int m_length,
        const unsigned char *sigbuf, unsigned int siglen,
        void *key);
 int required_pkey_type[5];
 int block_size;
 int ctx_size;

 int (*md_ctrl)(EVP_MD_CTX *ctx, int cmd, int p1, void *p2);
 } ;

typedef int evp_sign_method(int type,const unsigned char *m,
       unsigned int m_length,unsigned char *sigret,
       unsigned int *siglen, void *key);
typedef int evp_verify_method(int type,const unsigned char *m,
       unsigned int m_length,const unsigned char *sigbuf,
       unsigned int siglen, void *key);

struct env_md_ctx_st
 {
 const EVP_MD *digest;
 ENGINE *engine;
 unsigned long flags;
 void *md_data;

 EVP_PKEY_CTX *pctx;

 int (*update)(EVP_MD_CTX *ctx,const void *data,size_t count);
 } ;

struct evp_cipher_st
 {
 int nid;
 int block_size;
 int key_len;
 int iv_len;
 unsigned long flags;
 int (*init)(EVP_CIPHER_CTX *ctx, const unsigned char *key,
      const unsigned char *iv, int enc);
 int (*do_cipher)(EVP_CIPHER_CTX *ctx, unsigned char *out,
    const unsigned char *in, size_t inl);
 int (*cleanup)(EVP_CIPHER_CTX *);
 int ctx_size;
 int (*set_asn1_parameters)(EVP_CIPHER_CTX *, ASN1_TYPE *);
 int (*get_asn1_parameters)(EVP_CIPHER_CTX *, ASN1_TYPE *);
 int (*ctrl)(EVP_CIPHER_CTX *, int type, int arg, void *ptr);
 void *app_data;
 } ;

typedef struct evp_cipher_info_st
 {
 const EVP_CIPHER *cipher;
 unsigned char iv[16];
 } EVP_CIPHER_INFO;

struct evp_cipher_ctx_st
 {
 const EVP_CIPHER *cipher;
 ENGINE *engine;
 int encrypt;
 int buf_len;

 unsigned char oiv[16];
 unsigned char iv[16];
 unsigned char buf[32];
 int num;

 void *app_data;
 int key_len;
 unsigned long flags;
 void *cipher_data;
 int final_used;
 int block_mask;
 unsigned char final[32];
 } ;

typedef struct evp_Encode_Ctx_st
 {
 int num;
 int length;




 unsigned char enc_data[80];
 int line_num;
 int expect_nl;
 } EVP_ENCODE_CTX;


typedef int (EVP_PBE_KEYGEN)(EVP_CIPHER_CTX *ctx, const char *pass, int passlen,
  ASN1_TYPE *param, const EVP_CIPHER *cipher,
                const EVP_MD *md, int en_de);

int EVP_MD_type(const EVP_MD *md);


int EVP_MD_pkey_type(const EVP_MD *md);
int EVP_MD_size(const EVP_MD *md);
int EVP_MD_block_size(const EVP_MD *md);
unsigned long EVP_MD_flags(const EVP_MD *md);

const EVP_MD *EVP_MD_CTX_md(const EVP_MD_CTX *ctx);




int EVP_CIPHER_nid(const EVP_CIPHER *cipher);

int EVP_CIPHER_block_size(const EVP_CIPHER *cipher);
int EVP_CIPHER_key_length(const EVP_CIPHER *cipher);
int EVP_CIPHER_iv_length(const EVP_CIPHER *cipher);
unsigned long EVP_CIPHER_flags(const EVP_CIPHER *cipher);


const EVP_CIPHER * EVP_CIPHER_CTX_cipher(const EVP_CIPHER_CTX *ctx);
int EVP_CIPHER_CTX_nid(const EVP_CIPHER_CTX *ctx);
int EVP_CIPHER_CTX_block_size(const EVP_CIPHER_CTX *ctx);
int EVP_CIPHER_CTX_key_length(const EVP_CIPHER_CTX *ctx);
int EVP_CIPHER_CTX_iv_length(const EVP_CIPHER_CTX *ctx);
int EVP_CIPHER_CTX_copy(EVP_CIPHER_CTX *out, const EVP_CIPHER_CTX *in);
void * EVP_CIPHER_CTX_get_app_data(const EVP_CIPHER_CTX *ctx);
void EVP_CIPHER_CTX_set_app_data(EVP_CIPHER_CTX *ctx, void *data);

unsigned long EVP_CIPHER_CTX_flags(const EVP_CIPHER_CTX *ctx);

int EVP_Cipher(EVP_CIPHER_CTX *c,
  unsigned char *out,
  const unsigned char *in,
  unsigned int inl);

void EVP_MD_CTX_init(EVP_MD_CTX *ctx);
int EVP_MD_CTX_cleanup(EVP_MD_CTX *ctx);
EVP_MD_CTX *EVP_MD_CTX_create(void);
void EVP_MD_CTX_destroy(EVP_MD_CTX *ctx);
int EVP_MD_CTX_copy_ex(EVP_MD_CTX *out,const EVP_MD_CTX *in);
void EVP_MD_CTX_set_flags(EVP_MD_CTX *ctx, int flags);
void EVP_MD_CTX_clear_flags(EVP_MD_CTX *ctx, int flags);
int EVP_MD_CTX_test_flags(const EVP_MD_CTX *ctx,int flags);
int EVP_DigestInit_ex(EVP_MD_CTX *ctx, const EVP_MD *type, ENGINE *impl);
int EVP_DigestUpdate(EVP_MD_CTX *ctx,const void *d,
    size_t cnt);
int EVP_DigestFinal_ex(EVP_MD_CTX *ctx,unsigned char *md,unsigned int *s);
int EVP_Digest(const void *data, size_t count,
  unsigned char *md, unsigned int *size, const EVP_MD *type, ENGINE *impl);

int EVP_MD_CTX_copy(EVP_MD_CTX *out,const EVP_MD_CTX *in);
int EVP_DigestInit(EVP_MD_CTX *ctx, const EVP_MD *type);
int EVP_DigestFinal(EVP_MD_CTX *ctx,unsigned char *md,unsigned int *s);

int EVP_read_pw_string(char *buf,int length,const char *prompt,int verify);
int EVP_read_pw_string_min(char *buf,int minlen,int maxlen,const char *prompt,int verify);
void EVP_set_pw_prompt(const char *prompt);
char * EVP_get_pw_prompt(void);

int EVP_BytesToKey(const EVP_CIPHER *type,const EVP_MD *md,
  const unsigned char *salt, const unsigned char *data,
  int datal, int count, unsigned char *key,unsigned char *iv);

void EVP_CIPHER_CTX_set_flags(EVP_CIPHER_CTX *ctx, int flags);
void EVP_CIPHER_CTX_clear_flags(EVP_CIPHER_CTX *ctx, int flags);
int EVP_CIPHER_CTX_test_flags(const EVP_CIPHER_CTX *ctx,int flags);

int EVP_EncryptInit(EVP_CIPHER_CTX *ctx,const EVP_CIPHER *cipher,
  const unsigned char *key, const unsigned char *iv);
int EVP_EncryptInit_ex(EVP_CIPHER_CTX *ctx,const EVP_CIPHER *cipher, ENGINE *impl,
  const unsigned char *key, const unsigned char *iv);
int EVP_EncryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
  int *outl, const unsigned char *in, int inl);
int EVP_EncryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl);
int EVP_EncryptFinal(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl);

int EVP_DecryptInit(EVP_CIPHER_CTX *ctx,const EVP_CIPHER *cipher,
  const unsigned char *key, const unsigned char *iv);
int EVP_DecryptInit_ex(EVP_CIPHER_CTX *ctx,const EVP_CIPHER *cipher, ENGINE *impl,
  const unsigned char *key, const unsigned char *iv);
int EVP_DecryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
  int *outl, const unsigned char *in, int inl);
int EVP_DecryptFinal(EVP_CIPHER_CTX *ctx, unsigned char *outm, int *outl);
int EVP_DecryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *outm, int *outl);

int EVP_CipherInit(EVP_CIPHER_CTX *ctx,const EVP_CIPHER *cipher,
         const unsigned char *key,const unsigned char *iv,
         int enc);
int EVP_CipherInit_ex(EVP_CIPHER_CTX *ctx,const EVP_CIPHER *cipher, ENGINE *impl,
         const unsigned char *key,const unsigned char *iv,
         int enc);
int EVP_CipherUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
  int *outl, const unsigned char *in, int inl);
int EVP_CipherFinal(EVP_CIPHER_CTX *ctx, unsigned char *outm, int *outl);
int EVP_CipherFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *outm, int *outl);

int EVP_SignFinal(EVP_MD_CTX *ctx,unsigned char *md,unsigned int *s,
  EVP_PKEY *pkey);

int EVP_VerifyFinal(EVP_MD_CTX *ctx,const unsigned char *sigbuf,
  unsigned int siglen,EVP_PKEY *pkey);

int EVP_DigestSignInit(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx,
   const EVP_MD *type, ENGINE *e, EVP_PKEY *pkey);
int EVP_DigestSignFinal(EVP_MD_CTX *ctx,
   unsigned char *sigret, size_t *siglen);

int EVP_DigestVerifyInit(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx,
   const EVP_MD *type, ENGINE *e, EVP_PKEY *pkey);
int EVP_DigestVerifyFinal(EVP_MD_CTX *ctx,
   unsigned char *sig, size_t siglen);

int EVP_OpenInit(EVP_CIPHER_CTX *ctx,const EVP_CIPHER *type,
  const unsigned char *ek, int ekl, const unsigned char *iv,
  EVP_PKEY *priv);
int EVP_OpenFinal(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl);

int EVP_SealInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
   unsigned char **ek, int *ekl, unsigned char *iv,
  EVP_PKEY **pubk, int npubk);
int EVP_SealFinal(EVP_CIPHER_CTX *ctx,unsigned char *out,int *outl);

void EVP_EncodeInit(EVP_ENCODE_CTX *ctx);
void EVP_EncodeUpdate(EVP_ENCODE_CTX *ctx,unsigned char *out,int *outl,
  const unsigned char *in,int inl);
void EVP_EncodeFinal(EVP_ENCODE_CTX *ctx,unsigned char *out,int *outl);
int EVP_EncodeBlock(unsigned char *t, const unsigned char *f, int n);

void EVP_DecodeInit(EVP_ENCODE_CTX *ctx);
int EVP_DecodeUpdate(EVP_ENCODE_CTX *ctx,unsigned char *out,int *outl,
  const unsigned char *in, int inl);
int EVP_DecodeFinal(EVP_ENCODE_CTX *ctx, unsigned
  char *out, int *outl);
int EVP_DecodeBlock(unsigned char *t, const unsigned char *f, int n);

void EVP_CIPHER_CTX_init(EVP_CIPHER_CTX *a);
int EVP_CIPHER_CTX_cleanup(EVP_CIPHER_CTX *a);
EVP_CIPHER_CTX *EVP_CIPHER_CTX_new(void);
void EVP_CIPHER_CTX_free(EVP_CIPHER_CTX *a);
int EVP_CIPHER_CTX_set_key_length(EVP_CIPHER_CTX *x, int keylen);
int EVP_CIPHER_CTX_set_padding(EVP_CIPHER_CTX *c, int pad);
int EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr);
int EVP_CIPHER_CTX_rand_key(EVP_CIPHER_CTX *ctx, unsigned char *key);


BIO_METHOD *BIO_f_md(void);
BIO_METHOD *BIO_f_base64(void);
BIO_METHOD *BIO_f_cipher(void);
BIO_METHOD *BIO_f_reliable(void);
void BIO_set_cipher(BIO *b,const EVP_CIPHER *c,const unsigned char *k,
  const unsigned char *i, int enc);


const EVP_MD *EVP_md_null(void);




const EVP_MD *EVP_md4(void);


const EVP_MD *EVP_md5(void);


const EVP_MD *EVP_sha(void);
const EVP_MD *EVP_sha1(void);
const EVP_MD *EVP_dss(void);
const EVP_MD *EVP_dss1(void);
const EVP_MD *EVP_ecdsa(void);


const EVP_MD *EVP_sha224(void);
const EVP_MD *EVP_sha256(void);


const EVP_MD *EVP_sha384(void);
const EVP_MD *EVP_sha512(void);





const EVP_MD *EVP_ripemd160(void);


const EVP_MD *EVP_whirlpool(void);

const EVP_CIPHER *EVP_enc_null(void);

const EVP_CIPHER *EVP_des_ecb(void);
const EVP_CIPHER *EVP_des_ede(void);
const EVP_CIPHER *EVP_des_ede3(void);
const EVP_CIPHER *EVP_des_ede_ecb(void);
const EVP_CIPHER *EVP_des_ede3_ecb(void);
const EVP_CIPHER *EVP_des_cfb64(void);

const EVP_CIPHER *EVP_des_cfb1(void);
const EVP_CIPHER *EVP_des_cfb8(void);
const EVP_CIPHER *EVP_des_ede_cfb64(void);





const EVP_CIPHER *EVP_des_ede3_cfb64(void);

const EVP_CIPHER *EVP_des_ede3_cfb1(void);
const EVP_CIPHER *EVP_des_ede3_cfb8(void);
const EVP_CIPHER *EVP_des_ofb(void);
const EVP_CIPHER *EVP_des_ede_ofb(void);
const EVP_CIPHER *EVP_des_ede3_ofb(void);
const EVP_CIPHER *EVP_des_cbc(void);
const EVP_CIPHER *EVP_des_ede_cbc(void);
const EVP_CIPHER *EVP_des_ede3_cbc(void);
const EVP_CIPHER *EVP_desx_cbc(void);

const EVP_CIPHER *EVP_rc4(void);
const EVP_CIPHER *EVP_rc4_40(void);

const EVP_CIPHER *EVP_rc4_hmac_md5(void);

const EVP_CIPHER *EVP_rc2_ecb(void);
const EVP_CIPHER *EVP_rc2_cbc(void);
const EVP_CIPHER *EVP_rc2_40_cbc(void);
const EVP_CIPHER *EVP_rc2_64_cbc(void);
const EVP_CIPHER *EVP_rc2_cfb64(void);

const EVP_CIPHER *EVP_rc2_ofb(void);


const EVP_CIPHER *EVP_bf_ecb(void);
const EVP_CIPHER *EVP_bf_cbc(void);
const EVP_CIPHER *EVP_bf_cfb64(void);

const EVP_CIPHER *EVP_bf_ofb(void);


const EVP_CIPHER *EVP_cast5_ecb(void);
const EVP_CIPHER *EVP_cast5_cbc(void);
const EVP_CIPHER *EVP_cast5_cfb64(void);

const EVP_CIPHER *EVP_cast5_ofb(void);

const EVP_CIPHER *EVP_aes_128_ecb(void);
const EVP_CIPHER *EVP_aes_128_cbc(void);
const EVP_CIPHER *EVP_aes_128_cfb1(void);
const EVP_CIPHER *EVP_aes_128_cfb8(void);
const EVP_CIPHER *EVP_aes_128_cfb128(void);

const EVP_CIPHER *EVP_aes_128_ofb(void);
const EVP_CIPHER *EVP_aes_128_ctr(void);
const EVP_CIPHER *EVP_aes_128_ccm(void);
const EVP_CIPHER *EVP_aes_128_gcm(void);
const EVP_CIPHER *EVP_aes_128_xts(void);
const EVP_CIPHER *EVP_aes_192_ecb(void);
const EVP_CIPHER *EVP_aes_192_cbc(void);
const EVP_CIPHER *EVP_aes_192_cfb1(void);
const EVP_CIPHER *EVP_aes_192_cfb8(void);
const EVP_CIPHER *EVP_aes_192_cfb128(void);

const EVP_CIPHER *EVP_aes_192_ofb(void);
const EVP_CIPHER *EVP_aes_192_ctr(void);
const EVP_CIPHER *EVP_aes_192_ccm(void);
const EVP_CIPHER *EVP_aes_192_gcm(void);
const EVP_CIPHER *EVP_aes_256_ecb(void);
const EVP_CIPHER *EVP_aes_256_cbc(void);
const EVP_CIPHER *EVP_aes_256_cfb1(void);
const EVP_CIPHER *EVP_aes_256_cfb8(void);
const EVP_CIPHER *EVP_aes_256_cfb128(void);

const EVP_CIPHER *EVP_aes_256_ofb(void);
const EVP_CIPHER *EVP_aes_256_ctr(void);
const EVP_CIPHER *EVP_aes_256_ccm(void);
const EVP_CIPHER *EVP_aes_256_gcm(void);
const EVP_CIPHER *EVP_aes_256_xts(void);

const EVP_CIPHER *EVP_aes_128_cbc_hmac_sha1(void);
const EVP_CIPHER *EVP_aes_256_cbc_hmac_sha1(void);



const EVP_CIPHER *EVP_camellia_128_ecb(void);
const EVP_CIPHER *EVP_camellia_128_cbc(void);
const EVP_CIPHER *EVP_camellia_128_cfb1(void);
const EVP_CIPHER *EVP_camellia_128_cfb8(void);
const EVP_CIPHER *EVP_camellia_128_cfb128(void);

const EVP_CIPHER *EVP_camellia_128_ofb(void);
const EVP_CIPHER *EVP_camellia_192_ecb(void);
const EVP_CIPHER *EVP_camellia_192_cbc(void);
const EVP_CIPHER *EVP_camellia_192_cfb1(void);
const EVP_CIPHER *EVP_camellia_192_cfb8(void);
const EVP_CIPHER *EVP_camellia_192_cfb128(void);

const EVP_CIPHER *EVP_camellia_192_ofb(void);
const EVP_CIPHER *EVP_camellia_256_ecb(void);
const EVP_CIPHER *EVP_camellia_256_cbc(void);
const EVP_CIPHER *EVP_camellia_256_cfb1(void);
const EVP_CIPHER *EVP_camellia_256_cfb8(void);
const EVP_CIPHER *EVP_camellia_256_cfb128(void);

const EVP_CIPHER *EVP_camellia_256_ofb(void);



const EVP_CIPHER *EVP_seed_ecb(void);
const EVP_CIPHER *EVP_seed_cbc(void);
const EVP_CIPHER *EVP_seed_cfb128(void);

const EVP_CIPHER *EVP_seed_ofb(void);


void OPENSSL_add_all_algorithms_noconf(void);
void OPENSSL_add_all_algorithms_conf(void);

void OpenSSL_add_all_ciphers(void);
void OpenSSL_add_all_digests(void);




int EVP_add_cipher(const EVP_CIPHER *cipher);
int EVP_add_digest(const EVP_MD *digest);

const EVP_CIPHER *EVP_get_cipherbyname(const char *name);
const EVP_MD *EVP_get_digestbyname(const char *name);
void EVP_cleanup(void);

void EVP_CIPHER_do_all(void (*fn)(const EVP_CIPHER *ciph,
  const char *from, const char *to, void *x), void *arg);
void EVP_CIPHER_do_all_sorted(void (*fn)(const EVP_CIPHER *ciph,
  const char *from, const char *to, void *x), void *arg);

void EVP_MD_do_all(void (*fn)(const EVP_MD *ciph,
  const char *from, const char *to, void *x), void *arg);
void EVP_MD_do_all_sorted(void (*fn)(const EVP_MD *ciph,
  const char *from, const char *to, void *x), void *arg);

int EVP_PKEY_decrypt_old(unsigned char *dec_key,
   const unsigned char *enc_key,int enc_key_len,
   EVP_PKEY *private_key);
int EVP_PKEY_encrypt_old(unsigned char *enc_key,
   const unsigned char *key,int key_len,
   EVP_PKEY *pub_key);
int EVP_PKEY_type(int type);
int EVP_PKEY_id(const EVP_PKEY *pkey);
int EVP_PKEY_base_id(const EVP_PKEY *pkey);
int EVP_PKEY_bits(EVP_PKEY *pkey);
int EVP_PKEY_size(EVP_PKEY *pkey);
int EVP_PKEY_set_type(EVP_PKEY *pkey,int type);
int EVP_PKEY_set_type_str(EVP_PKEY *pkey, const char *str, int len);
int EVP_PKEY_assign(EVP_PKEY *pkey,int type,void *key);
void * EVP_PKEY_get0(EVP_PKEY *pkey);


struct rsa_st;
int EVP_PKEY_set1_RSA(EVP_PKEY *pkey,struct rsa_st *key);
struct rsa_st *EVP_PKEY_get1_RSA(EVP_PKEY *pkey);


struct dsa_st;
int EVP_PKEY_set1_DSA(EVP_PKEY *pkey,struct dsa_st *key);
struct dsa_st *EVP_PKEY_get1_DSA(EVP_PKEY *pkey);


struct dh_st;
int EVP_PKEY_set1_DH(EVP_PKEY *pkey,struct dh_st *key);
struct dh_st *EVP_PKEY_get1_DH(EVP_PKEY *pkey);


struct ec_key_st;
int EVP_PKEY_set1_EC_KEY(EVP_PKEY *pkey,struct ec_key_st *key);
struct ec_key_st *EVP_PKEY_get1_EC_KEY(EVP_PKEY *pkey);


EVP_PKEY * EVP_PKEY_new(void);
void EVP_PKEY_free(EVP_PKEY *pkey);

EVP_PKEY * d2i_PublicKey(int type,EVP_PKEY **a, const unsigned char **pp,
   long length);
int i2d_PublicKey(EVP_PKEY *a, unsigned char **pp);

EVP_PKEY * d2i_PrivateKey(int type,EVP_PKEY **a, const unsigned char **pp,
   long length);
EVP_PKEY * d2i_AutoPrivateKey(EVP_PKEY **a, const unsigned char **pp,
   long length);
int i2d_PrivateKey(EVP_PKEY *a, unsigned char **pp);

int EVP_PKEY_copy_parameters(EVP_PKEY *to, const EVP_PKEY *from);
int EVP_PKEY_missing_parameters(const EVP_PKEY *pkey);
int EVP_PKEY_save_parameters(EVP_PKEY *pkey,int mode);
int EVP_PKEY_cmp_parameters(const EVP_PKEY *a, const EVP_PKEY *b);

int EVP_PKEY_cmp(const EVP_PKEY *a, const EVP_PKEY *b);

int EVP_PKEY_print_public(BIO *out, const EVP_PKEY *pkey,
    int indent, ASN1_PCTX *pctx);
int EVP_PKEY_print_private(BIO *out, const EVP_PKEY *pkey,
    int indent, ASN1_PCTX *pctx);
int EVP_PKEY_print_params(BIO *out, const EVP_PKEY *pkey,
    int indent, ASN1_PCTX *pctx);

int EVP_PKEY_get_default_digest_nid(EVP_PKEY *pkey, int *pnid);

int EVP_CIPHER_type(const EVP_CIPHER *ctx);


int EVP_CIPHER_param_to_asn1(EVP_CIPHER_CTX *c, ASN1_TYPE *type);
int EVP_CIPHER_asn1_to_param(EVP_CIPHER_CTX *c, ASN1_TYPE *type);


int EVP_CIPHER_set_asn1_iv(EVP_CIPHER_CTX *c,ASN1_TYPE *type);
int EVP_CIPHER_get_asn1_iv(EVP_CIPHER_CTX *c,ASN1_TYPE *type);


int PKCS5_PBE_keyivgen(EVP_CIPHER_CTX *ctx, const char *pass, int passlen,
    ASN1_TYPE *param, const EVP_CIPHER *cipher, const EVP_MD *md,
    int en_de);
int PKCS5_PBKDF2_HMAC_SHA1(const char *pass, int passlen,
      const unsigned char *salt, int saltlen, int iter,
      int keylen, unsigned char *out);
int PKCS5_PBKDF2_HMAC(const char *pass, int passlen,
      const unsigned char *salt, int saltlen, int iter,
      const EVP_MD *digest,
        int keylen, unsigned char *out);
int PKCS5_v2_PBE_keyivgen(EVP_CIPHER_CTX *ctx, const char *pass, int passlen,
    ASN1_TYPE *param, const EVP_CIPHER *cipher, const EVP_MD *md,
    int en_de);

void PKCS5_PBE_add(void);

int EVP_PBE_CipherInit (ASN1_OBJECT *pbe_obj, const char *pass, int passlen,
      ASN1_TYPE *param, EVP_CIPHER_CTX *ctx, int en_de);

int EVP_PBE_alg_add_type(int pbe_type, int pbe_nid, int cipher_nid, int md_nid,
      EVP_PBE_KEYGEN *keygen);
int EVP_PBE_alg_add(int nid, const EVP_CIPHER *cipher, const EVP_MD *md,
      EVP_PBE_KEYGEN *keygen);
int EVP_PBE_find(int type, int pbe_nid,
   int *pcnid, int *pmnid, EVP_PBE_KEYGEN **pkeygen);
void EVP_PBE_cleanup(void);

int EVP_PKEY_asn1_get_count(void);
const EVP_PKEY_ASN1_METHOD *EVP_PKEY_asn1_get0(int idx);
const EVP_PKEY_ASN1_METHOD *EVP_PKEY_asn1_find(ENGINE **pe, int type);
const EVP_PKEY_ASN1_METHOD *EVP_PKEY_asn1_find_str(ENGINE **pe,
     const char *str, int len);
int EVP_PKEY_asn1_add0(const EVP_PKEY_ASN1_METHOD *ameth);
int EVP_PKEY_asn1_add_alias(int to, int from);
int EVP_PKEY_asn1_get0_info(int *ppkey_id, int *pkey_base_id, int *ppkey_flags,
    const char **pinfo, const char **ppem_str,
     const EVP_PKEY_ASN1_METHOD *ameth);

const EVP_PKEY_ASN1_METHOD* EVP_PKEY_get0_asn1(EVP_PKEY *pkey);
EVP_PKEY_ASN1_METHOD* EVP_PKEY_asn1_new(int id, int flags,
     const char *pem_str, const char *info);
void EVP_PKEY_asn1_copy(EVP_PKEY_ASN1_METHOD *dst,
   const EVP_PKEY_ASN1_METHOD *src);
void EVP_PKEY_asn1_free(EVP_PKEY_ASN1_METHOD *ameth);
void EVP_PKEY_asn1_set_public(EVP_PKEY_ASN1_METHOD *ameth,
  int (*pub_decode)(EVP_PKEY *pk, X509_PUBKEY *pub),
  int (*pub_encode)(X509_PUBKEY *pub, const EVP_PKEY *pk),
  int (*pub_cmp)(const EVP_PKEY *a, const EVP_PKEY *b),
  int (*pub_print)(BIO *out, const EVP_PKEY *pkey, int indent,
       ASN1_PCTX *pctx),
  int (*pkey_size)(const EVP_PKEY *pk),
  int (*pkey_bits)(const EVP_PKEY *pk));
void EVP_PKEY_asn1_set_private(EVP_PKEY_ASN1_METHOD *ameth,
  int (*priv_decode)(EVP_PKEY *pk, PKCS8_PRIV_KEY_INFO *p8inf),
  int (*priv_encode)(PKCS8_PRIV_KEY_INFO *p8, const EVP_PKEY *pk),
  int (*priv_print)(BIO *out, const EVP_PKEY *pkey, int indent,
       ASN1_PCTX *pctx));
void EVP_PKEY_asn1_set_param(EVP_PKEY_ASN1_METHOD *ameth,
  int (*param_decode)(EVP_PKEY *pkey,
    const unsigned char **pder, int derlen),
  int (*param_encode)(const EVP_PKEY *pkey, unsigned char **pder),
  int (*param_missing)(const EVP_PKEY *pk),
  int (*param_copy)(EVP_PKEY *to, const EVP_PKEY *from),
  int (*param_cmp)(const EVP_PKEY *a, const EVP_PKEY *b),
  int (*param_print)(BIO *out, const EVP_PKEY *pkey, int indent,
       ASN1_PCTX *pctx));

void EVP_PKEY_asn1_set_free(EVP_PKEY_ASN1_METHOD *ameth,
  void (*pkey_free)(EVP_PKEY *pkey));
void EVP_PKEY_asn1_set_ctrl(EVP_PKEY_ASN1_METHOD *ameth,
  int (*pkey_ctrl)(EVP_PKEY *pkey, int op,
       long arg1, void *arg2));

const EVP_PKEY_METHOD *EVP_PKEY_meth_find(int type);
EVP_PKEY_METHOD* EVP_PKEY_meth_new(int id, int flags);
void EVP_PKEY_meth_get0_info(int *ppkey_id, int *pflags,
    const EVP_PKEY_METHOD *meth);
void EVP_PKEY_meth_copy(EVP_PKEY_METHOD *dst, const EVP_PKEY_METHOD *src);
void EVP_PKEY_meth_free(EVP_PKEY_METHOD *pmeth);
int EVP_PKEY_meth_add0(const EVP_PKEY_METHOD *pmeth);

EVP_PKEY_CTX *EVP_PKEY_CTX_new(EVP_PKEY *pkey, ENGINE *e);
EVP_PKEY_CTX *EVP_PKEY_CTX_new_id(int id, ENGINE *e);
EVP_PKEY_CTX *EVP_PKEY_CTX_dup(EVP_PKEY_CTX *ctx);
void EVP_PKEY_CTX_free(EVP_PKEY_CTX *ctx);

int EVP_PKEY_CTX_ctrl(EVP_PKEY_CTX *ctx, int keytype, int optype,
    int cmd, int p1, void *p2);
int EVP_PKEY_CTX_ctrl_str(EVP_PKEY_CTX *ctx, const char *type,
      const char *value);

int EVP_PKEY_CTX_get_operation(EVP_PKEY_CTX *ctx);
void EVP_PKEY_CTX_set0_keygen_info(EVP_PKEY_CTX *ctx, int *dat, int datlen);

EVP_PKEY *EVP_PKEY_new_mac_key(int type, ENGINE *e,
    const unsigned char *key, int keylen);

void EVP_PKEY_CTX_set_data(EVP_PKEY_CTX *ctx, void *data);
void *EVP_PKEY_CTX_get_data(EVP_PKEY_CTX *ctx);
EVP_PKEY *EVP_PKEY_CTX_get0_pkey(EVP_PKEY_CTX *ctx);

EVP_PKEY *EVP_PKEY_CTX_get0_peerkey(EVP_PKEY_CTX *ctx);

void EVP_PKEY_CTX_set_app_data(EVP_PKEY_CTX *ctx, void *data);
void *EVP_PKEY_CTX_get_app_data(EVP_PKEY_CTX *ctx);

int EVP_PKEY_sign_init(EVP_PKEY_CTX *ctx);
int EVP_PKEY_sign(EVP_PKEY_CTX *ctx,
   unsigned char *sig, size_t *siglen,
   const unsigned char *tbs, size_t tbslen);
int EVP_PKEY_verify_init(EVP_PKEY_CTX *ctx);
int EVP_PKEY_verify(EVP_PKEY_CTX *ctx,
   const unsigned char *sig, size_t siglen,
   const unsigned char *tbs, size_t tbslen);
int EVP_PKEY_verify_recover_init(EVP_PKEY_CTX *ctx);
int EVP_PKEY_verify_recover(EVP_PKEY_CTX *ctx,
   unsigned char *rout, size_t *routlen,
   const unsigned char *sig, size_t siglen);
int EVP_PKEY_encrypt_init(EVP_PKEY_CTX *ctx);
int EVP_PKEY_encrypt(EVP_PKEY_CTX *ctx,
   unsigned char *out, size_t *outlen,
   const unsigned char *in, size_t inlen);
int EVP_PKEY_decrypt_init(EVP_PKEY_CTX *ctx);
int EVP_PKEY_decrypt(EVP_PKEY_CTX *ctx,
   unsigned char *out, size_t *outlen,
   const unsigned char *in, size_t inlen);

int EVP_PKEY_derive_init(EVP_PKEY_CTX *ctx);
int EVP_PKEY_derive_set_peer(EVP_PKEY_CTX *ctx, EVP_PKEY *peer);
int EVP_PKEY_derive(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen);

typedef int EVP_PKEY_gen_cb(EVP_PKEY_CTX *ctx);

int EVP_PKEY_paramgen_init(EVP_PKEY_CTX *ctx);
int EVP_PKEY_paramgen(EVP_PKEY_CTX *ctx, EVP_PKEY **ppkey);
int EVP_PKEY_keygen_init(EVP_PKEY_CTX *ctx);
int EVP_PKEY_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY **ppkey);

void EVP_PKEY_CTX_set_cb(EVP_PKEY_CTX *ctx, EVP_PKEY_gen_cb *cb);
EVP_PKEY_gen_cb *EVP_PKEY_CTX_get_cb(EVP_PKEY_CTX *ctx);

int EVP_PKEY_CTX_get_keygen_info(EVP_PKEY_CTX *ctx, int idx);

void EVP_PKEY_meth_set_init(EVP_PKEY_METHOD *pmeth,
 int (*init)(EVP_PKEY_CTX *ctx));

void EVP_PKEY_meth_set_copy(EVP_PKEY_METHOD *pmeth,
 int (*copy)(EVP_PKEY_CTX *dst, EVP_PKEY_CTX *src));

void EVP_PKEY_meth_set_cleanup(EVP_PKEY_METHOD *pmeth,
 void (*cleanup)(EVP_PKEY_CTX *ctx));

void EVP_PKEY_meth_set_paramgen(EVP_PKEY_METHOD *pmeth,
 int (*paramgen_init)(EVP_PKEY_CTX *ctx),
 int (*paramgen)(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey));

void EVP_PKEY_meth_set_keygen(EVP_PKEY_METHOD *pmeth,
 int (*keygen_init)(EVP_PKEY_CTX *ctx),
 int (*keygen)(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey));

void EVP_PKEY_meth_set_sign(EVP_PKEY_METHOD *pmeth,
 int (*sign_init)(EVP_PKEY_CTX *ctx),
 int (*sign)(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
     const unsigned char *tbs, size_t tbslen));

void EVP_PKEY_meth_set_verify(EVP_PKEY_METHOD *pmeth,
 int (*verify_init)(EVP_PKEY_CTX *ctx),
 int (*verify)(EVP_PKEY_CTX *ctx, const unsigned char *sig, size_t siglen,
     const unsigned char *tbs, size_t tbslen));

void EVP_PKEY_meth_set_verify_recover(EVP_PKEY_METHOD *pmeth,
 int (*verify_recover_init)(EVP_PKEY_CTX *ctx),
 int (*verify_recover)(EVP_PKEY_CTX *ctx,
     unsigned char *sig, size_t *siglen,
     const unsigned char *tbs, size_t tbslen));

void EVP_PKEY_meth_set_signctx(EVP_PKEY_METHOD *pmeth,
 int (*signctx_init)(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx),
 int (*signctx)(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
     EVP_MD_CTX *mctx));

void EVP_PKEY_meth_set_verifyctx(EVP_PKEY_METHOD *pmeth,
 int (*verifyctx_init)(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx),
 int (*verifyctx)(EVP_PKEY_CTX *ctx, const unsigned char *sig,int siglen,
     EVP_MD_CTX *mctx));

void EVP_PKEY_meth_set_encrypt(EVP_PKEY_METHOD *pmeth,
 int (*encrypt_init)(EVP_PKEY_CTX *ctx),
 int (*encryptfn)(EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen,
     const unsigned char *in, size_t inlen));

void EVP_PKEY_meth_set_decrypt(EVP_PKEY_METHOD *pmeth,
 int (*decrypt_init)(EVP_PKEY_CTX *ctx),
 int (*decrypt)(EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen,
     const unsigned char *in, size_t inlen));

void EVP_PKEY_meth_set_derive(EVP_PKEY_METHOD *pmeth,
 int (*derive_init)(EVP_PKEY_CTX *ctx),
 int (*derive)(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen));

void EVP_PKEY_meth_set_ctrl(EVP_PKEY_METHOD *pmeth,
 int (*ctrl)(EVP_PKEY_CTX *ctx, int type, int p1, void *p2),
 int (*ctrl_str)(EVP_PKEY_CTX *ctx,
     const char *type, const char *value));

void EVP_add_alg_module(void);





void ERR_load_EVP_strings(void);



typedef struct CMAC_CTX_st CMAC_CTX;

CMAC_CTX *CMAC_CTX_new(void);
void CMAC_CTX_cleanup(CMAC_CTX *ctx);
void CMAC_CTX_free(CMAC_CTX *ctx);
EVP_CIPHER_CTX *CMAC_CTX_get0_cipher_ctx(CMAC_CTX *ctx);
int CMAC_CTX_copy(CMAC_CTX *out, const CMAC_CTX *in);

int CMAC_Init(CMAC_CTX *ctx, const void *key, size_t keylen,
   const EVP_CIPHER *cipher, ENGINE *impl);
int CMAC_Update(CMAC_CTX *ctx, const void *data, size_t dlen);
int CMAC_Final(CMAC_CTX *ctx, unsigned char *out, size_t *poutlen);
int CMAC_resume(CMAC_CTX *ctx);
















typedef enum {


 POINT_CONVERSION_COMPRESSED = 2,

 POINT_CONVERSION_UNCOMPRESSED = 4,


 POINT_CONVERSION_HYBRID = 6
} point_conversion_form_t;


typedef struct ec_method_st EC_METHOD;

typedef struct ec_group_st

 EC_GROUP;

typedef struct ec_point_st EC_POINT;

const EC_METHOD *EC_GFp_simple_method(void);




const EC_METHOD *EC_GFp_mont_method(void);




const EC_METHOD *EC_GFp_nist_method(void);





const EC_METHOD *EC_GFp_nistp224_method(void);




const EC_METHOD *EC_GFp_nistp256_method(void);




const EC_METHOD *EC_GFp_nistp521_method(void);

const EC_METHOD *EC_GF2m_simple_method(void);

EC_GROUP *EC_GROUP_new(const EC_METHOD *meth);




void EC_GROUP_free(EC_GROUP *group);




void EC_GROUP_clear_free(EC_GROUP *group);






int EC_GROUP_copy(EC_GROUP *dst, const EC_GROUP *src);






EC_GROUP *EC_GROUP_dup(const EC_GROUP *src);





const EC_METHOD *EC_GROUP_method_of(const EC_GROUP *group);





int EC_METHOD_get_field_type(const EC_METHOD *meth);

int EC_GROUP_set_generator(EC_GROUP *group, const EC_POINT *generator, const BIGNUM *order, const BIGNUM *cofactor);





const EC_POINT *EC_GROUP_get0_generator(const EC_GROUP *group);







int EC_GROUP_get_order(const EC_GROUP *group, BIGNUM *order, BN_CTX *ctx);







int EC_GROUP_get_cofactor(const EC_GROUP *group, BIGNUM *cofactor, BN_CTX *ctx);





void EC_GROUP_set_curve_name(EC_GROUP *group, int nid);





int EC_GROUP_get_curve_name(const EC_GROUP *group);

void EC_GROUP_set_asn1_flag(EC_GROUP *group, int flag);
int EC_GROUP_get_asn1_flag(const EC_GROUP *group);

void EC_GROUP_set_point_conversion_form(EC_GROUP *group, point_conversion_form_t form);
point_conversion_form_t EC_GROUP_get_point_conversion_form(const EC_GROUP *);

unsigned char *EC_GROUP_get0_seed(const EC_GROUP *x);
size_t EC_GROUP_get_seed_len(const EC_GROUP *);
size_t EC_GROUP_set_seed(EC_GROUP *, const unsigned char *, size_t len);

int EC_GROUP_set_curve_GFp(EC_GROUP *group, const BIGNUM *p, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx);

int EC_GROUP_get_curve_GFp(const EC_GROUP *group, BIGNUM *p, BIGNUM *a, BIGNUM *b, BN_CTX *ctx);

int EC_GROUP_set_curve_GF2m(EC_GROUP *group, const BIGNUM *p, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx);

int EC_GROUP_get_curve_GF2m(const EC_GROUP *group, BIGNUM *p, BIGNUM *a, BIGNUM *b, BN_CTX *ctx);





int EC_GROUP_get_degree(const EC_GROUP *group);






int EC_GROUP_check(const EC_GROUP *group, BN_CTX *ctx);






int EC_GROUP_check_discriminant(const EC_GROUP *group, BN_CTX *ctx);







int EC_GROUP_cmp(const EC_GROUP *a, const EC_GROUP *b, BN_CTX *ctx);

EC_GROUP *EC_GROUP_new_curve_GFp(const BIGNUM *p, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx);

EC_GROUP *EC_GROUP_new_curve_GF2m(const BIGNUM *p, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx);






EC_GROUP *EC_GROUP_new_by_curve_name(int nid);






typedef struct {
 int nid;
 const char *comment;
 } EC_builtin_curve;





size_t EC_get_builtin_curves(EC_builtin_curve *r, size_t nitems);

EC_POINT *EC_POINT_new(const EC_GROUP *group);




void EC_POINT_free(EC_POINT *point);




void EC_POINT_clear_free(EC_POINT *point);






int EC_POINT_copy(EC_POINT *dst, const EC_POINT *src);







EC_POINT *EC_POINT_dup(const EC_POINT *src, const EC_GROUP *group);





const EC_METHOD *EC_POINT_method_of(const EC_POINT *point);






int EC_POINT_set_to_infinity(const EC_GROUP *group, EC_POINT *point);

int EC_POINT_set_Jprojective_coordinates_GFp(const EC_GROUP *group, EC_POINT *p,
 const BIGNUM *x, const BIGNUM *y, const BIGNUM *z, BN_CTX *ctx);

int EC_POINT_get_Jprojective_coordinates_GFp(const EC_GROUP *group,
 const EC_POINT *p, BIGNUM *x, BIGNUM *y, BIGNUM *z, BN_CTX *ctx);

int EC_POINT_set_affine_coordinates_GFp(const EC_GROUP *group, EC_POINT *p,
 const BIGNUM *x, const BIGNUM *y, BN_CTX *ctx);

int EC_POINT_get_affine_coordinates_GFp(const EC_GROUP *group,
 const EC_POINT *p, BIGNUM *x, BIGNUM *y, BN_CTX *ctx);

int EC_POINT_set_compressed_coordinates_GFp(const EC_GROUP *group, EC_POINT *p,
 const BIGNUM *x, int y_bit, BN_CTX *ctx);

int EC_POINT_set_affine_coordinates_GF2m(const EC_GROUP *group, EC_POINT *p,
 const BIGNUM *x, const BIGNUM *y, BN_CTX *ctx);

int EC_POINT_get_affine_coordinates_GF2m(const EC_GROUP *group,
 const EC_POINT *p, BIGNUM *x, BIGNUM *y, BN_CTX *ctx);

int EC_POINT_set_compressed_coordinates_GF2m(const EC_GROUP *group, EC_POINT *p,
 const BIGNUM *x, int y_bit, BN_CTX *ctx);

size_t EC_POINT_point2oct(const EC_GROUP *group, const EC_POINT *p,
 point_conversion_form_t form,
        unsigned char *buf, size_t len, BN_CTX *ctx);

int EC_POINT_oct2point(const EC_GROUP *group, EC_POINT *p,
        const unsigned char *buf, size_t len, BN_CTX *ctx);


BIGNUM *EC_POINT_point2bn(const EC_GROUP *, const EC_POINT *,
 point_conversion_form_t form, BIGNUM *, BN_CTX *);
EC_POINT *EC_POINT_bn2point(const EC_GROUP *, const BIGNUM *,
 EC_POINT *, BN_CTX *);
char *EC_POINT_point2hex(const EC_GROUP *, const EC_POINT *,
 point_conversion_form_t form, BN_CTX *);
EC_POINT *EC_POINT_hex2point(const EC_GROUP *, const char *,
 EC_POINT *, BN_CTX *);

int EC_POINT_add(const EC_GROUP *group, EC_POINT *r, const EC_POINT *a, const EC_POINT *b, BN_CTX *ctx);

int EC_POINT_dbl(const EC_GROUP *group, EC_POINT *r, const EC_POINT *a, BN_CTX *ctx);







int EC_POINT_invert(const EC_GROUP *group, EC_POINT *a, BN_CTX *ctx);






int EC_POINT_is_at_infinity(const EC_GROUP *group, const EC_POINT *p);







int EC_POINT_is_on_curve(const EC_GROUP *group, const EC_POINT *point, BN_CTX *ctx);

int EC_POINT_cmp(const EC_GROUP *group, const EC_POINT *a, const EC_POINT *b, BN_CTX *ctx);

int EC_POINT_make_affine(const EC_GROUP *group, EC_POINT *point, BN_CTX *ctx);
int EC_POINTs_make_affine(const EC_GROUP *group, size_t num, EC_POINT *points[], BN_CTX *ctx);

int EC_POINTs_mul(const EC_GROUP *group, EC_POINT *r, const BIGNUM *n, size_t num, const EC_POINT *p[], const BIGNUM *m[], BN_CTX *ctx);

int EC_POINT_mul(const EC_GROUP *group, EC_POINT *r, const BIGNUM *n, const EC_POINT *q, const BIGNUM *m, BN_CTX *ctx);






int EC_GROUP_precompute_mult(EC_GROUP *group, BN_CTX *ctx);





int EC_GROUP_have_precompute_mult(const EC_GROUP *group);

int EC_GROUP_get_basis_type(const EC_GROUP *);

int EC_GROUP_get_trinomial_basis(const EC_GROUP *, unsigned int *k);
int EC_GROUP_get_pentanomial_basis(const EC_GROUP *, unsigned int *k1,
 unsigned int *k2, unsigned int *k3);




typedef struct ecpk_parameters_st ECPKPARAMETERS;

EC_GROUP *d2i_ECPKParameters(EC_GROUP **, const unsigned char **in, long len);
int i2d_ECPKParameters(const EC_GROUP *, unsigned char **out);

int ECPKParameters_print(BIO *bp, const EC_GROUP *x, int off);


int ECPKParameters_print_fp(FILE *fp, const EC_GROUP *x, int off);







typedef struct ec_key_st EC_KEY;

EC_KEY *EC_KEY_new(void);

int EC_KEY_get_flags(const EC_KEY *key);

void EC_KEY_set_flags(EC_KEY *key, int flags);

void EC_KEY_clear_flags(EC_KEY *key, int flags);






EC_KEY *EC_KEY_new_by_curve_name(int nid);




void EC_KEY_free(EC_KEY *key);






EC_KEY *EC_KEY_copy(EC_KEY *dst, const EC_KEY *src);





EC_KEY *EC_KEY_dup(const EC_KEY *src);





int EC_KEY_up_ref(EC_KEY *key);





const EC_GROUP *EC_KEY_get0_group(const EC_KEY *key);







int EC_KEY_set_group(EC_KEY *key, const EC_GROUP *group);





const BIGNUM *EC_KEY_get0_private_key(const EC_KEY *key);







int EC_KEY_set_private_key(EC_KEY *key, const BIGNUM *prv);





const EC_POINT *EC_KEY_get0_public_key(const EC_KEY *key);







int EC_KEY_set_public_key(EC_KEY *key, const EC_POINT *pub);

unsigned EC_KEY_get_enc_flags(const EC_KEY *key);
void EC_KEY_set_enc_flags(EC_KEY *eckey, unsigned int flags);
point_conversion_form_t EC_KEY_get_conv_form(const EC_KEY *key);
void EC_KEY_set_conv_form(EC_KEY *eckey, point_conversion_form_t cform);

void *EC_KEY_get_key_method_data(EC_KEY *key,
 void *(*dup_func)(void *), void (*free_func)(void *), void (*clear_free_func)(void *));

void *EC_KEY_insert_key_method_data(EC_KEY *key, void *data,
 void *(*dup_func)(void *), void (*free_func)(void *), void (*clear_free_func)(void *));

void EC_KEY_set_asn1_flag(EC_KEY *eckey, int asn1_flag);







int EC_KEY_precompute_mult(EC_KEY *key, BN_CTX *ctx);





int EC_KEY_generate_key(EC_KEY *key);





int EC_KEY_check_key(const EC_KEY *key);

int EC_KEY_set_public_key_affine_coordinates(EC_KEY *key, BIGNUM *x, BIGNUM *y);

EC_KEY *d2i_ECPrivateKey(EC_KEY **key, const unsigned char **in, long len);







int i2d_ECPrivateKey(EC_KEY *key, unsigned char **out);

EC_KEY *d2i_ECParameters(EC_KEY **key, const unsigned char **in, long len);







int i2d_ECParameters(EC_KEY *key, unsigned char **out);

EC_KEY *o2i_ECPublicKey(EC_KEY **key, const unsigned char **in, long len);







int i2o_ECPublicKey(EC_KEY *key, unsigned char **out);







int ECParameters_print(BIO *bp, const EC_KEY *key);







int EC_KEY_print(BIO *bp, const EC_KEY *key, int off);

int ECParameters_print_fp(FILE *fp, const EC_KEY *key);







int EC_KEY_print_fp(FILE *fp, const EC_KEY *key, int off);

void ERR_load_EC_strings(void);









typedef struct ECDSA_SIG_st
 {
 BIGNUM *r;
 BIGNUM *s;
 } ECDSA_SIG;




ECDSA_SIG *ECDSA_SIG_new(void);




void ECDSA_SIG_free(ECDSA_SIG *sig);







int i2d_ECDSA_SIG(const ECDSA_SIG *sig, unsigned char **pp);

ECDSA_SIG *d2i_ECDSA_SIG(ECDSA_SIG **sig, const unsigned char **pp, long len);

ECDSA_SIG *ECDSA_do_sign(const unsigned char *dgst,int dgst_len,EC_KEY *eckey);

ECDSA_SIG *ECDSA_do_sign_ex(const unsigned char *dgst, int dgstlen,
  const BIGNUM *kinv, const BIGNUM *rp, EC_KEY *eckey);

int ECDSA_do_verify(const unsigned char *dgst, int dgst_len,
  const ECDSA_SIG *sig, EC_KEY* eckey);

const ECDSA_METHOD *ECDSA_OpenSSL(void);




void ECDSA_set_default_method(const ECDSA_METHOD *meth);




const ECDSA_METHOD *ECDSA_get_default_method(void);






int ECDSA_set_method(EC_KEY *eckey, const ECDSA_METHOD *meth);





int ECDSA_size(const EC_KEY *eckey);

int ECDSA_sign_setup(EC_KEY *eckey, BN_CTX *ctx, BIGNUM **kinv,
  BIGNUM **rp);

int ECDSA_sign(int type, const unsigned char *dgst, int dgstlen,
  unsigned char *sig, unsigned int *siglen, EC_KEY *eckey);

int ECDSA_sign_ex(int type, const unsigned char *dgst, int dgstlen,
  unsigned char *sig, unsigned int *siglen, const BIGNUM *kinv,
  const BIGNUM *rp, EC_KEY *eckey);

int ECDSA_verify(int type, const unsigned char *dgst, int dgstlen,
  const unsigned char *sig, int siglen, EC_KEY *eckey);


int ECDSA_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new
  *new_func, CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func);
int ECDSA_set_ex_data(EC_KEY *d, int idx, void *arg);
void *ECDSA_get_ex_data(EC_KEY *d, int idx);






void ERR_load_ECDSA_strings(void);









const ECDH_METHOD *ECDH_OpenSSL(void);

void ECDH_set_default_method(const ECDH_METHOD *);
const ECDH_METHOD *ECDH_get_default_method(void);
int ECDH_set_method(EC_KEY *, const ECDH_METHOD *);

int ECDH_compute_key(void *out, size_t outlen, const EC_POINT *pub_key, EC_KEY *ecdh,
                     void *(*KDF)(const void *in, size_t inlen, void *out, size_t *outlen));

int ECDH_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new
  *new_func, CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func);
int ECDH_set_ex_data(EC_KEY *d, int idx, void *arg);
void *ECDH_get_ex_data(EC_KEY *d, int idx);






void ERR_load_ECDH_strings(void);







struct rsa_meth_st
 {
 const char *name;
 int (*rsa_pub_enc)(int flen,const unsigned char *from,
      unsigned char *to,
      RSA *rsa,int padding);
 int (*rsa_pub_dec)(int flen,const unsigned char *from,
      unsigned char *to,
      RSA *rsa,int padding);
 int (*rsa_priv_enc)(int flen,const unsigned char *from,
       unsigned char *to,
       RSA *rsa,int padding);
 int (*rsa_priv_dec)(int flen,const unsigned char *from,
       unsigned char *to,
       RSA *rsa,int padding);
 int (*rsa_mod_exp)(BIGNUM *r0,const BIGNUM *I,RSA *rsa,BN_CTX *ctx);
 int (*bn_mod_exp)(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
     const BIGNUM *m, BN_CTX *ctx,
     BN_MONT_CTX *m_ctx);
 int (*init)(RSA *rsa);
 int (*finish)(RSA *rsa);
 int flags;
 char *app_data;







 int (*rsa_sign)(int type,
  const unsigned char *m, unsigned int m_length,
  unsigned char *sigret, unsigned int *siglen, const RSA *rsa);
 int (*rsa_verify)(int dtype,
  const unsigned char *m, unsigned int m_length,
  const unsigned char *sigbuf, unsigned int siglen,
        const RSA *rsa);




 int (*rsa_keygen)(RSA *rsa, int bits, BIGNUM *e, BN_GENCB *cb);
 };

struct rsa_st
 {


 int pad;
 long version;
 const RSA_METHOD *meth;

 ENGINE *engine;
 BIGNUM *n;
 BIGNUM *e;
 BIGNUM *d;
 BIGNUM *p;
 BIGNUM *q;
 BIGNUM *dmp1;
 BIGNUM *dmq1;
 BIGNUM *iqmp;

 CRYPTO_EX_DATA ex_data;
 int references;
 int flags;


 BN_MONT_CTX *_method_mod_n;
 BN_MONT_CTX *_method_mod_p;
 BN_MONT_CTX *_method_mod_q;



 char *bignum_data;
 BN_BLINDING *blinding;
 BN_BLINDING *mt_blinding;
 };

RSA * RSA_new(void);
RSA * RSA_new_method(ENGINE *engine);
int RSA_size(const RSA *rsa);



RSA * RSA_generate_key(int bits, unsigned long e,void
  (*callback)(int,int,void *),void *cb_arg);



int RSA_generate_key_ex(RSA *rsa, int bits, BIGNUM *e, BN_GENCB *cb);

int RSA_check_key(const RSA *);

int RSA_public_encrypt(int flen, const unsigned char *from,
  unsigned char *to, RSA *rsa,int padding);
int RSA_private_encrypt(int flen, const unsigned char *from,
  unsigned char *to, RSA *rsa,int padding);
int RSA_public_decrypt(int flen, const unsigned char *from,
  unsigned char *to, RSA *rsa,int padding);
int RSA_private_decrypt(int flen, const unsigned char *from,
  unsigned char *to, RSA *rsa,int padding);
void RSA_free (RSA *r);

int RSA_up_ref(RSA *r);

int RSA_flags(const RSA *r);

void RSA_set_default_method(const RSA_METHOD *meth);
const RSA_METHOD *RSA_get_default_method(void);
const RSA_METHOD *RSA_get_method(const RSA *rsa);
int RSA_set_method(RSA *rsa, const RSA_METHOD *meth);


int RSA_memory_lock(RSA *r);


const RSA_METHOD *RSA_PKCS1_SSLeay(void);

const RSA_METHOD *RSA_null_method(void);

RSA *d2i_RSAPublicKey(RSA **a, const unsigned char **in, long len); int i2d_RSAPublicKey(const RSA *a, unsigned char **out); extern const ASN1_ITEM RSAPublicKey_it;
RSA *d2i_RSAPrivateKey(RSA **a, const unsigned char **in, long len); int i2d_RSAPrivateKey(const RSA *a, unsigned char **out); extern const ASN1_ITEM RSAPrivateKey_it;

typedef struct rsa_pss_params_st
 {
 X509_ALGOR *hashAlgorithm;
 X509_ALGOR *maskGenAlgorithm;
 ASN1_INTEGER *saltLength;
 ASN1_INTEGER *trailerField;
 } RSA_PSS_PARAMS;

RSA_PSS_PARAMS *RSA_PSS_PARAMS_new(void); void RSA_PSS_PARAMS_free(RSA_PSS_PARAMS *a); RSA_PSS_PARAMS *d2i_RSA_PSS_PARAMS(RSA_PSS_PARAMS **a, const unsigned char **in, long len); int i2d_RSA_PSS_PARAMS(RSA_PSS_PARAMS *a, unsigned char **out); extern const ASN1_ITEM RSA_PSS_PARAMS_it;


int RSA_print_fp(FILE *fp, const RSA *r,int offset);



int RSA_print(BIO *bp, const RSA *r,int offset);



int i2d_RSA_NET(const RSA *a, unsigned char **pp,
  int (*cb)(char *buf, int len, const char *prompt, int verify),
  int sgckey);
RSA *d2i_RSA_NET(RSA **a, const unsigned char **pp, long length,
   int (*cb)(char *buf, int len, const char *prompt, int verify),
   int sgckey);

int i2d_Netscape_RSA(const RSA *a, unsigned char **pp,
       int (*cb)(char *buf, int len, const char *prompt,
          int verify));
RSA *d2i_Netscape_RSA(RSA **a, const unsigned char **pp, long length,
        int (*cb)(char *buf, int len, const char *prompt,
    int verify));




int RSA_sign(int type, const unsigned char *m, unsigned int m_length,
 unsigned char *sigret, unsigned int *siglen, RSA *rsa);
int RSA_verify(int type, const unsigned char *m, unsigned int m_length,
 const unsigned char *sigbuf, unsigned int siglen, RSA *rsa);



int RSA_sign_ASN1_OCTET_STRING(int type,
 const unsigned char *m, unsigned int m_length,
 unsigned char *sigret, unsigned int *siglen, RSA *rsa);
int RSA_verify_ASN1_OCTET_STRING(int type,
 const unsigned char *m, unsigned int m_length,
 unsigned char *sigbuf, unsigned int siglen, RSA *rsa);

int RSA_blinding_on(RSA *rsa, BN_CTX *ctx);
void RSA_blinding_off(RSA *rsa);
BN_BLINDING *RSA_setup_blinding(RSA *rsa, BN_CTX *ctx);

int RSA_padding_add_PKCS1_type_1(unsigned char *to,int tlen,
 const unsigned char *f,int fl);
int RSA_padding_check_PKCS1_type_1(unsigned char *to,int tlen,
 const unsigned char *f,int fl,int rsa_len);
int RSA_padding_add_PKCS1_type_2(unsigned char *to,int tlen,
 const unsigned char *f,int fl);
int RSA_padding_check_PKCS1_type_2(unsigned char *to,int tlen,
 const unsigned char *f,int fl,int rsa_len);
int PKCS1_MGF1(unsigned char *mask, long len,
 const unsigned char *seed, long seedlen, const EVP_MD *dgst);
int RSA_padding_add_PKCS1_OAEP(unsigned char *to,int tlen,
 const unsigned char *f,int fl,
 const unsigned char *p,int pl);
int RSA_padding_check_PKCS1_OAEP(unsigned char *to,int tlen,
 const unsigned char *f,int fl,int rsa_len,
 const unsigned char *p,int pl);
int RSA_padding_add_SSLv23(unsigned char *to,int tlen,
 const unsigned char *f,int fl);
int RSA_padding_check_SSLv23(unsigned char *to,int tlen,
 const unsigned char *f,int fl,int rsa_len);
int RSA_padding_add_none(unsigned char *to,int tlen,
 const unsigned char *f,int fl);
int RSA_padding_check_none(unsigned char *to,int tlen,
 const unsigned char *f,int fl,int rsa_len);
int RSA_padding_add_X931(unsigned char *to,int tlen,
 const unsigned char *f,int fl);
int RSA_padding_check_X931(unsigned char *to,int tlen,
 const unsigned char *f,int fl,int rsa_len);
int RSA_X931_hash_id(int nid);

int RSA_verify_PKCS1_PSS(RSA *rsa, const unsigned char *mHash,
   const EVP_MD *Hash, const unsigned char *EM, int sLen);
int RSA_padding_add_PKCS1_PSS(RSA *rsa, unsigned char *EM,
   const unsigned char *mHash,
   const EVP_MD *Hash, int sLen);

int RSA_verify_PKCS1_PSS_mgf1(RSA *rsa, const unsigned char *mHash,
   const EVP_MD *Hash, const EVP_MD *mgf1Hash,
   const unsigned char *EM, int sLen);

int RSA_padding_add_PKCS1_PSS_mgf1(RSA *rsa, unsigned char *EM,
   const unsigned char *mHash,
   const EVP_MD *Hash, const EVP_MD *mgf1Hash, int sLen);

int RSA_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func,
 CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func);
int RSA_set_ex_data(RSA *r,int idx,void *arg);
void *RSA_get_ex_data(const RSA *r, int idx);

RSA *RSAPublicKey_dup(RSA *rsa);
RSA *RSAPrivateKey_dup(RSA *rsa);

void ERR_load_RSA_strings(void);



















struct dh_method
 {
 const char *name;

 int (*generate_key)(DH *dh);
 int (*compute_key)(unsigned char *key,const BIGNUM *pub_key,DH *dh);
 int (*bn_mod_exp)(const DH *dh, BIGNUM *r, const BIGNUM *a,
    const BIGNUM *p, const BIGNUM *m, BN_CTX *ctx,
    BN_MONT_CTX *m_ctx);

 int (*init)(DH *dh);
 int (*finish)(DH *dh);
 int flags;
 char *app_data;

 int (*generate_params)(DH *dh, int prime_len, int generator, BN_GENCB *cb);
 };

struct dh_st
 {


 int pad;
 int version;
 BIGNUM *p;
 BIGNUM *g;
 long length;
 BIGNUM *pub_key;
 BIGNUM *priv_key;

 int flags;
 BN_MONT_CTX *method_mont_p;

 BIGNUM *q;
 BIGNUM *j;
 unsigned char *seed;
 int seedlen;
 BIGNUM *counter;

 int references;
 CRYPTO_EX_DATA ex_data;
 const DH_METHOD *meth;
 ENGINE *engine;
 };

DH *DHparams_dup(DH *);

const DH_METHOD *DH_OpenSSL(void);

void DH_set_default_method(const DH_METHOD *meth);
const DH_METHOD *DH_get_default_method(void);
int DH_set_method(DH *dh, const DH_METHOD *meth);
DH *DH_new_method(ENGINE *engine);

DH * DH_new(void);
void DH_free(DH *dh);
int DH_up_ref(DH *dh);
int DH_size(const DH *dh);
int DH_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func,
      CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func);
int DH_set_ex_data(DH *d, int idx, void *arg);
void *DH_get_ex_data(DH *d, int idx);



DH * DH_generate_parameters(int prime_len,int generator,
  void (*callback)(int,int,void *),void *cb_arg);



int DH_generate_parameters_ex(DH *dh, int prime_len,int generator, BN_GENCB *cb);

int DH_check(const DH *dh,int *codes);
int DH_check_pub_key(const DH *dh,const BIGNUM *pub_key, int *codes);
int DH_generate_key(DH *dh);
int DH_compute_key(unsigned char *key,const BIGNUM *pub_key,DH *dh);
DH * d2i_DHparams(DH **a,const unsigned char **pp, long length);
int i2d_DHparams(const DH *a,unsigned char **pp);

int DHparams_print_fp(FILE *fp, const DH *x);


int DHparams_print(BIO *bp, const DH *x);

void ERR_load_DH_strings(void);


typedef struct DSA_SIG_st
 {
 BIGNUM *r;
 BIGNUM *s;
 } DSA_SIG;

struct dsa_method
 {
 const char *name;
 DSA_SIG * (*dsa_do_sign)(const unsigned char *dgst, int dlen, DSA *dsa);
 int (*dsa_sign_setup)(DSA *dsa, BN_CTX *ctx_in, BIGNUM **kinvp,
        BIGNUM **rp);
 int (*dsa_do_verify)(const unsigned char *dgst, int dgst_len,
        DSA_SIG *sig, DSA *dsa);
 int (*dsa_mod_exp)(DSA *dsa, BIGNUM *rr, BIGNUM *a1, BIGNUM *p1,
   BIGNUM *a2, BIGNUM *p2, BIGNUM *m, BN_CTX *ctx,
   BN_MONT_CTX *in_mont);
 int (*bn_mod_exp)(DSA *dsa, BIGNUM *r, BIGNUM *a, const BIGNUM *p,
    const BIGNUM *m, BN_CTX *ctx,
    BN_MONT_CTX *m_ctx);
 int (*init)(DSA *dsa);
 int (*finish)(DSA *dsa);
 int flags;
 char *app_data;

 int (*dsa_paramgen)(DSA *dsa, int bits,
   const unsigned char *seed, int seed_len,
   int *counter_ret, unsigned long *h_ret,
   BN_GENCB *cb);

 int (*dsa_keygen)(DSA *dsa);
 };

struct dsa_st
 {


 int pad;
 long version;
 int write_params;
 BIGNUM *p;
 BIGNUM *q;
 BIGNUM *g;

 BIGNUM *pub_key;
 BIGNUM *priv_key;

 BIGNUM *kinv;
 BIGNUM *r;

 int flags;

 BN_MONT_CTX *method_mont_p;
 int references;
 CRYPTO_EX_DATA ex_data;
 const DSA_METHOD *meth;

 ENGINE *engine;
 };

DSA *DSAparams_dup(DSA *x);
DSA_SIG * DSA_SIG_new(void);
void DSA_SIG_free(DSA_SIG *a);
int i2d_DSA_SIG(const DSA_SIG *a, unsigned char **pp);
DSA_SIG * d2i_DSA_SIG(DSA_SIG **v, const unsigned char **pp, long length);

DSA_SIG * DSA_do_sign(const unsigned char *dgst,int dlen,DSA *dsa);
int DSA_do_verify(const unsigned char *dgst,int dgst_len,
        DSA_SIG *sig,DSA *dsa);

const DSA_METHOD *DSA_OpenSSL(void);

void DSA_set_default_method(const DSA_METHOD *);
const DSA_METHOD *DSA_get_default_method(void);
int DSA_set_method(DSA *dsa, const DSA_METHOD *);

DSA * DSA_new(void);
DSA * DSA_new_method(ENGINE *engine);
void DSA_free (DSA *r);

int DSA_up_ref(DSA *r);
int DSA_size(const DSA *);

int DSA_sign_setup( DSA *dsa,BN_CTX *ctx_in,BIGNUM **kinvp,BIGNUM **rp);
int DSA_sign(int type,const unsigned char *dgst,int dlen,
  unsigned char *sig, unsigned int *siglen, DSA *dsa);
int DSA_verify(int type,const unsigned char *dgst,int dgst_len,
  const unsigned char *sigbuf, int siglen, DSA *dsa);
int DSA_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func,
      CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func);
int DSA_set_ex_data(DSA *d, int idx, void *arg);
void *DSA_get_ex_data(DSA *d, int idx);

DSA * d2i_DSAPublicKey(DSA **a, const unsigned char **pp, long length);
DSA * d2i_DSAPrivateKey(DSA **a, const unsigned char **pp, long length);
DSA * d2i_DSAparams(DSA **a, const unsigned char **pp, long length);



DSA * DSA_generate_parameters(int bits,
  unsigned char *seed,int seed_len,
  int *counter_ret, unsigned long *h_ret,void
  (*callback)(int, int, void *),void *cb_arg);



int DSA_generate_parameters_ex(DSA *dsa, int bits,
  const unsigned char *seed,int seed_len,
  int *counter_ret, unsigned long *h_ret, BN_GENCB *cb);

int DSA_generate_key(DSA *a);
int i2d_DSAPublicKey(const DSA *a, unsigned char **pp);
int i2d_DSAPrivateKey(const DSA *a, unsigned char **pp);
int i2d_DSAparams(const DSA *a,unsigned char **pp);


int DSAparams_print(BIO *bp, const DSA *x);
int DSA_print(BIO *bp, const DSA *x, int off);


int DSAparams_print_fp(FILE *fp, const DSA *x);
int DSA_print_fp(FILE *bp, const DSA *x, int off);

DH *DSA_dup_DH(const DSA *r);

void ERR_load_DSA_strings(void);




















typedef struct SHAstate_st
 {
 unsigned int h0,h1,h2,h3,h4;
 unsigned int Nl,Nh;
 unsigned int data[16];
 unsigned int num;
 } SHA_CTX;





int SHA_Init(SHA_CTX *c);
int SHA_Update(SHA_CTX *c, const void *data, size_t len);
int SHA_Final(unsigned char *md, SHA_CTX *c);
unsigned char *SHA(const unsigned char *d, size_t n, unsigned char *md);
void SHA_Transform(SHA_CTX *c, const unsigned char *data);





int SHA1_Init(SHA_CTX *c);
int SHA1_Update(SHA_CTX *c, const void *data, size_t len);
int SHA1_Final(unsigned char *md, SHA_CTX *c);
unsigned char *SHA1(const unsigned char *d, size_t n, unsigned char *md);
void SHA1_Transform(SHA_CTX *c, const unsigned char *data);

typedef struct SHA256state_st
 {
 unsigned int h[8];
 unsigned int Nl,Nh;
 unsigned int data[16];
 unsigned int num,md_len;
 } SHA256_CTX;






int SHA224_Init(SHA256_CTX *c);
int SHA224_Update(SHA256_CTX *c, const void *data, size_t len);
int SHA224_Final(unsigned char *md, SHA256_CTX *c);
unsigned char *SHA224(const unsigned char *d, size_t n,unsigned char *md);
int SHA256_Init(SHA256_CTX *c);
int SHA256_Update(SHA256_CTX *c, const void *data, size_t len);
int SHA256_Final(unsigned char *md, SHA256_CTX *c);
unsigned char *SHA256(const unsigned char *d, size_t n,unsigned char *md);
void SHA256_Transform(SHA256_CTX *c, const unsigned char *data);

typedef struct SHA512state_st
 {
 unsigned long long h[8];
 unsigned long long Nl,Nh;
 union {
  unsigned long long d[16];
  unsigned char p[(16*8)];
 } u;
 unsigned int num,md_len;
 } SHA512_CTX;







int SHA384_Init(SHA512_CTX *c);
int SHA384_Update(SHA512_CTX *c, const void *data, size_t len);
int SHA384_Final(unsigned char *md, SHA512_CTX *c);
unsigned char *SHA384(const unsigned char *d, size_t n,unsigned char *md);
int SHA512_Init(SHA512_CTX *c);
int SHA512_Update(SHA512_CTX *c, const void *data, size_t len);
int SHA512_Final(unsigned char *md, SHA512_CTX *c);
unsigned char *SHA512(const unsigned char *d, size_t n,unsigned char *md);
void SHA512_Transform(SHA512_CTX *c, const unsigned char *data);


typedef struct X509_objects_st
 {
 int nid;
 int (*a2i)(void);
 int (*i2a)(void);
 } X509_OBJECTS;

struct X509_algor_st
 {
 ASN1_OBJECT *algorithm;
 ASN1_TYPE *parameter;
 } ;



typedef struct stack_st_X509_ALGOR X509_ALGORS;

typedef struct X509_val_st
 {
 ASN1_TIME *notBefore;
 ASN1_TIME *notAfter;
 } X509_VAL;

struct X509_pubkey_st
 {
 X509_ALGOR *algor;
 ASN1_BIT_STRING *public_key;
 EVP_PKEY *pkey;
 };

typedef struct X509_sig_st
 {
 X509_ALGOR *algor;
 ASN1_OCTET_STRING *digest;
 } X509_SIG;

typedef struct X509_name_entry_st
 {
 ASN1_OBJECT *object;
 ASN1_STRING *value;
 int set;
 int size;
 } X509_NAME_ENTRY;

struct stack_st_X509_NAME_ENTRY { _STACK stack; };



struct X509_name_st
 {
 struct stack_st_X509_NAME_ENTRY *entries;
 int modified;

 BUF_MEM *bytes;




 unsigned char *canon_enc;
 int canon_enclen;
 } ;

struct stack_st_X509_NAME { _STACK stack; };



typedef struct X509_extension_st
 {
 ASN1_OBJECT *object;
 ASN1_BOOLEAN critical;
 ASN1_OCTET_STRING *value;
 } X509_EXTENSION;

typedef struct stack_st_X509_EXTENSION X509_EXTENSIONS;

struct stack_st_X509_EXTENSION { _STACK stack; };



typedef struct x509_attributes_st
 {
 ASN1_OBJECT *object;
 int single;
 union {
  char *ptr;
         struct stack_st_ASN1_TYPE *set;
         ASN1_TYPE *single;
  } value;
 } X509_ATTRIBUTE;

struct stack_st_X509_ATTRIBUTE { _STACK stack; };



typedef struct X509_req_info_st
 {
 ASN1_ENCODING enc;
 ASN1_INTEGER *version;
 X509_NAME *subject;
 X509_PUBKEY *pubkey;

 struct stack_st_X509_ATTRIBUTE *attributes;
 } X509_REQ_INFO;

typedef struct X509_req_st
 {
 X509_REQ_INFO *req_info;
 X509_ALGOR *sig_alg;
 ASN1_BIT_STRING *signature;
 int references;
 } X509_REQ;

typedef struct x509_cinf_st
 {
 ASN1_INTEGER *version;
 ASN1_INTEGER *serialNumber;
 X509_ALGOR *signature;
 X509_NAME *issuer;
 X509_VAL *validity;
 X509_NAME *subject;
 X509_PUBKEY *key;
 ASN1_BIT_STRING *issuerUID;
 ASN1_BIT_STRING *subjectUID;
 struct stack_st_X509_EXTENSION *extensions;
 ASN1_ENCODING enc;
 } X509_CINF;







typedef struct x509_cert_aux_st
 {
 struct stack_st_ASN1_OBJECT *trust;
 struct stack_st_ASN1_OBJECT *reject;
 ASN1_UTF8STRING *alias;
 ASN1_OCTET_STRING *keyid;
 struct stack_st_X509_ALGOR *other;
 } X509_CERT_AUX;

struct x509_st
 {
 X509_CINF *cert_info;
 X509_ALGOR *sig_alg;
 ASN1_BIT_STRING *signature;
 int valid;
 int references;
 char *name;
 CRYPTO_EX_DATA ex_data;

 long ex_pathlen;
 long ex_pcpathlen;
 unsigned long ex_flags;
 unsigned long ex_kusage;
 unsigned long ex_xkusage;
 unsigned long ex_nscert;
 ASN1_OCTET_STRING *skid;
 AUTHORITY_KEYID *akid;
 X509_POLICY_CACHE *policy_cache;
 struct stack_st_DIST_POINT *crldp;
 struct stack_st_GENERAL_NAME *altname;
 NAME_CONSTRAINTS *nc;





 unsigned char sha1_hash[20];

 X509_CERT_AUX *aux;
 } ;

struct stack_st_X509 { _STACK stack; };




typedef struct x509_trust_st {
 int trust;
 int flags;
 int (*check_trust)(struct x509_trust_st *, X509 *, int);
 char *name;
 int arg1;
 void *arg2;
} X509_TRUST;

struct stack_st_X509_TRUST { _STACK stack; };

typedef struct x509_cert_pair_st {
 X509 *forward;
 X509 *reverse;
} X509_CERT_PAIR;

struct x509_revoked_st
 {
 ASN1_INTEGER *serialNumber;
 ASN1_TIME *revocationDate;
 struct stack_st_X509_EXTENSION *extensions;

 struct stack_st_GENERAL_NAME *issuer;

 int reason;
 int sequence;
 };

struct stack_st_X509_REVOKED { _STACK stack; };


typedef struct X509_crl_info_st
 {
 ASN1_INTEGER *version;
 X509_ALGOR *sig_alg;
 X509_NAME *issuer;
 ASN1_TIME *lastUpdate;
 ASN1_TIME *nextUpdate;
 struct stack_st_X509_REVOKED *revoked;
 struct stack_st_X509_EXTENSION *extensions;
 ASN1_ENCODING enc;
 } X509_CRL_INFO;

struct X509_crl_st
 {

 X509_CRL_INFO *crl;
 X509_ALGOR *sig_alg;
 ASN1_BIT_STRING *signature;
 int references;
 int flags;

 AUTHORITY_KEYID *akid;
 ISSUING_DIST_POINT *idp;

 int idp_flags;
 int idp_reasons;

 ASN1_INTEGER *crl_number;
 ASN1_INTEGER *base_crl_number;

 unsigned char sha1_hash[20];

 struct stack_st_GENERAL_NAMES *issuers;
 const X509_CRL_METHOD *meth;
 void *meth_data;
 } ;

struct stack_st_X509_CRL { _STACK stack; };


typedef struct private_key_st
 {
 int version;

 X509_ALGOR *enc_algor;
 ASN1_OCTET_STRING *enc_pkey;


 EVP_PKEY *dec_pkey;


 int key_length;
 char *key_data;
 int key_free;


 EVP_CIPHER_INFO cipher;

 int references;
 } X509_PKEY;


typedef struct X509_info_st
 {
 X509 *x509;
 X509_CRL *crl;
 X509_PKEY *x_pkey;

 EVP_CIPHER_INFO enc_cipher;
 int enc_len;
 char *enc_data;

 int references;
 } X509_INFO;

struct stack_st_X509_INFO { _STACK stack; };






typedef struct Netscape_spkac_st
 {
 X509_PUBKEY *pubkey;
 ASN1_IA5STRING *challenge;
 } NETSCAPE_SPKAC;

typedef struct Netscape_spki_st
 {
 NETSCAPE_SPKAC *spkac;
 X509_ALGOR *sig_algor;
 ASN1_BIT_STRING *signature;
 } NETSCAPE_SPKI;


typedef struct Netscape_certificate_sequence
 {
 ASN1_OBJECT *type;
 struct stack_st_X509 *certs;
 } NETSCAPE_CERT_SEQUENCE;

typedef struct PBEPARAM_st {
ASN1_OCTET_STRING *salt;
ASN1_INTEGER *iter;
} PBEPARAM;



typedef struct PBE2PARAM_st {
X509_ALGOR *keyfunc;
X509_ALGOR *encryption;
} PBE2PARAM;

typedef struct PBKDF2PARAM_st {
ASN1_TYPE *salt;
ASN1_INTEGER *iter;
ASN1_INTEGER *keylength;
X509_ALGOR *prf;
} PBKDF2PARAM;




struct pkcs8_priv_key_info_st
        {
        int broken;





        ASN1_INTEGER *version;
        X509_ALGOR *pkeyalg;
        ASN1_TYPE *pkey;
        struct stack_st_X509_ATTRIBUTE *attributes;
        };


















typedef struct lhash_node_st
 {
 void *data;
 struct lhash_node_st *next;

 unsigned long hash;

 } LHASH_NODE;

typedef int (*LHASH_COMP_FN_TYPE)(const void *, const void *);
typedef unsigned long (*LHASH_HASH_FN_TYPE)(const void *);
typedef void (*LHASH_DOALL_FN_TYPE)(void *);
typedef void (*LHASH_DOALL_ARG_FN_TYPE)(void *, void *);

typedef struct lhash_st
 {
 LHASH_NODE **b;
 LHASH_COMP_FN_TYPE comp;
 LHASH_HASH_FN_TYPE hash;
 unsigned int num_nodes;
 unsigned int num_alloc_nodes;
 unsigned int p;
 unsigned int pmax;
 unsigned long up_load;
 unsigned long down_load;
 unsigned long num_items;

 unsigned long num_expands;
 unsigned long num_expand_reallocs;
 unsigned long num_contracts;
 unsigned long num_contract_reallocs;
 unsigned long num_hash_calls;
 unsigned long num_comp_calls;
 unsigned long num_insert;
 unsigned long num_replace;
 unsigned long num_delete;
 unsigned long num_no_delete;
 unsigned long num_retrieve;
 unsigned long num_retrieve_miss;
 unsigned long num_hash_comps;

 int error;
 } _LHASH;

_LHASH *lh_new(LHASH_HASH_FN_TYPE h, LHASH_COMP_FN_TYPE c);
void lh_free(_LHASH *lh);
void *lh_insert(_LHASH *lh, void *data);
void *lh_delete(_LHASH *lh, const void *data);
void *lh_retrieve(_LHASH *lh, const void *data);
void lh_doall(_LHASH *lh, LHASH_DOALL_FN_TYPE func);
void lh_doall_arg(_LHASH *lh, LHASH_DOALL_ARG_FN_TYPE func, void *arg);
unsigned long lh_strhash(const char *c);
unsigned long lh_num_items(const _LHASH *lh);


void lh_stats(const _LHASH *lh, FILE *out);
void lh_node_stats(const _LHASH *lh, FILE *out);
void lh_node_usage_stats(const _LHASH *lh, FILE *out);



void lh_stats_bio(const _LHASH *lh, BIO *out);
void lh_node_stats_bio(const _LHASH *lh, BIO *out);
void lh_node_usage_stats_bio(const _LHASH *lh, BIO *out);

struct lhash_st_OPENSSL_STRING { int dummy; };
struct lhash_st_OPENSSL_CSTRING { int dummy; };


typedef struct x509_file_st
 {
 int num_paths;
 int num_alloced;
 char **paths;
 int *path_type;
 } X509_CERT_FILE_CTX;

typedef struct x509_object_st
 {

 int type;
 union {
  char *ptr;
  X509 *x509;
  X509_CRL *crl;
  EVP_PKEY *pkey;
  } data;
 } X509_OBJECT;

typedef struct x509_lookup_st X509_LOOKUP;

struct stack_st_X509_LOOKUP { _STACK stack; };
struct stack_st_X509_OBJECT { _STACK stack; };


typedef struct x509_lookup_method_st
 {
 const char *name;
 int (*new_item)(X509_LOOKUP *ctx);
 void (*free)(X509_LOOKUP *ctx);
 int (*init)(X509_LOOKUP *ctx);
 int (*shutdown)(X509_LOOKUP *ctx);
 int (*ctrl)(X509_LOOKUP *ctx,int cmd,const char *argc,long argl,
   char **ret);
 int (*get_by_subject)(X509_LOOKUP *ctx,int type,X509_NAME *name,
         X509_OBJECT *ret);
 int (*get_by_issuer_serial)(X509_LOOKUP *ctx,int type,X509_NAME *name,
        ASN1_INTEGER *serial,X509_OBJECT *ret);
 int (*get_by_fingerprint)(X509_LOOKUP *ctx,int type,
      unsigned char *bytes,int len,
      X509_OBJECT *ret);
 int (*get_by_alias)(X509_LOOKUP *ctx,int type,char *str,int len,
       X509_OBJECT *ret);
 } X509_LOOKUP_METHOD;






typedef struct X509_VERIFY_PARAM_st
 {
 char *name;
 time_t check_time;
 unsigned long inh_flags;
 unsigned long flags;
 int purpose;
 int trust;
 int depth;
 struct stack_st_ASN1_OBJECT *policies;
 } X509_VERIFY_PARAM;

struct stack_st_X509_VERIFY_PARAM { _STACK stack; };




struct x509_store_st
 {

 int cache;
 struct stack_st_X509_OBJECT *objs;


 struct stack_st_X509_LOOKUP *get_cert_methods;

 X509_VERIFY_PARAM *param;


 int (*verify)(X509_STORE_CTX *ctx);
 int (*verify_cb)(int ok,X509_STORE_CTX *ctx);
 int (*get_issuer)(X509 **issuer, X509_STORE_CTX *ctx, X509 *x);
 int (*check_issued)(X509_STORE_CTX *ctx, X509 *x, X509 *issuer);
 int (*check_revocation)(X509_STORE_CTX *ctx);
 int (*get_crl)(X509_STORE_CTX *ctx, X509_CRL **crl, X509 *x);
 int (*check_crl)(X509_STORE_CTX *ctx, X509_CRL *crl);
 int (*cert_crl)(X509_STORE_CTX *ctx, X509_CRL *crl, X509 *x);
 struct stack_st_X509 * (*lookup_certs)(X509_STORE_CTX *ctx, X509_NAME *nm);
 struct stack_st_X509_CRL * (*lookup_crls)(X509_STORE_CTX *ctx, X509_NAME *nm);
 int (*cleanup)(X509_STORE_CTX *ctx);

 CRYPTO_EX_DATA ex_data;
 int references;
 } ;

int X509_STORE_set_depth(X509_STORE *store, int depth);





struct x509_lookup_st
 {
 int init;
 int skip;
 X509_LOOKUP_METHOD *method;
 char *method_data;

 X509_STORE *store_ctx;
 } ;




struct x509_store_ctx_st
 {
 X509_STORE *ctx;
 int current_method;


 X509 *cert;
 struct stack_st_X509 *untrusted;
 struct stack_st_X509_CRL *crls;

 X509_VERIFY_PARAM *param;
 void *other_ctx;


 int (*verify)(X509_STORE_CTX *ctx);
 int (*verify_cb)(int ok,X509_STORE_CTX *ctx);
 int (*get_issuer)(X509 **issuer, X509_STORE_CTX *ctx, X509 *x);
 int (*check_issued)(X509_STORE_CTX *ctx, X509 *x, X509 *issuer);
 int (*check_revocation)(X509_STORE_CTX *ctx);
 int (*get_crl)(X509_STORE_CTX *ctx, X509_CRL **crl, X509 *x);
 int (*check_crl)(X509_STORE_CTX *ctx, X509_CRL *crl);
 int (*cert_crl)(X509_STORE_CTX *ctx, X509_CRL *crl, X509 *x);
 int (*check_policy)(X509_STORE_CTX *ctx);
 struct stack_st_X509 * (*lookup_certs)(X509_STORE_CTX *ctx, X509_NAME *nm);
 struct stack_st_X509_CRL * (*lookup_crls)(X509_STORE_CTX *ctx, X509_NAME *nm);
 int (*cleanup)(X509_STORE_CTX *ctx);


 int valid;
 int last_untrusted;
 struct stack_st_X509 *chain;
 X509_POLICY_TREE *tree;

 int explicit_policy;


 int error_depth;
 int error;
 X509 *current_cert;
 X509 *current_issuer;
 X509_CRL *current_crl;

 int current_crl_score;
 unsigned int current_reasons;

 X509_STORE_CTX *parent;

 CRYPTO_EX_DATA ex_data;
 } ;

void X509_STORE_CTX_set_depth(X509_STORE_CTX *ctx, int depth);

int X509_OBJECT_idx_by_subject(struct stack_st_X509_OBJECT *h, int type,
      X509_NAME *name);
X509_OBJECT *X509_OBJECT_retrieve_by_subject(struct stack_st_X509_OBJECT *h,int type,X509_NAME *name);
X509_OBJECT *X509_OBJECT_retrieve_match(struct stack_st_X509_OBJECT *h, X509_OBJECT *x);
void X509_OBJECT_up_ref_count(X509_OBJECT *a);
void X509_OBJECT_free_contents(X509_OBJECT *a);
X509_STORE *X509_STORE_new(void );
void X509_STORE_free(X509_STORE *v);

struct stack_st_X509* X509_STORE_get1_certs(X509_STORE_CTX *st, X509_NAME *nm);
struct stack_st_X509_CRL* X509_STORE_get1_crls(X509_STORE_CTX *st, X509_NAME *nm);
int X509_STORE_set_flags(X509_STORE *ctx, unsigned long flags);
int X509_STORE_set_purpose(X509_STORE *ctx, int purpose);
int X509_STORE_set_trust(X509_STORE *ctx, int trust);
int X509_STORE_set1_param(X509_STORE *ctx, X509_VERIFY_PARAM *pm);

void X509_STORE_set_verify_cb(X509_STORE *ctx,
      int (*verify_cb)(int, X509_STORE_CTX *));

X509_STORE_CTX *X509_STORE_CTX_new(void);

int X509_STORE_CTX_get1_issuer(X509 **issuer, X509_STORE_CTX *ctx, X509 *x);

void X509_STORE_CTX_free(X509_STORE_CTX *ctx);
int X509_STORE_CTX_init(X509_STORE_CTX *ctx, X509_STORE *store,
    X509 *x509, struct stack_st_X509 *chain);
void X509_STORE_CTX_trusted_stack(X509_STORE_CTX *ctx, struct stack_st_X509 *sk);
void X509_STORE_CTX_cleanup(X509_STORE_CTX *ctx);

X509_LOOKUP *X509_STORE_add_lookup(X509_STORE *v, X509_LOOKUP_METHOD *m);

X509_LOOKUP_METHOD *X509_LOOKUP_hash_dir(void);
X509_LOOKUP_METHOD *X509_LOOKUP_file(void);

int X509_STORE_add_cert(X509_STORE *ctx, X509 *x);
int X509_STORE_add_crl(X509_STORE *ctx, X509_CRL *x);

int X509_STORE_get_by_subject(X509_STORE_CTX *vs,int type,X509_NAME *name,
 X509_OBJECT *ret);

int X509_LOOKUP_ctrl(X509_LOOKUP *ctx, int cmd, const char *argc,
 long argl, char **ret);


int X509_load_cert_file(X509_LOOKUP *ctx, const char *file, int type);
int X509_load_crl_file(X509_LOOKUP *ctx, const char *file, int type);
int X509_load_cert_crl_file(X509_LOOKUP *ctx, const char *file, int type);



X509_LOOKUP *X509_LOOKUP_new(X509_LOOKUP_METHOD *method);
void X509_LOOKUP_free(X509_LOOKUP *ctx);
int X509_LOOKUP_init(X509_LOOKUP *ctx);
int X509_LOOKUP_by_subject(X509_LOOKUP *ctx, int type, X509_NAME *name,
 X509_OBJECT *ret);
int X509_LOOKUP_by_issuer_serial(X509_LOOKUP *ctx, int type, X509_NAME *name,
 ASN1_INTEGER *serial, X509_OBJECT *ret);
int X509_LOOKUP_by_fingerprint(X509_LOOKUP *ctx, int type,
 unsigned char *bytes, int len, X509_OBJECT *ret);
int X509_LOOKUP_by_alias(X509_LOOKUP *ctx, int type, char *str,
 int len, X509_OBJECT *ret);
int X509_LOOKUP_shutdown(X509_LOOKUP *ctx);


int X509_STORE_load_locations (X509_STORE *ctx,
  const char *file, const char *dir);
int X509_STORE_set_default_paths(X509_STORE *ctx);


int X509_STORE_CTX_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func,
 CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func);
int X509_STORE_CTX_set_ex_data(X509_STORE_CTX *ctx,int idx,void *data);
void * X509_STORE_CTX_get_ex_data(X509_STORE_CTX *ctx,int idx);
int X509_STORE_CTX_get_error(X509_STORE_CTX *ctx);
void X509_STORE_CTX_set_error(X509_STORE_CTX *ctx,int s);
int X509_STORE_CTX_get_error_depth(X509_STORE_CTX *ctx);
X509 * X509_STORE_CTX_get_current_cert(X509_STORE_CTX *ctx);
X509 *X509_STORE_CTX_get0_current_issuer(X509_STORE_CTX *ctx);
X509_CRL *X509_STORE_CTX_get0_current_crl(X509_STORE_CTX *ctx);
X509_STORE_CTX *X509_STORE_CTX_get0_parent_ctx(X509_STORE_CTX *ctx);
struct stack_st_X509 *X509_STORE_CTX_get_chain(X509_STORE_CTX *ctx);
struct stack_st_X509 *X509_STORE_CTX_get1_chain(X509_STORE_CTX *ctx);
void X509_STORE_CTX_set_cert(X509_STORE_CTX *c,X509 *x);
void X509_STORE_CTX_set_chain(X509_STORE_CTX *c,struct stack_st_X509 *sk);
void X509_STORE_CTX_set0_crls(X509_STORE_CTX *c,struct stack_st_X509_CRL *sk);
int X509_STORE_CTX_set_purpose(X509_STORE_CTX *ctx, int purpose);
int X509_STORE_CTX_set_trust(X509_STORE_CTX *ctx, int trust);
int X509_STORE_CTX_purpose_inherit(X509_STORE_CTX *ctx, int def_purpose,
    int purpose, int trust);
void X509_STORE_CTX_set_flags(X509_STORE_CTX *ctx, unsigned long flags);
void X509_STORE_CTX_set_time(X509_STORE_CTX *ctx, unsigned long flags,
        time_t t);
void X509_STORE_CTX_set_verify_cb(X509_STORE_CTX *ctx,
      int (*verify_cb)(int, X509_STORE_CTX *));

X509_POLICY_TREE *X509_STORE_CTX_get0_policy_tree(X509_STORE_CTX *ctx);
int X509_STORE_CTX_get_explicit_policy(X509_STORE_CTX *ctx);

X509_VERIFY_PARAM *X509_STORE_CTX_get0_param(X509_STORE_CTX *ctx);
void X509_STORE_CTX_set0_param(X509_STORE_CTX *ctx, X509_VERIFY_PARAM *param);
int X509_STORE_CTX_set_default(X509_STORE_CTX *ctx, const char *name);



X509_VERIFY_PARAM *X509_VERIFY_PARAM_new(void);
void X509_VERIFY_PARAM_free(X509_VERIFY_PARAM *param);
int X509_VERIFY_PARAM_inherit(X509_VERIFY_PARAM *to,
      const X509_VERIFY_PARAM *from);
int X509_VERIFY_PARAM_set1(X509_VERIFY_PARAM *to,
      const X509_VERIFY_PARAM *from);
int X509_VERIFY_PARAM_set1_name(X509_VERIFY_PARAM *param, const char *name);
int X509_VERIFY_PARAM_set_flags(X509_VERIFY_PARAM *param, unsigned long flags);
int X509_VERIFY_PARAM_clear_flags(X509_VERIFY_PARAM *param,
       unsigned long flags);
unsigned long X509_VERIFY_PARAM_get_flags(X509_VERIFY_PARAM *param);
int X509_VERIFY_PARAM_set_purpose(X509_VERIFY_PARAM *param, int purpose);
int X509_VERIFY_PARAM_set_trust(X509_VERIFY_PARAM *param, int trust);
void X509_VERIFY_PARAM_set_depth(X509_VERIFY_PARAM *param, int depth);
void X509_VERIFY_PARAM_set_time(X509_VERIFY_PARAM *param, time_t t);
int X509_VERIFY_PARAM_add0_policy(X509_VERIFY_PARAM *param,
      ASN1_OBJECT *policy);
int X509_VERIFY_PARAM_set1_policies(X509_VERIFY_PARAM *param,
     struct stack_st_ASN1_OBJECT *policies);
int X509_VERIFY_PARAM_get_depth(const X509_VERIFY_PARAM *param);

int X509_VERIFY_PARAM_add0_table(X509_VERIFY_PARAM *param);
const X509_VERIFY_PARAM *X509_VERIFY_PARAM_lookup(const char *name);
void X509_VERIFY_PARAM_table_cleanup(void);

int X509_policy_check(X509_POLICY_TREE **ptree, int *pexplicit_policy,
   struct stack_st_X509 *certs,
   struct stack_st_ASN1_OBJECT *policy_oids,
   unsigned int flags);

void X509_policy_tree_free(X509_POLICY_TREE *tree);

int X509_policy_tree_level_count(const X509_POLICY_TREE *tree);
X509_POLICY_LEVEL *
 X509_policy_tree_get0_level(const X509_POLICY_TREE *tree, int i);

struct stack_st_X509_POLICY_NODE *
 X509_policy_tree_get0_policies(const X509_POLICY_TREE *tree);

struct stack_st_X509_POLICY_NODE *
 X509_policy_tree_get0_user_policies(const X509_POLICY_TREE *tree);

int X509_policy_level_node_count(X509_POLICY_LEVEL *level);

X509_POLICY_NODE *X509_policy_level_get0_node(X509_POLICY_LEVEL *level, int i);

const ASN1_OBJECT *X509_policy_node_get0_policy(const X509_POLICY_NODE *node);

struct stack_st_POLICYQUALINFO *
 X509_policy_node_get0_qualifiers(const X509_POLICY_NODE *node);
const X509_POLICY_NODE *
 X509_policy_node_get0_parent(const X509_POLICY_NODE *node);









typedef struct pkcs7_issuer_and_serial_st
 {
 X509_NAME *issuer;
 ASN1_INTEGER *serial;
 } PKCS7_ISSUER_AND_SERIAL;

typedef struct pkcs7_signer_info_st
 {
 ASN1_INTEGER *version;
 PKCS7_ISSUER_AND_SERIAL *issuer_and_serial;
 X509_ALGOR *digest_alg;
 struct stack_st_X509_ATTRIBUTE *auth_attr;
 X509_ALGOR *digest_enc_alg;
 ASN1_OCTET_STRING *enc_digest;
 struct stack_st_X509_ATTRIBUTE *unauth_attr;


 EVP_PKEY *pkey;
 } PKCS7_SIGNER_INFO;

struct stack_st_PKCS7_SIGNER_INFO { _STACK stack; };


typedef struct pkcs7_recip_info_st
 {
 ASN1_INTEGER *version;
 PKCS7_ISSUER_AND_SERIAL *issuer_and_serial;
 X509_ALGOR *key_enc_algor;
 ASN1_OCTET_STRING *enc_key;
 X509 *cert;
 } PKCS7_RECIP_INFO;

struct stack_st_PKCS7_RECIP_INFO { _STACK stack; };


typedef struct pkcs7_signed_st
 {
 ASN1_INTEGER *version;
 struct stack_st_X509_ALGOR *md_algs;
 struct stack_st_X509 *cert;
 struct stack_st_X509_CRL *crl;
 struct stack_st_PKCS7_SIGNER_INFO *signer_info;

 struct pkcs7_st *contents;
 } PKCS7_SIGNED;



typedef struct pkcs7_enc_content_st
 {
 ASN1_OBJECT *content_type;
 X509_ALGOR *algorithm;
 ASN1_OCTET_STRING *enc_data;
 const EVP_CIPHER *cipher;
 } PKCS7_ENC_CONTENT;

typedef struct pkcs7_enveloped_st
 {
 ASN1_INTEGER *version;
 struct stack_st_PKCS7_RECIP_INFO *recipientinfo;
 PKCS7_ENC_CONTENT *enc_data;
 } PKCS7_ENVELOPE;

typedef struct pkcs7_signedandenveloped_st
 {
 ASN1_INTEGER *version;
 struct stack_st_X509_ALGOR *md_algs;
 struct stack_st_X509 *cert;
 struct stack_st_X509_CRL *crl;
 struct stack_st_PKCS7_SIGNER_INFO *signer_info;

 PKCS7_ENC_CONTENT *enc_data;
 struct stack_st_PKCS7_RECIP_INFO *recipientinfo;
 } PKCS7_SIGN_ENVELOPE;

typedef struct pkcs7_digest_st
 {
 ASN1_INTEGER *version;
 X509_ALGOR *md;
 struct pkcs7_st *contents;
 ASN1_OCTET_STRING *digest;
 } PKCS7_DIGEST;

typedef struct pkcs7_encrypted_st
 {
 ASN1_INTEGER *version;
 PKCS7_ENC_CONTENT *enc_data;
 } PKCS7_ENCRYPT;

typedef struct pkcs7_st
 {


 unsigned char *asn1;
 long length;




 int state;

 int detached;

 ASN1_OBJECT *type;



 union {
  char *ptr;


  ASN1_OCTET_STRING *data;


  PKCS7_SIGNED *sign;


  PKCS7_ENVELOPE *enveloped;


  PKCS7_SIGN_ENVELOPE *signed_and_enveloped;


  PKCS7_DIGEST *digest;


  PKCS7_ENCRYPT *encrypted;


  ASN1_TYPE *other;
  } d;
 } PKCS7;

struct stack_st_PKCS7 { _STACK stack; };



PKCS7_ISSUER_AND_SERIAL *PKCS7_ISSUER_AND_SERIAL_new(void); void PKCS7_ISSUER_AND_SERIAL_free(PKCS7_ISSUER_AND_SERIAL *a); PKCS7_ISSUER_AND_SERIAL *d2i_PKCS7_ISSUER_AND_SERIAL(PKCS7_ISSUER_AND_SERIAL **a, const unsigned char **in, long len); int i2d_PKCS7_ISSUER_AND_SERIAL(PKCS7_ISSUER_AND_SERIAL *a, unsigned char **out); extern const ASN1_ITEM PKCS7_ISSUER_AND_SERIAL_it;

int PKCS7_ISSUER_AND_SERIAL_digest(PKCS7_ISSUER_AND_SERIAL *data,const EVP_MD *type,
 unsigned char *md,unsigned int *len);

PKCS7 *d2i_PKCS7_fp(FILE *fp,PKCS7 **p7);
int i2d_PKCS7_fp(FILE *fp,PKCS7 *p7);

PKCS7 *PKCS7_dup(PKCS7 *p7);
PKCS7 *d2i_PKCS7_bio(BIO *bp,PKCS7 **p7);
int i2d_PKCS7_bio(BIO *bp,PKCS7 *p7);
int i2d_PKCS7_bio_stream(BIO *out, PKCS7 *p7, BIO *in, int flags);
int PEM_write_bio_PKCS7_stream(BIO *out, PKCS7 *p7, BIO *in, int flags);

PKCS7_SIGNER_INFO *PKCS7_SIGNER_INFO_new(void); void PKCS7_SIGNER_INFO_free(PKCS7_SIGNER_INFO *a); PKCS7_SIGNER_INFO *d2i_PKCS7_SIGNER_INFO(PKCS7_SIGNER_INFO **a, const unsigned char **in, long len); int i2d_PKCS7_SIGNER_INFO(PKCS7_SIGNER_INFO *a, unsigned char **out); extern const ASN1_ITEM PKCS7_SIGNER_INFO_it;
PKCS7_RECIP_INFO *PKCS7_RECIP_INFO_new(void); void PKCS7_RECIP_INFO_free(PKCS7_RECIP_INFO *a); PKCS7_RECIP_INFO *d2i_PKCS7_RECIP_INFO(PKCS7_RECIP_INFO **a, const unsigned char **in, long len); int i2d_PKCS7_RECIP_INFO(PKCS7_RECIP_INFO *a, unsigned char **out); extern const ASN1_ITEM PKCS7_RECIP_INFO_it;
PKCS7_SIGNED *PKCS7_SIGNED_new(void); void PKCS7_SIGNED_free(PKCS7_SIGNED *a); PKCS7_SIGNED *d2i_PKCS7_SIGNED(PKCS7_SIGNED **a, const unsigned char **in, long len); int i2d_PKCS7_SIGNED(PKCS7_SIGNED *a, unsigned char **out); extern const ASN1_ITEM PKCS7_SIGNED_it;
PKCS7_ENC_CONTENT *PKCS7_ENC_CONTENT_new(void); void PKCS7_ENC_CONTENT_free(PKCS7_ENC_CONTENT *a); PKCS7_ENC_CONTENT *d2i_PKCS7_ENC_CONTENT(PKCS7_ENC_CONTENT **a, const unsigned char **in, long len); int i2d_PKCS7_ENC_CONTENT(PKCS7_ENC_CONTENT *a, unsigned char **out); extern const ASN1_ITEM PKCS7_ENC_CONTENT_it;
PKCS7_ENVELOPE *PKCS7_ENVELOPE_new(void); void PKCS7_ENVELOPE_free(PKCS7_ENVELOPE *a); PKCS7_ENVELOPE *d2i_PKCS7_ENVELOPE(PKCS7_ENVELOPE **a, const unsigned char **in, long len); int i2d_PKCS7_ENVELOPE(PKCS7_ENVELOPE *a, unsigned char **out); extern const ASN1_ITEM PKCS7_ENVELOPE_it;
PKCS7_SIGN_ENVELOPE *PKCS7_SIGN_ENVELOPE_new(void); void PKCS7_SIGN_ENVELOPE_free(PKCS7_SIGN_ENVELOPE *a); PKCS7_SIGN_ENVELOPE *d2i_PKCS7_SIGN_ENVELOPE(PKCS7_SIGN_ENVELOPE **a, const unsigned char **in, long len); int i2d_PKCS7_SIGN_ENVELOPE(PKCS7_SIGN_ENVELOPE *a, unsigned char **out); extern const ASN1_ITEM PKCS7_SIGN_ENVELOPE_it;
PKCS7_DIGEST *PKCS7_DIGEST_new(void); void PKCS7_DIGEST_free(PKCS7_DIGEST *a); PKCS7_DIGEST *d2i_PKCS7_DIGEST(PKCS7_DIGEST **a, const unsigned char **in, long len); int i2d_PKCS7_DIGEST(PKCS7_DIGEST *a, unsigned char **out); extern const ASN1_ITEM PKCS7_DIGEST_it;
PKCS7_ENCRYPT *PKCS7_ENCRYPT_new(void); void PKCS7_ENCRYPT_free(PKCS7_ENCRYPT *a); PKCS7_ENCRYPT *d2i_PKCS7_ENCRYPT(PKCS7_ENCRYPT **a, const unsigned char **in, long len); int i2d_PKCS7_ENCRYPT(PKCS7_ENCRYPT *a, unsigned char **out); extern const ASN1_ITEM PKCS7_ENCRYPT_it;
PKCS7 *PKCS7_new(void); void PKCS7_free(PKCS7 *a); PKCS7 *d2i_PKCS7(PKCS7 **a, const unsigned char **in, long len); int i2d_PKCS7(PKCS7 *a, unsigned char **out); extern const ASN1_ITEM PKCS7_it;

extern const ASN1_ITEM PKCS7_ATTR_SIGN_it;
extern const ASN1_ITEM PKCS7_ATTR_VERIFY_it;

int i2d_PKCS7_NDEF(PKCS7 *a, unsigned char **out);
int PKCS7_print_ctx(BIO *out, PKCS7 *x, int indent, const ASN1_PCTX *pctx);

long PKCS7_ctrl(PKCS7 *p7, int cmd, long larg, char *parg);

int PKCS7_set_type(PKCS7 *p7, int type);
int PKCS7_set0_type_other(PKCS7 *p7, int type, ASN1_TYPE *other);
int PKCS7_set_content(PKCS7 *p7, PKCS7 *p7_data);
int PKCS7_SIGNER_INFO_set(PKCS7_SIGNER_INFO *p7i, X509 *x509, EVP_PKEY *pkey,
 const EVP_MD *dgst);
int PKCS7_SIGNER_INFO_sign(PKCS7_SIGNER_INFO *si);
int PKCS7_add_signer(PKCS7 *p7, PKCS7_SIGNER_INFO *p7i);
int PKCS7_add_certificate(PKCS7 *p7, X509 *x509);
int PKCS7_add_crl(PKCS7 *p7, X509_CRL *x509);
int PKCS7_content_new(PKCS7 *p7, int nid);
int PKCS7_dataVerify(X509_STORE *cert_store, X509_STORE_CTX *ctx,
 BIO *bio, PKCS7 *p7, PKCS7_SIGNER_INFO *si);
int PKCS7_signatureVerify(BIO *bio, PKCS7 *p7, PKCS7_SIGNER_INFO *si,
        X509 *x509);

BIO *PKCS7_dataInit(PKCS7 *p7, BIO *bio);
int PKCS7_dataFinal(PKCS7 *p7, BIO *bio);
BIO *PKCS7_dataDecode(PKCS7 *p7, EVP_PKEY *pkey, BIO *in_bio, X509 *pcert);


PKCS7_SIGNER_INFO *PKCS7_add_signature(PKCS7 *p7, X509 *x509,
 EVP_PKEY *pkey, const EVP_MD *dgst);
X509 *PKCS7_cert_from_signer_info(PKCS7 *p7, PKCS7_SIGNER_INFO *si);
int PKCS7_set_digest(PKCS7 *p7, const EVP_MD *md);
struct stack_st_PKCS7_SIGNER_INFO *PKCS7_get_signer_info(PKCS7 *p7);

PKCS7_RECIP_INFO *PKCS7_add_recipient(PKCS7 *p7, X509 *x509);
void PKCS7_SIGNER_INFO_get0_algs(PKCS7_SIGNER_INFO *si, EVP_PKEY **pk,
     X509_ALGOR **pdig, X509_ALGOR **psig);
void PKCS7_RECIP_INFO_get0_alg(PKCS7_RECIP_INFO *ri, X509_ALGOR **penc);
int PKCS7_add_recipient_info(PKCS7 *p7, PKCS7_RECIP_INFO *ri);
int PKCS7_RECIP_INFO_set(PKCS7_RECIP_INFO *p7i, X509 *x509);
int PKCS7_set_cipher(PKCS7 *p7, const EVP_CIPHER *cipher);
int PKCS7_stream(unsigned char ***boundary, PKCS7 *p7);

PKCS7_ISSUER_AND_SERIAL *PKCS7_get_issuer_and_serial(PKCS7 *p7, int idx);
ASN1_OCTET_STRING *PKCS7_digest_from_attributes(struct stack_st_X509_ATTRIBUTE *sk);
int PKCS7_add_signed_attribute(PKCS7_SIGNER_INFO *p7si,int nid,int type,
 void *data);
int PKCS7_add_attribute (PKCS7_SIGNER_INFO *p7si, int nid, int atrtype,
 void *value);
ASN1_TYPE *PKCS7_get_attribute(PKCS7_SIGNER_INFO *si, int nid);
ASN1_TYPE *PKCS7_get_signed_attribute(PKCS7_SIGNER_INFO *si, int nid);
int PKCS7_set_signed_attributes(PKCS7_SIGNER_INFO *p7si,
    struct stack_st_X509_ATTRIBUTE *sk);
int PKCS7_set_attributes(PKCS7_SIGNER_INFO *p7si,struct stack_st_X509_ATTRIBUTE *sk);


PKCS7 *PKCS7_sign(X509 *signcert, EVP_PKEY *pkey, struct stack_st_X509 *certs,
       BIO *data, int flags);

PKCS7_SIGNER_INFO *PKCS7_sign_add_signer(PKCS7 *p7,
   X509 *signcert, EVP_PKEY *pkey, const EVP_MD *md,
   int flags);

int PKCS7_final(PKCS7 *p7, BIO *data, int flags);
int PKCS7_verify(PKCS7 *p7, struct stack_st_X509 *certs, X509_STORE *store,
     BIO *indata, BIO *out, int flags);
struct stack_st_X509 *PKCS7_get0_signers(PKCS7 *p7, struct stack_st_X509 *certs, int flags);
PKCS7 *PKCS7_encrypt(struct stack_st_X509 *certs, BIO *in, const EVP_CIPHER *cipher,
        int flags);
int PKCS7_decrypt(PKCS7 *p7, EVP_PKEY *pkey, X509 *cert, BIO *data, int flags);

int PKCS7_add_attrib_smimecap(PKCS7_SIGNER_INFO *si,
         struct stack_st_X509_ALGOR *cap);
struct stack_st_X509_ALGOR *PKCS7_get_smimecap(PKCS7_SIGNER_INFO *si);
int PKCS7_simple_smimecap(struct stack_st_X509_ALGOR *sk, int nid, int arg);

int PKCS7_add_attrib_content_type(PKCS7_SIGNER_INFO *si, ASN1_OBJECT *coid);
int PKCS7_add0_attrib_signing_time(PKCS7_SIGNER_INFO *si, ASN1_TIME *t);
int PKCS7_add1_attrib_digest(PKCS7_SIGNER_INFO *si,
    const unsigned char *md, int mdlen);

int SMIME_write_PKCS7(BIO *bio, PKCS7 *p7, BIO *data, int flags);
PKCS7 *SMIME_read_PKCS7(BIO *bio, BIO **bcont);

BIO *BIO_new_PKCS7(BIO *out, PKCS7 *p7);






void ERR_load_PKCS7_strings(void);


void X509_CRL_set_default_method(const X509_CRL_METHOD *meth);
X509_CRL_METHOD *X509_CRL_METHOD_new(
 int (*crl_init)(X509_CRL *crl),
 int (*crl_free)(X509_CRL *crl),
 int (*crl_lookup)(X509_CRL *crl, X509_REVOKED **ret,
    ASN1_INTEGER *ser, X509_NAME *issuer),
 int (*crl_verify)(X509_CRL *crl, EVP_PKEY *pk));
void X509_CRL_METHOD_free(X509_CRL_METHOD *m);

void X509_CRL_set_meth_data(X509_CRL *crl, void *dat);
void *X509_CRL_get_meth_data(X509_CRL *crl);






const char *X509_verify_cert_error_string(long n);


int X509_verify(X509 *a, EVP_PKEY *r);

int X509_REQ_verify(X509_REQ *a, EVP_PKEY *r);
int X509_CRL_verify(X509_CRL *a, EVP_PKEY *r);
int NETSCAPE_SPKI_verify(NETSCAPE_SPKI *a, EVP_PKEY *r);

NETSCAPE_SPKI * NETSCAPE_SPKI_b64_decode(const char *str, int len);
char * NETSCAPE_SPKI_b64_encode(NETSCAPE_SPKI *x);
EVP_PKEY *NETSCAPE_SPKI_get_pubkey(NETSCAPE_SPKI *x);
int NETSCAPE_SPKI_set_pubkey(NETSCAPE_SPKI *x, EVP_PKEY *pkey);

int NETSCAPE_SPKI_print(BIO *out, NETSCAPE_SPKI *spki);

int X509_signature_dump(BIO *bp,const ASN1_STRING *sig, int indent);
int X509_signature_print(BIO *bp,X509_ALGOR *alg, ASN1_STRING *sig);

int X509_sign(X509 *x, EVP_PKEY *pkey, const EVP_MD *md);
int X509_sign_ctx(X509 *x, EVP_MD_CTX *ctx);
int X509_REQ_sign(X509_REQ *x, EVP_PKEY *pkey, const EVP_MD *md);
int X509_REQ_sign_ctx(X509_REQ *x, EVP_MD_CTX *ctx);
int X509_CRL_sign(X509_CRL *x, EVP_PKEY *pkey, const EVP_MD *md);
int X509_CRL_sign_ctx(X509_CRL *x, EVP_MD_CTX *ctx);
int NETSCAPE_SPKI_sign(NETSCAPE_SPKI *x, EVP_PKEY *pkey, const EVP_MD *md);

int X509_pubkey_digest(const X509 *data,const EVP_MD *type,
  unsigned char *md, unsigned int *len);
int X509_digest(const X509 *data,const EVP_MD *type,
  unsigned char *md, unsigned int *len);
int X509_CRL_digest(const X509_CRL *data,const EVP_MD *type,
  unsigned char *md, unsigned int *len);
int X509_REQ_digest(const X509_REQ *data,const EVP_MD *type,
  unsigned char *md, unsigned int *len);
int X509_NAME_digest(const X509_NAME *data,const EVP_MD *type,
  unsigned char *md, unsigned int *len);



X509 *d2i_X509_fp(FILE *fp, X509 **x509);
int i2d_X509_fp(FILE *fp,X509 *x509);
X509_CRL *d2i_X509_CRL_fp(FILE *fp,X509_CRL **crl);
int i2d_X509_CRL_fp(FILE *fp,X509_CRL *crl);
X509_REQ *d2i_X509_REQ_fp(FILE *fp,X509_REQ **req);
int i2d_X509_REQ_fp(FILE *fp,X509_REQ *req);

RSA *d2i_RSAPrivateKey_fp(FILE *fp,RSA **rsa);
int i2d_RSAPrivateKey_fp(FILE *fp,RSA *rsa);
RSA *d2i_RSAPublicKey_fp(FILE *fp,RSA **rsa);
int i2d_RSAPublicKey_fp(FILE *fp,RSA *rsa);
RSA *d2i_RSA_PUBKEY_fp(FILE *fp,RSA **rsa);
int i2d_RSA_PUBKEY_fp(FILE *fp,RSA *rsa);


DSA *d2i_DSA_PUBKEY_fp(FILE *fp, DSA **dsa);
int i2d_DSA_PUBKEY_fp(FILE *fp, DSA *dsa);
DSA *d2i_DSAPrivateKey_fp(FILE *fp, DSA **dsa);
int i2d_DSAPrivateKey_fp(FILE *fp, DSA *dsa);


EC_KEY *d2i_EC_PUBKEY_fp(FILE *fp, EC_KEY **eckey);
int i2d_EC_PUBKEY_fp(FILE *fp, EC_KEY *eckey);
EC_KEY *d2i_ECPrivateKey_fp(FILE *fp, EC_KEY **eckey);
int i2d_ECPrivateKey_fp(FILE *fp, EC_KEY *eckey);

X509_SIG *d2i_PKCS8_fp(FILE *fp,X509_SIG **p8);
int i2d_PKCS8_fp(FILE *fp,X509_SIG *p8);
PKCS8_PRIV_KEY_INFO *d2i_PKCS8_PRIV_KEY_INFO_fp(FILE *fp,
      PKCS8_PRIV_KEY_INFO **p8inf);
int i2d_PKCS8_PRIV_KEY_INFO_fp(FILE *fp,PKCS8_PRIV_KEY_INFO *p8inf);
int i2d_PKCS8PrivateKeyInfo_fp(FILE *fp, EVP_PKEY *key);
int i2d_PrivateKey_fp(FILE *fp, EVP_PKEY *pkey);
EVP_PKEY *d2i_PrivateKey_fp(FILE *fp, EVP_PKEY **a);
int i2d_PUBKEY_fp(FILE *fp, EVP_PKEY *pkey);
EVP_PKEY *d2i_PUBKEY_fp(FILE *fp, EVP_PKEY **a);



X509 *d2i_X509_bio(BIO *bp,X509 **x509);
int i2d_X509_bio(BIO *bp,X509 *x509);
X509_CRL *d2i_X509_CRL_bio(BIO *bp,X509_CRL **crl);
int i2d_X509_CRL_bio(BIO *bp,X509_CRL *crl);
X509_REQ *d2i_X509_REQ_bio(BIO *bp,X509_REQ **req);
int i2d_X509_REQ_bio(BIO *bp,X509_REQ *req);

RSA *d2i_RSAPrivateKey_bio(BIO *bp,RSA **rsa);
int i2d_RSAPrivateKey_bio(BIO *bp,RSA *rsa);
RSA *d2i_RSAPublicKey_bio(BIO *bp,RSA **rsa);
int i2d_RSAPublicKey_bio(BIO *bp,RSA *rsa);
RSA *d2i_RSA_PUBKEY_bio(BIO *bp,RSA **rsa);
int i2d_RSA_PUBKEY_bio(BIO *bp,RSA *rsa);


DSA *d2i_DSA_PUBKEY_bio(BIO *bp, DSA **dsa);
int i2d_DSA_PUBKEY_bio(BIO *bp, DSA *dsa);
DSA *d2i_DSAPrivateKey_bio(BIO *bp, DSA **dsa);
int i2d_DSAPrivateKey_bio(BIO *bp, DSA *dsa);


EC_KEY *d2i_EC_PUBKEY_bio(BIO *bp, EC_KEY **eckey);
int i2d_EC_PUBKEY_bio(BIO *bp, EC_KEY *eckey);
EC_KEY *d2i_ECPrivateKey_bio(BIO *bp, EC_KEY **eckey);
int i2d_ECPrivateKey_bio(BIO *bp, EC_KEY *eckey);

X509_SIG *d2i_PKCS8_bio(BIO *bp,X509_SIG **p8);
int i2d_PKCS8_bio(BIO *bp,X509_SIG *p8);
PKCS8_PRIV_KEY_INFO *d2i_PKCS8_PRIV_KEY_INFO_bio(BIO *bp,
      PKCS8_PRIV_KEY_INFO **p8inf);
int i2d_PKCS8_PRIV_KEY_INFO_bio(BIO *bp,PKCS8_PRIV_KEY_INFO *p8inf);
int i2d_PKCS8PrivateKeyInfo_bio(BIO *bp, EVP_PKEY *key);
int i2d_PrivateKey_bio(BIO *bp, EVP_PKEY *pkey);
EVP_PKEY *d2i_PrivateKey_bio(BIO *bp, EVP_PKEY **a);
int i2d_PUBKEY_bio(BIO *bp, EVP_PKEY *pkey);
EVP_PKEY *d2i_PUBKEY_bio(BIO *bp, EVP_PKEY **a);


X509 *X509_dup(X509 *x509);
X509_ATTRIBUTE *X509_ATTRIBUTE_dup(X509_ATTRIBUTE *xa);
X509_EXTENSION *X509_EXTENSION_dup(X509_EXTENSION *ex);
X509_CRL *X509_CRL_dup(X509_CRL *crl);
X509_REQ *X509_REQ_dup(X509_REQ *req);
X509_ALGOR *X509_ALGOR_dup(X509_ALGOR *xn);
int X509_ALGOR_set0(X509_ALGOR *alg, ASN1_OBJECT *aobj, int ptype, void *pval);
void X509_ALGOR_get0(ASN1_OBJECT **paobj, int *pptype, void **ppval,
      X509_ALGOR *algor);
void X509_ALGOR_set_md(X509_ALGOR *alg, const EVP_MD *md);
int X509_ALGOR_cmp(const X509_ALGOR *a, const X509_ALGOR *b);

X509_NAME *X509_NAME_dup(X509_NAME *xn);
X509_NAME_ENTRY *X509_NAME_ENTRY_dup(X509_NAME_ENTRY *ne);

int X509_cmp_time(const ASN1_TIME *s, time_t *t);
int X509_cmp_current_time(const ASN1_TIME *s);
ASN1_TIME * X509_time_adj(ASN1_TIME *s, long adj, time_t *t);
ASN1_TIME * X509_time_adj_ex(ASN1_TIME *s,
    int offset_day, long offset_sec, time_t *t);
ASN1_TIME * X509_gmtime_adj(ASN1_TIME *s, long adj);

const char * X509_get_default_cert_area(void );
const char * X509_get_default_cert_dir(void );
const char * X509_get_default_cert_file(void );
const char * X509_get_default_cert_dir_env(void );
const char * X509_get_default_cert_file_env(void );
const char * X509_get_default_private_dir(void );

X509_REQ * X509_to_X509_REQ(X509 *x, EVP_PKEY *pkey, const EVP_MD *md);
X509 * X509_REQ_to_X509(X509_REQ *r, int days,EVP_PKEY *pkey);

X509_ALGOR *X509_ALGOR_new(void); void X509_ALGOR_free(X509_ALGOR *a); X509_ALGOR *d2i_X509_ALGOR(X509_ALGOR **a, const unsigned char **in, long len); int i2d_X509_ALGOR(X509_ALGOR *a, unsigned char **out); extern const ASN1_ITEM X509_ALGOR_it;
X509_ALGORS *d2i_X509_ALGORS(X509_ALGORS **a, const unsigned char **in, long len); int i2d_X509_ALGORS(X509_ALGORS *a, unsigned char **out); extern const ASN1_ITEM X509_ALGORS_it;
X509_VAL *X509_VAL_new(void); void X509_VAL_free(X509_VAL *a); X509_VAL *d2i_X509_VAL(X509_VAL **a, const unsigned char **in, long len); int i2d_X509_VAL(X509_VAL *a, unsigned char **out); extern const ASN1_ITEM X509_VAL_it;

X509_PUBKEY *X509_PUBKEY_new(void); void X509_PUBKEY_free(X509_PUBKEY *a); X509_PUBKEY *d2i_X509_PUBKEY(X509_PUBKEY **a, const unsigned char **in, long len); int i2d_X509_PUBKEY(X509_PUBKEY *a, unsigned char **out); extern const ASN1_ITEM X509_PUBKEY_it;

int X509_PUBKEY_set(X509_PUBKEY **x, EVP_PKEY *pkey);
EVP_PKEY * X509_PUBKEY_get(X509_PUBKEY *key);
int X509_get_pubkey_parameters(EVP_PKEY *pkey,
        struct stack_st_X509 *chain);
int i2d_PUBKEY(EVP_PKEY *a,unsigned char **pp);
EVP_PKEY * d2i_PUBKEY(EVP_PKEY **a,const unsigned char **pp,
   long length);

int i2d_RSA_PUBKEY(RSA *a,unsigned char **pp);
RSA * d2i_RSA_PUBKEY(RSA **a,const unsigned char **pp,
   long length);


int i2d_DSA_PUBKEY(DSA *a,unsigned char **pp);
DSA * d2i_DSA_PUBKEY(DSA **a,const unsigned char **pp,
   long length);


int i2d_EC_PUBKEY(EC_KEY *a, unsigned char **pp);
EC_KEY *d2i_EC_PUBKEY(EC_KEY **a, const unsigned char **pp,
   long length);


X509_SIG *X509_SIG_new(void); void X509_SIG_free(X509_SIG *a); X509_SIG *d2i_X509_SIG(X509_SIG **a, const unsigned char **in, long len); int i2d_X509_SIG(X509_SIG *a, unsigned char **out); extern const ASN1_ITEM X509_SIG_it;
X509_REQ_INFO *X509_REQ_INFO_new(void); void X509_REQ_INFO_free(X509_REQ_INFO *a); X509_REQ_INFO *d2i_X509_REQ_INFO(X509_REQ_INFO **a, const unsigned char **in, long len); int i2d_X509_REQ_INFO(X509_REQ_INFO *a, unsigned char **out); extern const ASN1_ITEM X509_REQ_INFO_it;
X509_REQ *X509_REQ_new(void); void X509_REQ_free(X509_REQ *a); X509_REQ *d2i_X509_REQ(X509_REQ **a, const unsigned char **in, long len); int i2d_X509_REQ(X509_REQ *a, unsigned char **out); extern const ASN1_ITEM X509_REQ_it;

X509_ATTRIBUTE *X509_ATTRIBUTE_new(void); void X509_ATTRIBUTE_free(X509_ATTRIBUTE *a); X509_ATTRIBUTE *d2i_X509_ATTRIBUTE(X509_ATTRIBUTE **a, const unsigned char **in, long len); int i2d_X509_ATTRIBUTE(X509_ATTRIBUTE *a, unsigned char **out); extern const ASN1_ITEM X509_ATTRIBUTE_it;
X509_ATTRIBUTE *X509_ATTRIBUTE_create(int nid, int atrtype, void *value);

X509_EXTENSION *X509_EXTENSION_new(void); void X509_EXTENSION_free(X509_EXTENSION *a); X509_EXTENSION *d2i_X509_EXTENSION(X509_EXTENSION **a, const unsigned char **in, long len); int i2d_X509_EXTENSION(X509_EXTENSION *a, unsigned char **out); extern const ASN1_ITEM X509_EXTENSION_it;
X509_EXTENSIONS *d2i_X509_EXTENSIONS(X509_EXTENSIONS **a, const unsigned char **in, long len); int i2d_X509_EXTENSIONS(X509_EXTENSIONS *a, unsigned char **out); extern const ASN1_ITEM X509_EXTENSIONS_it;

X509_NAME_ENTRY *X509_NAME_ENTRY_new(void); void X509_NAME_ENTRY_free(X509_NAME_ENTRY *a); X509_NAME_ENTRY *d2i_X509_NAME_ENTRY(X509_NAME_ENTRY **a, const unsigned char **in, long len); int i2d_X509_NAME_ENTRY(X509_NAME_ENTRY *a, unsigned char **out); extern const ASN1_ITEM X509_NAME_ENTRY_it;

X509_NAME *X509_NAME_new(void); void X509_NAME_free(X509_NAME *a); X509_NAME *d2i_X509_NAME(X509_NAME **a, const unsigned char **in, long len); int i2d_X509_NAME(X509_NAME *a, unsigned char **out); extern const ASN1_ITEM X509_NAME_it;

int X509_NAME_set(X509_NAME **xn, X509_NAME *name);

X509_CINF *X509_CINF_new(void); void X509_CINF_free(X509_CINF *a); X509_CINF *d2i_X509_CINF(X509_CINF **a, const unsigned char **in, long len); int i2d_X509_CINF(X509_CINF *a, unsigned char **out); extern const ASN1_ITEM X509_CINF_it;

X509 *X509_new(void); void X509_free(X509 *a); X509 *d2i_X509(X509 **a, const unsigned char **in, long len); int i2d_X509(X509 *a, unsigned char **out); extern const ASN1_ITEM X509_it;
X509_CERT_AUX *X509_CERT_AUX_new(void); void X509_CERT_AUX_free(X509_CERT_AUX *a); X509_CERT_AUX *d2i_X509_CERT_AUX(X509_CERT_AUX **a, const unsigned char **in, long len); int i2d_X509_CERT_AUX(X509_CERT_AUX *a, unsigned char **out); extern const ASN1_ITEM X509_CERT_AUX_it;

X509_CERT_PAIR *X509_CERT_PAIR_new(void); void X509_CERT_PAIR_free(X509_CERT_PAIR *a); X509_CERT_PAIR *d2i_X509_CERT_PAIR(X509_CERT_PAIR **a, const unsigned char **in, long len); int i2d_X509_CERT_PAIR(X509_CERT_PAIR *a, unsigned char **out); extern const ASN1_ITEM X509_CERT_PAIR_it;

int X509_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func,
      CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func);
int X509_set_ex_data(X509 *r, int idx, void *arg);
void *X509_get_ex_data(X509 *r, int idx);
int i2d_X509_AUX(X509 *a,unsigned char **pp);
X509 * d2i_X509_AUX(X509 **a,const unsigned char **pp,long length);

int X509_alias_set1(X509 *x, unsigned char *name, int len);
int X509_keyid_set1(X509 *x, unsigned char *id, int len);
unsigned char * X509_alias_get0(X509 *x, int *len);
unsigned char * X509_keyid_get0(X509 *x, int *len);
int (*X509_TRUST_set_default(int (*trust)(int , X509 *, int)))(int, X509 *, int);
int X509_TRUST_set(int *t, int trust);
int X509_add1_trust_object(X509 *x, ASN1_OBJECT *obj);
int X509_add1_reject_object(X509 *x, ASN1_OBJECT *obj);
void X509_trust_clear(X509 *x);
void X509_reject_clear(X509 *x);

X509_REVOKED *X509_REVOKED_new(void); void X509_REVOKED_free(X509_REVOKED *a); X509_REVOKED *d2i_X509_REVOKED(X509_REVOKED **a, const unsigned char **in, long len); int i2d_X509_REVOKED(X509_REVOKED *a, unsigned char **out); extern const ASN1_ITEM X509_REVOKED_it;
X509_CRL_INFO *X509_CRL_INFO_new(void); void X509_CRL_INFO_free(X509_CRL_INFO *a); X509_CRL_INFO *d2i_X509_CRL_INFO(X509_CRL_INFO **a, const unsigned char **in, long len); int i2d_X509_CRL_INFO(X509_CRL_INFO *a, unsigned char **out); extern const ASN1_ITEM X509_CRL_INFO_it;
X509_CRL *X509_CRL_new(void); void X509_CRL_free(X509_CRL *a); X509_CRL *d2i_X509_CRL(X509_CRL **a, const unsigned char **in, long len); int i2d_X509_CRL(X509_CRL *a, unsigned char **out); extern const ASN1_ITEM X509_CRL_it;

int X509_CRL_add0_revoked(X509_CRL *crl, X509_REVOKED *rev);
int X509_CRL_get0_by_serial(X509_CRL *crl,
  X509_REVOKED **ret, ASN1_INTEGER *serial);
int X509_CRL_get0_by_cert(X509_CRL *crl, X509_REVOKED **ret, X509 *x);

X509_PKEY * X509_PKEY_new(void );
void X509_PKEY_free(X509_PKEY *a);
int i2d_X509_PKEY(X509_PKEY *a,unsigned char **pp);
X509_PKEY * d2i_X509_PKEY(X509_PKEY **a,const unsigned char **pp,long length);

NETSCAPE_SPKI *NETSCAPE_SPKI_new(void); void NETSCAPE_SPKI_free(NETSCAPE_SPKI *a); NETSCAPE_SPKI *d2i_NETSCAPE_SPKI(NETSCAPE_SPKI **a, const unsigned char **in, long len); int i2d_NETSCAPE_SPKI(NETSCAPE_SPKI *a, unsigned char **out); extern const ASN1_ITEM NETSCAPE_SPKI_it;
NETSCAPE_SPKAC *NETSCAPE_SPKAC_new(void); void NETSCAPE_SPKAC_free(NETSCAPE_SPKAC *a); NETSCAPE_SPKAC *d2i_NETSCAPE_SPKAC(NETSCAPE_SPKAC **a, const unsigned char **in, long len); int i2d_NETSCAPE_SPKAC(NETSCAPE_SPKAC *a, unsigned char **out); extern const ASN1_ITEM NETSCAPE_SPKAC_it;
NETSCAPE_CERT_SEQUENCE *NETSCAPE_CERT_SEQUENCE_new(void); void NETSCAPE_CERT_SEQUENCE_free(NETSCAPE_CERT_SEQUENCE *a); NETSCAPE_CERT_SEQUENCE *d2i_NETSCAPE_CERT_SEQUENCE(NETSCAPE_CERT_SEQUENCE **a, const unsigned char **in, long len); int i2d_NETSCAPE_CERT_SEQUENCE(NETSCAPE_CERT_SEQUENCE *a, unsigned char **out); extern const ASN1_ITEM NETSCAPE_CERT_SEQUENCE_it;


X509_INFO * X509_INFO_new(void);
void X509_INFO_free(X509_INFO *a);
char * X509_NAME_oneline(X509_NAME *a,char *buf,int size);

int ASN1_verify(i2d_of_void *i2d, X509_ALGOR *algor1,
  ASN1_BIT_STRING *signature,char *data,EVP_PKEY *pkey);

int ASN1_digest(i2d_of_void *i2d,const EVP_MD *type,char *data,
  unsigned char *md,unsigned int *len);

int ASN1_sign(i2d_of_void *i2d, X509_ALGOR *algor1,
       X509_ALGOR *algor2, ASN1_BIT_STRING *signature,
       char *data,EVP_PKEY *pkey, const EVP_MD *type);

int ASN1_item_digest(const ASN1_ITEM *it,const EVP_MD *type,void *data,
 unsigned char *md,unsigned int *len);

int ASN1_item_verify(const ASN1_ITEM *it, X509_ALGOR *algor1,
 ASN1_BIT_STRING *signature,void *data,EVP_PKEY *pkey);

int ASN1_item_sign(const ASN1_ITEM *it, X509_ALGOR *algor1, X509_ALGOR *algor2,
 ASN1_BIT_STRING *signature,
 void *data, EVP_PKEY *pkey, const EVP_MD *type);
int ASN1_item_sign_ctx(const ASN1_ITEM *it,
  X509_ALGOR *algor1, X509_ALGOR *algor2,
       ASN1_BIT_STRING *signature, void *asn, EVP_MD_CTX *ctx);


int X509_set_version(X509 *x,long version);
int X509_set_serialNumber(X509 *x, ASN1_INTEGER *serial);
ASN1_INTEGER * X509_get_serialNumber(X509 *x);
int X509_set_issuer_name(X509 *x, X509_NAME *name);
X509_NAME * X509_get_issuer_name(X509 *a);
int X509_set_subject_name(X509 *x, X509_NAME *name);
X509_NAME * X509_get_subject_name(X509 *a);
int X509_set_notBefore(X509 *x, const ASN1_TIME *tm);
int X509_set_notAfter(X509 *x, const ASN1_TIME *tm);
int X509_set_pubkey(X509 *x, EVP_PKEY *pkey);
EVP_PKEY * X509_get_pubkey(X509 *x);
ASN1_BIT_STRING * X509_get0_pubkey_bitstr(const X509 *x);
int X509_certificate_type(X509 *x,EVP_PKEY *pubkey );

int X509_REQ_set_version(X509_REQ *x,long version);
int X509_REQ_set_subject_name(X509_REQ *req,X509_NAME *name);
int X509_REQ_set_pubkey(X509_REQ *x, EVP_PKEY *pkey);
EVP_PKEY * X509_REQ_get_pubkey(X509_REQ *req);
int X509_REQ_extension_nid(int nid);
int * X509_REQ_get_extension_nids(void);
void X509_REQ_set_extension_nids(int *nids);
struct stack_st_X509_EXTENSION *X509_REQ_get_extensions(X509_REQ *req);
int X509_REQ_add_extensions_nid(X509_REQ *req, struct stack_st_X509_EXTENSION *exts,
    int nid);
int X509_REQ_add_extensions(X509_REQ *req, struct stack_st_X509_EXTENSION *exts);
int X509_REQ_get_attr_count(const X509_REQ *req);
int X509_REQ_get_attr_by_NID(const X509_REQ *req, int nid,
     int lastpos);
int X509_REQ_get_attr_by_OBJ(const X509_REQ *req, ASN1_OBJECT *obj,
     int lastpos);
X509_ATTRIBUTE *X509_REQ_get_attr(const X509_REQ *req, int loc);
X509_ATTRIBUTE *X509_REQ_delete_attr(X509_REQ *req, int loc);
int X509_REQ_add1_attr(X509_REQ *req, X509_ATTRIBUTE *attr);
int X509_REQ_add1_attr_by_OBJ(X509_REQ *req,
   const ASN1_OBJECT *obj, int type,
   const unsigned char *bytes, int len);
int X509_REQ_add1_attr_by_NID(X509_REQ *req,
   int nid, int type,
   const unsigned char *bytes, int len);
int X509_REQ_add1_attr_by_txt(X509_REQ *req,
   const char *attrname, int type,
   const unsigned char *bytes, int len);

int X509_CRL_set_version(X509_CRL *x, long version);
int X509_CRL_set_issuer_name(X509_CRL *x, X509_NAME *name);
int X509_CRL_set_lastUpdate(X509_CRL *x, const ASN1_TIME *tm);
int X509_CRL_set_nextUpdate(X509_CRL *x, const ASN1_TIME *tm);
int X509_CRL_sort(X509_CRL *crl);

int X509_REVOKED_set_serialNumber(X509_REVOKED *x, ASN1_INTEGER *serial);
int X509_REVOKED_set_revocationDate(X509_REVOKED *r, ASN1_TIME *tm);

int X509_REQ_check_private_key(X509_REQ *x509,EVP_PKEY *pkey);

int X509_check_private_key(X509 *x509,EVP_PKEY *pkey);

int X509_issuer_and_serial_cmp(const X509 *a, const X509 *b);
unsigned long X509_issuer_and_serial_hash(X509 *a);

int X509_issuer_name_cmp(const X509 *a, const X509 *b);
unsigned long X509_issuer_name_hash(X509 *a);

int X509_subject_name_cmp(const X509 *a, const X509 *b);
unsigned long X509_subject_name_hash(X509 *x);


unsigned long X509_issuer_name_hash_old(X509 *a);
unsigned long X509_subject_name_hash_old(X509 *x);


int X509_cmp(const X509 *a, const X509 *b);
int X509_NAME_cmp(const X509_NAME *a, const X509_NAME *b);
unsigned long X509_NAME_hash(X509_NAME *x);
unsigned long X509_NAME_hash_old(X509_NAME *x);

int X509_CRL_cmp(const X509_CRL *a, const X509_CRL *b);
int X509_CRL_match(const X509_CRL *a, const X509_CRL *b);

int X509_print_ex_fp(FILE *bp,X509 *x, unsigned long nmflag, unsigned long cflag);
int X509_print_fp(FILE *bp,X509 *x);
int X509_CRL_print_fp(FILE *bp,X509_CRL *x);
int X509_REQ_print_fp(FILE *bp,X509_REQ *req);
int X509_NAME_print_ex_fp(FILE *fp, X509_NAME *nm, int indent, unsigned long flags);



int X509_NAME_print(BIO *bp, X509_NAME *name, int obase);
int X509_NAME_print_ex(BIO *out, X509_NAME *nm, int indent, unsigned long flags);
int X509_print_ex(BIO *bp,X509 *x, unsigned long nmflag, unsigned long cflag);
int X509_print(BIO *bp,X509 *x);
int X509_ocspid_print(BIO *bp,X509 *x);
int X509_CERT_AUX_print(BIO *bp,X509_CERT_AUX *x, int indent);
int X509_CRL_print(BIO *bp,X509_CRL *x);
int X509_REQ_print_ex(BIO *bp, X509_REQ *x, unsigned long nmflag, unsigned long cflag);
int X509_REQ_print(BIO *bp,X509_REQ *req);


int X509_NAME_entry_count(X509_NAME *name);
int X509_NAME_get_text_by_NID(X509_NAME *name, int nid,
   char *buf,int len);
int X509_NAME_get_text_by_OBJ(X509_NAME *name, ASN1_OBJECT *obj,
   char *buf,int len);



int X509_NAME_get_index_by_NID(X509_NAME *name,int nid,int lastpos);
int X509_NAME_get_index_by_OBJ(X509_NAME *name,ASN1_OBJECT *obj,
   int lastpos);
X509_NAME_ENTRY *X509_NAME_get_entry(X509_NAME *name, int loc);
X509_NAME_ENTRY *X509_NAME_delete_entry(X509_NAME *name, int loc);
int X509_NAME_add_entry(X509_NAME *name,X509_NAME_ENTRY *ne,
   int loc, int set);
int X509_NAME_add_entry_by_OBJ(X509_NAME *name, ASN1_OBJECT *obj, int type,
   unsigned char *bytes, int len, int loc, int set);
int X509_NAME_add_entry_by_NID(X509_NAME *name, int nid, int type,
   unsigned char *bytes, int len, int loc, int set);
X509_NAME_ENTRY *X509_NAME_ENTRY_create_by_txt(X509_NAME_ENTRY **ne,
  const char *field, int type, const unsigned char *bytes, int len);
X509_NAME_ENTRY *X509_NAME_ENTRY_create_by_NID(X509_NAME_ENTRY **ne, int nid,
   int type,unsigned char *bytes, int len);
int X509_NAME_add_entry_by_txt(X509_NAME *name, const char *field, int type,
   const unsigned char *bytes, int len, int loc, int set);
X509_NAME_ENTRY *X509_NAME_ENTRY_create_by_OBJ(X509_NAME_ENTRY **ne,
   ASN1_OBJECT *obj, int type,const unsigned char *bytes,
   int len);
int X509_NAME_ENTRY_set_object(X509_NAME_ENTRY *ne,
   ASN1_OBJECT *obj);
int X509_NAME_ENTRY_set_data(X509_NAME_ENTRY *ne, int type,
   const unsigned char *bytes, int len);
ASN1_OBJECT * X509_NAME_ENTRY_get_object(X509_NAME_ENTRY *ne);
ASN1_STRING * X509_NAME_ENTRY_get_data(X509_NAME_ENTRY *ne);

int X509v3_get_ext_count(const struct stack_st_X509_EXTENSION *x);
int X509v3_get_ext_by_NID(const struct stack_st_X509_EXTENSION *x,
          int nid, int lastpos);
int X509v3_get_ext_by_OBJ(const struct stack_st_X509_EXTENSION *x,
          ASN1_OBJECT *obj,int lastpos);
int X509v3_get_ext_by_critical(const struct stack_st_X509_EXTENSION *x,
        int crit, int lastpos);
X509_EXTENSION *X509v3_get_ext(const struct stack_st_X509_EXTENSION *x, int loc);
X509_EXTENSION *X509v3_delete_ext(struct stack_st_X509_EXTENSION *x, int loc);
struct stack_st_X509_EXTENSION *X509v3_add_ext(struct stack_st_X509_EXTENSION **x,
      X509_EXTENSION *ex, int loc);

int X509_get_ext_count(X509 *x);
int X509_get_ext_by_NID(X509 *x, int nid, int lastpos);
int X509_get_ext_by_OBJ(X509 *x,ASN1_OBJECT *obj,int lastpos);
int X509_get_ext_by_critical(X509 *x, int crit, int lastpos);
X509_EXTENSION *X509_get_ext(X509 *x, int loc);
X509_EXTENSION *X509_delete_ext(X509 *x, int loc);
int X509_add_ext(X509 *x, X509_EXTENSION *ex, int loc);
void * X509_get_ext_d2i(X509 *x, int nid, int *crit, int *idx);
int X509_add1_ext_i2d(X509 *x, int nid, void *value, int crit,
       unsigned long flags);

int X509_CRL_get_ext_count(X509_CRL *x);
int X509_CRL_get_ext_by_NID(X509_CRL *x, int nid, int lastpos);
int X509_CRL_get_ext_by_OBJ(X509_CRL *x,ASN1_OBJECT *obj,int lastpos);
int X509_CRL_get_ext_by_critical(X509_CRL *x, int crit, int lastpos);
X509_EXTENSION *X509_CRL_get_ext(X509_CRL *x, int loc);
X509_EXTENSION *X509_CRL_delete_ext(X509_CRL *x, int loc);
int X509_CRL_add_ext(X509_CRL *x, X509_EXTENSION *ex, int loc);
void * X509_CRL_get_ext_d2i(X509_CRL *x, int nid, int *crit, int *idx);
int X509_CRL_add1_ext_i2d(X509_CRL *x, int nid, void *value, int crit,
       unsigned long flags);

int X509_REVOKED_get_ext_count(X509_REVOKED *x);
int X509_REVOKED_get_ext_by_NID(X509_REVOKED *x, int nid, int lastpos);
int X509_REVOKED_get_ext_by_OBJ(X509_REVOKED *x,ASN1_OBJECT *obj,int lastpos);
int X509_REVOKED_get_ext_by_critical(X509_REVOKED *x, int crit, int lastpos);
X509_EXTENSION *X509_REVOKED_get_ext(X509_REVOKED *x, int loc);
X509_EXTENSION *X509_REVOKED_delete_ext(X509_REVOKED *x, int loc);
int X509_REVOKED_add_ext(X509_REVOKED *x, X509_EXTENSION *ex, int loc);
void * X509_REVOKED_get_ext_d2i(X509_REVOKED *x, int nid, int *crit, int *idx);
int X509_REVOKED_add1_ext_i2d(X509_REVOKED *x, int nid, void *value, int crit,
       unsigned long flags);

X509_EXTENSION *X509_EXTENSION_create_by_NID(X509_EXTENSION **ex,
   int nid, int crit, ASN1_OCTET_STRING *data);
X509_EXTENSION *X509_EXTENSION_create_by_OBJ(X509_EXTENSION **ex,
   ASN1_OBJECT *obj,int crit,ASN1_OCTET_STRING *data);
int X509_EXTENSION_set_object(X509_EXTENSION *ex,ASN1_OBJECT *obj);
int X509_EXTENSION_set_critical(X509_EXTENSION *ex, int crit);
int X509_EXTENSION_set_data(X509_EXTENSION *ex,
   ASN1_OCTET_STRING *data);
ASN1_OBJECT * X509_EXTENSION_get_object(X509_EXTENSION *ex);
ASN1_OCTET_STRING *X509_EXTENSION_get_data(X509_EXTENSION *ne);
int X509_EXTENSION_get_critical(X509_EXTENSION *ex);

int X509at_get_attr_count(const struct stack_st_X509_ATTRIBUTE *x);
int X509at_get_attr_by_NID(const struct stack_st_X509_ATTRIBUTE *x, int nid,
     int lastpos);
int X509at_get_attr_by_OBJ(const struct stack_st_X509_ATTRIBUTE *sk, ASN1_OBJECT *obj,
     int lastpos);
X509_ATTRIBUTE *X509at_get_attr(const struct stack_st_X509_ATTRIBUTE *x, int loc);
X509_ATTRIBUTE *X509at_delete_attr(struct stack_st_X509_ATTRIBUTE *x, int loc);
struct stack_st_X509_ATTRIBUTE *X509at_add1_attr(struct stack_st_X509_ATTRIBUTE **x,
      X509_ATTRIBUTE *attr);
struct stack_st_X509_ATTRIBUTE *X509at_add1_attr_by_OBJ(struct stack_st_X509_ATTRIBUTE **x,
   const ASN1_OBJECT *obj, int type,
   const unsigned char *bytes, int len);
struct stack_st_X509_ATTRIBUTE *X509at_add1_attr_by_NID(struct stack_st_X509_ATTRIBUTE **x,
   int nid, int type,
   const unsigned char *bytes, int len);
struct stack_st_X509_ATTRIBUTE *X509at_add1_attr_by_txt(struct stack_st_X509_ATTRIBUTE **x,
   const char *attrname, int type,
   const unsigned char *bytes, int len);
void *X509at_get0_data_by_OBJ(struct stack_st_X509_ATTRIBUTE *x,
    ASN1_OBJECT *obj, int lastpos, int type);
X509_ATTRIBUTE *X509_ATTRIBUTE_create_by_NID(X509_ATTRIBUTE **attr, int nid,
      int atrtype, const void *data, int len);
X509_ATTRIBUTE *X509_ATTRIBUTE_create_by_OBJ(X509_ATTRIBUTE **attr,
      const ASN1_OBJECT *obj, int atrtype, const void *data, int len);
X509_ATTRIBUTE *X509_ATTRIBUTE_create_by_txt(X509_ATTRIBUTE **attr,
  const char *atrname, int type, const unsigned char *bytes, int len);
int X509_ATTRIBUTE_set1_object(X509_ATTRIBUTE *attr, const ASN1_OBJECT *obj);
int X509_ATTRIBUTE_set1_data(X509_ATTRIBUTE *attr, int attrtype, const void *data, int len);
void *X509_ATTRIBUTE_get0_data(X509_ATTRIBUTE *attr, int idx,
     int atrtype, void *data);
int X509_ATTRIBUTE_count(X509_ATTRIBUTE *attr);
ASN1_OBJECT *X509_ATTRIBUTE_get0_object(X509_ATTRIBUTE *attr);
ASN1_TYPE *X509_ATTRIBUTE_get0_type(X509_ATTRIBUTE *attr, int idx);

int EVP_PKEY_get_attr_count(const EVP_PKEY *key);
int EVP_PKEY_get_attr_by_NID(const EVP_PKEY *key, int nid,
     int lastpos);
int EVP_PKEY_get_attr_by_OBJ(const EVP_PKEY *key, ASN1_OBJECT *obj,
     int lastpos);
X509_ATTRIBUTE *EVP_PKEY_get_attr(const EVP_PKEY *key, int loc);
X509_ATTRIBUTE *EVP_PKEY_delete_attr(EVP_PKEY *key, int loc);
int EVP_PKEY_add1_attr(EVP_PKEY *key, X509_ATTRIBUTE *attr);
int EVP_PKEY_add1_attr_by_OBJ(EVP_PKEY *key,
   const ASN1_OBJECT *obj, int type,
   const unsigned char *bytes, int len);
int EVP_PKEY_add1_attr_by_NID(EVP_PKEY *key,
   int nid, int type,
   const unsigned char *bytes, int len);
int EVP_PKEY_add1_attr_by_txt(EVP_PKEY *key,
   const char *attrname, int type,
   const unsigned char *bytes, int len);

int X509_verify_cert(X509_STORE_CTX *ctx);


X509 *X509_find_by_issuer_and_serial(struct stack_st_X509 *sk,X509_NAME *name,
         ASN1_INTEGER *serial);
X509 *X509_find_by_subject(struct stack_st_X509 *sk,X509_NAME *name);

PBEPARAM *PBEPARAM_new(void); void PBEPARAM_free(PBEPARAM *a); PBEPARAM *d2i_PBEPARAM(PBEPARAM **a, const unsigned char **in, long len); int i2d_PBEPARAM(PBEPARAM *a, unsigned char **out); extern const ASN1_ITEM PBEPARAM_it;
PBE2PARAM *PBE2PARAM_new(void); void PBE2PARAM_free(PBE2PARAM *a); PBE2PARAM *d2i_PBE2PARAM(PBE2PARAM **a, const unsigned char **in, long len); int i2d_PBE2PARAM(PBE2PARAM *a, unsigned char **out); extern const ASN1_ITEM PBE2PARAM_it;
PBKDF2PARAM *PBKDF2PARAM_new(void); void PBKDF2PARAM_free(PBKDF2PARAM *a); PBKDF2PARAM *d2i_PBKDF2PARAM(PBKDF2PARAM **a, const unsigned char **in, long len); int i2d_PBKDF2PARAM(PBKDF2PARAM *a, unsigned char **out); extern const ASN1_ITEM PBKDF2PARAM_it;

int PKCS5_pbe_set0_algor(X509_ALGOR *algor, int alg, int iter,
    const unsigned char *salt, int saltlen);

X509_ALGOR *PKCS5_pbe_set(int alg, int iter,
    const unsigned char *salt, int saltlen);
X509_ALGOR *PKCS5_pbe2_set(const EVP_CIPHER *cipher, int iter,
      unsigned char *salt, int saltlen);
X509_ALGOR *PKCS5_pbe2_set_iv(const EVP_CIPHER *cipher, int iter,
     unsigned char *salt, int saltlen,
     unsigned char *aiv, int prf_nid);

X509_ALGOR *PKCS5_pbkdf2_set(int iter, unsigned char *salt, int saltlen,
    int prf_nid, int keylen);



PKCS8_PRIV_KEY_INFO *PKCS8_PRIV_KEY_INFO_new(void); void PKCS8_PRIV_KEY_INFO_free(PKCS8_PRIV_KEY_INFO *a); PKCS8_PRIV_KEY_INFO *d2i_PKCS8_PRIV_KEY_INFO(PKCS8_PRIV_KEY_INFO **a, const unsigned char **in, long len); int i2d_PKCS8_PRIV_KEY_INFO(PKCS8_PRIV_KEY_INFO *a, unsigned char **out); extern const ASN1_ITEM PKCS8_PRIV_KEY_INFO_it;

EVP_PKEY *EVP_PKCS82PKEY(PKCS8_PRIV_KEY_INFO *p8);
PKCS8_PRIV_KEY_INFO *EVP_PKEY2PKCS8(EVP_PKEY *pkey);
PKCS8_PRIV_KEY_INFO *EVP_PKEY2PKCS8_broken(EVP_PKEY *pkey, int broken);
PKCS8_PRIV_KEY_INFO *PKCS8_set_broken(PKCS8_PRIV_KEY_INFO *p8, int broken);

int PKCS8_pkey_set0(PKCS8_PRIV_KEY_INFO *priv, ASN1_OBJECT *aobj,
   int version, int ptype, void *pval,
    unsigned char *penc, int penclen);
int PKCS8_pkey_get0(ASN1_OBJECT **ppkalg,
  const unsigned char **pk, int *ppklen,
  X509_ALGOR **pa,
  PKCS8_PRIV_KEY_INFO *p8);

int X509_PUBKEY_set0_param(X509_PUBKEY *pub, ASN1_OBJECT *aobj,
     int ptype, void *pval,
     unsigned char *penc, int penclen);
int X509_PUBKEY_get0_param(ASN1_OBJECT **ppkalg,
  const unsigned char **pk, int *ppklen,
  X509_ALGOR **pa,
  X509_PUBKEY *pub);

int X509_check_trust(X509 *x, int id, int flags);
int X509_TRUST_get_count(void);
X509_TRUST * X509_TRUST_get0(int idx);
int X509_TRUST_get_by_id(int id);
int X509_TRUST_add(int id, int flags, int (*ck)(X509_TRUST *, X509 *, int),
     char *name, int arg1, void *arg2);
void X509_TRUST_cleanup(void);
int X509_TRUST_get_flags(X509_TRUST *xp);
char *X509_TRUST_get0_name(X509_TRUST *xp);
int X509_TRUST_get_trust(X509_TRUST *xp);





void ERR_load_X509_strings(void);


typedef struct CMS_ContentInfo_st CMS_ContentInfo;
typedef struct CMS_SignerInfo_st CMS_SignerInfo;
typedef struct CMS_CertificateChoices CMS_CertificateChoices;
typedef struct CMS_RevocationInfoChoice_st CMS_RevocationInfoChoice;
typedef struct CMS_RecipientInfo_st CMS_RecipientInfo;
typedef struct CMS_ReceiptRequest_st CMS_ReceiptRequest;
typedef struct CMS_Receipt_st CMS_Receipt;

struct stack_st_CMS_SignerInfo { _STACK stack; };
struct stack_st_GENERAL_NAMES { _STACK stack; };
CMS_ContentInfo *CMS_ContentInfo_new(void); void CMS_ContentInfo_free(CMS_ContentInfo *a); CMS_ContentInfo *d2i_CMS_ContentInfo(CMS_ContentInfo **a, const unsigned char **in, long len); int i2d_CMS_ContentInfo(CMS_ContentInfo *a, unsigned char **out); extern const ASN1_ITEM CMS_ContentInfo_it;
CMS_ReceiptRequest *CMS_ReceiptRequest_new(void); void CMS_ReceiptRequest_free(CMS_ReceiptRequest *a); CMS_ReceiptRequest *d2i_CMS_ReceiptRequest(CMS_ReceiptRequest **a, const unsigned char **in, long len); int i2d_CMS_ReceiptRequest(CMS_ReceiptRequest *a, unsigned char **out); extern const ASN1_ITEM CMS_ReceiptRequest_it;
int CMS_ContentInfo_print_ctx(BIO *out, CMS_ContentInfo *x, int indent, const ASN1_PCTX *pctx);

const ASN1_OBJECT *CMS_get0_type(CMS_ContentInfo *cms);

BIO *CMS_dataInit(CMS_ContentInfo *cms, BIO *icont);
int CMS_dataFinal(CMS_ContentInfo *cms, BIO *bio);

ASN1_OCTET_STRING **CMS_get0_content(CMS_ContentInfo *cms);
int CMS_is_detached(CMS_ContentInfo *cms);
int CMS_set_detached(CMS_ContentInfo *cms, int detached);





int CMS_stream(unsigned char ***boundary, CMS_ContentInfo *cms);
CMS_ContentInfo *d2i_CMS_bio(BIO *bp, CMS_ContentInfo **cms);
int i2d_CMS_bio(BIO *bp, CMS_ContentInfo *cms);

BIO *BIO_new_CMS(BIO *out, CMS_ContentInfo *cms);
int i2d_CMS_bio_stream(BIO *out, CMS_ContentInfo *cms, BIO *in, int flags);
int PEM_write_bio_CMS_stream(BIO *out, CMS_ContentInfo *cms, BIO *in, int flags);
CMS_ContentInfo *SMIME_read_CMS(BIO *bio, BIO **bcont);
int SMIME_write_CMS(BIO *bio, CMS_ContentInfo *cms, BIO *data, int flags);

int CMS_final(CMS_ContentInfo *cms, BIO *data, BIO *dcont, unsigned int flags);

CMS_ContentInfo *CMS_sign(X509 *signcert, EVP_PKEY *pkey, struct stack_st_X509 *certs,
      BIO *data, unsigned int flags);

CMS_ContentInfo *CMS_sign_receipt(CMS_SignerInfo *si,
     X509 *signcert, EVP_PKEY *pkey,
     struct stack_st_X509 *certs,
     unsigned int flags);

int CMS_data(CMS_ContentInfo *cms, BIO *out, unsigned int flags);
CMS_ContentInfo *CMS_data_create(BIO *in, unsigned int flags);

int CMS_digest_verify(CMS_ContentInfo *cms, BIO *dcont, BIO *out,
       unsigned int flags);
CMS_ContentInfo *CMS_digest_create(BIO *in, const EVP_MD *md,
       unsigned int flags);

int CMS_EncryptedData_decrypt(CMS_ContentInfo *cms,
    const unsigned char *key, size_t keylen,
    BIO *dcont, BIO *out, unsigned int flags);

CMS_ContentInfo *CMS_EncryptedData_encrypt(BIO *in, const EVP_CIPHER *cipher,
     const unsigned char *key, size_t keylen,
     unsigned int flags);

int CMS_EncryptedData_set1_key(CMS_ContentInfo *cms, const EVP_CIPHER *ciph,
    const unsigned char *key, size_t keylen);

int CMS_verify(CMS_ContentInfo *cms, struct stack_st_X509 *certs,
   X509_STORE *store, BIO *dcont, BIO *out, unsigned int flags);

int CMS_verify_receipt(CMS_ContentInfo *rcms, CMS_ContentInfo *ocms,
   struct stack_st_X509 *certs,
   X509_STORE *store, unsigned int flags);

struct stack_st_X509 *CMS_get0_signers(CMS_ContentInfo *cms);

CMS_ContentInfo *CMS_encrypt(struct stack_st_X509 *certs, BIO *in,
    const EVP_CIPHER *cipher, unsigned int flags);

int CMS_decrypt(CMS_ContentInfo *cms, EVP_PKEY *pkey, X509 *cert,
    BIO *dcont, BIO *out,
    unsigned int flags);

int CMS_decrypt_set1_pkey(CMS_ContentInfo *cms, EVP_PKEY *pk, X509 *cert);
int CMS_decrypt_set1_key(CMS_ContentInfo *cms,
    unsigned char *key, size_t keylen,
    unsigned char *id, size_t idlen);
int CMS_decrypt_set1_password(CMS_ContentInfo *cms,
    unsigned char *pass, ssize_t passlen);

struct stack_st_CMS_RecipientInfo *CMS_get0_RecipientInfos(CMS_ContentInfo *cms);
int CMS_RecipientInfo_type(CMS_RecipientInfo *ri);
CMS_ContentInfo *CMS_EnvelopedData_create(const EVP_CIPHER *cipher);
CMS_RecipientInfo *CMS_add1_recipient_cert(CMS_ContentInfo *cms,
     X509 *recip, unsigned int flags);
int CMS_RecipientInfo_set0_pkey(CMS_RecipientInfo *ri, EVP_PKEY *pkey);
int CMS_RecipientInfo_ktri_cert_cmp(CMS_RecipientInfo *ri, X509 *cert);
int CMS_RecipientInfo_ktri_get0_algs(CMS_RecipientInfo *ri,
     EVP_PKEY **pk, X509 **recip,
     X509_ALGOR **palg);
int CMS_RecipientInfo_ktri_get0_signer_id(CMS_RecipientInfo *ri,
     ASN1_OCTET_STRING **keyid,
     X509_NAME **issuer, ASN1_INTEGER **sno);

CMS_RecipientInfo *CMS_add0_recipient_key(CMS_ContentInfo *cms, int nid,
     unsigned char *key, size_t keylen,
     unsigned char *id, size_t idlen,
     ASN1_GENERALIZEDTIME *date,
     ASN1_OBJECT *otherTypeId,
     ASN1_TYPE *otherType);

int CMS_RecipientInfo_kekri_get0_id(CMS_RecipientInfo *ri,
     X509_ALGOR **palg,
     ASN1_OCTET_STRING **pid,
     ASN1_GENERALIZEDTIME **pdate,
     ASN1_OBJECT **potherid,
     ASN1_TYPE **pothertype);

int CMS_RecipientInfo_set0_key(CMS_RecipientInfo *ri,
    unsigned char *key, size_t keylen);

int CMS_RecipientInfo_kekri_id_cmp(CMS_RecipientInfo *ri,
     const unsigned char *id, size_t idlen);

int CMS_RecipientInfo_set0_password(CMS_RecipientInfo *ri,
     unsigned char *pass,
     ssize_t passlen);

CMS_RecipientInfo *CMS_add0_recipient_password(CMS_ContentInfo *cms,
     int iter, int wrap_nid, int pbe_nid,
     unsigned char *pass,
     ssize_t passlen,
     const EVP_CIPHER *kekciph);

int CMS_RecipientInfo_decrypt(CMS_ContentInfo *cms, CMS_RecipientInfo *ri);

int CMS_uncompress(CMS_ContentInfo *cms, BIO *dcont, BIO *out,
       unsigned int flags);
CMS_ContentInfo *CMS_compress(BIO *in, int comp_nid, unsigned int flags);

int CMS_set1_eContentType(CMS_ContentInfo *cms, const ASN1_OBJECT *oid);
const ASN1_OBJECT *CMS_get0_eContentType(CMS_ContentInfo *cms);

CMS_CertificateChoices *CMS_add0_CertificateChoices(CMS_ContentInfo *cms);
int CMS_add0_cert(CMS_ContentInfo *cms, X509 *cert);
int CMS_add1_cert(CMS_ContentInfo *cms, X509 *cert);
struct stack_st_X509 *CMS_get1_certs(CMS_ContentInfo *cms);

CMS_RevocationInfoChoice *CMS_add0_RevocationInfoChoice(CMS_ContentInfo *cms);
int CMS_add0_crl(CMS_ContentInfo *cms, X509_CRL *crl);
int CMS_add1_crl(CMS_ContentInfo *cms, X509_CRL *crl);
struct stack_st_X509_CRL *CMS_get1_crls(CMS_ContentInfo *cms);

int CMS_SignedData_init(CMS_ContentInfo *cms);
CMS_SignerInfo *CMS_add1_signer(CMS_ContentInfo *cms,
   X509 *signer, EVP_PKEY *pk, const EVP_MD *md,
   unsigned int flags);
struct stack_st_CMS_SignerInfo *CMS_get0_SignerInfos(CMS_ContentInfo *cms);

void CMS_SignerInfo_set1_signer_cert(CMS_SignerInfo *si, X509 *signer);
int CMS_SignerInfo_get0_signer_id(CMS_SignerInfo *si,
     ASN1_OCTET_STRING **keyid,
     X509_NAME **issuer, ASN1_INTEGER **sno);
int CMS_SignerInfo_cert_cmp(CMS_SignerInfo *si, X509 *cert);
int CMS_set1_signers_certs(CMS_ContentInfo *cms, struct stack_st_X509 *certs,
     unsigned int flags);
void CMS_SignerInfo_get0_algs(CMS_SignerInfo *si, EVP_PKEY **pk, X509 **signer,
     X509_ALGOR **pdig, X509_ALGOR **psig);
int CMS_SignerInfo_sign(CMS_SignerInfo *si);
int CMS_SignerInfo_verify(CMS_SignerInfo *si);
int CMS_SignerInfo_verify_content(CMS_SignerInfo *si, BIO *chain);

int CMS_add_smimecap(CMS_SignerInfo *si, struct stack_st_X509_ALGOR *algs);
int CMS_add_simple_smimecap(struct stack_st_X509_ALGOR **algs,
    int algnid, int keysize);
int CMS_add_standard_smimecap(struct stack_st_X509_ALGOR **smcap);

int CMS_signed_get_attr_count(const CMS_SignerInfo *si);
int CMS_signed_get_attr_by_NID(const CMS_SignerInfo *si, int nid,
     int lastpos);
int CMS_signed_get_attr_by_OBJ(const CMS_SignerInfo *si, ASN1_OBJECT *obj,
     int lastpos);
X509_ATTRIBUTE *CMS_signed_get_attr(const CMS_SignerInfo *si, int loc);
X509_ATTRIBUTE *CMS_signed_delete_attr(CMS_SignerInfo *si, int loc);
int CMS_signed_add1_attr(CMS_SignerInfo *si, X509_ATTRIBUTE *attr);
int CMS_signed_add1_attr_by_OBJ(CMS_SignerInfo *si,
   const ASN1_OBJECT *obj, int type,
   const void *bytes, int len);
int CMS_signed_add1_attr_by_NID(CMS_SignerInfo *si,
   int nid, int type,
   const void *bytes, int len);
int CMS_signed_add1_attr_by_txt(CMS_SignerInfo *si,
   const char *attrname, int type,
   const void *bytes, int len);
void *CMS_signed_get0_data_by_OBJ(CMS_SignerInfo *si, ASN1_OBJECT *oid,
     int lastpos, int type);

int CMS_unsigned_get_attr_count(const CMS_SignerInfo *si);
int CMS_unsigned_get_attr_by_NID(const CMS_SignerInfo *si, int nid,
     int lastpos);
int CMS_unsigned_get_attr_by_OBJ(const CMS_SignerInfo *si, ASN1_OBJECT *obj,
     int lastpos);
X509_ATTRIBUTE *CMS_unsigned_get_attr(const CMS_SignerInfo *si, int loc);
X509_ATTRIBUTE *CMS_unsigned_delete_attr(CMS_SignerInfo *si, int loc);
int CMS_unsigned_add1_attr(CMS_SignerInfo *si, X509_ATTRIBUTE *attr);
int CMS_unsigned_add1_attr_by_OBJ(CMS_SignerInfo *si,
   const ASN1_OBJECT *obj, int type,
   const void *bytes, int len);
int CMS_unsigned_add1_attr_by_NID(CMS_SignerInfo *si,
   int nid, int type,
   const void *bytes, int len);
int CMS_unsigned_add1_attr_by_txt(CMS_SignerInfo *si,
   const char *attrname, int type,
   const void *bytes, int len);
void *CMS_unsigned_get0_data_by_OBJ(CMS_SignerInfo *si, ASN1_OBJECT *oid,
     int lastpos, int type);

void ERR_load_CMS_strings(void);



typedef struct comp_ctx_st COMP_CTX;

typedef struct comp_method_st
 {
 int type;
 const char *name;
 int (*init)(COMP_CTX *ctx);
 void (*finish)(COMP_CTX *ctx);
 int (*compress)(COMP_CTX *ctx,
   unsigned char *out, unsigned int olen,
   unsigned char *in, unsigned int ilen);
 int (*expand)(COMP_CTX *ctx,
        unsigned char *out, unsigned int olen,
        unsigned char *in, unsigned int ilen);

 long (*ctrl)(void);
 long (*callback_ctrl)(void);
 } COMP_METHOD;

struct comp_ctx_st
 {
 COMP_METHOD *meth;
 unsigned long compress_in;
 unsigned long compress_out;
 unsigned long expand_in;
 unsigned long expand_out;

 CRYPTO_EX_DATA ex_data;
 };


COMP_CTX *COMP_CTX_new(COMP_METHOD *meth);
void COMP_CTX_free(COMP_CTX *ctx);
int COMP_compress_block(COMP_CTX *ctx, unsigned char *out, int olen,
 unsigned char *in, int ilen);
int COMP_expand_block(COMP_CTX *ctx, unsigned char *out, int olen,
 unsigned char *in, int ilen);
COMP_METHOD *COMP_rle(void );
COMP_METHOD *COMP_zlib(void );
void COMP_zlib_cleanup(void);

void ERR_load_COMP_strings(void);

















typedef struct
 {
 char *section;
 char *name;
 char *value;
 } CONF_VALUE;

struct stack_st_CONF_VALUE { _STACK stack; };
struct lhash_st_CONF_VALUE { int dummy; };

struct conf_st;
struct conf_method_st;
typedef struct conf_method_st CONF_METHOD;

struct conf_method_st
 {
 const char *name;
 CONF *(*create)(CONF_METHOD *meth);
 int (*init)(CONF *conf);
 int (*destroy)(CONF *conf);
 int (*destroy_data)(CONF *conf);
 int (*load_bio)(CONF *conf, BIO *bp, long *eline);
 int (*dump)(const CONF *conf, BIO *bp);
 int (*is_number)(const CONF *conf, char c);
 int (*to_int)(const CONF *conf, char c);
 int (*load)(CONF *conf, const char *name, long *eline);
 };



typedef struct conf_imodule_st CONF_IMODULE;
typedef struct conf_module_st CONF_MODULE;

struct stack_st_CONF_MODULE { _STACK stack; };
struct stack_st_CONF_IMODULE { _STACK stack; };


typedef int conf_init_func(CONF_IMODULE *md, const CONF *cnf);
typedef void conf_finish_func(CONF_IMODULE *md);

int CONF_set_default_method(CONF_METHOD *meth);
void CONF_set_nconf(CONF *conf,struct lhash_st_CONF_VALUE *hash);
struct lhash_st_CONF_VALUE *CONF_load(struct lhash_st_CONF_VALUE *conf,const char *file,
    long *eline);

struct lhash_st_CONF_VALUE *CONF_load_fp(struct lhash_st_CONF_VALUE *conf, FILE *fp,
       long *eline);

struct lhash_st_CONF_VALUE *CONF_load_bio(struct lhash_st_CONF_VALUE *conf, BIO *bp,long *eline);
struct stack_st_CONF_VALUE *CONF_get_section(struct lhash_st_CONF_VALUE *conf,
           const char *section);
char *CONF_get_string(struct lhash_st_CONF_VALUE *conf,const char *group,
        const char *name);
long CONF_get_number(struct lhash_st_CONF_VALUE *conf,const char *group,
       const char *name);
void CONF_free(struct lhash_st_CONF_VALUE *conf);
int CONF_dump_fp(struct lhash_st_CONF_VALUE *conf, FILE *out);
int CONF_dump_bio(struct lhash_st_CONF_VALUE *conf, BIO *out);

void OPENSSL_config(const char *config_name);
void OPENSSL_no_config(void);




struct conf_st
 {
 CONF_METHOD *meth;
 void *meth_data;
 struct lhash_st_CONF_VALUE *data;
 };

CONF *NCONF_new(CONF_METHOD *meth);
CONF_METHOD *NCONF_default(void);
CONF_METHOD *NCONF_WIN32(void);



void NCONF_free(CONF *conf);
void NCONF_free_data(CONF *conf);

int NCONF_load(CONF *conf,const char *file,long *eline);

int NCONF_load_fp(CONF *conf, FILE *fp,long *eline);

int NCONF_load_bio(CONF *conf, BIO *bp,long *eline);
struct stack_st_CONF_VALUE *NCONF_get_section(const CONF *conf,const char *section);
char *NCONF_get_string(const CONF *conf,const char *group,const char *name);
int NCONF_get_number_e(const CONF *conf,const char *group,const char *name,
         long *result);
int NCONF_dump_fp(const CONF *conf, FILE *out);
int NCONF_dump_bio(const CONF *conf, BIO *out);

int CONF_modules_load(const CONF *cnf, const char *appname,
        unsigned long flags);
int CONF_modules_load_file(const char *filename, const char *appname,
      unsigned long flags);
void CONF_modules_unload(int all);
void CONF_modules_finish(void);
void CONF_modules_free(void);
int CONF_module_add(const char *name, conf_init_func *ifunc,
      conf_finish_func *ffunc);

const char *CONF_imodule_get_name(const CONF_IMODULE *md);
const char *CONF_imodule_get_value(const CONF_IMODULE *md);
void *CONF_imodule_get_usr_data(const CONF_IMODULE *md);
void CONF_imodule_set_usr_data(CONF_IMODULE *md, void *usr_data);
CONF_MODULE *CONF_imodule_get_module(const CONF_IMODULE *md);
unsigned long CONF_imodule_get_flags(const CONF_IMODULE *md);
void CONF_imodule_set_flags(CONF_IMODULE *md, unsigned long flags);
void *CONF_module_get_usr_data(CONF_MODULE *pmod);
void CONF_module_set_usr_data(CONF_MODULE *pmod, void *usr_data);

char *CONF_get1_default_config_file(void);

int CONF_parse_list(const char *list, int sep, int nospc,
 int (*list_cb)(const char *elem, int len, void *usr), void *arg);

void OPENSSL_load_builtin_modules(void);





void ERR_load_CONF_strings(void);







CONF_VALUE *_CONF_new_section(CONF *conf, const char *section);

CONF_VALUE *_CONF_get_section(const CONF *conf, const char *section);

struct stack_st_CONF_VALUE *_CONF_get_section_values(const CONF *conf,
            const char *section);

int _CONF_add_string(CONF *conf, CONF_VALUE *section, CONF_VALUE *value);
char *_CONF_get_string(const CONF *conf, const char *section,
         const char *name);
long _CONF_get_number(const CONF *conf, const char *section, const char *name);

int _CONF_new_data(CONF *conf);
void _CONF_free_data(CONF *conf);











typedef unsigned char DES_cblock[8];
typedef unsigned char const_DES_cblock[8];



typedef struct DES_ks
    {
    union
 {
 DES_cblock cblock;


 unsigned int deslong[2];
 } ks[16];
    } DES_key_schedule;









typedef unsigned char _ossl_old_des_cblock[8];
typedef struct _ossl_old_des_ks_struct
 {
 union {
  _ossl_old_des_cblock _;


  unsigned int pad[2];
  } ks;
 } _ossl_old_des_key_schedule[16];

const char *_ossl_old_des_options(void);
void _ossl_old_des_ecb3_encrypt(_ossl_old_des_cblock *input,_ossl_old_des_cblock *output,
 _ossl_old_des_key_schedule ks1,_ossl_old_des_key_schedule ks2,
 _ossl_old_des_key_schedule ks3, int enc);
unsigned int _ossl_old_des_cbc_cksum(_ossl_old_des_cblock *input,_ossl_old_des_cblock *output,
 long length,_ossl_old_des_key_schedule schedule,_ossl_old_des_cblock *ivec);
void _ossl_old_des_cbc_encrypt(_ossl_old_des_cblock *input,_ossl_old_des_cblock *output,long length,
 _ossl_old_des_key_schedule schedule,_ossl_old_des_cblock *ivec,int enc);
void _ossl_old_des_ncbc_encrypt(_ossl_old_des_cblock *input,_ossl_old_des_cblock *output,long length,
 _ossl_old_des_key_schedule schedule,_ossl_old_des_cblock *ivec,int enc);
void _ossl_old_des_xcbc_encrypt(_ossl_old_des_cblock *input,_ossl_old_des_cblock *output,long length,
 _ossl_old_des_key_schedule schedule,_ossl_old_des_cblock *ivec,
 _ossl_old_des_cblock *inw,_ossl_old_des_cblock *outw,int enc);
void _ossl_old_des_cfb_encrypt(unsigned char *in,unsigned char *out,int numbits,
 long length,_ossl_old_des_key_schedule schedule,_ossl_old_des_cblock *ivec,int enc);
void _ossl_old_des_ecb_encrypt(_ossl_old_des_cblock *input,_ossl_old_des_cblock *output,
 _ossl_old_des_key_schedule ks,int enc);
void _ossl_old_des_encrypt(unsigned int *data,_ossl_old_des_key_schedule ks, int enc);
void _ossl_old_des_encrypt2(unsigned int *data,_ossl_old_des_key_schedule ks, int enc);
void _ossl_old_des_encrypt3(unsigned int *data, _ossl_old_des_key_schedule ks1,
 _ossl_old_des_key_schedule ks2, _ossl_old_des_key_schedule ks3);
void _ossl_old_des_decrypt3(unsigned int *data, _ossl_old_des_key_schedule ks1,
 _ossl_old_des_key_schedule ks2, _ossl_old_des_key_schedule ks3);
void _ossl_old_des_ede3_cbc_encrypt(_ossl_old_des_cblock *input, _ossl_old_des_cblock *output,
 long length, _ossl_old_des_key_schedule ks1, _ossl_old_des_key_schedule ks2,
 _ossl_old_des_key_schedule ks3, _ossl_old_des_cblock *ivec, int enc);
void _ossl_old_des_ede3_cfb64_encrypt(unsigned char *in, unsigned char *out,
 long length, _ossl_old_des_key_schedule ks1, _ossl_old_des_key_schedule ks2,
 _ossl_old_des_key_schedule ks3, _ossl_old_des_cblock *ivec, int *num, int enc);
void _ossl_old_des_ede3_ofb64_encrypt(unsigned char *in, unsigned char *out,
 long length, _ossl_old_des_key_schedule ks1, _ossl_old_des_key_schedule ks2,
 _ossl_old_des_key_schedule ks3, _ossl_old_des_cblock *ivec, int *num);





int _ossl_old_des_enc_read(int fd,char *buf,int len,_ossl_old_des_key_schedule sched,
 _ossl_old_des_cblock *iv);
int _ossl_old_des_enc_write(int fd,char *buf,int len,_ossl_old_des_key_schedule sched,
 _ossl_old_des_cblock *iv);
char *_ossl_old_des_fcrypt(const char *buf,const char *salt, char *ret);
char *_ossl_old_des_crypt(const char *buf,const char *salt);

char *_ossl_old_crypt(const char *buf,const char *salt);

void _ossl_old_des_ofb_encrypt(unsigned char *in,unsigned char *out,
 int numbits,long length,_ossl_old_des_key_schedule schedule,_ossl_old_des_cblock *ivec);
void _ossl_old_des_pcbc_encrypt(_ossl_old_des_cblock *input,_ossl_old_des_cblock *output,long length,
 _ossl_old_des_key_schedule schedule,_ossl_old_des_cblock *ivec,int enc);
unsigned int _ossl_old_des_quad_cksum(_ossl_old_des_cblock *input,_ossl_old_des_cblock *output,
 long length,int out_count,_ossl_old_des_cblock *seed);
void _ossl_old_des_random_seed(_ossl_old_des_cblock key);
void _ossl_old_des_random_key(_ossl_old_des_cblock ret);
int _ossl_old_des_read_password(_ossl_old_des_cblock *key,const char *prompt,int verify);
int _ossl_old_des_read_2passwords(_ossl_old_des_cblock *key1,_ossl_old_des_cblock *key2,
 const char *prompt,int verify);
void _ossl_old_des_set_odd_parity(_ossl_old_des_cblock *key);
int _ossl_old_des_is_weak_key(_ossl_old_des_cblock *key);
int _ossl_old_des_set_key(_ossl_old_des_cblock *key,_ossl_old_des_key_schedule schedule);
int _ossl_old_des_key_sched(_ossl_old_des_cblock *key,_ossl_old_des_key_schedule schedule);
void _ossl_old_des_string_to_key(char *str,_ossl_old_des_cblock *key);
void _ossl_old_des_string_to_2keys(char *str,_ossl_old_des_cblock *key1,_ossl_old_des_cblock *key2);
void _ossl_old_des_cfb64_encrypt(unsigned char *in, unsigned char *out, long length,
 _ossl_old_des_key_schedule schedule, _ossl_old_des_cblock *ivec, int *num, int enc);
void _ossl_old_des_ofb64_encrypt(unsigned char *in, unsigned char *out, long length,
 _ossl_old_des_key_schedule schedule, _ossl_old_des_cblock *ivec, int *num);

void _ossl_096_des_random_seed(DES_cblock *key);







UI *UI_new(void);
UI *UI_new_method(const UI_METHOD *method);
void UI_free(UI *ui);

int UI_add_input_string(UI *ui, const char *prompt, int flags,
 char *result_buf, int minsize, int maxsize);
int UI_dup_input_string(UI *ui, const char *prompt, int flags,
 char *result_buf, int minsize, int maxsize);
int UI_add_verify_string(UI *ui, const char *prompt, int flags,
 char *result_buf, int minsize, int maxsize, const char *test_buf);
int UI_dup_verify_string(UI *ui, const char *prompt, int flags,
 char *result_buf, int minsize, int maxsize, const char *test_buf);
int UI_add_input_boolean(UI *ui, const char *prompt, const char *action_desc,
 const char *ok_chars, const char *cancel_chars,
 int flags, char *result_buf);
int UI_dup_input_boolean(UI *ui, const char *prompt, const char *action_desc,
 const char *ok_chars, const char *cancel_chars,
 int flags, char *result_buf);
int UI_add_info_string(UI *ui, const char *text);
int UI_dup_info_string(UI *ui, const char *text);
int UI_add_error_string(UI *ui, const char *text);
int UI_dup_error_string(UI *ui, const char *text);

char *UI_construct_prompt(UI *ui_method,
 const char *object_desc, const char *object_name);

void *UI_add_user_data(UI *ui, void *user_data);

void *UI_get0_user_data(UI *ui);


const char *UI_get0_result(UI *ui, int i);


int UI_process(UI *ui);




int UI_ctrl(UI *ui, int cmd, long i, void *p, void (*f)(void));

int UI_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func,
 CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func);
int UI_set_ex_data(UI *r,int idx,void *arg);
void *UI_get_ex_data(UI *r, int idx);


void UI_set_default_method(const UI_METHOD *meth);
const UI_METHOD *UI_get_default_method(void);
const UI_METHOD *UI_get_method(UI *ui);
const UI_METHOD *UI_set_method(UI *ui, const UI_METHOD *meth);


UI_METHOD *UI_OpenSSL(void);

typedef struct ui_string_st UI_STRING;
struct stack_st_UI_STRING { _STACK stack; };



enum UI_string_types
 {
 UIT_NONE=0,
 UIT_PROMPT,
 UIT_VERIFY,
 UIT_BOOLEAN,
 UIT_INFO,
 UIT_ERROR
 };


UI_METHOD *UI_create_method(char *name);
void UI_destroy_method(UI_METHOD *ui_method);
int UI_method_set_opener(UI_METHOD *method, int (*opener)(UI *ui));
int UI_method_set_writer(UI_METHOD *method, int (*writer)(UI *ui, UI_STRING *uis));
int UI_method_set_flusher(UI_METHOD *method, int (*flusher)(UI *ui));
int UI_method_set_reader(UI_METHOD *method, int (*reader)(UI *ui, UI_STRING *uis));
int UI_method_set_closer(UI_METHOD *method, int (*closer)(UI *ui));
int UI_method_set_prompt_constructor(UI_METHOD *method, char *(*prompt_constructor)(UI* ui, const char* object_desc, const char* object_name));
int (*UI_method_get_opener(UI_METHOD *method))(UI*);
int (*UI_method_get_writer(UI_METHOD *method))(UI*,UI_STRING*);
int (*UI_method_get_flusher(UI_METHOD *method))(UI*);
int (*UI_method_get_reader(UI_METHOD *method))(UI*,UI_STRING*);
int (*UI_method_get_closer(UI_METHOD *method))(UI*);
char * (*UI_method_get_prompt_constructor(UI_METHOD *method))(UI*, const char*, const char*);





enum UI_string_types UI_get_string_type(UI_STRING *uis);

int UI_get_input_flags(UI_STRING *uis);

const char *UI_get0_output_string(UI_STRING *uis);

const char *UI_get0_action_string(UI_STRING *uis);

const char *UI_get0_result_string(UI_STRING *uis);

const char *UI_get0_test_string(UI_STRING *uis);

int UI_get_result_minsize(UI_STRING *uis);

int UI_get_result_maxsize(UI_STRING *uis);

int UI_set_result(UI *ui, UI_STRING *uis, const char *result);



int UI_UTIL_read_pw_string(char *buf,int length,const char *prompt,int verify);
int UI_UTIL_read_pw(char *buf,char *buff,int size,const char *prompt,int verify);






void ERR_load_UI_strings(void);


int _ossl_old_des_read_pw_string(char *buf,int length,const char *prompt,int verify);
int _ossl_old_des_read_pw(char *buf,char *buff,int size,const char *prompt,int verify);



extern int _shadow_DES_check_key;

extern int _shadow_DES_rw_mode;


const char *DES_options(void);
void DES_ecb3_encrypt(const_DES_cblock *input, DES_cblock *output,
        DES_key_schedule *ks1,DES_key_schedule *ks2,
        DES_key_schedule *ks3, int enc);
unsigned int DES_cbc_cksum(const unsigned char *input,DES_cblock *output,
         long length,DES_key_schedule *schedule,
         const_DES_cblock *ivec);

void DES_cbc_encrypt(const unsigned char *input,unsigned char *output,
       long length,DES_key_schedule *schedule,DES_cblock *ivec,
       int enc);
void DES_ncbc_encrypt(const unsigned char *input,unsigned char *output,
        long length,DES_key_schedule *schedule,DES_cblock *ivec,
        int enc);
void DES_xcbc_encrypt(const unsigned char *input,unsigned char *output,
        long length,DES_key_schedule *schedule,DES_cblock *ivec,
        const_DES_cblock *inw,const_DES_cblock *outw,int enc);
void DES_cfb_encrypt(const unsigned char *in,unsigned char *out,int numbits,
       long length,DES_key_schedule *schedule,DES_cblock *ivec,
       int enc);
void DES_ecb_encrypt(const_DES_cblock *input,DES_cblock *output,
       DES_key_schedule *ks,int enc);

void DES_encrypt1(unsigned int *data,DES_key_schedule *ks, int enc);







void DES_encrypt2(unsigned int *data,DES_key_schedule *ks, int enc);

void DES_encrypt3(unsigned int *data, DES_key_schedule *ks1,
    DES_key_schedule *ks2, DES_key_schedule *ks3);
void DES_decrypt3(unsigned int *data, DES_key_schedule *ks1,
    DES_key_schedule *ks2, DES_key_schedule *ks3);
void DES_ede3_cbc_encrypt(const unsigned char *input,unsigned char *output,
     long length,
     DES_key_schedule *ks1,DES_key_schedule *ks2,
     DES_key_schedule *ks3,DES_cblock *ivec,int enc);
void DES_ede3_cbcm_encrypt(const unsigned char *in,unsigned char *out,
      long length,
      DES_key_schedule *ks1,DES_key_schedule *ks2,
      DES_key_schedule *ks3,
      DES_cblock *ivec1,DES_cblock *ivec2,
      int enc);
void DES_ede3_cfb64_encrypt(const unsigned char *in,unsigned char *out,
       long length,DES_key_schedule *ks1,
       DES_key_schedule *ks2,DES_key_schedule *ks3,
       DES_cblock *ivec,int *num,int enc);
void DES_ede3_cfb_encrypt(const unsigned char *in,unsigned char *out,
     int numbits,long length,DES_key_schedule *ks1,
     DES_key_schedule *ks2,DES_key_schedule *ks3,
     DES_cblock *ivec,int enc);
void DES_ede3_ofb64_encrypt(const unsigned char *in,unsigned char *out,
       long length,DES_key_schedule *ks1,
       DES_key_schedule *ks2,DES_key_schedule *ks3,
       DES_cblock *ivec,int *num);





int DES_enc_read(int fd,void *buf,int len,DES_key_schedule *sched,
   DES_cblock *iv);
int DES_enc_write(int fd,const void *buf,int len,DES_key_schedule *sched,
    DES_cblock *iv);
char *DES_fcrypt(const char *buf,const char *salt, char *ret);
char *DES_crypt(const char *buf,const char *salt);
void DES_ofb_encrypt(const unsigned char *in,unsigned char *out,int numbits,
       long length,DES_key_schedule *schedule,DES_cblock *ivec);
void DES_pcbc_encrypt(const unsigned char *input,unsigned char *output,
        long length,DES_key_schedule *schedule,DES_cblock *ivec,
        int enc);
unsigned int DES_quad_cksum(const unsigned char *input,DES_cblock output[],
   long length,int out_count,DES_cblock *seed);
int DES_random_key(DES_cblock *ret);
void DES_set_odd_parity(DES_cblock *key);
int DES_check_key_parity(const_DES_cblock *key);
int DES_is_weak_key(const_DES_cblock *key);



int DES_set_key(const_DES_cblock *key,DES_key_schedule *schedule);
int DES_key_sched(const_DES_cblock *key,DES_key_schedule *schedule);
int DES_set_key_checked(const_DES_cblock *key,DES_key_schedule *schedule);
void DES_set_key_unchecked(const_DES_cblock *key,DES_key_schedule *schedule);



void DES_string_to_key(const char *str,DES_cblock *key);
void DES_string_to_2keys(const char *str,DES_cblock *key1,DES_cblock *key2);
void DES_cfb64_encrypt(const unsigned char *in,unsigned char *out,long length,
         DES_key_schedule *schedule,DES_cblock *ivec,int *num,
         int enc);
void DES_ofb64_encrypt(const unsigned char *in,unsigned char *out,long length,
         DES_key_schedule *schedule,DES_cblock *ivec,int *num);

int DES_read_password(DES_cblock *key, const char *prompt, int verify);
int DES_read_2passwords(DES_cblock *key1, DES_cblock *key2, const char *prompt,
 int verify);






typedef void (*DSO_FUNC_TYPE)(void);

typedef struct dso_st DSO;







typedef char* (*DSO_NAME_CONVERTER_FUNC)(DSO *, const char *);

typedef char* (*DSO_MERGER_FUNC)(DSO *, const char *, const char *);

typedef struct dso_meth_st
 {
 const char *name;



 int (*dso_load)(DSO *dso);

 int (*dso_unload)(DSO *dso);

 void *(*dso_bind_var)(DSO *dso, const char *symname);






 DSO_FUNC_TYPE (*dso_bind_func)(DSO *dso, const char *symname);

 long (*dso_ctrl)(DSO *dso, int cmd, long larg, void *parg);


 DSO_NAME_CONVERTER_FUNC dso_name_converter;


 DSO_MERGER_FUNC dso_merger;


 int (*init)(DSO *dso);
 int (*finish)(DSO *dso);


 int (*pathbyaddr)(void *addr,char *path,int sz);

 void *(*globallookup)(const char *symname);
 } DSO_METHOD;




struct dso_st
 {
 DSO_METHOD *meth;





 struct stack_st_void *meth_data;
 int references;
 int flags;


 CRYPTO_EX_DATA ex_data;



 DSO_NAME_CONVERTER_FUNC name_converter;



 DSO_MERGER_FUNC merger;


 char *filename;

 char *loaded_filename;
 };


DSO * DSO_new(void);
DSO * DSO_new_method(DSO_METHOD *method);
int DSO_free(DSO *dso);
int DSO_flags(DSO *dso);
int DSO_up_ref(DSO *dso);
long DSO_ctrl(DSO *dso, int cmd, long larg, void *parg);





int DSO_set_name_converter(DSO *dso, DSO_NAME_CONVERTER_FUNC cb,
    DSO_NAME_CONVERTER_FUNC *oldcb);


const char *DSO_get_filename(DSO *dso);
int DSO_set_filename(DSO *dso, const char *filename);

char *DSO_convert_filename(DSO *dso, const char *filename);




char *DSO_merge(DSO *dso, const char *filespec1, const char *filespec2);







const char *DSO_get_loaded_filename(DSO *dso);

void DSO_set_default_method(DSO_METHOD *meth);
DSO_METHOD *DSO_get_default_method(void);
DSO_METHOD *DSO_get_method(DSO *dso);
DSO_METHOD *DSO_set_method(DSO *dso, DSO_METHOD *meth);






DSO *DSO_load(DSO *dso, const char *filename, DSO_METHOD *meth, int flags);


void *DSO_bind_var(DSO *dso, const char *symname);


DSO_FUNC_TYPE DSO_bind_func(DSO *dso, const char *symname);




DSO_METHOD *DSO_METHOD_openssl(void);



DSO_METHOD *DSO_METHOD_null(void);




DSO_METHOD *DSO_METHOD_dlfcn(void);




DSO_METHOD *DSO_METHOD_dl(void);


DSO_METHOD *DSO_METHOD_win32(void);


DSO_METHOD *DSO_METHOD_vms(void);

int DSO_pathbyaddr(void *addr,char *path,int sz);

void *DSO_global_lookup(const char *name);


DSO_METHOD *DSO_METHOD_beos(void);





void ERR_load_DSO_strings(void);















typedef struct _pqueue *pqueue;

typedef struct _pitem
 {
 unsigned char priority[8];
 void *data;
 struct _pitem *next;
 } pitem;

typedef struct _pitem *piterator;

pitem *pitem_new(unsigned char *prio64be, void *data);
void pitem_free(pitem *item);

pqueue pqueue_new(void);
void pqueue_free(pqueue pq);

pitem *pqueue_insert(pqueue pq, pitem *item);
pitem *pqueue_peek(pqueue pq);
pitem *pqueue_pop(pqueue pq);
pitem *pqueue_find(pqueue pq, unsigned char *prio64be);
pitem *pqueue_iterator(pqueue pq);
pitem *pqueue_next(piterator *iter);

void pqueue_print(pqueue pq);
int pqueue_size(pqueue pq);









struct timezone
  {
    int tz_minuteswest;
    int tz_dsttime;
  };

typedef struct timezone *__restrict __timezone_ptr_t;

extern int gettimeofday (struct timeval *__restrict __tv,
    __timezone_ptr_t __tz)  ;




extern int settimeofday (const struct timeval *__tv,
    const struct timezone *__tz)
     ;





extern int adjtime (const struct timeval *__delta,
      struct timeval *__olddelta) ;





struct itimerval
  {

    struct timeval it_interval;

    struct timeval it_value;
  };






typedef int __itimer_which_t;




extern int getitimer (__itimer_which_t __which,
        struct itimerval *__value) ;




extern int setitimer (__itimer_which_t __which,
        const struct itimerval *__restrict __new,
        struct itimerval *__restrict __old) ;




extern int utimes (const char *__file, const struct timeval __tvp[2])
      ;



extern int lutimes (const char *__file, const struct timeval __tvp[2])
      ;


extern int futimes (int __fd, const struct timeval __tvp[2]) ;




typedef struct dtls1_bitmap_st
 {
 unsigned long map;

 unsigned char max_seq_num[8];


 } DTLS1_BITMAP;

struct dtls1_retransmit_state
 {
 EVP_CIPHER_CTX *enc_write_ctx;
 EVP_MD_CTX *write_hash;

 COMP_CTX *compress;



 SSL_SESSION *session;
 unsigned short epoch;
 };

struct hm_header_st
 {
 unsigned char type;
 unsigned long msg_len;
 unsigned short seq;
 unsigned long frag_off;
 unsigned long frag_len;
 unsigned int is_ccs;
 struct dtls1_retransmit_state saved_retransmit_state;
 };

struct ccs_header_st
 {
 unsigned char type;
 unsigned short seq;
 };

struct dtls1_timeout_st
 {

 unsigned int read_timeouts;


 unsigned int write_timeouts;


 unsigned int num_alerts;
 };

typedef struct record_pqueue_st
 {
 unsigned short epoch;
 pqueue q;
 } record_pqueue;

typedef struct hm_fragment_st
 {
 struct hm_header_st msg_header;
 unsigned char *fragment;
 unsigned char *reassembly;
 } hm_fragment;

typedef struct dtls1_state_st
 {
 unsigned int send_cookie;
 unsigned char cookie[256];
 unsigned char rcvd_cookie[256];
 unsigned int cookie_len;






 unsigned short r_epoch;
 unsigned short w_epoch;


 DTLS1_BITMAP bitmap;


 DTLS1_BITMAP next_bitmap;


 unsigned short handshake_write_seq;
 unsigned short next_handshake_write_seq;

 unsigned short handshake_read_seq;


 unsigned char last_write_sequence[8];


 record_pqueue unprocessed_rcds;
 record_pqueue processed_rcds;


 pqueue buffered_messages;


 pqueue sent_messages;






 record_pqueue buffered_app_data;


 unsigned int listen;

 unsigned int mtu;

 struct hm_header_st w_msg_hdr;
 struct hm_header_st r_msg_hdr;

 struct dtls1_timeout_st timeout;


 struct timeval next_timeout;


 unsigned short timeout_duration;



 unsigned char alert_fragment[2];
 unsigned int alert_fragment_len;
 unsigned char handshake_fragment[12];
 unsigned int handshake_fragment_len;

 unsigned int retransmitting;
 unsigned int change_cipher_spec_ok;

 } DTLS1_STATE;


typedef struct ssl3_record_st
 {
       int type;
       unsigned int length;
       unsigned int off;
       unsigned char *data;
       unsigned char *input;
       unsigned char *comp;
        unsigned long epoch;
        unsigned char seq_num[8];
 } SSL3_RECORD;

typedef struct ssl3_buffer_st
 {
 unsigned char *buf;

 size_t len;
 int offset;
 int left;
 } SSL3_BUFFER;

typedef struct dtls1_record_data_st
 {
 unsigned char *packet;
 unsigned int packet_length;
 SSL3_BUFFER rbuf;
 SSL3_RECORD rrec;



 } DTLS1_RECORD_DATA;



extern const unsigned char _openssl_os_toascii[256];
extern const unsigned char _openssl_os_toebcdic[256];
void *_openssl_ebcdic2ascii(void *dest, const void *srce, size_t count);
void *_openssl_ascii2ebcdic(void *dest, const void *srce, size_t count);

















struct rand_meth_st
 {
 void (*seed)(const void *buf, int num);
 int (*bytes)(unsigned char *buf, int num);
 void (*cleanup)(void);
 void (*add)(const void *buf, int num, double entropy);
 int (*pseudorand)(unsigned char *buf, int num);
 int (*status)(void);
 };





int RAND_set_rand_method(const RAND_METHOD *meth);
const RAND_METHOD *RAND_get_rand_method(void);

int RAND_set_rand_engine(ENGINE *engine);

RAND_METHOD *RAND_SSLeay(void);
void RAND_cleanup(void );
int RAND_bytes(unsigned char *buf,int num);
int RAND_pseudo_bytes(unsigned char *buf,int num);
void RAND_seed(const void *buf,int num);
void RAND_add(const void *buf,int num,double entropy);
int RAND_load_file(const char *file,long max_bytes);
int RAND_write_file(const char *file);
const char *RAND_file_name(char *file,size_t num);
int RAND_status(void);
int RAND_query_egd_bytes(const char *path, unsigned char *buf, int bytes);
int RAND_egd(const char *path);
int RAND_egd_bytes(const char *path,int bytes);
int RAND_poll(void);

void ERR_load_RAND_strings(void);






























extern int *__errno_location (void)  ;











typedef struct err_state_st
 {
 CRYPTO_THREADID tid;
 int err_flags[16];
 unsigned long err_buffer[16];
 char *err_data[16];
 int err_data_flags[16];
 const char *err_file[16];
 int err_line[16];
 int top,bottom;
 } ERR_STATE;

typedef struct ERR_string_data_st
 {
 unsigned long error;
 const char *string;
 } ERR_STRING_DATA;

void ERR_put_error(int lib, int func,int reason,const char *file,int line);
void ERR_set_error_data(char *data,int flags);

unsigned long ERR_get_error(void);
unsigned long ERR_get_error_line(const char **file,int *line);
unsigned long ERR_get_error_line_data(const char **file,int *line,
          const char **data, int *flags);
unsigned long ERR_peek_error(void);
unsigned long ERR_peek_error_line(const char **file,int *line);
unsigned long ERR_peek_error_line_data(const char **file,int *line,
           const char **data,int *flags);
unsigned long ERR_peek_last_error(void);
unsigned long ERR_peek_last_error_line(const char **file,int *line);
unsigned long ERR_peek_last_error_line_data(const char **file,int *line,
           const char **data,int *flags);
void ERR_clear_error(void );
char *ERR_error_string(unsigned long e,char *buf);
void ERR_error_string_n(unsigned long e, char *buf, size_t len);
const char *ERR_lib_error_string(unsigned long e);
const char *ERR_func_error_string(unsigned long e);
const char *ERR_reason_error_string(unsigned long e);
void ERR_print_errors_cb(int (*cb)(const char *str, size_t len, void *u),
    void *u);

void ERR_print_errors_fp(FILE *fp);


void ERR_print_errors(BIO *bp);

void ERR_add_error_data(int num, ...);
void ERR_add_error_vdata(int num, va_list args);
void ERR_load_strings(int lib,ERR_STRING_DATA str[]);
void ERR_unload_strings(int lib,ERR_STRING_DATA str[]);
void ERR_load_ERR_strings(void);
void ERR_load_crypto_strings(void);
void ERR_free_strings(void);

void ERR_remove_thread_state(const CRYPTO_THREADID *tid);

void ERR_remove_state(unsigned long pid);

ERR_STATE *ERR_get_state(void);


struct lhash_st_ERR_STRING_DATA *ERR_get_string_table(void);
struct lhash_st_ERR_STATE *ERR_get_err_state_table(void);
void ERR_release_err_state_table(struct lhash_st_ERR_STATE **hash);


int ERR_get_next_error_library(void);

int ERR_set_mark(void);
int ERR_pop_to_mark(void);





const ERR_FNS *ERR_get_implementation(void);


int ERR_set_implementation(const ERR_FNS *fns);


typedef struct ENGINE_CMD_DEFN_st
 {
 unsigned int cmd_num;
 const char *cmd_name;
 const char *cmd_desc;
 unsigned int cmd_flags;
 } ENGINE_CMD_DEFN;


typedef int (*ENGINE_GEN_FUNC_PTR)(void);

typedef int (*ENGINE_GEN_INT_FUNC_PTR)(ENGINE *);

typedef int (*ENGINE_CTRL_FUNC_PTR)(ENGINE *, int, long, void *, void (*f)(void));

typedef EVP_PKEY * (*ENGINE_LOAD_KEY_PTR)(ENGINE *, const char *,
 UI_METHOD *ui_method, void *callback_data);
typedef int (*ENGINE_SSL_CLIENT_CERT_PTR)(ENGINE *, SSL *ssl,
 struct stack_st_X509_NAME *ca_dn, X509 **pcert, EVP_PKEY **pkey,
 struct stack_st_X509 **pother, UI_METHOD *ui_method, void *callback_data);

typedef int (*ENGINE_CIPHERS_PTR)(ENGINE *, const EVP_CIPHER **, const int **, int);
typedef int (*ENGINE_DIGESTS_PTR)(ENGINE *, const EVP_MD **, const int **, int);
typedef int (*ENGINE_PKEY_METHS_PTR)(ENGINE *, EVP_PKEY_METHOD **, const int **, int);
typedef int (*ENGINE_PKEY_ASN1_METHS_PTR)(ENGINE *, EVP_PKEY_ASN1_METHOD **, const int **, int);

ENGINE *ENGINE_get_first(void);
ENGINE *ENGINE_get_last(void);

ENGINE *ENGINE_get_next(ENGINE *e);
ENGINE *ENGINE_get_prev(ENGINE *e);

int ENGINE_add(ENGINE *e);

int ENGINE_remove(ENGINE *e);

ENGINE *ENGINE_by_id(const char *id);

void ENGINE_load_openssl(void);
void ENGINE_load_dynamic(void);

void ENGINE_load_cryptodev(void);
void ENGINE_load_rsax(void);
void ENGINE_load_rdrand(void);
void ENGINE_load_builtin_engines(void);



unsigned int ENGINE_get_table_flags(void);
void ENGINE_set_table_flags(unsigned int flags);

int ENGINE_register_RSA(ENGINE *e);
void ENGINE_unregister_RSA(ENGINE *e);
void ENGINE_register_all_RSA(void);

int ENGINE_register_DSA(ENGINE *e);
void ENGINE_unregister_DSA(ENGINE *e);
void ENGINE_register_all_DSA(void);

int ENGINE_register_ECDH(ENGINE *e);
void ENGINE_unregister_ECDH(ENGINE *e);
void ENGINE_register_all_ECDH(void);

int ENGINE_register_ECDSA(ENGINE *e);
void ENGINE_unregister_ECDSA(ENGINE *e);
void ENGINE_register_all_ECDSA(void);

int ENGINE_register_DH(ENGINE *e);
void ENGINE_unregister_DH(ENGINE *e);
void ENGINE_register_all_DH(void);

int ENGINE_register_RAND(ENGINE *e);
void ENGINE_unregister_RAND(ENGINE *e);
void ENGINE_register_all_RAND(void);

int ENGINE_register_STORE(ENGINE *e);
void ENGINE_unregister_STORE(ENGINE *e);
void ENGINE_register_all_STORE(void);

int ENGINE_register_ciphers(ENGINE *e);
void ENGINE_unregister_ciphers(ENGINE *e);
void ENGINE_register_all_ciphers(void);

int ENGINE_register_digests(ENGINE *e);
void ENGINE_unregister_digests(ENGINE *e);
void ENGINE_register_all_digests(void);

int ENGINE_register_pkey_meths(ENGINE *e);
void ENGINE_unregister_pkey_meths(ENGINE *e);
void ENGINE_register_all_pkey_meths(void);

int ENGINE_register_pkey_asn1_meths(ENGINE *e);
void ENGINE_unregister_pkey_asn1_meths(ENGINE *e);
void ENGINE_register_all_pkey_asn1_meths(void);





int ENGINE_register_complete(ENGINE *e);
int ENGINE_register_all_complete(void);

int ENGINE_ctrl(ENGINE *e, int cmd, long i, void *p, void (*f)(void));





int ENGINE_cmd_is_executable(ENGINE *e, int cmd);





int ENGINE_ctrl_cmd(ENGINE *e, const char *cmd_name,
        long i, void *p, void (*f)(void), int cmd_optional);

int ENGINE_ctrl_cmd_string(ENGINE *e, const char *cmd_name, const char *arg,
    int cmd_optional);







ENGINE *ENGINE_new(void);
int ENGINE_free(ENGINE *e);
int ENGINE_up_ref(ENGINE *e);
int ENGINE_set_id(ENGINE *e, const char *id);
int ENGINE_set_name(ENGINE *e, const char *name);
int ENGINE_set_RSA(ENGINE *e, const RSA_METHOD *rsa_meth);
int ENGINE_set_DSA(ENGINE *e, const DSA_METHOD *dsa_meth);
int ENGINE_set_ECDH(ENGINE *e, const ECDH_METHOD *ecdh_meth);
int ENGINE_set_ECDSA(ENGINE *e, const ECDSA_METHOD *ecdsa_meth);
int ENGINE_set_DH(ENGINE *e, const DH_METHOD *dh_meth);
int ENGINE_set_RAND(ENGINE *e, const RAND_METHOD *rand_meth);
int ENGINE_set_STORE(ENGINE *e, const STORE_METHOD *store_meth);
int ENGINE_set_destroy_function(ENGINE *e, ENGINE_GEN_INT_FUNC_PTR destroy_f);
int ENGINE_set_init_function(ENGINE *e, ENGINE_GEN_INT_FUNC_PTR init_f);
int ENGINE_set_finish_function(ENGINE *e, ENGINE_GEN_INT_FUNC_PTR finish_f);
int ENGINE_set_ctrl_function(ENGINE *e, ENGINE_CTRL_FUNC_PTR ctrl_f);
int ENGINE_set_load_privkey_function(ENGINE *e, ENGINE_LOAD_KEY_PTR loadpriv_f);
int ENGINE_set_load_pubkey_function(ENGINE *e, ENGINE_LOAD_KEY_PTR loadpub_f);
int ENGINE_set_load_ssl_client_cert_function(ENGINE *e,
    ENGINE_SSL_CLIENT_CERT_PTR loadssl_f);
int ENGINE_set_ciphers(ENGINE *e, ENGINE_CIPHERS_PTR f);
int ENGINE_set_digests(ENGINE *e, ENGINE_DIGESTS_PTR f);
int ENGINE_set_pkey_meths(ENGINE *e, ENGINE_PKEY_METHS_PTR f);
int ENGINE_set_pkey_asn1_meths(ENGINE *e, ENGINE_PKEY_ASN1_METHS_PTR f);
int ENGINE_set_flags(ENGINE *e, int flags);
int ENGINE_set_cmd_defns(ENGINE *e, const ENGINE_CMD_DEFN *defns);

int ENGINE_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func,
  CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func);
int ENGINE_set_ex_data(ENGINE *e, int idx, void *arg);
void *ENGINE_get_ex_data(const ENGINE *e, int idx);





void ENGINE_cleanup(void);





const char *ENGINE_get_id(const ENGINE *e);
const char *ENGINE_get_name(const ENGINE *e);
const RSA_METHOD *ENGINE_get_RSA(const ENGINE *e);
const DSA_METHOD *ENGINE_get_DSA(const ENGINE *e);
const ECDH_METHOD *ENGINE_get_ECDH(const ENGINE *e);
const ECDSA_METHOD *ENGINE_get_ECDSA(const ENGINE *e);
const DH_METHOD *ENGINE_get_DH(const ENGINE *e);
const RAND_METHOD *ENGINE_get_RAND(const ENGINE *e);
const STORE_METHOD *ENGINE_get_STORE(const ENGINE *e);
ENGINE_GEN_INT_FUNC_PTR ENGINE_get_destroy_function(const ENGINE *e);
ENGINE_GEN_INT_FUNC_PTR ENGINE_get_init_function(const ENGINE *e);
ENGINE_GEN_INT_FUNC_PTR ENGINE_get_finish_function(const ENGINE *e);
ENGINE_CTRL_FUNC_PTR ENGINE_get_ctrl_function(const ENGINE *e);
ENGINE_LOAD_KEY_PTR ENGINE_get_load_privkey_function(const ENGINE *e);
ENGINE_LOAD_KEY_PTR ENGINE_get_load_pubkey_function(const ENGINE *e);
ENGINE_SSL_CLIENT_CERT_PTR ENGINE_get_ssl_client_cert_function(const ENGINE *e);
ENGINE_CIPHERS_PTR ENGINE_get_ciphers(const ENGINE *e);
ENGINE_DIGESTS_PTR ENGINE_get_digests(const ENGINE *e);
ENGINE_PKEY_METHS_PTR ENGINE_get_pkey_meths(const ENGINE *e);
ENGINE_PKEY_ASN1_METHS_PTR ENGINE_get_pkey_asn1_meths(const ENGINE *e);
const EVP_CIPHER *ENGINE_get_cipher(ENGINE *e, int nid);
const EVP_MD *ENGINE_get_digest(ENGINE *e, int nid);
const EVP_PKEY_METHOD *ENGINE_get_pkey_meth(ENGINE *e, int nid);
const EVP_PKEY_ASN1_METHOD *ENGINE_get_pkey_asn1_meth(ENGINE *e, int nid);
const EVP_PKEY_ASN1_METHOD *ENGINE_get_pkey_asn1_meth_str(ENGINE *e,
     const char *str, int len);
const EVP_PKEY_ASN1_METHOD *ENGINE_pkey_asn1_find_str(ENGINE **pe,
     const char *str, int len);
const ENGINE_CMD_DEFN *ENGINE_get_cmd_defns(const ENGINE *e);
int ENGINE_get_flags(const ENGINE *e);

int ENGINE_init(ENGINE *e);



int ENGINE_finish(ENGINE *e);




EVP_PKEY *ENGINE_load_private_key(ENGINE *e, const char *key_id,
 UI_METHOD *ui_method, void *callback_data);
EVP_PKEY *ENGINE_load_public_key(ENGINE *e, const char *key_id,
 UI_METHOD *ui_method, void *callback_data);
int ENGINE_load_ssl_client_cert(ENGINE *e, SSL *s,
 struct stack_st_X509_NAME *ca_dn, X509 **pcert, EVP_PKEY **ppkey,
 struct stack_st_X509 **pother,
 UI_METHOD *ui_method, void *callback_data);





ENGINE *ENGINE_get_default_RSA(void);

ENGINE *ENGINE_get_default_DSA(void);
ENGINE *ENGINE_get_default_ECDH(void);
ENGINE *ENGINE_get_default_ECDSA(void);
ENGINE *ENGINE_get_default_DH(void);
ENGINE *ENGINE_get_default_RAND(void);


ENGINE *ENGINE_get_cipher_engine(int nid);
ENGINE *ENGINE_get_digest_engine(int nid);
ENGINE *ENGINE_get_pkey_meth_engine(int nid);
ENGINE *ENGINE_get_pkey_asn1_meth_engine(int nid);





int ENGINE_set_default_RSA(ENGINE *e);
int ENGINE_set_default_string(ENGINE *e, const char *def_list);

int ENGINE_set_default_DSA(ENGINE *e);
int ENGINE_set_default_ECDH(ENGINE *e);
int ENGINE_set_default_ECDSA(ENGINE *e);
int ENGINE_set_default_DH(ENGINE *e);
int ENGINE_set_default_RAND(ENGINE *e);
int ENGINE_set_default_ciphers(ENGINE *e);
int ENGINE_set_default_digests(ENGINE *e);
int ENGINE_set_default_pkey_meths(ENGINE *e);
int ENGINE_set_default_pkey_asn1_meths(ENGINE *e);






int ENGINE_set_default(ENGINE *e, unsigned int flags);

void ENGINE_add_conf_module(void);

typedef void *(*dyn_MEM_malloc_cb)(size_t);
typedef void *(*dyn_MEM_realloc_cb)(void *, size_t);
typedef void (*dyn_MEM_free_cb)(void *);
typedef struct st_dynamic_MEM_fns {
 dyn_MEM_malloc_cb malloc_cb;
 dyn_MEM_realloc_cb realloc_cb;
 dyn_MEM_free_cb free_cb;
 } dynamic_MEM_fns;


typedef void (*dyn_lock_locking_cb)(int,int,const char *,int);
typedef int (*dyn_lock_add_lock_cb)(int*,int,int,const char *,int);
typedef struct CRYPTO_dynlock_value *(*dyn_dynlock_create_cb)(
      const char *,int);
typedef void (*dyn_dynlock_lock_cb)(int,struct CRYPTO_dynlock_value *,
      const char *,int);
typedef void (*dyn_dynlock_destroy_cb)(struct CRYPTO_dynlock_value *,
      const char *,int);
typedef struct st_dynamic_LOCK_fns {
 dyn_lock_locking_cb lock_locking_cb;
 dyn_lock_add_lock_cb lock_add_lock_cb;
 dyn_dynlock_create_cb dynlock_create_cb;
 dyn_dynlock_lock_cb dynlock_lock_cb;
 dyn_dynlock_destroy_cb dynlock_destroy_cb;
 } dynamic_LOCK_fns;

typedef struct st_dynamic_fns {
 void *static_state;
 const ERR_FNS *err_fns;
 const CRYPTO_EX_DATA_IMPL *ex_data_fns;
 dynamic_MEM_fns mem_fns;
 dynamic_LOCK_fns lock_fns;
 } dynamic_fns;

typedef unsigned long (*dynamic_v_check_fn)(unsigned long ossl_version);

typedef int (*dynamic_bind_engine)(ENGINE *e, const char *id,
    const dynamic_fns *fns);

void *ENGINE_get_static_state(void);

void ERR_load_ENGINE_strings(void);













typedef struct hmac_ctx_st
 {
 const EVP_MD *md;
 EVP_MD_CTX md_ctx;
 EVP_MD_CTX i_ctx;
 EVP_MD_CTX o_ctx;
 unsigned int key_length;
 unsigned char key[128];
 } HMAC_CTX;




void HMAC_CTX_init(HMAC_CTX *ctx);
void HMAC_CTX_cleanup(HMAC_CTX *ctx);



int HMAC_Init(HMAC_CTX *ctx, const void *key, int len,
        const EVP_MD *md);
int HMAC_Init_ex(HMAC_CTX *ctx, const void *key, int len,
    const EVP_MD *md, ENGINE *impl);
int HMAC_Update(HMAC_CTX *ctx, const unsigned char *data, size_t len);
int HMAC_Final(HMAC_CTX *ctx, unsigned char *md, unsigned int *len);
unsigned char *HMAC(const EVP_MD *evp_md, const void *key, int key_len,
      const unsigned char *d, size_t n, unsigned char *md,
      unsigned int *md_len);
int HMAC_CTX_copy(HMAC_CTX *dctx, HMAC_CTX *sctx);

void HMAC_CTX_set_flags(HMAC_CTX *ctx, unsigned long flags);



typedef struct krb5_encdata_st
 {
 ASN1_INTEGER *etype;
 ASN1_INTEGER *kvno;
 ASN1_OCTET_STRING *cipher;
 } KRB5_ENCDATA;

struct stack_st_KRB5_ENCDATA { _STACK stack; };






typedef struct krb5_princname_st
 {
 ASN1_INTEGER *nametype;
 struct stack_st_ASN1_GENERALSTRING *namestring;
 } KRB5_PRINCNAME;

struct stack_st_KRB5_PRINCNAME { _STACK stack; };

typedef struct krb5_tktbody_st
 {
 ASN1_INTEGER *tktvno;
 ASN1_GENERALSTRING *realm;
 KRB5_PRINCNAME *sname;
 KRB5_ENCDATA *encdata;
 } KRB5_TKTBODY;

typedef struct stack_st_KRB5_TKTBODY KRB5_TICKET;
struct stack_st_KRB5_TKTBODY { _STACK stack; };

typedef struct krb5_ap_req_st
 {
 ASN1_INTEGER *pvno;
 ASN1_INTEGER *msgtype;
 ASN1_BIT_STRING *apoptions;
 KRB5_TICKET *ticket;
 KRB5_ENCDATA *authenticator;
 } KRB5_APREQBODY;

typedef struct stack_st_KRB5_APREQBODY KRB5_APREQ;
struct stack_st_KRB5_APREQBODY { _STACK stack; };

typedef struct krb5_checksum_st
 {
 ASN1_INTEGER *ctype;
 ASN1_OCTET_STRING *checksum;
 } KRB5_CHECKSUM;

struct stack_st_KRB5_CHECKSUM { _STACK stack; };







typedef struct krb5_encryptionkey_st
 {
 ASN1_INTEGER *ktype;
 ASN1_OCTET_STRING *keyvalue;
 } KRB5_ENCKEY;

struct stack_st_KRB5_ENCKEY { _STACK stack; };







typedef struct krb5_authorization_st
 {
 ASN1_INTEGER *adtype;
 ASN1_OCTET_STRING *addata;
 } KRB5_AUTHDATA;

struct stack_st_KRB5_AUTHDATA { _STACK stack; };

typedef struct krb5_authenticator_st
 {
 ASN1_INTEGER *avno;
 ASN1_GENERALSTRING *crealm;
 KRB5_PRINCNAME *cname;
 KRB5_CHECKSUM *cksum;
 ASN1_INTEGER *cusec;
 ASN1_GENERALIZEDTIME *ctime;
 KRB5_ENCKEY *subkey;
 ASN1_INTEGER *seqnum;
 KRB5_AUTHDATA *authorization;
 } KRB5_AUTHENTBODY;

typedef struct stack_st_KRB5_AUTHENTBODY KRB5_AUTHENT;
struct stack_st_KRB5_AUTHENTBODY { _STACK stack; };

KRB5_ENCDATA *KRB5_ENCDATA_new(void); void KRB5_ENCDATA_free(KRB5_ENCDATA *a); KRB5_ENCDATA *d2i_KRB5_ENCDATA(KRB5_ENCDATA **a, const unsigned char **in, long len); int i2d_KRB5_ENCDATA(KRB5_ENCDATA *a, unsigned char **out); extern const ASN1_ITEM KRB5_ENCDATA_it;
KRB5_PRINCNAME *KRB5_PRINCNAME_new(void); void KRB5_PRINCNAME_free(KRB5_PRINCNAME *a); KRB5_PRINCNAME *d2i_KRB5_PRINCNAME(KRB5_PRINCNAME **a, const unsigned char **in, long len); int i2d_KRB5_PRINCNAME(KRB5_PRINCNAME *a, unsigned char **out); extern const ASN1_ITEM KRB5_PRINCNAME_it;
KRB5_TKTBODY *KRB5_TKTBODY_new(void); void KRB5_TKTBODY_free(KRB5_TKTBODY *a); KRB5_TKTBODY *d2i_KRB5_TKTBODY(KRB5_TKTBODY **a, const unsigned char **in, long len); int i2d_KRB5_TKTBODY(KRB5_TKTBODY *a, unsigned char **out); extern const ASN1_ITEM KRB5_TKTBODY_it;
KRB5_APREQBODY *KRB5_APREQBODY_new(void); void KRB5_APREQBODY_free(KRB5_APREQBODY *a); KRB5_APREQBODY *d2i_KRB5_APREQBODY(KRB5_APREQBODY **a, const unsigned char **in, long len); int i2d_KRB5_APREQBODY(KRB5_APREQBODY *a, unsigned char **out); extern const ASN1_ITEM KRB5_APREQBODY_it;
KRB5_TICKET *KRB5_TICKET_new(void); void KRB5_TICKET_free(KRB5_TICKET *a); KRB5_TICKET *d2i_KRB5_TICKET(KRB5_TICKET **a, const unsigned char **in, long len); int i2d_KRB5_TICKET(KRB5_TICKET *a, unsigned char **out); extern const ASN1_ITEM KRB5_TICKET_it;
KRB5_APREQ *KRB5_APREQ_new(void); void KRB5_APREQ_free(KRB5_APREQ *a); KRB5_APREQ *d2i_KRB5_APREQ(KRB5_APREQ **a, const unsigned char **in, long len); int i2d_KRB5_APREQ(KRB5_APREQ *a, unsigned char **out); extern const ASN1_ITEM KRB5_APREQ_it;

KRB5_CHECKSUM *KRB5_CHECKSUM_new(void); void KRB5_CHECKSUM_free(KRB5_CHECKSUM *a); KRB5_CHECKSUM *d2i_KRB5_CHECKSUM(KRB5_CHECKSUM **a, const unsigned char **in, long len); int i2d_KRB5_CHECKSUM(KRB5_CHECKSUM *a, unsigned char **out); extern const ASN1_ITEM KRB5_CHECKSUM_it;
KRB5_ENCKEY *KRB5_ENCKEY_new(void); void KRB5_ENCKEY_free(KRB5_ENCKEY *a); KRB5_ENCKEY *d2i_KRB5_ENCKEY(KRB5_ENCKEY **a, const unsigned char **in, long len); int i2d_KRB5_ENCKEY(KRB5_ENCKEY *a, unsigned char **out); extern const ASN1_ITEM KRB5_ENCKEY_it;
KRB5_AUTHDATA *KRB5_AUTHDATA_new(void); void KRB5_AUTHDATA_free(KRB5_AUTHDATA *a); KRB5_AUTHDATA *d2i_KRB5_AUTHDATA(KRB5_AUTHDATA **a, const unsigned char **in, long len); int i2d_KRB5_AUTHDATA(KRB5_AUTHDATA *a, unsigned char **out); extern const ASN1_ITEM KRB5_AUTHDATA_it;
KRB5_AUTHENTBODY *KRB5_AUTHENTBODY_new(void); void KRB5_AUTHENTBODY_free(KRB5_AUTHENTBODY *a); KRB5_AUTHENTBODY *d2i_KRB5_AUTHENTBODY(KRB5_AUTHENTBODY **a, const unsigned char **in, long len); int i2d_KRB5_AUTHENTBODY(KRB5_AUTHENTBODY *a, unsigned char **out); extern const ASN1_ITEM KRB5_AUTHENTBODY_it;
KRB5_AUTHENT *KRB5_AUTHENT_new(void); void KRB5_AUTHENT_free(KRB5_AUTHENT *a); KRB5_AUTHENT *d2i_KRB5_AUTHENT(KRB5_AUTHENT **a, const unsigned char **in, long len); int i2d_KRB5_AUTHENT(KRB5_AUTHENT *a, unsigned char **out); extern const ASN1_ITEM KRB5_AUTHENT_it;

















typedef struct MD4state_st
 {
 unsigned int A,B,C,D;
 unsigned int Nl,Nh;
 unsigned int data[(64/4)];
 unsigned int num;
 } MD4_CTX;




int MD4_Init(MD4_CTX *c);
int MD4_Update(MD4_CTX *c, const void *data, size_t len);
int MD4_Final(unsigned char *md, MD4_CTX *c);
unsigned char *MD4(const unsigned char *d, size_t n, unsigned char *md);
void MD4_Transform(MD4_CTX *c, const unsigned char *b);











typedef struct MD5state_st
 {
 unsigned int A,B,C,D;
 unsigned int Nl,Nh;
 unsigned int data[(64/4)];
 unsigned int num;
 } MD5_CTX;




int MD5_Init(MD5_CTX *c);
int MD5_Update(MD5_CTX *c, const void *data, size_t len);
int MD5_Final(unsigned char *md, MD5_CTX *c);
unsigned char *MD5(const unsigned char *d, size_t n, unsigned char *md);
void MD5_Transform(MD5_CTX *c, const unsigned char *b);












typedef void (*block128_f)(const unsigned char in[16],
   unsigned char out[16],
   const void *key);

typedef void (*cbc128_f)(const unsigned char *in, unsigned char *out,
   size_t len, const void *key,
   unsigned char ivec[16], int enc);

typedef void (*ctr128_f)(const unsigned char *in, unsigned char *out,
   size_t blocks, const void *key,
   const unsigned char ivec[16]);

typedef void (*ccm128_f)(const unsigned char *in, unsigned char *out,
   size_t blocks, const void *key,
   const unsigned char ivec[16],unsigned char cmac[16]);

void CRYPTO_cbc128_encrypt(const unsigned char *in, unsigned char *out,
   size_t len, const void *key,
   unsigned char ivec[16], block128_f block);
void CRYPTO_cbc128_decrypt(const unsigned char *in, unsigned char *out,
   size_t len, const void *key,
   unsigned char ivec[16], block128_f block);

void CRYPTO_ctr128_encrypt(const unsigned char *in, unsigned char *out,
   size_t len, const void *key,
   unsigned char ivec[16], unsigned char ecount_buf[16],
   unsigned int *num, block128_f block);

void CRYPTO_ctr128_encrypt_ctr32(const unsigned char *in, unsigned char *out,
   size_t len, const void *key,
   unsigned char ivec[16], unsigned char ecount_buf[16],
   unsigned int *num, ctr128_f ctr);

void CRYPTO_ofb128_encrypt(const unsigned char *in, unsigned char *out,
   size_t len, const void *key,
   unsigned char ivec[16], int *num,
   block128_f block);

void CRYPTO_cfb128_encrypt(const unsigned char *in, unsigned char *out,
   size_t len, const void *key,
   unsigned char ivec[16], int *num,
   int enc, block128_f block);
void CRYPTO_cfb128_8_encrypt(const unsigned char *in, unsigned char *out,
   size_t length, const void *key,
   unsigned char ivec[16], int *num,
   int enc, block128_f block);
void CRYPTO_cfb128_1_encrypt(const unsigned char *in, unsigned char *out,
   size_t bits, const void *key,
   unsigned char ivec[16], int *num,
   int enc, block128_f block);

size_t CRYPTO_cts128_encrypt_block(const unsigned char *in, unsigned char *out,
   size_t len, const void *key,
   unsigned char ivec[16], block128_f block);
size_t CRYPTO_cts128_encrypt(const unsigned char *in, unsigned char *out,
   size_t len, const void *key,
   unsigned char ivec[16], cbc128_f cbc);
size_t CRYPTO_cts128_decrypt_block(const unsigned char *in, unsigned char *out,
   size_t len, const void *key,
   unsigned char ivec[16], block128_f block);
size_t CRYPTO_cts128_decrypt(const unsigned char *in, unsigned char *out,
   size_t len, const void *key,
   unsigned char ivec[16], cbc128_f cbc);

size_t CRYPTO_nistcts128_encrypt_block(const unsigned char *in, unsigned char *out,
   size_t len, const void *key,
   unsigned char ivec[16], block128_f block);
size_t CRYPTO_nistcts128_encrypt(const unsigned char *in, unsigned char *out,
   size_t len, const void *key,
   unsigned char ivec[16], cbc128_f cbc);
size_t CRYPTO_nistcts128_decrypt_block(const unsigned char *in, unsigned char *out,
   size_t len, const void *key,
   unsigned char ivec[16], block128_f block);
size_t CRYPTO_nistcts128_decrypt(const unsigned char *in, unsigned char *out,
   size_t len, const void *key,
   unsigned char ivec[16], cbc128_f cbc);

typedef struct gcm128_context GCM128_CONTEXT;

GCM128_CONTEXT *CRYPTO_gcm128_new(void *key, block128_f block);
void CRYPTO_gcm128_init(GCM128_CONTEXT *ctx,void *key,block128_f block);
void CRYPTO_gcm128_setiv(GCM128_CONTEXT *ctx, const unsigned char *iv,
   size_t len);
int CRYPTO_gcm128_aad(GCM128_CONTEXT *ctx, const unsigned char *aad,
   size_t len);
int CRYPTO_gcm128_encrypt(GCM128_CONTEXT *ctx,
   const unsigned char *in, unsigned char *out,
   size_t len);
int CRYPTO_gcm128_decrypt(GCM128_CONTEXT *ctx,
   const unsigned char *in, unsigned char *out,
   size_t len);
int CRYPTO_gcm128_encrypt_ctr32(GCM128_CONTEXT *ctx,
   const unsigned char *in, unsigned char *out,
   size_t len, ctr128_f stream);
int CRYPTO_gcm128_decrypt_ctr32(GCM128_CONTEXT *ctx,
   const unsigned char *in, unsigned char *out,
   size_t len, ctr128_f stream);
int CRYPTO_gcm128_finish(GCM128_CONTEXT *ctx,const unsigned char *tag,
   size_t len);
void CRYPTO_gcm128_tag(GCM128_CONTEXT *ctx, unsigned char *tag, size_t len);
void CRYPTO_gcm128_release(GCM128_CONTEXT *ctx);

typedef struct ccm128_context CCM128_CONTEXT;

void CRYPTO_ccm128_init(CCM128_CONTEXT *ctx,
 unsigned int M, unsigned int L, void *key,block128_f block);
int CRYPTO_ccm128_setiv(CCM128_CONTEXT *ctx,
 const unsigned char *nonce, size_t nlen, size_t mlen);
void CRYPTO_ccm128_aad(CCM128_CONTEXT *ctx,
 const unsigned char *aad, size_t alen);
int CRYPTO_ccm128_encrypt(CCM128_CONTEXT *ctx,
 const unsigned char *inp, unsigned char *out, size_t len);
int CRYPTO_ccm128_decrypt(CCM128_CONTEXT *ctx,
 const unsigned char *inp, unsigned char *out, size_t len);
int CRYPTO_ccm128_encrypt_ccm64(CCM128_CONTEXT *ctx,
 const unsigned char *inp, unsigned char *out, size_t len,
 ccm128_f stream);
int CRYPTO_ccm128_decrypt_ccm64(CCM128_CONTEXT *ctx,
 const unsigned char *inp, unsigned char *out, size_t len,
 ccm128_f stream);
size_t CRYPTO_ccm128_tag(CCM128_CONTEXT *ctx, unsigned char *tag, size_t len);

typedef struct xts128_context XTS128_CONTEXT;

int CRYPTO_xts128_encrypt(const XTS128_CONTEXT *ctx, const unsigned char iv[16],
 const unsigned char *inp, unsigned char *out, size_t len, int enc);








struct v3_ext_method;
struct v3_ext_ctx;



typedef void * (*X509V3_EXT_NEW)(void);
typedef void (*X509V3_EXT_FREE)(void *);
typedef void * (*X509V3_EXT_D2I)(void *, const unsigned char ** , long);
typedef int (*X509V3_EXT_I2D)(void *, unsigned char **);
typedef struct stack_st_CONF_VALUE *
  (*X509V3_EXT_I2V)(const struct v3_ext_method *method, void *ext,
      struct stack_st_CONF_VALUE *extlist);
typedef void * (*X509V3_EXT_V2I)(const struct v3_ext_method *method,
     struct v3_ext_ctx *ctx,
     struct stack_st_CONF_VALUE *values);
typedef char * (*X509V3_EXT_I2S)(const struct v3_ext_method *method, void *ext);
typedef void * (*X509V3_EXT_S2I)(const struct v3_ext_method *method,
     struct v3_ext_ctx *ctx, const char *str);
typedef int (*X509V3_EXT_I2R)(const struct v3_ext_method *method, void *ext,
         BIO *out, int indent);
typedef void * (*X509V3_EXT_R2I)(const struct v3_ext_method *method,
     struct v3_ext_ctx *ctx, const char *str);



struct v3_ext_method {
int ext_nid;
int ext_flags;

ASN1_ITEM_EXP *it;

X509V3_EXT_NEW ext_new;
X509V3_EXT_FREE ext_free;
X509V3_EXT_D2I d2i;
X509V3_EXT_I2D i2d;


X509V3_EXT_I2S i2s;
X509V3_EXT_S2I s2i;


X509V3_EXT_I2V i2v;
X509V3_EXT_V2I v2i;


X509V3_EXT_I2R i2r;
X509V3_EXT_R2I r2i;

void *usr_data;
};

typedef struct X509V3_CONF_METHOD_st {
char * (*get_string)(void *db, char *section, char *value);
struct stack_st_CONF_VALUE * (*get_section)(void *db, char *section);
void (*free_string)(void *db, char * string);
void (*free_section)(void *db, struct stack_st_CONF_VALUE *section);
} X509V3_CONF_METHOD;


struct v3_ext_ctx {

int flags;
X509 *issuer_cert;
X509 *subject_cert;
X509_REQ *subject_req;
X509_CRL *crl;
X509V3_CONF_METHOD *db_meth;
void *db;

};

typedef struct v3_ext_method X509V3_EXT_METHOD;

struct stack_st_X509V3_EXT_METHOD { _STACK stack; };






typedef BIT_STRING_BITNAME ENUMERATED_NAMES;

typedef struct BASIC_CONSTRAINTS_st {
int ca;
ASN1_INTEGER *pathlen;
} BASIC_CONSTRAINTS;


typedef struct PKEY_USAGE_PERIOD_st {
ASN1_GENERALIZEDTIME *notBefore;
ASN1_GENERALIZEDTIME *notAfter;
} PKEY_USAGE_PERIOD;

typedef struct otherName_st {
ASN1_OBJECT *type_id;
ASN1_TYPE *value;
} OTHERNAME;

typedef struct EDIPartyName_st {
 ASN1_STRING *nameAssigner;
 ASN1_STRING *partyName;
} EDIPARTYNAME;

typedef struct GENERAL_NAME_st {

int type;
union {
 char *ptr;
 OTHERNAME *otherName;
 ASN1_IA5STRING *rfc822Name;
 ASN1_IA5STRING *dNSName;
 ASN1_TYPE *x400Address;
 X509_NAME *directoryName;
 EDIPARTYNAME *ediPartyName;
 ASN1_IA5STRING *uniformResourceIdentifier;
 ASN1_OCTET_STRING *iPAddress;
 ASN1_OBJECT *registeredID;


 ASN1_OCTET_STRING *ip;
 X509_NAME *dirn;
 ASN1_IA5STRING *ia5;
 ASN1_OBJECT *rid;
 ASN1_TYPE *other;
} d;
} GENERAL_NAME;

typedef struct stack_st_GENERAL_NAME GENERAL_NAMES;

typedef struct ACCESS_DESCRIPTION_st {
 ASN1_OBJECT *method;
 GENERAL_NAME *location;
} ACCESS_DESCRIPTION;

typedef struct stack_st_ACCESS_DESCRIPTION AUTHORITY_INFO_ACCESS;

typedef struct stack_st_ASN1_OBJECT EXTENDED_KEY_USAGE;

struct stack_st_GENERAL_NAME { _STACK stack; };


struct stack_st_ACCESS_DESCRIPTION { _STACK stack; };


typedef struct DIST_POINT_NAME_st {
int type;
union {
 GENERAL_NAMES *fullname;
 struct stack_st_X509_NAME_ENTRY *relativename;
} name;

X509_NAME *dpname;
} DIST_POINT_NAME;

struct DIST_POINT_st {
DIST_POINT_NAME *distpoint;
ASN1_BIT_STRING *reasons;
GENERAL_NAMES *CRLissuer;
int dp_reasons;
};

typedef struct stack_st_DIST_POINT CRL_DIST_POINTS;

struct stack_st_DIST_POINT { _STACK stack; };


struct AUTHORITY_KEYID_st {
ASN1_OCTET_STRING *keyid;
GENERAL_NAMES *issuer;
ASN1_INTEGER *serial;
};



typedef struct SXNET_ID_st {
 ASN1_INTEGER *zone;
 ASN1_OCTET_STRING *user;
} SXNETID;

struct stack_st_SXNETID { _STACK stack; };


typedef struct SXNET_st {
 ASN1_INTEGER *version;
 struct stack_st_SXNETID *ids;
} SXNET;

typedef struct NOTICEREF_st {
 ASN1_STRING *organization;
 struct stack_st_ASN1_INTEGER *noticenos;
} NOTICEREF;

typedef struct USERNOTICE_st {
 NOTICEREF *noticeref;
 ASN1_STRING *exptext;
} USERNOTICE;

typedef struct POLICYQUALINFO_st {
 ASN1_OBJECT *pqualid;
 union {
  ASN1_IA5STRING *cpsuri;
  USERNOTICE *usernotice;
  ASN1_TYPE *other;
 } d;
} POLICYQUALINFO;

struct stack_st_POLICYQUALINFO { _STACK stack; };


typedef struct POLICYINFO_st {
 ASN1_OBJECT *policyid;
 struct stack_st_POLICYQUALINFO *qualifiers;
} POLICYINFO;

typedef struct stack_st_POLICYINFO CERTIFICATEPOLICIES;

struct stack_st_POLICYINFO { _STACK stack; };


typedef struct POLICY_MAPPING_st {
 ASN1_OBJECT *issuerDomainPolicy;
 ASN1_OBJECT *subjectDomainPolicy;
} POLICY_MAPPING;

struct stack_st_POLICY_MAPPING { _STACK stack; };

typedef struct stack_st_POLICY_MAPPING POLICY_MAPPINGS;

typedef struct GENERAL_SUBTREE_st {
 GENERAL_NAME *base;
 ASN1_INTEGER *minimum;
 ASN1_INTEGER *maximum;
} GENERAL_SUBTREE;

struct stack_st_GENERAL_SUBTREE { _STACK stack; };

struct NAME_CONSTRAINTS_st {
 struct stack_st_GENERAL_SUBTREE *permittedSubtrees;
 struct stack_st_GENERAL_SUBTREE *excludedSubtrees;
};

typedef struct POLICY_CONSTRAINTS_st {
 ASN1_INTEGER *requireExplicitPolicy;
 ASN1_INTEGER *inhibitPolicyMapping;
} POLICY_CONSTRAINTS;


typedef struct PROXY_POLICY_st
 {
 ASN1_OBJECT *policyLanguage;
 ASN1_OCTET_STRING *policy;
 } PROXY_POLICY;

typedef struct PROXY_CERT_INFO_EXTENSION_st
 {
 ASN1_INTEGER *pcPathLengthConstraint;
 PROXY_POLICY *proxyPolicy;
 } PROXY_CERT_INFO_EXTENSION;

PROXY_POLICY *PROXY_POLICY_new(void); void PROXY_POLICY_free(PROXY_POLICY *a); PROXY_POLICY *d2i_PROXY_POLICY(PROXY_POLICY **a, const unsigned char **in, long len); int i2d_PROXY_POLICY(PROXY_POLICY *a, unsigned char **out); extern const ASN1_ITEM PROXY_POLICY_it;
PROXY_CERT_INFO_EXTENSION *PROXY_CERT_INFO_EXTENSION_new(void); void PROXY_CERT_INFO_EXTENSION_free(PROXY_CERT_INFO_EXTENSION *a); PROXY_CERT_INFO_EXTENSION *d2i_PROXY_CERT_INFO_EXTENSION(PROXY_CERT_INFO_EXTENSION **a, const unsigned char **in, long len); int i2d_PROXY_CERT_INFO_EXTENSION(PROXY_CERT_INFO_EXTENSION *a, unsigned char **out); extern const ASN1_ITEM PROXY_CERT_INFO_EXTENSION_it;

struct ISSUING_DIST_POINT_st
 {
 DIST_POINT_NAME *distpoint;
 int onlyuser;
 int onlyCA;
 ASN1_BIT_STRING *onlysomereasons;
 int indirectCRL;
 int onlyattr;
 };

typedef struct x509_purpose_st {
 int purpose;
 int trust;
 int flags;
 int (*check_purpose)(const struct x509_purpose_st *,
    const X509 *, int);
 char *name;
 char *sname;
 void *usr_data;
} X509_PURPOSE;

struct stack_st_X509_PURPOSE { _STACK stack; };

BASIC_CONSTRAINTS *BASIC_CONSTRAINTS_new(void); void BASIC_CONSTRAINTS_free(BASIC_CONSTRAINTS *a); BASIC_CONSTRAINTS *d2i_BASIC_CONSTRAINTS(BASIC_CONSTRAINTS **a, const unsigned char **in, long len); int i2d_BASIC_CONSTRAINTS(BASIC_CONSTRAINTS *a, unsigned char **out); extern const ASN1_ITEM BASIC_CONSTRAINTS_it;

SXNET *SXNET_new(void); void SXNET_free(SXNET *a); SXNET *d2i_SXNET(SXNET **a, const unsigned char **in, long len); int i2d_SXNET(SXNET *a, unsigned char **out); extern const ASN1_ITEM SXNET_it;
SXNETID *SXNETID_new(void); void SXNETID_free(SXNETID *a); SXNETID *d2i_SXNETID(SXNETID **a, const unsigned char **in, long len); int i2d_SXNETID(SXNETID *a, unsigned char **out); extern const ASN1_ITEM SXNETID_it;

int SXNET_add_id_asc(SXNET **psx, char *zone, char *user, int userlen);
int SXNET_add_id_ulong(SXNET **psx, unsigned long lzone, char *user, int userlen);
int SXNET_add_id_INTEGER(SXNET **psx, ASN1_INTEGER *izone, char *user, int userlen);

ASN1_OCTET_STRING *SXNET_get_id_asc(SXNET *sx, char *zone);
ASN1_OCTET_STRING *SXNET_get_id_ulong(SXNET *sx, unsigned long lzone);
ASN1_OCTET_STRING *SXNET_get_id_INTEGER(SXNET *sx, ASN1_INTEGER *zone);

AUTHORITY_KEYID *AUTHORITY_KEYID_new(void); void AUTHORITY_KEYID_free(AUTHORITY_KEYID *a); AUTHORITY_KEYID *d2i_AUTHORITY_KEYID(AUTHORITY_KEYID **a, const unsigned char **in, long len); int i2d_AUTHORITY_KEYID(AUTHORITY_KEYID *a, unsigned char **out); extern const ASN1_ITEM AUTHORITY_KEYID_it;

PKEY_USAGE_PERIOD *PKEY_USAGE_PERIOD_new(void); void PKEY_USAGE_PERIOD_free(PKEY_USAGE_PERIOD *a); PKEY_USAGE_PERIOD *d2i_PKEY_USAGE_PERIOD(PKEY_USAGE_PERIOD **a, const unsigned char **in, long len); int i2d_PKEY_USAGE_PERIOD(PKEY_USAGE_PERIOD *a, unsigned char **out); extern const ASN1_ITEM PKEY_USAGE_PERIOD_it;

GENERAL_NAME *GENERAL_NAME_new(void); void GENERAL_NAME_free(GENERAL_NAME *a); GENERAL_NAME *d2i_GENERAL_NAME(GENERAL_NAME **a, const unsigned char **in, long len); int i2d_GENERAL_NAME(GENERAL_NAME *a, unsigned char **out); extern const ASN1_ITEM GENERAL_NAME_it;
GENERAL_NAME *GENERAL_NAME_dup(GENERAL_NAME *a);
int GENERAL_NAME_cmp(GENERAL_NAME *a, GENERAL_NAME *b);



ASN1_BIT_STRING *v2i_ASN1_BIT_STRING(X509V3_EXT_METHOD *method,
    X509V3_CTX *ctx, struct stack_st_CONF_VALUE *nval);
struct stack_st_CONF_VALUE *i2v_ASN1_BIT_STRING(X509V3_EXT_METHOD *method,
    ASN1_BIT_STRING *bits,
    struct stack_st_CONF_VALUE *extlist);

struct stack_st_CONF_VALUE *i2v_GENERAL_NAME(X509V3_EXT_METHOD *method, GENERAL_NAME *gen, struct stack_st_CONF_VALUE *ret);
int GENERAL_NAME_print(BIO *out, GENERAL_NAME *gen);

GENERAL_NAMES *GENERAL_NAMES_new(void); void GENERAL_NAMES_free(GENERAL_NAMES *a); GENERAL_NAMES *d2i_GENERAL_NAMES(GENERAL_NAMES **a, const unsigned char **in, long len); int i2d_GENERAL_NAMES(GENERAL_NAMES *a, unsigned char **out); extern const ASN1_ITEM GENERAL_NAMES_it;

struct stack_st_CONF_VALUE *i2v_GENERAL_NAMES(X509V3_EXT_METHOD *method,
  GENERAL_NAMES *gen, struct stack_st_CONF_VALUE *extlist);
GENERAL_NAMES *v2i_GENERAL_NAMES(const X509V3_EXT_METHOD *method,
     X509V3_CTX *ctx, struct stack_st_CONF_VALUE *nval);

OTHERNAME *OTHERNAME_new(void); void OTHERNAME_free(OTHERNAME *a); OTHERNAME *d2i_OTHERNAME(OTHERNAME **a, const unsigned char **in, long len); int i2d_OTHERNAME(OTHERNAME *a, unsigned char **out); extern const ASN1_ITEM OTHERNAME_it;
EDIPARTYNAME *EDIPARTYNAME_new(void); void EDIPARTYNAME_free(EDIPARTYNAME *a); EDIPARTYNAME *d2i_EDIPARTYNAME(EDIPARTYNAME **a, const unsigned char **in, long len); int i2d_EDIPARTYNAME(EDIPARTYNAME *a, unsigned char **out); extern const ASN1_ITEM EDIPARTYNAME_it;
int OTHERNAME_cmp(OTHERNAME *a, OTHERNAME *b);
void GENERAL_NAME_set0_value(GENERAL_NAME *a, int type, void *value);
void *GENERAL_NAME_get0_value(GENERAL_NAME *a, int *ptype);
int GENERAL_NAME_set0_othername(GENERAL_NAME *gen,
    ASN1_OBJECT *oid, ASN1_TYPE *value);
int GENERAL_NAME_get0_otherName(GENERAL_NAME *gen,
    ASN1_OBJECT **poid, ASN1_TYPE **pvalue);

char *i2s_ASN1_OCTET_STRING(X509V3_EXT_METHOD *method, ASN1_OCTET_STRING *ia5);
ASN1_OCTET_STRING *s2i_ASN1_OCTET_STRING(X509V3_EXT_METHOD *method, X509V3_CTX *ctx, char *str);

EXTENDED_KEY_USAGE *EXTENDED_KEY_USAGE_new(void); void EXTENDED_KEY_USAGE_free(EXTENDED_KEY_USAGE *a); EXTENDED_KEY_USAGE *d2i_EXTENDED_KEY_USAGE(EXTENDED_KEY_USAGE **a, const unsigned char **in, long len); int i2d_EXTENDED_KEY_USAGE(EXTENDED_KEY_USAGE *a, unsigned char **out); extern const ASN1_ITEM EXTENDED_KEY_USAGE_it;
int i2a_ACCESS_DESCRIPTION(BIO *bp, ACCESS_DESCRIPTION* a);

CERTIFICATEPOLICIES *CERTIFICATEPOLICIES_new(void); void CERTIFICATEPOLICIES_free(CERTIFICATEPOLICIES *a); CERTIFICATEPOLICIES *d2i_CERTIFICATEPOLICIES(CERTIFICATEPOLICIES **a, const unsigned char **in, long len); int i2d_CERTIFICATEPOLICIES(CERTIFICATEPOLICIES *a, unsigned char **out); extern const ASN1_ITEM CERTIFICATEPOLICIES_it;
POLICYINFO *POLICYINFO_new(void); void POLICYINFO_free(POLICYINFO *a); POLICYINFO *d2i_POLICYINFO(POLICYINFO **a, const unsigned char **in, long len); int i2d_POLICYINFO(POLICYINFO *a, unsigned char **out); extern const ASN1_ITEM POLICYINFO_it;
POLICYQUALINFO *POLICYQUALINFO_new(void); void POLICYQUALINFO_free(POLICYQUALINFO *a); POLICYQUALINFO *d2i_POLICYQUALINFO(POLICYQUALINFO **a, const unsigned char **in, long len); int i2d_POLICYQUALINFO(POLICYQUALINFO *a, unsigned char **out); extern const ASN1_ITEM POLICYQUALINFO_it;
USERNOTICE *USERNOTICE_new(void); void USERNOTICE_free(USERNOTICE *a); USERNOTICE *d2i_USERNOTICE(USERNOTICE **a, const unsigned char **in, long len); int i2d_USERNOTICE(USERNOTICE *a, unsigned char **out); extern const ASN1_ITEM USERNOTICE_it;
NOTICEREF *NOTICEREF_new(void); void NOTICEREF_free(NOTICEREF *a); NOTICEREF *d2i_NOTICEREF(NOTICEREF **a, const unsigned char **in, long len); int i2d_NOTICEREF(NOTICEREF *a, unsigned char **out); extern const ASN1_ITEM NOTICEREF_it;

CRL_DIST_POINTS *CRL_DIST_POINTS_new(void); void CRL_DIST_POINTS_free(CRL_DIST_POINTS *a); CRL_DIST_POINTS *d2i_CRL_DIST_POINTS(CRL_DIST_POINTS **a, const unsigned char **in, long len); int i2d_CRL_DIST_POINTS(CRL_DIST_POINTS *a, unsigned char **out); extern const ASN1_ITEM CRL_DIST_POINTS_it;
DIST_POINT *DIST_POINT_new(void); void DIST_POINT_free(DIST_POINT *a); DIST_POINT *d2i_DIST_POINT(DIST_POINT **a, const unsigned char **in, long len); int i2d_DIST_POINT(DIST_POINT *a, unsigned char **out); extern const ASN1_ITEM DIST_POINT_it;
DIST_POINT_NAME *DIST_POINT_NAME_new(void); void DIST_POINT_NAME_free(DIST_POINT_NAME *a); DIST_POINT_NAME *d2i_DIST_POINT_NAME(DIST_POINT_NAME **a, const unsigned char **in, long len); int i2d_DIST_POINT_NAME(DIST_POINT_NAME *a, unsigned char **out); extern const ASN1_ITEM DIST_POINT_NAME_it;
ISSUING_DIST_POINT *ISSUING_DIST_POINT_new(void); void ISSUING_DIST_POINT_free(ISSUING_DIST_POINT *a); ISSUING_DIST_POINT *d2i_ISSUING_DIST_POINT(ISSUING_DIST_POINT **a, const unsigned char **in, long len); int i2d_ISSUING_DIST_POINT(ISSUING_DIST_POINT *a, unsigned char **out); extern const ASN1_ITEM ISSUING_DIST_POINT_it;

int DIST_POINT_set_dpname(DIST_POINT_NAME *dpn, X509_NAME *iname);

int NAME_CONSTRAINTS_check(X509 *x, NAME_CONSTRAINTS *nc);

ACCESS_DESCRIPTION *ACCESS_DESCRIPTION_new(void); void ACCESS_DESCRIPTION_free(ACCESS_DESCRIPTION *a); ACCESS_DESCRIPTION *d2i_ACCESS_DESCRIPTION(ACCESS_DESCRIPTION **a, const unsigned char **in, long len); int i2d_ACCESS_DESCRIPTION(ACCESS_DESCRIPTION *a, unsigned char **out); extern const ASN1_ITEM ACCESS_DESCRIPTION_it;
AUTHORITY_INFO_ACCESS *AUTHORITY_INFO_ACCESS_new(void); void AUTHORITY_INFO_ACCESS_free(AUTHORITY_INFO_ACCESS *a); AUTHORITY_INFO_ACCESS *d2i_AUTHORITY_INFO_ACCESS(AUTHORITY_INFO_ACCESS **a, const unsigned char **in, long len); int i2d_AUTHORITY_INFO_ACCESS(AUTHORITY_INFO_ACCESS *a, unsigned char **out); extern const ASN1_ITEM AUTHORITY_INFO_ACCESS_it;

extern const ASN1_ITEM POLICY_MAPPING_it;
POLICY_MAPPING *POLICY_MAPPING_new(void); void POLICY_MAPPING_free(POLICY_MAPPING *a);
extern const ASN1_ITEM POLICY_MAPPINGS_it;

extern const ASN1_ITEM GENERAL_SUBTREE_it;
GENERAL_SUBTREE *GENERAL_SUBTREE_new(void); void GENERAL_SUBTREE_free(GENERAL_SUBTREE *a);

extern const ASN1_ITEM NAME_CONSTRAINTS_it;
NAME_CONSTRAINTS *NAME_CONSTRAINTS_new(void); void NAME_CONSTRAINTS_free(NAME_CONSTRAINTS *a);

POLICY_CONSTRAINTS *POLICY_CONSTRAINTS_new(void); void POLICY_CONSTRAINTS_free(POLICY_CONSTRAINTS *a);
extern const ASN1_ITEM POLICY_CONSTRAINTS_it;

GENERAL_NAME *a2i_GENERAL_NAME(GENERAL_NAME *out,
          const X509V3_EXT_METHOD *method, X509V3_CTX *ctx,
          int gen_type, char *value, int is_nc);


GENERAL_NAME *v2i_GENERAL_NAME(const X509V3_EXT_METHOD *method, X509V3_CTX *ctx,
          CONF_VALUE *cnf);
GENERAL_NAME *v2i_GENERAL_NAME_ex(GENERAL_NAME *out,
      const X509V3_EXT_METHOD *method,
      X509V3_CTX *ctx, CONF_VALUE *cnf, int is_nc);
void X509V3_conf_free(CONF_VALUE *val);

X509_EXTENSION *X509V3_EXT_nconf_nid(CONF *conf, X509V3_CTX *ctx, int ext_nid, char *value);
X509_EXTENSION *X509V3_EXT_nconf(CONF *conf, X509V3_CTX *ctx, char *name, char *value);
int X509V3_EXT_add_nconf_sk(CONF *conf, X509V3_CTX *ctx, char *section, struct stack_st_X509_EXTENSION **sk);
int X509V3_EXT_add_nconf(CONF *conf, X509V3_CTX *ctx, char *section, X509 *cert);
int X509V3_EXT_REQ_add_nconf(CONF *conf, X509V3_CTX *ctx, char *section, X509_REQ *req);
int X509V3_EXT_CRL_add_nconf(CONF *conf, X509V3_CTX *ctx, char *section, X509_CRL *crl);

X509_EXTENSION *X509V3_EXT_conf_nid(struct lhash_st_CONF_VALUE *conf, X509V3_CTX *ctx,
        int ext_nid, char *value);
X509_EXTENSION *X509V3_EXT_conf(struct lhash_st_CONF_VALUE *conf, X509V3_CTX *ctx,
    char *name, char *value);
int X509V3_EXT_add_conf(struct lhash_st_CONF_VALUE *conf, X509V3_CTX *ctx,
   char *section, X509 *cert);
int X509V3_EXT_REQ_add_conf(struct lhash_st_CONF_VALUE *conf, X509V3_CTX *ctx,
       char *section, X509_REQ *req);
int X509V3_EXT_CRL_add_conf(struct lhash_st_CONF_VALUE *conf, X509V3_CTX *ctx,
       char *section, X509_CRL *crl);

int X509V3_add_value_bool_nf(char *name, int asn1_bool,
        struct stack_st_CONF_VALUE **extlist);
int X509V3_get_value_bool(CONF_VALUE *value, int *asn1_bool);
int X509V3_get_value_int(CONF_VALUE *value, ASN1_INTEGER **aint);
void X509V3_set_nconf(X509V3_CTX *ctx, CONF *conf);
void X509V3_set_conf_lhash(X509V3_CTX *ctx, struct lhash_st_CONF_VALUE *lhash);


char * X509V3_get_string(X509V3_CTX *ctx, char *name, char *section);
struct stack_st_CONF_VALUE * X509V3_get_section(X509V3_CTX *ctx, char *section);
void X509V3_string_free(X509V3_CTX *ctx, char *str);
void X509V3_section_free( X509V3_CTX *ctx, struct stack_st_CONF_VALUE *section);
void X509V3_set_ctx(X509V3_CTX *ctx, X509 *issuer, X509 *subject,
     X509_REQ *req, X509_CRL *crl, int flags);

int X509V3_add_value(const char *name, const char *value,
      struct stack_st_CONF_VALUE **extlist);
int X509V3_add_value_uchar(const char *name, const unsigned char *value,
      struct stack_st_CONF_VALUE **extlist);
int X509V3_add_value_bool(const char *name, int asn1_bool,
      struct stack_st_CONF_VALUE **extlist);
int X509V3_add_value_int(const char *name, ASN1_INTEGER *aint,
      struct stack_st_CONF_VALUE **extlist);
char * i2s_ASN1_INTEGER(X509V3_EXT_METHOD *meth, ASN1_INTEGER *aint);
ASN1_INTEGER * s2i_ASN1_INTEGER(X509V3_EXT_METHOD *meth, char *value);
char * i2s_ASN1_ENUMERATED(X509V3_EXT_METHOD *meth, ASN1_ENUMERATED *aint);
char * i2s_ASN1_ENUMERATED_TABLE(X509V3_EXT_METHOD *meth, ASN1_ENUMERATED *aint);
int X509V3_EXT_add(X509V3_EXT_METHOD *ext);
int X509V3_EXT_add_list(X509V3_EXT_METHOD *extlist);
int X509V3_EXT_add_alias(int nid_to, int nid_from);
void X509V3_EXT_cleanup(void);

const X509V3_EXT_METHOD *X509V3_EXT_get(X509_EXTENSION *ext);
const X509V3_EXT_METHOD *X509V3_EXT_get_nid(int nid);
int X509V3_add_standard_extensions(void);
struct stack_st_CONF_VALUE *X509V3_parse_list(const char *line);
void *X509V3_EXT_d2i(X509_EXTENSION *ext);
void *X509V3_get_d2i(struct stack_st_X509_EXTENSION *x, int nid, int *crit, int *idx);


X509_EXTENSION *X509V3_EXT_i2d(int ext_nid, int crit, void *ext_struc);
int X509V3_add1_i2d(struct stack_st_X509_EXTENSION **x, int nid, void *value, int crit, unsigned long flags);

char *hex_to_string(const unsigned char *buffer, long len);
unsigned char *string_to_hex(const char *str, long *len);
int name_cmp(const char *name, const char *cmp);

void X509V3_EXT_val_prn(BIO *out, struct stack_st_CONF_VALUE *val, int indent,
         int ml);
int X509V3_EXT_print(BIO *out, X509_EXTENSION *ext, unsigned long flag, int indent);
int X509V3_EXT_print_fp(FILE *out, X509_EXTENSION *ext, int flag, int indent);

int X509V3_extensions_print(BIO *out, char *title, struct stack_st_X509_EXTENSION *exts, unsigned long flag, int indent);

int X509_check_ca(X509 *x);
int X509_check_purpose(X509 *x, int id, int ca);
int X509_supported_extension(X509_EXTENSION *ex);
int X509_PURPOSE_set(int *p, int purpose);
int X509_check_issued(X509 *issuer, X509 *subject);
int X509_check_akid(X509 *issuer, AUTHORITY_KEYID *akid);
int X509_PURPOSE_get_count(void);
X509_PURPOSE * X509_PURPOSE_get0(int idx);
int X509_PURPOSE_get_by_sname(char *sname);
int X509_PURPOSE_get_by_id(int id);
int X509_PURPOSE_add(int id, int trust, int flags,
   int (*ck)(const X509_PURPOSE *, const X509 *, int),
    char *name, char *sname, void *arg);
char *X509_PURPOSE_get0_name(X509_PURPOSE *xp);
char *X509_PURPOSE_get0_sname(X509_PURPOSE *xp);
int X509_PURPOSE_get_trust(X509_PURPOSE *xp);
void X509_PURPOSE_cleanup(void);
int X509_PURPOSE_get_id(X509_PURPOSE *);

struct stack_st_OPENSSL_STRING *X509_get1_email(X509 *x);
struct stack_st_OPENSSL_STRING *X509_REQ_get1_email(X509_REQ *x);
void X509_email_free(struct stack_st_OPENSSL_STRING *sk);
struct stack_st_OPENSSL_STRING *X509_get1_ocsp(X509 *x);

ASN1_OCTET_STRING *a2i_IPADDRESS(const char *ipasc);
ASN1_OCTET_STRING *a2i_IPADDRESS_NC(const char *ipasc);
int a2i_ipadd(unsigned char *ipout, const char *ipasc);
int X509V3_NAME_from_section(X509_NAME *nm, struct stack_st_CONF_VALUE*dn_sk,
      unsigned long chtype);

void X509_POLICY_NODE_print(BIO *out, X509_POLICY_NODE *node, int indent);
struct stack_st_X509_POLICY_NODE { _STACK stack; };

void ERR_load_X509V3_strings(void);


typedef struct ocsp_cert_id_st
 {
 X509_ALGOR *hashAlgorithm;
 ASN1_OCTET_STRING *issuerNameHash;
 ASN1_OCTET_STRING *issuerKeyHash;
 ASN1_INTEGER *serialNumber;
 } OCSP_CERTID;

struct stack_st_OCSP_CERTID { _STACK stack; };





typedef struct ocsp_one_request_st
 {
 OCSP_CERTID *reqCert;
 struct stack_st_X509_EXTENSION *singleRequestExtensions;
 } OCSP_ONEREQ;

struct stack_st_OCSP_ONEREQ { _STACK stack; };


typedef struct ocsp_req_info_st
 {
 ASN1_INTEGER *version;
 GENERAL_NAME *requestorName;
 struct stack_st_OCSP_ONEREQ *requestList;
 struct stack_st_X509_EXTENSION *requestExtensions;
 } OCSP_REQINFO;






typedef struct ocsp_signature_st
 {
 X509_ALGOR *signatureAlgorithm;
 ASN1_BIT_STRING *signature;
 struct stack_st_X509 *certs;
 } OCSP_SIGNATURE;





typedef struct ocsp_request_st
 {
 OCSP_REQINFO *tbsRequest;
 OCSP_SIGNATURE *optionalSignature;
 } OCSP_REQUEST;

typedef struct ocsp_resp_bytes_st
 {
 ASN1_OBJECT *responseType;
 ASN1_OCTET_STRING *response;
 } OCSP_RESPBYTES;





struct ocsp_response_st
 {
 ASN1_ENUMERATED *responseStatus;
 OCSP_RESPBYTES *responseBytes;
 };







struct ocsp_responder_id_st
 {
 int type;
 union {
  X509_NAME* byName;
         ASN1_OCTET_STRING *byKey;
  } value;
 };

struct stack_st_OCSP_RESPID { _STACK stack; };
OCSP_RESPID *OCSP_RESPID_new(void); void OCSP_RESPID_free(OCSP_RESPID *a); OCSP_RESPID *d2i_OCSP_RESPID(OCSP_RESPID **a, const unsigned char **in, long len); int i2d_OCSP_RESPID(OCSP_RESPID *a, unsigned char **out); extern const ASN1_ITEM OCSP_RESPID_it;

typedef struct ocsp_revoked_info_st
 {
 ASN1_GENERALIZEDTIME *revocationTime;
 ASN1_ENUMERATED *revocationReason;
 } OCSP_REVOKEDINFO;

typedef struct ocsp_cert_status_st
 {
 int type;
 union {
  ASN1_NULL *good;
  OCSP_REVOKEDINFO *revoked;
  ASN1_NULL *unknown;
  } value;
 } OCSP_CERTSTATUS;

typedef struct ocsp_single_response_st
 {
 OCSP_CERTID *certId;
 OCSP_CERTSTATUS *certStatus;
 ASN1_GENERALIZEDTIME *thisUpdate;
 ASN1_GENERALIZEDTIME *nextUpdate;
 struct stack_st_X509_EXTENSION *singleExtensions;
 } OCSP_SINGLERESP;

struct stack_st_OCSP_SINGLERESP { _STACK stack; };


typedef struct ocsp_response_data_st
 {
 ASN1_INTEGER *version;
 OCSP_RESPID *responderId;
 ASN1_GENERALIZEDTIME *producedAt;
 struct stack_st_OCSP_SINGLERESP *responses;
 struct stack_st_X509_EXTENSION *responseExtensions;
 } OCSP_RESPDATA;

typedef struct ocsp_basic_response_st
 {
 OCSP_RESPDATA *tbsResponseData;
 X509_ALGOR *signatureAlgorithm;
 ASN1_BIT_STRING *signature;
 struct stack_st_X509 *certs;
 } OCSP_BASICRESP;

typedef struct ocsp_crl_id_st
        {
 ASN1_IA5STRING *crlUrl;
 ASN1_INTEGER *crlNum;
 ASN1_GENERALIZEDTIME *crlTime;
        } OCSP_CRLID;





typedef struct ocsp_service_locator_st
        {
 X509_NAME* issuer;
 struct stack_st_ACCESS_DESCRIPTION *locator;
        } OCSP_SERVICELOC;

OCSP_CERTID *OCSP_CERTID_dup(OCSP_CERTID *id);

OCSP_RESPONSE *OCSP_sendreq_bio(BIO *b, char *path, OCSP_REQUEST *req);
OCSP_REQ_CTX *OCSP_sendreq_new(BIO *io, char *path, OCSP_REQUEST *req,
        int maxline);
int OCSP_sendreq_nbio(OCSP_RESPONSE **presp, OCSP_REQ_CTX *rctx);
void OCSP_REQ_CTX_free(OCSP_REQ_CTX *rctx);
int OCSP_REQ_CTX_set1_req(OCSP_REQ_CTX *rctx, OCSP_REQUEST *req);
int OCSP_REQ_CTX_add1_header(OCSP_REQ_CTX *rctx,
  const char *name, const char *value);

OCSP_CERTID *OCSP_cert_to_id(const EVP_MD *dgst, X509 *subject, X509 *issuer);

OCSP_CERTID *OCSP_cert_id_new(const EVP_MD *dgst,
         X509_NAME *issuerName,
         ASN1_BIT_STRING* issuerKey,
         ASN1_INTEGER *serialNumber);

OCSP_ONEREQ *OCSP_request_add0_id(OCSP_REQUEST *req, OCSP_CERTID *cid);

int OCSP_request_add1_nonce(OCSP_REQUEST *req, unsigned char *val, int len);
int OCSP_basic_add1_nonce(OCSP_BASICRESP *resp, unsigned char *val, int len);
int OCSP_check_nonce(OCSP_REQUEST *req, OCSP_BASICRESP *bs);
int OCSP_copy_nonce(OCSP_BASICRESP *resp, OCSP_REQUEST *req);

int OCSP_request_set1_name(OCSP_REQUEST *req, X509_NAME *nm);
int OCSP_request_add1_cert(OCSP_REQUEST *req, X509 *cert);

int OCSP_request_sign(OCSP_REQUEST *req,
        X509 *signer,
        EVP_PKEY *key,
        const EVP_MD *dgst,
        struct stack_st_X509 *certs,
        unsigned long flags);

int OCSP_response_status(OCSP_RESPONSE *resp);
OCSP_BASICRESP *OCSP_response_get1_basic(OCSP_RESPONSE *resp);

int OCSP_resp_count(OCSP_BASICRESP *bs);
OCSP_SINGLERESP *OCSP_resp_get0(OCSP_BASICRESP *bs, int idx);
int OCSP_resp_find(OCSP_BASICRESP *bs, OCSP_CERTID *id, int last);
int OCSP_single_get0_status(OCSP_SINGLERESP *single, int *reason,
    ASN1_GENERALIZEDTIME **revtime,
    ASN1_GENERALIZEDTIME **thisupd,
    ASN1_GENERALIZEDTIME **nextupd);
int OCSP_resp_find_status(OCSP_BASICRESP *bs, OCSP_CERTID *id, int *status,
    int *reason,
    ASN1_GENERALIZEDTIME **revtime,
    ASN1_GENERALIZEDTIME **thisupd,
    ASN1_GENERALIZEDTIME **nextupd);
int OCSP_check_validity(ASN1_GENERALIZEDTIME *thisupd,
   ASN1_GENERALIZEDTIME *nextupd,
   long sec, long maxsec);

int OCSP_request_verify(OCSP_REQUEST *req, struct stack_st_X509 *certs, X509_STORE *store, unsigned long flags);

int OCSP_parse_url(char *url, char **phost, char **pport, char **ppath, int *pssl);

int OCSP_id_issuer_cmp(OCSP_CERTID *a, OCSP_CERTID *b);
int OCSP_id_cmp(OCSP_CERTID *a, OCSP_CERTID *b);

int OCSP_request_onereq_count(OCSP_REQUEST *req);
OCSP_ONEREQ *OCSP_request_onereq_get0(OCSP_REQUEST *req, int i);
OCSP_CERTID *OCSP_onereq_get0_id(OCSP_ONEREQ *one);
int OCSP_id_get0_info(ASN1_OCTET_STRING **piNameHash, ASN1_OBJECT **pmd,
   ASN1_OCTET_STRING **pikeyHash,
   ASN1_INTEGER **pserial, OCSP_CERTID *cid);
int OCSP_request_is_signed(OCSP_REQUEST *req);
OCSP_RESPONSE *OCSP_response_create(int status, OCSP_BASICRESP *bs);
OCSP_SINGLERESP *OCSP_basic_add1_status(OCSP_BASICRESP *rsp,
      OCSP_CERTID *cid,
      int status, int reason,
      ASN1_TIME *revtime,
     ASN1_TIME *thisupd, ASN1_TIME *nextupd);
int OCSP_basic_add1_cert(OCSP_BASICRESP *resp, X509 *cert);
int OCSP_basic_sign(OCSP_BASICRESP *brsp,
   X509 *signer, EVP_PKEY *key, const EVP_MD *dgst,
   struct stack_st_X509 *certs, unsigned long flags);

X509_EXTENSION *OCSP_crlID_new(char *url, long *n, char *tim);

X509_EXTENSION *OCSP_accept_responses_new(char **oids);

X509_EXTENSION *OCSP_archive_cutoff_new(char* tim);

X509_EXTENSION *OCSP_url_svcloc_new(X509_NAME* issuer, char **urls);

int OCSP_REQUEST_get_ext_count(OCSP_REQUEST *x);
int OCSP_REQUEST_get_ext_by_NID(OCSP_REQUEST *x, int nid, int lastpos);
int OCSP_REQUEST_get_ext_by_OBJ(OCSP_REQUEST *x, ASN1_OBJECT *obj, int lastpos);
int OCSP_REQUEST_get_ext_by_critical(OCSP_REQUEST *x, int crit, int lastpos);
X509_EXTENSION *OCSP_REQUEST_get_ext(OCSP_REQUEST *x, int loc);
X509_EXTENSION *OCSP_REQUEST_delete_ext(OCSP_REQUEST *x, int loc);
void *OCSP_REQUEST_get1_ext_d2i(OCSP_REQUEST *x, int nid, int *crit, int *idx);
int OCSP_REQUEST_add1_ext_i2d(OCSP_REQUEST *x, int nid, void *value, int crit,
       unsigned long flags);
int OCSP_REQUEST_add_ext(OCSP_REQUEST *x, X509_EXTENSION *ex, int loc);

int OCSP_ONEREQ_get_ext_count(OCSP_ONEREQ *x);
int OCSP_ONEREQ_get_ext_by_NID(OCSP_ONEREQ *x, int nid, int lastpos);
int OCSP_ONEREQ_get_ext_by_OBJ(OCSP_ONEREQ *x, ASN1_OBJECT *obj, int lastpos);
int OCSP_ONEREQ_get_ext_by_critical(OCSP_ONEREQ *x, int crit, int lastpos);
X509_EXTENSION *OCSP_ONEREQ_get_ext(OCSP_ONEREQ *x, int loc);
X509_EXTENSION *OCSP_ONEREQ_delete_ext(OCSP_ONEREQ *x, int loc);
void *OCSP_ONEREQ_get1_ext_d2i(OCSP_ONEREQ *x, int nid, int *crit, int *idx);
int OCSP_ONEREQ_add1_ext_i2d(OCSP_ONEREQ *x, int nid, void *value, int crit,
       unsigned long flags);
int OCSP_ONEREQ_add_ext(OCSP_ONEREQ *x, X509_EXTENSION *ex, int loc);

int OCSP_BASICRESP_get_ext_count(OCSP_BASICRESP *x);
int OCSP_BASICRESP_get_ext_by_NID(OCSP_BASICRESP *x, int nid, int lastpos);
int OCSP_BASICRESP_get_ext_by_OBJ(OCSP_BASICRESP *x, ASN1_OBJECT *obj, int lastpos);
int OCSP_BASICRESP_get_ext_by_critical(OCSP_BASICRESP *x, int crit, int lastpos);
X509_EXTENSION *OCSP_BASICRESP_get_ext(OCSP_BASICRESP *x, int loc);
X509_EXTENSION *OCSP_BASICRESP_delete_ext(OCSP_BASICRESP *x, int loc);
void *OCSP_BASICRESP_get1_ext_d2i(OCSP_BASICRESP *x, int nid, int *crit, int *idx);
int OCSP_BASICRESP_add1_ext_i2d(OCSP_BASICRESP *x, int nid, void *value, int crit,
       unsigned long flags);
int OCSP_BASICRESP_add_ext(OCSP_BASICRESP *x, X509_EXTENSION *ex, int loc);

int OCSP_SINGLERESP_get_ext_count(OCSP_SINGLERESP *x);
int OCSP_SINGLERESP_get_ext_by_NID(OCSP_SINGLERESP *x, int nid, int lastpos);
int OCSP_SINGLERESP_get_ext_by_OBJ(OCSP_SINGLERESP *x, ASN1_OBJECT *obj, int lastpos);
int OCSP_SINGLERESP_get_ext_by_critical(OCSP_SINGLERESP *x, int crit, int lastpos);
X509_EXTENSION *OCSP_SINGLERESP_get_ext(OCSP_SINGLERESP *x, int loc);
X509_EXTENSION *OCSP_SINGLERESP_delete_ext(OCSP_SINGLERESP *x, int loc);
void *OCSP_SINGLERESP_get1_ext_d2i(OCSP_SINGLERESP *x, int nid, int *crit, int *idx);
int OCSP_SINGLERESP_add1_ext_i2d(OCSP_SINGLERESP *x, int nid, void *value, int crit,
       unsigned long flags);
int OCSP_SINGLERESP_add_ext(OCSP_SINGLERESP *x, X509_EXTENSION *ex, int loc);

OCSP_SINGLERESP *OCSP_SINGLERESP_new(void); void OCSP_SINGLERESP_free(OCSP_SINGLERESP *a); OCSP_SINGLERESP *d2i_OCSP_SINGLERESP(OCSP_SINGLERESP **a, const unsigned char **in, long len); int i2d_OCSP_SINGLERESP(OCSP_SINGLERESP *a, unsigned char **out); extern const ASN1_ITEM OCSP_SINGLERESP_it;
OCSP_CERTSTATUS *OCSP_CERTSTATUS_new(void); void OCSP_CERTSTATUS_free(OCSP_CERTSTATUS *a); OCSP_CERTSTATUS *d2i_OCSP_CERTSTATUS(OCSP_CERTSTATUS **a, const unsigned char **in, long len); int i2d_OCSP_CERTSTATUS(OCSP_CERTSTATUS *a, unsigned char **out); extern const ASN1_ITEM OCSP_CERTSTATUS_it;
OCSP_REVOKEDINFO *OCSP_REVOKEDINFO_new(void); void OCSP_REVOKEDINFO_free(OCSP_REVOKEDINFO *a); OCSP_REVOKEDINFO *d2i_OCSP_REVOKEDINFO(OCSP_REVOKEDINFO **a, const unsigned char **in, long len); int i2d_OCSP_REVOKEDINFO(OCSP_REVOKEDINFO *a, unsigned char **out); extern const ASN1_ITEM OCSP_REVOKEDINFO_it;
OCSP_BASICRESP *OCSP_BASICRESP_new(void); void OCSP_BASICRESP_free(OCSP_BASICRESP *a); OCSP_BASICRESP *d2i_OCSP_BASICRESP(OCSP_BASICRESP **a, const unsigned char **in, long len); int i2d_OCSP_BASICRESP(OCSP_BASICRESP *a, unsigned char **out); extern const ASN1_ITEM OCSP_BASICRESP_it;
OCSP_RESPDATA *OCSP_RESPDATA_new(void); void OCSP_RESPDATA_free(OCSP_RESPDATA *a); OCSP_RESPDATA *d2i_OCSP_RESPDATA(OCSP_RESPDATA **a, const unsigned char **in, long len); int i2d_OCSP_RESPDATA(OCSP_RESPDATA *a, unsigned char **out); extern const ASN1_ITEM OCSP_RESPDATA_it;
OCSP_RESPID *OCSP_RESPID_new(void); void OCSP_RESPID_free(OCSP_RESPID *a); OCSP_RESPID *d2i_OCSP_RESPID(OCSP_RESPID **a, const unsigned char **in, long len); int i2d_OCSP_RESPID(OCSP_RESPID *a, unsigned char **out); extern const ASN1_ITEM OCSP_RESPID_it;
OCSP_RESPONSE *OCSP_RESPONSE_new(void); void OCSP_RESPONSE_free(OCSP_RESPONSE *a); OCSP_RESPONSE *d2i_OCSP_RESPONSE(OCSP_RESPONSE **a, const unsigned char **in, long len); int i2d_OCSP_RESPONSE(OCSP_RESPONSE *a, unsigned char **out); extern const ASN1_ITEM OCSP_RESPONSE_it;
OCSP_RESPBYTES *OCSP_RESPBYTES_new(void); void OCSP_RESPBYTES_free(OCSP_RESPBYTES *a); OCSP_RESPBYTES *d2i_OCSP_RESPBYTES(OCSP_RESPBYTES **a, const unsigned char **in, long len); int i2d_OCSP_RESPBYTES(OCSP_RESPBYTES *a, unsigned char **out); extern const ASN1_ITEM OCSP_RESPBYTES_it;
OCSP_ONEREQ *OCSP_ONEREQ_new(void); void OCSP_ONEREQ_free(OCSP_ONEREQ *a); OCSP_ONEREQ *d2i_OCSP_ONEREQ(OCSP_ONEREQ **a, const unsigned char **in, long len); int i2d_OCSP_ONEREQ(OCSP_ONEREQ *a, unsigned char **out); extern const ASN1_ITEM OCSP_ONEREQ_it;
OCSP_CERTID *OCSP_CERTID_new(void); void OCSP_CERTID_free(OCSP_CERTID *a); OCSP_CERTID *d2i_OCSP_CERTID(OCSP_CERTID **a, const unsigned char **in, long len); int i2d_OCSP_CERTID(OCSP_CERTID *a, unsigned char **out); extern const ASN1_ITEM OCSP_CERTID_it;
OCSP_REQUEST *OCSP_REQUEST_new(void); void OCSP_REQUEST_free(OCSP_REQUEST *a); OCSP_REQUEST *d2i_OCSP_REQUEST(OCSP_REQUEST **a, const unsigned char **in, long len); int i2d_OCSP_REQUEST(OCSP_REQUEST *a, unsigned char **out); extern const ASN1_ITEM OCSP_REQUEST_it;
OCSP_SIGNATURE *OCSP_SIGNATURE_new(void); void OCSP_SIGNATURE_free(OCSP_SIGNATURE *a); OCSP_SIGNATURE *d2i_OCSP_SIGNATURE(OCSP_SIGNATURE **a, const unsigned char **in, long len); int i2d_OCSP_SIGNATURE(OCSP_SIGNATURE *a, unsigned char **out); extern const ASN1_ITEM OCSP_SIGNATURE_it;
OCSP_REQINFO *OCSP_REQINFO_new(void); void OCSP_REQINFO_free(OCSP_REQINFO *a); OCSP_REQINFO *d2i_OCSP_REQINFO(OCSP_REQINFO **a, const unsigned char **in, long len); int i2d_OCSP_REQINFO(OCSP_REQINFO *a, unsigned char **out); extern const ASN1_ITEM OCSP_REQINFO_it;
OCSP_CRLID *OCSP_CRLID_new(void); void OCSP_CRLID_free(OCSP_CRLID *a); OCSP_CRLID *d2i_OCSP_CRLID(OCSP_CRLID **a, const unsigned char **in, long len); int i2d_OCSP_CRLID(OCSP_CRLID *a, unsigned char **out); extern const ASN1_ITEM OCSP_CRLID_it;
OCSP_SERVICELOC *OCSP_SERVICELOC_new(void); void OCSP_SERVICELOC_free(OCSP_SERVICELOC *a); OCSP_SERVICELOC *d2i_OCSP_SERVICELOC(OCSP_SERVICELOC **a, const unsigned char **in, long len); int i2d_OCSP_SERVICELOC(OCSP_SERVICELOC *a, unsigned char **out); extern const ASN1_ITEM OCSP_SERVICELOC_it;

const char *OCSP_response_status_str(long s);
const char *OCSP_cert_status_str(long s);
const char *OCSP_crl_reason_str(long s);

int OCSP_REQUEST_print(BIO *bp, OCSP_REQUEST* a, unsigned long flags);
int OCSP_RESPONSE_print(BIO *bp, OCSP_RESPONSE* o, unsigned long flags);

int OCSP_basic_verify(OCSP_BASICRESP *bs, struct stack_st_X509 *certs,
    X509_STORE *st, unsigned long flags);





void ERR_load_OCSP_strings(void);





void ERR_load_PEM_strings(void);












typedef struct PEM_Encode_Seal_st
 {
 EVP_ENCODE_CTX encode;
 EVP_MD_CTX md;
 EVP_CIPHER_CTX cipher;
 } PEM_ENCODE_SEAL_CTX;







typedef struct pem_recip_st
 {
 char *name;
 X509_NAME *dn;

 int cipher;
 int key_enc;

 } PEM_USER;

typedef struct pem_ctx_st
 {
 int type;

 struct {
  int version;
  int mode;
  } proc_type;

 char *domain;

 struct {
  int cipher;


  } DEK_info;

 PEM_USER *originator;

 int num_recipient;
 PEM_USER **recipient;



 EVP_MD *md;

 int md_enc;
 int md_len;
 char *md_data;

 EVP_CIPHER *dec;
 int key_len;
 unsigned char *key;




 int data_enc;
 int data_len;
 unsigned char *data;
 } PEM_CTX;

typedef int pem_password_cb(char *buf, int size, int rwflag, void *userdata);





int PEM_get_EVP_CIPHER_INFO(char *header, EVP_CIPHER_INFO *cipher);
int PEM_do_header (EVP_CIPHER_INFO *cipher, unsigned char *data,long *len,
 pem_password_cb *callback,void *u);


int PEM_read_bio(BIO *bp, char **name, char **header,
  unsigned char **data,long *len);
int PEM_write_bio(BIO *bp,const char *name,char *hdr,unsigned char *data,
  long len);
int PEM_bytes_read_bio(unsigned char **pdata, long *plen, char **pnm, const char *name, BIO *bp,
      pem_password_cb *cb, void *u);
void * PEM_ASN1_read_bio(d2i_of_void *d2i, const char *name, BIO *bp,
     void **x, pem_password_cb *cb, void *u);
int PEM_ASN1_write_bio(i2d_of_void *i2d,const char *name,BIO *bp, void *x,
      const EVP_CIPHER *enc,unsigned char *kstr,int klen,
      pem_password_cb *cb, void *u);

struct stack_st_X509_INFO * PEM_X509_INFO_read_bio(BIO *bp, struct stack_st_X509_INFO *sk, pem_password_cb *cb, void *u);
int PEM_X509_INFO_write_bio(BIO *bp,X509_INFO *xi, EVP_CIPHER *enc,
  unsigned char *kstr, int klen, pem_password_cb *cd, void *u);


int PEM_read(FILE *fp, char **name, char **header,
  unsigned char **data,long *len);
int PEM_write(FILE *fp,char *name,char *hdr,unsigned char *data,long len);
void * PEM_ASN1_read(d2i_of_void *d2i, const char *name, FILE *fp, void **x,
        pem_password_cb *cb, void *u);
int PEM_ASN1_write(i2d_of_void *i2d,const char *name,FILE *fp,
         void *x,const EVP_CIPHER *enc,unsigned char *kstr,
         int klen,pem_password_cb *callback, void *u);
struct stack_st_X509_INFO * PEM_X509_INFO_read(FILE *fp, struct stack_st_X509_INFO *sk,
 pem_password_cb *cb, void *u);

int PEM_SealInit(PEM_ENCODE_SEAL_CTX *ctx, EVP_CIPHER *type,
  EVP_MD *md_type, unsigned char **ek, int *ekl,
  unsigned char *iv, EVP_PKEY **pubk, int npubk);
void PEM_SealUpdate(PEM_ENCODE_SEAL_CTX *ctx, unsigned char *out, int *outl,
  unsigned char *in, int inl);
int PEM_SealFinal(PEM_ENCODE_SEAL_CTX *ctx, unsigned char *sig,int *sigl,
  unsigned char *out, int *outl, EVP_PKEY *priv);

void PEM_SignInit(EVP_MD_CTX *ctx, EVP_MD *type);
void PEM_SignUpdate(EVP_MD_CTX *ctx,unsigned char *d,unsigned int cnt);
int PEM_SignFinal(EVP_MD_CTX *ctx, unsigned char *sigret,
  unsigned int *siglen, EVP_PKEY *pkey);

int PEM_def_callback(char *buf, int num, int w, void *key);
void PEM_proc_type(char *buf, int type);
void PEM_dek_info(char *buf, const char *type, int len, char *str);




X509 *PEM_read_bio_X509(BIO *bp, X509 **x, pem_password_cb *cb, void *u); X509 *PEM_read_X509(FILE *fp, X509 **x, pem_password_cb *cb, void *u); int PEM_write_bio_X509(BIO *bp, X509 *x); int PEM_write_X509(FILE *fp, X509 *x);

X509 *PEM_read_bio_X509_AUX(BIO *bp, X509 **x, pem_password_cb *cb, void *u); X509 *PEM_read_X509_AUX(FILE *fp, X509 **x, pem_password_cb *cb, void *u); int PEM_write_bio_X509_AUX(BIO *bp, X509 *x); int PEM_write_X509_AUX(FILE *fp, X509 *x);

X509_CERT_PAIR *PEM_read_bio_X509_CERT_PAIR(BIO *bp, X509_CERT_PAIR **x, pem_password_cb *cb, void *u); X509_CERT_PAIR *PEM_read_X509_CERT_PAIR(FILE *fp, X509_CERT_PAIR **x, pem_password_cb *cb, void *u); int PEM_write_bio_X509_CERT_PAIR(BIO *bp, X509_CERT_PAIR *x); int PEM_write_X509_CERT_PAIR(FILE *fp, X509_CERT_PAIR *x);

X509_REQ *PEM_read_bio_X509_REQ(BIO *bp, X509_REQ **x, pem_password_cb *cb, void *u); X509_REQ *PEM_read_X509_REQ(FILE *fp, X509_REQ **x, pem_password_cb *cb, void *u); int PEM_write_bio_X509_REQ(BIO *bp, X509_REQ *x); int PEM_write_X509_REQ(FILE *fp, X509_REQ *x);
int PEM_write_bio_X509_REQ_NEW(BIO *bp, X509_REQ *x); int PEM_write_X509_REQ_NEW(FILE *fp, X509_REQ *x);

X509_CRL *PEM_read_bio_X509_CRL(BIO *bp, X509_CRL **x, pem_password_cb *cb, void *u); X509_CRL *PEM_read_X509_CRL(FILE *fp, X509_CRL **x, pem_password_cb *cb, void *u); int PEM_write_bio_X509_CRL(BIO *bp, X509_CRL *x); int PEM_write_X509_CRL(FILE *fp, X509_CRL *x);

PKCS7 *PEM_read_bio_PKCS7(BIO *bp, PKCS7 **x, pem_password_cb *cb, void *u); PKCS7 *PEM_read_PKCS7(FILE *fp, PKCS7 **x, pem_password_cb *cb, void *u); int PEM_write_bio_PKCS7(BIO *bp, PKCS7 *x); int PEM_write_PKCS7(FILE *fp, PKCS7 *x);

NETSCAPE_CERT_SEQUENCE *PEM_read_bio_NETSCAPE_CERT_SEQUENCE(BIO *bp, NETSCAPE_CERT_SEQUENCE **x, pem_password_cb *cb, void *u); NETSCAPE_CERT_SEQUENCE *PEM_read_NETSCAPE_CERT_SEQUENCE(FILE *fp, NETSCAPE_CERT_SEQUENCE **x, pem_password_cb *cb, void *u); int PEM_write_bio_NETSCAPE_CERT_SEQUENCE(BIO *bp, NETSCAPE_CERT_SEQUENCE *x); int PEM_write_NETSCAPE_CERT_SEQUENCE(FILE *fp, NETSCAPE_CERT_SEQUENCE *x);

X509_SIG *PEM_read_bio_PKCS8(BIO *bp, X509_SIG **x, pem_password_cb *cb, void *u); X509_SIG *PEM_read_PKCS8(FILE *fp, X509_SIG **x, pem_password_cb *cb, void *u); int PEM_write_bio_PKCS8(BIO *bp, X509_SIG *x); int PEM_write_PKCS8(FILE *fp, X509_SIG *x);

PKCS8_PRIV_KEY_INFO *PEM_read_bio_PKCS8_PRIV_KEY_INFO(BIO *bp, PKCS8_PRIV_KEY_INFO **x, pem_password_cb *cb, void *u); PKCS8_PRIV_KEY_INFO *PEM_read_PKCS8_PRIV_KEY_INFO(FILE *fp, PKCS8_PRIV_KEY_INFO **x, pem_password_cb *cb, void *u); int PEM_write_bio_PKCS8_PRIV_KEY_INFO(BIO *bp, PKCS8_PRIV_KEY_INFO *x); int PEM_write_PKCS8_PRIV_KEY_INFO(FILE *fp, PKCS8_PRIV_KEY_INFO *x);



RSA *PEM_read_bio_RSAPrivateKey(BIO *bp, RSA **x, pem_password_cb *cb, void *u); RSA *PEM_read_RSAPrivateKey(FILE *fp, RSA **x, pem_password_cb *cb, void *u); int PEM_write_bio_RSAPrivateKey(BIO *bp, RSA *x, const EVP_CIPHER *enc, unsigned char *kstr, int klen, pem_password_cb *cb, void *u); int PEM_write_RSAPrivateKey(FILE *fp, RSA *x, const EVP_CIPHER *enc, unsigned char *kstr, int klen, pem_password_cb *cb, void *u);

RSA *PEM_read_bio_RSAPublicKey(BIO *bp, RSA **x, pem_password_cb *cb, void *u); RSA *PEM_read_RSAPublicKey(FILE *fp, RSA **x, pem_password_cb *cb, void *u); int PEM_write_bio_RSAPublicKey(BIO *bp, const RSA *x); int PEM_write_RSAPublicKey(FILE *fp, const RSA *x);
RSA *PEM_read_bio_RSA_PUBKEY(BIO *bp, RSA **x, pem_password_cb *cb, void *u); RSA *PEM_read_RSA_PUBKEY(FILE *fp, RSA **x, pem_password_cb *cb, void *u); int PEM_write_bio_RSA_PUBKEY(BIO *bp, RSA *x); int PEM_write_RSA_PUBKEY(FILE *fp, RSA *x);





DSA *PEM_read_bio_DSAPrivateKey(BIO *bp, DSA **x, pem_password_cb *cb, void *u); DSA *PEM_read_DSAPrivateKey(FILE *fp, DSA **x, pem_password_cb *cb, void *u); int PEM_write_bio_DSAPrivateKey(BIO *bp, DSA *x, const EVP_CIPHER *enc, unsigned char *kstr, int klen, pem_password_cb *cb, void *u); int PEM_write_DSAPrivateKey(FILE *fp, DSA *x, const EVP_CIPHER *enc, unsigned char *kstr, int klen, pem_password_cb *cb, void *u);

DSA *PEM_read_bio_DSA_PUBKEY(BIO *bp, DSA **x, pem_password_cb *cb, void *u); DSA *PEM_read_DSA_PUBKEY(FILE *fp, DSA **x, pem_password_cb *cb, void *u); int PEM_write_bio_DSA_PUBKEY(BIO *bp, DSA *x); int PEM_write_DSA_PUBKEY(FILE *fp, DSA *x);

DSA *PEM_read_bio_DSAparams(BIO *bp, DSA **x, pem_password_cb *cb, void *u); DSA *PEM_read_DSAparams(FILE *fp, DSA **x, pem_password_cb *cb, void *u); int PEM_write_bio_DSAparams(BIO *bp, const DSA *x); int PEM_write_DSAparams(FILE *fp, const DSA *x);




EC_GROUP *PEM_read_bio_ECPKParameters(BIO *bp, EC_GROUP **x, pem_password_cb *cb, void *u); EC_GROUP *PEM_read_ECPKParameters(FILE *fp, EC_GROUP **x, pem_password_cb *cb, void *u); int PEM_write_bio_ECPKParameters(BIO *bp, const EC_GROUP *x); int PEM_write_ECPKParameters(FILE *fp, const EC_GROUP *x);
EC_KEY *PEM_read_bio_ECPrivateKey(BIO *bp, EC_KEY **x, pem_password_cb *cb, void *u); EC_KEY *PEM_read_ECPrivateKey(FILE *fp, EC_KEY **x, pem_password_cb *cb, void *u); int PEM_write_bio_ECPrivateKey(BIO *bp, EC_KEY *x, const EVP_CIPHER *enc, unsigned char *kstr, int klen, pem_password_cb *cb, void *u); int PEM_write_ECPrivateKey(FILE *fp, EC_KEY *x, const EVP_CIPHER *enc, unsigned char *kstr, int klen, pem_password_cb *cb, void *u);
EC_KEY *PEM_read_bio_EC_PUBKEY(BIO *bp, EC_KEY **x, pem_password_cb *cb, void *u); EC_KEY *PEM_read_EC_PUBKEY(FILE *fp, EC_KEY **x, pem_password_cb *cb, void *u); int PEM_write_bio_EC_PUBKEY(BIO *bp, EC_KEY *x); int PEM_write_EC_PUBKEY(FILE *fp, EC_KEY *x);




DH *PEM_read_bio_DHparams(BIO *bp, DH **x, pem_password_cb *cb, void *u); DH *PEM_read_DHparams(FILE *fp, DH **x, pem_password_cb *cb, void *u); int PEM_write_bio_DHparams(BIO *bp, const DH *x); int PEM_write_DHparams(FILE *fp, const DH *x);



EVP_PKEY *PEM_read_bio_PrivateKey(BIO *bp, EVP_PKEY **x, pem_password_cb *cb, void *u); EVP_PKEY *PEM_read_PrivateKey(FILE *fp, EVP_PKEY **x, pem_password_cb *cb, void *u); int PEM_write_bio_PrivateKey(BIO *bp, EVP_PKEY *x, const EVP_CIPHER *enc, unsigned char *kstr, int klen, pem_password_cb *cb, void *u); int PEM_write_PrivateKey(FILE *fp, EVP_PKEY *x, const EVP_CIPHER *enc, unsigned char *kstr, int klen, pem_password_cb *cb, void *u);

EVP_PKEY *PEM_read_bio_PUBKEY(BIO *bp, EVP_PKEY **x, pem_password_cb *cb, void *u); EVP_PKEY *PEM_read_PUBKEY(FILE *fp, EVP_PKEY **x, pem_password_cb *cb, void *u); int PEM_write_bio_PUBKEY(BIO *bp, EVP_PKEY *x); int PEM_write_PUBKEY(FILE *fp, EVP_PKEY *x);

int PEM_write_bio_PKCS8PrivateKey_nid(BIO *bp, EVP_PKEY *x, int nid,
      char *kstr, int klen,
      pem_password_cb *cb, void *u);
int PEM_write_bio_PKCS8PrivateKey(BIO *, EVP_PKEY *, const EVP_CIPHER *,
                                  char *, int, pem_password_cb *, void *);
int i2d_PKCS8PrivateKey_bio(BIO *bp, EVP_PKEY *x, const EVP_CIPHER *enc,
      char *kstr, int klen,
      pem_password_cb *cb, void *u);
int i2d_PKCS8PrivateKey_nid_bio(BIO *bp, EVP_PKEY *x, int nid,
      char *kstr, int klen,
      pem_password_cb *cb, void *u);
EVP_PKEY *d2i_PKCS8PrivateKey_bio(BIO *bp, EVP_PKEY **x, pem_password_cb *cb, void *u);

int i2d_PKCS8PrivateKey_fp(FILE *fp, EVP_PKEY *x, const EVP_CIPHER *enc,
      char *kstr, int klen,
      pem_password_cb *cb, void *u);
int i2d_PKCS8PrivateKey_nid_fp(FILE *fp, EVP_PKEY *x, int nid,
      char *kstr, int klen,
      pem_password_cb *cb, void *u);
int PEM_write_PKCS8PrivateKey_nid(FILE *fp, EVP_PKEY *x, int nid,
      char *kstr, int klen,
      pem_password_cb *cb, void *u);

EVP_PKEY *d2i_PKCS8PrivateKey_fp(FILE *fp, EVP_PKEY **x, pem_password_cb *cb, void *u);

int PEM_write_PKCS8PrivateKey(FILE *fp,EVP_PKEY *x,const EVP_CIPHER *enc,
         char *kstr,int klen, pem_password_cb *cd, void *u);

EVP_PKEY *PEM_read_bio_Parameters(BIO *bp, EVP_PKEY **x);
int PEM_write_bio_Parameters(BIO *bp, EVP_PKEY *x);


EVP_PKEY *b2i_PrivateKey(const unsigned char **in, long length);
EVP_PKEY *b2i_PublicKey(const unsigned char **in, long length);
EVP_PKEY *b2i_PrivateKey_bio(BIO *in);
EVP_PKEY *b2i_PublicKey_bio(BIO *in);
int i2b_PrivateKey_bio(BIO *out, EVP_PKEY *pk);
int i2b_PublicKey_bio(BIO *out, EVP_PKEY *pk);

EVP_PKEY *b2i_PVK_bio(BIO *in, pem_password_cb *cb, void *u);
int i2b_PVK_bio(BIO *out, EVP_PKEY *pk, int enclevel,
  pem_password_cb *cb, void *u);







void ERR_load_PEM_strings(void);



typedef struct {
X509_SIG *dinfo;
ASN1_OCTET_STRING *salt;
ASN1_INTEGER *iter;
} PKCS12_MAC_DATA;

typedef struct {
ASN1_INTEGER *version;
PKCS12_MAC_DATA *mac;
PKCS7 *authsafes;
} PKCS12;

typedef struct {
ASN1_OBJECT *type;
union {
 struct pkcs12_bag_st *bag;
 struct pkcs8_priv_key_info_st *keybag;
 X509_SIG *shkeybag;
 struct stack_st_PKCS12_SAFEBAG *safes;
 ASN1_TYPE *other;
}value;
struct stack_st_X509_ATTRIBUTE *attrib;
} PKCS12_SAFEBAG;

struct stack_st_PKCS12_SAFEBAG { _STACK stack; };



typedef struct pkcs12_bag_st {
ASN1_OBJECT *type;
union {
 ASN1_OCTET_STRING *x509cert;
 ASN1_OCTET_STRING *x509crl;
 ASN1_OCTET_STRING *octet;
 ASN1_IA5STRING *sdsicert;
 ASN1_TYPE *other;
}value;
} PKCS12_BAGS;

PKCS12_SAFEBAG *PKCS12_x5092certbag(X509 *x509);
PKCS12_SAFEBAG *PKCS12_x509crl2certbag(X509_CRL *crl);
X509 *PKCS12_certbag2x509(PKCS12_SAFEBAG *bag);
X509_CRL *PKCS12_certbag2x509crl(PKCS12_SAFEBAG *bag);

PKCS12_SAFEBAG *PKCS12_item_pack_safebag(void *obj, const ASN1_ITEM *it, int nid1,
      int nid2);
PKCS12_SAFEBAG *PKCS12_MAKE_KEYBAG(PKCS8_PRIV_KEY_INFO *p8);
PKCS8_PRIV_KEY_INFO *PKCS8_decrypt(X509_SIG *p8, const char *pass, int passlen);
PKCS8_PRIV_KEY_INFO *PKCS12_decrypt_skey(PKCS12_SAFEBAG *bag, const char *pass,
        int passlen);
X509_SIG *PKCS8_encrypt(int pbe_nid, const EVP_CIPHER *cipher,
   const char *pass, int passlen,
   unsigned char *salt, int saltlen, int iter,
   PKCS8_PRIV_KEY_INFO *p8);
PKCS12_SAFEBAG *PKCS12_MAKE_SHKEYBAG(int pbe_nid, const char *pass,
         int passlen, unsigned char *salt,
         int saltlen, int iter,
         PKCS8_PRIV_KEY_INFO *p8);
PKCS7 *PKCS12_pack_p7data(struct stack_st_PKCS12_SAFEBAG *sk);
struct stack_st_PKCS12_SAFEBAG *PKCS12_unpack_p7data(PKCS7 *p7);
PKCS7 *PKCS12_pack_p7encdata(int pbe_nid, const char *pass, int passlen,
        unsigned char *salt, int saltlen, int iter,
        struct stack_st_PKCS12_SAFEBAG *bags);
struct stack_st_PKCS12_SAFEBAG *PKCS12_unpack_p7encdata(PKCS7 *p7, const char *pass, int passlen);

int PKCS12_pack_authsafes(PKCS12 *p12, struct stack_st_PKCS7 *safes);
struct stack_st_PKCS7 *PKCS12_unpack_authsafes(PKCS12 *p12);

int PKCS12_add_localkeyid(PKCS12_SAFEBAG *bag, unsigned char *name, int namelen);
int PKCS12_add_friendlyname_asc(PKCS12_SAFEBAG *bag, const char *name,
    int namelen);
int PKCS12_add_CSPName_asc(PKCS12_SAFEBAG *bag, const char *name,
    int namelen);
int PKCS12_add_friendlyname_uni(PKCS12_SAFEBAG *bag, const unsigned char *name,
    int namelen);
int PKCS8_add_keyusage(PKCS8_PRIV_KEY_INFO *p8, int usage);
ASN1_TYPE *PKCS12_get_attr_gen(struct stack_st_X509_ATTRIBUTE *attrs, int attr_nid);
char *PKCS12_get_friendlyname(PKCS12_SAFEBAG *bag);
unsigned char *PKCS12_pbe_crypt(X509_ALGOR *algor, const char *pass,
    int passlen, unsigned char *in, int inlen,
    unsigned char **data, int *datalen, int en_de);
void * PKCS12_item_decrypt_d2i(X509_ALGOR *algor, const ASN1_ITEM *it,
      const char *pass, int passlen, ASN1_OCTET_STRING *oct, int zbuf);
ASN1_OCTET_STRING *PKCS12_item_i2d_encrypt(X509_ALGOR *algor, const ASN1_ITEM *it,
           const char *pass, int passlen,
           void *obj, int zbuf);
PKCS12 *PKCS12_init(int mode);
int PKCS12_key_gen_asc(const char *pass, int passlen, unsigned char *salt,
         int saltlen, int id, int iter, int n,
         unsigned char *out, const EVP_MD *md_type);
int PKCS12_key_gen_uni(unsigned char *pass, int passlen, unsigned char *salt, int saltlen, int id, int iter, int n, unsigned char *out, const EVP_MD *md_type);
int PKCS12_PBE_keyivgen(EVP_CIPHER_CTX *ctx, const char *pass, int passlen,
    ASN1_TYPE *param, const EVP_CIPHER *cipher, const EVP_MD *md_type,
    int en_de);
int PKCS12_gen_mac(PKCS12 *p12, const char *pass, int passlen,
    unsigned char *mac, unsigned int *maclen);
int PKCS12_verify_mac(PKCS12 *p12, const char *pass, int passlen);
int PKCS12_set_mac(PKCS12 *p12, const char *pass, int passlen,
     unsigned char *salt, int saltlen, int iter,
     const EVP_MD *md_type);
int PKCS12_setup_mac(PKCS12 *p12, int iter, unsigned char *salt,
      int saltlen, const EVP_MD *md_type);
unsigned char *OPENSSL_asc2uni(const char *asc, int asclen, unsigned char **uni, int *unilen);
char *OPENSSL_uni2asc(unsigned char *uni, int unilen);

PKCS12 *PKCS12_new(void); void PKCS12_free(PKCS12 *a); PKCS12 *d2i_PKCS12(PKCS12 **a, const unsigned char **in, long len); int i2d_PKCS12(PKCS12 *a, unsigned char **out); extern const ASN1_ITEM PKCS12_it;
PKCS12_MAC_DATA *PKCS12_MAC_DATA_new(void); void PKCS12_MAC_DATA_free(PKCS12_MAC_DATA *a); PKCS12_MAC_DATA *d2i_PKCS12_MAC_DATA(PKCS12_MAC_DATA **a, const unsigned char **in, long len); int i2d_PKCS12_MAC_DATA(PKCS12_MAC_DATA *a, unsigned char **out); extern const ASN1_ITEM PKCS12_MAC_DATA_it;
PKCS12_SAFEBAG *PKCS12_SAFEBAG_new(void); void PKCS12_SAFEBAG_free(PKCS12_SAFEBAG *a); PKCS12_SAFEBAG *d2i_PKCS12_SAFEBAG(PKCS12_SAFEBAG **a, const unsigned char **in, long len); int i2d_PKCS12_SAFEBAG(PKCS12_SAFEBAG *a, unsigned char **out); extern const ASN1_ITEM PKCS12_SAFEBAG_it;
PKCS12_BAGS *PKCS12_BAGS_new(void); void PKCS12_BAGS_free(PKCS12_BAGS *a); PKCS12_BAGS *d2i_PKCS12_BAGS(PKCS12_BAGS **a, const unsigned char **in, long len); int i2d_PKCS12_BAGS(PKCS12_BAGS *a, unsigned char **out); extern const ASN1_ITEM PKCS12_BAGS_it;

extern const ASN1_ITEM PKCS12_SAFEBAGS_it;
extern const ASN1_ITEM PKCS12_AUTHSAFES_it;

void PKCS12_PBE_add(void);
int PKCS12_parse(PKCS12 *p12, const char *pass, EVP_PKEY **pkey, X509 **cert,
   struct stack_st_X509 **ca);
PKCS12 *PKCS12_create(char *pass, char *name, EVP_PKEY *pkey, X509 *cert,
    struct stack_st_X509 *ca, int nid_key, int nid_cert, int iter,
       int mac_iter, int keytype);

PKCS12_SAFEBAG *PKCS12_add_cert(struct stack_st_PKCS12_SAFEBAG **pbags, X509 *cert);
PKCS12_SAFEBAG *PKCS12_add_key(struct stack_st_PKCS12_SAFEBAG **pbags, EVP_PKEY *key,
      int key_usage, int iter,
      int key_nid, char *pass);
int PKCS12_add_safe(struct stack_st_PKCS7 **psafes, struct stack_st_PKCS12_SAFEBAG *bags,
     int safe_nid, int iter, char *pass);
PKCS12 *PKCS12_add_safes(struct stack_st_PKCS7 *safes, int p7_nid);

int i2d_PKCS12_bio(BIO *bp, PKCS12 *p12);
int i2d_PKCS12_fp(FILE *fp, PKCS12 *p12);
PKCS12 *d2i_PKCS12_bio(BIO *bp, PKCS12 **p12);
PKCS12 *d2i_PKCS12_fp(FILE *fp, PKCS12 **p12);
int PKCS12_newpass(PKCS12 *p12, char *oldpass, char *newpass);





void ERR_load_PKCS12_strings(void);









typedef struct rc2_key_st
 {
 unsigned int data[64];
 } RC2_KEY;




void RC2_set_key(RC2_KEY *key, int len, const unsigned char *data,int bits);
void RC2_ecb_encrypt(const unsigned char *in,unsigned char *out,RC2_KEY *key,
       int enc);
void RC2_encrypt(unsigned long *data,RC2_KEY *key);
void RC2_decrypt(unsigned long *data,RC2_KEY *key);
void RC2_cbc_encrypt(const unsigned char *in, unsigned char *out, long length,
 RC2_KEY *ks, unsigned char *iv, int enc);
void RC2_cfb64_encrypt(const unsigned char *in, unsigned char *out,
         long length, RC2_KEY *schedule, unsigned char *ivec,
         int *num, int enc);
void RC2_ofb64_encrypt(const unsigned char *in, unsigned char *out,
         long length, RC2_KEY *schedule, unsigned char *ivec,
         int *num);
















typedef struct rc4_key_st
 {
 unsigned int x,y;
 unsigned int data[256];
 } RC4_KEY;


const char *RC4_options(void);
void RC4_set_key(RC4_KEY *key, int len, const unsigned char *data);
void private_RC4_set_key(RC4_KEY *key, int len, const unsigned char *data);
void RC4(RC4_KEY *key, size_t len, const unsigned char *indata,
  unsigned char *outdata);











typedef struct RIPEMD160state_st
 {
 unsigned int A,B,C,D,E;
 unsigned int Nl,Nh;
 unsigned int data[(64/4)];
 unsigned int num;
 } RIPEMD160_CTX;




int RIPEMD160_Init(RIPEMD160_CTX *c);
int RIPEMD160_Update(RIPEMD160_CTX *c, const void *data, size_t len);
int RIPEMD160_Final(unsigned char *md, RIPEMD160_CTX *c);
unsigned char *RIPEMD160(const unsigned char *d, size_t n,
 unsigned char *md);
void RIPEMD160_Transform(RIPEMD160_CTX *c, const unsigned char *b);













typedef struct seed_key_st {



    unsigned int data[32];

} SEED_KEY_SCHEDULE;




void SEED_set_key(const unsigned char rawkey[16], SEED_KEY_SCHEDULE *ks);

void SEED_encrypt(const unsigned char s[16], unsigned char d[16], const SEED_KEY_SCHEDULE *ks);
void SEED_decrypt(const unsigned char s[16], unsigned char d[16], const SEED_KEY_SCHEDULE *ks);

void SEED_ecb_encrypt(const unsigned char *in, unsigned char *out, const SEED_KEY_SCHEDULE *ks, int enc);
void SEED_cbc_encrypt(const unsigned char *in, unsigned char *out,
        size_t len, const SEED_KEY_SCHEDULE *ks, unsigned char ivec[16], int enc);
void SEED_cfb128_encrypt(const unsigned char *in, unsigned char *out,
        size_t len, const SEED_KEY_SCHEDULE *ks, unsigned char ivec[16], int *num, int enc);
void SEED_ofb128_encrypt(const unsigned char *in, unsigned char *out,
        size_t len, const SEED_KEY_SCHEDULE *ks, unsigned char ivec[16], int *num);




typedef struct SRP_gN_cache_st
 {
 char *b64_bn;
 BIGNUM *bn;
 } SRP_gN_cache;


struct stack_st_SRP_gN_cache { _STACK stack; };

typedef struct SRP_user_pwd_st
 {

 char *id;
 BIGNUM *s;
 BIGNUM *v;

 const BIGNUM *g;
 const BIGNUM *N;

 char *info;
 } SRP_user_pwd;

struct stack_st_SRP_user_pwd { _STACK stack; };

void SRP_user_pwd_free(SRP_user_pwd *user_pwd);

typedef struct SRP_VBASE_st
 {
 struct stack_st_SRP_user_pwd *users_pwd;
 struct stack_st_SRP_gN_cache *gN_cache;

 char *seed_key;
 BIGNUM *default_g;
 BIGNUM *default_N;
 } SRP_VBASE;



typedef struct SRP_gN_st
 {
 char *id;
 BIGNUM *g;
 BIGNUM *N;
 } SRP_gN;

struct stack_st_SRP_gN { _STACK stack; };

SRP_VBASE *SRP_VBASE_new(char *seed_key);
int SRP_VBASE_free(SRP_VBASE *vb);
int SRP_VBASE_init(SRP_VBASE *vb, char * verifier_file);


SRP_user_pwd *SRP_VBASE_get_by_user(SRP_VBASE *vb, char *username);

SRP_user_pwd *SRP_VBASE_get1_by_user(SRP_VBASE *vb, char *username);

char *SRP_create_verifier(const char *user, const char *pass, char **salt,
     char **verifier, const char *N, const char *g);
int SRP_create_verifier_BN(const char *user, const char *pass, BIGNUM **salt, BIGNUM **verifier, BIGNUM *N, BIGNUM *g);

char * SRP_check_known_gN_param(BIGNUM* g, BIGNUM* N);
SRP_gN *SRP_get_default_gN(const char * id) ;


BIGNUM *SRP_Calc_server_key(BIGNUM *A, BIGNUM *v, BIGNUM *u, BIGNUM *b, BIGNUM *N);
BIGNUM *SRP_Calc_B(BIGNUM *b, BIGNUM *N, BIGNUM *g, BIGNUM *v);
int SRP_Verify_A_mod_N(BIGNUM *A, BIGNUM *N);
BIGNUM *SRP_Calc_u(BIGNUM *A, BIGNUM *B, BIGNUM *N) ;




BIGNUM *SRP_Calc_x(BIGNUM *s, const char *user, const char *pass);
BIGNUM *SRP_Calc_A(BIGNUM *a, BIGNUM *N, BIGNUM *g);
BIGNUM *SRP_Calc_client_key(BIGNUM *N, BIGNUM *B, BIGNUM *g, BIGNUM *x, BIGNUM *a, BIGNUM *u);
int SRP_Verify_B_mod_N(BIGNUM *B, BIGNUM *N);


typedef struct srtp_protection_profile_st
       {
       const char *name;
       unsigned long id;
       } SRTP_PROTECTION_PROFILE;

int SSL_CTX_set_tlsext_use_srtp(SSL_CTX *ctx, const char *profiles);
int SSL_set_tlsext_use_srtp(SSL *ctx, const char *profiles);
SRTP_PROTECTION_PROFILE *SSL_get_selected_srtp_profile(SSL *s);

struct stack_st_SRTP_PROTECTION_PROFILE *SSL_get_srtp_profiles(SSL *ssl);
SRTP_PROTECTION_PROFILE *SSL_get_selected_srtp_profile(SSL *s);





typedef struct ssl2_state_st
 {
 int three_byte_header;
 int clear_text;
 int escape;
 int ssl2_rollback;



 unsigned int wnum;
 int wpend_tot;
 const unsigned char *wpend_buf;

 int wpend_off;
 int wpend_len;
 int wpend_ret;


 int rbuf_left;
 int rbuf_offs;
 unsigned char *rbuf;
 unsigned char *wbuf;

 unsigned char *write_ptr;


 unsigned int padding;
 unsigned int rlength;
 int ract_data_length;
 unsigned int wlength;
 int wact_data_length;
 unsigned char *ract_data;
 unsigned char *wact_data;
 unsigned char *mac_data;

 unsigned char *read_key;
 unsigned char *write_key;


 unsigned int challenge_length;
 unsigned char challenge[32];
 unsigned int conn_id_length;
 unsigned char conn_id[16];
 unsigned int key_material_length;
 unsigned char key_material[24*2];

 unsigned long read_sequence;
 unsigned long write_sequence;

 struct {
  unsigned int conn_id_length;
  unsigned int cert_type;
  unsigned int cert_length;
  unsigned int csl;
  unsigned int clear;
  unsigned int enc;
  unsigned char ccl[32];
  unsigned int cipher_spec_length;
  unsigned int session_id_length;
  unsigned int clen;
  unsigned int rlen;
  } tmp;
 } SSL2_STATE;











typedef struct ssl_st *ssl_crock_st;
typedef struct tls_session_ticket_ext_st TLS_SESSION_TICKET_EXT;
typedef struct ssl_method_st SSL_METHOD;
typedef struct ssl_cipher_st SSL_CIPHER;

struct stack_st_SSL_CIPHER { _STACK stack; };



struct stack_st_SRTP_PROTECTION_PROFILE { _STACK stack; };

typedef int (*tls_session_ticket_ext_cb_fn)(SSL *s, const unsigned char *data, int len, void *arg);
typedef int (*tls_session_secret_cb_fn)(SSL *s, void *secret, int *secret_len, struct stack_st_SSL_CIPHER *peer_ciphers, SSL_CIPHER **cipher, void *arg);





struct ssl_cipher_st
 {
 int valid;
 const char *name;
 unsigned long id;


 unsigned long algorithm_mkey;
 unsigned long algorithm_auth;
 unsigned long algorithm_enc;
 unsigned long algorithm_mac;
 unsigned long algorithm_ssl;

 unsigned long algo_strength;
 unsigned long algorithm2;
 int strength_bits;
 int alg_bits;
 };



struct ssl_method_st
 {
 int version;
 int (*ssl_new)(SSL *s);
 void (*ssl_clear)(SSL *s);
 void (*ssl_free)(SSL *s);
 int (*ssl_accept)(SSL *s);
 int (*ssl_connect)(SSL *s);
 int (*ssl_read)(SSL *s,void *buf,int len);
 int (*ssl_peek)(SSL *s,void *buf,int len);
 int (*ssl_write)(SSL *s,const void *buf,int len);
 int (*ssl_shutdown)(SSL *s);
 int (*ssl_renegotiate)(SSL *s);
 int (*ssl_renegotiate_check)(SSL *s);
 long (*ssl_get_message)(SSL *s, int st1, int stn, int mt, long
  max, int *ok);
 int (*ssl_read_bytes)(SSL *s, int type, unsigned char *buf, int len,
  int peek);
 int (*ssl_write_bytes)(SSL *s, int type, const void *buf_, int len);
 int (*ssl_dispatch_alert)(SSL *s);
 long (*ssl_ctrl)(SSL *s,int cmd,long larg,void *parg);
 long (*ssl_ctx_ctrl)(SSL_CTX *ctx,int cmd,long larg,void *parg);
 const SSL_CIPHER *(*get_cipher_by_char)(const unsigned char *ptr);
 int (*put_cipher_by_char)(const SSL_CIPHER *cipher,unsigned char *ptr);
 int (*ssl_pending)(const SSL *s);
 int (*num_ciphers)(void);
 const SSL_CIPHER *(*get_cipher)(unsigned ncipher);
 const struct ssl_method_st *(*get_ssl_method)(int version);
 long (*get_timeout)(void);
 struct ssl3_enc_method *ssl3_enc;
 int (*ssl_version)(void);
 long (*ssl_callback_ctrl)(SSL *s, int cb_id, void (*fp)(void));
 long (*ssl_ctx_callback_ctrl)(SSL_CTX *s, int cb_id, void (*fp)(void));
 };

struct ssl_session_st
 {
 int ssl_version;



 unsigned int key_arg_length;
 unsigned char key_arg[8];
 int master_key_length;
 unsigned char master_key[48];

 unsigned int session_id_length;
 unsigned char session_id[32];



 unsigned int sid_ctx_length;
 unsigned char sid_ctx[32];






 char *psk_identity_hint;
 char *psk_identity;




 int not_resumable;


 struct sess_cert_st *sess_cert;





 X509 *peer;


 long verify_result;

 int references;
 long timeout;
 long time;

 unsigned int compress_meth;

 const SSL_CIPHER *cipher;
 unsigned long cipher_id;



 struct stack_st_SSL_CIPHER *ciphers;

 CRYPTO_EX_DATA ex_data;



 struct ssl_session_st *prev,*next;

 char *tlsext_hostname;

 size_t tlsext_ecpointformatlist_length;
 unsigned char *tlsext_ecpointformatlist;
 size_t tlsext_ellipticcurvelist_length;
 unsigned char *tlsext_ellipticcurvelist;


 unsigned char *tlsext_tick;
 size_t tlsext_ticklen;
 long tlsext_tick_lifetime_hint;


 char *srp_username;

 };

void SSL_CTX_set_msg_callback(SSL_CTX *ctx, void (*cb)(int write_p, int version, int content_type, const void *buf, size_t len, SSL *ssl, void *arg));
void SSL_set_msg_callback(SSL *ssl, void (*cb)(int write_p, int version, int content_type, const void *buf, size_t len, SSL *ssl, void *arg));







typedef struct srp_ctx_st
 {

 void *SRP_cb_arg;

 int (*TLS_ext_srp_username_callback)(SSL *, int *, void *);

 int (*SRP_verify_param_callback)(SSL *, void *);

 char *(*SRP_give_srp_client_pwd_callback)(SSL *, void *);

 char *login;
 BIGNUM *N,*g,*s,*B,*A;
 BIGNUM *a,*b,*v;
 char *info;
 int strength;

 unsigned long srp_Mask;
 } SRP_CTX;




int SSL_SRP_CTX_init(SSL *s);
int SSL_CTX_SRP_CTX_init(SSL_CTX *ctx);
int SSL_SRP_CTX_free(SSL *ctx);
int SSL_CTX_SRP_CTX_free(SSL_CTX *ctx);
int SSL_srp_server_param_with_username(SSL *s, int *ad);
int SRP_generate_server_master_secret(SSL *s,unsigned char *master_key);
int SRP_Calc_A_param(SSL *s);
int SRP_generate_client_master_secret(SSL *s,unsigned char *master_key);

typedef int (*GEN_SESSION_CB)(const SSL *ssl, unsigned char *id,
    unsigned int *id_len);

typedef struct ssl_comp_st SSL_COMP;



struct ssl_comp_st
 {
 int id;
 const char *name;

 COMP_METHOD *method;



 };

struct stack_st_SSL_COMP { _STACK stack; };
struct lhash_st_SSL_SESSION { int dummy; };

struct ssl_ctx_st
 {
 const SSL_METHOD *method;

 struct stack_st_SSL_CIPHER *cipher_list;

 struct stack_st_SSL_CIPHER *cipher_list_by_id;

 struct x509_store_st *cert_store;
 struct lhash_st_SSL_SESSION *sessions;


 unsigned long session_cache_size;
 struct ssl_session_st *session_cache_head;
 struct ssl_session_st *session_cache_tail;






 int session_cache_mode;




 long session_timeout;

 int (*new_session_cb)(struct ssl_st *ssl,SSL_SESSION *sess);
 void (*remove_session_cb)(struct ssl_ctx_st *ctx,SSL_SESSION *sess);
 SSL_SESSION *(*get_session_cb)(struct ssl_st *ssl,
  unsigned char *data,int len,int *copy);

 struct
  {
  int sess_connect;
  int sess_connect_renegotiate;
  int sess_connect_good;
  int sess_accept;
  int sess_accept_renegotiate;
  int sess_accept_good;
  int sess_miss;
  int sess_timeout;
  int sess_cache_full;
  int sess_hit;
  int sess_cb_hit;





  } stats;

 int references;


 int (*app_verify_callback)(X509_STORE_CTX *, void *);
 void *app_verify_arg;




 pem_password_cb *default_passwd_callback;


 void *default_passwd_callback_userdata;


 int (*client_cert_cb)(SSL *ssl, X509 **x509, EVP_PKEY **pkey);


    int (*app_gen_cookie_cb)(SSL *ssl, unsigned char *cookie,
        unsigned int *cookie_len);


    int (*app_verify_cookie_cb)(SSL *ssl, unsigned char *cookie,
        unsigned int cookie_len);

 CRYPTO_EX_DATA ex_data;

 const EVP_MD *rsa_md5;
 const EVP_MD *md5;
 const EVP_MD *sha1;

 struct stack_st_X509 *extra_certs;
 struct stack_st_SSL_COMP *comp_methods;




 void (*info_callback)(const SSL *ssl,int type,int val);


 struct stack_st_X509_NAME *client_CA;




 unsigned long options;
 unsigned long mode;
 long max_cert_list;

 struct cert_st *cert;
 int read_ahead;


 void (*msg_callback)(int write_p, int version, int content_type, const void *buf, size_t len, SSL *ssl, void *arg);
 void *msg_callback_arg;

 int verify_mode;
 unsigned int sid_ctx_length;
 unsigned char sid_ctx[32];
 int (*default_verify_callback)(int ok,X509_STORE_CTX *ctx);


 GEN_SESSION_CB generate_session_id;

 X509_VERIFY_PARAM *param;






 int quiet_shutdown;





 unsigned int max_send_fragment;




 ENGINE *client_cert_engine;




 int (*tlsext_servername_callback)(SSL*, int *, void *);
 void *tlsext_servername_arg;

 unsigned char tlsext_tick_key_name[16];
 unsigned char tlsext_tick_hmac_key[16];
 unsigned char tlsext_tick_aes_key[16];

 int (*tlsext_ticket_key_cb)(SSL *ssl,
     unsigned char *name, unsigned char *iv,
     EVP_CIPHER_CTX *ectx,
      HMAC_CTX *hctx, int enc);



 int (*tlsext_status_cb)(SSL *ssl, void *arg);
 void *tlsext_status_arg;


 int (*tlsext_opaque_prf_input_callback)(SSL *, void *peerinput, size_t len, void *arg);
 void *tlsext_opaque_prf_input_callback_arg;



 char *psk_identity_hint;
 unsigned int (*psk_client_callback)(SSL *ssl, const char *hint, char *identity,
  unsigned int max_identity_len, unsigned char *psk,
  unsigned int max_psk_len);
 unsigned int (*psk_server_callback)(SSL *ssl, const char *identity,
  unsigned char *psk, unsigned int max_psk_len);




 unsigned int freelist_max_len;
 struct ssl3_buf_freelist_st *wbuf_freelist;
 struct ssl3_buf_freelist_st *rbuf_freelist;


 SRP_CTX srp_ctx;

 int (*next_protos_advertised_cb)(SSL *s, const unsigned char **buf,
                    unsigned int *len, void *arg);
 void *next_protos_advertised_cb_arg;


 int (*next_proto_select_cb)(SSL *s, unsigned char **out,
        unsigned char *outlen,
        const unsigned char *in,
        unsigned int inlen,
        void *arg);
 void *next_proto_select_cb_arg;


        struct stack_st_SRTP_PROTECTION_PROFILE *srtp_profiles;

 };

struct lhash_st_SSL_SESSION *SSL_CTX_sessions(SSL_CTX *ctx);

void SSL_CTX_sess_set_new_cb(SSL_CTX *ctx, int (*new_session_cb)(struct ssl_st *ssl,SSL_SESSION *sess));
int (*SSL_CTX_sess_get_new_cb(SSL_CTX *ctx))(struct ssl_st *ssl, SSL_SESSION *sess);
void SSL_CTX_sess_set_remove_cb(SSL_CTX *ctx, void (*remove_session_cb)(struct ssl_ctx_st *ctx,SSL_SESSION *sess));
void (*SSL_CTX_sess_get_remove_cb(SSL_CTX *ctx))(struct ssl_ctx_st *ctx, SSL_SESSION *sess);
void SSL_CTX_sess_set_get_cb(SSL_CTX *ctx, SSL_SESSION *(*get_session_cb)(struct ssl_st *ssl, unsigned char *data,int len,int *copy));
SSL_SESSION *(*SSL_CTX_sess_get_get_cb(SSL_CTX *ctx))(struct ssl_st *ssl, unsigned char *Data, int len, int *copy);
void SSL_CTX_set_info_callback(SSL_CTX *ctx, void (*cb)(const SSL *ssl,int type,int val));
void (*SSL_CTX_get_info_callback(SSL_CTX *ctx))(const SSL *ssl,int type,int val);
void SSL_CTX_set_client_cert_cb(SSL_CTX *ctx, int (*client_cert_cb)(SSL *ssl, X509 **x509, EVP_PKEY **pkey));
int (*SSL_CTX_get_client_cert_cb(SSL_CTX *ctx))(SSL *ssl, X509 **x509, EVP_PKEY **pkey);

int SSL_CTX_set_client_cert_engine(SSL_CTX *ctx, ENGINE *e);

void SSL_CTX_set_cookie_generate_cb(SSL_CTX *ctx, int (*app_gen_cookie_cb)(SSL *ssl, unsigned char *cookie, unsigned int *cookie_len));
void SSL_CTX_set_cookie_verify_cb(SSL_CTX *ctx, int (*app_verify_cookie_cb)(SSL *ssl, unsigned char *cookie, unsigned int cookie_len));

void SSL_CTX_set_next_protos_advertised_cb(SSL_CTX *s,
        int (*cb) (SSL *ssl,
            const unsigned char **out,
            unsigned int *outlen,
            void *arg),
        void *arg);
void SSL_CTX_set_next_proto_select_cb(SSL_CTX *s,
          int (*cb) (SSL *ssl,
       unsigned char **out,
       unsigned char *outlen,
       const unsigned char *in,
       unsigned int inlen,
       void *arg),
          void *arg);

int SSL_select_next_proto(unsigned char **out, unsigned char *outlen,
     const unsigned char *in, unsigned int inlen,
     const unsigned char *client, unsigned int client_len);
void SSL_get0_next_proto_negotiated(const SSL *s,
        const unsigned char **data, unsigned *len);

void SSL_CTX_set_psk_client_callback(SSL_CTX *ctx,
 unsigned int (*psk_client_callback)(SSL *ssl, const char *hint,
  char *identity, unsigned int max_identity_len, unsigned char *psk,
  unsigned int max_psk_len));
void SSL_set_psk_client_callback(SSL *ssl,
 unsigned int (*psk_client_callback)(SSL *ssl, const char *hint,
  char *identity, unsigned int max_identity_len, unsigned char *psk,
  unsigned int max_psk_len));
void SSL_CTX_set_psk_server_callback(SSL_CTX *ctx,
 unsigned int (*psk_server_callback)(SSL *ssl, const char *identity,
  unsigned char *psk, unsigned int max_psk_len));
void SSL_set_psk_server_callback(SSL *ssl,
 unsigned int (*psk_server_callback)(SSL *ssl, const char *identity,
  unsigned char *psk, unsigned int max_psk_len));
int SSL_CTX_use_psk_identity_hint(SSL_CTX *ctx, const char *identity_hint);
int SSL_use_psk_identity_hint(SSL *s, const char *identity_hint);
const char *SSL_get_psk_identity_hint(const SSL *s);
const char *SSL_get_psk_identity(const SSL *s);

struct ssl_st
 {



 int version;
 int type;

 const SSL_METHOD *method;






 BIO *rbio;
 BIO *wbio;
 BIO *bbio;

 int rwstate;


 int in_handshake;
 int (*handshake_func)(SSL *);

 int server;

 int new_session;



 int quiet_shutdown;
 int shutdown;

 int state;
 int rstate;

 BUF_MEM *init_buf;
 void *init_msg;
 int init_num;
 int init_off;


 unsigned char *packet;
 unsigned int packet_length;

 struct ssl2_state_st *s2;
 struct ssl3_state_st *s3;
 struct dtls1_state_st *d1;

 int read_ahead;



 void (*msg_callback)(int write_p, int version, int content_type, const void *buf, size_t len, SSL *ssl, void *arg);
 void *msg_callback_arg;

 int hit;

 X509_VERIFY_PARAM *param;







 struct stack_st_SSL_CIPHER *cipher_list;
 struct stack_st_SSL_CIPHER *cipher_list_by_id;



 int mac_flags;
 EVP_CIPHER_CTX *enc_read_ctx;
 EVP_MD_CTX *read_hash;

 COMP_CTX *expand;




 EVP_CIPHER_CTX *enc_write_ctx;
 EVP_MD_CTX *write_hash;

 COMP_CTX *compress;

 struct cert_st *cert;



 unsigned int sid_ctx_length;
 unsigned char sid_ctx[32];


 SSL_SESSION *session;


 GEN_SESSION_CB generate_session_id;


 int verify_mode;

 int (*verify_callback)(int ok,X509_STORE_CTX *ctx);

 void (*info_callback)(const SSL *ssl,int type,int val);

 int error;
 int error_code;






 unsigned int (*psk_client_callback)(SSL *ssl, const char *hint, char *identity,
  unsigned int max_identity_len, unsigned char *psk,
  unsigned int max_psk_len);
 unsigned int (*psk_server_callback)(SSL *ssl, const char *identity,
  unsigned char *psk, unsigned int max_psk_len);


 SSL_CTX *ctx;


 int debug;


 long verify_result;
 CRYPTO_EX_DATA ex_data;


 struct stack_st_X509_NAME *client_CA;

 int references;
 unsigned long options;
 unsigned long mode;
 long max_cert_list;
 int first_packet;
 int client_version;

 unsigned int max_send_fragment;


 void (*tlsext_debug_cb)(SSL *s, int client_server, int type,
     unsigned char *data, int len,
     void *arg);
 void *tlsext_debug_arg;
 char *tlsext_hostname;
 int servername_done;






 int tlsext_status_type;

 int tlsext_status_expected;

 struct stack_st_OCSP_RESPID *tlsext_ocsp_ids;
 X509_EXTENSIONS *tlsext_ocsp_exts;

 unsigned char *tlsext_ocsp_resp;
 int tlsext_ocsp_resplen;


 int tlsext_ticket_expected;

 size_t tlsext_ecpointformatlist_length;
 unsigned char *tlsext_ecpointformatlist;
 size_t tlsext_ellipticcurvelist_length;
 unsigned char *tlsext_ellipticcurvelist;



 void *tlsext_opaque_prf_input;
 size_t tlsext_opaque_prf_input_len;


 TLS_SESSION_TICKET_EXT *tlsext_session_ticket;


 tls_session_ticket_ext_cb_fn tls_session_ticket_ext_cb;
 void *tls_session_ticket_ext_cb_arg;


 tls_session_secret_cb_fn tls_session_secret_cb;
 void *tls_session_secret_cb_arg;

 SSL_CTX * initial_ctx;

 unsigned char *next_proto_negotiated;
 unsigned char next_proto_negotiated_len;




 struct stack_st_SRTP_PROTECTION_PROFILE *srtp_profiles;
 SRTP_PROTECTION_PROFILE *srtp_profile;

 unsigned int tlsext_heartbeat;




 unsigned int tlsext_hb_pending;
 unsigned int tlsext_hb_seq;




 int renegotiate;




 SRP_CTX srp_ctx;

 };





const char *SSL_get_servername(const SSL *s, const int type);
int SSL_get_servername_type(const SSL *s);







int SSL_export_keying_material(SSL *s, unsigned char *out, size_t olen,
 const char *label, size_t llen, const unsigned char *p, size_t plen,
 int use_context);

struct tls_session_ticket_ext_st
 {
 unsigned short length;
 void *data;
 };


size_t SSL_get_finished(const SSL *s, void *buf, size_t count);
size_t SSL_get_peer_finished(const SSL *s, void *buf, size_t count);

SSL_SESSION *PEM_read_bio_SSL_SESSION(BIO *bp, SSL_SESSION **x, pem_password_cb *cb, void *u); SSL_SESSION *PEM_read_SSL_SESSION(FILE *fp, SSL_SESSION **x, pem_password_cb *cb, void *u); int PEM_write_bio_SSL_SESSION(BIO *bp, SSL_SESSION *x); int PEM_write_SSL_SESSION(FILE *fp, SSL_SESSION *x);

BIO_METHOD *BIO_f_ssl(void);
BIO *BIO_new_ssl(SSL_CTX *ctx,int client);
BIO *BIO_new_ssl_connect(SSL_CTX *ctx);
BIO *BIO_new_buffer_ssl_connect(SSL_CTX *ctx);
int BIO_ssl_copy_session_id(BIO *to,BIO *from);
void BIO_ssl_shutdown(BIO *ssl_bio);



int SSL_CTX_set_cipher_list(SSL_CTX *,const char *str);
SSL_CTX *SSL_CTX_new(const SSL_METHOD *meth);
void SSL_CTX_free(SSL_CTX *);
long SSL_CTX_set_timeout(SSL_CTX *ctx,long t);
long SSL_CTX_get_timeout(const SSL_CTX *ctx);
X509_STORE *SSL_CTX_get_cert_store(const SSL_CTX *);
void SSL_CTX_set_cert_store(SSL_CTX *,X509_STORE *);
int SSL_want(const SSL *s);
int SSL_clear(SSL *s);

void SSL_CTX_flush_sessions(SSL_CTX *ctx,long tm);

const SSL_CIPHER *SSL_get_current_cipher(const SSL *s);
int SSL_CIPHER_get_bits(const SSL_CIPHER *c,int *alg_bits);
char * SSL_CIPHER_get_version(const SSL_CIPHER *c);
const char * SSL_CIPHER_get_name(const SSL_CIPHER *c);
unsigned long SSL_CIPHER_get_id(const SSL_CIPHER *c);

int SSL_get_fd(const SSL *s);
int SSL_get_rfd(const SSL *s);
int SSL_get_wfd(const SSL *s);
const char * SSL_get_cipher_list(const SSL *s,int n);
char * SSL_get_shared_ciphers(const SSL *s, char *buf, int len);
int SSL_get_read_ahead(const SSL * s);
int SSL_pending(const SSL *s);

int SSL_set_fd(SSL *s, int fd);
int SSL_set_rfd(SSL *s, int fd);
int SSL_set_wfd(SSL *s, int fd);


void SSL_set_bio(SSL *s, BIO *rbio,BIO *wbio);
BIO * SSL_get_rbio(const SSL *s);
BIO * SSL_get_wbio(const SSL *s);

int SSL_set_cipher_list(SSL *s, const char *str);
void SSL_set_read_ahead(SSL *s, int yes);
int SSL_get_verify_mode(const SSL *s);
int SSL_get_verify_depth(const SSL *s);
int (*SSL_get_verify_callback(const SSL *s))(int,X509_STORE_CTX *);
void SSL_set_verify(SSL *s, int mode,
         int (*callback)(int ok,X509_STORE_CTX *ctx));
void SSL_set_verify_depth(SSL *s, int depth);

int SSL_use_RSAPrivateKey(SSL *ssl, RSA *rsa);

int SSL_use_RSAPrivateKey_ASN1(SSL *ssl, unsigned char *d, long len);
int SSL_use_PrivateKey(SSL *ssl, EVP_PKEY *pkey);
int SSL_use_PrivateKey_ASN1(int pk,SSL *ssl, const unsigned char *d, long len);
int SSL_use_certificate(SSL *ssl, X509 *x);
int SSL_use_certificate_ASN1(SSL *ssl, const unsigned char *d, int len);


int SSL_use_RSAPrivateKey_file(SSL *ssl, const char *file, int type);
int SSL_use_PrivateKey_file(SSL *ssl, const char *file, int type);
int SSL_use_certificate_file(SSL *ssl, const char *file, int type);
int SSL_CTX_use_RSAPrivateKey_file(SSL_CTX *ctx, const char *file, int type);
int SSL_CTX_use_PrivateKey_file(SSL_CTX *ctx, const char *file, int type);
int SSL_CTX_use_certificate_file(SSL_CTX *ctx, const char *file, int type);
int SSL_CTX_use_certificate_chain_file(SSL_CTX *ctx, const char *file);
struct stack_st_X509_NAME *SSL_load_client_CA_file(const char *file);
int SSL_add_file_cert_subjects_to_stack(struct stack_st_X509_NAME *stackCAs,
         const char *file);


int SSL_add_dir_cert_subjects_to_stack(struct stack_st_X509_NAME *stackCAs,
        const char *dir);





void SSL_load_error_strings(void );
const char *SSL_state_string(const SSL *s);
const char *SSL_rstate_string(const SSL *s);
const char *SSL_state_string_long(const SSL *s);
const char *SSL_rstate_string_long(const SSL *s);
long SSL_SESSION_get_time(const SSL_SESSION *s);
long SSL_SESSION_set_time(SSL_SESSION *s, long t);
long SSL_SESSION_get_timeout(const SSL_SESSION *s);
long SSL_SESSION_set_timeout(SSL_SESSION *s, long t);
void SSL_copy_session_id(SSL *to,const SSL *from);
X509 *SSL_SESSION_get0_peer(SSL_SESSION *s);
int SSL_SESSION_set1_id_context(SSL_SESSION *s,const unsigned char *sid_ctx,
          unsigned int sid_ctx_len);

SSL_SESSION *SSL_SESSION_new(void);
const unsigned char *SSL_SESSION_get_id(const SSL_SESSION *s,
     unsigned int *len);
unsigned int SSL_SESSION_get_compress_id(const SSL_SESSION *s);

int SSL_SESSION_print_fp(FILE *fp,const SSL_SESSION *ses);


int SSL_SESSION_print(BIO *fp,const SSL_SESSION *ses);

void SSL_SESSION_free(SSL_SESSION *ses);
int i2d_SSL_SESSION(SSL_SESSION *in,unsigned char **pp);
int SSL_set_session(SSL *to, SSL_SESSION *session);
int SSL_CTX_add_session(SSL_CTX *s, SSL_SESSION *c);
int SSL_CTX_remove_session(SSL_CTX *,SSL_SESSION *c);
int SSL_CTX_set_generate_session_id(SSL_CTX *, GEN_SESSION_CB);
int SSL_set_generate_session_id(SSL *, GEN_SESSION_CB);
int SSL_has_matching_session_id(const SSL *ssl, const unsigned char *id,
     unsigned int id_len);
SSL_SESSION *d2i_SSL_SESSION(SSL_SESSION **a,const unsigned char **pp,
        long length);


X509 * SSL_get_peer_certificate(const SSL *s);


struct stack_st_X509 *SSL_get_peer_cert_chain(const SSL *s);

int SSL_CTX_get_verify_mode(const SSL_CTX *ctx);
int SSL_CTX_get_verify_depth(const SSL_CTX *ctx);
int (*SSL_CTX_get_verify_callback(const SSL_CTX *ctx))(int,X509_STORE_CTX *);
void SSL_CTX_set_verify(SSL_CTX *ctx,int mode,
   int (*callback)(int, X509_STORE_CTX *));
void SSL_CTX_set_verify_depth(SSL_CTX *ctx,int depth);
void SSL_CTX_set_cert_verify_callback(SSL_CTX *ctx, int (*cb)(X509_STORE_CTX *,void *), void *arg);

int SSL_CTX_use_RSAPrivateKey(SSL_CTX *ctx, RSA *rsa);

int SSL_CTX_use_RSAPrivateKey_ASN1(SSL_CTX *ctx, const unsigned char *d, long len);
int SSL_CTX_use_PrivateKey(SSL_CTX *ctx, EVP_PKEY *pkey);
int SSL_CTX_use_PrivateKey_ASN1(int pk,SSL_CTX *ctx,
 const unsigned char *d, long len);
int SSL_CTX_use_certificate(SSL_CTX *ctx, X509 *x);
int SSL_CTX_use_certificate_ASN1(SSL_CTX *ctx, int len, const unsigned char *d);

void SSL_CTX_set_default_passwd_cb(SSL_CTX *ctx, pem_password_cb *cb);
void SSL_CTX_set_default_passwd_cb_userdata(SSL_CTX *ctx, void *u);

int SSL_CTX_check_private_key(const SSL_CTX *ctx);
int SSL_check_private_key(const SSL *ctx);

int SSL_CTX_set_session_id_context(SSL_CTX *ctx,const unsigned char *sid_ctx,
           unsigned int sid_ctx_len);

SSL * SSL_new(SSL_CTX *ctx);
int SSL_set_session_id_context(SSL *ssl,const unsigned char *sid_ctx,
       unsigned int sid_ctx_len);

int SSL_CTX_set_purpose(SSL_CTX *s, int purpose);
int SSL_set_purpose(SSL *s, int purpose);
int SSL_CTX_set_trust(SSL_CTX *s, int trust);
int SSL_set_trust(SSL *s, int trust);

int SSL_CTX_set1_param(SSL_CTX *ctx, X509_VERIFY_PARAM *vpm);
int SSL_set1_param(SSL *ssl, X509_VERIFY_PARAM *vpm);


int SSL_CTX_set_srp_username(SSL_CTX *ctx,char *name);
int SSL_CTX_set_srp_password(SSL_CTX *ctx,char *password);
int SSL_CTX_set_srp_strength(SSL_CTX *ctx, int strength);
int SSL_CTX_set_srp_client_pwd_callback(SSL_CTX *ctx,
     char *(*cb)(SSL *,void *));
int SSL_CTX_set_srp_verify_param_callback(SSL_CTX *ctx,
       int (*cb)(SSL *,void *));
int SSL_CTX_set_srp_username_callback(SSL_CTX *ctx,
          int (*cb)(SSL *,int *,void *));
int SSL_CTX_set_srp_cb_arg(SSL_CTX *ctx, void *arg);

int SSL_set_srp_server_param(SSL *s, const BIGNUM *N, const BIGNUM *g,
        BIGNUM *sa, BIGNUM *v, char *info);
int SSL_set_srp_server_param_pw(SSL *s, const char *user, const char *pass,
    const char *grp);

BIGNUM *SSL_get_srp_g(SSL *s);
BIGNUM *SSL_get_srp_N(SSL *s);

char *SSL_get_srp_username(SSL *s);
char *SSL_get_srp_userinfo(SSL *s);


void SSL_free(SSL *ssl);
int SSL_accept(SSL *ssl);
int SSL_connect(SSL *ssl);
int SSL_read(SSL *ssl,void *buf,int num);
int SSL_peek(SSL *ssl,void *buf,int num);
int SSL_write(SSL *ssl,const void *buf,int num);
long SSL_ctrl(SSL *ssl,int cmd, long larg, void *parg);
long SSL_callback_ctrl(SSL *, int, void (*)(void));
long SSL_CTX_ctrl(SSL_CTX *ctx,int cmd, long larg, void *parg);
long SSL_CTX_callback_ctrl(SSL_CTX *, int, void (*)(void));

int SSL_get_error(const SSL *s,int ret_code);
const char *SSL_get_version(const SSL *s);


int SSL_CTX_set_ssl_version(SSL_CTX *ctx, const SSL_METHOD *meth);







const SSL_METHOD *SSLv3_method(void);
const SSL_METHOD *SSLv3_server_method(void);
const SSL_METHOD *SSLv3_client_method(void);

const SSL_METHOD *SSLv23_method(void);
const SSL_METHOD *SSLv23_server_method(void);
const SSL_METHOD *SSLv23_client_method(void);

const SSL_METHOD *TLSv1_method(void);
const SSL_METHOD *TLSv1_server_method(void);
const SSL_METHOD *TLSv1_client_method(void);

const SSL_METHOD *TLSv1_1_method(void);
const SSL_METHOD *TLSv1_1_server_method(void);
const SSL_METHOD *TLSv1_1_client_method(void);

const SSL_METHOD *TLSv1_2_method(void);
const SSL_METHOD *TLSv1_2_server_method(void);
const SSL_METHOD *TLSv1_2_client_method(void);


const SSL_METHOD *DTLSv1_method(void);
const SSL_METHOD *DTLSv1_server_method(void);
const SSL_METHOD *DTLSv1_client_method(void);

struct stack_st_SSL_CIPHER *SSL_get_ciphers(const SSL *s);

int SSL_do_handshake(SSL *s);
int SSL_renegotiate(SSL *s);
int SSL_renegotiate_abbreviated(SSL *s);
int SSL_renegotiate_pending(SSL *s);
int SSL_shutdown(SSL *s);

const SSL_METHOD *SSL_get_ssl_method(SSL *s);
int SSL_set_ssl_method(SSL *s, const SSL_METHOD *method);
const char *SSL_alert_type_string_long(int value);
const char *SSL_alert_type_string(int value);
const char *SSL_alert_desc_string_long(int value);
const char *SSL_alert_desc_string(int value);

void SSL_set_client_CA_list(SSL *s, struct stack_st_X509_NAME *name_list);
void SSL_CTX_set_client_CA_list(SSL_CTX *ctx, struct stack_st_X509_NAME *name_list);
struct stack_st_X509_NAME *SSL_get_client_CA_list(const SSL *s);
struct stack_st_X509_NAME *SSL_CTX_get_client_CA_list(const SSL_CTX *s);
int SSL_add_client_CA(SSL *ssl,X509 *x);
int SSL_CTX_add_client_CA(SSL_CTX *ctx,X509 *x);

void SSL_set_connect_state(SSL *s);
void SSL_set_accept_state(SSL *s);

long SSL_get_default_timeout(const SSL *s);

int SSL_library_init(void );

char *SSL_CIPHER_description(const SSL_CIPHER *,char *buf,int size);
struct stack_st_X509_NAME *SSL_dup_CA_list(struct stack_st_X509_NAME *sk);

SSL *SSL_dup(SSL *ssl);

X509 *SSL_get_certificate(const SSL *ssl);
               struct evp_pkey_st *SSL_get_privatekey(SSL *ssl);

void SSL_CTX_set_quiet_shutdown(SSL_CTX *ctx,int mode);
int SSL_CTX_get_quiet_shutdown(const SSL_CTX *ctx);
void SSL_set_quiet_shutdown(SSL *ssl,int mode);
int SSL_get_quiet_shutdown(const SSL *ssl);
void SSL_set_shutdown(SSL *ssl,int mode);
int SSL_get_shutdown(const SSL *ssl);
int SSL_version(const SSL *ssl);
int SSL_CTX_set_default_verify_paths(SSL_CTX *ctx);
int SSL_CTX_load_verify_locations(SSL_CTX *ctx, const char *CAfile,
 const char *CApath);

SSL_SESSION *SSL_get_session(const SSL *ssl);
SSL_SESSION *SSL_get1_session(SSL *ssl);
SSL_CTX *SSL_get_SSL_CTX(const SSL *ssl);
SSL_CTX *SSL_set_SSL_CTX(SSL *ssl, SSL_CTX* ctx);
void SSL_set_info_callback(SSL *ssl,
      void (*cb)(const SSL *ssl,int type,int val));
void (*SSL_get_info_callback(const SSL *ssl))(const SSL *ssl,int type,int val);
int SSL_state(const SSL *ssl);
void SSL_set_state(SSL *ssl, int state);

void SSL_set_verify_result(SSL *ssl,long v);
long SSL_get_verify_result(const SSL *ssl);

int SSL_set_ex_data(SSL *ssl,int idx,void *data);
void *SSL_get_ex_data(const SSL *ssl,int idx);
int SSL_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func,
 CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func);

int SSL_SESSION_set_ex_data(SSL_SESSION *ss,int idx,void *data);
void *SSL_SESSION_get_ex_data(const SSL_SESSION *ss,int idx);
int SSL_SESSION_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func,
 CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func);

int SSL_CTX_set_ex_data(SSL_CTX *ssl,int idx,void *data);
void *SSL_CTX_get_ex_data(const SSL_CTX *ssl,int idx);
int SSL_CTX_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func,
 CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func);

int SSL_get_ex_data_X509_STORE_CTX_idx(void );

void SSL_CTX_set_tmp_rsa_callback(SSL_CTX *ctx,
      RSA *(*cb)(SSL *ssl,int is_export,
          int keylength));

void SSL_set_tmp_rsa_callback(SSL *ssl,
      RSA *(*cb)(SSL *ssl,int is_export,
          int keylength));


void SSL_CTX_set_tmp_dh_callback(SSL_CTX *ctx,
     DH *(*dh)(SSL *ssl,int is_export,
        int keylength));
void SSL_set_tmp_dh_callback(SSL *ssl,
     DH *(*dh)(SSL *ssl,int is_export,
        int keylength));


void SSL_CTX_set_tmp_ecdh_callback(SSL_CTX *ctx,
     EC_KEY *(*ecdh)(SSL *ssl,int is_export,
        int keylength));
void SSL_set_tmp_ecdh_callback(SSL *ssl,
     EC_KEY *(*ecdh)(SSL *ssl,int is_export,
        int keylength));



const COMP_METHOD *SSL_get_current_compression(SSL *s);
const COMP_METHOD *SSL_get_current_expansion(SSL *s);
const char *SSL_COMP_get_name(const COMP_METHOD *comp);
struct stack_st_SSL_COMP *SSL_COMP_get_compression_methods(void);
int SSL_COMP_add_compression_method(int id,COMP_METHOD *cm);

int SSL_set_session_ticket_ext(SSL *s, void *ext_data, int ext_len);

int SSL_set_session_ticket_ext_cb(SSL *s, tls_session_ticket_ext_cb_fn cb,
      void *arg);


int SSL_set_session_secret_cb(SSL *s, tls_session_secret_cb_fn tls_session_secret_cb, void *arg);

void SSL_set_debug(SSL *s, int debug);
int SSL_cache_hit(SSL *s);





void ERR_load_SSL_strings(void);


typedef struct ssl3_state_st
 {
 long flags;
 int delay_buf_pop_ret;

 unsigned char read_sequence[8];
 int read_mac_secret_size;
 unsigned char read_mac_secret[64];
 unsigned char write_sequence[8];
 int write_mac_secret_size;
 unsigned char write_mac_secret[64];

 unsigned char server_random[32];
 unsigned char client_random[32];


 int need_empty_fragments;
 int empty_fragment_done;


 int init_extra;

 SSL3_BUFFER rbuf;
 SSL3_BUFFER wbuf;

 SSL3_RECORD rrec;
 SSL3_RECORD wrec;



 unsigned char alert_fragment[2];
 unsigned int alert_fragment_len;
 unsigned char handshake_fragment[4];
 unsigned int handshake_fragment_len;


 unsigned int wnum;
 int wpend_tot;
 int wpend_type;
 int wpend_ret;
 const unsigned char *wpend_buf;


 BIO *handshake_buffer;



 EVP_MD_CTX **handshake_dgst;


 int change_cipher_spec;

 int warn_alert;
 int fatal_alert;


 int alert_dispatch;
 unsigned char send_alert[2];



 int renegotiate;
 int total_renegotiations;
 int num_renegotiations;

 int in_read_app_data;




 void *client_opaque_prf_input;
 size_t client_opaque_prf_input_len;
 void *server_opaque_prf_input;
 size_t server_opaque_prf_input_len;

 struct {

  unsigned char cert_verify_md[64*2];


  unsigned char finish_md[64*2];
  int finish_md_len;
  unsigned char peer_finish_md[64*2];
  int peer_finish_md_len;

  unsigned long message_size;
  int message_type;


  const SSL_CIPHER *new_cipher;

  DH *dh;



  EC_KEY *ecdh;



  int next_state;

  int reuse_message;


  int cert_req;
  int ctype_num;
  char ctype[9];
  struct stack_st_X509_NAME *ca_names;

  int use_rsa_tmp;

  int key_block_length;
  unsigned char *key_block;

  const EVP_CIPHER *new_sym_enc;
  const EVP_MD *new_hash;
  int new_mac_pkey_type;
  int new_mac_secret_size;

  const SSL_COMP *new_compression;



  int cert_request;
  } tmp;


        unsigned char previous_client_finished[64];
        unsigned char previous_client_finished_len;
        unsigned char previous_server_finished[64];
        unsigned char previous_server_finished_len;
        int send_connection_binding;



 int next_proto_neg_seen;







 char is_probably_safari;


 } SSL3_STATE;










typedef struct TS_msg_imprint_st
 {
 X509_ALGOR *hash_algo;
 ASN1_OCTET_STRING *hashed_msg;
 } TS_MSG_IMPRINT;

typedef struct TS_req_st
 {
 ASN1_INTEGER *version;
 TS_MSG_IMPRINT *msg_imprint;
 ASN1_OBJECT *policy_id;
 ASN1_INTEGER *nonce;
 ASN1_BOOLEAN cert_req;
 struct stack_st_X509_EXTENSION *extensions;
 } TS_REQ;

typedef struct TS_accuracy_st
 {
 ASN1_INTEGER *seconds;
 ASN1_INTEGER *millis;
 ASN1_INTEGER *micros;
 } TS_ACCURACY;

typedef struct TS_tst_info_st
 {
 ASN1_INTEGER *version;
 ASN1_OBJECT *policy_id;
 TS_MSG_IMPRINT *msg_imprint;
 ASN1_INTEGER *serial;
 ASN1_GENERALIZEDTIME *time;
 TS_ACCURACY *accuracy;
 ASN1_BOOLEAN ordering;
 ASN1_INTEGER *nonce;
 GENERAL_NAME *tsa;
 struct stack_st_X509_EXTENSION *extensions;
 } TS_TST_INFO;

typedef struct TS_status_info_st
 {
 ASN1_INTEGER *status;
 struct stack_st_ASN1_UTF8STRING *text;
 ASN1_BIT_STRING *failure_info;
 } TS_STATUS_INFO;

struct stack_st_ASN1_UTF8STRING { _STACK stack; };








typedef struct TS_resp_st
 {
 TS_STATUS_INFO *status_info;
 PKCS7 *token;
 TS_TST_INFO *tst_info;
 } TS_RESP;

typedef struct ESS_issuer_serial
 {
 struct stack_st_GENERAL_NAME *issuer;
 ASN1_INTEGER *serial;
 } ESS_ISSUER_SERIAL;

typedef struct ESS_cert_id
 {
 ASN1_OCTET_STRING *hash;
 ESS_ISSUER_SERIAL *issuer_serial;
 } ESS_CERT_ID;

struct stack_st_ESS_CERT_ID { _STACK stack; };


typedef struct ESS_signing_cert
 {
 struct stack_st_ESS_CERT_ID *cert_ids;
 struct stack_st_POLICYINFO *policy_info;
 } ESS_SIGNING_CERT;


TS_REQ *TS_REQ_new(void);
void TS_REQ_free(TS_REQ *a);
int i2d_TS_REQ(const TS_REQ *a, unsigned char **pp);
TS_REQ *d2i_TS_REQ(TS_REQ **a, const unsigned char **pp, long length);

TS_REQ *TS_REQ_dup(TS_REQ *a);

TS_REQ *d2i_TS_REQ_fp(FILE *fp, TS_REQ **a);
int i2d_TS_REQ_fp(FILE *fp, TS_REQ *a);
TS_REQ *d2i_TS_REQ_bio(BIO *fp, TS_REQ **a);
int i2d_TS_REQ_bio(BIO *fp, TS_REQ *a);

TS_MSG_IMPRINT *TS_MSG_IMPRINT_new(void);
void TS_MSG_IMPRINT_free(TS_MSG_IMPRINT *a);
int i2d_TS_MSG_IMPRINT(const TS_MSG_IMPRINT *a, unsigned char **pp);
TS_MSG_IMPRINT *d2i_TS_MSG_IMPRINT(TS_MSG_IMPRINT **a,
        const unsigned char **pp, long length);

TS_MSG_IMPRINT *TS_MSG_IMPRINT_dup(TS_MSG_IMPRINT *a);

TS_MSG_IMPRINT *d2i_TS_MSG_IMPRINT_fp(FILE *fp, TS_MSG_IMPRINT **a);
int i2d_TS_MSG_IMPRINT_fp(FILE *fp, TS_MSG_IMPRINT *a);
TS_MSG_IMPRINT *d2i_TS_MSG_IMPRINT_bio(BIO *fp, TS_MSG_IMPRINT **a);
int i2d_TS_MSG_IMPRINT_bio(BIO *fp, TS_MSG_IMPRINT *a);

TS_RESP *TS_RESP_new(void);
void TS_RESP_free(TS_RESP *a);
int i2d_TS_RESP(const TS_RESP *a, unsigned char **pp);
TS_RESP *d2i_TS_RESP(TS_RESP **a, const unsigned char **pp, long length);
TS_TST_INFO *PKCS7_to_TS_TST_INFO(PKCS7 *token);
TS_RESP *TS_RESP_dup(TS_RESP *a);

TS_RESP *d2i_TS_RESP_fp(FILE *fp, TS_RESP **a);
int i2d_TS_RESP_fp(FILE *fp, TS_RESP *a);
TS_RESP *d2i_TS_RESP_bio(BIO *fp, TS_RESP **a);
int i2d_TS_RESP_bio(BIO *fp, TS_RESP *a);

TS_STATUS_INFO *TS_STATUS_INFO_new(void);
void TS_STATUS_INFO_free(TS_STATUS_INFO *a);
int i2d_TS_STATUS_INFO(const TS_STATUS_INFO *a, unsigned char **pp);
TS_STATUS_INFO *d2i_TS_STATUS_INFO(TS_STATUS_INFO **a,
        const unsigned char **pp, long length);
TS_STATUS_INFO *TS_STATUS_INFO_dup(TS_STATUS_INFO *a);

TS_TST_INFO *TS_TST_INFO_new(void);
void TS_TST_INFO_free(TS_TST_INFO *a);
int i2d_TS_TST_INFO(const TS_TST_INFO *a, unsigned char **pp);
TS_TST_INFO *d2i_TS_TST_INFO(TS_TST_INFO **a, const unsigned char **pp,
        long length);
TS_TST_INFO *TS_TST_INFO_dup(TS_TST_INFO *a);

TS_TST_INFO *d2i_TS_TST_INFO_fp(FILE *fp, TS_TST_INFO **a);
int i2d_TS_TST_INFO_fp(FILE *fp, TS_TST_INFO *a);
TS_TST_INFO *d2i_TS_TST_INFO_bio(BIO *fp, TS_TST_INFO **a);
int i2d_TS_TST_INFO_bio(BIO *fp, TS_TST_INFO *a);

TS_ACCURACY *TS_ACCURACY_new(void);
void TS_ACCURACY_free(TS_ACCURACY *a);
int i2d_TS_ACCURACY(const TS_ACCURACY *a, unsigned char **pp);
TS_ACCURACY *d2i_TS_ACCURACY(TS_ACCURACY **a, const unsigned char **pp,
        long length);
TS_ACCURACY *TS_ACCURACY_dup(TS_ACCURACY *a);

ESS_ISSUER_SERIAL *ESS_ISSUER_SERIAL_new(void);
void ESS_ISSUER_SERIAL_free(ESS_ISSUER_SERIAL *a);
int i2d_ESS_ISSUER_SERIAL(const ESS_ISSUER_SERIAL *a,
     unsigned char **pp);
ESS_ISSUER_SERIAL *d2i_ESS_ISSUER_SERIAL(ESS_ISSUER_SERIAL **a,
      const unsigned char **pp, long length);
ESS_ISSUER_SERIAL *ESS_ISSUER_SERIAL_dup(ESS_ISSUER_SERIAL *a);

ESS_CERT_ID *ESS_CERT_ID_new(void);
void ESS_CERT_ID_free(ESS_CERT_ID *a);
int i2d_ESS_CERT_ID(const ESS_CERT_ID *a, unsigned char **pp);
ESS_CERT_ID *d2i_ESS_CERT_ID(ESS_CERT_ID **a, const unsigned char **pp,
     long length);
ESS_CERT_ID *ESS_CERT_ID_dup(ESS_CERT_ID *a);

ESS_SIGNING_CERT *ESS_SIGNING_CERT_new(void);
void ESS_SIGNING_CERT_free(ESS_SIGNING_CERT *a);
int i2d_ESS_SIGNING_CERT(const ESS_SIGNING_CERT *a,
          unsigned char **pp);
ESS_SIGNING_CERT *d2i_ESS_SIGNING_CERT(ESS_SIGNING_CERT **a,
           const unsigned char **pp, long length);
ESS_SIGNING_CERT *ESS_SIGNING_CERT_dup(ESS_SIGNING_CERT *a);

void ERR_load_TS_strings(void);

int TS_REQ_set_version(TS_REQ *a, long version);
long TS_REQ_get_version(const TS_REQ *a);

int TS_REQ_set_msg_imprint(TS_REQ *a, TS_MSG_IMPRINT *msg_imprint);
TS_MSG_IMPRINT *TS_REQ_get_msg_imprint(TS_REQ *a);

int TS_MSG_IMPRINT_set_algo(TS_MSG_IMPRINT *a, X509_ALGOR *alg);
X509_ALGOR *TS_MSG_IMPRINT_get_algo(TS_MSG_IMPRINT *a);

int TS_MSG_IMPRINT_set_msg(TS_MSG_IMPRINT *a, unsigned char *d, int len);
ASN1_OCTET_STRING *TS_MSG_IMPRINT_get_msg(TS_MSG_IMPRINT *a);

int TS_REQ_set_policy_id(TS_REQ *a, ASN1_OBJECT *policy);
ASN1_OBJECT *TS_REQ_get_policy_id(TS_REQ *a);

int TS_REQ_set_nonce(TS_REQ *a, const ASN1_INTEGER *nonce);
const ASN1_INTEGER *TS_REQ_get_nonce(const TS_REQ *a);

int TS_REQ_set_cert_req(TS_REQ *a, int cert_req);
int TS_REQ_get_cert_req(const TS_REQ *a);

struct stack_st_X509_EXTENSION *TS_REQ_get_exts(TS_REQ *a);
void TS_REQ_ext_free(TS_REQ *a);
int TS_REQ_get_ext_count(TS_REQ *a);
int TS_REQ_get_ext_by_NID(TS_REQ *a, int nid, int lastpos);
int TS_REQ_get_ext_by_OBJ(TS_REQ *a, ASN1_OBJECT *obj, int lastpos);
int TS_REQ_get_ext_by_critical(TS_REQ *a, int crit, int lastpos);
X509_EXTENSION *TS_REQ_get_ext(TS_REQ *a, int loc);
X509_EXTENSION *TS_REQ_delete_ext(TS_REQ *a, int loc);
int TS_REQ_add_ext(TS_REQ *a, X509_EXTENSION *ex, int loc);
void *TS_REQ_get_ext_d2i(TS_REQ *a, int nid, int *crit, int *idx);



int TS_REQ_print_bio(BIO *bio, TS_REQ *a);



int TS_RESP_set_status_info(TS_RESP *a, TS_STATUS_INFO *info);
TS_STATUS_INFO *TS_RESP_get_status_info(TS_RESP *a);


void TS_RESP_set_tst_info(TS_RESP *a, PKCS7 *p7, TS_TST_INFO *tst_info);
PKCS7 *TS_RESP_get_token(TS_RESP *a);
TS_TST_INFO *TS_RESP_get_tst_info(TS_RESP *a);

int TS_TST_INFO_set_version(TS_TST_INFO *a, long version);
long TS_TST_INFO_get_version(const TS_TST_INFO *a);

int TS_TST_INFO_set_policy_id(TS_TST_INFO *a, ASN1_OBJECT *policy_id);
ASN1_OBJECT *TS_TST_INFO_get_policy_id(TS_TST_INFO *a);

int TS_TST_INFO_set_msg_imprint(TS_TST_INFO *a, TS_MSG_IMPRINT *msg_imprint);
TS_MSG_IMPRINT *TS_TST_INFO_get_msg_imprint(TS_TST_INFO *a);

int TS_TST_INFO_set_serial(TS_TST_INFO *a, const ASN1_INTEGER *serial);
const ASN1_INTEGER *TS_TST_INFO_get_serial(const TS_TST_INFO *a);

int TS_TST_INFO_set_time(TS_TST_INFO *a, const ASN1_GENERALIZEDTIME *gtime);
const ASN1_GENERALIZEDTIME *TS_TST_INFO_get_time(const TS_TST_INFO *a);

int TS_TST_INFO_set_accuracy(TS_TST_INFO *a, TS_ACCURACY *accuracy);
TS_ACCURACY *TS_TST_INFO_get_accuracy(TS_TST_INFO *a);

int TS_ACCURACY_set_seconds(TS_ACCURACY *a, const ASN1_INTEGER *seconds);
const ASN1_INTEGER *TS_ACCURACY_get_seconds(const TS_ACCURACY *a);

int TS_ACCURACY_set_millis(TS_ACCURACY *a, const ASN1_INTEGER *millis);
const ASN1_INTEGER *TS_ACCURACY_get_millis(const TS_ACCURACY *a);

int TS_ACCURACY_set_micros(TS_ACCURACY *a, const ASN1_INTEGER *micros);
const ASN1_INTEGER *TS_ACCURACY_get_micros(const TS_ACCURACY *a);

int TS_TST_INFO_set_ordering(TS_TST_INFO *a, int ordering);
int TS_TST_INFO_get_ordering(const TS_TST_INFO *a);

int TS_TST_INFO_set_nonce(TS_TST_INFO *a, const ASN1_INTEGER *nonce);
const ASN1_INTEGER *TS_TST_INFO_get_nonce(const TS_TST_INFO *a);

int TS_TST_INFO_set_tsa(TS_TST_INFO *a, GENERAL_NAME *tsa);
GENERAL_NAME *TS_TST_INFO_get_tsa(TS_TST_INFO *a);

struct stack_st_X509_EXTENSION *TS_TST_INFO_get_exts(TS_TST_INFO *a);
void TS_TST_INFO_ext_free(TS_TST_INFO *a);
int TS_TST_INFO_get_ext_count(TS_TST_INFO *a);
int TS_TST_INFO_get_ext_by_NID(TS_TST_INFO *a, int nid, int lastpos);
int TS_TST_INFO_get_ext_by_OBJ(TS_TST_INFO *a, ASN1_OBJECT *obj, int lastpos);
int TS_TST_INFO_get_ext_by_critical(TS_TST_INFO *a, int crit, int lastpos);
X509_EXTENSION *TS_TST_INFO_get_ext(TS_TST_INFO *a, int loc);
X509_EXTENSION *TS_TST_INFO_delete_ext(TS_TST_INFO *a, int loc);
int TS_TST_INFO_add_ext(TS_TST_INFO *a, X509_EXTENSION *ex, int loc);
void *TS_TST_INFO_get_ext_d2i(TS_TST_INFO *a, int nid, int *crit, int *idx);

struct TS_resp_ctx;


typedef ASN1_INTEGER *(*TS_serial_cb)(struct TS_resp_ctx *, void *);




typedef int (*TS_time_cb)(struct TS_resp_ctx *, void *, long *sec, long *usec);






typedef int (*TS_extension_cb)(struct TS_resp_ctx *, X509_EXTENSION *, void *);

typedef struct TS_resp_ctx
 {
 X509 *signer_cert;
 EVP_PKEY *signer_key;
 struct stack_st_X509 *certs;
 struct stack_st_ASN1_OBJECT *policies;
 ASN1_OBJECT *default_policy;
 struct stack_st_EVP_MD *mds;
 ASN1_INTEGER *seconds;
 ASN1_INTEGER *millis;
 ASN1_INTEGER *micros;
 unsigned clock_precision_digits;

 unsigned flags;


 TS_serial_cb serial_cb;
 void *serial_cb_data;

 TS_time_cb time_cb;
 void *time_cb_data;

 TS_extension_cb extension_cb;
 void *extension_cb_data;


 TS_REQ *request;
 TS_RESP *response;
 TS_TST_INFO *tst_info;
 } TS_RESP_CTX;

struct stack_st_EVP_MD { _STACK stack; };



TS_RESP_CTX *TS_RESP_CTX_new(void);
void TS_RESP_CTX_free(TS_RESP_CTX *ctx);


int TS_RESP_CTX_set_signer_cert(TS_RESP_CTX *ctx, X509 *signer);


int TS_RESP_CTX_set_signer_key(TS_RESP_CTX *ctx, EVP_PKEY *key);


int TS_RESP_CTX_set_def_policy(TS_RESP_CTX *ctx, ASN1_OBJECT *def_policy);


int TS_RESP_CTX_set_certs(TS_RESP_CTX *ctx, struct stack_st_X509 *certs);



int TS_RESP_CTX_add_policy(TS_RESP_CTX *ctx, ASN1_OBJECT *policy);



int TS_RESP_CTX_add_md(TS_RESP_CTX *ctx, const EVP_MD *md);


int TS_RESP_CTX_set_accuracy(TS_RESP_CTX *ctx,
        int secs, int millis, int micros);



int TS_RESP_CTX_set_clock_precision_digits(TS_RESP_CTX *ctx,
        unsigned clock_precision_digits);




void TS_RESP_CTX_add_flags(TS_RESP_CTX *ctx, int flags);


void TS_RESP_CTX_set_serial_cb(TS_RESP_CTX *ctx, TS_serial_cb cb, void *data);


void TS_RESP_CTX_set_time_cb(TS_RESP_CTX *ctx, TS_time_cb cb, void *data);




void TS_RESP_CTX_set_extension_cb(TS_RESP_CTX *ctx,
      TS_extension_cb cb, void *data);


int TS_RESP_CTX_set_status_info(TS_RESP_CTX *ctx,
    int status, const char *text);


int TS_RESP_CTX_set_status_info_cond(TS_RESP_CTX *ctx,
         int status, const char *text);

int TS_RESP_CTX_add_failure_info(TS_RESP_CTX *ctx, int failure);


TS_REQ *TS_RESP_CTX_get_request(TS_RESP_CTX *ctx);

TS_TST_INFO *TS_RESP_CTX_get_tst_info(TS_RESP_CTX *ctx);






TS_RESP *TS_RESP_create_response(TS_RESP_CTX *ctx, BIO *req_bio);






int TS_RESP_verify_signature(PKCS7 *token, struct stack_st_X509 *certs,
        X509_STORE *store, X509 **signer_out);

typedef struct TS_verify_ctx
 {

 unsigned flags;


 X509_STORE *store;
 struct stack_st_X509 *certs;


 ASN1_OBJECT *policy;



 X509_ALGOR *md_alg;
 unsigned char *imprint;
 unsigned imprint_len;


 BIO *data;


 ASN1_INTEGER *nonce;


 GENERAL_NAME *tsa_name;
 } TS_VERIFY_CTX;

int TS_RESP_verify_response(TS_VERIFY_CTX *ctx, TS_RESP *response);
int TS_RESP_verify_token(TS_VERIFY_CTX *ctx, PKCS7 *token);







TS_VERIFY_CTX *TS_VERIFY_CTX_new(void);
void TS_VERIFY_CTX_init(TS_VERIFY_CTX *ctx);
void TS_VERIFY_CTX_free(TS_VERIFY_CTX *ctx);
void TS_VERIFY_CTX_cleanup(TS_VERIFY_CTX *ctx);

TS_VERIFY_CTX *TS_REQ_to_TS_VERIFY_CTX(TS_REQ *req, TS_VERIFY_CTX *ctx);



int TS_RESP_print_bio(BIO *bio, TS_RESP *a);
int TS_STATUS_INFO_print_bio(BIO *bio, TS_STATUS_INFO *a);
int TS_TST_INFO_print_bio(BIO *bio, TS_TST_INFO *a);



int TS_ASN1_INTEGER_print_bio(BIO *bio, const ASN1_INTEGER *num);
int TS_OBJ_print_bio(BIO *bio, const ASN1_OBJECT *obj);
int TS_ext_print_bio(BIO *bio, const struct stack_st_X509_EXTENSION *extensions);
int TS_X509_ALGOR_print_bio(BIO *bio, const X509_ALGOR *alg);
int TS_MSG_IMPRINT_print_bio(BIO *bio, TS_MSG_IMPRINT *msg);




X509 *TS_CONF_load_cert(const char *file);
struct stack_st_X509 *TS_CONF_load_certs(const char *file);
EVP_PKEY *TS_CONF_load_key(const char *file, const char *pass);
const char *TS_CONF_get_tsa_section(CONF *conf, const char *section);
int TS_CONF_set_serial(CONF *conf, const char *section, TS_serial_cb cb,
         TS_RESP_CTX *ctx);
int TS_CONF_set_crypto_device(CONF *conf, const char *section,
         const char *device);
int TS_CONF_set_default_engine(const char *name);
int TS_CONF_set_signer_cert(CONF *conf, const char *section,
       const char *cert, TS_RESP_CTX *ctx);
int TS_CONF_set_certs(CONF *conf, const char *section, const char *certs,
        TS_RESP_CTX *ctx);
int TS_CONF_set_signer_key(CONF *conf, const char *section,
      const char *key, const char *pass, TS_RESP_CTX *ctx);
int TS_CONF_set_def_policy(CONF *conf, const char *section,
      const char *policy, TS_RESP_CTX *ctx);
int TS_CONF_set_policies(CONF *conf, const char *section, TS_RESP_CTX *ctx);
int TS_CONF_set_digests(CONF *conf, const char *section, TS_RESP_CTX *ctx);
int TS_CONF_set_accuracy(CONF *conf, const char *section, TS_RESP_CTX *ctx);
int TS_CONF_set_clock_precision_digits(CONF *conf, const char *section,
           TS_RESP_CTX *ctx);
int TS_CONF_set_ordering(CONF *conf, const char *section, TS_RESP_CTX *ctx);
int TS_CONF_set_tsa_name(CONF *conf, const char *section, TS_RESP_CTX *ctx);
int TS_CONF_set_ess_cert_id_chain(CONF *conf, const char *section,
      TS_RESP_CTX *ctx);






void ERR_load_TS_strings(void);






typedef OPENSSL_STRING *OPENSSL_PSTRING;
struct stack_st_OPENSSL_PSTRING { _STACK stack; };

typedef struct txt_db_st
 {
 int num_fields;
 struct stack_st_OPENSSL_PSTRING *data;
 struct lhash_st_OPENSSL_STRING **index;
 int (**qual)(OPENSSL_STRING *);
 long error;
 long arg1;
 long arg2;
 OPENSSL_STRING *arg_row;
 } TXT_DB;


TXT_DB *TXT_DB_read(BIO *in, int num);
long TXT_DB_write(BIO *out, TXT_DB *db);




int TXT_DB_create_index(TXT_DB *db,int field,int (*qual)(OPENSSL_STRING *),
   LHASH_HASH_FN_TYPE hash, LHASH_COMP_FN_TYPE cmp);
void TXT_DB_free(TXT_DB *db);
OPENSSL_STRING *TXT_DB_get_by_index(TXT_DB *db, int idx, OPENSSL_STRING *value);
int TXT_DB_insert(TXT_DB *db, OPENSSL_STRING *value);















typedef struct {
 union {
  unsigned char c[(512/8)];

  double q[(512/8)/sizeof(double)];
  } H;
 unsigned char data[512/8];
 unsigned int bitoff;
 size_t bitlen[(256/8)/sizeof(size_t)];
 } WHIRLPOOL_CTX;





int WHIRLPOOL_Init (WHIRLPOOL_CTX *c);
int WHIRLPOOL_Update (WHIRLPOOL_CTX *c,const void *inp,size_t bytes);
void WHIRLPOOL_BitUpdate(WHIRLPOOL_CTX *c,const void *inp,size_t bits);
int WHIRLPOOL_Final (unsigned char *md,WHIRLPOOL_CTX *c);
unsigned char *WHIRLPOOL(const void *inp,size_t bytes,unsigned char *md);




enum openssl_consts {
_X509_CHECK_FLAG_DOT_SUBDOMAINS = 0x8000,
AES_BLOCK_SIZE = 16,
AES_DECRYPT = 0,
AES_ENCRYPT = 1,
AES_MAXNR = 14,
ASIdentifierChoice_asIdsOrRanges = 1,
ASIdentifierChoice_inherit = 0,
ASIdOrRange_id = 0,
ASIdOrRange_range = 1,
ASN1_AFLG_BROKEN = 4,
ASN1_AFLG_ENCODING = 2,
ASN1_AFLG_REFCOUNT = 1,
ASN1_F_A2D_ASN1_OBJECT = 100,
ASN1_F_A2I_ASN1_ENUMERATED = 101,
ASN1_F_A2I_ASN1_INTEGER = 102,
ASN1_F_A2I_ASN1_STRING = 103,
ASN1_F_APPEND_EXP = 176,
ASN1_F_ASN1_BIT_STRING_SET_BIT = 183,
ASN1_F_ASN1_CB = 177,
ASN1_F_ASN1_CHECK_TLEN = 104,
ASN1_F_ASN1_COLLATE_PRIMITIVE = 105,
ASN1_F_ASN1_COLLECT = 106,
ASN1_F_ASN1_D2I_EX_PRIMITIVE = 108,
ASN1_F_ASN1_D2I_FP = 109,
ASN1_F_ASN1_D2I_READ_BIO = 107,
ASN1_F_ASN1_DIGEST = 184,
ASN1_F_ASN1_DO_ADB = 110,
ASN1_F_ASN1_DUP = 111,
ASN1_F_ASN1_ENUMERATED_SET = 112,
ASN1_F_ASN1_ENUMERATED_TO_BN = 113,
ASN1_F_ASN1_EX_C2I = 204,
ASN1_F_ASN1_FIND_END = 190,
ASN1_F_ASN1_GENERALIZEDTIME_ADJ = 216,
ASN1_F_ASN1_GENERALIZEDTIME_SET = 185,
ASN1_F_ASN1_GENERATE_V3 = 178,
ASN1_F_ASN1_GET_OBJECT = 114,
ASN1_F_ASN1_HEADER_NEW = 115,
ASN1_F_ASN1_I2D_BIO = 116,
ASN1_F_ASN1_I2D_FP = 117,
ASN1_F_ASN1_INTEGER_SET = 118,
ASN1_F_ASN1_INTEGER_TO_BN = 119,
ASN1_F_ASN1_ITEM_D2I_FP = 206,
ASN1_F_ASN1_ITEM_DUP = 191,
ASN1_F_ASN1_ITEM_EX_COMBINE_NEW = 121,
ASN1_F_ASN1_ITEM_EX_D2I = 120,
ASN1_F_ASN1_ITEM_I2D_BIO = 192,
ASN1_F_ASN1_ITEM_I2D_FP = 193,
ASN1_F_ASN1_ITEM_PACK = 198,
ASN1_F_ASN1_ITEM_SIGN = 195,
ASN1_F_ASN1_ITEM_SIGN_CTX = 220,
ASN1_F_ASN1_ITEM_UNPACK = 199,
ASN1_F_ASN1_ITEM_VERIFY = 197,
ASN1_F_ASN1_MBSTRING_NCOPY = 122,
ASN1_F_ASN1_OBJECT_NEW = 123,
ASN1_F_ASN1_OUTPUT_DATA = 214,
ASN1_F_ASN1_PACK_STRING = 124,
ASN1_F_ASN1_PCTX_NEW = 205,
ASN1_F_ASN1_PKCS5_PBE_SET = 125,
ASN1_F_ASN1_SEQ_PACK = 126,
ASN1_F_ASN1_SEQ_UNPACK = 127,
ASN1_F_ASN1_SIGN = 128,
ASN1_F_ASN1_STR2TYPE = 179,
ASN1_F_ASN1_STRING_SET = 186,
ASN1_F_ASN1_STRING_TABLE_ADD = 129,
ASN1_F_ASN1_STRING_TYPE_NEW = 130,
ASN1_F_ASN1_TEMPLATE_EX_D2I = 132,
ASN1_F_ASN1_TEMPLATE_NEW = 133,
ASN1_F_ASN1_TEMPLATE_NOEXP_D2I = 131,
ASN1_F_ASN1_TIME_ADJ = 217,
ASN1_F_ASN1_TIME_SET = 175,
ASN1_F_ASN1_TYPE_GET_INT_OCTETSTRING = 134,
ASN1_F_ASN1_TYPE_GET_OCTETSTRING = 135,
ASN1_F_ASN1_UNPACK_STRING = 136,
ASN1_F_ASN1_UTCTIME_ADJ = 218,
ASN1_F_ASN1_UTCTIME_SET = 187,
ASN1_F_ASN1_VERIFY = 137,
ASN1_F_B64_READ_ASN1 = 209,
ASN1_F_B64_WRITE_ASN1 = 210,
ASN1_F_BIO_NEW_NDEF = 208,
ASN1_F_BITSTR_CB = 180,
ASN1_F_BN_TO_ASN1_ENUMERATED = 138,
ASN1_F_BN_TO_ASN1_INTEGER = 139,
ASN1_F_C2I_ASN1_BIT_STRING = 189,
ASN1_F_C2I_ASN1_INTEGER = 194,
ASN1_F_C2I_ASN1_OBJECT = 196,
ASN1_F_COLLECT_DATA = 140,
ASN1_F_D2I_ASN1_BIT_STRING = 141,
ASN1_F_D2I_ASN1_BOOLEAN = 142,
ASN1_F_D2I_ASN1_BYTES = 143,
ASN1_F_D2I_ASN1_GENERALIZEDTIME = 144,
ASN1_F_D2I_ASN1_HEADER = 145,
ASN1_F_D2I_ASN1_INTEGER = 146,
ASN1_F_D2I_ASN1_OBJECT = 147,
ASN1_F_D2I_ASN1_SET = 148,
ASN1_F_D2I_ASN1_TYPE_BYTES = 149,
ASN1_F_D2I_ASN1_UINTEGER = 150,
ASN1_F_D2I_ASN1_UTCTIME = 151,
ASN1_F_D2I_AUTOPRIVATEKEY = 207,
ASN1_F_D2I_NETSCAPE_RSA = 152,
ASN1_F_D2I_NETSCAPE_RSA_2 = 153,
ASN1_F_D2I_PRIVATEKEY = 154,
ASN1_F_D2I_PUBLICKEY = 155,
ASN1_F_D2I_RSA_NET = 200,
ASN1_F_D2I_RSA_NET_2 = 201,
ASN1_F_D2I_X509 = 156,
ASN1_F_D2I_X509_CINF = 157,
ASN1_F_D2I_X509_PKEY = 159,
ASN1_F_I2D_ASN1_BIO_STREAM = 211,
ASN1_F_I2D_ASN1_SET = 188,
ASN1_F_I2D_ASN1_TIME = 160,
ASN1_F_I2D_DSA_PUBKEY = 161,
ASN1_F_I2D_EC_PUBKEY = 181,
ASN1_F_I2D_PRIVATEKEY = 163,
ASN1_F_I2D_PUBLICKEY = 164,
ASN1_F_I2D_RSA_NET = 162,
ASN1_F_I2D_RSA_PUBKEY = 165,
ASN1_F_LONG_C2I = 166,
ASN1_F_OID_MODULE_INIT = 174,
ASN1_F_PARSE_TAGGING = 182,
ASN1_F_PKCS5_PBE_SET = 202,
ASN1_F_PKCS5_PBE_SET0_ALGOR = 215,
ASN1_F_PKCS5_PBE2_SET_IV = 167,
ASN1_F_PKCS5_PBKDF2_SET = 219,
ASN1_F_SMIME_READ_ASN1 = 212,
ASN1_F_SMIME_TEXT = 213,
ASN1_F_X509_CINF_NEW = 168,
ASN1_F_X509_CRL_ADD0_REVOKED = 169,
ASN1_F_X509_INFO_NEW = 170,
ASN1_F_X509_NAME_ENCODE = 203,
ASN1_F_X509_NAME_EX_D2I = 158,
ASN1_F_X509_NAME_EX_NEW = 171,
ASN1_F_X509_NEW = 172,
ASN1_F_X509_PKEY_NEW = 173,
ASN1_ITYPE_CHOICE = 0x2,
ASN1_ITYPE_COMPAT = 0x3,
ASN1_ITYPE_EXTERN = 0x4,
ASN1_ITYPE_MSTRING = 0x5,
ASN1_ITYPE_NDEF_SEQUENCE = 0x6,
ASN1_ITYPE_PRIMITIVE = 0x0,
ASN1_ITYPE_SEQUENCE = 0x1,
ASN1_OP_D2I_POST = 5,
ASN1_OP_D2I_PRE = 4,
ASN1_OP_DETACHED_POST = 13,
ASN1_OP_DETACHED_PRE = 12,
ASN1_OP_FREE_POST = 3,
ASN1_OP_FREE_PRE = 2,
ASN1_OP_I2D_POST = 7,
ASN1_OP_I2D_PRE = 6,
ASN1_OP_NEW_POST = 1,
ASN1_OP_NEW_PRE = 0,
ASN1_OP_PRINT_POST = 9,
ASN1_OP_PRINT_PRE = 8,
ASN1_OP_STREAM_POST = 11,
ASN1_OP_STREAM_PRE = 10,
ASN1_PCTX_FLAGS_NO_ANY_TYPE = 0x010,
ASN1_PCTX_FLAGS_NO_FIELD_NAME = 0x040,
ASN1_PCTX_FLAGS_NO_MSTRING_TYPE = 0x020,
ASN1_PCTX_FLAGS_NO_STRUCT_NAME = 0x100,
ASN1_PCTX_FLAGS_SHOW_ABSENT = 0x001,
ASN1_PCTX_FLAGS_SHOW_FIELD_STRUCT_NAME = 0x080,
ASN1_PCTX_FLAGS_SHOW_SEQUENCE = 0x002,
ASN1_PCTX_FLAGS_SHOW_SSOF = 0x004,
ASN1_PCTX_FLAGS_SHOW_TYPE = 0x008,
ASN1_PKEY_ALIAS = 0x1,
ASN1_PKEY_CTRL_CMS_ENVELOPE = 0x7,
ASN1_PKEY_CTRL_CMS_RI_TYPE = 0x8,
ASN1_PKEY_CTRL_CMS_SIGN = 0x5,
ASN1_PKEY_CTRL_DEFAULT_MD_NID = 0x3,
ASN1_PKEY_CTRL_PKCS7_ENCRYPT = 0x2,
ASN1_PKEY_CTRL_PKCS7_SIGN = 0x1,
ASN1_PKEY_DYNAMIC = 0x2,
ASN1_PKEY_SIGPARAM_NULL = 0x4,
ASN1_R_ADDING_OBJECT = 171,
ASN1_R_ASN1_PARSE_ERROR = 203,
ASN1_R_ASN1_SIG_PARSE_ERROR = 204,
ASN1_R_AUX_ERROR = 100,
ASN1_R_BAD_CLASS = 101,
ASN1_R_BAD_OBJECT_HEADER = 102,
ASN1_R_BAD_PASSWORD_READ = 103,
ASN1_R_BAD_TAG = 104,
ASN1_R_BMPSTRING_IS_WRONG_LENGTH = 214,
ASN1_R_BN_LIB = 105,
ASN1_R_BOOLEAN_IS_WRONG_LENGTH = 106,
ASN1_R_BUFFER_TOO_SMALL = 107,
ASN1_R_CIPHER_HAS_NO_OBJECT_IDENTIFIER = 108,
ASN1_R_CONTEXT_NOT_INITIALISED = 217,
ASN1_R_DATA_IS_WRONG = 109,
ASN1_R_DECODE_ERROR = 110,
ASN1_R_DECODING_ERROR = 111,
ASN1_R_DEPTH_EXCEEDED = 174,
ASN1_R_DIGEST_AND_KEY_TYPE_NOT_SUPPORTED = 198,
ASN1_R_ENCODE_ERROR = 112,
ASN1_R_ERROR_GETTING_TIME = 173,
ASN1_R_ERROR_LOADING_SECTION = 172,
ASN1_R_ERROR_PARSING_SET_ELEMENT = 113,
ASN1_R_ERROR_SETTING_CIPHER_PARAMS = 114,
ASN1_R_EXPECTING_A_BOOLEAN = 117,
ASN1_R_EXPECTING_A_TIME = 118,
ASN1_R_EXPECTING_AN_INTEGER = 115,
ASN1_R_EXPECTING_AN_OBJECT = 116,
ASN1_R_EXPLICIT_LENGTH_MISMATCH = 119,
ASN1_R_EXPLICIT_TAG_NOT_CONSTRUCTED = 120,
ASN1_R_FIELD_MISSING = 121,
ASN1_R_FIRST_NUM_TOO_LARGE = 122,
ASN1_R_HEADER_TOO_LONG = 123,
ASN1_R_ILLEGAL_BITSTRING_FORMAT = 175,
ASN1_R_ILLEGAL_BOOLEAN = 176,
ASN1_R_ILLEGAL_CHARACTERS = 124,
ASN1_R_ILLEGAL_FORMAT = 177,
ASN1_R_ILLEGAL_HEX = 178,
ASN1_R_ILLEGAL_IMPLICIT_TAG = 179,
ASN1_R_ILLEGAL_INTEGER = 180,
ASN1_R_ILLEGAL_NESTED_TAGGING = 181,
ASN1_R_ILLEGAL_NULL = 125,
ASN1_R_ILLEGAL_NULL_VALUE = 182,
ASN1_R_ILLEGAL_OBJECT = 183,
ASN1_R_ILLEGAL_OPTIONAL_ANY = 126,
ASN1_R_ILLEGAL_OPTIONS_ON_ITEM_TEMPLATE = 170,
ASN1_R_ILLEGAL_TAGGED_ANY = 127,
ASN1_R_ILLEGAL_TIME_VALUE = 184,
ASN1_R_INTEGER_NOT_ASCII_FORMAT = 185,
ASN1_R_INTEGER_TOO_LARGE_FOR_LONG = 128,
ASN1_R_INVALID_BIT_STRING_BITS_LEFT = 220,
ASN1_R_INVALID_BMPSTRING_LENGTH = 129,
ASN1_R_INVALID_DIGIT = 130,
ASN1_R_INVALID_MIME_TYPE = 205,
ASN1_R_INVALID_MODIFIER = 186,
ASN1_R_INVALID_NUMBER = 187,
ASN1_R_INVALID_OBJECT_ENCODING = 216,
ASN1_R_INVALID_SEPARATOR = 131,
ASN1_R_INVALID_TIME_FORMAT = 132,
ASN1_R_INVALID_UNIVERSALSTRING_LENGTH = 133,
ASN1_R_INVALID_UTF8STRING = 134,
ASN1_R_IV_TOO_LARGE = 135,
ASN1_R_LENGTH_ERROR = 136,
ASN1_R_LIST_ERROR = 188,
ASN1_R_MIME_NO_CONTENT_TYPE = 206,
ASN1_R_MIME_PARSE_ERROR = 207,
ASN1_R_MIME_SIG_PARSE_ERROR = 208,
ASN1_R_MISSING_EOC = 137,
ASN1_R_MISSING_SECOND_NUMBER = 138,
ASN1_R_MISSING_VALUE = 189,
ASN1_R_MSTRING_NOT_UNIVERSAL = 139,
ASN1_R_MSTRING_WRONG_TAG = 140,
ASN1_R_NESTED_ASN1_STRING = 197,
ASN1_R_NESTED_TOO_DEEP = 219,
ASN1_R_NO_CONTENT_TYPE = 209,
ASN1_R_NO_DEFAULT_DIGEST = 201,
ASN1_R_NO_MATCHING_CHOICE_TYPE = 143,
ASN1_R_NO_MULTIPART_BODY_FAILURE = 210,
ASN1_R_NO_MULTIPART_BOUNDARY = 211,
ASN1_R_NO_SIG_CONTENT_TYPE = 212,
ASN1_R_NON_HEX_CHARACTERS = 141,
ASN1_R_NOT_ASCII_FORMAT = 190,
ASN1_R_NOT_ENOUGH_DATA = 142,
ASN1_R_NULL_IS_WRONG_LENGTH = 144,
ASN1_R_OBJECT_NOT_ASCII_FORMAT = 191,
ASN1_R_ODD_NUMBER_OF_CHARS = 145,
ASN1_R_PRIVATE_KEY_HEADER_MISSING = 146,
ASN1_R_SECOND_NUMBER_TOO_LARGE = 147,
ASN1_R_SEQUENCE_LENGTH_MISMATCH = 148,
ASN1_R_SEQUENCE_NOT_CONSTRUCTED = 149,
ASN1_R_SEQUENCE_OR_SET_NEEDS_CONFIG = 192,
ASN1_R_SHORT_LINE = 150,
ASN1_R_SIG_INVALID_MIME_TYPE = 213,
ASN1_R_STREAMING_NOT_SUPPORTED = 202,
ASN1_R_STRING_TOO_LONG = 151,
ASN1_R_STRING_TOO_SHORT = 152,
ASN1_R_TAG_VALUE_TOO_HIGH = 153,
ASN1_R_THE_ASN1_OBJECT_IDENTIFIER_IS_NOT_KNOWN_FOR_THIS_MD = 154,
ASN1_R_TIME_NOT_ASCII_FORMAT = 193,
ASN1_R_TOO_LONG = 155,
ASN1_R_TYPE_NOT_CONSTRUCTED = 156,
ASN1_R_TYPE_NOT_PRIMITIVE = 218,
ASN1_R_UNABLE_TO_DECODE_RSA_KEY = 157,
ASN1_R_UNABLE_TO_DECODE_RSA_PRIVATE_KEY = 158,
ASN1_R_UNEXPECTED_EOC = 159,
ASN1_R_UNIVERSALSTRING_IS_WRONG_LENGTH = 215,
ASN1_R_UNKNOWN_FORMAT = 160,
ASN1_R_UNKNOWN_MESSAGE_DIGEST_ALGORITHM = 161,
ASN1_R_UNKNOWN_OBJECT_TYPE = 162,
ASN1_R_UNKNOWN_PUBLIC_KEY_TYPE = 163,
ASN1_R_UNKNOWN_SIGNATURE_ALGORITHM = 199,
ASN1_R_UNKNOWN_TAG = 194,
ASN1_R_UNKOWN_FORMAT = 195,
ASN1_R_UNSUPPORTED_ANY_DEFINED_BY_TYPE = 164,
ASN1_R_UNSUPPORTED_CIPHER = 165,
ASN1_R_UNSUPPORTED_ENCRYPTION_ALGORITHM = 166,
ASN1_R_UNSUPPORTED_PUBLIC_KEY_TYPE = 167,
ASN1_R_UNSUPPORTED_TYPE = 196,
ASN1_R_WRONG_PUBLIC_KEY_TYPE = 200,
ASN1_R_WRONG_TAG = 168,
ASN1_R_WRONG_TYPE = 169,
ASN1_STRFLGS_DUMP_ALL = 0x80,
ASN1_STRFLGS_DUMP_DER = 0x200,
ASN1_STRFLGS_DUMP_UNKNOWN = 0x100,
ASN1_STRFLGS_ESC_2253 = 1,
ASN1_STRFLGS_ESC_CTRL = 2,
ASN1_STRFLGS_ESC_MSB = 4,
ASN1_STRFLGS_ESC_QUOTE = 8,
ASN1_STRFLGS_IGNORE_TYPE = 0x20,
ASN1_STRFLGS_SHOW_TYPE = 0x40,
ASN1_STRFLGS_UTF8_CONVERT = 0x10,
ASN1_STRING_FLAG_CONT = 0x020,
ASN1_STRING_FLAG_MSTRING = 0x040,
ASN1_STRING_FLAG_NDEF = 0x010,
B_ASN1_BIT_STRING = 0x0400,
B_ASN1_BMPSTRING = 0x0800,
B_ASN1_GENERALIZEDTIME = 0x8000,
B_ASN1_GENERALSTRING = 0x0080,
B_ASN1_GRAPHICSTRING = 0x0020,
B_ASN1_IA5STRING = 0x0010,
B_ASN1_ISO64STRING = 0x0040,
B_ASN1_NUMERICSTRING = 0x0001,
B_ASN1_OCTET_STRING = 0x0200,
B_ASN1_PRINTABLESTRING = 0x0002,
B_ASN1_SEQUENCE = 0x10000,
B_ASN1_T61STRING = 0x0004,
B_ASN1_TELETEXSTRING = 0x0004,
B_ASN1_UNIVERSALSTRING = 0x0100,
B_ASN1_UNKNOWN = 0x1000,
B_ASN1_UTCTIME = 0x4000,
B_ASN1_UTF8STRING = 0x2000,
B_ASN1_VIDEOTEXSTRING = 0x0008,
B_ASN1_VISIBLESTRING = 0x0040,
BF_BLOCK = 8,
BF_DECRYPT = 0,
BF_ENCRYPT = 1,
BF_LONG_LOG2 = 3,
BF_ROUNDS = 16,
BIO_BIND_NORMAL = 0,
BIO_BIND_REUSEADDR = 2,
BIO_BIND_REUSEADDR_IF_UNUSED = 1,
BIO_C_DESTROY_BIO_PAIR = 139,
BIO_C_DO_STATE_MACHINE = 101,
BIO_C_FILE_SEEK = 128,
BIO_C_FILE_TELL = 133,
BIO_C_GET_ACCEPT = 124,
BIO_C_GET_BIND_MODE = 132,
BIO_C_GET_BUF_MEM_PTR = 115,
BIO_C_GET_BUFF_NUM_LINES = 116,
BIO_C_GET_CIPHER_CTX = 129,
BIO_C_GET_CIPHER_STATUS = 113,
BIO_C_GET_CONNECT = 123,
BIO_C_GET_EX_ARG = 154,
BIO_C_GET_FD = 105,
BIO_C_GET_FILE_PTR = 107,
BIO_C_GET_MD = 112,
BIO_C_GET_MD_CTX = 120,
BIO_C_GET_PREFIX = 150,
BIO_C_GET_PROXY_PARAM = 121,
BIO_C_GET_READ_REQUEST = 141,
BIO_C_GET_SOCKS = 134,
BIO_C_GET_SSL = 110,
BIO_C_GET_SSL_NUM_RENEGOTIATES = 126,
BIO_C_GET_SUFFIX = 152,
BIO_C_GET_WRITE_BUF_SIZE = 137,
BIO_C_GET_WRITE_GUARANTEE = 140,
BIO_C_MAKE_BIO_PAIR = 138,
BIO_C_NREAD = 144,
BIO_C_NREAD0 = 143,
BIO_C_NWRITE = 146,
BIO_C_NWRITE0 = 145,
BIO_C_RESET_READ_REQUEST = 147,
BIO_C_SET_ACCEPT = 118,
BIO_C_SET_BIND_MODE = 131,
BIO_C_SET_BUF_MEM = 114,
BIO_C_SET_BUFF_SIZE = 117,
BIO_C_SET_CONNECT = 100,
BIO_C_SET_EX_ARG = 153,
BIO_C_SET_FD = 104,
BIO_C_SET_FILE_PTR = 106,
BIO_C_SET_FILENAME = 108,
BIO_C_SET_MD = 111,
BIO_C_SET_MD_CTX = 148,
BIO_C_SET_NBIO = 102,
BIO_C_SET_PREFIX = 149,
BIO_C_SET_PROXY_PARAM = 103,
BIO_C_SET_SOCKS = 135,
BIO_C_SET_SSL = 109,
BIO_C_SET_SSL_RENEGOTIATE_BYTES = 125,
BIO_C_SET_SSL_RENEGOTIATE_TIMEOUT = 127,
BIO_C_SET_SUFFIX = 151,
BIO_C_SHUTDOWN_WR = 142,
BIO_C_SSL_MODE = 119,
BIO_CB_CTRL = 0x06,
BIO_CB_FREE = 0x01,
BIO_CB_GETS = 0x05,
BIO_CB_PUTS = 0x04,
BIO_CB_READ = 0x02,
BIO_CB_RETURN = 0x80,
BIO_CB_WRITE = 0x03,
BIO_CLOSE = 0x01,
BIO_CONN_S_BEFORE = 1,
BIO_CONN_S_BLOCKED_CONNECT = 7,
BIO_CONN_S_CONNECT = 5,
BIO_CONN_S_CREATE_SOCKET = 4,
BIO_CONN_S_GET_IP = 2,
BIO_CONN_S_GET_PORT = 3,
BIO_CONN_S_NBIO = 8,
BIO_CONN_S_OK = 6,
BIO_CTRL_DGRAM_GET_FALLBACK_MTU = 47,
BIO_CTRL_DGRAM_GET_MTU_OVERHEAD = 49,
BIO_CTRL_DGRAM_GET_PEER = 46,
BIO_CTRL_DGRAM_SCTP_ADD_AUTH_KEY = 51,
BIO_CTRL_DGRAM_SCTP_AUTH_CCS_RCVD = 53,
BIO_CTRL_DGRAM_SCTP_GET_PRINFO = 64,
BIO_CTRL_DGRAM_SCTP_GET_RCVINFO = 62,
BIO_CTRL_DGRAM_SCTP_GET_SNDINFO = 60,
BIO_CTRL_DGRAM_SCTP_NEXT_AUTH_KEY = 52,
BIO_CTRL_DGRAM_SCTP_SAVE_SHUTDOWN = 70,
BIO_CTRL_DGRAM_SCTP_SET_IN_HANDSHAKE = 50,
BIO_CTRL_DGRAM_SCTP_SET_PRINFO = 65,
BIO_CTRL_DGRAM_SCTP_SET_RCVINFO = 63,
BIO_CTRL_DGRAM_SCTP_SET_SNDINFO = 61,
BIO_CTRL_DGRAM_SET_DONT_FRAG = 48,
BIO_F_ACPT_STATE = 100,
BIO_F_BIO_ACCEPT = 101,
BIO_F_BIO_BER_GET_HEADER = 102,
BIO_F_BIO_CALLBACK_CTRL = 131,
BIO_F_BIO_CTRL = 103,
BIO_F_BIO_GET_ACCEPT_SOCKET = 105,
BIO_F_BIO_GET_HOST_IP = 106,
BIO_F_BIO_GET_PORT = 107,
BIO_F_BIO_GETHOSTBYNAME = 120,
BIO_F_BIO_GETS = 104,
BIO_F_BIO_MAKE_PAIR = 121,
BIO_F_BIO_NEW = 108,
BIO_F_BIO_NEW_FILE = 109,
BIO_F_BIO_NEW_MEM_BUF = 126,
BIO_F_BIO_NREAD = 123,
BIO_F_BIO_NREAD0 = 124,
BIO_F_BIO_NWRITE = 125,
BIO_F_BIO_NWRITE0 = 122,
BIO_F_BIO_PUTS = 110,
BIO_F_BIO_READ = 111,
BIO_F_BIO_SOCK_INIT = 112,
BIO_F_BIO_WRITE = 113,
BIO_F_BUFFER_CTRL = 114,
BIO_F_CONN_CTRL = 127,
BIO_F_CONN_STATE = 115,
BIO_F_DGRAM_SCTP_READ = 132,
BIO_F_DGRAM_SCTP_WRITE = 133,
BIO_F_FILE_CTRL = 116,
BIO_F_FILE_READ = 130,
BIO_F_LINEBUFFER_CTRL = 129,
BIO_F_MEM_READ = 128,
BIO_F_MEM_WRITE = 117,
BIO_F_SSL_NEW = 118,
BIO_F_WSASTARTUP = 119,
BIO_FLAGS_BASE64_NO_NL = 0x100,
BIO_FLAGS_IO_SPECIAL = 0x04,
BIO_FLAGS_MEM_RDONLY = 0x200,
BIO_FLAGS_READ = 0x01,
BIO_FLAGS_SHOULD_RETRY = 0x08,
BIO_FLAGS_UPLINK = 0,
BIO_FLAGS_WRITE = 0x02,
BIO_FP_APPEND = 0x08,
BIO_FP_READ = 0x02,
BIO_FP_TEXT = 0x10,
BIO_FP_WRITE = 0x04,
BIO_GHBN_CTRL_CACHE_SIZE = 3,
BIO_GHBN_CTRL_FLUSH = 5,
BIO_GHBN_CTRL_GET_ENTRY = 4,
BIO_GHBN_CTRL_HITS = 1,
BIO_GHBN_CTRL_MISSES = 2,
BIO_NOCLOSE = 0x00,
BIO_R_ACCEPT_ERROR = 100,
BIO_R_BAD_FOPEN_MODE = 101,
BIO_R_BAD_HOSTNAME_LOOKUP = 102,
BIO_R_BROKEN_PIPE = 124,
BIO_R_CONNECT_ERROR = 103,
BIO_R_EOF_ON_MEMORY_BIO = 127,
BIO_R_ERROR_SETTING_NBIO = 104,
BIO_R_ERROR_SETTING_NBIO_ON_ACCEPT_SOCKET = 106,
BIO_R_ERROR_SETTING_NBIO_ON_ACCEPTED_SOCKET = 105,
BIO_R_GETHOSTBYNAME_ADDR_IS_NOT_AF_INET = 107,
BIO_R_IN_USE = 123,
BIO_R_INVALID_ARGUMENT = 125,
BIO_R_INVALID_IP_ADDRESS = 108,
BIO_R_KEEPALIVE = 109,
BIO_R_NBIO_CONNECT_ERROR = 110,
BIO_R_NO_ACCEPT_PORT_SPECIFIED = 111,
BIO_R_NO_HOSTNAME_SPECIFIED = 112,
BIO_R_NO_PORT_DEFINED = 113,
BIO_R_NO_PORT_SPECIFIED = 114,
BIO_R_NO_SUCH_FILE = 128,
BIO_R_NULL_PARAMETER = 115,
BIO_R_TAG_MISMATCH = 116,
BIO_R_UNABLE_TO_BIND_SOCKET = 117,
BIO_R_UNABLE_TO_CREATE_SOCKET = 118,
BIO_R_UNABLE_TO_LISTEN_SOCKET = 119,
BIO_R_UNINITIALIZED = 120,
BIO_R_UNSUPPORTED_METHOD = 121,
BIO_R_WRITE_TO_READ_ONLY_BIO = 126,
BIO_R_WSASTARTUP = 122,
BIO_RR_ACCEPT = 0x03,
BIO_RR_CONNECT = 0x02,
BIO_RR_SSL_X509_LOOKUP = 0x01,
BIO_TYPE_FILTER = 0x0200,
BIO_TYPE_NONE = 0,
BIO_TYPE_SOURCE_SINK = 0x0400,
BN_BLINDING_NO_RECREATE = 0x00000002,
BN_BLINDING_NO_UPDATE = 0x00000001,
BN_F_BN_BLINDING_CONVERT_EX = 100,
BN_F_BN_BLINDING_CREATE_PARAM = 128,
BN_F_BN_BLINDING_INVERT_EX = 101,
BN_F_BN_BLINDING_NEW = 102,
BN_F_BN_BLINDING_UPDATE = 103,
BN_F_BN_BN2DEC = 104,
BN_F_BN_BN2HEX = 105,
BN_F_BN_CTX_GET = 116,
BN_F_BN_CTX_NEW = 106,
BN_F_BN_CTX_START = 129,
BN_F_BN_DIV = 107,
BN_F_BN_DIV_NO_BRANCH = 138,
BN_F_BN_DIV_RECP = 130,
BN_F_BN_EXP = 123,
BN_F_BN_EXPAND_INTERNAL = 120,
BN_F_BN_EXPAND2 = 108,
BN_F_BN_GF2M_MOD = 131,
BN_F_BN_GF2M_MOD_EXP = 132,
BN_F_BN_GF2M_MOD_MUL = 133,
BN_F_BN_GF2M_MOD_SOLVE_QUAD = 134,
BN_F_BN_GF2M_MOD_SOLVE_QUAD_ARR = 135,
BN_F_BN_GF2M_MOD_SQR = 136,
BN_F_BN_GF2M_MOD_SQRT = 137,
BN_F_BN_LSHIFT = 145,
BN_F_BN_MOD_EXP_MONT = 109,
BN_F_BN_MOD_EXP_MONT_CONSTTIME = 124,
BN_F_BN_MOD_EXP_MONT_WORD = 117,
BN_F_BN_MOD_EXP_RECP = 125,
BN_F_BN_MOD_EXP_SIMPLE = 126,
BN_F_BN_MOD_EXP2_MONT = 118,
BN_F_BN_MOD_INVERSE = 110,
BN_F_BN_MOD_INVERSE_NO_BRANCH = 139,
BN_F_BN_MOD_LSHIFT_QUICK = 119,
BN_F_BN_MOD_MUL_RECIPROCAL = 111,
BN_F_BN_MOD_SQRT = 121,
BN_F_BN_MPI2BN = 112,
BN_F_BN_NEW = 113,
BN_F_BN_RAND = 114,
BN_F_BN_RAND_RANGE = 122,
BN_F_BN_RSHIFT = 146,
BN_F_BN_USUB = 115,
BN_F_BNRAND = 127,
BN_FLG_CONSTTIME = 0x04,
BN_FLG_FREE = 0x8000,
BN_FLG_MALLOCED = 0x01,
BN_FLG_STATIC_DATA = 0x02,
BN_R_ARG2_LT_ARG3 = 100,
BN_R_BAD_RECIPROCAL = 101,
BN_R_BIGNUM_TOO_LONG = 114,
BN_R_BITS_TOO_SMALL = 118,
BN_R_CALLED_WITH_EVEN_MODULUS = 102,
BN_R_DIV_BY_ZERO = 103,
BN_R_ENCODING_ERROR = 104,
BN_R_EXPAND_ON_STATIC_BIGNUM_DATA = 105,
BN_R_INPUT_NOT_REDUCED = 110,
BN_R_INVALID_LENGTH = 106,
BN_R_INVALID_RANGE = 115,
BN_R_INVALID_SHIFT = 119,
BN_R_NO_INVERSE = 108,
BN_R_NO_SOLUTION = 116,
BN_R_NOT_A_SQUARE = 111,
BN_R_NOT_INITIALIZED = 107,
BN_R_P_IS_NOT_PRIME = 112,
BN_R_TOO_MANY_ITERATIONS = 113,
BN_R_TOO_MANY_TEMPORARY_VARIABLES = 109,
BUF_F_BUF_MEM_GROW = 100,
BUF_F_BUF_MEM_GROW_CLEAN = 105,
BUF_F_BUF_MEM_NEW = 101,
BUF_F_BUF_MEMDUP = 103,
BUF_F_BUF_STRDUP = 102,
BUF_F_BUF_STRNDUP = 104,
CAMELLIA_BLOCK_SIZE = 16,
CAMELLIA_DECRYPT = 0,
CAMELLIA_ENCRYPT = 1,
CAMELLIA_TABLE_BYTE_LEN = 272,
CAST_BLOCK = 8,
CAST_DECRYPT = 0,
CAST_ENCRYPT = 1,
CAST_KEY_LENGTH = 16,
CERT_PKEY_CA_PARAM = 0x80,
CERT_PKEY_CA_SIGNATURE = 0x20,
CERT_PKEY_CERT_TYPE = 0x400,
CERT_PKEY_EE_PARAM = 0x40,
CERT_PKEY_EE_SIGNATURE = 0x10,
CERT_PKEY_EXPLICIT_SIGN = 0x100,
CERT_PKEY_ISSUER_NAME = 0x200,
CERT_PKEY_SIGN = 0x2,
CERT_PKEY_SUITEB = 0x800,
CERT_PKEY_VALID = 0x1,
CHARTYPE_FIRST_ESC_2253 = 0x20,
CHARTYPE_LAST_ESC_2253 = 0x40,
CHARTYPE_PRINTABLESTRING = 0x10,
CMS_BINARY = 0x80,
CMS_CRLFEOL = 0x800,
CMS_DEBUG_DECRYPT = 0x20000,
CMS_DETACHED = 0x40,
CMS_F_CHECK_CONTENT = 99,
CMS_F_CMS_ADD0_CERT = 164,
CMS_F_CMS_ADD0_RECIPIENT_KEY = 100,
CMS_F_CMS_ADD0_RECIPIENT_PASSWORD = 165,
CMS_F_CMS_ADD1_RECEIPTREQUEST = 158,
CMS_F_CMS_ADD1_RECIPIENT_CERT = 101,
CMS_F_CMS_ADD1_SIGNER = 102,
CMS_F_CMS_ADD1_SIGNINGTIME = 103,
CMS_F_CMS_COMPRESS = 104,
CMS_F_CMS_COMPRESSEDDATA_CREATE = 105,
CMS_F_CMS_COMPRESSEDDATA_INIT_BIO = 106,
CMS_F_CMS_COPY_CONTENT = 107,
CMS_F_CMS_COPY_MESSAGEDIGEST = 108,
CMS_F_CMS_DATA = 109,
CMS_F_CMS_DATAFINAL = 110,
CMS_F_CMS_DATAINIT = 111,
CMS_F_CMS_DECRYPT = 112,
CMS_F_CMS_DECRYPT_SET1_KEY = 113,
CMS_F_CMS_DECRYPT_SET1_PASSWORD = 166,
CMS_F_CMS_DECRYPT_SET1_PKEY = 114,
CMS_F_CMS_DIGEST_VERIFY = 118,
CMS_F_CMS_DIGESTALGORITHM_FIND_CTX = 115,
CMS_F_CMS_DIGESTALGORITHM_INIT_BIO = 116,
CMS_F_CMS_DIGESTEDDATA_DO_FINAL = 117,
CMS_F_CMS_ENCODE_RECEIPT = 161,
CMS_F_CMS_ENCRYPT = 119,
CMS_F_CMS_ENCRYPTEDCONTENT_INIT_BIO = 120,
CMS_F_CMS_ENCRYPTEDDATA_DECRYPT = 121,
CMS_F_CMS_ENCRYPTEDDATA_ENCRYPT = 122,
CMS_F_CMS_ENCRYPTEDDATA_SET1_KEY = 123,
CMS_F_CMS_ENV_ASN1_CTRL = 171,
CMS_F_CMS_ENVELOPED_DATA_INIT = 126,
CMS_F_CMS_ENVELOPEDDATA_CREATE = 124,
CMS_F_CMS_ENVELOPEDDATA_INIT_BIO = 125,
CMS_F_CMS_FINAL = 127,
CMS_F_CMS_GET0_CERTIFICATE_CHOICES = 128,
CMS_F_CMS_GET0_CONTENT = 129,
CMS_F_CMS_GET0_ECONTENT_TYPE = 130,
CMS_F_CMS_GET0_ENVELOPED = 131,
CMS_F_CMS_GET0_REVOCATION_CHOICES = 132,
CMS_F_CMS_GET0_SIGNED = 133,
CMS_F_CMS_MSGSIGDIGEST_ADD1 = 162,
CMS_F_CMS_RECEIPT_VERIFY = 160,
CMS_F_CMS_RECEIPTREQUEST_CREATE0 = 159,
CMS_F_CMS_RECIPIENTINFO_DECRYPT = 134,
CMS_F_CMS_RECIPIENTINFO_ENCRYPT = 169,
CMS_F_CMS_RECIPIENTINFO_KARI_ENCRYPT = 178,
CMS_F_CMS_RECIPIENTINFO_KARI_GET0_ALG = 175,
CMS_F_CMS_RECIPIENTINFO_KARI_GET0_ORIG_ID = 173,
CMS_F_CMS_RECIPIENTINFO_KARI_GET0_REKS = 172,
CMS_F_CMS_RECIPIENTINFO_KARI_ORIG_ID_CMP = 174,
CMS_F_CMS_RECIPIENTINFO_KEKRI_DECRYPT = 135,
CMS_F_CMS_RECIPIENTINFO_KEKRI_ENCRYPT = 136,
CMS_F_CMS_RECIPIENTINFO_KEKRI_GET0_ID = 137,
CMS_F_CMS_RECIPIENTINFO_KEKRI_ID_CMP = 138,
CMS_F_CMS_RECIPIENTINFO_KTRI_CERT_CMP = 139,
CMS_F_CMS_RECIPIENTINFO_KTRI_DECRYPT = 140,
CMS_F_CMS_RECIPIENTINFO_KTRI_ENCRYPT = 141,
CMS_F_CMS_RECIPIENTINFO_KTRI_GET0_ALGS = 142,
CMS_F_CMS_RECIPIENTINFO_KTRI_GET0_SIGNER_ID = 143,
CMS_F_CMS_RECIPIENTINFO_PWRI_CRYPT = 167,
CMS_F_CMS_RECIPIENTINFO_SET0_KEY = 144,
CMS_F_CMS_RECIPIENTINFO_SET0_PASSWORD = 168,
CMS_F_CMS_RECIPIENTINFO_SET0_PKEY = 145,
CMS_F_CMS_SD_ASN1_CTRL = 170,
CMS_F_CMS_SET_DETACHED = 147,
CMS_F_CMS_SET1_IAS = 176,
CMS_F_CMS_SET1_KEYID = 177,
CMS_F_CMS_SET1_SIGNERIDENTIFIER = 146,
CMS_F_CMS_SIGN = 148,
CMS_F_CMS_SIGN_RECEIPT = 163,
CMS_F_CMS_SIGNED_DATA_INIT = 149,
CMS_F_CMS_SIGNERINFO_CONTENT_SIGN = 150,
CMS_F_CMS_SIGNERINFO_SIGN = 151,
CMS_F_CMS_SIGNERINFO_VERIFY = 152,
CMS_F_CMS_SIGNERINFO_VERIFY_CERT = 153,
CMS_F_CMS_SIGNERINFO_VERIFY_CONTENT = 154,
CMS_F_CMS_STREAM = 155,
CMS_F_CMS_UNCOMPRESS = 156,
CMS_F_CMS_VERIFY = 157,
CMS_KEY_PARAM = 0x40000,
CMS_NO_ATTR_VERIFY = 0x8,
CMS_NO_CONTENT_VERIFY = 0x4,
CMS_NO_SIGNER_CERT_VERIFY = 0x20,
CMS_NOATTR = 0x100,
CMS_NOCERTS = 0x2,
CMS_NOCRL = 0x2000,
CMS_NOINTERN = 0x10,
CMS_NOOLDMIMETYPE = 0x400,
CMS_NOSMIMECAP = 0x200,
CMS_NOVERIFY = 0x20,
CMS_PARTIAL = 0x4000,
CMS_R_ADD_SIGNER_ERROR = 99,
CMS_R_CERTIFICATE_ALREADY_PRESENT = 175,
CMS_R_CERTIFICATE_HAS_NO_KEYID = 160,
CMS_R_CERTIFICATE_VERIFY_ERROR = 100,
CMS_R_CIPHER_INITIALISATION_ERROR = 101,
CMS_R_CIPHER_PARAMETER_INITIALISATION_ERROR = 102,
CMS_R_CMS_DATAFINAL_ERROR = 103,
CMS_R_CMS_LIB = 104,
CMS_R_CONTENT_NOT_FOUND = 105,
CMS_R_CONTENT_TYPE_MISMATCH = 171,
CMS_R_CONTENT_TYPE_NOT_COMPRESSED_DATA = 106,
CMS_R_CONTENT_TYPE_NOT_ENVELOPED_DATA = 107,
CMS_R_CONTENT_TYPE_NOT_SIGNED_DATA = 108,
CMS_R_CONTENT_VERIFY_ERROR = 109,
CMS_R_CONTENTIDENTIFIER_MISMATCH = 170,
CMS_R_CTRL_ERROR = 110,
CMS_R_CTRL_FAILURE = 111,
CMS_R_DECRYPT_ERROR = 112,
CMS_R_DIGEST_ERROR = 161,
CMS_R_ERROR_GETTING_PUBLIC_KEY = 113,
CMS_R_ERROR_READING_MESSAGEDIGEST_ATTRIBUTE = 114,
CMS_R_ERROR_SETTING_KEY = 115,
CMS_R_ERROR_SETTING_RECIPIENTINFO = 116,
CMS_R_INVALID_ENCRYPTED_KEY_LENGTH = 117,
CMS_R_INVALID_KEY_ENCRYPTION_PARAMETER = 176,
CMS_R_INVALID_KEY_LENGTH = 118,
CMS_R_MD_BIO_INIT_ERROR = 119,
CMS_R_MESSAGEDIGEST_ATTRIBUTE_WRONG_LENGTH = 120,
CMS_R_MESSAGEDIGEST_WRONG_LENGTH = 121,
CMS_R_MSGSIGDIGEST_ERROR = 172,
CMS_R_MSGSIGDIGEST_VERIFICATION_FAILURE = 162,
CMS_R_MSGSIGDIGEST_WRONG_LENGTH = 163,
CMS_R_NEED_ONE_SIGNER = 164,
CMS_R_NO_CIPHER = 126,
CMS_R_NO_CONTENT = 127,
CMS_R_NO_CONTENT_TYPE = 173,
CMS_R_NO_DEFAULT_DIGEST = 128,
CMS_R_NO_DIGEST_SET = 129,
CMS_R_NO_KEY = 130,
CMS_R_NO_KEY_OR_CERT = 174,
CMS_R_NO_MATCHING_DIGEST = 131,
CMS_R_NO_MATCHING_RECIPIENT = 132,
CMS_R_NO_MATCHING_SIGNATURE = 166,
CMS_R_NO_MSGSIGDIGEST = 167,
CMS_R_NO_PASSWORD = 178,
CMS_R_NO_PRIVATE_KEY = 133,
CMS_R_NO_PUBLIC_KEY = 134,
CMS_R_NO_RECEIPT_REQUEST = 168,
CMS_R_NO_SIGNERS = 135,
CMS_R_NOT_A_SIGNED_RECEIPT = 165,
CMS_R_NOT_ENCRYPTED_DATA = 122,
CMS_R_NOT_KEK = 123,
CMS_R_NOT_KEY_AGREEMENT = 181,
CMS_R_NOT_KEY_TRANSPORT = 124,
CMS_R_NOT_PWRI = 177,
CMS_R_NOT_SUPPORTED_FOR_THIS_KEY_TYPE = 125,
CMS_R_PRIVATE_KEY_DOES_NOT_MATCH_CERTIFICATE = 136,
CMS_R_RECEIPT_DECODE_ERROR = 169,
CMS_R_RECIPIENT_ERROR = 137,
CMS_R_SIGNER_CERTIFICATE_NOT_FOUND = 138,
CMS_R_SIGNFINAL_ERROR = 139,
CMS_R_SMIME_TEXT_ERROR = 140,
CMS_R_STORE_INIT_ERROR = 141,
CMS_R_TYPE_NOT_COMPRESSED_DATA = 142,
CMS_R_TYPE_NOT_DATA = 143,
CMS_R_TYPE_NOT_DIGESTED_DATA = 144,
CMS_R_TYPE_NOT_ENCRYPTED_DATA = 145,
CMS_R_TYPE_NOT_ENVELOPED_DATA = 146,
CMS_R_UNABLE_TO_FINALIZE_CONTEXT = 147,
CMS_R_UNKNOWN_CIPHER = 148,
CMS_R_UNKNOWN_DIGEST_ALGORIHM = 149,
CMS_R_UNKNOWN_ID = 150,
CMS_R_UNSUPPORTED_COMPRESSION_ALGORITHM = 151,
CMS_R_UNSUPPORTED_CONTENT_TYPE = 152,
CMS_R_UNSUPPORTED_KEK_ALGORITHM = 153,
CMS_R_UNSUPPORTED_KEY_ENCRYPTION_ALGORITHM = 179,
CMS_R_UNSUPPORTED_RECIPIENT_TYPE = 154,
CMS_R_UNSUPPORTED_RECPIENTINFO_TYPE = 155,
CMS_R_UNSUPPORTED_TYPE = 156,
CMS_R_UNWRAP_ERROR = 157,
CMS_R_UNWRAP_FAILURE = 180,
CMS_R_VERIFICATION_FAILURE = 158,
CMS_R_WRAP_ERROR = 159,
CMS_RECIPINFO_AGREE = 1,
CMS_RECIPINFO_KEK = 2,
CMS_RECIPINFO_NONE = -1,
CMS_RECIPINFO_OTHER = 4,
CMS_RECIPINFO_PASS = 3,
CMS_RECIPINFO_TRANS = 0,
CMS_REUSE_DIGEST = 0x8000,
CMS_SIGNERINFO_ISSUER_SERIAL = 0,
CMS_SIGNERINFO_KEYIDENTIFIER = 1,
CMS_STREAM = 0x1000,
CMS_TEXT = 0x1,
CMS_USE_KEYID = 0x10000,
COMP_F_BIO_ZLIB_FLUSH = 99,
COMP_F_BIO_ZLIB_NEW = 100,
COMP_F_BIO_ZLIB_READ = 101,
COMP_F_BIO_ZLIB_WRITE = 102,
COMP_R_ZLIB_DEFLATE_ERROR = 99,
COMP_R_ZLIB_INFLATE_ERROR = 100,
COMP_R_ZLIB_NOT_SUPPORTED = 101,
CONF_F_CONF_DUMP_FP = 104,
CONF_F_CONF_LOAD = 100,
CONF_F_CONF_LOAD_BIO = 102,
CONF_F_CONF_LOAD_FP = 103,
CONF_F_CONF_MODULES_LOAD = 116,
CONF_F_CONF_PARSE_LIST = 119,
CONF_F_DEF_LOAD = 120,
CONF_F_DEF_LOAD_BIO = 121,
CONF_F_MODULE_INIT = 115,
CONF_F_MODULE_LOAD_DSO = 117,
CONF_F_MODULE_RUN = 118,
CONF_F_NCONF_DUMP_BIO = 105,
CONF_F_NCONF_DUMP_FP = 106,
CONF_F_NCONF_GET_NUMBER = 107,
CONF_F_NCONF_GET_NUMBER_E = 112,
CONF_F_NCONF_GET_SECTION = 108,
CONF_F_NCONF_GET_STRING = 109,
CONF_F_NCONF_LOAD = 113,
CONF_F_NCONF_LOAD_BIO = 110,
CONF_F_NCONF_LOAD_FP = 114,
CONF_F_NCONF_NEW = 111,
CONF_F_STR_COPY = 101,
CONF_MFLAGS_DEFAULT_SECTION = 0x20,
CONF_MFLAGS_IGNORE_ERRORS = 0x1,
CONF_MFLAGS_IGNORE_MISSING_FILE = 0x10,
CONF_MFLAGS_IGNORE_RETURN_CODES = 0x2,
CONF_MFLAGS_NO_DSO = 0x8,
CONF_MFLAGS_SILENT = 0x4,
CONF_R_ERROR_LOADING_DSO = 110,
CONF_R_LIST_CANNOT_BE_NULL = 115,
CONF_R_MISSING_CLOSE_SQUARE_BRACKET = 100,
CONF_R_MISSING_EQUAL_SIGN = 101,
CONF_R_MISSING_FINISH_FUNCTION = 111,
CONF_R_MISSING_INIT_FUNCTION = 112,
CONF_R_MODULE_INITIALIZATION_ERROR = 109,
CONF_R_NO_CLOSE_BRACE = 102,
CONF_R_NO_CONF = 105,
CONF_R_NO_CONF_OR_ENVIRONMENT_VARIABLE = 106,
CONF_R_NO_SECTION = 107,
CONF_R_NO_SUCH_FILE = 114,
CONF_R_NO_VALUE = 108,
CONF_R_UNABLE_TO_CREATE_NEW_SECTION = 103,
CONF_R_UNKNOWN_MODULE_NAME = 113,
CONF_R_VARIABLE_EXPANSION_TOO_LONG = 116,
CONF_R_VARIABLE_HAS_NO_VALUE = 104,
CRL_REASON_AA_COMPROMISE = 10,
CRL_REASON_AFFILIATION_CHANGED = 3,
CRL_REASON_CA_COMPROMISE = 2,
CRL_REASON_CERTIFICATE_HOLD = 6,
CRL_REASON_CESSATION_OF_OPERATION = 5,
CRL_REASON_KEY_COMPROMISE = 1,
CRL_REASON_NONE = -1,
CRL_REASON_PRIVILEGE_WITHDRAWN = 9,
CRL_REASON_REMOVE_FROM_CRL = 8,
CRL_REASON_SUPERSEDED = 4,
CRL_REASON_UNSPECIFIED = 0,
CRLDP_ALL_REASONS = 0x807f,
CRYPTO_EX_INDEX_BIO = 0,
CRYPTO_EX_INDEX_COMP = 14,
CRYPTO_EX_INDEX_DH = 8,
CRYPTO_EX_INDEX_DSA = 7,
CRYPTO_EX_INDEX_ECDH = 13,
CRYPTO_EX_INDEX_ECDSA = 12,
CRYPTO_EX_INDEX_ENGINE = 9,
CRYPTO_EX_INDEX_RSA = 6,
CRYPTO_EX_INDEX_SSL = 1,
CRYPTO_EX_INDEX_SSL_CTX = 2,
CRYPTO_EX_INDEX_SSL_SESSION = 3,
CRYPTO_EX_INDEX_STORE = 15,
CRYPTO_EX_INDEX_UI = 11,
CRYPTO_EX_INDEX_USER = 100,
CRYPTO_EX_INDEX_X509 = 10,
CRYPTO_EX_INDEX_X509_STORE = 4,
CRYPTO_EX_INDEX_X509_STORE_CTX = 5,
CRYPTO_F_CRYPTO_GET_EX_NEW_INDEX = 100,
CRYPTO_F_CRYPTO_GET_NEW_DYNLOCKID = 103,
CRYPTO_F_CRYPTO_GET_NEW_LOCKID = 101,
CRYPTO_F_CRYPTO_SET_EX_DATA = 102,
CRYPTO_F_DEF_ADD_INDEX = 104,
CRYPTO_F_DEF_GET_CLASS = 105,
CRYPTO_F_FIPS_MODE_SET = 109,
CRYPTO_F_INT_DUP_EX_DATA = 106,
CRYPTO_F_INT_FREE_EX_DATA = 107,
CRYPTO_F_INT_NEW_EX_DATA = 108,
CRYPTO_LOCK = 1,
CRYPTO_LOCK_BIO = 21,
CRYPTO_LOCK_BN = 35,
CRYPTO_LOCK_COMP = 38,
CRYPTO_LOCK_DH = 26,
CRYPTO_LOCK_DSA = 8,
CRYPTO_LOCK_DSO = 28,
CRYPTO_LOCK_DYNLOCK = 29,
CRYPTO_LOCK_EC = 33,
CRYPTO_LOCK_EC_PRE_COMP = 36,
CRYPTO_LOCK_ECDH = 34,
CRYPTO_LOCK_ECDSA = 32,
CRYPTO_LOCK_ENGINE = 30,
CRYPTO_LOCK_ERR = 1,
CRYPTO_LOCK_EVP_PKEY = 10,
CRYPTO_LOCK_EX_DATA = 2,
CRYPTO_LOCK_FIPS = 39,
CRYPTO_LOCK_FIPS2 = 40,
CRYPTO_LOCK_GETHOSTBYNAME = 22,
CRYPTO_LOCK_GETSERVBYNAME = 23,
CRYPTO_LOCK_MALLOC = 20,
CRYPTO_LOCK_MALLOC2 = 27,
CRYPTO_LOCK_RAND = 18,
CRYPTO_LOCK_RAND2 = 19,
CRYPTO_LOCK_READDIR = 24,
CRYPTO_LOCK_RSA = 9,
CRYPTO_LOCK_RSA_BLINDING = 25,
CRYPTO_LOCK_SSL = 16,
CRYPTO_LOCK_SSL_CERT = 13,
CRYPTO_LOCK_SSL_CTX = 12,
CRYPTO_LOCK_SSL_METHOD = 17,
CRYPTO_LOCK_SSL_SESS_CERT = 15,
CRYPTO_LOCK_SSL_SESSION = 14,
CRYPTO_LOCK_STORE = 37,
CRYPTO_LOCK_UI = 31,
CRYPTO_LOCK_X509 = 3,
CRYPTO_LOCK_X509_CRL = 6,
CRYPTO_LOCK_X509_INFO = 4,
CRYPTO_LOCK_X509_PKEY = 5,
CRYPTO_LOCK_X509_REQ = 7,
CRYPTO_LOCK_X509_STORE = 11,
CRYPTO_NUM_LOCKS = 41,
CRYPTO_R_FIPS_MODE_NOT_SUPPORTED = 101,
CRYPTO_R_NO_DYNLOCK_CREATE_CALLBACK = 100,
CRYPTO_READ = 4,
CRYPTO_UNLOCK = 2,
CRYPTO_WRITE = 8,
CTX_TEST = 0x1,
DB_ERROR_INDEX_CLASH = 2,
DB_ERROR_INDEX_OUT_OF_RANGE = 3,
DB_ERROR_INSERT_INDEX_CLASH = 5,
DB_ERROR_MALLOC = 1,
DB_ERROR_NO_INDEX = 4,
DB_ERROR_OK = 0,
DB_NUMBER = 6,
DB_srpgN = 4,
DB_srpid = 3,
DB_srpinfo = 5,
DB_srpsalt = 2,
DB_srptype = 0,
DB_srpverifier = 1,
DES_CBC_MODE = 0,
DES_DECRYPT = 0,
DES_ENCRYPT = 1,
DES_PCBC_MODE = 1,
DH_CHECK_INVALID_J_VALUE = 0x40,
DH_CHECK_INVALID_Q_VALUE = 0x20,
DH_CHECK_P_NOT_PRIME = 0x01,
DH_CHECK_P_NOT_SAFE_PRIME = 0x02,
DH_CHECK_PUBKEY_INVALID = 0x04,
DH_CHECK_PUBKEY_TOO_LARGE = 0x02,
DH_CHECK_PUBKEY_TOO_SMALL = 0x01,
DH_CHECK_Q_NOT_PRIME = 0x10,
DH_F_COMPUTE_KEY = 102,
DH_F_DH_BUILTIN_GENPARAMS = 106,
DH_F_DH_CMS_DECRYPT = 117,
DH_F_DH_CMS_SET_PEERKEY = 118,
DH_F_DH_CMS_SET_SHARED_INFO = 119,
DH_F_DH_COMPUTE_KEY = 114,
DH_F_DH_GENERATE_KEY = 115,
DH_F_DH_GENERATE_PARAMETERS_EX = 116,
DH_F_DH_NEW_METHOD = 105,
DH_F_DH_PARAM_DECODE = 107,
DH_F_DH_PRIV_DECODE = 110,
DH_F_DH_PRIV_ENCODE = 111,
DH_F_DH_PUB_DECODE = 108,
DH_F_DH_PUB_ENCODE = 109,
DH_F_DHPARAMS_PRINT_FP = 101,
DH_F_DO_DH_PRINT = 100,
DH_F_GENERATE_KEY = 103,
DH_F_GENERATE_PARAMETERS = 104,
DH_F_PKEY_DH_DERIVE = 112,
DH_F_PKEY_DH_KEYGEN = 113,
DH_FLAG_CACHE_MONT_P = 0x01,
DH_FLAG_FIPS_METHOD = 0x0400,
DH_FLAG_NO_EXP_CONSTTIME = 0x02,
DH_FLAG_NON_FIPS_ALLOW = 0x0400,
DH_GENERATOR_2 = 2,
DH_GENERATOR_5 = 5,
DH_NOT_SUITABLE_GENERATOR = 0x08,
DH_R_BAD_GENERATOR = 101,
DH_R_BN_DECODE_ERROR = 109,
DH_R_BN_ERROR = 106,
DH_R_DECODE_ERROR = 104,
DH_R_INVALID_PUBKEY = 102,
DH_R_KDF_PARAMETER_ERROR = 112,
DH_R_KEY_SIZE_TOO_SMALL = 110,
DH_R_KEYS_NOT_SET = 108,
DH_R_MODULUS_TOO_LARGE = 103,
DH_R_NO_PARAMETERS_SET = 107,
DH_R_NO_PRIVATE_VALUE = 100,
DH_R_NON_FIPS_METHOD = 111,
DH_R_PARAMETER_ENCODING_ERROR = 105,
DH_R_PEER_KEY_ERROR = 113,
DH_R_SHARED_INFO_ERROR = 114,
DH_UNABLE_TO_CHECK_GENERATOR = 0x04,
DSA_F_D2I_DSA_SIG = 110,
DSA_F_DO_DSA_PRINT = 104,
DSA_F_DSA_BUILTIN_PARAMGEN2 = 126,
DSA_F_DSA_DO_SIGN = 112,
DSA_F_DSA_DO_VERIFY = 113,
DSA_F_DSA_GENERATE_KEY = 124,
DSA_F_DSA_GENERATE_PARAMETERS_EX = 123,
DSA_F_DSA_NEW_METHOD = 103,
DSA_F_DSA_PARAM_DECODE = 119,
DSA_F_DSA_PRINT_FP = 105,
DSA_F_DSA_PRIV_DECODE = 115,
DSA_F_DSA_PRIV_ENCODE = 116,
DSA_F_DSA_PUB_DECODE = 117,
DSA_F_DSA_PUB_ENCODE = 118,
DSA_F_DSA_SIG_NEW = 109,
DSA_F_DSA_SIG_PRINT = 125,
DSA_F_DSA_SIGN = 106,
DSA_F_DSA_SIGN_SETUP = 107,
DSA_F_DSA_VERIFY = 108,
DSA_F_DSAPARAMS_PRINT = 100,
DSA_F_DSAPARAMS_PRINT_FP = 101,
DSA_F_I2D_DSA_SIG = 111,
DSA_F_OLD_DSA_PRIV_DECODE = 122,
DSA_F_PKEY_DSA_CTRL = 120,
DSA_F_PKEY_DSA_KEYGEN = 121,
DSA_F_SIG_CB = 114,
DSA_FLAG_CACHE_MONT_P = 0x01,
DSA_FLAG_FIPS_METHOD = 0x0400,
DSA_FLAG_NO_EXP_CONSTTIME = 0x02,
DSA_FLAG_NON_FIPS_ALLOW = 0x0400,
DSA_R_BAD_Q_VALUE = 102,
DSA_R_BN_DECODE_ERROR = 108,
DSA_R_BN_ERROR = 109,
DSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE = 100,
DSA_R_DECODE_ERROR = 104,
DSA_R_INVALID_DIGEST_TYPE = 106,
DSA_R_INVALID_PARAMETERS = 112,
DSA_R_MISSING_PARAMETERS = 101,
DSA_R_MODULUS_TOO_LARGE = 103,
DSA_R_NEED_NEW_SETUP_VALUES = 110,
DSA_R_NO_PARAMETERS_SET = 107,
DSA_R_NON_FIPS_DSA_METHOD = 111,
DSA_R_PARAMETER_ENCODING_ERROR = 105,
DSA_R_Q_NOT_PRIME = 113,
DSO_CTRL_GET_FLAGS = 1,
DSO_CTRL_OR_FLAGS = 3,
DSO_CTRL_SET_FLAGS = 2,
DSO_F_BEOS_BIND_FUNC = 144,
DSO_F_BEOS_BIND_VAR = 145,
DSO_F_BEOS_LOAD = 146,
DSO_F_BEOS_NAME_CONVERTER = 147,
DSO_F_BEOS_UNLOAD = 148,
DSO_F_DL_BIND_FUNC = 104,
DSO_F_DL_BIND_VAR = 105,
DSO_F_DL_LOAD = 106,
DSO_F_DL_MERGER = 131,
DSO_F_DL_NAME_CONVERTER = 124,
DSO_F_DL_UNLOAD = 107,
DSO_F_DLFCN_BIND_FUNC = 100,
DSO_F_DLFCN_BIND_VAR = 101,
DSO_F_DLFCN_LOAD = 102,
DSO_F_DLFCN_MERGER = 130,
DSO_F_DLFCN_NAME_CONVERTER = 123,
DSO_F_DLFCN_UNLOAD = 103,
DSO_F_DSO_BIND_FUNC = 108,
DSO_F_DSO_BIND_VAR = 109,
DSO_F_DSO_CONVERT_FILENAME = 126,
DSO_F_DSO_CTRL = 110,
DSO_F_DSO_FREE = 111,
DSO_F_DSO_GET_FILENAME = 127,
DSO_F_DSO_GET_LOADED_FILENAME = 128,
DSO_F_DSO_GLOBAL_LOOKUP = 139,
DSO_F_DSO_LOAD = 112,
DSO_F_DSO_MERGE = 132,
DSO_F_DSO_NEW_METHOD = 113,
DSO_F_DSO_PATHBYADDR = 140,
DSO_F_DSO_SET_FILENAME = 129,
DSO_F_DSO_SET_NAME_CONVERTER = 122,
DSO_F_DSO_UP_REF = 114,
DSO_F_GLOBAL_LOOKUP_FUNC = 138,
DSO_F_PATHBYADDR = 137,
DSO_F_VMS_BIND_SYM = 115,
DSO_F_VMS_LOAD = 116,
DSO_F_VMS_MERGER = 133,
DSO_F_VMS_UNLOAD = 117,
DSO_F_WIN32_BIND_FUNC = 118,
DSO_F_WIN32_BIND_VAR = 119,
DSO_F_WIN32_GLOBALLOOKUP = 142,
DSO_F_WIN32_GLOBALLOOKUP_FUNC = 143,
DSO_F_WIN32_JOINER = 135,
DSO_F_WIN32_LOAD = 120,
DSO_F_WIN32_MERGER = 134,
DSO_F_WIN32_NAME_CONVERTER = 125,
DSO_F_WIN32_PATHBYADDR = 141,
DSO_F_WIN32_SPLITTER = 136,
DSO_F_WIN32_UNLOAD = 121,
DSO_FLAG_GLOBAL_SYMBOLS = 0x20,
DSO_FLAG_NAME_TRANSLATION_EXT_ONLY = 0x02,
DSO_FLAG_NO_NAME_TRANSLATION = 0x01,
DSO_FLAG_UPCASE_SYMBOL = 0x10,
DSO_R_CTRL_FAILED = 100,
DSO_R_DSO_ALREADY_LOADED = 110,
DSO_R_EMPTY_FILE_STRUCTURE = 113,
DSO_R_FAILURE = 114,
DSO_R_FILENAME_TOO_BIG = 101,
DSO_R_FINISH_FAILED = 102,
DSO_R_INCORRECT_FILE_SYNTAX = 115,
DSO_R_LOAD_FAILED = 103,
DSO_R_NAME_TRANSLATION_FAILED = 109,
DSO_R_NO_FILE_SPECIFICATION = 116,
DSO_R_NO_FILENAME = 111,
DSO_R_NULL_HANDLE = 104,
DSO_R_SET_FILENAME_FAILED = 112,
DSO_R_STACK_ERROR = 105,
DSO_R_SYM_FAILURE = 106,
DSO_R_UNLOAD_FAILED = 107,
DSO_R_UNSUPPORTED = 108,
DSS_prime_checks = 50,
DTLS_ANY_VERSION = 0x1FFFF,
DTLS_CTRL_GET_LINK_MIN_MTU = 121,
DTLS_CTRL_GET_TIMEOUT = 73,
DTLS_CTRL_HANDLE_TIMEOUT = 74,
DTLS_CTRL_LISTEN = 75,
DTLS_CTRL_SET_LINK_MTU = 120,
DTLS1_2_VERSION = 0xFEFD,
DTLS1_AD_MISSING_HANDSHAKE_MESSAGE = 110,
DTLS1_BAD_VER = 0x0100,
DTLS1_CCS_HEADER_LENGTH = 1,
DTLS1_COOKIE_LENGTH = 256,
DTLS1_HM_BAD_FRAGMENT = -2,
DTLS1_HM_FRAGMENT_RETRY = -3,
DTLS1_HM_HEADER_LENGTH = 12,
DTLS1_MAX_MTU_OVERHEAD = 48,
DTLS1_MT_HELLO_VERIFY_REQUEST = 3,
DTLS1_RT_HEADER_LENGTH = 13,
DTLS1_TMO_ALERT_COUNT = 12,
DTLS1_TMO_READ_COUNT = 2,
DTLS1_TMO_WRITE_COUNT = 2,
DTLS1_VERSION = 0xFEFF,
DTLS1_VERSION_MAJOR = 0xFE,
EC_F_BN_TO_FELEM = 224,
EC_F_COMPUTE_WNAF = 143,
EC_F_D2I_ECPARAMETERS = 144,
EC_F_D2I_ECPKPARAMETERS = 145,
EC_F_D2I_ECPRIVATEKEY = 146,
EC_F_DO_EC_KEY_PRINT = 221,
EC_F_EC_ASN1_GROUP2CURVE = 153,
EC_F_EC_ASN1_GROUP2FIELDID = 154,
EC_F_EC_ASN1_GROUP2PARAMETERS = 155,
EC_F_EC_ASN1_GROUP2PKPARAMETERS = 156,
EC_F_EC_ASN1_PARAMETERS2GROUP = 157,
EC_F_EC_ASN1_PKPARAMETERS2GROUP = 158,
EC_F_EC_EX_DATA_SET_DATA = 211,
EC_F_EC_GF2M_MONTGOMERY_POINT_MULTIPLY = 208,
EC_F_EC_GF2M_SIMPLE_GROUP_CHECK_DISCRIMINANT = 159,
EC_F_EC_GF2M_SIMPLE_GROUP_SET_CURVE = 195,
EC_F_EC_GF2M_SIMPLE_OCT2POINT = 160,
EC_F_EC_GF2M_SIMPLE_POINT_GET_AFFINE_COORDINATES = 162,
EC_F_EC_GF2M_SIMPLE_POINT_SET_AFFINE_COORDINATES = 163,
EC_F_EC_GF2M_SIMPLE_POINT2OCT = 161,
EC_F_EC_GF2M_SIMPLE_SET_COMPRESSED_COORDINATES = 164,
EC_F_EC_GFP_MONT_FIELD_DECODE = 133,
EC_F_EC_GFP_MONT_FIELD_ENCODE = 134,
EC_F_EC_GFP_MONT_FIELD_MUL = 131,
EC_F_EC_GFP_MONT_FIELD_SET_TO_ONE = 209,
EC_F_EC_GFP_MONT_FIELD_SQR = 132,
EC_F_EC_GFP_MONT_GROUP_SET_CURVE = 189,
EC_F_EC_GFP_MONT_GROUP_SET_CURVE_GFP = 135,
EC_F_EC_GFP_NIST_FIELD_MUL = 200,
EC_F_EC_GFP_NIST_FIELD_SQR = 201,
EC_F_EC_GFP_NIST_GROUP_SET_CURVE = 202,
EC_F_EC_GFP_NISTP224_GROUP_SET_CURVE = 225,
EC_F_EC_GFP_NISTP224_POINT_GET_AFFINE_COORDINATES = 226,
EC_F_EC_GFP_NISTP224_POINTS_MUL = 228,
EC_F_EC_GFP_NISTP256_GROUP_SET_CURVE = 230,
EC_F_EC_GFP_NISTP256_POINT_GET_AFFINE_COORDINATES = 232,
EC_F_EC_GFP_NISTP256_POINTS_MUL = 231,
EC_F_EC_GFP_NISTP521_GROUP_SET_CURVE = 233,
EC_F_EC_GFP_NISTP521_POINT_GET_AFFINE_COORDINATES = 235,
EC_F_EC_GFP_NISTP521_POINTS_MUL = 234,
EC_F_EC_GFP_SIMPLE_GROUP_CHECK_DISCRIMINANT = 165,
EC_F_EC_GFP_SIMPLE_GROUP_SET_CURVE = 166,
EC_F_EC_GFP_SIMPLE_GROUP_SET_CURVE_GFP = 100,
EC_F_EC_GFP_SIMPLE_GROUP_SET_GENERATOR = 101,
EC_F_EC_GFP_SIMPLE_MAKE_AFFINE = 102,
EC_F_EC_GFP_SIMPLE_OCT2POINT = 103,
EC_F_EC_GFP_SIMPLE_POINT_GET_AFFINE_COORDINATES = 167,
EC_F_EC_GFP_SIMPLE_POINT_GET_AFFINE_COORDINATES_GFP = 105,
EC_F_EC_GFP_SIMPLE_POINT_SET_AFFINE_COORDINATES = 168,
EC_F_EC_GFP_SIMPLE_POINT_SET_AFFINE_COORDINATES_GFP = 128,
EC_F_EC_GFP_SIMPLE_POINT2OCT = 104,
EC_F_EC_GFP_SIMPLE_POINTS_MAKE_AFFINE = 137,
EC_F_EC_GFP_SIMPLE_SET_COMPRESSED_COORDINATES = 169,
EC_F_EC_GFP_SIMPLE_SET_COMPRESSED_COORDINATES_GFP = 129,
EC_F_EC_GROUP_CHECK = 170,
EC_F_EC_GROUP_CHECK_DISCRIMINANT = 171,
EC_F_EC_GROUP_COPY = 106,
EC_F_EC_GROUP_GET_COFACTOR = 140,
EC_F_EC_GROUP_GET_CURVE_GF2M = 172,
EC_F_EC_GROUP_GET_CURVE_GFP = 130,
EC_F_EC_GROUP_GET_DEGREE = 173,
EC_F_EC_GROUP_GET_ORDER = 141,
EC_F_EC_GROUP_GET_PENTANOMIAL_BASIS = 193,
EC_F_EC_GROUP_GET_TRINOMIAL_BASIS = 194,
EC_F_EC_GROUP_GET0_GENERATOR = 139,
EC_F_EC_GROUP_NEW = 108,
EC_F_EC_GROUP_NEW_BY_CURVE_NAME = 174,
EC_F_EC_GROUP_NEW_FROM_DATA = 175,
EC_F_EC_GROUP_PRECOMPUTE_MULT = 142,
EC_F_EC_GROUP_SET_CURVE_GF2M = 176,
EC_F_EC_GROUP_SET_CURVE_GFP = 109,
EC_F_EC_GROUP_SET_EXTRA_DATA = 110,
EC_F_EC_GROUP_SET_GENERATOR = 111,
EC_F_EC_KEY_CHECK_KEY = 177,
EC_F_EC_KEY_COPY = 178,
EC_F_EC_KEY_GENERATE_KEY = 179,
EC_F_EC_KEY_NEW = 182,
EC_F_EC_KEY_PRINT = 180,
EC_F_EC_KEY_PRINT_FP = 181,
EC_F_EC_KEY_SET_PUBLIC_KEY_AFFINE_COORDINATES = 229,
EC_F_EC_POINT_ADD = 112,
EC_F_EC_POINT_CMP = 113,
EC_F_EC_POINT_COPY = 114,
EC_F_EC_POINT_DBL = 115,
EC_F_EC_POINT_GET_AFFINE_COORDINATES_GF2M = 183,
EC_F_EC_POINT_GET_AFFINE_COORDINATES_GFP = 116,
EC_F_EC_POINT_GET_JPROJECTIVE_COORDINATES_GFP = 117,
EC_F_EC_POINT_INVERT = 210,
EC_F_EC_POINT_IS_AT_INFINITY = 118,
EC_F_EC_POINT_IS_ON_CURVE = 119,
EC_F_EC_POINT_MAKE_AFFINE = 120,
EC_F_EC_POINT_MUL = 184,
EC_F_EC_POINT_NEW = 121,
EC_F_EC_POINT_OCT2POINT = 122,
EC_F_EC_POINT_POINT2OCT = 123,
EC_F_EC_POINT_SET_AFFINE_COORDINATES_GF2M = 185,
EC_F_EC_POINT_SET_AFFINE_COORDINATES_GFP = 124,
EC_F_EC_POINT_SET_COMPRESSED_COORDINATES_GF2M = 186,
EC_F_EC_POINT_SET_COMPRESSED_COORDINATES_GFP = 125,
EC_F_EC_POINT_SET_JPROJECTIVE_COORDINATES_GFP = 126,
EC_F_EC_POINT_SET_TO_INFINITY = 127,
EC_F_EC_POINTS_MAKE_AFFINE = 136,
EC_F_EC_PRE_COMP_DUP = 207,
EC_F_EC_PRE_COMP_NEW = 196,
EC_F_EC_WNAF_MUL = 187,
EC_F_EC_WNAF_PRECOMPUTE_MULT = 188,
EC_F_ECDH_CMS_DECRYPT = 238,
EC_F_ECDH_CMS_SET_SHARED_INFO = 239,
EC_F_ECKEY_PARAM_DECODE = 212,
EC_F_ECKEY_PARAM2TYPE = 223,
EC_F_ECKEY_PRIV_DECODE = 213,
EC_F_ECKEY_PRIV_ENCODE = 214,
EC_F_ECKEY_PUB_DECODE = 215,
EC_F_ECKEY_PUB_ENCODE = 216,
EC_F_ECKEY_TYPE2PARAM = 220,
EC_F_ECP_NIST_MOD_192 = 203,
EC_F_ECP_NIST_MOD_224 = 204,
EC_F_ECP_NIST_MOD_256 = 205,
EC_F_ECP_NIST_MOD_521 = 206,
EC_F_ECP_NISTZ256_GET_AFFINE = 240,
EC_F_ECP_NISTZ256_MULT_PRECOMPUTE = 243,
EC_F_ECP_NISTZ256_POINTS_MUL = 241,
EC_F_ECP_NISTZ256_PRE_COMP_NEW = 244,
EC_F_ECP_NISTZ256_SET_WORDS = 245,
EC_F_ECP_NISTZ256_WINDOWED_MUL = 242,
EC_F_ECPARAMETERS_PRINT = 147,
EC_F_ECPARAMETERS_PRINT_FP = 148,
EC_F_ECPKPARAMETERS_PRINT = 149,
EC_F_ECPKPARAMETERS_PRINT_FP = 150,
EC_F_I2D_ECPARAMETERS = 190,
EC_F_I2D_ECPKPARAMETERS = 191,
EC_F_I2D_ECPRIVATEKEY = 192,
EC_F_I2O_ECPUBLICKEY = 151,
EC_F_NISTP224_PRE_COMP_NEW = 227,
EC_F_NISTP256_PRE_COMP_NEW = 236,
EC_F_NISTP521_PRE_COMP_NEW = 237,
EC_F_O2I_ECPUBLICKEY = 152,
EC_F_OLD_EC_PRIV_DECODE = 222,
EC_F_PKEY_EC_CTRL = 197,
EC_F_PKEY_EC_CTRL_STR = 198,
EC_F_PKEY_EC_DERIVE = 217,
EC_F_PKEY_EC_KEYGEN = 199,
EC_F_PKEY_EC_PARAMGEN = 219,
EC_F_PKEY_EC_SIGN = 218,
EC_FLAG_COFACTOR_ECDH = 0x1000,
EC_FLAG_FIPS_CHECKED = 0x2,
EC_FLAG_NON_FIPS_ALLOW = 0x1,
EC_PKEY_NO_PARAMETERS = 0x001,
EC_PKEY_NO_PUBKEY = 0x002,
EC_R_ASN1_ERROR = 115,
EC_R_ASN1_UNKNOWN_FIELD = 116,
EC_R_BIGNUM_OUT_OF_RANGE = 144,
EC_R_BUFFER_TOO_SMALL = 100,
EC_R_COORDINATES_OUT_OF_RANGE = 146,
EC_R_D2I_ECPKPARAMETERS_FAILURE = 117,
EC_R_DECODE_ERROR = 142,
EC_R_DISCRIMINANT_IS_ZERO = 118,
EC_R_EC_GROUP_NEW_BY_NAME_FAILURE = 119,
EC_R_FIELD_TOO_LARGE = 143,
EC_R_GF2M_NOT_SUPPORTED = 147,
EC_R_GROUP2PKPARAMETERS_FAILURE = 120,
EC_R_I2D_ECPKPARAMETERS_FAILURE = 121,
EC_R_INCOMPATIBLE_OBJECTS = 101,
EC_R_INVALID_ARGUMENT = 112,
EC_R_INVALID_COMPRESSED_POINT = 110,
EC_R_INVALID_COMPRESSION_BIT = 109,
EC_R_INVALID_CURVE = 141,
EC_R_INVALID_DIGEST = 151,
EC_R_INVALID_DIGEST_TYPE = 138,
EC_R_INVALID_ENCODING = 102,
EC_R_INVALID_FIELD = 103,
EC_R_INVALID_FORM = 104,
EC_R_INVALID_GROUP_ORDER = 122,
EC_R_INVALID_PENTANOMIAL_BASIS = 132,
EC_R_INVALID_PRIVATE_KEY = 123,
EC_R_INVALID_TRINOMIAL_BASIS = 137,
EC_R_KDF_PARAMETER_ERROR = 148,
EC_R_KEYS_NOT_SET = 140,
EC_R_MISSING_PARAMETERS = 124,
EC_R_MISSING_PRIVATE_KEY = 125,
EC_R_NO_FIELD_MOD = 133,
EC_R_NO_PARAMETERS_SET = 139,
EC_R_NOT_A_NIST_PRIME = 135,
EC_R_NOT_A_SUPPORTED_NIST_PRIME = 136,
EC_R_NOT_IMPLEMENTED = 126,
EC_R_NOT_INITIALIZED = 111,
EC_R_PASSED_NULL_PARAMETER = 134,
EC_R_PEER_KEY_ERROR = 149,
EC_R_PKPARAMETERS2GROUP_FAILURE = 127,
EC_R_POINT_AT_INFINITY = 106,
EC_R_POINT_IS_NOT_ON_CURVE = 107,
EC_R_SHARED_INFO_ERROR = 150,
EC_R_SLOT_FULL = 108,
EC_R_UNDEFINED_GENERATOR = 113,
EC_R_UNDEFINED_ORDER = 128,
EC_R_UNKNOWN_GROUP = 129,
EC_R_UNKNOWN_ORDER = 114,
EC_R_UNSUPPORTED_FIELD = 131,
EC_R_WRONG_CURVE_PARAMETERS = 145,
EC_R_WRONG_ORDER = 130,
ECDH_F_ECDH_CHECK = 102,
ECDH_F_ECDH_COMPUTE_KEY = 100,
ECDH_F_ECDH_DATA_NEW_METHOD = 101,
ECDH_R_KDF_FAILED = 102,
ECDH_R_NO_PRIVATE_VALUE = 100,
ECDH_R_NON_FIPS_METHOD = 103,
ECDH_R_POINT_ARITHMETIC_FAILURE = 101,
ECDSA_F_ECDSA_CHECK = 104,
ECDSA_F_ECDSA_DATA_NEW_METHOD = 100,
ECDSA_F_ECDSA_DO_SIGN = 101,
ECDSA_F_ECDSA_DO_VERIFY = 102,
ECDSA_F_ECDSA_METHOD_NEW = 105,
ECDSA_F_ECDSA_SIGN_SETUP = 103,
ECDSA_R_BAD_SIGNATURE = 100,
ECDSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE = 101,
ECDSA_R_ERR_EC_LIB = 102,
ECDSA_R_MISSING_PARAMETERS = 103,
ECDSA_R_NEED_NEW_SETUP_VALUES = 106,
ECDSA_R_NON_FIPS_METHOD = 107,
ECDSA_R_RANDOM_NUMBER_GENERATION_FAILED = 104,
ECDSA_R_SIGNATURE_MALLOC_FAILED = 105,
ENGINE_CMD_BASE = 200,
ENGINE_CMD_FLAG_INTERNAL = (unsigned int)0x0008,
ENGINE_CMD_FLAG_NO_INPUT = (unsigned int)0x0004,
ENGINE_CMD_FLAG_NUMERIC = (unsigned int)0x0001,
ENGINE_CMD_FLAG_STRING = (unsigned int)0x0002,
ENGINE_CTRL_CHIL_NO_LOCKING = 101,
ENGINE_CTRL_CHIL_SET_FORKCHECK = 100,
ENGINE_CTRL_GET_CMD_FLAGS = 18,
ENGINE_CTRL_GET_CMD_FROM_NAME = 13,
ENGINE_CTRL_GET_DESC_FROM_CMD = 17,
ENGINE_CTRL_GET_DESC_LEN_FROM_CMD = 16,
ENGINE_CTRL_GET_FIRST_CMD_TYPE = 11,
ENGINE_CTRL_GET_NAME_FROM_CMD = 15,
ENGINE_CTRL_GET_NAME_LEN_FROM_CMD = 14,
ENGINE_CTRL_GET_NEXT_CMD_TYPE = 12,
ENGINE_CTRL_HAS_CTRL_FUNCTION = 10,
ENGINE_CTRL_SET_LOGSTREAM = 1,
ENGINE_CTRL_SET_PASSWORD_CALLBACK = 2,
ENGINE_F_DYNAMIC_CTRL = 180,
ENGINE_F_DYNAMIC_GET_DATA_CTX = 181,
ENGINE_F_DYNAMIC_LOAD = 182,
ENGINE_F_DYNAMIC_SET_DATA_CTX = 183,
ENGINE_F_ENGINE_ADD = 105,
ENGINE_F_ENGINE_BY_ID = 106,
ENGINE_F_ENGINE_CMD_IS_EXECUTABLE = 170,
ENGINE_F_ENGINE_CTRL = 142,
ENGINE_F_ENGINE_CTRL_CMD = 178,
ENGINE_F_ENGINE_CTRL_CMD_STRING = 171,
ENGINE_F_ENGINE_FINISH = 107,
ENGINE_F_ENGINE_FREE_UTIL = 108,
ENGINE_F_ENGINE_GET_CIPHER = 185,
ENGINE_F_ENGINE_GET_DEFAULT_TYPE = 177,
ENGINE_F_ENGINE_GET_DIGEST = 186,
ENGINE_F_ENGINE_GET_NEXT = 115,
ENGINE_F_ENGINE_GET_PKEY_ASN1_METH = 193,
ENGINE_F_ENGINE_GET_PKEY_METH = 192,
ENGINE_F_ENGINE_GET_PREV = 116,
ENGINE_F_ENGINE_INIT = 119,
ENGINE_F_ENGINE_LIST_ADD = 120,
ENGINE_F_ENGINE_LIST_REMOVE = 121,
ENGINE_F_ENGINE_LOAD_PRIVATE_KEY = 150,
ENGINE_F_ENGINE_LOAD_PUBLIC_KEY = 151,
ENGINE_F_ENGINE_LOAD_SSL_CLIENT_CERT = 194,
ENGINE_F_ENGINE_NEW = 122,
ENGINE_F_ENGINE_REMOVE = 123,
ENGINE_F_ENGINE_SET_DEFAULT_STRING = 189,
ENGINE_F_ENGINE_SET_DEFAULT_TYPE = 126,
ENGINE_F_ENGINE_SET_ID = 129,
ENGINE_F_ENGINE_SET_NAME = 130,
ENGINE_F_ENGINE_TABLE_REGISTER = 184,
ENGINE_F_ENGINE_UNLOAD_KEY = 152,
ENGINE_F_ENGINE_UNLOCKED_FINISH = 191,
ENGINE_F_ENGINE_UP_REF = 190,
ENGINE_F_INT_CTRL_HELPER = 172,
ENGINE_F_INT_ENGINE_CONFIGURE = 188,
ENGINE_F_INT_ENGINE_MODULE_INIT = 187,
ENGINE_F_LOG_MESSAGE = 141,
ENGINE_FLAGS_BY_ID_COPY = (int)0x0004,
ENGINE_FLAGS_MANUAL_CMD_CTRL = (int)0x0002,
ENGINE_FLAGS_NO_REGISTER_ALL = (int)0x0008,
ENGINE_METHOD_ALL = (unsigned int)0xFFFF,
ENGINE_METHOD_CIPHERS = (unsigned int)0x0040,
ENGINE_METHOD_DH = (unsigned int)0x0004,
ENGINE_METHOD_DIGESTS = (unsigned int)0x0080,
ENGINE_METHOD_DSA = (unsigned int)0x0002,
ENGINE_METHOD_ECDH = (unsigned int)0x0010,
ENGINE_METHOD_ECDSA = (unsigned int)0x0020,
ENGINE_METHOD_NONE = (unsigned int)0x0000,
ENGINE_METHOD_PKEY_ASN1_METHS = (unsigned int)0x0400,
ENGINE_METHOD_PKEY_METHS = (unsigned int)0x0200,
ENGINE_METHOD_RAND = (unsigned int)0x0008,
ENGINE_METHOD_RSA = (unsigned int)0x0001,
ENGINE_METHOD_STORE = (unsigned int)0x0100,
ENGINE_R_ALREADY_LOADED = 100,
ENGINE_R_ARGUMENT_IS_NOT_A_NUMBER = 133,
ENGINE_R_CMD_NOT_EXECUTABLE = 134,
ENGINE_R_COMMAND_TAKES_INPUT = 135,
ENGINE_R_COMMAND_TAKES_NO_INPUT = 136,
ENGINE_R_CONFLICTING_ENGINE_ID = 103,
ENGINE_R_CTRL_COMMAND_NOT_IMPLEMENTED = 119,
ENGINE_R_DH_NOT_IMPLEMENTED = 139,
ENGINE_R_DSA_NOT_IMPLEMENTED = 140,
ENGINE_R_DSO_FAILURE = 104,
ENGINE_R_DSO_NOT_FOUND = 132,
ENGINE_R_ENGINE_CONFIGURATION_ERROR = 102,
ENGINE_R_ENGINE_IS_NOT_IN_LIST = 105,
ENGINE_R_ENGINE_SECTION_ERROR = 149,
ENGINE_R_ENGINES_SECTION_ERROR = 148,
ENGINE_R_FAILED_LOADING_PRIVATE_KEY = 128,
ENGINE_R_FAILED_LOADING_PUBLIC_KEY = 129,
ENGINE_R_FINISH_FAILED = 106,
ENGINE_R_GET_HANDLE_FAILED = 107,
ENGINE_R_ID_OR_NAME_MISSING = 108,
ENGINE_R_INIT_FAILED = 109,
ENGINE_R_INTERNAL_LIST_ERROR = 110,
ENGINE_R_INVALID_ARGUMENT = 143,
ENGINE_R_INVALID_CMD_NAME = 137,
ENGINE_R_INVALID_CMD_NUMBER = 138,
ENGINE_R_INVALID_INIT_VALUE = 151,
ENGINE_R_INVALID_STRING = 150,
ENGINE_R_NO_CONTROL_FUNCTION = 120,
ENGINE_R_NO_INDEX = 144,
ENGINE_R_NO_LOAD_FUNCTION = 125,
ENGINE_R_NO_REFERENCE = 130,
ENGINE_R_NO_SUCH_ENGINE = 116,
ENGINE_R_NO_UNLOAD_FUNCTION = 126,
ENGINE_R_NOT_INITIALISED = 117,
ENGINE_R_NOT_LOADED = 112,
ENGINE_R_PROVIDE_PARAMETERS = 113,
ENGINE_R_RSA_NOT_IMPLEMENTED = 141,
ENGINE_R_UNIMPLEMENTED_CIPHER = 146,
ENGINE_R_UNIMPLEMENTED_DIGEST = 147,
ENGINE_R_UNIMPLEMENTED_PUBLIC_KEY_METHOD = 101,
ENGINE_R_VERSION_INCOMPATIBILITY = 145,
ENGINE_TABLE_FLAG_NOINIT = (unsigned int)0x0001,
ERR_FLAG_MARK = 0x01,
ERR_LIB_ASN1 = 13,
ERR_LIB_BIO = 32,
ERR_LIB_BN = 3,
ERR_LIB_BUF = 7,
ERR_LIB_CMS = 46,
ERR_LIB_COMP = 41,
ERR_LIB_CONF = 14,
ERR_LIB_CRYPTO = 15,
ERR_LIB_DH = 5,
ERR_LIB_DSA = 10,
ERR_LIB_DSO = 37,
ERR_LIB_EC = 16,
ERR_LIB_ECDH = 43,
ERR_LIB_ECDSA = 42,
ERR_LIB_ENGINE = 38,
ERR_LIB_EVP = 6,
ERR_LIB_FIPS = 45,
ERR_LIB_HMAC = 48,
ERR_LIB_JPAKE = 49,
ERR_LIB_NONE = 1,
ERR_LIB_OBJ = 8,
ERR_LIB_OCSP = 39,
ERR_LIB_PEM = 9,
ERR_LIB_PKCS12 = 35,
ERR_LIB_PKCS7 = 33,
ERR_LIB_RAND = 36,
ERR_LIB_RSA = 4,
ERR_LIB_SSL = 20,
ERR_LIB_STORE = 44,
ERR_LIB_SYS = 2,
ERR_LIB_TS = 47,
ERR_LIB_UI = 40,
ERR_LIB_USER = 128,
ERR_LIB_X509 = 11,
ERR_LIB_X509V3 = 34,
ERR_NUM_ERRORS = 16,
ERR_R_ASN1_LENGTH_MISMATCH = 62,
ERR_R_BAD_ASN1_OBJECT_HEADER = 59,
ERR_R_BAD_GET_ASN1_OBJECT_CALL = 60,
ERR_R_EXPECTING_AN_ASN1_SEQUENCE = 61,
ERR_R_FATAL = 64,
ERR_R_MISSING_ASN1_EOS = 63,
ERR_R_NESTED_ASN1_ERROR = 58,
ERR_TXT_MALLOCED = 0x01,
ERR_TXT_STRING = 0x02,
EVP_AEAD_TLS1_AAD_LEN = 13,
EVP_BLOWFISH_KEY_SIZE = 16,
EVP_CAST5_KEY_SIZE = 16,
EVP_CIPH_ALWAYS_CALL_INIT = 0x20,
EVP_CIPH_CBC_MODE = 0x2,
EVP_CIPH_CCM_MODE = 0x7,
EVP_CIPH_CFB_MODE = 0x3,
EVP_CIPH_CTR_MODE = 0x5,
EVP_CIPH_CTRL_INIT = 0x40,
EVP_CIPH_CUSTOM_COPY = 0x400,
EVP_CIPH_CUSTOM_IV = 0x10,
EVP_CIPH_CUSTOM_KEY_LENGTH = 0x80,
EVP_CIPH_ECB_MODE = 0x1,
EVP_CIPH_FLAG_AEAD_CIPHER = 0x200000,
EVP_CIPH_FLAG_CUSTOM_CIPHER = 0x100000,
EVP_CIPH_FLAG_DEFAULT_ASN1 = 0x1000,
EVP_CIPH_FLAG_FIPS = 0x4000,
EVP_CIPH_FLAG_LENGTH_BITS = 0x2000,
EVP_CIPH_FLAG_NON_FIPS_ALLOW = 0x8000,
EVP_CIPH_FLAG_TLS1_1_MULTIBLOCK = 0x400000,
EVP_CIPH_GCM_MODE = 0x6,
EVP_CIPH_MODE = 0xF0007,
EVP_CIPH_NO_PADDING = 0x100,
EVP_CIPH_OFB_MODE = 0x4,
EVP_CIPH_RAND_KEY = 0x200,
EVP_CIPH_STREAM_CIPHER = 0x0,
EVP_CIPH_VARIABLE_LENGTH = 0x8,
EVP_CIPH_WRAP_MODE = 0x10002,
EVP_CIPH_XTS_MODE = 0x10001,
EVP_CIPHER_CTX_FLAG_WRAP_ALLOW = 0x1,
EVP_CTRL_AEAD_SET_MAC_KEY = 0x17,
EVP_CTRL_AEAD_TLS1_AAD = 0x16,
EVP_CTRL_CCM_SET_L = 0x14,
EVP_CTRL_CCM_SET_MSGLEN = 0x15,
EVP_CTRL_COPY = 0x8,
EVP_CTRL_GCM_GET_TAG = 0x10,
EVP_CTRL_GCM_IV_GEN = 0x13,
EVP_CTRL_GCM_SET_IV_FIXED = 0x12,
EVP_CTRL_GCM_SET_IV_INV = 0x18,
EVP_CTRL_GCM_SET_IVLEN = 0x9,
EVP_CTRL_GCM_SET_TAG = 0x11,
EVP_CTRL_GET_RC2_KEY_BITS = 0x2,
EVP_CTRL_GET_RC5_ROUNDS = 0x4,
EVP_CTRL_INIT = 0x0,
EVP_CTRL_PBE_PRF_NID = 0x7,
EVP_CTRL_RAND_KEY = 0x6,
EVP_CTRL_SET_KEY_LENGTH = 0x1,
EVP_CTRL_SET_RC2_KEY_BITS = 0x3,
EVP_CTRL_SET_RC5_ROUNDS = 0x5,
EVP_CTRL_TLS1_1_MULTIBLOCK_AAD = 0x19,
EVP_CTRL_TLS1_1_MULTIBLOCK_DECRYPT = 0x1b,
EVP_CTRL_TLS1_1_MULTIBLOCK_ENCRYPT = 0x1a,
EVP_CTRL_TLS1_1_MULTIBLOCK_MAX_BUFSIZE = 0x1c,
EVP_F_AES_INIT_KEY = 133,
EVP_F_AES_T4_INIT_KEY = 178,
EVP_F_AES_XTS = 172,
EVP_F_AES_XTS_CIPHER = 175,
EVP_F_AESNI_INIT_KEY = 165,
EVP_F_AESNI_XTS_CIPHER = 176,
EVP_F_ALG_MODULE_INIT = 177,
EVP_F_CAMELLIA_INIT_KEY = 159,
EVP_F_CMAC_INIT = 173,
EVP_F_CMLL_T4_INIT_KEY = 179,
EVP_F_D2I_PKEY = 100,
EVP_F_DO_SIGVER_INIT = 161,
EVP_F_DSA_PKEY2PKCS8 = 135,
EVP_F_DSAPKEY2PKCS8 = 134,
EVP_F_ECDSA_PKEY2PKCS8 = 129,
EVP_F_ECKEY_PKEY2PKCS8 = 132,
EVP_F_EVP_CIPHER_CTX_COPY = 163,
EVP_F_EVP_CIPHER_CTX_CTRL = 124,
EVP_F_EVP_CIPHER_CTX_SET_KEY_LENGTH = 122,
EVP_F_EVP_CIPHERINIT_EX = 123,
EVP_F_EVP_DECRYPTFINAL_EX = 101,
EVP_F_EVP_DIGESTINIT_EX = 128,
EVP_F_EVP_ENCRYPTFINAL_EX = 127,
EVP_F_EVP_MD_CTX_COPY_EX = 110,
EVP_F_EVP_MD_SIZE = 162,
EVP_F_EVP_OPENINIT = 102,
EVP_F_EVP_PBE_ALG_ADD = 115,
EVP_F_EVP_PBE_ALG_ADD_TYPE = 160,
EVP_F_EVP_PBE_CIPHERINIT = 116,
EVP_F_EVP_PKCS82PKEY = 111,
EVP_F_EVP_PKCS82PKEY_BROKEN = 136,
EVP_F_EVP_PKEY_COPY_PARAMETERS = 103,
EVP_F_EVP_PKEY_CTX_CTRL = 137,
EVP_F_EVP_PKEY_CTX_CTRL_STR = 150,
EVP_F_EVP_PKEY_CTX_DUP = 156,
EVP_F_EVP_PKEY_DECRYPT = 104,
EVP_F_EVP_PKEY_DECRYPT_INIT = 138,
EVP_F_EVP_PKEY_DECRYPT_OLD = 151,
EVP_F_EVP_PKEY_DERIVE = 153,
EVP_F_EVP_PKEY_DERIVE_INIT = 154,
EVP_F_EVP_PKEY_DERIVE_SET_PEER = 155,
EVP_F_EVP_PKEY_ENCRYPT = 105,
EVP_F_EVP_PKEY_ENCRYPT_INIT = 139,
EVP_F_EVP_PKEY_ENCRYPT_OLD = 152,
EVP_F_EVP_PKEY_GET1_DH = 119,
EVP_F_EVP_PKEY_GET1_DSA = 120,
EVP_F_EVP_PKEY_GET1_EC_KEY = 131,
EVP_F_EVP_PKEY_GET1_ECDSA = 130,
EVP_F_EVP_PKEY_GET1_RSA = 121,
EVP_F_EVP_PKEY_KEYGEN = 146,
EVP_F_EVP_PKEY_KEYGEN_INIT = 147,
EVP_F_EVP_PKEY_NEW = 106,
EVP_F_EVP_PKEY_PARAMGEN = 148,
EVP_F_EVP_PKEY_PARAMGEN_INIT = 149,
EVP_F_EVP_PKEY_SIGN = 140,
EVP_F_EVP_PKEY_SIGN_INIT = 141,
EVP_F_EVP_PKEY_VERIFY = 142,
EVP_F_EVP_PKEY_VERIFY_INIT = 143,
EVP_F_EVP_PKEY_VERIFY_RECOVER = 144,
EVP_F_EVP_PKEY_VERIFY_RECOVER_INIT = 145,
EVP_F_EVP_PKEY2PKCS8_BROKEN = 113,
EVP_F_EVP_RIJNDAEL = 126,
EVP_F_EVP_SIGNFINAL = 107,
EVP_F_EVP_VERIFYFINAL = 108,
EVP_F_FIPS_CIPHER_CTX_COPY = 170,
EVP_F_FIPS_CIPHER_CTX_CTRL = 167,
EVP_F_FIPS_CIPHER_CTX_SET_KEY_LENGTH = 171,
EVP_F_FIPS_CIPHERINIT = 166,
EVP_F_FIPS_DIGESTINIT = 168,
EVP_F_FIPS_MD_CTX_COPY = 169,
EVP_F_HMAC_INIT_EX = 174,
EVP_F_INT_CTX_NEW = 157,
EVP_F_PKCS5_PBE_KEYIVGEN = 117,
EVP_F_PKCS5_V2_PBE_KEYIVGEN = 118,
EVP_F_PKCS5_V2_PBKDF2_KEYIVGEN = 164,
EVP_F_PKCS8_SET_BROKEN = 112,
EVP_F_PKEY_SET_TYPE = 158,
EVP_F_RC2_MAGIC_TO_METH = 109,
EVP_F_RC5_CTRL = 125,
EVP_GCM_TLS_EXPLICIT_IV_LEN = 8,
EVP_GCM_TLS_FIXED_IV_LEN = 4,
EVP_GCM_TLS_TAG_LEN = 16,
EVP_MAX_BLOCK_LENGTH = 32,
EVP_MAX_IV_LENGTH = 16,
EVP_MAX_KEY_LENGTH = 64,
EVP_MD_CTRL_ALG_CTRL = 0x1000,
EVP_MD_CTRL_DIGALGID = 0x1,
EVP_MD_CTRL_MICALG = 0x2,
EVP_MD_FLAG_DIGALGID_ABSENT = 0x0008,
EVP_MD_FLAG_DIGALGID_CUSTOM = 0x0018,
EVP_MD_FLAG_DIGALGID_MASK = 0x0018,
EVP_MD_FLAG_DIGALGID_NULL = 0x0000,
EVP_MD_FLAG_FIPS = 0x0400,
EVP_MD_FLAG_ONESHOT = 0x0001,
EVP_MD_FLAG_PKEY_DIGEST = 0x0002,
EVP_MD_FLAG_PKEY_METHOD_SIGNATURE = 0x0004,
EVP_PBE_TYPE_OUTER = 0x0,
EVP_PBE_TYPE_PRF = 0x1,
EVP_PK_DH = 0x0004,
EVP_PK_DSA = 0x0002,
EVP_PK_EC = 0x0008,
EVP_PK_RSA = 0x0001,
EVP_PKEY_ALG_CTRL = 0x1000,
EVP_PKEY_CTRL_CIPHER = 12,
EVP_PKEY_CTRL_CMS_DECRYPT = 10,
EVP_PKEY_CTRL_CMS_ENCRYPT = 9,
EVP_PKEY_CTRL_CMS_SIGN = 11,
EVP_PKEY_CTRL_DIGESTINIT = 7,
EVP_PKEY_CTRL_GET_MD = 13,
EVP_PKEY_CTRL_MD = 1,
EVP_PKEY_CTRL_PEER_KEY = 2,
EVP_PKEY_CTRL_PKCS7_DECRYPT = 4,
EVP_PKEY_CTRL_PKCS7_ENCRYPT = 3,
EVP_PKEY_CTRL_PKCS7_SIGN = 5,
EVP_PKEY_CTRL_SET_IV = 8,
EVP_PKEY_CTRL_SET_MAC_KEY = 6,
EVP_PKEY_DH_KDF_NONE = 1,
EVP_PKEY_DH_KDF_X9_42 = 2,
EVP_PKEY_ECDH_KDF_NONE = 1,
EVP_PKEY_ECDH_KDF_X9_62 = 2,
EVP_PKEY_FLAG_AUTOARGLEN = 2,
EVP_PKEY_FLAG_SIGCTX_CUSTOM = 4,
EVP_PKEY_MO_DECRYPT = 0x0008,
EVP_PKEY_MO_ENCRYPT = 0x0004,
EVP_PKEY_MO_SIGN = 0x0001,
EVP_PKEY_MO_VERIFY = 0x0002,
EVP_PKEY_OP_UNDEFINED = 0,
EVP_PKS_DSA = 0x0200,
EVP_PKS_EC = 0x0400,
EVP_PKS_RSA = 0x0100,
EVP_PKT_ENC = 0x0020,
EVP_PKT_EXCH = 0x0040,
EVP_PKT_SIGN = 0x0010,
EVP_R_AES_IV_SETUP_FAILED = 162,
EVP_R_AES_KEY_SETUP_FAILED = 143,
EVP_R_ASN1_LIB = 140,
EVP_R_BAD_BLOCK_LENGTH = 136,
EVP_R_BAD_DECRYPT = 100,
EVP_R_BAD_KEY_LENGTH = 137,
EVP_R_BN_DECODE_ERROR = 112,
EVP_R_BN_PUBKEY_ERROR = 113,
EVP_R_BUFFER_TOO_SMALL = 155,
EVP_R_CAMELLIA_KEY_SETUP_FAILED = 157,
EVP_R_CIPHER_PARAMETER_ERROR = 122,
EVP_R_COMMAND_NOT_SUPPORTED = 147,
EVP_R_CTRL_NOT_IMPLEMENTED = 132,
EVP_R_CTRL_OPERATION_NOT_IMPLEMENTED = 133,
EVP_R_DATA_NOT_MULTIPLE_OF_BLOCK_LENGTH = 138,
EVP_R_DECODE_ERROR = 114,
EVP_R_DIFFERENT_KEY_TYPES = 101,
EVP_R_DIFFERENT_PARAMETERS = 153,
EVP_R_DISABLED_FOR_FIPS = 163,
EVP_R_ENCODE_ERROR = 115,
EVP_R_ERROR_LOADING_SECTION = 165,
EVP_R_ERROR_SETTING_FIPS_MODE = 166,
EVP_R_EVP_PBE_CIPHERINIT_ERROR = 119,
EVP_R_EXPECTING_A_DH_KEY = 128,
EVP_R_EXPECTING_A_DSA_KEY = 129,
EVP_R_EXPECTING_A_EC_KEY = 142,
EVP_R_EXPECTING_A_ECDSA_KEY = 141,
EVP_R_EXPECTING_AN_RSA_KEY = 127,
EVP_R_FIPS_MODE_NOT_SUPPORTED = 167,
EVP_R_INITIALIZATION_ERROR = 134,
EVP_R_INPUT_NOT_INITIALIZED = 111,
EVP_R_INVALID_DIGEST = 152,
EVP_R_INVALID_FIPS_MODE = 168,
EVP_R_INVALID_KEY = 171,
EVP_R_INVALID_KEY_LENGTH = 130,
EVP_R_INVALID_OPERATION = 148,
EVP_R_IV_TOO_LARGE = 102,
EVP_R_KEYGEN_FAILURE = 120,
EVP_R_MESSAGE_DIGEST_IS_NULL = 159,
EVP_R_METHOD_NOT_SUPPORTED = 144,
EVP_R_MISSING_PARAMETERS = 103,
EVP_R_NO_CIPHER_SET = 131,
EVP_R_NO_DEFAULT_DIGEST = 158,
EVP_R_NO_DIGEST_SET = 139,
EVP_R_NO_DSA_PARAMETERS = 116,
EVP_R_NO_KEY_SET = 154,
EVP_R_NO_OPERATION_SET = 149,
EVP_R_NO_SIGN_FUNCTION_CONFIGURED = 104,
EVP_R_NO_VERIFY_FUNCTION_CONFIGURED = 105,
EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE = 150,
EVP_R_OPERATON_NOT_INITIALIZED = 151,
EVP_R_PKCS8_UNKNOWN_BROKEN_TYPE = 117,
EVP_R_PRIVATE_KEY_DECODE_ERROR = 145,
EVP_R_PRIVATE_KEY_ENCODE_ERROR = 146,
EVP_R_PUBLIC_KEY_NOT_RSA = 106,
EVP_R_TOO_LARGE = 164,
EVP_R_UNKNOWN_CIPHER = 160,
EVP_R_UNKNOWN_DIGEST = 161,
EVP_R_UNKNOWN_OPTION = 169,
EVP_R_UNKNOWN_PBE_ALGORITHM = 121,
EVP_R_UNSUPORTED_NUMBER_OF_ROUNDS = 135,
EVP_R_UNSUPPORTED_ALGORITHM = 156,
EVP_R_UNSUPPORTED_CIPHER = 107,
EVP_R_UNSUPPORTED_KEY_DERIVATION_FUNCTION = 124,
EVP_R_UNSUPPORTED_KEY_SIZE = 108,
EVP_R_UNSUPPORTED_KEYLENGTH = 123,
EVP_R_UNSUPPORTED_PRF = 125,
EVP_R_UNSUPPORTED_PRIVATE_KEY_ALGORITHM = 118,
EVP_R_UNSUPPORTED_SALT_TYPE = 126,
EVP_R_WRAP_MODE_NOT_ALLOWED = 170,
EVP_R_WRONG_FINAL_BLOCK_LENGTH = 109,
EVP_R_WRONG_PUBLIC_KEY_TYPE = 110,
EVP_RC4_KEY_SIZE = 16,
EVP_RC5_32_12_16_KEY_SIZE = 16,
EXFLAG_BCONS = 0x1,
EXFLAG_CA = 0x10,
EXFLAG_CRITICAL = 0x200,
EXFLAG_FRESHEST = 0x1000,
EXFLAG_INVALID = 0x80,
EXFLAG_INVALID_POLICY = 0x800,
EXFLAG_KUSAGE = 0x2,
EXFLAG_NSCERT = 0x8,
EXFLAG_PROXY = 0x400,
EXFLAG_SET = 0x100,
EXFLAG_SI = 0x20,
EXFLAG_SS = 0x2000,
EXFLAG_V1 = 0x40,
EXFLAG_XKUSAGE = 0x4,
GEN_DIRNAME = 4,
GEN_DNS = 2,
GEN_EDIPARTY = 5,
GEN_EMAIL = 1,
GEN_IPADD = 7,
GEN_OTHERNAME = 0,
GEN_RID = 8,
GEN_URI = 6,
GEN_X400 = 3,
IANA_AFI_IPV4 = 1,
IANA_AFI_IPV6 = 2,
IDEA_BLOCK = 8,
IDEA_DECRYPT = 0,
IDEA_ENCRYPT = 1,
IDEA_KEY_LENGTH = 16,
IDP_INDIRECT = 0x20,
IDP_INVALID = 0x2,
IDP_ONLYATTR = 0x10,
IDP_ONLYCA = 0x8,
IDP_ONLYUSER = 0x4,
IDP_PRESENT = 0x1,
IDP_REASONS = 0x40,
IPAddressChoice_addressesOrRanges = 1,
IPAddressChoice_inherit = 0,
IPAddressOrRange_addressPrefix = 0,
IPAddressOrRange_addressRange = 1,
IS_SEQUENCE = 0,
IS_SET = 1,
KEY_EX = 0x10,
KEY_SIG = 0x80,
KRB5CHECKAUTH = 1,
KRB5SENDAUTH = 1,
KSSL_CLIENT = 1,
KSSL_CTX_ERR = 1,
KSSL_CTX_OK = 0,
KSSL_ERR_MAX = 255,
KSSL_KEYTAB = 4,
KSSL_NOMEM = 2,
KSSL_SERVER = 2,
KSSL_SERVICE = 3,
KU_CRL_SIGN = 0x0002,
KU_DATA_ENCIPHERMENT = 0x0010,
KU_DECIPHER_ONLY = 0x8000,
KU_DIGITAL_SIGNATURE = 0x0080,
KU_ENCIPHER_ONLY = 0x0001,
KU_KEY_AGREEMENT = 0x0008,
KU_KEY_CERT_SIGN = 0x0004,
KU_KEY_ENCIPHERMENT = 0x0020,
KU_NON_REPUDIATION = 0x0040,
LH_LOAD_MULT = 256,
MBSTRING_FLAG = 0x1000,
MD4_CBLOCK = 64,
MD4_DIGEST_LENGTH = 16,
MD4_LONG_LOG2 = 3,
MD5_CBLOCK = 64,
MD5_DIGEST_LENGTH = 16,
MD5_LONG_LOG2 = 3,
MDC2_BLOCK = 8,
MDC2_DIGEST_LENGTH = 16,
NS_OBJSIGN = 0x10,
NS_OBJSIGN_CA = 0x01,
NS_SMIME = 0x20,
NS_SMIME_CA = 0x02,
NS_SSL_CA = 0x04,
NS_SSL_CLIENT = 0x80,
NS_SSL_SERVER = 0x40,
OBJ_BSEARCH_FIRST_VALUE_ON_MATCH = 0x02,
OBJ_BSEARCH_VALUE_ON_NOMATCH = 0x01,
OBJ_F_OBJ_ADD_OBJECT = 105,
OBJ_F_OBJ_CREATE = 100,
OBJ_F_OBJ_DUP = 101,
OBJ_F_OBJ_NAME_NEW_INDEX = 106,
OBJ_F_OBJ_NID2LN = 102,
OBJ_F_OBJ_NID2OBJ = 103,
OBJ_F_OBJ_NID2SN = 104,
OBJ_NAME_ALIAS = 0x8000,
OBJ_NAME_TYPE_CIPHER_METH = 0x02,
OBJ_NAME_TYPE_COMP_METH = 0x04,
OBJ_NAME_TYPE_MD_METH = 0x01,
OBJ_NAME_TYPE_NUM = 0x05,
OBJ_NAME_TYPE_PKEY_METH = 0x03,
OBJ_NAME_TYPE_UNDEF = 0x00,
OBJ_R_MALLOC_FAILURE = 100,
OBJ_R_UNKNOWN_NID = 101,
OCSP_DEFAULT_NONCE_LENGTH = 16,
OCSP_F_ASN1_STRING_ENCODE = 100,
OCSP_F_D2I_OCSP_NONCE = 102,
OCSP_F_OCSP_BASIC_ADD1_STATUS = 103,
OCSP_F_OCSP_BASIC_SIGN = 104,
OCSP_F_OCSP_BASIC_VERIFY = 105,
OCSP_F_OCSP_CERT_ID_NEW = 101,
OCSP_F_OCSP_CHECK_DELEGATED = 106,
OCSP_F_OCSP_CHECK_IDS = 107,
OCSP_F_OCSP_CHECK_ISSUER = 108,
OCSP_F_OCSP_CHECK_VALIDITY = 115,
OCSP_F_OCSP_MATCH_ISSUERID = 109,
OCSP_F_OCSP_PARSE_URL = 114,
OCSP_F_OCSP_REQUEST_SIGN = 110,
OCSP_F_OCSP_REQUEST_VERIFY = 116,
OCSP_F_OCSP_RESPONSE_GET1_BASIC = 111,
OCSP_F_OCSP_SENDREQ_BIO = 112,
OCSP_F_OCSP_SENDREQ_NBIO = 117,
OCSP_F_PARSE_HTTP_LINE1 = 118,
OCSP_F_REQUEST_VERIFY = 113,
OCSP_NOCASIGN = 0x40,
OCSP_NOCERTS = 0x1,
OCSP_NOCHAIN = 0x8,
OCSP_NOCHECKS = 0x100,
OCSP_NODELEGATED = 0x80,
OCSP_NOEXPLICIT = 0x20,
OCSP_NOINTERN = 0x2,
OCSP_NOSIGS = 0x4,
OCSP_NOTIME = 0x800,
OCSP_NOVERIFY = 0x10,
OCSP_R_BAD_DATA = 100,
OCSP_R_CERTIFICATE_VERIFY_ERROR = 101,
OCSP_R_DIGEST_ERR = 102,
OCSP_R_ERROR_IN_NEXTUPDATE_FIELD = 122,
OCSP_R_ERROR_IN_THISUPDATE_FIELD = 123,
OCSP_R_ERROR_PARSING_URL = 121,
OCSP_R_MISSING_OCSPSIGNING_USAGE = 103,
OCSP_R_NEXTUPDATE_BEFORE_THISUPDATE = 124,
OCSP_R_NO_CERTIFICATES_IN_CHAIN = 105,
OCSP_R_NO_CONTENT = 106,
OCSP_R_NO_PUBLIC_KEY = 107,
OCSP_R_NO_RESPONSE_DATA = 108,
OCSP_R_NO_REVOKED_TIME = 109,
OCSP_R_NOT_BASIC_RESPONSE = 104,
OCSP_R_PRIVATE_KEY_DOES_NOT_MATCH_CERTIFICATE = 110,
OCSP_R_REQUEST_NOT_SIGNED = 128,
OCSP_R_RESPONSE_CONTAINS_NO_REVOCATION_DATA = 111,
OCSP_R_ROOT_CA_NOT_TRUSTED = 112,
OCSP_R_SERVER_READ_ERROR = 113,
OCSP_R_SERVER_RESPONSE_ERROR = 114,
OCSP_R_SERVER_RESPONSE_PARSE_ERROR = 115,
OCSP_R_SERVER_WRITE_ERROR = 116,
OCSP_R_SIGNATURE_FAILURE = 117,
OCSP_R_SIGNER_CERTIFICATE_NOT_FOUND = 118,
OCSP_R_STATUS_EXPIRED = 125,
OCSP_R_STATUS_NOT_YET_VALID = 126,
OCSP_R_STATUS_TOO_OLD = 127,
OCSP_R_UNKNOWN_MESSAGE_DIGEST = 119,
OCSP_R_UNKNOWN_NID = 120,
OCSP_R_UNSUPPORTED_REQUESTORNAME_TYPE = 129,
OCSP_RESPID_KEY = 0x400,
OCSP_RESPONSE_STATUS_INTERNALERROR = 2,
OCSP_RESPONSE_STATUS_MALFORMEDREQUEST = 1,
OCSP_RESPONSE_STATUS_SIGREQUIRED = 5,
OCSP_RESPONSE_STATUS_SUCCESSFUL = 0,
OCSP_RESPONSE_STATUS_TRYLATER = 3,
OCSP_RESPONSE_STATUS_UNAUTHORIZED = 6,
OCSP_REVOKED_STATUS_AFFILIATIONCHANGED = 3,
OCSP_REVOKED_STATUS_CACOMPROMISE = 2,
OCSP_REVOKED_STATUS_CERTIFICATEHOLD = 6,
OCSP_REVOKED_STATUS_CESSATIONOFOPERATION = 5,
OCSP_REVOKED_STATUS_KEYCOMPROMISE = 1,
OCSP_REVOKED_STATUS_NOSTATUS = -1,
OCSP_REVOKED_STATUS_REMOVEFROMCRL = 8,
OCSP_REVOKED_STATUS_SUPERSEDED = 4,
OCSP_REVOKED_STATUS_UNSPECIFIED = 0,
OCSP_TRUSTOTHER = 0x200,
OPENSSL_DH_MAX_MODULUS_BITS = 10000,
OPENSSL_DSA_MAX_MODULUS_BITS = 10000,
OPENSSL_EC_NAMED_CURVE = 0x001,
OPENSSL_ECC_MAX_FIELD_BITS = 661,
OPENSSL_NPN_NEGOTIATED = 1,
OPENSSL_NPN_NO_OVERLAP = 2,
OPENSSL_NPN_UNSUPPORTED = 0,
OPENSSL_RSA_MAX_MODULUS_BITS = 16384,
OPENSSL_RSA_MAX_PUBEXP_BITS = 64,
OPENSSL_RSA_SMALL_MODULUS_BITS = 3072,
OSSL_DYNAMIC_OLDEST = (unsigned long)0x00020000,
OSSL_DYNAMIC_VERSION = (unsigned long)0x00020000,
PEM_BUFSIZE = 1024,
PEM_DEK_DES_CBC = 40,
PEM_DEK_DES_ECB = 60,
PEM_DEK_DES_EDE = 50,
PEM_DEK_IDEA_CBC = 45,
PEM_DEK_RSA = 70,
PEM_DEK_RSA_MD2 = 80,
PEM_DEK_RSA_MD5 = 90,
PEM_ERROR = 30,
PEM_F_B2I_DSS = 127,
PEM_F_B2I_PVK_BIO = 128,
PEM_F_B2I_RSA = 129,
PEM_F_CHECK_BITLEN_DSA = 130,
PEM_F_CHECK_BITLEN_RSA = 131,
PEM_F_D2I_PKCS8PRIVATEKEY_BIO = 120,
PEM_F_D2I_PKCS8PRIVATEKEY_FP = 121,
PEM_F_DO_B2I = 132,
PEM_F_DO_B2I_BIO = 133,
PEM_F_DO_BLOB_HEADER = 134,
PEM_F_DO_PK8PKEY = 126,
PEM_F_DO_PK8PKEY_FP = 125,
PEM_F_DO_PVK_BODY = 135,
PEM_F_DO_PVK_HEADER = 136,
PEM_F_I2B_PVK = 137,
PEM_F_I2B_PVK_BIO = 138,
PEM_F_LOAD_IV = 101,
PEM_F_PEM_ASN1_READ = 102,
PEM_F_PEM_ASN1_READ_BIO = 103,
PEM_F_PEM_ASN1_WRITE = 104,
PEM_F_PEM_ASN1_WRITE_BIO = 105,
PEM_F_PEM_DEF_CALLBACK = 100,
PEM_F_PEM_DO_HEADER = 106,
PEM_F_PEM_F_PEM_WRITE_PKCS8PRIVATEKEY = 118,
PEM_F_PEM_GET_EVP_CIPHER_INFO = 107,
PEM_F_PEM_PK8PKEY = 119,
PEM_F_PEM_READ = 108,
PEM_F_PEM_READ_BIO = 109,
PEM_F_PEM_READ_BIO_DHPARAMS = 141,
PEM_F_PEM_READ_BIO_PARAMETERS = 140,
PEM_F_PEM_READ_BIO_PRIVATEKEY = 123,
PEM_F_PEM_READ_DHPARAMS = 142,
PEM_F_PEM_READ_PRIVATEKEY = 124,
PEM_F_PEM_SEALFINAL = 110,
PEM_F_PEM_SEALINIT = 111,
PEM_F_PEM_SIGNFINAL = 112,
PEM_F_PEM_WRITE = 113,
PEM_F_PEM_WRITE_BIO = 114,
PEM_F_PEM_WRITE_PRIVATEKEY = 139,
PEM_F_PEM_X509_INFO_READ = 115,
PEM_F_PEM_X509_INFO_READ_BIO = 116,
PEM_F_PEM_X509_INFO_WRITE_BIO = 117,
PEM_OBJ_CRL = 3,
PEM_OBJ_DHPARAMS = 17,
PEM_OBJ_DSAPARAMS = 18,
PEM_OBJ_ECPARAMETERS = 22,
PEM_OBJ_PRIV_DH = 13,
PEM_OBJ_PRIV_DSA = 12,
PEM_OBJ_PRIV_ECDSA = 20,
PEM_OBJ_PRIV_KEY = 10,
PEM_OBJ_PRIV_RSA = 11,
PEM_OBJ_PRIV_RSA_PUBLIC = 19,
PEM_OBJ_PUB_DH = 16,
PEM_OBJ_PUB_DSA = 15,
PEM_OBJ_PUB_ECDSA = 21,
PEM_OBJ_PUB_RSA = 14,
PEM_OBJ_SSL_SESSION = 4,
PEM_OBJ_UNDEF = 0,
PEM_OBJ_X509 = 1,
PEM_OBJ_X509_REQ = 2,
PEM_R_BAD_BASE64_DECODE = 100,
PEM_R_BAD_DECRYPT = 101,
PEM_R_BAD_END_LINE = 102,
PEM_R_BAD_IV_CHARS = 103,
PEM_R_BAD_MAGIC_NUMBER = 116,
PEM_R_BAD_PASSWORD_READ = 104,
PEM_R_BAD_VERSION_NUMBER = 117,
PEM_R_BIO_WRITE_FAILURE = 118,
PEM_R_CIPHER_IS_NULL = 127,
PEM_R_ERROR_CONVERTING_PRIVATE_KEY = 115,
PEM_R_EXPECTING_PRIVATE_KEY_BLOB = 119,
PEM_R_EXPECTING_PUBLIC_KEY_BLOB = 120,
PEM_R_HEADER_TOO_LONG = 128,
PEM_R_INCONSISTENT_HEADER = 121,
PEM_R_KEYBLOB_HEADER_PARSE_ERROR = 122,
PEM_R_KEYBLOB_TOO_SHORT = 123,
PEM_R_NO_START_LINE = 108,
PEM_R_NOT_DEK_INFO = 105,
PEM_R_NOT_ENCRYPTED = 106,
PEM_R_NOT_PROC_TYPE = 107,
PEM_R_PROBLEMS_GETTING_PASSWORD = 109,
PEM_R_PUBLIC_KEY_NO_RSA = 110,
PEM_R_PVK_DATA_TOO_SHORT = 124,
PEM_R_PVK_TOO_SHORT = 125,
PEM_R_READ_KEY = 111,
PEM_R_SHORT_HEADER = 112,
PEM_R_UNSUPPORTED_CIPHER = 113,
PEM_R_UNSUPPORTED_ENCRYPTION = 114,
PEM_R_UNSUPPORTED_KEY_COMPONENTS = 126,
PEM_TYPE_CLEAR = 40,
PEM_TYPE_ENCRYPTED = 10,
PEM_TYPE_MIC_CLEAR = 30,
PEM_TYPE_MIC_ONLY = 20,
PKCS12_ERROR = 0,
PKCS12_F_PARSE_BAG = 129,
PKCS12_F_PARSE_BAGS = 103,
PKCS12_F_PKCS12_ADD_FRIENDLYNAME = 100,
PKCS12_F_PKCS12_ADD_FRIENDLYNAME_ASC = 127,
PKCS12_F_PKCS12_ADD_FRIENDLYNAME_UNI = 102,
PKCS12_F_PKCS12_ADD_LOCALKEYID = 104,
PKCS12_F_PKCS12_CREATE = 105,
PKCS12_F_PKCS12_GEN_MAC = 107,
PKCS12_F_PKCS12_INIT = 109,
PKCS12_F_PKCS12_ITEM_DECRYPT_D2I = 106,
PKCS12_F_PKCS12_ITEM_I2D_ENCRYPT = 108,
PKCS12_F_PKCS12_ITEM_PACK_SAFEBAG = 117,
PKCS12_F_PKCS12_KEY_GEN_ASC = 110,
PKCS12_F_PKCS12_KEY_GEN_UNI = 111,
PKCS12_F_PKCS12_MAKE_KEYBAG = 112,
PKCS12_F_PKCS12_MAKE_SHKEYBAG = 113,
PKCS12_F_PKCS12_NEWPASS = 128,
PKCS12_F_PKCS12_PACK_P7DATA = 114,
PKCS12_F_PKCS12_PACK_P7ENCDATA = 115,
PKCS12_F_PKCS12_PARSE = 118,
PKCS12_F_PKCS12_PBE_CRYPT = 119,
PKCS12_F_PKCS12_PBE_KEYIVGEN = 120,
PKCS12_F_PKCS12_SET_MAC = 123,
PKCS12_F_PKCS12_SETUP_MAC = 122,
PKCS12_F_PKCS12_UNPACK_AUTHSAFES = 130,
PKCS12_F_PKCS12_UNPACK_P7DATA = 131,
PKCS12_F_PKCS12_VERIFY_MAC = 126,
PKCS12_F_PKCS8_ADD_KEYUSAGE = 124,
PKCS12_F_PKCS8_ENCRYPT = 125,
PKCS12_IV_ID = 2,
PKCS12_KEY_ID = 1,
PKCS12_MAC_ID = 3,
PKCS12_MAC_KEY_LENGTH = 20,
PKCS12_OK = 1,
PKCS12_R_CANT_PACK_STRUCTURE = 100,
PKCS12_R_CONTENT_TYPE_NOT_DATA = 121,
PKCS12_R_DECODE_ERROR = 101,
PKCS12_R_ENCODE_ERROR = 102,
PKCS12_R_ENCRYPT_ERROR = 103,
PKCS12_R_ERROR_SETTING_ENCRYPTED_DATA_TYPE = 120,
PKCS12_R_INVALID_NULL_ARGUMENT = 104,
PKCS12_R_INVALID_NULL_PKCS12_POINTER = 105,
PKCS12_R_IV_GEN_ERROR = 106,
PKCS12_R_KEY_GEN_ERROR = 107,
PKCS12_R_MAC_ABSENT = 108,
PKCS12_R_MAC_GENERATION_ERROR = 109,
PKCS12_R_MAC_SETUP_ERROR = 110,
PKCS12_R_MAC_STRING_SET_ERROR = 111,
PKCS12_R_MAC_VERIFY_ERROR = 112,
PKCS12_R_MAC_VERIFY_FAILURE = 113,
PKCS12_R_PARSE_ERROR = 114,
PKCS12_R_PKCS12_ALGOR_CIPHERINIT_ERROR = 115,
PKCS12_R_PKCS12_CIPHERFINAL_ERROR = 116,
PKCS12_R_PKCS12_PBE_CRYPT_ERROR = 117,
PKCS12_R_UNKNOWN_DIGEST_ALGORITHM = 118,
PKCS12_R_UNSUPPORTED_PKCS12_MODE = 119,
PKCS12_SALT_LEN = 8,
PKCS5_DEFAULT_ITER = 2048,
PKCS5_SALT_LEN = 8,
PKCS7_BINARY = 0x80,
PKCS7_CRLFEOL = 0x800,
PKCS7_DETACHED = 0x40,
PKCS7_F_B64_READ_PKCS7 = 120,
PKCS7_F_B64_WRITE_PKCS7 = 121,
PKCS7_F_DO_PKCS7_SIGNED_ATTRIB = 136,
PKCS7_F_I2D_PKCS7_BIO_STREAM = 140,
PKCS7_F_PKCS7_ADD_ATTRIB_SMIMECAP = 118,
PKCS7_F_PKCS7_ADD_CERTIFICATE = 100,
PKCS7_F_PKCS7_ADD_CRL = 101,
PKCS7_F_PKCS7_ADD_RECIPIENT_INFO = 102,
PKCS7_F_PKCS7_ADD_SIGNATURE = 131,
PKCS7_F_PKCS7_ADD_SIGNER = 103,
PKCS7_F_PKCS7_ADD0_ATTRIB_SIGNING_TIME = 135,
PKCS7_F_PKCS7_BIO_ADD_DIGEST = 125,
PKCS7_F_PKCS7_COPY_EXISTING_DIGEST = 138,
PKCS7_F_PKCS7_CTRL = 104,
PKCS7_F_PKCS7_DATADECODE = 112,
PKCS7_F_PKCS7_DATAFINAL = 128,
PKCS7_F_PKCS7_DATAINIT = 105,
PKCS7_F_PKCS7_DATASIGN = 106,
PKCS7_F_PKCS7_DATAVERIFY = 107,
PKCS7_F_PKCS7_DECRYPT = 114,
PKCS7_F_PKCS7_DECRYPT_RINFO = 133,
PKCS7_F_PKCS7_ENCODE_RINFO = 132,
PKCS7_F_PKCS7_ENCRYPT = 115,
PKCS7_F_PKCS7_FINAL = 134,
PKCS7_F_PKCS7_FIND_DIGEST = 127,
PKCS7_F_PKCS7_GET0_SIGNERS = 124,
PKCS7_F_PKCS7_RECIP_INFO_SET = 130,
PKCS7_F_PKCS7_SET_CIPHER = 108,
PKCS7_F_PKCS7_SET_CONTENT = 109,
PKCS7_F_PKCS7_SET_DIGEST = 126,
PKCS7_F_PKCS7_SET_TYPE = 110,
PKCS7_F_PKCS7_SIGN = 116,
PKCS7_F_PKCS7_SIGN_ADD_SIGNER = 137,
PKCS7_F_PKCS7_SIGNATUREVERIFY = 113,
PKCS7_F_PKCS7_SIGNER_INFO_SET = 129,
PKCS7_F_PKCS7_SIGNER_INFO_SIGN = 139,
PKCS7_F_PKCS7_SIMPLE_SMIMECAP = 119,
PKCS7_F_PKCS7_VERIFY = 117,
PKCS7_F_SMIME_READ_PKCS7 = 122,
PKCS7_F_SMIME_TEXT = 123,
PKCS7_NOATTR = 0x100,
PKCS7_NOCERTS = 0x2,
PKCS7_NOCHAIN = 0x8,
PKCS7_NOCRL = 0x2000,
PKCS7_NOINTERN = 0x10,
PKCS7_NOOLDMIMETYPE = 0x400,
PKCS7_NOSIGS = 0x4,
PKCS7_NOSMIMECAP = 0x200,
PKCS7_NOVERIFY = 0x20,
PKCS7_OP_GET_DETACHED_SIGNATURE = 2,
PKCS7_OP_SET_DETACHED_SIGNATURE = 1,
PKCS7_PARTIAL = 0x4000,
PKCS7_R_CERTIFICATE_VERIFY_ERROR = 117,
PKCS7_R_CIPHER_HAS_NO_OBJECT_IDENTIFIER = 144,
PKCS7_R_CIPHER_NOT_INITIALIZED = 116,
PKCS7_R_CONTENT_AND_DATA_PRESENT = 118,
PKCS7_R_CTRL_ERROR = 152,
PKCS7_R_DECODE_ERROR = 130,
PKCS7_R_DECRYPT_ERROR = 119,
PKCS7_R_DECRYPTED_KEY_IS_WRONG_LENGTH = 100,
PKCS7_R_DIGEST_FAILURE = 101,
PKCS7_R_ENCRYPTION_CTRL_FAILURE = 149,
PKCS7_R_ENCRYPTION_NOT_SUPPORTED_FOR_THIS_KEY_TYPE = 150,
PKCS7_R_ERROR_ADDING_RECIPIENT = 120,
PKCS7_R_ERROR_SETTING_CIPHER = 121,
PKCS7_R_INVALID_MIME_TYPE = 131,
PKCS7_R_INVALID_NULL_POINTER = 143,
PKCS7_R_INVALID_SIGNED_DATA_TYPE = 155,
PKCS7_R_MIME_NO_CONTENT_TYPE = 132,
PKCS7_R_MIME_PARSE_ERROR = 133,
PKCS7_R_MIME_SIG_PARSE_ERROR = 134,
PKCS7_R_MISSING_CERIPEND_INFO = 103,
PKCS7_R_NO_CONTENT = 122,
PKCS7_R_NO_CONTENT_TYPE = 135,
PKCS7_R_NO_DEFAULT_DIGEST = 151,
PKCS7_R_NO_MATCHING_DIGEST_TYPE_FOUND = 154,
PKCS7_R_NO_MULTIPART_BODY_FAILURE = 136,
PKCS7_R_NO_MULTIPART_BOUNDARY = 137,
PKCS7_R_NO_RECIPIENT_MATCHES_CERTIFICATE = 115,
PKCS7_R_NO_RECIPIENT_MATCHES_KEY = 146,
PKCS7_R_NO_SIG_CONTENT_TYPE = 138,
PKCS7_R_NO_SIGNATURES_ON_DATA = 123,
PKCS7_R_NO_SIGNERS = 142,
PKCS7_R_OPERATION_NOT_SUPPORTED_ON_THIS_TYPE = 104,
PKCS7_R_PKCS7_ADD_SIGNATURE_ERROR = 124,
PKCS7_R_PKCS7_ADD_SIGNER_ERROR = 153,
PKCS7_R_PKCS7_DATAFINAL = 126,
PKCS7_R_PKCS7_DATAFINAL_ERROR = 125,
PKCS7_R_PKCS7_DATASIGN = 145,
PKCS7_R_PKCS7_PARSE_ERROR = 139,
PKCS7_R_PKCS7_SIG_PARSE_ERROR = 140,
PKCS7_R_PRIVATE_KEY_DOES_NOT_MATCH_CERTIFICATE = 127,
PKCS7_R_SIG_INVALID_MIME_TYPE = 141,
PKCS7_R_SIGNATURE_FAILURE = 105,
PKCS7_R_SIGNER_CERTIFICATE_NOT_FOUND = 128,
PKCS7_R_SIGNING_CTRL_FAILURE = 147,
PKCS7_R_SIGNING_NOT_SUPPORTED_FOR_THIS_KEY_TYPE = 148,
PKCS7_R_SMIME_TEXT_ERROR = 129,
PKCS7_R_UNABLE_TO_FIND_CERTIFICATE = 106,
PKCS7_R_UNABLE_TO_FIND_MEM_BIO = 107,
PKCS7_R_UNABLE_TO_FIND_MESSAGE_DIGEST = 108,
PKCS7_R_UNKNOWN_DIGEST_TYPE = 109,
PKCS7_R_UNKNOWN_OPERATION = 110,
PKCS7_R_UNSUPPORTED_CIPHER_TYPE = 111,
PKCS7_R_UNSUPPORTED_CONTENT_TYPE = 112,
PKCS7_R_WRONG_CONTENT_TYPE = 113,
PKCS7_R_WRONG_PKCS7_TYPE = 114,
PKCS7_REUSE_DIGEST = 0x8000,
PKCS7_S_BODY = 1,
PKCS7_S_HEADER = 0,
PKCS7_S_TAIL = 2,
PKCS7_STREAM = 0x1000,
PKCS7_TEXT = 0x1,
PKCS8_EMBEDDED_PARAM = 2,
PKCS8_NEG_PRIVKEY = 4,
PKCS8_NO_OCTET = 1,
PKCS8_NS_DB = 3,
PKCS8_OK = 0,
PSK_MAX_IDENTITY_LEN = 128,
PSK_MAX_PSK_LEN = 256,
RAND_F_RAND_GET_RAND_METHOD = 101,
RAND_F_RAND_INIT_FIPS = 102,
RAND_F_SSLEAY_RAND_BYTES = 100,
RAND_R_DUAL_EC_DRBG_DISABLED = 104,
RAND_R_ERROR_INITIALISING_DRBG = 102,
RAND_R_ERROR_INSTANTIATING_DRBG = 103,
RAND_R_NO_FIPS_RANDOM_METHOD_SET = 101,
RAND_R_PRNG_NOT_SEEDED = 100,
RC2_BLOCK = 8,
RC2_DECRYPT = 0,
RC2_ENCRYPT = 1,
RC2_KEY_LENGTH = 16,
RIPEMD160_CBLOCK = 64,
RIPEMD160_DIGEST_LENGTH = 20,
RIPEMD160_LONG_LOG2 = 3,
RSA_F_CHECK_PADDING_MD = 140,
RSA_F_DO_RSA_PRINT = 146,
RSA_F_INT_RSA_VERIFY = 145,
RSA_F_MEMORY_LOCK = 100,
RSA_F_OLD_RSA_PRIV_DECODE = 147,
RSA_F_PKEY_RSA_CTRL = 143,
RSA_F_PKEY_RSA_CTRL_STR = 144,
RSA_F_PKEY_RSA_SIGN = 142,
RSA_F_PKEY_RSA_VERIFY = 154,
RSA_F_PKEY_RSA_VERIFYRECOVER = 141,
RSA_F_RSA_ALGOR_TO_MD = 157,
RSA_F_RSA_BUILTIN_KEYGEN = 129,
RSA_F_RSA_CHECK_KEY = 123,
RSA_F_RSA_CMS_DECRYPT = 158,
RSA_F_RSA_EAY_PRIVATE_DECRYPT = 101,
RSA_F_RSA_EAY_PRIVATE_ENCRYPT = 102,
RSA_F_RSA_EAY_PUBLIC_DECRYPT = 103,
RSA_F_RSA_EAY_PUBLIC_ENCRYPT = 104,
RSA_F_RSA_GENERATE_KEY = 105,
RSA_F_RSA_GENERATE_KEY_EX = 155,
RSA_F_RSA_ITEM_VERIFY = 156,
RSA_F_RSA_MEMORY_LOCK = 130,
RSA_F_RSA_MGF1_TO_MD = 159,
RSA_F_RSA_NEW_METHOD = 106,
RSA_F_RSA_NULL = 124,
RSA_F_RSA_NULL_MOD_EXP = 131,
RSA_F_RSA_NULL_PRIVATE_DECRYPT = 132,
RSA_F_RSA_NULL_PRIVATE_ENCRYPT = 133,
RSA_F_RSA_NULL_PUBLIC_DECRYPT = 134,
RSA_F_RSA_NULL_PUBLIC_ENCRYPT = 135,
RSA_F_RSA_PADDING_ADD_NONE = 107,
RSA_F_RSA_PADDING_ADD_PKCS1_OAEP = 121,
RSA_F_RSA_PADDING_ADD_PKCS1_OAEP_MGF1 = 160,
RSA_F_RSA_PADDING_ADD_PKCS1_PSS = 125,
RSA_F_RSA_PADDING_ADD_PKCS1_PSS_MGF1 = 148,
RSA_F_RSA_PADDING_ADD_PKCS1_TYPE_1 = 108,
RSA_F_RSA_PADDING_ADD_PKCS1_TYPE_2 = 109,
RSA_F_RSA_PADDING_ADD_SSLV23 = 110,
RSA_F_RSA_PADDING_ADD_X931 = 127,
RSA_F_RSA_PADDING_CHECK_NONE = 111,
RSA_F_RSA_PADDING_CHECK_PKCS1_OAEP = 122,
RSA_F_RSA_PADDING_CHECK_PKCS1_OAEP_MGF1 = 161,
RSA_F_RSA_PADDING_CHECK_PKCS1_TYPE_1 = 112,
RSA_F_RSA_PADDING_CHECK_PKCS1_TYPE_2 = 113,
RSA_F_RSA_PADDING_CHECK_SSLV23 = 114,
RSA_F_RSA_PADDING_CHECK_X931 = 128,
RSA_F_RSA_PRINT = 115,
RSA_F_RSA_PRINT_FP = 116,
RSA_F_RSA_PRIV_DECODE = 137,
RSA_F_RSA_PRIV_ENCODE = 138,
RSA_F_RSA_PRIVATE_DECRYPT = 150,
RSA_F_RSA_PRIVATE_ENCRYPT = 151,
RSA_F_RSA_PSS_TO_CTX = 162,
RSA_F_RSA_PUB_DECODE = 139,
RSA_F_RSA_PUBLIC_DECRYPT = 152,
RSA_F_RSA_PUBLIC_ENCRYPT = 153,
RSA_F_RSA_SETUP_BLINDING = 136,
RSA_F_RSA_SIGN = 117,
RSA_F_RSA_SIGN_ASN1_OCTET_STRING = 118,
RSA_F_RSA_VERIFY = 119,
RSA_F_RSA_VERIFY_ASN1_OCTET_STRING = 120,
RSA_F_RSA_VERIFY_PKCS1_PSS = 126,
RSA_F_RSA_VERIFY_PKCS1_PSS_MGF1 = 149,
RSA_FLAG_BLINDING = 0x0008,
RSA_FLAG_CACHE_PRIVATE = 0x0004,
RSA_FLAG_CACHE_PUBLIC = 0x0002,
RSA_FLAG_CHECKED = 0x0800,
RSA_FLAG_EXT_PKEY = 0x0020,
RSA_FLAG_FIPS_METHOD = 0x0400,
RSA_FLAG_NO_BLINDING = 0x0080,
RSA_FLAG_NO_CONSTTIME = 0x0100,
RSA_FLAG_NON_FIPS_ALLOW = 0x0400,
RSA_FLAG_SIGN_VER = 0x0040,
RSA_FLAG_THREAD_SAFE = 0x0010,
RSA_NO_PADDING = 3,
RSA_PKCS1_OAEP_PADDING = 4,
RSA_PKCS1_PADDING = 1,
RSA_PKCS1_PADDING_SIZE = 11,
RSA_PKCS1_PSS_PADDING = 6,
RSA_R_ALGORITHM_MISMATCH = 100,
RSA_R_BAD_E_VALUE = 101,
RSA_R_BAD_FIXED_HEADER_DECRYPT = 102,
RSA_R_BAD_PAD_BYTE_COUNT = 103,
RSA_R_BAD_SIGNATURE = 104,
RSA_R_BLOCK_TYPE_IS_NOT_01 = 106,
RSA_R_BLOCK_TYPE_IS_NOT_02 = 107,
RSA_R_D_E_NOT_CONGRUENT_TO_1 = 123,
RSA_R_DATA_GREATER_THAN_MOD_LEN = 108,
RSA_R_DATA_TOO_LARGE = 109,
RSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE = 110,
RSA_R_DATA_TOO_LARGE_FOR_MODULUS = 132,
RSA_R_DATA_TOO_SMALL = 111,
RSA_R_DATA_TOO_SMALL_FOR_KEY_SIZE = 122,
RSA_R_DIGEST_DOES_NOT_MATCH = 166,
RSA_R_DIGEST_TOO_BIG_FOR_RSA_KEY = 112,
RSA_R_DMP1_NOT_CONGRUENT_TO_D = 124,
RSA_R_DMQ1_NOT_CONGRUENT_TO_D = 125,
RSA_R_FIRST_OCTET_INVALID = 133,
RSA_R_ILLEGAL_OR_UNSUPPORTED_PADDING_MODE = 144,
RSA_R_INVALID_DIGEST = 160,
RSA_R_INVALID_DIGEST_LENGTH = 143,
RSA_R_INVALID_HEADER = 137,
RSA_R_INVALID_KEYBITS = 145,
RSA_R_INVALID_LABEL = 161,
RSA_R_INVALID_MESSAGE_LENGTH = 131,
RSA_R_INVALID_MGF1_MD = 156,
RSA_R_INVALID_OAEP_PARAMETERS = 162,
RSA_R_INVALID_PADDING = 138,
RSA_R_INVALID_PADDING_MODE = 141,
RSA_R_INVALID_PSS_PARAMETERS = 149,
RSA_R_INVALID_PSS_SALTLEN = 146,
RSA_R_INVALID_SALT_LENGTH = 150,
RSA_R_INVALID_TRAILER = 139,
RSA_R_INVALID_X931_DIGEST = 142,
RSA_R_IQMP_NOT_INVERSE_OF_Q = 126,
RSA_R_KEY_SIZE_TOO_SMALL = 120,
RSA_R_LAST_OCTET_INVALID = 134,
RSA_R_MODULUS_TOO_LARGE = 105,
RSA_R_N_DOES_NOT_EQUAL_P_Q = 127,
RSA_R_NO_PUBLIC_EXPONENT = 140,
RSA_R_NON_FIPS_RSA_METHOD = 157,
RSA_R_NULL_BEFORE_BLOCK_MISSING = 113,
RSA_R_OAEP_DECODING_ERROR = 121,
RSA_R_OPERATION_NOT_ALLOWED_IN_FIPS_MODE = 158,
RSA_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE = 148,
RSA_R_P_NOT_PRIME = 128,
RSA_R_PADDING_CHECK_FAILED = 114,
RSA_R_PKCS_DECODING_ERROR = 159,
RSA_R_Q_NOT_PRIME = 129,
RSA_R_RSA_OPERATIONS_NOT_SUPPORTED = 130,
RSA_R_SLEN_CHECK_FAILED = 136,
RSA_R_SLEN_RECOVERY_FAILED = 135,
RSA_R_SSLV3_ROLLBACK_ATTACK = 115,
RSA_R_THE_ASN1_OBJECT_IDENTIFIER_IS_NOT_KNOWN_FOR_THIS_MD = 116,
RSA_R_UNKNOWN_ALGORITHM_TYPE = 117,
RSA_R_UNKNOWN_DIGEST = 163,
RSA_R_UNKNOWN_MASK_DIGEST = 151,
RSA_R_UNKNOWN_PADDING_TYPE = 118,
RSA_R_UNKNOWN_PSS_DIGEST = 152,
RSA_R_UNSUPPORTED_ENCRYPTION_TYPE = 164,
RSA_R_UNSUPPORTED_LABEL_SOURCE = 165,
RSA_R_UNSUPPORTED_MASK_ALGORITHM = 153,
RSA_R_UNSUPPORTED_MASK_PARAMETER = 154,
RSA_R_UNSUPPORTED_SIGNATURE_TYPE = 155,
RSA_R_VALUE_MISSING = 147,
RSA_R_WRONG_SIGNATURE_LENGTH = 119,
RSA_SSLV23_PADDING = 2,
RSA_X931_PADDING = 5,
SEED_BLOCK_SIZE = 16,
SEED_KEY_LENGTH = 16,
SEED_LONG = 1,
SHA_DIGEST_LENGTH = 20,
SHA_LBLOCK = 16,
SHA_LONG_LOG2 = 3,
SHA224_DIGEST_LENGTH = 28,
SHA256_DIGEST_LENGTH = 32,
SHA384_DIGEST_LENGTH = 48,
SHA512_DIGEST_LENGTH = 64,
SMIME_CRLFEOL = 0x800,
SMIME_OLDMIME = 0x400,
SMIME_STREAM = 0x1000,
SRP_ERR_MEMORY = 4,
SRP_ERR_OPEN_FILE = 3,
SRP_ERR_VBASE_BN_LIB = 2,
SRP_ERR_VBASE_INCOMPLETE_FILE = 1,
SRP_MINIMAL_N = 1024,
SRP_NO_ERROR = 0,
SRTP_AES128_CM_SHA1_32 = 0x0002,
SRTP_AES128_CM_SHA1_80 = 0x0001,
SRTP_AES128_F8_SHA1_32 = 0x0004,
SRTP_AES128_F8_SHA1_80 = 0x0003,
SRTP_NULL_SHA1_32 = 0x0006,
SRTP_NULL_SHA1_80 = 0x0005,
SSL_BUILD_CHAIN_FLAG_CHECK = 0x4,
SSL_BUILD_CHAIN_FLAG_CLEAR_ERROR = 0x10,
SSL_BUILD_CHAIN_FLAG_IGNORE_ERROR = 0x8,
SSL_BUILD_CHAIN_FLAG_NO_ROOT = 0x2,
SSL_BUILD_CHAIN_FLAG_UNTRUSTED = 0x1,
SSL_CB_EXIT = 0x02,
SSL_CB_HANDSHAKE_DONE = 0x20,
SSL_CB_HANDSHAKE_START = 0x10,
SSL_CB_LOOP = 0x01,
SSL_CB_READ = 0x04,
SSL_CB_WRITE = 0x08,
SSL_CERT_FLAG_BROKEN_PROTOCOL = 0x10000000,
SSL_CERT_FLAG_SUITEB_128_LOS = 0x30000,
SSL_CERT_FLAG_SUITEB_128_LOS_ONLY = 0x10000,
SSL_CERT_FLAG_SUITEB_192_LOS = 0x20000,
SSL_CERT_SET_FIRST = 1,
SSL_CERT_SET_NEXT = 2,
SSL_CERT_SET_SERVER = 3,
SSL_CONF_FLAG_CERTIFICATE = 0x20,
SSL_CONF_FLAG_CLIENT = 0x4,
SSL_CONF_FLAG_CMDLINE = 0x1,
SSL_CONF_FLAG_FILE = 0x2,
SSL_CONF_FLAG_SERVER = 0x8,
SSL_CONF_FLAG_SHOW_ERRORS = 0x10,
SSL_CONF_TYPE_DIR = 0x3,
SSL_CONF_TYPE_FILE = 0x2,
SSL_CONF_TYPE_STRING = 0x1,
SSL_CONF_TYPE_UNKNOWN = 0x0,
SSL_CTRL_BUILD_CERT_CHAIN = 105,
SSL_CTRL_CERT_FLAGS = 99,
SSL_CTRL_CHAIN = 88,
SSL_CTRL_CHAIN_CERT = 89,
SSL_CTRL_CHECK_PROTO_VERSION = 119,
SSL_CTRL_CLEAR_CERT_FLAGS = 100,
SSL_CTRL_CLEAR_EXTRA_CHAIN_CERTS = 83,
SSL_CTRL_CLEAR_MODE = 78,
SSL_CTRL_CLEAR_NUM_RENEGOTIATIONS = 11,
SSL_CTRL_CLEAR_OPTIONS = 77,
SSL_CTRL_EXTRA_CHAIN_CERT = 14,
SSL_CTRL_GET_CHAIN_CERTS = 115,
SSL_CTRL_GET_CLIENT_CERT_REQUEST = 9,
SSL_CTRL_GET_CLIENT_CERT_TYPES = 103,
SSL_CTRL_GET_CURVES = 90,
SSL_CTRL_GET_EC_POINT_FORMATS = 111,
SSL_CTRL_GET_EXTRA_CHAIN_CERTS = 82,
SSL_CTRL_GET_FLAGS = 13,
SSL_CTRL_GET_MAX_CERT_LIST = 50,
SSL_CTRL_GET_NUM_RENEGOTIATIONS = 10,
SSL_CTRL_GET_PEER_SIGNATURE_NID = 108,
SSL_CTRL_GET_RAW_CIPHERLIST = 110,
SSL_CTRL_GET_READ_AHEAD = 40,
SSL_CTRL_GET_RI_SUPPORT = 76,
SSL_CTRL_GET_SERVER_TMP_KEY = 109,
SSL_CTRL_GET_SESS_CACHE_MODE = 45,
SSL_CTRL_GET_SESS_CACHE_SIZE = 43,
SSL_CTRL_GET_SESSION_REUSED = 8,
SSL_CTRL_GET_SHARED_CURVE = 93,
SSL_CTRL_GET_TLS_EXT_HEARTBEAT_PENDING = 86,
SSL_CTRL_GET_TLSEXT_STATUS_REQ_EXTS = 66,
SSL_CTRL_GET_TLSEXT_STATUS_REQ_IDS = 68,
SSL_CTRL_GET_TLSEXT_STATUS_REQ_OCSP_RESP = 70,
SSL_CTRL_GET_TLSEXT_TICKET_KEYS = 58,
SSL_CTRL_GET_TOTAL_RENEGOTIATIONS = 12,
SSL_CTRL_MODE = 33,
SSL_CTRL_NEED_TMP_RSA = 1,
SSL_CTRL_OPTIONS = 32,
SSL_CTRL_SELECT_CURRENT_CERT = 116,
SSL_CTRL_SESS_ACCEPT = 24,
SSL_CTRL_SESS_ACCEPT_GOOD = 25,
SSL_CTRL_SESS_ACCEPT_RENEGOTIATE = 26,
SSL_CTRL_SESS_CACHE_FULL = 31,
SSL_CTRL_SESS_CB_HIT = 28,
SSL_CTRL_SESS_CONNECT = 21,
SSL_CTRL_SESS_CONNECT_GOOD = 22,
SSL_CTRL_SESS_CONNECT_RENEGOTIATE = 23,
SSL_CTRL_SESS_HIT = 27,
SSL_CTRL_SESS_MISSES = 29,
SSL_CTRL_SESS_NUMBER = 20,
SSL_CTRL_SESS_TIMEOUTS = 30,
SSL_CTRL_SET_CHAIN_CERT_STORE = 107,
SSL_CTRL_SET_CLIENT_CERT_TYPES = 104,
SSL_CTRL_SET_CLIENT_SIGALGS = 101,
SSL_CTRL_SET_CLIENT_SIGALGS_LIST = 102,
SSL_CTRL_SET_CURRENT_CERT = 117,
SSL_CTRL_SET_CURVES = 91,
SSL_CTRL_SET_CURVES_LIST = 92,
SSL_CTRL_SET_ECDH_AUTO = 94,
SSL_CTRL_SET_MAX_CERT_LIST = 51,
SSL_CTRL_SET_MAX_SEND_FRAGMENT = 52,
SSL_CTRL_SET_MSG_CALLBACK = 15,
SSL_CTRL_SET_MSG_CALLBACK_ARG = 16,
SSL_CTRL_SET_MTU = 17,
SSL_CTRL_SET_READ_AHEAD = 41,
SSL_CTRL_SET_SESS_CACHE_MODE = 44,
SSL_CTRL_SET_SESS_CACHE_SIZE = 42,
SSL_CTRL_SET_SIGALGS = 97,
SSL_CTRL_SET_SIGALGS_LIST = 98,
SSL_CTRL_SET_SRP_ARG = 78,
SSL_CTRL_SET_SRP_GIVE_CLIENT_PWD_CB = 77,
SSL_CTRL_SET_SRP_VERIFY_PARAM_CB = 76,
SSL_CTRL_SET_TLS_EXT_HEARTBEAT_NO_REQUESTS = 87,
SSL_CTRL_SET_TLS_EXT_SRP_PASSWORD = 81,
SSL_CTRL_SET_TLS_EXT_SRP_STRENGTH = 80,
SSL_CTRL_SET_TLS_EXT_SRP_USERNAME = 79,
SSL_CTRL_SET_TLS_EXT_SRP_USERNAME_CB = 75,
SSL_CTRL_SET_TLSEXT_DEBUG_ARG = 57,
SSL_CTRL_SET_TLSEXT_DEBUG_CB = 56,
SSL_CTRL_SET_TLSEXT_HOSTNAME = 55,
SSL_CTRL_SET_TLSEXT_OPAQUE_PRF_INPUT = 60,
SSL_CTRL_SET_TLSEXT_OPAQUE_PRF_INPUT_CB = 61,
SSL_CTRL_SET_TLSEXT_OPAQUE_PRF_INPUT_CB_ARG = 62,
SSL_CTRL_SET_TLSEXT_SERVERNAME_ARG = 54,
SSL_CTRL_SET_TLSEXT_SERVERNAME_CB = 53,
SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB = 63,
SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB_ARG = 64,
SSL_CTRL_SET_TLSEXT_STATUS_REQ_EXTS = 67,
SSL_CTRL_SET_TLSEXT_STATUS_REQ_IDS = 69,
SSL_CTRL_SET_TLSEXT_STATUS_REQ_OCSP_RESP = 71,
SSL_CTRL_SET_TLSEXT_STATUS_REQ_TYPE = 65,
SSL_CTRL_SET_TLSEXT_TICKET_KEY_CB = 72,
SSL_CTRL_SET_TLSEXT_TICKET_KEYS = 59,
SSL_CTRL_SET_TMP_DH = 3,
SSL_CTRL_SET_TMP_DH_CB = 6,
SSL_CTRL_SET_TMP_ECDH = 4,
SSL_CTRL_SET_TMP_ECDH_CB = 7,
SSL_CTRL_SET_TMP_RSA = 2,
SSL_CTRL_SET_TMP_RSA_CB = 5,
SSL_CTRL_SET_VERIFY_CERT_STORE = 106,
SSL_CTRL_TLS_EXT_SEND_HEARTBEAT = 85,
SSL_ERROR_NONE = 0,
SSL_ERROR_SSL = 1,
SSL_ERROR_WANT_ACCEPT = 8,
SSL_ERROR_WANT_CONNECT = 7,
SSL_ERROR_WANT_READ = 2,
SSL_ERROR_WANT_WRITE = 3,
SSL_ERROR_WANT_X509_LOOKUP = 4,
SSL_ERROR_ZERO_RETURN = 6,
SSL_F_CHECK_SUITEB_CIPHER_LIST = 331,
SSL_F_CLIENT_CERTIFICATE = 100,
SSL_F_CLIENT_FINISHED = 167,
SSL_F_CLIENT_HELLO = 101,
SSL_F_CLIENT_MASTER_KEY = 102,
SSL_F_D2I_SSL_SESSION = 103,
SSL_F_DO_DTLS1_WRITE = 245,
SSL_F_DO_SSL3_WRITE = 104,
SSL_F_DTLS1_ACCEPT = 246,
SSL_F_DTLS1_ADD_CERT_TO_BUF = 295,
SSL_F_DTLS1_BUFFER_RECORD = 247,
SSL_F_DTLS1_CHECK_TIMEOUT_NUM = 316,
SSL_F_DTLS1_CLIENT_HELLO = 248,
SSL_F_DTLS1_CONNECT = 249,
SSL_F_DTLS1_ENC = 250,
SSL_F_DTLS1_GET_HELLO_VERIFY = 251,
SSL_F_DTLS1_GET_MESSAGE = 252,
SSL_F_DTLS1_GET_MESSAGE_FRAGMENT = 253,
SSL_F_DTLS1_GET_RECORD = 254,
SSL_F_DTLS1_HANDLE_TIMEOUT = 297,
SSL_F_DTLS1_HEARTBEAT = 305,
SSL_F_DTLS1_OUTPUT_CERT_CHAIN = 255,
SSL_F_DTLS1_PREPROCESS_FRAGMENT = 288,
SSL_F_DTLS1_PROCESS_BUFFERED_RECORDS = 424,
SSL_F_DTLS1_PROCESS_OUT_OF_SEQ_MESSAGE = 256,
SSL_F_DTLS1_PROCESS_RECORD = 257,
SSL_F_DTLS1_READ_BYTES = 258,
SSL_F_DTLS1_READ_FAILED = 259,
SSL_F_DTLS1_SEND_CERTIFICATE_REQUEST = 260,
SSL_F_DTLS1_SEND_CLIENT_CERTIFICATE = 261,
SSL_F_DTLS1_SEND_CLIENT_KEY_EXCHANGE = 262,
SSL_F_DTLS1_SEND_CLIENT_VERIFY = 263,
SSL_F_DTLS1_SEND_HELLO_VERIFY_REQUEST = 264,
SSL_F_DTLS1_SEND_SERVER_CERTIFICATE = 265,
SSL_F_DTLS1_SEND_SERVER_HELLO = 266,
SSL_F_DTLS1_SEND_SERVER_KEY_EXCHANGE = 267,
SSL_F_DTLS1_WRITE_APP_DATA_BYTES = 268,
SSL_F_GET_CLIENT_FINISHED = 105,
SSL_F_GET_CLIENT_HELLO = 106,
SSL_F_GET_CLIENT_MASTER_KEY = 107,
SSL_F_GET_SERVER_FINISHED = 108,
SSL_F_GET_SERVER_HELLO = 109,
SSL_F_GET_SERVER_STATIC_DH_KEY = 340,
SSL_F_GET_SERVER_VERIFY = 110,
SSL_F_I2D_SSL_SESSION = 111,
SSL_F_READ_N = 112,
SSL_F_REQUEST_CERTIFICATE = 113,
SSL_F_SERVER_FINISH = 239,
SSL_F_SERVER_HELLO = 114,
SSL_F_SERVER_VERIFY = 240,
SSL_F_SSL_ADD_CERT_CHAIN = 318,
SSL_F_SSL_ADD_CERT_TO_BUF = 319,
SSL_F_SSL_ADD_CLIENTHELLO_RENEGOTIATE_EXT = 298,
SSL_F_SSL_ADD_CLIENTHELLO_TLSEXT = 277,
SSL_F_SSL_ADD_CLIENTHELLO_USE_SRTP_EXT = 307,
SSL_F_SSL_ADD_DIR_CERT_SUBJECTS_TO_STACK = 215,
SSL_F_SSL_ADD_FILE_CERT_SUBJECTS_TO_STACK = 216,
SSL_F_SSL_ADD_SERVERHELLO_RENEGOTIATE_EXT = 299,
SSL_F_SSL_ADD_SERVERHELLO_TLSEXT = 278,
SSL_F_SSL_ADD_SERVERHELLO_USE_SRTP_EXT = 308,
SSL_F_SSL_BAD_METHOD = 160,
SSL_F_SSL_BUILD_CERT_CHAIN = 332,
SSL_F_SSL_BYTES_TO_CIPHER_LIST = 161,
SSL_F_SSL_CERT_DUP = 221,
SSL_F_SSL_CERT_INST = 222,
SSL_F_SSL_CERT_INSTANTIATE = 214,
SSL_F_SSL_CERT_NEW = 162,
SSL_F_SSL_CHECK_PRIVATE_KEY = 163,
SSL_F_SSL_CHECK_SERVERHELLO_TLSEXT = 280,
SSL_F_SSL_CHECK_SRVR_ECC_CERT_AND_ALG = 279,
SSL_F_SSL_CIPHER_PROCESS_RULESTR = 230,
SSL_F_SSL_CIPHER_STRENGTH_SORT = 231,
SSL_F_SSL_CLEAR = 164,
SSL_F_SSL_COMP_ADD_COMPRESSION_METHOD = 165,
SSL_F_SSL_CONF_CMD = 334,
SSL_F_SSL_CREATE_CIPHER_LIST = 166,
SSL_F_SSL_CTRL = 232,
SSL_F_SSL_CTX_CHECK_PRIVATE_KEY = 168,
SSL_F_SSL_CTX_MAKE_PROFILES = 309,
SSL_F_SSL_CTX_NEW = 169,
SSL_F_SSL_CTX_SET_CIPHER_LIST = 269,
SSL_F_SSL_CTX_SET_CLIENT_CERT_ENGINE = 290,
SSL_F_SSL_CTX_SET_PURPOSE = 226,
SSL_F_SSL_CTX_SET_SESSION_ID_CONTEXT = 219,
SSL_F_SSL_CTX_SET_SSL_VERSION = 170,
SSL_F_SSL_CTX_SET_TRUST = 229,
SSL_F_SSL_CTX_USE_CERTIFICATE = 171,
SSL_F_SSL_CTX_USE_CERTIFICATE_ASN1 = 172,
SSL_F_SSL_CTX_USE_CERTIFICATE_CHAIN_FILE = 220,
SSL_F_SSL_CTX_USE_CERTIFICATE_FILE = 173,
SSL_F_SSL_CTX_USE_PRIVATEKEY = 174,
SSL_F_SSL_CTX_USE_PRIVATEKEY_ASN1 = 175,
SSL_F_SSL_CTX_USE_PRIVATEKEY_FILE = 176,
SSL_F_SSL_CTX_USE_PSK_IDENTITY_HINT = 272,
SSL_F_SSL_CTX_USE_RSAPRIVATEKEY = 177,
SSL_F_SSL_CTX_USE_RSAPRIVATEKEY_ASN1 = 178,
SSL_F_SSL_CTX_USE_RSAPRIVATEKEY_FILE = 179,
SSL_F_SSL_CTX_USE_SERVERINFO = 336,
SSL_F_SSL_CTX_USE_SERVERINFO_FILE = 337,
SSL_F_SSL_DO_HANDSHAKE = 180,
SSL_F_SSL_GET_NEW_SESSION = 181,
SSL_F_SSL_GET_PREV_SESSION = 217,
SSL_F_SSL_GET_SERVER_CERT_INDEX = 322,
SSL_F_SSL_GET_SERVER_SEND_CERT = 182,
SSL_F_SSL_GET_SERVER_SEND_PKEY = 317,
SSL_F_SSL_GET_SIGN_PKEY = 183,
SSL_F_SSL_INIT_WBIO_BUFFER = 184,
SSL_F_SSL_LOAD_CLIENT_CA_FILE = 185,
SSL_F_SSL_NEW = 186,
SSL_F_SSL_PARSE_CLIENTHELLO_RENEGOTIATE_EXT = 300,
SSL_F_SSL_PARSE_CLIENTHELLO_TLSEXT = 302,
SSL_F_SSL_PARSE_CLIENTHELLO_USE_SRTP_EXT = 310,
SSL_F_SSL_PARSE_SERVERHELLO_RENEGOTIATE_EXT = 301,
SSL_F_SSL_PARSE_SERVERHELLO_TLSEXT = 303,
SSL_F_SSL_PARSE_SERVERHELLO_USE_SRTP_EXT = 311,
SSL_F_SSL_PEEK = 270,
SSL_F_SSL_PREPARE_CLIENTHELLO_TLSEXT = 281,
SSL_F_SSL_PREPARE_SERVERHELLO_TLSEXT = 282,
SSL_F_SSL_READ = 223,
SSL_F_SSL_RSA_PRIVATE_DECRYPT = 187,
SSL_F_SSL_RSA_PUBLIC_ENCRYPT = 188,
SSL_F_SSL_SCAN_CLIENTHELLO_TLSEXT = 320,
SSL_F_SSL_SCAN_SERVERHELLO_TLSEXT = 321,
SSL_F_SSL_SESS_CERT_NEW = 225,
SSL_F_SSL_SESSION_DUP = 348,
SSL_F_SSL_SESSION_NEW = 189,
SSL_F_SSL_SESSION_PRINT_FP = 190,
SSL_F_SSL_SESSION_SET1_ID_CONTEXT = 312,
SSL_F_SSL_SET_CERT = 191,
SSL_F_SSL_SET_CIPHER_LIST = 271,
SSL_F_SSL_SET_FD = 192,
SSL_F_SSL_SET_PKEY = 193,
SSL_F_SSL_SET_PURPOSE = 227,
SSL_F_SSL_SET_RFD = 194,
SSL_F_SSL_SET_SESSION = 195,
SSL_F_SSL_SET_SESSION_ID_CONTEXT = 218,
SSL_F_SSL_SET_SESSION_TICKET_EXT = 294,
SSL_F_SSL_SET_TRUST = 228,
SSL_F_SSL_SET_WFD = 196,
SSL_F_SSL_SHUTDOWN = 224,
SSL_F_SSL_SRP_CTX_INIT = 313,
SSL_F_SSL_UNDEFINED_CONST_FUNCTION = 243,
SSL_F_SSL_UNDEFINED_FUNCTION = 197,
SSL_F_SSL_UNDEFINED_VOID_FUNCTION = 244,
SSL_F_SSL_USE_CERTIFICATE = 198,
SSL_F_SSL_USE_CERTIFICATE_ASN1 = 199,
SSL_F_SSL_USE_CERTIFICATE_FILE = 200,
SSL_F_SSL_USE_PRIVATEKEY = 201,
SSL_F_SSL_USE_PRIVATEKEY_ASN1 = 202,
SSL_F_SSL_USE_PRIVATEKEY_FILE = 203,
SSL_F_SSL_USE_PSK_IDENTITY_HINT = 273,
SSL_F_SSL_USE_RSAPRIVATEKEY = 204,
SSL_F_SSL_USE_RSAPRIVATEKEY_ASN1 = 205,
SSL_F_SSL_USE_RSAPRIVATEKEY_FILE = 206,
SSL_F_SSL_VERIFY_CERT_CHAIN = 207,
SSL_F_SSL_WRITE = 208,
SSL_F_SSL2_ACCEPT = 122,
SSL_F_SSL2_CONNECT = 123,
SSL_F_SSL2_ENC_INIT = 124,
SSL_F_SSL2_GENERATE_KEY_MATERIAL = 241,
SSL_F_SSL2_PEEK = 234,
SSL_F_SSL2_READ = 125,
SSL_F_SSL2_READ_INTERNAL = 236,
SSL_F_SSL2_SET_CERTIFICATE = 126,
SSL_F_SSL2_WRITE = 127,
SSL_F_SSL23_ACCEPT = 115,
SSL_F_SSL23_CLIENT_HELLO = 116,
SSL_F_SSL23_CONNECT = 117,
SSL_F_SSL23_GET_CLIENT_HELLO = 118,
SSL_F_SSL23_GET_SERVER_HELLO = 119,
SSL_F_SSL23_PEEK = 237,
SSL_F_SSL23_READ = 120,
SSL_F_SSL23_WRITE = 121,
SSL_F_SSL3_ACCEPT = 128,
SSL_F_SSL3_ADD_CERT_TO_BUF = 296,
SSL_F_SSL3_CALLBACK_CTRL = 233,
SSL_F_SSL3_CHANGE_CIPHER_STATE = 129,
SSL_F_SSL3_CHECK_CERT_AND_ALGORITHM = 130,
SSL_F_SSL3_CHECK_CLIENT_HELLO = 304,
SSL_F_SSL3_CHECK_FINISHED = 339,
SSL_F_SSL3_CLIENT_HELLO = 131,
SSL_F_SSL3_CONNECT = 132,
SSL_F_SSL3_CTRL = 213,
SSL_F_SSL3_CTX_CTRL = 133,
SSL_F_SSL3_DIGEST_CACHED_RECORDS = 293,
SSL_F_SSL3_DO_CHANGE_CIPHER_SPEC = 292,
SSL_F_SSL3_ENC = 134,
SSL_F_SSL3_GENERATE_KEY_BLOCK = 238,
SSL_F_SSL3_GENERATE_MASTER_SECRET = 388,
SSL_F_SSL3_GET_CERT_STATUS = 289,
SSL_F_SSL3_GET_CERT_VERIFY = 136,
SSL_F_SSL3_GET_CERTIFICATE_REQUEST = 135,
SSL_F_SSL3_GET_CLIENT_CERTIFICATE = 137,
SSL_F_SSL3_GET_CLIENT_HELLO = 138,
SSL_F_SSL3_GET_CLIENT_KEY_EXCHANGE = 139,
SSL_F_SSL3_GET_FINISHED = 140,
SSL_F_SSL3_GET_KEY_EXCHANGE = 141,
SSL_F_SSL3_GET_MESSAGE = 142,
SSL_F_SSL3_GET_NEW_SESSION_TICKET = 283,
SSL_F_SSL3_GET_NEXT_PROTO = 306,
SSL_F_SSL3_GET_RECORD = 143,
SSL_F_SSL3_GET_SERVER_CERTIFICATE = 144,
SSL_F_SSL3_GET_SERVER_DONE = 145,
SSL_F_SSL3_GET_SERVER_HELLO = 146,
SSL_F_SSL3_HANDSHAKE_MAC = 285,
SSL_F_SSL3_NEW_SESSION_TICKET = 287,
SSL_F_SSL3_OUTPUT_CERT_CHAIN = 147,
SSL_F_SSL3_PEEK = 235,
SSL_F_SSL3_READ_BYTES = 148,
SSL_F_SSL3_READ_N = 149,
SSL_F_SSL3_SEND_CERTIFICATE_REQUEST = 150,
SSL_F_SSL3_SEND_CLIENT_CERTIFICATE = 151,
SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE = 152,
SSL_F_SSL3_SEND_CLIENT_VERIFY = 153,
SSL_F_SSL3_SEND_SERVER_CERTIFICATE = 154,
SSL_F_SSL3_SEND_SERVER_HELLO = 242,
SSL_F_SSL3_SEND_SERVER_KEY_EXCHANGE = 155,
SSL_F_SSL3_SETUP_KEY_BLOCK = 157,
SSL_F_SSL3_SETUP_READ_BUFFER = 156,
SSL_F_SSL3_SETUP_WRITE_BUFFER = 291,
SSL_F_SSL3_WRITE_BYTES = 158,
SSL_F_SSL3_WRITE_PENDING = 159,
SSL_F_TLS1_CERT_VERIFY_MAC = 286,
SSL_F_TLS1_CHANGE_CIPHER_STATE = 209,
SSL_F_TLS1_CHECK_SERVERHELLO_TLSEXT = 274,
SSL_F_TLS1_ENC = 210,
SSL_F_TLS1_EXPORT_KEYING_MATERIAL = 314,
SSL_F_TLS1_GET_CURVELIST = 338,
SSL_F_TLS1_HEARTBEAT = 315,
SSL_F_TLS1_PREPARE_CLIENTHELLO_TLSEXT = 275,
SSL_F_TLS1_PREPARE_SERVERHELLO_TLSEXT = 276,
SSL_F_TLS1_PRF = 284,
SSL_F_TLS1_SET_SERVER_SIGALGS = 335,
SSL_F_TLS1_SETUP_KEY_BLOCK = 211,
SSL_F_TLS12_CHECK_PEER_SIGALG = 333,
SSL_F_WRITE_PENDING = 212,
SSL_MAC_FLAG_READ_MAC_STREAM = 1,
SSL_MAC_FLAG_WRITE_MAC_STREAM = 2,
SSL_MAX_BUF_FREELIST_LEN_DEFAULT = 32,
SSL_MAX_KEY_ARG_LENGTH = 8,
SSL_MAX_KRB5_PRINCIPAL_LENGTH = 256,
SSL_MAX_MASTER_KEY_LENGTH = 48,
SSL_MAX_SID_CTX_LENGTH = 32,
SSL_MAX_SSL_SESSION_ID_LENGTH = 32,
SSL_NOTHING = 1,
SSL_OP_EPHEMERAL_RSA = 0x0,
SSL_OP_MSIE_SSLV2_RSA_PADDING = 0x0,
SSL_OP_PKCS1_CHECK_1 = 0x0,
SSL_OP_PKCS1_CHECK_2 = 0x0,
SSL_OP_SSLREF2_REUSE_CERT_TYPE_BUG = 0x0,
SSL_R_APP_DATA_IN_HANDSHAKE = 100,
SSL_R_ATTEMPT_TO_REUSE_SESSION_IN_DIFFERENT_CONTEXT = 272,
SSL_R_BAD_ALERT_RECORD = 101,
SSL_R_BAD_AUTHENTICATION_TYPE = 102,
SSL_R_BAD_CHANGE_CIPHER_SPEC = 103,
SSL_R_BAD_CHECKSUM = 104,
SSL_R_BAD_DATA = 390,
SSL_R_BAD_DATA_RETURNED_BY_CALLBACK = 106,
SSL_R_BAD_DECOMPRESSION = 107,
SSL_R_BAD_DH_G_LENGTH = 108,
SSL_R_BAD_DH_G_VALUE = 375,
SSL_R_BAD_DH_P_LENGTH = 110,
SSL_R_BAD_DH_P_VALUE = 395,
SSL_R_BAD_DH_PUB_KEY_LENGTH = 109,
SSL_R_BAD_DH_PUB_KEY_VALUE = 393,
SSL_R_BAD_DIGEST_LENGTH = 111,
SSL_R_BAD_DSA_SIGNATURE = 112,
SSL_R_BAD_ECC_CERT = 304,
SSL_R_BAD_ECDSA_SIGNATURE = 305,
SSL_R_BAD_ECPOINT = 306,
SSL_R_BAD_HANDSHAKE_LENGTH = 332,
SSL_R_BAD_HELLO_REQUEST = 105,
SSL_R_BAD_LENGTH = 271,
SSL_R_BAD_MAC_DECODE = 113,
SSL_R_BAD_MAC_LENGTH = 333,
SSL_R_BAD_MESSAGE_TYPE = 114,
SSL_R_BAD_PACKET_LENGTH = 115,
SSL_R_BAD_PROTOCOL_VERSION_NUMBER = 116,
SSL_R_BAD_PSK_IDENTITY_HINT_LENGTH = 316,
SSL_R_BAD_RESPONSE_ARGUMENT = 117,
SSL_R_BAD_RSA_DECRYPT = 118,
SSL_R_BAD_RSA_E_LENGTH = 120,
SSL_R_BAD_RSA_ENCRYPT = 119,
SSL_R_BAD_RSA_MODULUS_LENGTH = 121,
SSL_R_BAD_RSA_SIGNATURE = 122,
SSL_R_BAD_SIGNATURE = 123,
SSL_R_BAD_SRP_A_LENGTH = 347,
SSL_R_BAD_SRP_B_LENGTH = 348,
SSL_R_BAD_SRP_G_LENGTH = 349,
SSL_R_BAD_SRP_N_LENGTH = 350,
SSL_R_BAD_SRP_PARAMETERS = 371,
SSL_R_BAD_SRP_S_LENGTH = 351,
SSL_R_BAD_SRTP_MKI_VALUE = 352,
SSL_R_BAD_SRTP_PROTECTION_PROFILE_LIST = 353,
SSL_R_BAD_SSL_FILETYPE = 124,
SSL_R_BAD_SSL_SESSION_ID_LENGTH = 125,
SSL_R_BAD_STATE = 126,
SSL_R_BAD_VALUE = 384,
SSL_R_BAD_WRITE_RETRY = 127,
SSL_R_BIO_NOT_SET = 128,
SSL_R_BLOCK_CIPHER_PAD_IS_WRONG = 129,
SSL_R_BN_LIB = 130,
SSL_R_CA_DN_LENGTH_MISMATCH = 131,
SSL_R_CA_DN_TOO_LONG = 132,
SSL_R_CCS_RECEIVED_EARLY = 133,
SSL_R_CERT_CB_ERROR = 377,
SSL_R_CERT_LENGTH_MISMATCH = 135,
SSL_R_CERTIFICATE_VERIFY_FAILED = 134,
SSL_R_CHALLENGE_IS_DIFFERENT = 136,
SSL_R_CIPHER_CODE_WRONG_LENGTH = 137,
SSL_R_CIPHER_OR_HASH_UNAVAILABLE = 138,
SSL_R_CIPHER_TABLE_SRC_ERROR = 139,
SSL_R_CLIENTHELLO_TLSEXT = 226,
SSL_R_COMPRESSED_LENGTH_TOO_LONG = 140,
SSL_R_COMPRESSION_DISABLED = 343,
SSL_R_COMPRESSION_FAILURE = 141,
SSL_R_COMPRESSION_ID_NOT_WITHIN_PRIVATE_RANGE = 307,
SSL_R_COMPRESSION_LIBRARY_ERROR = 142,
SSL_R_CONNECTION_ID_IS_DIFFERENT = 143,
SSL_R_CONNECTION_TYPE_NOT_SET = 144,
SSL_R_COOKIE_MISMATCH = 308,
SSL_R_DATA_BETWEEN_CCS_AND_FINISHED = 145,
SSL_R_DATA_LENGTH_TOO_LONG = 146,
SSL_R_DECRYPTION_FAILED = 147,
SSL_R_DECRYPTION_FAILED_OR_BAD_RECORD_MAC = 281,
SSL_R_DH_KEY_TOO_SMALL = 372,
SSL_R_DH_PUBLIC_VALUE_LENGTH_IS_WRONG = 148,
SSL_R_DIGEST_CHECK_FAILED = 149,
SSL_R_DTLS_MESSAGE_TOO_BIG = 334,
SSL_R_DUPLICATE_COMPRESSION_ID = 309,
SSL_R_ECC_CERT_NOT_FOR_KEY_AGREEMENT = 317,
SSL_R_ECC_CERT_NOT_FOR_SIGNING = 318,
SSL_R_ECC_CERT_SHOULD_HAVE_RSA_SIGNATURE = 322,
SSL_R_ECC_CERT_SHOULD_HAVE_SHA1_SIGNATURE = 323,
SSL_R_ECDH_REQUIRED_FOR_SUITEB_MODE = 374,
SSL_R_ECGROUP_TOO_LARGE_FOR_CIPHER = 310,
SSL_R_EMPTY_SRTP_PROTECTION_PROFILE_LIST = 354,
SSL_R_ENCRYPTED_LENGTH_TOO_LONG = 150,
SSL_R_ERROR_GENERATING_TMP_RSA_KEY = 282,
SSL_R_ERROR_IN_RECEIVED_CIPHER_LIST = 151,
SSL_R_EXCESSIVE_MESSAGE_SIZE = 152,
SSL_R_EXTRA_DATA_IN_MESSAGE = 153,
SSL_R_GOT_A_FIN_BEFORE_A_CCS = 154,
SSL_R_GOT_NEXT_PROTO_BEFORE_A_CCS = 355,
SSL_R_GOT_NEXT_PROTO_WITHOUT_EXTENSION = 356,
SSL_R_HTTP_REQUEST = 156,
SSL_R_HTTPS_PROXY_REQUEST = 155,
SSL_R_ILLEGAL_PADDING = 283,
SSL_R_ILLEGAL_SUITEB_DIGEST = 380,
SSL_R_INAPPROPRIATE_FALLBACK = 373,
SSL_R_INCONSISTENT_COMPRESSION = 340,
SSL_R_INVALID_CHALLENGE_LENGTH = 158,
SSL_R_INVALID_COMMAND = 280,
SSL_R_INVALID_COMPRESSION_ALGORITHM = 341,
SSL_R_INVALID_NULL_CMD_NAME = 385,
SSL_R_INVALID_PURPOSE = 278,
SSL_R_INVALID_SERVERINFO_DATA = 388,
SSL_R_INVALID_SRP_USERNAME = 357,
SSL_R_INVALID_STATUS_RESPONSE = 328,
SSL_R_INVALID_TICKET_KEYS_LENGTH = 325,
SSL_R_INVALID_TRUST = 279,
SSL_R_KEY_ARG_TOO_LONG = 284,
SSL_R_KRB5 = 285,
SSL_R_KRB5_C_CC_PRINC = 286,
SSL_R_KRB5_C_GET_CRED = 287,
SSL_R_KRB5_C_INIT = 288,
SSL_R_KRB5_C_MK_REQ = 289,
SSL_R_KRB5_S_BAD_TICKET = 290,
SSL_R_KRB5_S_INIT = 291,
SSL_R_KRB5_S_RD_REQ = 292,
SSL_R_KRB5_S_TKT_EXPIRED = 293,
SSL_R_KRB5_S_TKT_NYV = 294,
SSL_R_KRB5_S_TKT_SKEW = 295,
SSL_R_LENGTH_MISMATCH = 159,
SSL_R_LENGTH_TOO_SHORT = 160,
SSL_R_LIBRARY_BUG = 274,
SSL_R_LIBRARY_HAS_NO_CIPHERS = 161,
SSL_R_MESSAGE_TOO_LONG = 296,
SSL_R_MISSING_DH_DSA_CERT = 162,
SSL_R_MISSING_DH_KEY = 163,
SSL_R_MISSING_DH_RSA_CERT = 164,
SSL_R_MISSING_DSA_SIGNING_CERT = 165,
SSL_R_MISSING_ECDH_CERT = 382,
SSL_R_MISSING_ECDSA_SIGNING_CERT = 381,
SSL_R_MISSING_EXPORT_TMP_DH_KEY = 166,
SSL_R_MISSING_EXPORT_TMP_RSA_KEY = 167,
SSL_R_MISSING_RSA_CERTIFICATE = 168,
SSL_R_MISSING_RSA_ENCRYPTING_CERT = 169,
SSL_R_MISSING_RSA_SIGNING_CERT = 170,
SSL_R_MISSING_SRP_PARAM = 358,
SSL_R_MISSING_TMP_DH_KEY = 171,
SSL_R_MISSING_TMP_ECDH_KEY = 311,
SSL_R_MISSING_TMP_RSA_KEY = 172,
SSL_R_MISSING_TMP_RSA_PKEY = 173,
SSL_R_MISSING_VERIFY_MESSAGE = 174,
SSL_R_MULTIPLE_SGC_RESTARTS = 346,
SSL_R_NO_CERTIFICATE_ASSIGNED = 177,
SSL_R_NO_CERTIFICATE_RETURNED = 178,
SSL_R_NO_CERTIFICATE_SET = 179,
SSL_R_NO_CERTIFICATE_SPECIFIED = 180,
SSL_R_NO_CERTIFICATES_RETURNED = 176,
SSL_R_NO_CIPHER_LIST = 184,
SSL_R_NO_CIPHER_MATCH = 185,
SSL_R_NO_CIPHERS_AVAILABLE = 181,
SSL_R_NO_CIPHERS_PASSED = 182,
SSL_R_NO_CIPHERS_SPECIFIED = 183,
SSL_R_NO_CLIENT_CERT_METHOD = 331,
SSL_R_NO_CLIENT_CERT_RECEIVED = 186,
SSL_R_NO_COMPRESSION_SPECIFIED = 187,
SSL_R_NO_GOST_CERTIFICATE_SENT_BY_PEER = 330,
SSL_R_NO_METHOD_SPECIFIED = 188,
SSL_R_NO_PEM_EXTENSIONS = 389,
SSL_R_NO_PRIVATE_KEY_ASSIGNED = 190,
SSL_R_NO_PRIVATEKEY = 189,
SSL_R_NO_PROTOCOLS_AVAILABLE = 191,
SSL_R_NO_PUBLICKEY = 192,
SSL_R_NO_RENEGOTIATION = 339,
SSL_R_NO_REQUIRED_DIGEST = 324,
SSL_R_NO_SHARED_CIPHER = 193,
SSL_R_NO_SHARED_SIGATURE_ALGORITHMS = 376,
SSL_R_NO_SRTP_PROFILES = 359,
SSL_R_NO_VERIFY_CALLBACK = 194,
SSL_R_NON_SSLV2_INITIAL_PACKET = 175,
SSL_R_NULL_SSL_CTX = 195,
SSL_R_NULL_SSL_METHOD_PASSED = 196,
SSL_R_OLD_SESSION_CIPHER_NOT_RETURNED = 197,
SSL_R_OLD_SESSION_COMPRESSION_ALGORITHM_NOT_RETURNED = 344,
SSL_R_ONLY_DTLS_1_2_ALLOWED_IN_SUITEB_MODE = 387,
SSL_R_ONLY_TLS_1_2_ALLOWED_IN_SUITEB_MODE = 379,
SSL_R_ONLY_TLS_ALLOWED_IN_FIPS_MODE = 297,
SSL_R_OPAQUE_PRF_INPUT_TOO_LONG = 327,
SSL_R_PACKET_LENGTH_TOO_LONG = 198,
SSL_R_PARSE_TLSEXT = 227,
SSL_R_PATH_TOO_LONG = 270,
SSL_R_PEER_DID_NOT_RETURN_A_CERTIFICATE = 199,
SSL_R_PEER_ERROR = 200,
SSL_R_PEER_ERROR_CERTIFICATE = 201,
SSL_R_PEER_ERROR_NO_CERTIFICATE = 202,
SSL_R_PEER_ERROR_NO_CIPHER = 203,
SSL_R_PEER_ERROR_UNSUPPORTED_CERTIFICATE_TYPE = 204,
SSL_R_PEM_NAME_BAD_PREFIX = 391,
SSL_R_PEM_NAME_TOO_SHORT = 392,
SSL_R_PRE_MAC_LENGTH_TOO_LONG = 205,
SSL_R_PROBLEMS_MAPPING_CIPHER_FUNCTIONS = 206,
SSL_R_PROTOCOL_IS_SHUTDOWN = 207,
SSL_R_PSK_IDENTITY_NOT_FOUND = 223,
SSL_R_PSK_NO_CLIENT_CB = 224,
SSL_R_PSK_NO_SERVER_CB = 225,
SSL_R_PUBLIC_KEY_ENCRYPT_ERROR = 208,
SSL_R_PUBLIC_KEY_IS_NOT_RSA = 209,
SSL_R_PUBLIC_KEY_NOT_RSA = 210,
SSL_R_READ_BIO_NOT_SET = 211,
SSL_R_READ_TIMEOUT_EXPIRED = 312,
SSL_R_READ_WRONG_PACKET_TYPE = 212,
SSL_R_RECORD_LENGTH_MISMATCH = 213,
SSL_R_RECORD_TOO_LARGE = 214,
SSL_R_RECORD_TOO_SMALL = 298,
SSL_R_RENEGOTIATE_EXT_TOO_LONG = 335,
SSL_R_RENEGOTIATION_ENCODING_ERR = 336,
SSL_R_RENEGOTIATION_MISMATCH = 337,
SSL_R_REQUIRED_CIPHER_MISSING = 215,
SSL_R_REQUIRED_COMPRESSSION_ALGORITHM_MISSING = 342,
SSL_R_REUSE_CERT_LENGTH_NOT_ZERO = 216,
SSL_R_REUSE_CERT_TYPE_NOT_ZERO = 217,
SSL_R_REUSE_CIPHER_LIST_NOT_ZERO = 218,
SSL_R_SCSV_RECEIVED_WHEN_RENEGOTIATING = 345,
SSL_R_SERVERHELLO_TLSEXT = 275,
SSL_R_SESSION_ID_CONTEXT_UNINITIALIZED = 277,
SSL_R_SHORT_READ = 219,
SSL_R_SHUTDOWN_WHILE_IN_INIT = 407,
SSL_R_SIGNATURE_ALGORITHMS_ERROR = 360,
SSL_R_SIGNATURE_FOR_NON_SIGNING_CERTIFICATE = 220,
SSL_R_SRP_A_CALC = 361,
SSL_R_SRTP_COULD_NOT_ALLOCATE_PROFILES = 362,
SSL_R_SRTP_PROTECTION_PROFILE_LIST_TOO_LONG = 363,
SSL_R_SRTP_UNKNOWN_PROTECTION_PROFILE = 364,
SSL_R_SSL_CTX_HAS_NO_DEFAULT_SSL_VERSION = 228,
SSL_R_SSL_HANDSHAKE_FAILURE = 229,
SSL_R_SSL_LIBRARY_HAS_NO_CIPHERS = 230,
SSL_R_SSL_SESSION_ID_CALLBACK_FAILED = 301,
SSL_R_SSL_SESSION_ID_CONFLICT = 302,
SSL_R_SSL_SESSION_ID_CONTEXT_TOO_LONG = 273,
SSL_R_SSL_SESSION_ID_HAS_BAD_LENGTH = 303,
SSL_R_SSL_SESSION_ID_IS_DIFFERENT = 231,
SSL_R_SSL2_CONNECTION_ID_TOO_LONG = 299,
SSL_R_SSL23_DOING_SESSION_ID_REUSE = 221,
SSL_R_SSL3_EXT_INVALID_ECPOINTFORMAT = 321,
SSL_R_SSL3_EXT_INVALID_SERVERNAME = 319,
SSL_R_SSL3_EXT_INVALID_SERVERNAME_TYPE = 320,
SSL_R_SSL3_SESSION_ID_TOO_LONG = 300,
SSL_R_SSL3_SESSION_ID_TOO_SHORT = 222,
SSL_R_SSLV3_ALERT_BAD_CERTIFICATE = 1042,
SSL_R_SSLV3_ALERT_BAD_RECORD_MAC = 1020,
SSL_R_SSLV3_ALERT_CERTIFICATE_EXPIRED = 1045,
SSL_R_SSLV3_ALERT_CERTIFICATE_REVOKED = 1044,
SSL_R_SSLV3_ALERT_CERTIFICATE_UNKNOWN = 1046,
SSL_R_SSLV3_ALERT_DECOMPRESSION_FAILURE = 1030,
SSL_R_SSLV3_ALERT_HANDSHAKE_FAILURE = 1040,
SSL_R_SSLV3_ALERT_ILLEGAL_PARAMETER = 1047,
SSL_R_SSLV3_ALERT_NO_CERTIFICATE = 1041,
SSL_R_SSLV3_ALERT_UNEXPECTED_MESSAGE = 1010,
SSL_R_SSLV3_ALERT_UNSUPPORTED_CERTIFICATE = 1043,
SSL_R_TLS_CLIENT_CERT_REQ_WITH_ANON_CIPHER = 232,
SSL_R_TLS_HEARTBEAT_PEER_DOESNT_ACCEPT = 365,
SSL_R_TLS_HEARTBEAT_PENDING = 366,
SSL_R_TLS_ILLEGAL_EXPORTER_LABEL = 367,
SSL_R_TLS_INVALID_ECPOINTFORMAT_LIST = 157,
SSL_R_TLS_PEER_DID_NOT_RESPOND_WITH_CERTIFICATE_LIST = 233,
SSL_R_TLS_RSA_ENCRYPTED_VALUE_LENGTH_IS_WRONG = 234,
SSL_R_TLSV1_ALERT_ACCESS_DENIED = 1049,
SSL_R_TLSV1_ALERT_DECODE_ERROR = 1050,
SSL_R_TLSV1_ALERT_DECRYPT_ERROR = 1051,
SSL_R_TLSV1_ALERT_DECRYPTION_FAILED = 1021,
SSL_R_TLSV1_ALERT_EXPORT_RESTRICTION = 1060,
SSL_R_TLSV1_ALERT_INAPPROPRIATE_FALLBACK = 1086,
SSL_R_TLSV1_ALERT_INSUFFICIENT_SECURITY = 1071,
SSL_R_TLSV1_ALERT_INTERNAL_ERROR = 1080,
SSL_R_TLSV1_ALERT_NO_RENEGOTIATION = 1100,
SSL_R_TLSV1_ALERT_PROTOCOL_VERSION = 1070,
SSL_R_TLSV1_ALERT_RECORD_OVERFLOW = 1022,
SSL_R_TLSV1_ALERT_UNKNOWN_CA = 1048,
SSL_R_TLSV1_ALERT_USER_CANCELLED = 1090,
SSL_R_TLSV1_BAD_CERTIFICATE_HASH_VALUE = 1114,
SSL_R_TLSV1_BAD_CERTIFICATE_STATUS_RESPONSE = 1113,
SSL_R_TLSV1_CERTIFICATE_UNOBTAINABLE = 1111,
SSL_R_TLSV1_UNRECOGNIZED_NAME = 1112,
SSL_R_TLSV1_UNSUPPORTED_EXTENSION = 1110,
SSL_R_TOO_MANY_WARN_ALERTS = 409,
SSL_R_TRIED_TO_USE_UNSUPPORTED_CIPHER = 235,
SSL_R_UNABLE_TO_DECODE_DH_CERTS = 236,
SSL_R_UNABLE_TO_DECODE_ECDH_CERTS = 313,
SSL_R_UNABLE_TO_EXTRACT_PUBLIC_KEY = 237,
SSL_R_UNABLE_TO_FIND_DH_PARAMETERS = 238,
SSL_R_UNABLE_TO_FIND_ECDH_PARAMETERS = 314,
SSL_R_UNABLE_TO_FIND_PUBLIC_KEY_PARAMETERS = 239,
SSL_R_UNABLE_TO_FIND_SSL_METHOD = 240,
SSL_R_UNABLE_TO_LOAD_SSL2_MD5_ROUTINES = 241,
SSL_R_UNABLE_TO_LOAD_SSL3_MD5_ROUTINES = 242,
SSL_R_UNABLE_TO_LOAD_SSL3_SHA1_ROUTINES = 243,
SSL_R_UNEXPECTED_MESSAGE = 244,
SSL_R_UNEXPECTED_RECORD = 245,
SSL_R_UNINITIALIZED = 276,
SSL_R_UNKNOWN_ALERT_TYPE = 246,
SSL_R_UNKNOWN_CERTIFICATE_TYPE = 247,
SSL_R_UNKNOWN_CIPHER_RETURNED = 248,
SSL_R_UNKNOWN_CIPHER_TYPE = 249,
SSL_R_UNKNOWN_CMD_NAME = 386,
SSL_R_UNKNOWN_DIGEST = 368,
SSL_R_UNKNOWN_KEY_EXCHANGE_TYPE = 250,
SSL_R_UNKNOWN_PKEY_TYPE = 251,
SSL_R_UNKNOWN_PROTOCOL = 252,
SSL_R_UNKNOWN_REMOTE_ERROR_TYPE = 253,
SSL_R_UNKNOWN_SSL_VERSION = 254,
SSL_R_UNKNOWN_STATE = 255,
SSL_R_UNSAFE_LEGACY_RENEGOTIATION_DISABLED = 338,
SSL_R_UNSUPPORTED_CIPHER = 256,
SSL_R_UNSUPPORTED_COMPRESSION_ALGORITHM = 257,
SSL_R_UNSUPPORTED_DIGEST_TYPE = 326,
SSL_R_UNSUPPORTED_ELLIPTIC_CURVE = 315,
SSL_R_UNSUPPORTED_PROTOCOL = 258,
SSL_R_UNSUPPORTED_SSL_VERSION = 259,
SSL_R_UNSUPPORTED_STATUS_TYPE = 329,
SSL_R_USE_SRTP_NOT_NEGOTIATED = 369,
SSL_R_WRITE_BIO_NOT_SET = 260,
SSL_R_WRONG_CERTIFICATE_TYPE = 383,
SSL_R_WRONG_CIPHER_RETURNED = 261,
SSL_R_WRONG_CURVE = 378,
SSL_R_WRONG_MESSAGE_TYPE = 262,
SSL_R_WRONG_NUMBER_OF_KEY_BITS = 263,
SSL_R_WRONG_SIGNATURE_LENGTH = 264,
SSL_R_WRONG_SIGNATURE_SIZE = 265,
SSL_R_WRONG_SIGNATURE_TYPE = 370,
SSL_R_WRONG_SSL_VERSION = 266,
SSL_R_WRONG_VERSION_NUMBER = 267,
SSL_R_X509_LIB = 268,
SSL_R_X509_VERIFICATION_SETUP_PROBLEMS = 269,
SSL_READING = 3,
SSL_RECEIVED_SHUTDOWN = 2,
SSL_RT_MAX_CIPHER_BLOCK_SIZE = 16,
SSL_SENT_SHUTDOWN = 1,
SSL_SESS_CACHE_CLIENT = 0x0001,
SSL_SESS_CACHE_NO_AUTO_CLEAR = 0x0080,
SSL_SESS_CACHE_NO_INTERNAL_LOOKUP = 0x0100,
SSL_SESS_CACHE_NO_INTERNAL_STORE = 0x0200,
SSL_SESS_CACHE_OFF = 0x0000,
SSL_SESS_CACHE_SERVER = 0x0002,
SSL_SESSION_ASN1_VERSION = 0x0001,
SSL_ST_ACCEPT = 0x2000,
SSL_ST_BEFORE = 0x4000,
SSL_ST_CONNECT = 0x1000,
SSL_ST_MASK = 0x0FFF,
SSL_ST_OK = 0x03,
SSL_ST_READ_BODY = 0xF1,
SSL_ST_READ_DONE = 0xF2,
SSL_ST_READ_HEADER = 0xF0,
SSL_TLSEXT_ERR_ALERT_FATAL = 2,
SSL_TLSEXT_ERR_ALERT_WARNING = 1,
SSL_TLSEXT_ERR_NOACK = 3,
SSL_TLSEXT_ERR_OK = 0,
SSL_TLSEXT_HB_DONT_RECV_REQUESTS = 0x04,
SSL_TLSEXT_HB_DONT_SEND_REQUESTS = 0x02,
SSL_TLSEXT_HB_ENABLED = 0x01,
SSL_VERIFY_CLIENT_ONCE = 0x04,
SSL_VERIFY_FAIL_IF_NO_PEER_CERT = 0x02,
SSL_VERIFY_NONE = 0x00,
SSL_VERIFY_PEER = 0x01,
SSL_WRITING = 2,
SSL_X509_LOOKUP = 4,
SSL2_AT_MD5_WITH_RSA_ENCRYPTION = 0x01,
SSL2_CF_5_BYTE_ENC = 0x01,
SSL2_CF_8_BYTE_ENC = 0x02,
SSL2_CHALLENGE_LENGTH = 16,
SSL2_CK_DES_192_EDE3_CBC_WITH_MD5 = 0x020700c0,
SSL2_CK_DES_64_CBC_WITH_MD5 = 0x02060040,
SSL2_CK_IDEA_128_CBC_WITH_MD5 = 0x02050080,
SSL2_CK_RC2_128_CBC_EXPORT40_WITH_MD5 = 0x02040080,
SSL2_CK_RC2_128_CBC_WITH_MD5 = 0x02030080,
SSL2_CK_RC4_128_EXPORT40_WITH_MD5 = 0x02020080,
SSL2_CK_RC4_128_WITH_MD5 = 0x02010080,
SSL2_CONNECTION_ID_LENGTH = 16,
SSL2_CT_X509_CERTIFICATE = 0x01,
SSL2_MAX_CERT_CHALLENGE_LENGTH = 32,
SSL2_MAX_CHALLENGE_LENGTH = 32,
SSL2_MAX_CONNECTION_ID_LENGTH = 16,
SSL2_MAX_KEY_MATERIAL_LENGTH = 24,
SSL2_MAX_MASTER_KEY_LENGTH_IN_BITS = 256,
SSL2_MAX_SSL_SESSION_ID_LENGTH = 32,
SSL2_MIN_CERT_CHALLENGE_LENGTH = 16,
SSL2_MIN_CHALLENGE_LENGTH = 16,
SSL2_MT_CLIENT_CERTIFICATE = 8,
SSL2_MT_CLIENT_FINISHED = 3,
SSL2_MT_CLIENT_HELLO = 1,
SSL2_MT_CLIENT_MASTER_KEY = 2,
SSL2_MT_ERROR = 0,
SSL2_MT_REQUEST_CERTIFICATE = 7,
SSL2_MT_SERVER_FINISHED = 6,
SSL2_MT_SERVER_HELLO = 4,
SSL2_MT_SERVER_VERIFY = 5,
SSL2_PE_BAD_CERTIFICATE = 0x0004,
SSL2_PE_NO_CERTIFICATE = 0x0002,
SSL2_PE_NO_CIPHER = 0x0001,
SSL2_PE_UNDEFINED_ERROR = 0x0000,
SSL2_PE_UNSUPPORTED_CERTIFICATE_TYPE = 0x0006,
SSL2_SSL_SESSION_ID_LENGTH = 16,
SSL2_VERSION = 0x0002,
SSL2_VERSION_MAJOR = 0x00,
SSL2_VERSION_MINOR = 0x02,
SSL3_AD_BAD_CERTIFICATE = 42,
SSL3_AD_CERTIFICATE_EXPIRED = 45,
SSL3_AD_CERTIFICATE_REVOKED = 44,
SSL3_AD_CERTIFICATE_UNKNOWN = 46,
SSL3_AD_CLOSE_NOTIFY = 0,
SSL3_AD_NO_CERTIFICATE = 41,
SSL3_AD_UNSUPPORTED_CERTIFICATE = 43,
SSL3_AL_FATAL = 2,
SSL3_AL_WARNING = 1,
SSL3_ALIGN_PAYLOAD = 8,
SSL3_CC_CLIENT = 0x10,
SSL3_CC_READ = 0x01,
SSL3_CC_SERVER = 0x20,
SSL3_CC_WRITE = 0x02,
SSL3_CK_ADH_DES_192_CBC_SHA = 0x0300001B,
SSL3_CK_ADH_DES_40_CBC_SHA = 0x03000019,
SSL3_CK_ADH_DES_64_CBC_SHA = 0x0300001A,
SSL3_CK_ADH_RC4_128_MD5 = 0x03000018,
SSL3_CK_ADH_RC4_40_MD5 = 0x03000017,
SSL3_CK_DH_DSS_DES_192_CBC3_SHA = 0x0300000D,
SSL3_CK_DH_DSS_DES_40_CBC_SHA = 0x0300000B,
SSL3_CK_DH_DSS_DES_64_CBC_SHA = 0x0300000C,
SSL3_CK_DH_RSA_DES_192_CBC3_SHA = 0x03000010,
SSL3_CK_DH_RSA_DES_40_CBC_SHA = 0x0300000E,
SSL3_CK_DH_RSA_DES_64_CBC_SHA = 0x0300000F,
SSL3_CK_EDH_DSS_DES_192_CBC3_SHA = 0x03000013,
SSL3_CK_EDH_DSS_DES_40_CBC_SHA = 0x03000011,
SSL3_CK_EDH_DSS_DES_64_CBC_SHA = 0x03000012,
SSL3_CK_EDH_RSA_DES_192_CBC3_SHA = 0x03000016,
SSL3_CK_EDH_RSA_DES_40_CBC_SHA = 0x03000014,
SSL3_CK_EDH_RSA_DES_64_CBC_SHA = 0x03000015,
SSL3_CK_FALLBACK_SCSV = 0x03005600,
SSL3_CK_FZA_DMS_FZA_SHA = 0x0300001D,
SSL3_CK_FZA_DMS_NULL_SHA = 0x0300001C,
SSL3_CK_FZA_DMS_RC4_SHA = 0x0300001E,
SSL3_CK_KRB5_DES_192_CBC3_MD5 = 0x03000023,
SSL3_CK_KRB5_DES_192_CBC3_SHA = 0x0300001F,
SSL3_CK_KRB5_DES_40_CBC_MD5 = 0x03000029,
SSL3_CK_KRB5_DES_40_CBC_SHA = 0x03000026,
SSL3_CK_KRB5_DES_64_CBC_MD5 = 0x03000022,
SSL3_CK_KRB5_DES_64_CBC_SHA = 0x0300001E,
SSL3_CK_KRB5_IDEA_128_CBC_MD5 = 0x03000025,
SSL3_CK_KRB5_IDEA_128_CBC_SHA = 0x03000021,
SSL3_CK_KRB5_RC2_40_CBC_MD5 = 0x0300002A,
SSL3_CK_KRB5_RC2_40_CBC_SHA = 0x03000027,
SSL3_CK_KRB5_RC4_128_MD5 = 0x03000024,
SSL3_CK_KRB5_RC4_128_SHA = 0x03000020,
SSL3_CK_KRB5_RC4_40_MD5 = 0x0300002B,
SSL3_CK_KRB5_RC4_40_SHA = 0x03000028,
SSL3_CK_RSA_DES_192_CBC3_SHA = 0x0300000A,
SSL3_CK_RSA_DES_40_CBC_SHA = 0x03000008,
SSL3_CK_RSA_DES_64_CBC_SHA = 0x03000009,
SSL3_CK_RSA_IDEA_128_SHA = 0x03000007,
SSL3_CK_RSA_NULL_MD5 = 0x03000001,
SSL3_CK_RSA_NULL_SHA = 0x03000002,
SSL3_CK_RSA_RC2_40_MD5 = 0x03000006,
SSL3_CK_RSA_RC4_128_MD5 = 0x03000004,
SSL3_CK_RSA_RC4_128_SHA = 0x03000005,
SSL3_CK_RSA_RC4_40_MD5 = 0x03000003,
SSL3_CK_SCSV = 0x030000FF,
SSL3_CT_DSS_EPHEMERAL_DH = 6,
SSL3_CT_DSS_FIXED_DH = 4,
SSL3_CT_DSS_SIGN = 2,
SSL3_CT_FORTEZZA_DMS = 20,
SSL3_CT_NUMBER = 9,
SSL3_CT_RSA_EPHEMERAL_DH = 5,
SSL3_CT_RSA_FIXED_DH = 3,
SSL3_CT_RSA_SIGN = 1,
SSL3_FLAGS_CCS_OK = 0x0080,
SSL3_FLAGS_DELAY_CLIENT_FINISHED = 0x0002,
SSL3_FLAGS_NO_RENEGOTIATE_CIPHERS = 0x0001,
SSL3_FLAGS_POP_BUFFER = 0x0004,
SSL3_FLAGS_SGC_RESTART_DONE = 0x0040,
SSL3_HM_HEADER_LENGTH = 4,
SSL3_MASTER_SECRET_SIZE = 48,
SSL3_MAX_SSL_SESSION_ID_LENGTH = 32,
SSL3_MT_CCS = 1,
SSL3_MT_CERTIFICATE = 11,
SSL3_MT_CERTIFICATE_REQUEST = 13,
SSL3_MT_CERTIFICATE_STATUS = 22,
SSL3_MT_CERTIFICATE_VERIFY = 15,
SSL3_MT_CLIENT_HELLO = 1,
SSL3_MT_CLIENT_KEY_EXCHANGE = 16,
SSL3_MT_FINISHED = 20,
SSL3_MT_HELLO_REQUEST = 0,
SSL3_MT_NEWSESSION_TICKET = 4,
SSL3_MT_NEXT_PROTO = 67,
SSL3_MT_SERVER_DONE = 14,
SSL3_MT_SERVER_HELLO = 2,
SSL3_MT_SERVER_KEY_EXCHANGE = 12,
SSL3_RANDOM_SIZE = 32,
SSL3_RT_ALERT = 21,
SSL3_RT_APPLICATION_DATA = 23,
SSL3_RT_CHANGE_CIPHER_SPEC = 20,
SSL3_RT_HANDSHAKE = 22,
SSL3_RT_HEADER = 0x100,
SSL3_RT_HEADER_LENGTH = 5,
SSL3_RT_MAX_COMPRESSED_OVERHEAD = 1024,
SSL3_RT_MAX_MD_SIZE = 64,
SSL3_RT_MAX_PLAIN_LENGTH = 16384,
SSL3_SESSION_ID_SIZE = 32,
SSL3_SSL_SESSION_ID_LENGTH = 32,
SSL3_VERSION = 0x0300,
SSL3_VERSION_MAJOR = 0x03,
SSL3_VERSION_MINOR = 0x00,
SSLEAY_BUILT_ON = 3,
SSLEAY_CFLAGS = 2,
SSLEAY_DIR = 5,
SSLEAY_PLATFORM = 4,
SSLEAY_VERSION = 0,
STABLE_FLAGS_MALLOC = 0x01,
STABLE_NO_MASK = 0x02,
SYS_F_ACCEPT = 8,
SYS_F_BIND = 6,
SYS_F_CONNECT = 2,
SYS_F_FFLUSH = 18,
SYS_F_FOPEN = 1,
SYS_F_FREAD = 11,
SYS_F_GETSERVBYNAME = 3,
SYS_F_IOCTLSOCKET = 5,
SYS_F_LISTEN = 7,
SYS_F_OPENDIR = 10,
SYS_F_SOCKET = 4,
TLS_CT_DSS_FIXED_DH = 4,
TLS_CT_DSS_SIGN = 2,
TLS_CT_ECDSA_FIXED_ECDH = 66,
TLS_CT_ECDSA_SIGN = 64,
TLS_CT_GOST01_SIGN = 22,
TLS_CT_GOST94_SIGN = 21,
TLS_CT_NUMBER = 9,
TLS_CT_RSA_FIXED_DH = 3,
TLS_CT_RSA_FIXED_ECDH = 65,
TLS_CT_RSA_SIGN = 1,
TLS_MD_MAX_CONST_SIZE = 20,
TLS1_1_VERSION = 0x0302,
TLS1_1_VERSION_MAJOR = 0x03,
TLS1_1_VERSION_MINOR = 0x02,
TLS1_2_VERSION = 0x0303,
TLS1_2_VERSION_MAJOR = 0x03,
TLS1_2_VERSION_MINOR = 0x03,
TLS1_AD_BAD_CERTIFICATE_HASH_VALUE = 114,
TLS1_AD_BAD_CERTIFICATE_STATUS_RESPONSE = 113,
TLS1_AD_CERTIFICATE_UNOBTAINABLE = 111,
TLS1_AD_DECRYPT_ERROR = 51,
TLS1_AD_DECRYPTION_FAILED = 21,
TLS1_AD_NO_RENEGOTIATION = 100,
TLS1_AD_RECORD_OVERFLOW = 22,
TLS1_AD_UNRECOGNIZED_NAME = 112,
TLS1_AD_UNSUPPORTED_EXTENSION = 110,
TLS1_AD_USER_CANCELLED = 90,
TLS1_ALLOW_EXPERIMENTAL_CIPHERSUITES = 0,
TLS1_CK_ADH_WITH_AES_128_GCM_SHA256 = 0x030000A6,
TLS1_CK_ADH_WITH_AES_128_SHA = 0x03000034,
TLS1_CK_ADH_WITH_AES_128_SHA256 = 0x0300006C,
TLS1_CK_ADH_WITH_AES_256_GCM_SHA384 = 0x030000A7,
TLS1_CK_ADH_WITH_AES_256_SHA = 0x0300003A,
TLS1_CK_ADH_WITH_AES_256_SHA256 = 0x0300006D,
TLS1_CK_ADH_WITH_CAMELLIA_128_CBC_SHA = 0x03000046,
TLS1_CK_ADH_WITH_CAMELLIA_256_CBC_SHA = 0x03000089,
TLS1_CK_ADH_WITH_SEED_SHA = 0x0300009B,
TLS1_CK_DH_DSS_WITH_AES_128_GCM_SHA256 = 0x030000A4,
TLS1_CK_DH_DSS_WITH_AES_128_SHA = 0x03000030,
TLS1_CK_DH_DSS_WITH_AES_128_SHA256 = 0x0300003E,
TLS1_CK_DH_DSS_WITH_AES_256_GCM_SHA384 = 0x030000A5,
TLS1_CK_DH_DSS_WITH_AES_256_SHA = 0x03000036,
TLS1_CK_DH_DSS_WITH_AES_256_SHA256 = 0x03000068,
TLS1_CK_DH_DSS_WITH_CAMELLIA_128_CBC_SHA = 0x03000042,
TLS1_CK_DH_DSS_WITH_CAMELLIA_256_CBC_SHA = 0x03000085,
TLS1_CK_DH_DSS_WITH_SEED_SHA = 0x03000097,
TLS1_CK_DH_RSA_WITH_AES_128_GCM_SHA256 = 0x030000A0,
TLS1_CK_DH_RSA_WITH_AES_128_SHA = 0x03000031,
TLS1_CK_DH_RSA_WITH_AES_128_SHA256 = 0x0300003F,
TLS1_CK_DH_RSA_WITH_AES_256_GCM_SHA384 = 0x030000A1,
TLS1_CK_DH_RSA_WITH_AES_256_SHA = 0x03000037,
TLS1_CK_DH_RSA_WITH_AES_256_SHA256 = 0x03000069,
TLS1_CK_DH_RSA_WITH_CAMELLIA_128_CBC_SHA = 0x03000043,
TLS1_CK_DH_RSA_WITH_CAMELLIA_256_CBC_SHA = 0x03000086,
TLS1_CK_DH_RSA_WITH_SEED_SHA = 0x03000098,
TLS1_CK_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA = 0x03000063,
TLS1_CK_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA = 0x03000065,
TLS1_CK_DHE_DSS_WITH_AES_128_GCM_SHA256 = 0x030000A2,
TLS1_CK_DHE_DSS_WITH_AES_128_SHA = 0x03000032,
TLS1_CK_DHE_DSS_WITH_AES_128_SHA256 = 0x03000040,
TLS1_CK_DHE_DSS_WITH_AES_256_GCM_SHA384 = 0x030000A3,
TLS1_CK_DHE_DSS_WITH_AES_256_SHA = 0x03000038,
TLS1_CK_DHE_DSS_WITH_AES_256_SHA256 = 0x0300006A,
TLS1_CK_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA = 0x03000044,
TLS1_CK_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA = 0x03000087,
TLS1_CK_DHE_DSS_WITH_RC4_128_SHA = 0x03000066,
TLS1_CK_DHE_DSS_WITH_SEED_SHA = 0x03000099,
TLS1_CK_DHE_RSA_WITH_AES_128_GCM_SHA256 = 0x0300009E,
TLS1_CK_DHE_RSA_WITH_AES_128_SHA = 0x03000033,
TLS1_CK_DHE_RSA_WITH_AES_128_SHA256 = 0x03000067,
TLS1_CK_DHE_RSA_WITH_AES_256_GCM_SHA384 = 0x0300009F,
TLS1_CK_DHE_RSA_WITH_AES_256_SHA = 0x03000039,
TLS1_CK_DHE_RSA_WITH_AES_256_SHA256 = 0x0300006B,
TLS1_CK_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA = 0x03000045,
TLS1_CK_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA = 0x03000088,
TLS1_CK_DHE_RSA_WITH_SEED_SHA = 0x0300009A,
TLS1_CK_ECDH_anon_WITH_AES_128_CBC_SHA = 0x0300C018,
TLS1_CK_ECDH_anon_WITH_AES_256_CBC_SHA = 0x0300C019,
TLS1_CK_ECDH_anon_WITH_DES_192_CBC3_SHA = 0x0300C017,
TLS1_CK_ECDH_anon_WITH_NULL_SHA = 0x0300C015,
TLS1_CK_ECDH_anon_WITH_RC4_128_SHA = 0x0300C016,
TLS1_CK_ECDH_ECDSA_WITH_AES_128_CBC_SHA = 0x0300C004,
TLS1_CK_ECDH_ECDSA_WITH_AES_128_GCM_SHA256 = 0x0300C02D,
TLS1_CK_ECDH_ECDSA_WITH_AES_128_SHA256 = 0x0300C025,
TLS1_CK_ECDH_ECDSA_WITH_AES_256_CBC_SHA = 0x0300C005,
TLS1_CK_ECDH_ECDSA_WITH_AES_256_GCM_SHA384 = 0x0300C02E,
TLS1_CK_ECDH_ECDSA_WITH_AES_256_SHA384 = 0x0300C026,
TLS1_CK_ECDH_ECDSA_WITH_DES_192_CBC3_SHA = 0x0300C003,
TLS1_CK_ECDH_ECDSA_WITH_NULL_SHA = 0x0300C001,
TLS1_CK_ECDH_ECDSA_WITH_RC4_128_SHA = 0x0300C002,
TLS1_CK_ECDH_RSA_WITH_AES_128_CBC_SHA = 0x0300C00E,
TLS1_CK_ECDH_RSA_WITH_AES_128_GCM_SHA256 = 0x0300C031,
TLS1_CK_ECDH_RSA_WITH_AES_128_SHA256 = 0x0300C029,
TLS1_CK_ECDH_RSA_WITH_AES_256_CBC_SHA = 0x0300C00F,
TLS1_CK_ECDH_RSA_WITH_AES_256_GCM_SHA384 = 0x0300C032,
TLS1_CK_ECDH_RSA_WITH_AES_256_SHA384 = 0x0300C02A,
TLS1_CK_ECDH_RSA_WITH_DES_192_CBC3_SHA = 0x0300C00D,
TLS1_CK_ECDH_RSA_WITH_NULL_SHA = 0x0300C00B,
TLS1_CK_ECDH_RSA_WITH_RC4_128_SHA = 0x0300C00C,
TLS1_CK_ECDHE_ECDSA_WITH_AES_128_CBC_SHA = 0x0300C009,
TLS1_CK_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = 0x0300C02B,
TLS1_CK_ECDHE_ECDSA_WITH_AES_128_SHA256 = 0x0300C023,
TLS1_CK_ECDHE_ECDSA_WITH_AES_256_CBC_SHA = 0x0300C00A,
TLS1_CK_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 = 0x0300C02C,
TLS1_CK_ECDHE_ECDSA_WITH_AES_256_SHA384 = 0x0300C024,
TLS1_CK_ECDHE_ECDSA_WITH_DES_192_CBC3_SHA = 0x0300C008,
TLS1_CK_ECDHE_ECDSA_WITH_NULL_SHA = 0x0300C006,
TLS1_CK_ECDHE_ECDSA_WITH_RC4_128_SHA = 0x0300C007,
TLS1_CK_ECDHE_RSA_WITH_AES_128_CBC_SHA = 0x0300C013,
TLS1_CK_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = 0x0300C02F,
TLS1_CK_ECDHE_RSA_WITH_AES_128_SHA256 = 0x0300C027,
TLS1_CK_ECDHE_RSA_WITH_AES_256_CBC_SHA = 0x0300C014,
TLS1_CK_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = 0x0300C030,
TLS1_CK_ECDHE_RSA_WITH_AES_256_SHA384 = 0x0300C028,
TLS1_CK_ECDHE_RSA_WITH_DES_192_CBC3_SHA = 0x0300C012,
TLS1_CK_ECDHE_RSA_WITH_NULL_SHA = 0x0300C010,
TLS1_CK_ECDHE_RSA_WITH_RC4_128_SHA = 0x0300C011,
TLS1_CK_PSK_WITH_3DES_EDE_CBC_SHA = 0x0300008B,
TLS1_CK_PSK_WITH_AES_128_CBC_SHA = 0x0300008C,
TLS1_CK_PSK_WITH_AES_256_CBC_SHA = 0x0300008D,
TLS1_CK_PSK_WITH_RC4_128_SHA = 0x0300008A,
TLS1_CK_RSA_EXPORT1024_WITH_DES_CBC_SHA = 0x03000062,
TLS1_CK_RSA_EXPORT1024_WITH_RC4_56_SHA = 0x03000064,
TLS1_CK_RSA_WITH_AES_128_GCM_SHA256 = 0x0300009C,
TLS1_CK_RSA_WITH_AES_128_SHA = 0x0300002F,
TLS1_CK_RSA_WITH_AES_128_SHA256 = 0x0300003C,
TLS1_CK_RSA_WITH_AES_256_GCM_SHA384 = 0x0300009D,
TLS1_CK_RSA_WITH_AES_256_SHA = 0x03000035,
TLS1_CK_RSA_WITH_AES_256_SHA256 = 0x0300003D,
TLS1_CK_RSA_WITH_CAMELLIA_128_CBC_SHA = 0x03000041,
TLS1_CK_RSA_WITH_CAMELLIA_256_CBC_SHA = 0x03000084,
TLS1_CK_RSA_WITH_NULL_SHA256 = 0x0300003B,
TLS1_CK_RSA_WITH_SEED_SHA = 0x03000096,
TLS1_CK_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA = 0x0300C01C,
TLS1_CK_SRP_SHA_DSS_WITH_AES_128_CBC_SHA = 0x0300C01F,
TLS1_CK_SRP_SHA_DSS_WITH_AES_256_CBC_SHA = 0x0300C022,
TLS1_CK_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA = 0x0300C01B,
TLS1_CK_SRP_SHA_RSA_WITH_AES_128_CBC_SHA = 0x0300C01E,
TLS1_CK_SRP_SHA_RSA_WITH_AES_256_CBC_SHA = 0x0300C021,
TLS1_CK_SRP_SHA_WITH_3DES_EDE_CBC_SHA = 0x0300C01A,
TLS1_CK_SRP_SHA_WITH_AES_128_CBC_SHA = 0x0300C01D,
TLS1_CK_SRP_SHA_WITH_AES_256_CBC_SHA = 0x0300C020,
TLS1_FINISH_MAC_LENGTH = 12,
TLS1_FLAGS_KEEP_HANDSHAKE = 0x0020,
TLS1_FLAGS_SKIP_CERT_VERIFY = 0x0010,
TLS1_FLAGS_TLS_PADDING_BUG = 0x0008,
TLS1_HB_REQUEST = 1,
TLS1_HB_RESPONSE = 2,
TLS1_RT_CRYPTO = 0x1000,
TLS1_RT_CRYPTO_READ = 0x0000,
TLS1_RT_CRYPTO_WRITE = 0x0100,
TLS1_RT_HEARTBEAT = 24,
TLS1_VERSION = 0x0301,
TLS1_VERSION_MAJOR = 0x03,
TLS1_VERSION_MINOR = 0x01,
TLSEXT_curve_P_256 = 23,
TLSEXT_curve_P_384 = 24,
TLSEXT_ECPOINTFORMAT_ansiX962_compressed_char2 = 2,
TLSEXT_ECPOINTFORMAT_ansiX962_compressed_prime = 1,
TLSEXT_ECPOINTFORMAT_first = 0,
TLSEXT_ECPOINTFORMAT_last = 2,
TLSEXT_ECPOINTFORMAT_uncompressed = 0,
TLSEXT_hash_md5 = 1,
TLSEXT_hash_none = 0,
TLSEXT_hash_num = 7,
TLSEXT_hash_sha1 = 2,
TLSEXT_hash_sha224 = 3,
TLSEXT_hash_sha256 = 4,
TLSEXT_hash_sha384 = 5,
TLSEXT_hash_sha512 = 6,
TLSEXT_MAXLEN_host_name = 255,
TLSEXT_NAMETYPE_host_name = 0,
TLSEXT_nid_unknown = 0x1000000,
TLSEXT_signature_anonymous = 0,
TLSEXT_signature_dsa = 2,
TLSEXT_signature_ecdsa = 3,
TLSEXT_signature_num = 4,
TLSEXT_signature_rsa = 1,
TLSEXT_STATUSTYPE_ocsp = 1,
TLSEXT_TYPE_application_layer_protocol_negotiation = 16,
TLSEXT_TYPE_cert_type = 9,
TLSEXT_TYPE_client_authz = 7,
TLSEXT_TYPE_client_certificate_url = 2,
TLSEXT_TYPE_ec_point_formats = 11,
TLSEXT_TYPE_elliptic_curves = 10,
TLSEXT_TYPE_heartbeat = 15,
TLSEXT_TYPE_max_fragment_length = 1,
TLSEXT_TYPE_next_proto_neg = 13172,
TLSEXT_TYPE_padding = 21,
TLSEXT_TYPE_renegotiate = 0xff01,
TLSEXT_TYPE_server_authz = 8,
TLSEXT_TYPE_server_name = 0,
TLSEXT_TYPE_session_ticket = 35,
TLSEXT_TYPE_signature_algorithms = 13,
TLSEXT_TYPE_srp = 12,
TLSEXT_TYPE_status_request = 5,
TLSEXT_TYPE_truncated_hmac = 4,
TLSEXT_TYPE_trusted_ca_keys = 3,
TLSEXT_TYPE_use_srtp = 14,
TLSEXT_TYPE_user_mapping = 6,
TS_ESS_CERT_ID_CHAIN = 0x04,
TS_F_D2I_TS_RESP = 147,
TS_F_DEF_SERIAL_CB = 110,
TS_F_DEF_TIME_CB = 111,
TS_F_ESS_ADD_SIGNING_CERT = 112,
TS_F_ESS_CERT_ID_NEW_INIT = 113,
TS_F_ESS_SIGNING_CERT_NEW_INIT = 114,
TS_F_INT_TS_RESP_VERIFY_TOKEN = 149,
TS_F_PKCS7_TO_TS_TST_INFO = 148,
TS_F_TS_ACCURACY_SET_MICROS = 115,
TS_F_TS_ACCURACY_SET_MILLIS = 116,
TS_F_TS_ACCURACY_SET_SECONDS = 117,
TS_F_TS_CHECK_IMPRINTS = 100,
TS_F_TS_CHECK_NONCES = 101,
TS_F_TS_CHECK_POLICY = 102,
TS_F_TS_CHECK_SIGNING_CERTS = 103,
TS_F_TS_CHECK_STATUS_INFO = 104,
TS_F_TS_COMPUTE_IMPRINT = 145,
TS_F_TS_CONF_SET_DEFAULT_ENGINE = 146,
TS_F_TS_GET_STATUS_TEXT = 105,
TS_F_TS_MSG_IMPRINT_SET_ALGO = 118,
TS_F_TS_REQ_SET_MSG_IMPRINT = 119,
TS_F_TS_REQ_SET_NONCE = 120,
TS_F_TS_REQ_SET_POLICY_ID = 121,
TS_F_TS_RESP_CREATE_RESPONSE = 122,
TS_F_TS_RESP_CREATE_TST_INFO = 123,
TS_F_TS_RESP_CTX_ADD_FAILURE_INFO = 124,
TS_F_TS_RESP_CTX_ADD_MD = 125,
TS_F_TS_RESP_CTX_ADD_POLICY = 126,
TS_F_TS_RESP_CTX_NEW = 127,
TS_F_TS_RESP_CTX_SET_ACCURACY = 128,
TS_F_TS_RESP_CTX_SET_CERTS = 129,
TS_F_TS_RESP_CTX_SET_DEF_POLICY = 130,
TS_F_TS_RESP_CTX_SET_SIGNER_CERT = 131,
TS_F_TS_RESP_CTX_SET_STATUS_INFO = 132,
TS_F_TS_RESP_GET_POLICY = 133,
TS_F_TS_RESP_SET_GENTIME_WITH_PRECISION = 134,
TS_F_TS_RESP_SET_STATUS_INFO = 135,
TS_F_TS_RESP_SET_TST_INFO = 150,
TS_F_TS_RESP_SIGN = 136,
TS_F_TS_RESP_VERIFY_SIGNATURE = 106,
TS_F_TS_RESP_VERIFY_TOKEN = 107,
TS_F_TS_TST_INFO_SET_ACCURACY = 137,
TS_F_TS_TST_INFO_SET_MSG_IMPRINT = 138,
TS_F_TS_TST_INFO_SET_NONCE = 139,
TS_F_TS_TST_INFO_SET_POLICY_ID = 140,
TS_F_TS_TST_INFO_SET_SERIAL = 141,
TS_F_TS_TST_INFO_SET_TIME = 142,
TS_F_TS_TST_INFO_SET_TSA = 143,
TS_F_TS_VERIFY = 108,
TS_F_TS_VERIFY_CERT = 109,
TS_F_TS_VERIFY_CTX_NEW = 144,
TS_INFO_ADD_INFO_NOT_AVAILABLE = 17,
TS_INFO_BAD_ALG = 0,
TS_INFO_BAD_DATA_FORMAT = 5,
TS_INFO_BAD_REQUEST = 2,
TS_INFO_SYSTEM_FAILURE = 25,
TS_INFO_TIME_NOT_AVAILABLE = 14,
TS_INFO_UNACCEPTED_EXTENSION = 16,
TS_INFO_UNACCEPTED_POLICY = 15,
TS_MAX_CLOCK_PRECISION_DIGITS = 6,
TS_ORDERING = 0x02,
TS_R_BAD_PKCS7_TYPE = 132,
TS_R_BAD_TYPE = 133,
TS_R_CERTIFICATE_VERIFY_ERROR = 100,
TS_R_COULD_NOT_SET_ENGINE = 127,
TS_R_COULD_NOT_SET_TIME = 115,
TS_R_D2I_TS_RESP_INT_FAILED = 128,
TS_R_DETACHED_CONTENT = 134,
TS_R_ESS_ADD_SIGNING_CERT_ERROR = 116,
TS_R_ESS_SIGNING_CERTIFICATE_ERROR = 101,
TS_R_INVALID_NULL_POINTER = 102,
TS_R_INVALID_SIGNER_CERTIFICATE_PURPOSE = 117,
TS_R_MESSAGE_IMPRINT_MISMATCH = 103,
TS_R_NO_CONTENT = 106,
TS_R_NO_TIME_STAMP_TOKEN = 107,
TS_R_NONCE_MISMATCH = 104,
TS_R_NONCE_NOT_RETURNED = 105,
TS_R_PKCS7_ADD_SIGNATURE_ERROR = 118,
TS_R_PKCS7_ADD_SIGNED_ATTR_ERROR = 119,
TS_R_PKCS7_TO_TS_TST_INFO_FAILED = 129,
TS_R_POLICY_MISMATCH = 108,
TS_R_PRIVATE_KEY_DOES_NOT_MATCH_CERTIFICATE = 120,
TS_R_RESPONSE_SETUP_ERROR = 121,
TS_R_SIGNATURE_FAILURE = 109,
TS_R_THERE_MUST_BE_ONE_SIGNER = 110,
TS_R_TIME_SYSCALL_ERROR = 122,
TS_R_TOKEN_NOT_PRESENT = 130,
TS_R_TOKEN_PRESENT = 131,
TS_R_TS_DATASIGN = 124,
TS_R_TSA_NAME_MISMATCH = 111,
TS_R_TSA_UNTRUSTED = 112,
TS_R_TST_INFO_SETUP_ERROR = 123,
TS_R_UNACCEPTABLE_POLICY = 125,
TS_R_UNSUPPORTED_MD_ALGORITHM = 126,
TS_R_UNSUPPORTED_VERSION = 113,
TS_R_WRONG_CONTENT_TYPE = 114,
TS_STATUS_GRANTED = 0,
TS_STATUS_GRANTED_WITH_MODS = 1,
TS_STATUS_REJECTION = 2,
TS_STATUS_REVOCATION_NOTIFICATION = 5,
TS_STATUS_REVOCATION_WARNING = 4,
TS_STATUS_WAITING = 3,
TS_TSA_NAME = 0x01,
ub_common_name = 64,
ub_email_address = 128,
ub_locality_name = 128,
ub_name = 32768,
ub_organization_name = 64,
ub_organization_unit_name = 64,
ub_state_name = 128,
ub_title = 64,
UI_CTRL_IS_REDOABLE = 2,
UI_CTRL_PRINT_ERRORS = 1,
UI_F_GENERAL_ALLOCATE_BOOLEAN = 108,
UI_F_GENERAL_ALLOCATE_PROMPT = 109,
UI_F_GENERAL_ALLOCATE_STRING = 100,
UI_F_UI_CTRL = 111,
UI_F_UI_DUP_ERROR_STRING = 101,
UI_F_UI_DUP_INFO_STRING = 102,
UI_F_UI_DUP_INPUT_BOOLEAN = 110,
UI_F_UI_DUP_INPUT_STRING = 103,
UI_F_UI_DUP_VERIFY_STRING = 106,
UI_F_UI_GET0_RESULT = 107,
UI_F_UI_NEW_METHOD = 104,
UI_F_UI_SET_RESULT = 105,
UI_INPUT_FLAG_DEFAULT_PWD = 0x02,
UI_INPUT_FLAG_ECHO = 0x01,
UI_INPUT_FLAG_USER_BASE = 16,
UI_R_COMMON_OK_AND_CANCEL_CHARACTERS = 104,
UI_R_INDEX_TOO_LARGE = 102,
UI_R_INDEX_TOO_SMALL = 103,
UI_R_NO_RESULT_BUFFER = 105,
UI_R_RESULT_TOO_LARGE = 100,
UI_R_RESULT_TOO_SMALL = 101,
UI_R_UNKNOWN_CONTROL_COMMAND = 106,
V_ASN1_APPLICATION = 0x40,
V_ASN1_BIT_STRING = 3,
V_ASN1_BMPSTRING = 30,
V_ASN1_CONSTRUCTED = 0x20,
V_ASN1_CONTEXT_SPECIFIC = 0x80,
V_ASN1_ENUMERATED = 10,
V_ASN1_EOC = 0,
V_ASN1_EXTERNAL = 8,
V_ASN1_IA5STRING = 22,
V_ASN1_INTEGER = 2,
V_ASN1_NULL = 5,
V_ASN1_OBJECT = 6,
V_ASN1_OBJECT_DESCRIPTOR = 7,
V_ASN1_OCTET_STRING = 4,
V_ASN1_PRIMATIVE_TAG = 0x1f,
V_ASN1_PRIMITIVE_TAG = 0x1f,
V_ASN1_PRINTABLESTRING = 19,
V_ASN1_PRIVATE = 0xc0,
V_ASN1_REAL = 9,
V_ASN1_SEQUENCE = 16,
V_ASN1_SET = 17,
V_ASN1_T61STRING = 20,
V_ASN1_UNDEF = -1,
V_ASN1_UNIVERSAL = 0x00,
V_ASN1_UTCTIME = 23,
V_ASN1_UTF8STRING = 12,
V_OCSP_CERTSTATUS_GOOD = 0,
V_OCSP_CERTSTATUS_REVOKED = 1,
V_OCSP_CERTSTATUS_UNKNOWN = 2,
V_OCSP_RESPID_KEY = 1,
V_OCSP_RESPID_NAME = 0,
V3_ASID_ASNUM = 0,
V3_ASID_RDI = 1,
WHIRLPOOL_BBLOCK = 512,
X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT = 0x1,
X509_CHECK_FLAG_MULTI_LABEL_WILDCARDS = 0x8,
X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS = 0x4,
X509_CHECK_FLAG_NO_WILDCARDS = 0x2,
X509_CHECK_FLAG_SINGLE_LABEL_SUBDOMAINS = 0x10,
X509_EX_V_INIT = 0x0001,
X509_EX_V_NETSCAPE_HACK = 0x8000,
X509_EXT_PACK_STRING = 2,
X509_EXT_PACK_UNKNOWN = 1,
X509_F_ADD_CERT_DIR = 100,
X509_F_BY_FILE_CTRL = 101,
X509_F_CHECK_NAME_CONSTRAINTS = 106,
X509_F_CHECK_POLICY = 145,
X509_F_DIR_CTRL = 102,
X509_F_GET_CERT_BY_SUBJECT = 103,
X509_F_NETSCAPE_SPKI_B64_DECODE = 129,
X509_F_NETSCAPE_SPKI_B64_ENCODE = 130,
X509_F_X509_ATTRIBUTE_CREATE_BY_NID = 136,
X509_F_X509_ATTRIBUTE_CREATE_BY_OBJ = 137,
X509_F_X509_ATTRIBUTE_CREATE_BY_TXT = 140,
X509_F_X509_ATTRIBUTE_GET0_DATA = 139,
X509_F_X509_ATTRIBUTE_SET1_DATA = 138,
X509_F_X509_CHECK_PRIVATE_KEY = 128,
X509_F_X509_CRL_DIFF = 105,
X509_F_X509_CRL_PRINT_FP = 147,
X509_F_X509_EXTENSION_CREATE_BY_NID = 108,
X509_F_X509_EXTENSION_CREATE_BY_OBJ = 109,
X509_F_X509_GET_PUBKEY_PARAMETERS = 110,
X509_F_X509_LOAD_CERT_CRL_FILE = 132,
X509_F_X509_LOAD_CERT_FILE = 111,
X509_F_X509_LOAD_CRL_FILE = 112,
X509_F_X509_NAME_ADD_ENTRY = 113,
X509_F_X509_NAME_ENTRY_CREATE_BY_NID = 114,
X509_F_X509_NAME_ENTRY_CREATE_BY_TXT = 131,
X509_F_X509_NAME_ENTRY_SET_OBJECT = 115,
X509_F_X509_NAME_ONELINE = 116,
X509_F_X509_NAME_PRINT = 117,
X509_F_X509_PRINT_EX_FP = 118,
X509_F_X509_PUBKEY_GET = 119,
X509_F_X509_PUBKEY_SET = 120,
X509_F_X509_REQ_CHECK_PRIVATE_KEY = 144,
X509_F_X509_REQ_PRINT_EX = 121,
X509_F_X509_REQ_PRINT_FP = 122,
X509_F_X509_REQ_TO_X509 = 123,
X509_F_X509_STORE_ADD_CERT = 124,
X509_F_X509_STORE_ADD_CRL = 125,
X509_F_X509_STORE_CTX_GET1_ISSUER = 146,
X509_F_X509_STORE_CTX_INIT = 143,
X509_F_X509_STORE_CTX_NEW = 142,
X509_F_X509_STORE_CTX_PURPOSE_INHERIT = 134,
X509_F_X509_TO_X509_REQ = 126,
X509_F_X509_TRUST_ADD = 133,
X509_F_X509_TRUST_SET = 141,
X509_F_X509_VERIFY_CERT = 127,
X509_F_X509AT_ADD1_ATTR = 135,
X509_F_X509V3_ADD_EXT = 104,
X509_FILETYPE_ASN1 = 2,
X509_FILETYPE_DEFAULT = 3,
X509_FILETYPE_PEM = 1,
X509_FLAG_COMPAT = 0,
X509_L_ADD_DIR = 2,
X509_L_FILE_LOAD = 1,
X509_LU_CRL = 2,
X509_LU_FAIL = 0,
X509_LU_PKEY = 3,
X509_LU_RETRY = -1,
X509_LU_X509 = 1,
X509_PURPOSE_ANY = 7,
X509_PURPOSE_CRL_SIGN = 6,
X509_PURPOSE_DYNAMIC = 0x1,
X509_PURPOSE_DYNAMIC_NAME = 0x2,
X509_PURPOSE_MAX = 9,
X509_PURPOSE_MIN = 1,
X509_PURPOSE_NS_SSL_SERVER = 3,
X509_PURPOSE_OCSP_HELPER = 8,
X509_PURPOSE_SMIME_ENCRYPT = 5,
X509_PURPOSE_SMIME_SIGN = 4,
X509_PURPOSE_SSL_CLIENT = 1,
X509_PURPOSE_SSL_SERVER = 2,
X509_PURPOSE_TIMESTAMP_SIGN = 9,
X509_R_AKID_MISMATCH = 110,
X509_R_BAD_X509_FILETYPE = 100,
X509_R_BASE64_DECODE_ERROR = 118,
X509_R_CANT_CHECK_DH_KEY = 114,
X509_R_CERT_ALREADY_IN_HASH_TABLE = 101,
X509_R_CRL_ALREADY_DELTA = 127,
X509_R_CRL_VERIFY_FAILURE = 131,
X509_R_ERR_ASN1_LIB = 102,
X509_R_IDP_MISMATCH = 128,
X509_R_INVALID_DIRECTORY = 113,
X509_R_INVALID_FIELD_NAME = 119,
X509_R_INVALID_TRUST = 123,
X509_R_ISSUER_MISMATCH = 129,
X509_R_KEY_TYPE_MISMATCH = 115,
X509_R_KEY_VALUES_MISMATCH = 116,
X509_R_LOADING_CERT_DIR = 103,
X509_R_LOADING_DEFAULTS = 104,
X509_R_METHOD_NOT_SUPPORTED = 124,
X509_R_NAME_TOO_LONG = 134,
X509_R_NEWER_CRL_NOT_NEWER = 132,
X509_R_NO_CERT_SET_FOR_US_TO_VERIFY = 105,
X509_R_NO_CRL_NUMBER = 130,
X509_R_PUBLIC_KEY_DECODE_ERROR = 125,
X509_R_PUBLIC_KEY_ENCODE_ERROR = 126,
X509_R_SHOULD_RETRY = 106,
X509_R_UNABLE_TO_FIND_PARAMETERS_IN_CHAIN = 107,
X509_R_UNABLE_TO_GET_CERTS_PUBLIC_KEY = 108,
X509_R_UNKNOWN_KEY_TYPE = 117,
X509_R_UNKNOWN_NID = 109,
X509_R_UNKNOWN_PURPOSE_ID = 121,
X509_R_UNKNOWN_TRUST_ID = 120,
X509_R_UNSUPPORTED_ALGORITHM = 111,
X509_R_WRONG_LOOKUP_TYPE = 112,
X509_R_WRONG_TYPE = 122,
X509_TRUST_COMPAT = 1,
X509_TRUST_DYNAMIC = 1,
X509_TRUST_DYNAMIC_NAME = 2,
X509_TRUST_EMAIL = 4,
X509_TRUST_MAX = 8,
X509_TRUST_MIN = 1,
X509_TRUST_OBJECT_SIGN = 5,
X509_TRUST_OCSP_REQUEST = 7,
X509_TRUST_OCSP_SIGN = 6,
X509_TRUST_REJECTED = 2,
X509_TRUST_SSL_CLIENT = 2,
X509_TRUST_SSL_SERVER = 3,
X509_TRUST_TRUSTED = 1,
X509_TRUST_TSA = 8,
X509_TRUST_UNTRUSTED = 3,
X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH = 31,
X509_V_ERR_AKID_SKID_MISMATCH = 30,
X509_V_ERR_APPLICATION_VERIFICATION = 50,
X509_V_ERR_CERT_CHAIN_TOO_LONG = 22,
X509_V_ERR_CERT_HAS_EXPIRED = 10,
X509_V_ERR_CERT_NOT_YET_VALID = 9,
X509_V_ERR_CERT_REJECTED = 28,
X509_V_ERR_CERT_REVOKED = 23,
X509_V_ERR_CERT_SIGNATURE_FAILURE = 7,
X509_V_ERR_CERT_UNTRUSTED = 27,
X509_V_ERR_CRL_HAS_EXPIRED = 12,
X509_V_ERR_CRL_NOT_YET_VALID = 11,
X509_V_ERR_CRL_PATH_VALIDATION_ERROR = 54,
X509_V_ERR_CRL_SIGNATURE_FAILURE = 8,
X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT = 18,
X509_V_ERR_DIFFERENT_CRL_SCOPE = 44,
X509_V_ERR_EMAIL_MISMATCH = 63,
X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD = 14,
X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD = 13,
X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD = 15,
X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD = 16,
X509_V_ERR_EXCLUDED_VIOLATION = 48,
X509_V_ERR_HOSTNAME_MISMATCH = 62,
X509_V_ERR_INVALID_CA = 24,
X509_V_ERR_INVALID_CALL = 65,
X509_V_ERR_INVALID_EXTENSION = 41,
X509_V_ERR_INVALID_NON_CA = 37,
X509_V_ERR_INVALID_POLICY_EXTENSION = 42,
X509_V_ERR_INVALID_PURPOSE = 26,
X509_V_ERR_IP_ADDRESS_MISMATCH = 64,
X509_V_ERR_KEYUSAGE_NO_CERTSIGN = 32,
X509_V_ERR_KEYUSAGE_NO_CRL_SIGN = 35,
X509_V_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE = 39,
X509_V_ERR_NO_EXPLICIT_POLICY = 43,
X509_V_ERR_OUT_OF_MEM = 17,
X509_V_ERR_PATH_LENGTH_EXCEEDED = 25,
X509_V_ERR_PERMITTED_VIOLATION = 47,
X509_V_ERR_PROXY_CERTIFICATES_NOT_ALLOWED = 40,
X509_V_ERR_PROXY_PATH_LENGTH_EXCEEDED = 38,
X509_V_ERR_PROXY_SUBJECT_NAME_VIOLATION = 67,
X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN = 19,
X509_V_ERR_STORE_LOOKUP = 66,
X509_V_ERR_SUBJECT_ISSUER_MISMATCH = 29,
X509_V_ERR_SUBTREE_MINMAX = 49,
X509_V_ERR_SUITE_B_CANNOT_SIGN_P_384_WITH_P_256 = 61,
X509_V_ERR_SUITE_B_INVALID_ALGORITHM = 57,
X509_V_ERR_SUITE_B_INVALID_CURVE = 58,
X509_V_ERR_SUITE_B_INVALID_SIGNATURE_ALGORITHM = 59,
X509_V_ERR_SUITE_B_INVALID_VERSION = 56,
X509_V_ERR_SUITE_B_LOS_NOT_ALLOWED = 60,
X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY = 6,
X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE = 4,
X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE = 5,
X509_V_ERR_UNABLE_TO_GET_CRL = 3,
X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER = 33,
X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT = 2,
X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY = 20,
X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE = 21,
X509_V_ERR_UNHANDLED_CRITICAL_CRL_EXTENSION = 36,
X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION = 34,
X509_V_ERR_UNNESTED_RESOURCE = 46,
X509_V_ERR_UNSPECIFIED = 1,
X509_V_ERR_UNSUPPORTED_CONSTRAINT_SYNTAX = 52,
X509_V_ERR_UNSUPPORTED_CONSTRAINT_TYPE = 51,
X509_V_ERR_UNSUPPORTED_EXTENSION_FEATURE = 45,
X509_V_ERR_UNSUPPORTED_NAME_SYNTAX = 53,
X509_V_FLAG_ALLOW_PROXY_CERTS = 0x40,
X509_V_FLAG_CB_ISSUER_CHECK = 0x1,
X509_V_FLAG_CHECK_SS_SIGNATURE = 0x4000,
X509_V_FLAG_CRL_CHECK = 0x4,
X509_V_FLAG_CRL_CHECK_ALL = 0x8,
X509_V_FLAG_EXPLICIT_POLICY = 0x100,
X509_V_FLAG_EXTENDED_CRL_SUPPORT = 0x1000,
X509_V_FLAG_IGNORE_CRITICAL = 0x10,
X509_V_FLAG_INHIBIT_ANY = 0x200,
X509_V_FLAG_INHIBIT_MAP = 0x400,
X509_V_FLAG_NO_ALT_CHAINS = 0x100000,
X509_V_FLAG_NOTIFY_POLICY = 0x800,
X509_V_FLAG_PARTIAL_CHAIN = 0x80000,
X509_V_FLAG_POLICY_CHECK = 0x80,
X509_V_FLAG_SUITEB_128_LOS = 0x30000,
X509_V_FLAG_SUITEB_128_LOS_ONLY = 0x10000,
X509_V_FLAG_SUITEB_192_LOS = 0x20000,
X509_V_FLAG_TRUSTED_FIRST = 0x8000,
X509_V_FLAG_USE_CHECK_TIME = 0x2,
X509_V_FLAG_USE_DELTAS = 0x2000,
X509_V_FLAG_X509_STRICT = 0x20,
X509_V_OK = 0,
X509_VP_FLAG_DEFAULT = 0x1,
X509_VP_FLAG_LOCKED = 0x8,
X509_VP_FLAG_ONCE = 0x10,
X509_VP_FLAG_OVERWRITE = 0x2,
X509_VP_FLAG_RESET_FLAGS = 0x4,
X509V3_ADD_SILENT = 0x10,
X509V3_EXT_CTX_DEP = 0x2,
X509V3_EXT_DEFAULT = 0,
X509V3_EXT_DYNAMIC = 0x1,
X509V3_EXT_MULTILINE = 0x4,
X509V3_F_A2I_GENERAL_NAME = 164,
X509V3_F_ASIDENTIFIERCHOICE_CANONIZE = 161,
X509V3_F_ASIDENTIFIERCHOICE_IS_CANONICAL = 162,
X509V3_F_COPY_EMAIL = 122,
X509V3_F_COPY_ISSUER = 123,
X509V3_F_DO_DIRNAME = 144,
X509V3_F_DO_EXT_CONF = 124,
X509V3_F_DO_EXT_I2D = 135,
X509V3_F_DO_EXT_NCONF = 151,
X509V3_F_DO_I2V_NAME_CONSTRAINTS = 148,
X509V3_F_GNAMES_FROM_SECTNAME = 156,
X509V3_F_HEX_TO_STRING = 111,
X509V3_F_I2S_ASN1_ENUMERATED = 121,
X509V3_F_I2S_ASN1_IA5STRING = 149,
X509V3_F_I2S_ASN1_INTEGER = 120,
X509V3_F_I2V_AUTHORITY_INFO_ACCESS = 138,
X509V3_F_NOTICE_SECTION = 132,
X509V3_F_NREF_NOS = 133,
X509V3_F_POLICY_SECTION = 131,
X509V3_F_PROCESS_PCI_VALUE = 150,
X509V3_F_R2I_CERTPOL = 130,
X509V3_F_R2I_PCI = 155,
X509V3_F_S2I_ASN1_IA5STRING = 100,
X509V3_F_S2I_ASN1_INTEGER = 108,
X509V3_F_S2I_ASN1_OCTET_STRING = 112,
X509V3_F_S2I_ASN1_SKEY_ID = 114,
X509V3_F_S2I_SKEY_ID = 115,
X509V3_F_SET_DIST_POINT_NAME = 158,
X509V3_F_STRING_TO_HEX = 113,
X509V3_F_SXNET_ADD_ID_ASC = 125,
X509V3_F_SXNET_ADD_ID_INTEGER = 126,
X509V3_F_SXNET_ADD_ID_ULONG = 127,
X509V3_F_SXNET_GET_ID_ASC = 128,
X509V3_F_SXNET_GET_ID_ULONG = 129,
X509V3_F_V2I_ASIDENTIFIERS = 163,
X509V3_F_V2I_ASN1_BIT_STRING = 101,
X509V3_F_V2I_AUTHORITY_INFO_ACCESS = 139,
X509V3_F_V2I_AUTHORITY_KEYID = 119,
X509V3_F_V2I_BASIC_CONSTRAINTS = 102,
X509V3_F_V2I_CRLD = 134,
X509V3_F_V2I_EXTENDED_KEY_USAGE = 103,
X509V3_F_V2I_GENERAL_NAME_EX = 117,
X509V3_F_V2I_GENERAL_NAMES = 118,
X509V3_F_V2I_IDP = 157,
X509V3_F_V2I_IPADDRBLOCKS = 159,
X509V3_F_V2I_ISSUER_ALT = 153,
X509V3_F_V2I_NAME_CONSTRAINTS = 147,
X509V3_F_V2I_POLICY_CONSTRAINTS = 146,
X509V3_F_V2I_POLICY_MAPPINGS = 145,
X509V3_F_V2I_SUBJECT_ALT = 154,
X509V3_F_V3_ADDR_VALIDATE_PATH_INTERNAL = 160,
X509V3_F_V3_GENERIC_EXTENSION = 116,
X509V3_F_X509_PURPOSE_ADD = 137,
X509V3_F_X509_PURPOSE_SET = 141,
X509V3_F_X509V3_ADD_VALUE = 105,
X509V3_F_X509V3_ADD1_I2D = 140,
X509V3_F_X509V3_EXT_ADD = 104,
X509V3_F_X509V3_EXT_ADD_ALIAS = 106,
X509V3_F_X509V3_EXT_CONF = 107,
X509V3_F_X509V3_EXT_FREE = 165,
X509V3_F_X509V3_EXT_I2D = 136,
X509V3_F_X509V3_EXT_NCONF = 152,
X509V3_F_X509V3_GET_SECTION = 142,
X509V3_F_X509V3_GET_STRING = 143,
X509V3_F_X509V3_GET_VALUE_BOOL = 110,
X509V3_F_X509V3_PARSE_LIST = 109,
X509v3_KU_CRL_SIGN = 0x0002,
X509v3_KU_DATA_ENCIPHERMENT = 0x0010,
X509v3_KU_DECIPHER_ONLY = 0x8000,
X509v3_KU_DIGITAL_SIGNATURE = 0x0080,
X509v3_KU_ENCIPHER_ONLY = 0x0001,
X509v3_KU_KEY_AGREEMENT = 0x0008,
X509v3_KU_KEY_CERT_SIGN = 0x0004,
X509v3_KU_KEY_ENCIPHERMENT = 0x0020,
X509v3_KU_NON_REPUDIATION = 0x0040,
X509v3_KU_UNDEF = 0xffff,
X509V3_R_BAD_IP_ADDRESS = 118,
X509V3_R_BAD_OBJECT = 119,
X509V3_R_BN_DEC2BN_ERROR = 100,
X509V3_R_BN_TO_ASN1_INTEGER_ERROR = 101,
X509V3_R_CANNOT_FIND_FREE_FUNCTION = 168,
X509V3_R_DIRNAME_ERROR = 149,
X509V3_R_DISTPOINT_ALREADY_SET = 160,
X509V3_R_DUPLICATE_ZONE_ID = 133,
X509V3_R_ERROR_CONVERTING_ZONE = 131,
X509V3_R_ERROR_CREATING_EXTENSION = 144,
X509V3_R_ERROR_IN_EXTENSION = 128,
X509V3_R_EXPECTED_A_SECTION_NAME = 137,
X509V3_R_EXTENSION_EXISTS = 145,
X509V3_R_EXTENSION_NAME_ERROR = 115,
X509V3_R_EXTENSION_NOT_FOUND = 102,
X509V3_R_EXTENSION_SETTING_NOT_SUPPORTED = 103,
X509V3_R_EXTENSION_VALUE_ERROR = 116,
X509V3_R_ILLEGAL_EMPTY_EXTENSION = 151,
X509V3_R_ILLEGAL_HEX_DIGIT = 113,
X509V3_R_INCORRECT_POLICY_SYNTAX_TAG = 152,
X509V3_R_INVALID_ASNUMBER = 162,
X509V3_R_INVALID_ASRANGE = 163,
X509V3_R_INVALID_BOOLEAN_STRING = 104,
X509V3_R_INVALID_EXTENSION_STRING = 105,
X509V3_R_INVALID_INHERITANCE = 165,
X509V3_R_INVALID_IPADDRESS = 166,
X509V3_R_INVALID_MULTIPLE_RDNS = 161,
X509V3_R_INVALID_NAME = 106,
X509V3_R_INVALID_NULL_ARGUMENT = 107,
X509V3_R_INVALID_NULL_NAME = 108,
X509V3_R_INVALID_NULL_VALUE = 109,
X509V3_R_INVALID_NUMBER = 140,
X509V3_R_INVALID_NUMBERS = 141,
X509V3_R_INVALID_OBJECT_IDENTIFIER = 110,
X509V3_R_INVALID_OPTION = 138,
X509V3_R_INVALID_POLICY_IDENTIFIER = 134,
X509V3_R_INVALID_PROXY_POLICY_SETTING = 153,
X509V3_R_INVALID_PURPOSE = 146,
X509V3_R_INVALID_SAFI = 164,
X509V3_R_INVALID_SECTION = 135,
X509V3_R_INVALID_SYNTAX = 143,
X509V3_R_ISSUER_DECODE_ERROR = 126,
X509V3_R_MISSING_VALUE = 124,
X509V3_R_NEED_ORGANIZATION_AND_NUMBERS = 142,
X509V3_R_NO_CONFIG_DATABASE = 136,
X509V3_R_NO_ISSUER_CERTIFICATE = 121,
X509V3_R_NO_ISSUER_DETAILS = 127,
X509V3_R_NO_POLICY_IDENTIFIER = 139,
X509V3_R_NO_PROXY_CERT_POLICY_LANGUAGE_DEFINED = 154,
X509V3_R_NO_PUBLIC_KEY = 114,
X509V3_R_NO_SUBJECT_DETAILS = 125,
X509V3_R_ODD_NUMBER_OF_DIGITS = 112,
X509V3_R_OPERATION_NOT_DEFINED = 148,
X509V3_R_OTHERNAME_ERROR = 147,
X509V3_R_POLICY_LANGUAGE_ALREADY_DEFINED = 155,
X509V3_R_POLICY_PATH_LENGTH = 156,
X509V3_R_POLICY_PATH_LENGTH_ALREADY_DEFINED = 157,
X509V3_R_POLICY_SYNTAX_NOT_CURRENTLY_SUPPORTED = 158,
X509V3_R_POLICY_WHEN_PROXY_LANGUAGE_REQUIRES_NO_POLICY = 159,
X509V3_R_SECTION_NOT_FOUND = 150,
X509V3_R_UNABLE_TO_GET_ISSUER_DETAILS = 122,
X509V3_R_UNABLE_TO_GET_ISSUER_KEYID = 123,
X509V3_R_UNKNOWN_BIT_STRING_ARGUMENT = 111,
X509V3_R_UNKNOWN_EXTENSION = 129,
X509V3_R_UNKNOWN_EXTENSION_NAME = 130,
X509V3_R_UNKNOWN_OPTION = 120,
X509V3_R_UNSUPPORTED_OPTION = 117,
X509V3_R_UNSUPPORTED_TYPE = 167,
X509V3_R_USER_TOO_LONG = 132,
XKU_ANYEKU = 0x100,
XKU_CODE_SIGN = 0x8,
XKU_DVCS = 0x80,
XKU_OCSP_SIGN = 0x20,
XKU_SGC = 0x10,
XKU_SMIME = 0x4,
XKU_SSL_CLIENT = 0x2,
XKU_SSL_SERVER = 0x1,
XKU_TIMESTAMP = 0x40,
};

enum NID {
NID_aaControls = 289,
NID_ac_auditEntity = 287,
NID_ac_proxying = 397,
NID_ac_targeting = 288,
NID_account = 446,
NID_ad_ca_issuers = 179,
NID_ad_dvcs = 364,
NID_ad_OCSP = 178,
NID_ad_timeStamping = 363,
NID_aes_128_cbc = 419,
NID_aes_128_cbc_hmac_sha1 = 916,
NID_aes_128_cbc_hmac_sha256 = 948,
NID_aes_128_ccm = 896,
NID_aes_128_cfb1 = 650,
NID_aes_128_cfb128 = 421,
NID_aes_128_cfb8 = 653,
NID_aes_128_ctr = 904,
NID_aes_128_ecb = 418,
NID_aes_128_gcm = 895,
NID_aes_128_ofb128 = 420,
NID_aes_128_xts = 913,
NID_aes_192_cbc = 423,
NID_aes_192_cbc_hmac_sha1 = 917,
NID_aes_192_cbc_hmac_sha256 = 949,
NID_aes_192_ccm = 899,
NID_aes_192_cfb1 = 651,
NID_aes_192_cfb128 = 425,
NID_aes_192_cfb8 = 654,
NID_aes_192_ctr = 905,
NID_aes_192_ecb = 422,
NID_aes_192_gcm = 898,
NID_aes_192_ofb128 = 424,
NID_aes_256_cbc = 427,
NID_aes_256_cbc_hmac_sha1 = 918,
NID_aes_256_cbc_hmac_sha256 = 950,
NID_aes_256_ccm = 902,
NID_aes_256_cfb1 = 652,
NID_aes_256_cfb128 = 429,
NID_aes_256_cfb8 = 655,
NID_aes_256_ctr = 906,
NID_aes_256_ecb = 426,
NID_aes_256_gcm = 901,
NID_aes_256_ofb128 = 428,
NID_aes_256_xts = 914,
NID_ansi_X9_62 = 405,
NID_any_policy = 746,
NID_anyExtendedKeyUsage = 910,
NID_aRecord = 478,
NID_associatedDomain = 484,
NID_associatedName = 485,
NID_audio = 501,
NID_authority_key_identifier = 90,
NID_authorityRevocationList = 882,
NID_basic_constraints = 87,
NID_bf_cbc = 91,
NID_bf_cfb64 = 93,
NID_bf_ecb = 92,
NID_bf_ofb64 = 94,
NID_biometricInfo = 285,
NID_brainpoolP160r1 = 921,
NID_brainpoolP160t1 = 922,
NID_brainpoolP192r1 = 923,
NID_brainpoolP192t1 = 924,
NID_brainpoolP224r1 = 925,
NID_brainpoolP224t1 = 926,
NID_brainpoolP256r1 = 927,
NID_brainpoolP256t1 = 928,
NID_brainpoolP320r1 = 929,
NID_brainpoolP320t1 = 930,
NID_brainpoolP384r1 = 931,
NID_brainpoolP384t1 = 932,
NID_brainpoolP512r1 = 933,
NID_brainpoolP512t1 = 934,
NID_buildingName = 494,
NID_businessCategory = 860,
NID_cACertificate = 881,
NID_camellia_128_cbc = 751,
NID_camellia_128_cfb1 = 760,
NID_camellia_128_cfb128 = 757,
NID_camellia_128_cfb8 = 763,
NID_camellia_128_ecb = 754,
NID_camellia_128_ofb128 = 766,
NID_camellia_192_cbc = 752,
NID_camellia_192_cfb1 = 761,
NID_camellia_192_cfb128 = 758,
NID_camellia_192_cfb8 = 764,
NID_camellia_192_ecb = 755,
NID_camellia_192_ofb128 = 767,
NID_camellia_256_cbc = 753,
NID_camellia_256_cfb1 = 762,
NID_camellia_256_cfb128 = 759,
NID_camellia_256_cfb8 = 765,
NID_camellia_256_ecb = 756,
NID_camellia_256_ofb128 = 768,
NID_caRepository = 785,
NID_caseIgnoreIA5StringSyntax = 443,
NID_cast5_cbc = 108,
NID_cast5_cfb64 = 110,
NID_cast5_ecb = 109,
NID_cast5_ofb64 = 111,
NID_ccitt = 404,
NID_certBag = 152,
NID_certicom_arc = 677,
NID_certificate_issuer = 771,
NID_certificate_policies = 89,
NID_certificateRevocationList = 883,
NID_clearance = 395,
NID_client_auth = 130,
NID_cmac = 894,
NID_cNAMERecord = 483,
NID_code_sign = 131,
NID_commonName = 13,
NID_countryName = 14,
NID_crl_distribution_points = 103,
NID_crl_number = 88,
NID_crl_reason = 141,
NID_crlBag = 153,
NID_crossCertificatePair = 884,
NID_cryptocom = 806,
NID_cryptopro = 805,
NID_ct_cert_scts = 954,
NID_ct_precert_poison = 952,
NID_ct_precert_scts = 951,
NID_ct_precert_signer = 953,
NID_data = 434,
NID_dcObject = 390,
NID_delta_crl = 140,
NID_deltaRevocationList = 891,
NID_des_cbc = 31,
NID_des_cdmf = 643,
NID_des_cfb1 = 656,
NID_des_cfb64 = 30,
NID_des_cfb8 = 657,
NID_des_ecb = 29,
NID_des_ede = 32,
NID_des_ede_cbc = 43,
NID_des_ede_cfb64 = 60,
NID_des_ede_ecb = 32,
NID_des_ede_ofb64 = 62,
NID_des_ede3 = 33,
NID_des_ede3_cbc = 44,
NID_des_ede3_cfb1 = 658,
NID_des_ede3_cfb64 = 61,
NID_des_ede3_cfb8 = 659,
NID_des_ede3_ecb = 33,
NID_des_ede3_ofb64 = 63,
NID_des_ofb64 = 45,
NID_description = 107,
NID_destinationIndicator = 871,
NID_desx_cbc = 80,
NID_dh_cofactor_kdf = 947,
NID_dh_std_kdf = 946,
NID_dhKeyAgreement = 28,
NID_dhpublicnumber = 920,
NID_dhSinglePass_cofactorDH_sha1kdf_scheme = 941,
NID_dhSinglePass_cofactorDH_sha224kdf_scheme = 942,
NID_dhSinglePass_cofactorDH_sha256kdf_scheme = 943,
NID_dhSinglePass_cofactorDH_sha384kdf_scheme = 944,
NID_dhSinglePass_cofactorDH_sha512kdf_scheme = 945,
NID_dhSinglePass_stdDH_sha1kdf_scheme = 936,
NID_dhSinglePass_stdDH_sha224kdf_scheme = 937,
NID_dhSinglePass_stdDH_sha256kdf_scheme = 938,
NID_dhSinglePass_stdDH_sha384kdf_scheme = 939,
NID_dhSinglePass_stdDH_sha512kdf_scheme = 940,
NID_Directory = 382,
NID_distinguishedName = 887,
NID_dITRedirect = 500,
NID_dmdName = 892,
NID_dnQualifier = 174,
NID_dNSDomain = 451,
NID_document = 447,
NID_documentAuthor = 471,
NID_documentIdentifier = 468,
NID_documentLocation = 472,
NID_documentPublisher = 502,
NID_documentSeries = 449,
NID_documentTitle = 469,
NID_documentVersion = 470,
NID_dod = 380,
NID_Domain = 392,
NID_domainComponent = 391,
NID_domainRelatedObject = 452,
NID_dsa = 116,
NID_dsa_2 = 67,
NID_dsa_with_SHA224 = 802,
NID_dsa_with_SHA256 = 803,
NID_dSAQuality = 495,
NID_dsaWithSHA = 66,
NID_dsaWithSHA1 = 113,
NID_dsaWithSHA1_2 = 70,
NID_dvcs = 297,
NID_ecdsa_with_Recommended = 791,
NID_ecdsa_with_SHA1 = 416,
NID_ecdsa_with_SHA224 = 793,
NID_ecdsa_with_SHA256 = 794,
NID_ecdsa_with_SHA384 = 795,
NID_ecdsa_with_SHA512 = 796,
NID_ecdsa_with_Specified = 792,
NID_email_protect = 132,
NID_enhancedSearchGuide = 885,
NID_Enterprises = 389,
NID_Experimental = 384,
NID_ext_key_usage = 126,
NID_ext_req = 172,
NID_facsimileTelephoneNumber = 867,
NID_favouriteDrink = 462,
NID_freshest_crl = 857,
NID_friendlyCountry = 453,
NID_friendlyCountryName = 490,
NID_friendlyName = 156,
NID_generationQualifier = 509,
NID_givenName = 99,
NID_gost89_cnt = 814,
NID_hmac = 855,
NID_hmac_md5 = 780,
NID_hmac_sha1 = 781,
NID_hmacWithMD5 = 797,
NID_hmacWithSHA1 = 163,
NID_hmacWithSHA224 = 798,
NID_hmacWithSHA256 = 799,
NID_hmacWithSHA384 = 800,
NID_hmacWithSHA512 = 801,
NID_hold_instruction_call_issuer = 432,
NID_hold_instruction_code = 430,
NID_hold_instruction_none = 431,
NID_hold_instruction_reject = 433,
NID_homePostalAddress = 486,
NID_homeTelephoneNumber = 473,
NID_host = 466,
NID_houseIdentifier = 889,
NID_iA5StringSyntax = 442,
NID_iana = 381,
NID_id_aca = 266,
NID_id_aca_accessIdentity = 355,
NID_id_aca_authenticationInfo = 354,
NID_id_aca_chargingIdentity = 356,
NID_id_aca_encAttrs = 399,
NID_id_aca_group = 357,
NID_id_aca_role = 358,
NID_id_ad = 176,
NID_id_aes128_wrap = 788,
NID_id_aes128_wrap_pad = 897,
NID_id_aes192_wrap = 789,
NID_id_aes192_wrap_pad = 900,
NID_id_aes256_wrap = 790,
NID_id_aes256_wrap_pad = 903,
NID_id_alg = 262,
NID_id_alg_des40 = 323,
NID_id_alg_dh_pop = 326,
NID_id_alg_dh_sig_hmac_sha1 = 325,
NID_id_alg_noSignature = 324,
NID_id_alg_PWRI_KEK = 893,
NID_id_camellia128_wrap = 907,
NID_id_camellia192_wrap = 908,
NID_id_camellia256_wrap = 909,
NID_id_cct = 268,
NID_id_cct_crs = 360,
NID_id_cct_PKIData = 361,
NID_id_cct_PKIResponse = 362,
NID_id_ce = 81,
NID_id_cmc = 263,
NID_id_cmc_addExtensions = 334,
NID_id_cmc_confirmCertAcceptance = 346,
NID_id_cmc_dataReturn = 330,
NID_id_cmc_decryptedPOP = 336,
NID_id_cmc_encryptedPOP = 335,
NID_id_cmc_getCert = 338,
NID_id_cmc_getCRL = 339,
NID_id_cmc_identification = 328,
NID_id_cmc_identityProof = 329,
NID_id_cmc_lraPOPWitness = 337,
NID_id_cmc_popLinkRandom = 344,
NID_id_cmc_popLinkWitness = 345,
NID_id_cmc_queryPending = 343,
NID_id_cmc_recipientNonce = 333,
NID_id_cmc_regInfo = 341,
NID_id_cmc_responseInfo = 342,
NID_id_cmc_revokeRequest = 340,
NID_id_cmc_senderNonce = 332,
NID_id_cmc_statusInfo = 327,
NID_id_cmc_transactionId = 331,
NID_id_ct_asciiTextWithCRLF = 787,
NID_id_DHBasedMac = 783,
NID_id_Gost28147_89 = 813,
NID_id_Gost28147_89_cc = 849,
NID_id_Gost28147_89_CryptoPro_A_ParamSet = 824,
NID_id_Gost28147_89_CryptoPro_B_ParamSet = 825,
NID_id_Gost28147_89_CryptoPro_C_ParamSet = 826,
NID_id_Gost28147_89_CryptoPro_D_ParamSet = 827,
NID_id_Gost28147_89_CryptoPro_KeyMeshing = 819,
NID_id_Gost28147_89_CryptoPro_Oscar_1_0_ParamSet = 829,
NID_id_Gost28147_89_CryptoPro_Oscar_1_1_ParamSet = 828,
NID_id_Gost28147_89_CryptoPro_RIC_1_ParamSet = 830,
NID_id_Gost28147_89_MAC = 815,
NID_id_Gost28147_89_None_KeyMeshing = 820,
NID_id_Gost28147_89_TestParamSet = 823,
NID_id_GostR3410_2001 = 811,
NID_id_GostR3410_2001_cc = 851,
NID_id_GostR3410_2001_CryptoPro_A_ParamSet = 840,
NID_id_GostR3410_2001_CryptoPro_B_ParamSet = 841,
NID_id_GostR3410_2001_CryptoPro_C_ParamSet = 842,
NID_id_GostR3410_2001_CryptoPro_XchA_ParamSet = 843,
NID_id_GostR3410_2001_CryptoPro_XchB_ParamSet = 844,
NID_id_GostR3410_2001_ParamSet_cc = 854,
NID_id_GostR3410_2001_TestParamSet = 839,
NID_id_GostR3410_2001DH = 817,
NID_id_GostR3410_94 = 812,
NID_id_GostR3410_94_a = 845,
NID_id_GostR3410_94_aBis = 846,
NID_id_GostR3410_94_b = 847,
NID_id_GostR3410_94_bBis = 848,
NID_id_GostR3410_94_cc = 850,
NID_id_GostR3410_94_CryptoPro_A_ParamSet = 832,
NID_id_GostR3410_94_CryptoPro_B_ParamSet = 833,
NID_id_GostR3410_94_CryptoPro_C_ParamSet = 834,
NID_id_GostR3410_94_CryptoPro_D_ParamSet = 835,
NID_id_GostR3410_94_CryptoPro_XchA_ParamSet = 836,
NID_id_GostR3410_94_CryptoPro_XchB_ParamSet = 837,
NID_id_GostR3410_94_CryptoPro_XchC_ParamSet = 838,
NID_id_GostR3410_94_TestParamSet = 831,
NID_id_GostR3410_94DH = 818,
NID_id_GostR3411_94 = 809,
NID_id_GostR3411_94_CryptoProParamSet = 822,
NID_id_GostR3411_94_prf = 816,
NID_id_GostR3411_94_TestParamSet = 821,
NID_id_GostR3411_94_with_GostR3410_2001 = 807,
NID_id_GostR3411_94_with_GostR3410_2001_cc = 853,
NID_id_GostR3411_94_with_GostR3410_94 = 808,
NID_id_GostR3411_94_with_GostR3410_94_cc = 852,
NID_id_hex_multipart_message = 508,
NID_id_hex_partial_message = 507,
NID_id_HMACGostR3411_94 = 810,
NID_id_it = 260,
NID_id_it_caKeyUpdateInfo = 302,
NID_id_it_caProtEncCert = 298,
NID_id_it_confirmWaitTime = 311,
NID_id_it_currentCRL = 303,
NID_id_it_encKeyPairTypes = 300,
NID_id_it_implicitConfirm = 310,
NID_id_it_keyPairParamRep = 308,
NID_id_it_keyPairParamReq = 307,
NID_id_it_origPKIMessage = 312,
NID_id_it_preferredSymmAlg = 301,
NID_id_it_revPassphrase = 309,
NID_id_it_signKeyPairTypes = 299,
NID_id_it_subscriptionRequest = 305,
NID_id_it_subscriptionResponse = 306,
NID_id_it_suppLangTags = 784,
NID_id_it_unsupportedOIDs = 304,
NID_id_kp = 128,
NID_id_mod_attribute_cert = 280,
NID_id_mod_cmc = 274,
NID_id_mod_cmp = 277,
NID_id_mod_cmp2000 = 284,
NID_id_mod_crmf = 273,
NID_id_mod_dvcs = 283,
NID_id_mod_kea_profile_88 = 275,
NID_id_mod_kea_profile_93 = 276,
NID_id_mod_ocsp = 282,
NID_id_mod_qualified_cert_88 = 278,
NID_id_mod_qualified_cert_93 = 279,
NID_id_mod_timestamp_protocol = 281,
NID_id_on = 264,
NID_id_on_permanentIdentifier = 858,
NID_id_on_personalData = 347,
NID_id_PasswordBasedMAC = 782,
NID_id_pbkdf2 = 69,
NID_id_pda = 265,
NID_id_pda_countryOfCitizenship = 352,
NID_id_pda_countryOfResidence = 353,
NID_id_pda_dateOfBirth = 348,
NID_id_pda_gender = 351,
NID_id_pda_placeOfBirth = 349,
NID_id_pe = 175,
NID_id_pkip = 261,
NID_id_pkix = 127,
NID_id_pkix_mod = 258,
NID_id_pkix_OCSP_acceptableResponses = 368,
NID_id_pkix_OCSP_archiveCutoff = 370,
NID_id_pkix_OCSP_basic = 365,
NID_id_pkix_OCSP_CrlID = 367,
NID_id_pkix_OCSP_extendedStatus = 372,
NID_id_pkix_OCSP_noCheck = 369,
NID_id_pkix_OCSP_Nonce = 366,
NID_id_pkix_OCSP_path = 374,
NID_id_pkix_OCSP_serviceLocator = 371,
NID_id_pkix_OCSP_trustRoot = 375,
NID_id_pkix_OCSP_valid = 373,
NID_id_pkix1_explicit_88 = 269,
NID_id_pkix1_explicit_93 = 271,
NID_id_pkix1_implicit_88 = 270,
NID_id_pkix1_implicit_93 = 272,
NID_id_ppl = 662,
NID_id_ppl_anyLanguage = 664,
NID_id_ppl_inheritAll = 665,
NID_id_qcs = 267,
NID_id_qcs_pkixQCSyntax_v1 = 359,
NID_id_qt = 259,
NID_id_qt_cps = 164,
NID_id_qt_unotice = 165,
NID_id_regCtrl = 313,
NID_id_regCtrl_authenticator = 316,
NID_id_regCtrl_oldCertID = 319,
NID_id_regCtrl_pkiArchiveOptions = 318,
NID_id_regCtrl_pkiPublicationInfo = 317,
NID_id_regCtrl_protocolEncrKey = 320,
NID_id_regCtrl_regToken = 315,
NID_id_regInfo = 314,
NID_id_regInfo_certReq = 322,
NID_id_regInfo_utf8Pairs = 321,
NID_id_set = 512,
NID_id_smime_aa = 191,
NID_id_smime_aa_contentHint = 215,
NID_id_smime_aa_contentIdentifier = 218,
NID_id_smime_aa_contentReference = 221,
NID_id_smime_aa_dvcs_dvc = 240,
NID_id_smime_aa_encapContentType = 217,
NID_id_smime_aa_encrypKeyPref = 222,
NID_id_smime_aa_equivalentLabels = 220,
NID_id_smime_aa_ets_archiveTimeStamp = 238,
NID_id_smime_aa_ets_certCRLTimestamp = 237,
NID_id_smime_aa_ets_CertificateRefs = 232,
NID_id_smime_aa_ets_certValues = 234,
NID_id_smime_aa_ets_commitmentType = 227,
NID_id_smime_aa_ets_contentTimestamp = 231,
NID_id_smime_aa_ets_escTimeStamp = 236,
NID_id_smime_aa_ets_otherSigCert = 230,
NID_id_smime_aa_ets_RevocationRefs = 233,
NID_id_smime_aa_ets_revocationValues = 235,
NID_id_smime_aa_ets_signerAttr = 229,
NID_id_smime_aa_ets_signerLocation = 228,
NID_id_smime_aa_ets_sigPolicyId = 226,
NID_id_smime_aa_macValue = 219,
NID_id_smime_aa_mlExpandHistory = 214,
NID_id_smime_aa_msgSigDigest = 216,
NID_id_smime_aa_receiptRequest = 212,
NID_id_smime_aa_securityLabel = 213,
NID_id_smime_aa_signatureType = 239,
NID_id_smime_aa_signingCertificate = 223,
NID_id_smime_aa_smimeEncryptCerts = 224,
NID_id_smime_aa_timeStampToken = 225,
NID_id_smime_alg = 192,
NID_id_smime_alg_3DESwrap = 243,
NID_id_smime_alg_CMS3DESwrap = 246,
NID_id_smime_alg_CMSRC2wrap = 247,
NID_id_smime_alg_ESDH = 245,
NID_id_smime_alg_ESDHwith3DES = 241,
NID_id_smime_alg_ESDHwithRC2 = 242,
NID_id_smime_alg_RC2wrap = 244,
NID_id_smime_cd = 193,
NID_id_smime_cd_ldap = 248,
NID_id_smime_ct = 190,
NID_id_smime_ct_authData = 205,
NID_id_smime_ct_compressedData = 786,
NID_id_smime_ct_contentInfo = 209,
NID_id_smime_ct_DVCSRequestData = 210,
NID_id_smime_ct_DVCSResponseData = 211,
NID_id_smime_ct_publishCert = 206,
NID_id_smime_ct_receipt = 204,
NID_id_smime_ct_TDTInfo = 208,
NID_id_smime_ct_TSTInfo = 207,
NID_id_smime_cti = 195,
NID_id_smime_cti_ets_proofOfApproval = 255,
NID_id_smime_cti_ets_proofOfCreation = 256,
NID_id_smime_cti_ets_proofOfDelivery = 253,
NID_id_smime_cti_ets_proofOfOrigin = 251,
NID_id_smime_cti_ets_proofOfReceipt = 252,
NID_id_smime_cti_ets_proofOfSender = 254,
NID_id_smime_mod = 189,
NID_id_smime_mod_cms = 196,
NID_id_smime_mod_ess = 197,
NID_id_smime_mod_ets_eSignature_88 = 200,
NID_id_smime_mod_ets_eSignature_97 = 201,
NID_id_smime_mod_ets_eSigPolicy_88 = 202,
NID_id_smime_mod_ets_eSigPolicy_97 = 203,
NID_id_smime_mod_msg_v3 = 199,
NID_id_smime_mod_oid = 198,
NID_id_smime_spq = 194,
NID_id_smime_spq_ets_sqt_unotice = 250,
NID_id_smime_spq_ets_sqt_uri = 249,
NID_idea_cbc = 34,
NID_idea_cfb64 = 35,
NID_idea_ecb = 36,
NID_idea_ofb64 = 46,
NID_identified_organization = 676,
NID_Independent = 667,
NID_info = 461,
NID_info_access = 177,
NID_inhibit_any_policy = 748,
NID_initials = 101,
NID_international_organizations = 647,
NID_internationaliSDNNumber = 869,
NID_invalidity_date = 142,
NID_ipsec3 = 749,
NID_ipsec4 = 750,
NID_ipsecEndSystem = 294,
NID_ipsecTunnel = 295,
NID_ipsecUser = 296,
NID_iso = 181,
NID_ISO_US = 183,
NID_issuer_alt_name = 86,
NID_issuing_distribution_point = 770,
NID_itu_t = 645,
NID_janetMailbox = 492,
NID_joint_iso_ccitt = 393,
NID_joint_iso_itu_t = 646,
NID_jurisdictionCountryName = 957,
NID_jurisdictionLocalityName = 955,
NID_jurisdictionStateOrProvinceName = 956,
NID_key_usage = 83,
NID_keyBag = 150,
NID_kisa = 773,
NID_lastModifiedBy = 477,
NID_lastModifiedTime = 476,
NID_localityName = 15,
NID_localKeyID = 157,
NID_LocalKeySet = 856,
NID_Mail = 388,
NID_mailPreferenceOption = 493,
NID_Management = 383,
NID_manager = 467,
NID_md2 = 3,
NID_md2WithRSAEncryption = 7,
NID_md4 = 257,
NID_md4WithRSAEncryption = 396,
NID_md5 = 4,
NID_md5_sha1 = 114,
NID_md5WithRSA = 104,
NID_md5WithRSAEncryption = 8,
NID_mdc2 = 95,
NID_mdc2WithRSA = 96,
NID_member = 875,
NID_member_body = 182,
NID_mgf1 = 911,
NID_mime_mhs = 504,
NID_mime_mhs_bodies = 506,
NID_mime_mhs_headings = 505,
NID_mobileTelephoneNumber = 488,
NID_ms_code_com = 135,
NID_ms_code_ind = 134,
NID_ms_csp_name = 417,
NID_ms_ctl_sign = 136,
NID_ms_efs = 138,
NID_ms_ext_req = 171,
NID_ms_sgc = 137,
NID_ms_smartcard_login = 648,
NID_ms_upn = 649,
NID_mXRecord = 480,
NID_name = 173,
NID_name_constraints = 666,
NID_netscape = 57,
NID_netscape_base_url = 72,
NID_netscape_ca_policy_url = 76,
NID_netscape_ca_revocation_url = 74,
NID_netscape_cert_extension = 58,
NID_netscape_cert_sequence = 79,
NID_netscape_cert_type = 71,
NID_netscape_comment = 78,
NID_netscape_data_type = 59,
NID_netscape_renewal_url = 75,
NID_netscape_revocation_url = 73,
NID_netscape_ssl_server_name = 77,
NID_no_rev_avail = 403,
NID_ns_sgc = 139,
NID_nSRecord = 481,
NID_OCSP_sign = 180,
NID_org = 379,
NID_organizationalStatus = 491,
NID_organizationalUnitName = 18,
NID_organizationName = 17,
NID_otherMailbox = 475,
NID_owner = 876,
NID_pagerTelephoneNumber = 489,
NID_pbe_WithSHA1And128BitRC2_CBC = 148,
NID_pbe_WithSHA1And128BitRC4 = 144,
NID_pbe_WithSHA1And2_Key_TripleDES_CBC = 147,
NID_pbe_WithSHA1And3_Key_TripleDES_CBC = 146,
NID_pbe_WithSHA1And40BitRC2_CBC = 149,
NID_pbe_WithSHA1And40BitRC4 = 145,
NID_pbes2 = 161,
NID_pbeWithMD2AndDES_CBC = 9,
NID_pbeWithMD2AndRC2_CBC = 168,
NID_pbeWithMD5AndCast5_CBC = 112,
NID_pbeWithMD5AndDES_CBC = 10,
NID_pbeWithMD5AndRC2_CBC = 169,
NID_pbeWithSHA1AndDES_CBC = 170,
NID_pbeWithSHA1AndRC2_CBC = 68,
NID_pbmac1 = 162,
NID_personalSignature = 499,
NID_personalTitle = 487,
NID_photo = 464,
NID_physicalDeliveryOfficeName = 863,
NID_pilot = 437,
NID_pilotAttributeSyntax = 439,
NID_pilotAttributeType = 438,
NID_pilotAttributeType27 = 479,
NID_pilotDSA = 456,
NID_pilotGroups = 441,
NID_pilotObject = 444,
NID_pilotObjectClass = 440,
NID_pilotOrganization = 455,
NID_pilotPerson = 445,
NID_pkcs = 2,
NID_pkcs1 = 186,
NID_pkcs3 = 27,
NID_pkcs5 = 187,
NID_pkcs7 = 20,
NID_pkcs7_data = 21,
NID_pkcs7_digest = 25,
NID_pkcs7_encrypted = 26,
NID_pkcs7_enveloped = 23,
NID_pkcs7_signed = 22,
NID_pkcs7_signedAndEnveloped = 24,
NID_pkcs8ShroudedKeyBag = 151,
NID_pkcs9 = 47,
NID_pkcs9_challengePassword = 54,
NID_pkcs9_contentType = 50,
NID_pkcs9_countersignature = 53,
NID_pkcs9_emailAddress = 48,
NID_pkcs9_extCertAttributes = 56,
NID_pkcs9_messageDigest = 51,
NID_pkcs9_signingTime = 52,
NID_pkcs9_unstructuredAddress = 55,
NID_pkcs9_unstructuredName = 49,
NID_policy_constraints = 401,
NID_policy_mappings = 747,
NID_postalAddress = 861,
NID_postalCode = 661,
NID_postOfficeBox = 862,
NID_preferredDeliveryMethod = 872,
NID_presentationAddress = 873,
NID_Private = 385,
NID_private_key_usage_period = 84,
NID_protocolInformation = 886,
NID_proxyCertInfo = 663,
NID_pseudonym = 510,
NID_pSpecified = 935,
NID_pss = 435,
NID_qcStatements = 286,
NID_qualityLabelledData = 457,
NID_rc2_40_cbc = 98,
NID_rc2_64_cbc = 166,
NID_rc2_cbc = 37,
NID_rc2_cfb64 = 39,
NID_rc2_ecb = 38,
NID_rc2_ofb64 = 40,
NID_rc4 = 5,
NID_rc4_40 = 97,
NID_rc4_hmac_md5 = 915,
NID_rc5_cbc = 120,
NID_rc5_cfb64 = 122,
NID_rc5_ecb = 121,
NID_rc5_ofb64 = 123,
NID_registeredAddress = 870,
NID_rFC822localPart = 450,
NID_rfc822Mailbox = 460,
NID_ripemd160 = 117,
NID_ripemd160WithRSA = 119,
NID_rle_compression = 124,
NID_role = 400,
NID_roleOccupant = 877,
NID_room = 448,
NID_roomNumber = 463,
NID_rsa = 19,
NID_rsadsi = 1,
NID_rsaEncryption = 6,
NID_rsaesOaep = 919,
NID_rsaOAEPEncryptionSET = 644,
NID_rsaSignature = 377,
NID_rsassaPss = 912,
NID_safeContentsBag = 155,
NID_sbgp_autonomousSysNum = 291,
NID_sbgp_ipAddrBlock = 290,
NID_sbgp_routerIdentifier = 292,
NID_sdsiCertificate = 159,
NID_searchGuide = 859,
NID_secp112r1 = 704,
NID_secp112r2 = 705,
NID_secp128r1 = 706,
NID_secp128r2 = 707,
NID_secp160k1 = 708,
NID_secp160r1 = 709,
NID_secp160r2 = 710,
NID_secp192k1 = 711,
NID_secp224k1 = 712,
NID_secp224r1 = 713,
NID_secp256k1 = 714,
NID_secp384r1 = 715,
NID_secp521r1 = 716,
NID_secretary = 474,
NID_secretBag = 154,
NID_sect113r1 = 717,
NID_sect113r2 = 718,
NID_sect131r1 = 719,
NID_sect131r2 = 720,
NID_sect163k1 = 721,
NID_sect163r1 = 722,
NID_sect163r2 = 723,
NID_sect193r1 = 724,
NID_sect193r2 = 725,
NID_sect233k1 = 726,
NID_sect233r1 = 727,
NID_sect239k1 = 728,
NID_sect283k1 = 729,
NID_sect283r1 = 730,
NID_sect409k1 = 731,
NID_sect409r1 = 732,
NID_sect571k1 = 733,
NID_sect571r1 = 734,
NID_Security = 386,
NID_seeAlso = 878,
NID_seed_cbc = 777,
NID_seed_cfb128 = 779,
NID_seed_ecb = 776,
NID_seed_ofb128 = 778,
NID_selected_attribute_types = 394,
NID_serialNumber = 105,
NID_server_auth = 129,
NID_set_addPolicy = 625,
NID_set_attr = 515,
NID_set_brand = 518,
NID_set_brand_AmericanExpress = 638,
NID_set_brand_Diners = 637,
NID_set_brand_IATA_ATA = 636,
NID_set_brand_JCB = 639,
NID_set_brand_MasterCard = 641,
NID_set_brand_Novus = 642,
NID_set_brand_Visa = 640,
NID_set_certExt = 517,
NID_set_ctype = 513,
NID_set_msgExt = 514,
NID_set_policy = 516,
NID_set_policy_root = 607,
NID_set_rootKeyThumb = 624,
NID_setAttr_Cert = 620,
NID_setAttr_GenCryptgrm = 631,
NID_setAttr_IssCap = 623,
NID_setAttr_IssCap_CVM = 628,
NID_setAttr_IssCap_Sig = 630,
NID_setAttr_IssCap_T2 = 629,
NID_setAttr_PGWYcap = 621,
NID_setAttr_SecDevSig = 635,
NID_setAttr_T2cleartxt = 633,
NID_setAttr_T2Enc = 632,
NID_setAttr_Token_B0Prime = 627,
NID_setAttr_Token_EMV = 626,
NID_setAttr_TokenType = 622,
NID_setAttr_TokICCsig = 634,
NID_setCext_cCertRequired = 611,
NID_setCext_certType = 609,
NID_setCext_hashedRoot = 608,
NID_setCext_IssuerCapabilities = 619,
NID_setCext_merchData = 610,
NID_setCext_PGWYcapabilities = 615,
NID_setCext_setExt = 613,
NID_setCext_setQualf = 614,
NID_setCext_TokenIdentifier = 616,
NID_setCext_TokenType = 618,
NID_setCext_Track2Data = 617,
NID_setCext_tunneling = 612,
NID_setct_AcqCardCodeMsg = 540,
NID_setct_AcqCardCodeMsgTBE = 576,
NID_setct_AuthReqTBE = 570,
NID_setct_AuthReqTBS = 534,
NID_setct_AuthResBaggage = 527,
NID_setct_AuthResTBE = 571,
NID_setct_AuthResTBEX = 572,
NID_setct_AuthResTBS = 535,
NID_setct_AuthResTBSX = 536,
NID_setct_AuthRevReqBaggage = 528,
NID_setct_AuthRevReqTBE = 577,
NID_setct_AuthRevReqTBS = 541,
NID_setct_AuthRevResBaggage = 529,
NID_setct_AuthRevResData = 542,
NID_setct_AuthRevResTBE = 578,
NID_setct_AuthRevResTBEB = 579,
NID_setct_AuthRevResTBS = 543,
NID_setct_AuthTokenTBE = 573,
NID_setct_AuthTokenTBS = 537,
NID_setct_BatchAdminReqData = 558,
NID_setct_BatchAdminReqTBE = 592,
NID_setct_BatchAdminResData = 559,
NID_setct_BatchAdminResTBE = 593,
NID_setct_BCIDistributionTBS = 600,
NID_setct_CapReqTBE = 580,
NID_setct_CapReqTBEX = 581,
NID_setct_CapReqTBS = 544,
NID_setct_CapReqTBSX = 545,
NID_setct_CapResData = 546,
NID_setct_CapResTBE = 582,
NID_setct_CapRevReqTBE = 583,
NID_setct_CapRevReqTBEX = 584,
NID_setct_CapRevReqTBS = 547,
NID_setct_CapRevReqTBSX = 548,
NID_setct_CapRevResData = 549,
NID_setct_CapRevResTBE = 585,
NID_setct_CapTokenData = 538,
NID_setct_CapTokenSeq = 530,
NID_setct_CapTokenTBE = 574,
NID_setct_CapTokenTBEX = 575,
NID_setct_CapTokenTBS = 539,
NID_setct_CardCInitResTBS = 560,
NID_setct_CertInqReqTBS = 566,
NID_setct_CertReqData = 563,
NID_setct_CertReqTBE = 595,
NID_setct_CertReqTBEX = 596,
NID_setct_CertReqTBS = 564,
NID_setct_CertResData = 565,
NID_setct_CertResTBE = 597,
NID_setct_CredReqTBE = 586,
NID_setct_CredReqTBEX = 587,
NID_setct_CredReqTBS = 550,
NID_setct_CredReqTBSX = 551,
NID_setct_CredResData = 552,
NID_setct_CredResTBE = 588,
NID_setct_CredRevReqTBE = 589,
NID_setct_CredRevReqTBEX = 590,
NID_setct_CredRevReqTBS = 553,
NID_setct_CredRevReqTBSX = 554,
NID_setct_CredRevResData = 555,
NID_setct_CredRevResTBE = 591,
NID_setct_CRLNotificationResTBS = 599,
NID_setct_CRLNotificationTBS = 598,
NID_setct_ErrorTBS = 567,
NID_setct_HODInput = 526,
NID_setct_MeAqCInitResTBS = 561,
NID_setct_OIData = 522,
NID_setct_PANData = 519,
NID_setct_PANOnly = 521,
NID_setct_PANToken = 520,
NID_setct_PCertReqData = 556,
NID_setct_PCertResTBS = 557,
NID_setct_PI = 523,
NID_setct_PI_TBS = 532,
NID_setct_PIData = 524,
NID_setct_PIDataUnsigned = 525,
NID_setct_PIDualSignedTBE = 568,
NID_setct_PInitResData = 531,
NID_setct_PIUnsignedTBE = 569,
NID_setct_PResData = 533,
NID_setct_RegFormReqTBE = 594,
NID_setct_RegFormResTBS = 562,
NID_setext_cv = 606,
NID_setext_genCrypt = 601,
NID_setext_miAuth = 602,
NID_setext_pinAny = 604,
NID_setext_pinSecure = 603,
NID_setext_track2 = 605,
NID_sha = 41,
NID_sha1 = 64,
NID_sha1WithRSA = 115,
NID_sha1WithRSAEncryption = 65,
NID_sha224 = 675,
NID_sha224WithRSAEncryption = 671,
NID_sha256 = 672,
NID_sha256WithRSAEncryption = 668,
NID_sha384 = 673,
NID_sha384WithRSAEncryption = 669,
NID_sha512 = 674,
NID_sha512WithRSAEncryption = 670,
NID_shaWithRSAEncryption = 42,
NID_simpleSecurityObject = 454,
NID_sinfo_access = 398,
NID_singleLevelQuality = 496,
NID_SMIME = 188,
NID_SMIMECapabilities = 167,
NID_SNMPv2 = 387,
NID_sOARecord = 482,
NID_stateOrProvinceName = 16,
NID_streetAddress = 660,
NID_subject_alt_name = 85,
NID_subject_directory_attributes = 769,
NID_subject_key_identifier = 82,
NID_subtreeMaximumQuality = 498,
NID_subtreeMinimumQuality = 497,
NID_supportedAlgorithms = 890,
NID_supportedApplicationContext = 874,
NID_surname = 100,
NID_sxnet = 143,
NID_target_information = 402,
NID_telephoneNumber = 864,
NID_teletexTerminalIdentifier = 866,
NID_telexNumber = 865,
NID_textEncodedORAddress = 459,
NID_textNotice = 293,
NID_time_stamp = 133,
NID_title = 106,
NID_ucl = 436,
NID_undef = 0,
NID_uniqueIdentifier = 102,
NID_uniqueMember = 888,
NID_userCertificate = 880,
NID_userClass = 465,
NID_userId = 458,
NID_userPassword = 879,
NID_wap = 678,
NID_wap_wsg = 679,
NID_wap_wsg_idm_ecid_wtls1 = 735,
NID_wap_wsg_idm_ecid_wtls10 = 743,
NID_wap_wsg_idm_ecid_wtls11 = 744,
NID_wap_wsg_idm_ecid_wtls12 = 745,
NID_wap_wsg_idm_ecid_wtls3 = 736,
NID_wap_wsg_idm_ecid_wtls4 = 737,
NID_wap_wsg_idm_ecid_wtls5 = 738,
NID_wap_wsg_idm_ecid_wtls6 = 739,
NID_wap_wsg_idm_ecid_wtls7 = 740,
NID_wap_wsg_idm_ecid_wtls8 = 741,
NID_wap_wsg_idm_ecid_wtls9 = 742,
NID_whirlpool = 804,
NID_x121Address = 868,
NID_X500 = 11,
NID_X500algorithms = 378,
NID_x500UniqueIdentifier = 503,
NID_X509 = 12,
NID_x509Certificate = 158,
NID_x509Crl = 160,
NID_X9_57 = 184,
NID_X9_62_c2onb191v4 = 691,
NID_X9_62_c2onb191v5 = 692,
NID_X9_62_c2onb239v4 = 697,
NID_X9_62_c2onb239v5 = 698,
NID_X9_62_c2pnb163v1 = 684,
NID_X9_62_c2pnb163v2 = 685,
NID_X9_62_c2pnb163v3 = 686,
NID_X9_62_c2pnb176v1 = 687,
NID_X9_62_c2pnb208w1 = 693,
NID_X9_62_c2pnb272w1 = 699,
NID_X9_62_c2pnb304w1 = 700,
NID_X9_62_c2pnb368w1 = 702,
NID_X9_62_c2tnb191v1 = 688,
NID_X9_62_c2tnb191v2 = 689,
NID_X9_62_c2tnb191v3 = 690,
NID_X9_62_c2tnb239v1 = 694,
NID_X9_62_c2tnb239v2 = 695,
NID_X9_62_c2tnb239v3 = 696,
NID_X9_62_c2tnb359v1 = 701,
NID_X9_62_c2tnb431r1 = 703,
NID_X9_62_characteristic_two_field = 407,
NID_X9_62_id_characteristic_two_basis = 680,
NID_X9_62_id_ecPublicKey = 408,
NID_X9_62_onBasis = 681,
NID_X9_62_ppBasis = 683,
NID_X9_62_prime_field = 406,
NID_X9_62_prime192v1 = 409,
NID_X9_62_prime192v2 = 410,
NID_X9_62_prime192v3 = 411,
NID_X9_62_prime239v1 = 412,
NID_X9_62_prime239v2 = 413,
NID_X9_62_prime239v3 = 414,
NID_X9_62_prime256v1 = 415,
NID_X9_62_tpBasis = 682,
NID_X9cm = 185,
NID_zlib_compression = 125,
};
