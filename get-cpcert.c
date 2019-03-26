// get-cpcert.c : utility to read crypto pro 4 certificate
// and write it into pem form (GOST-2012)

#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#include <gost_lcl.h>
#include <gosthash2012.h>

//#define CFG_DEBUG
#define ERROR(msg) fprintf(stderr,"ERROR: %s\n",msg)
#define DIR_SEP '/'

// packet ----------------------------------------------------------------------
typedef struct {
  unsigned char* data;
  int size,limit,pos,ovf;
} packet_t;
void pkt_init(packet_t *p,unsigned char* buf,int buf_size) {
  p->data=buf;
  p->size=0;
  p->limit=buf_size;
  p->pos=0;
  p->ovf=0;
}
void pkt_clone(packet_t* dst,packet_t *src) {
  *dst=*src;
}
int pkt_end(packet_t *p) { return p->pos>=p->size; }
int pkt_left(packet_t *p) { return p->size-p->pos; }
int pkt_get(packet_t *p) { return p->pos<p->size ? p->data[p->pos++] : 0; }
int pkt_put(packet_t *p,int v) {
  if (p->pos>=p->size) {
    if (p->size>=p->limit) return p->ovf=1;
    p->size++;
  }
  if (p->pos>=p->size) p->ovf=1; else p->data[p->pos++]=v;
  return p->ovf;
}
int pkt_skip(packet_t *p,int size) {
  if (size>0) {
    p->pos+=size;
    if (p->pos>p->size) { p->ovf=1; p->pos=p->size; }
  }
  return p->ovf;
}
void pkt_sub(packet_t* dst,packet_t *src,int size) {
  *dst=*src;
  dst->size=src->pos+size;
  if (dst->size>src->size) { dst->size=src->size; dst->ovf=1; }
}
int pkt_gets(packet_t* p,unsigned char* data,int size) {
  int i;
  for(i=0;i<size;++i) data[i]=pkt_get(p);
  return p->ovf;
}
int pkt_readfile(packet_t* p,const char* name) {
  FILE *f;
  f=fopen(name,"rb"); if (!f) return 2;
  fseek(f,0,SEEK_END);
  if (ftell(f)>p->limit) p->ovf=1; 
  fseek(f,0,SEEK_SET);
  p->size=fread(p->data,1,p->limit,f);
  p->pos=0;
  fclose(f);
  return p->ovf;
}
// asn1 ------------------------------------------------------------------------
int asn1_len(packet_t *p) {
  int x,r;
  x=pkt_get(p);
  if (x<128) return x;
  x&=127;
  for(r=0;x>0;--x) {
    r<<=8;
    r|=pkt_get(p);
  }
  return r;
}
int asn1_num(packet_t *p) {
  int x,r=0;
  do { 
    x=pkt_get(p);
    r=(r<<7)|(x&127);
  } while(x&128);
  return r;
}
// asn1 parser -----------------------------------------------------------------
typedef struct {
  int level,index;
  int tag,tag_composite,tag_pos,tag_class,tag_type,tag_len;
  packet_t body[1];
  struct asn1_parser_tag_t *parent;
} asn1_parser_tag_t;

typedef struct {
  void *tag_ctx;
  int (*tag)(void* ctx,asn1_parser_tag_t* tag);
} asn1_parser_cfg_t;

typedef struct {
  packet_t *packet;
  asn1_parser_cfg_t *cfg;
} asn1_parser_t;

static int asn1_parse_tag(packet_t *p,
  asn1_parser_cfg_t *cfg,
  asn1_parser_tag_t *parent)
{
  enum {
    ASN1_MASK_MULTI=0x20, ASN1_MASK_TYPE=0x1F,
    ASN1_MASK_CLASS=0xC0, ASN1_SHIFT_CLASS=6
  };
  asn1_parser_tag_t tag[1];int rc;

  tag->index=0;
  tag->level=parent ? parent->level+1 : 0;
  while(!pkt_end(p)) {
    tag->tag_pos=p->pos;
    tag->tag=pkt_get(p);
    tag->tag_type=tag->tag&ASN1_MASK_TYPE;
    if (tag->tag_type==ASN1_MASK_TYPE) tag->tag_type=asn1_num(p);
    tag->tag_class=(tag->tag&ASN1_MASK_CLASS)>>ASN1_SHIFT_CLASS;
    tag->tag_len=asn1_len(p);
    if (tag->tag_len==0) { ERROR("streams are unsupported"); return 1; } 
    pkt_sub(tag->body,p,tag->tag_len);
    tag->tag_composite=tag->tag&ASN1_MASK_MULTI;
    rc=cfg->tag(cfg->tag_ctx,tag); if (rc) return rc;
    if (tag->tag_composite) {
      pkt_sub(tag->body,p,tag->tag_len);
      rc=asn1_parse_tag(tag->body,cfg,tag); if (rc) return rc;
    }
    pkt_skip(p,tag->tag_len);
    tag->index++;
  }
  return 0;
}
int asn1_parse(packet_t *p,asn1_parser_cfg_t *cfg) { 
  return asn1_parse_tag(p,cfg,0); 
}

// my_data ---------------------------------------------------------------------
enum {
  MY_DATA_MASK=1,
  MY_DATA_PRIM=2,
  MY_DATA_PUB8=4,
  MY_DATA_SALT=8,
  MY_DATA_ALG=16,
  MY_DATA_CERT=32,
  MY_DATA_PRIV=64
};
enum {
  ALG_UNKNOWN=0,
  ALG_GOST2001=1,
  ALG_GOST2012_256=2,
  ALG_MAX
};
typedef struct {
  int alg, parts, cert_len;
  unsigned char mask[32], prim[32], pub8[8], salt[12], priv[32], *cert;
  const char *password;
  void *trace_ctx; void (*trace)(void *ctx,const char* fmt,...);
} my_data_t;

static int wr_num(packet_t *res,unsigned n) {
  if (n>=10) wr_num(res,n/10);
  return pkt_put(res,'0'+n%10);
}
static int wr_oid(packet_t *res,packet_t* p) {
  int x;
  if (pkt_end(p)) return;
  x=pkt_get(p);
  wr_num(res,x/40);
  pkt_put(res,'.');
  wr_num(res,x%40);
  while(!pkt_end(p)) {
    x=asn1_num(p);
    pkt_put(res,'.');
    wr_num(res,x);
  }
  return res->ovf; 
}
static int sprint_oid(char* buf,int buf_size,packet_t *oid) {
  packet_t clone[1],text[1];
  pkt_init(text,buf,buf_size);
  pkt_clone(clone,oid);
  wr_oid(text,clone);
  return pkt_put(text,0);
}
#ifdef CFG_DEBUG
static void trace_body(packet_t *src,my_data_t *data) {
  enum { w=16 };
  int a,i,n; unsigned char line[w];
  packet_t p[1];
  if (!data->trace) return;
  pkt_clone(p,src);
  for(a=0;!pkt_end(p);a+=w) {
    for(n=0;!pkt_end(p) && n<w;++n) line[n]=pkt_get(p);
    data->trace(data->trace_ctx,"\n\t\t%04X:",a);
    for(i=0;i<n;i++) data->trace(data->trace_ctx," %02X",line[i]);
    for(;i<w;++i) data->trace(data->trace_ctx,"   ");
    data->trace(data->trace_ctx," |");
    for(i=0;i<n;i++) data->trace(data->trace_ctx,"%c",
      line[i]>=32 && line[i]<128 ? line[i] : '.');
    for(;i<w;++i) data->trace(data->trace_ctx," ");
    data->trace(data->trace_ctx,"|");
  break;
  }
}
static int dump_handler(void* ctx,asn1_parser_tag_t *tag) {
  my_data_t *data;
  data=(my_data_t*)ctx;
  data->trace(data->trace_ctx,"%04d\t",tag->tag_pos);
  {int i;for(i=0;i<tag->level;++i) data->trace(data->trace_ctx,"  ");}
  data->trace(data->trace_ctx,"L%d class=%d type=%d size=%d ",tag->level,
    tag->tag_class,tag->tag_type,pkt_left(tag->body));
  if (!tag->tag_composite) trace_body(tag->body,data);
  data->trace(data->trace_ctx,"\n");
  return 0;
}
#endif
static int header_handler(void* ctx,asn1_parser_tag_t *tag) {
  my_data_t *data;
  data=(my_data_t*)ctx;
  #ifdef CFG_DEBUG
  dump_handler(ctx,tag);
  #endif
  if (tag->tag_class==2) {
    if (tag->tag_type==10) {
      pkt_gets(tag->body,data->pub8,8);
      data->parts|=MY_DATA_PUB8;
    }
    if (tag->tag_type==5) {
      data->cert=tag->body->data+tag->body->pos;
      data->cert_len=pkt_left(tag->body);
      data->parts|=MY_DATA_CERT;
    }
  }
  if (tag->level==5) {
    if (tag->tag_class==0 && tag->tag_type==6) {
      enum { oid_size=32 }; char oid[oid_size];
      sprint_oid(oid,oid_size,tag->body);
      #ifdef CFG_DEBUG
      data->trace(data->trace_ctx,"OID=%s\n",oid);
      #endif
      if (strcmp(oid,"1.2.643.2.2.30.1")==0) {
        data->alg=ALG_GOST2001;
        data->parts|=MY_DATA_ALG;
        #ifdef CFG_DEBUG
        data->trace(data->trace_ctx,"GOST-2001\n");
        #endif
      }
      if (strcmp(oid,"1.2.643.7.1.1.2.2")==0) {
        data->alg=ALG_GOST2012_256;
        data->parts|=MY_DATA_ALG;
        #ifdef CFG_DEBUG
        data->trace(data->trace_ctx,"GOST-2012-256\n");
        #endif
      }
    }
  }
  return 0;
}
static int primary_handler(void* ctx,asn1_parser_tag_t *tag) {
  my_data_t *data;
  data=(my_data_t*)ctx;
  #ifdef CFG_DEBUG
  dump_handler(ctx,tag);
  #endif
  if (tag->tag==4 && tag->index==0) {
    pkt_gets(tag->body,data->prim,32);
    data->parts|=MY_DATA_PRIM;
  }
  return 0;
}
static int masks_handler(void* ctx,asn1_parser_tag_t *tag) {
  my_data_t *data;
  data=(my_data_t*)ctx;
  #ifdef CFG_DEBUG
  dump_handler(ctx,tag);
  #endif
  if (tag->tag==4) {
    if (tag->index==0) {
      pkt_gets(tag->body,data->mask,32);
      data->parts|=MY_DATA_MASK;;
    }
    if (tag->index==1) {
      pkt_gets(tag->body,data->salt,12);
      data->parts|=MY_DATA_SALT;
    }
  }
  return 0;
}
static void xor365C(char *x36, char *x5C, const char *s,int n) {
  int i; for(i=0;i<n;i++) { x36[i]=s[i]^0x36; x5C[i]=s[i]^0x5C; }
}
enum { salt0_size=32 };
static const char *salt0="DENEFH028.760246785.IUEFHWUIO.EF";
static int make2012_pwd_key(char *result_key,
  const char *salt, int salt_len,
  const char *pass)
{
  enum { HASH_SIZE=32, SIZE2=64, HASH_BITS=256 };
  enum { pincode_lim=4*80 }; char pincode4[pincode_lim];
  int result,i,n,pin_len;
  char current[SIZE2], x36[SIZE2], x5C[SIZE2], salt_pass[HASH_SIZE];
  gost2012_hash_ctx ctx[1];

  memset(pincode4,0,sizeof(pincode4));
  pin_len=strlen(pass); if (pin_len>pincode_lim) return 1;
  for(i=0;i<pin_len;i++) pincode4[i*4]=pass[i];

  init_gost2012_hash_ctx(ctx,HASH_BITS);
  gost2012_hash_block(ctx, salt, salt_len);
  gost2012_hash_block(ctx, pincode4, pin_len*4);
  gost2012_finish_hash(ctx, salt_pass);

  memset(current,0,SIZE2);
  memcpy(current,salt0,salt0_size);
  n=pin_len?2000:2;
  for(i=0;i<n; i++) {
    xor365C(x36,x5C,current,SIZE2);
    init_gost2012_hash_ctx(ctx,HASH_BITS);
    gost2012_hash_block(ctx,x36,SIZE2);
    gost2012_hash_block(ctx,salt_pass,HASH_SIZE);
    gost2012_hash_block(ctx,x5C,SIZE2);
    gost2012_hash_block(ctx,salt_pass,HASH_SIZE);
    gost2012_finish_hash(ctx,current);
  }

  xor365C(x36,x5C,current,SIZE2);
  init_gost2012_hash_ctx(ctx,HASH_BITS);
  gost2012_hash_block(ctx,x36,HASH_SIZE);
  gost2012_hash_block(ctx,salt,salt_len);
  gost2012_hash_block(ctx,x5C,HASH_SIZE);
  gost2012_hash_block(ctx,pincode4,pin_len*4);
  gost2012_finish_hash(ctx,current);

  init_gost2012_hash_ctx(ctx,HASH_BITS);
  gost2012_hash_block(ctx,current,HASH_SIZE);
  gost2012_finish_hash(ctx,result_key);
  
  return 0;
}
static int make2001_pwd_key(char *result_key,
  const char *salt, int salt_len,
  const char *pass)
{
  enum { HASH_SIZE=32, SIZE2=HASH_SIZE };
  enum { pincode_lim=4*80 }; char pincode4[pincode_lim];
  int result,i,n,pin_len;
  char current[SIZE2], x36[SIZE2], x5C[SIZE2], salt_pass[HASH_SIZE];
  gost_hash_ctx ctx[1];

  memset(pincode4,0,sizeof(pincode4));
  pin_len=strlen(pass); if (pin_len>pincode_lim) return 1;
  for(i=0;i<pin_len;i++) pincode4[i*4]=pass[i];

  init_gost_hash_ctx(ctx, &GostR3411_94_CryptoProParamSet);

  start_hash(ctx);
  hash_block(ctx, salt, salt_len);
  hash_block(ctx, pincode4, pin_len*4);
  finish_hash(ctx, salt_pass);

  memset(current,0,SIZE2);
  memcpy(current,salt0,salt0_size);
  n=pin_len?2000:2;
  for(i=0;i<n; i++) {
    xor365C(x36,x5C,current,SIZE2);
    start_hash(ctx);
    hash_block(ctx,x36,SIZE2);
    hash_block(ctx,salt_pass,HASH_SIZE);
    hash_block(ctx,x5C,SIZE2);
    hash_block(ctx,salt_pass,HASH_SIZE);
    finish_hash(ctx,current);
  }

  xor365C(x36,x5C,current,SIZE2);
  start_hash(ctx);
  hash_block(ctx,x36,HASH_SIZE);
  hash_block(ctx,salt,salt_len);
  hash_block(ctx,x5C,HASH_SIZE);
  hash_block(ctx,pincode4,pin_len*4);
  finish_hash(ctx,current);

  start_hash(ctx);
  hash_block(ctx,current,HASH_SIZE);
  finish_hash(ctx,result_key);
  
  return 0;
}
BIGNUM* decode_primary_key(char *pwd_key,char *primary_key,BN_CTX *bn,int ec) {
  gost_ctx ctx[1]; char buf[32]; 

  gost_init(ctx,ec
	?&Gost28147_TC26ParamSetZ
	:&Gost28147_CryptoProParamSetA	
  );
  gost_key(ctx,pwd_key);
  gost_dec(ctx,primary_key,buf,4);
  BUF_reverse(buf,0,32);
  return BN_bin2bn(buf,32,BN_CTX_get(bn));
}
int gost_compute_public(EC_KEY *ec) {
    const EC_GROUP *group=0;
    EC_POINT *pub_key=0;
    const BIGNUM *priv_key=0;
    BN_CTX *ctx=0;
    int res,rc;

    group=EC_KEY_get0_group(ec);                                                if (!group) { ERROR("no ec group"); rc=1; goto err; }
    ctx=BN_CTX_new();                                                           if (!ctx) { ERROR("no bn_ctx"); rc=2; goto err; }
    priv_key=EC_KEY_get0_private_key(ec);                                       if (!priv_key) { ERROR("no pk"); rc=3; goto err; } 
    pub_key=EC_POINT_new(group);                                                if (!pub_key) { ERROR("no pub key"); rc=4; goto err; }
    res=EC_POINT_mul(group,pub_key,priv_key,0,0,ctx);                           if (!res) { ERROR("ec mul\n"); rc=5; goto err; }   
    res=EC_KEY_set_public_key(ec,pub_key);                                      if (!res) { ERROR("set pub key");rc=6; goto err; }   
    rc=0; err:
    EC_POINT_free(pub_key);
    BN_CTX_free(ctx);
    return rc;
}
BIGNUM* remove_mask_and_check_public(BIGNUM *key_with_mask, BIGNUM *mask,
  char *pub8, BN_CTX *ctx)
{
  const EC_POINT *pubkey; const EC_GROUP *group;
  BIGNUM *order, *mask_inv, *raw_secret, *x, *y;
  char buf[32], pub[32]; int res,rc;
  EC_KEY *eckey=0;

  order=BN_CTX_get(ctx); mask_inv=BN_CTX_get(ctx); 
  raw_secret=BN_CTX_get(ctx); x=BN_CTX_get(ctx); y=BN_CTX_get(ctx);

  eckey=EC_KEY_new();                                                           if (!eckey) { ERROR("ec new key"); rc=7; goto err; }
  res=fill_GOST_EC_params(eckey,NID_id_GostR3410_2001_CryptoPro_XchA_ParamSet); if (!res) { ERROR("set ec param"); rc=8; goto err; }
  group=EC_KEY_get0_group(eckey);                                               if (!group) { ERROR("no ec group"); rc=9; goto err; }
  res=EC_GROUP_get_order(group,order,ctx);                                      if (!res) { ERROR("no group order"); rc=10; goto err; }
  mask_inv=BN_mod_inverse(mask_inv,mask,order,ctx);                             if (!mask_inv) { ERROR("inverse fail"); rc=11; goto err; }
  res=BN_mod_mul(raw_secret, key_with_mask, mask_inv, order, ctx);              if (!res) { ERROR("bn mul"); rc=12; goto err; }

  res=EC_KEY_set_private_key(eckey, raw_secret);                                if (!res) { ERROR("ec set priv key"); rc=13; goto err; }
  rc=gost_compute_public(eckey);                                                if (rc) { ERROR("compute pub"); rc=14; goto err; }
  pubkey=EC_KEY_get0_public_key(eckey);                                         if (!pubkey) { ERROR("ec no pub key"); rc=15; goto err; }
  res=EC_POINT_get_affine_coordinates_GFp(group,pubkey,x,y,ctx);                if (!res) { ERROR("ec get coord"); rc=16; goto err; }

  store_bignum(x,buf,sizeof(buf));
  BUF_reverse(pub,buf,sizeof(buf));
  rc=memcmp(pub,pub8,8) ? 17 : 0;
  err:
  if (eckey) EC_KEY_free(eckey);
  return rc?0:raw_secret;
}
static int extract_priv(my_data_t *data) {
  char pwd_key[32], buf[32]; int rc, ec=0;
  BN_CTX *ctx; BIGNUM *key_with_mask, *mask, *raw_key;

  ctx=BN_CTX_new(); BN_CTX_start(ctx);
  mask=BN_CTX_get(ctx);

  if (data->alg==ALG_GOST2001) {
    rc=make2001_pwd_key(pwd_key, data->salt,12, data->password); ec=0;          if (rc) { ERROR("pass"); rc=18; goto err; }
  } else
  if (data->alg==ALG_GOST2012_256) {
    rc=make2012_pwd_key(pwd_key, data->salt,12, data->password); ec=1;          if (rc) { ERROR("pass"); rc=19; goto err; }
  } else
  { ERROR("unsupported alg"); rc=1; goto err; }
  key_with_mask=decode_primary_key(pwd_key,data->prim,ctx,ec);                  if (!key_with_mask) { ERROR("decode"); rc=20; goto err; }
  OPENSSL_cleanse(pwd_key,sizeof(pwd_key));
  BUF_reverse(buf,data->mask,32);
  mask=BN_bin2bn(buf,32,mask);                                                  if (!mask) { ERROR("bin2nb"); rc=21; goto err; }
  raw_key=remove_mask_and_check_public(key_with_mask, mask, data->pub8, ctx);   if (!raw_key) { ERROR("invalid password"); rc=22; goto err; }
  store_bignum(raw_key, data->priv, 32);
  BN_bin2bn(pwd_key,32,raw_key);
  BUF_reverse(data->priv,0,32);
  data->parts|=MY_DATA_PRIV;
  rc=0; err:
  BN_CTX_free(ctx);
  return rc;
}
enum { apk2001_key=37, apk2001_size=69 };
static unsigned char apk2001[apk2001_size] = {
  /*00*/  0x30,67,
  /*02*/    2,1,0, // Integer(0)
  /*05*/    0x30,28,
  /*07*/      6,6, 42,0x85,3, 2,2,19,    // GOST R 34.10-2001 1.2.643.2.2.19
  /*15*/      0x30,18,
  /*17*/        6,7, 42,0x85,3, 2,2,36,0,  // id-GostR3410-2001-CryptoPro-XchA-ParamSet 1.2.643.2.2.36.0
  /*26*/        6,7, 42,0x85,3, 2,2,30,1,  // id-GostR3411-94-CryptoProParamSet         1.2.643.2.2.30.1
  /*35*/    4,32,// 2,32, // OctetString int
  /*39*/          0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  /*55*/          0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
  /*71*/
};
enum { apk2012_key=40, apk2012_size=72 };
static unsigned char apk2012[apk2012_size] = {
  /*00*/  0x30,70,
  /*02*/    2,1,0, // Integer(0)
  /*05*/    0x30,31, 
  /*07*/      6,8, 0x2A,0x85,3, 7,1,1,1,1, // GOST R 34.10-2012 with 256 bit modulus    1.2.643.7.1.1.1.1
  /*17*/      0x30,19,
  /*19*/        6,7, 42,0x85,3, 2,2,36,0,  // id-GostR3410-2001-CryptoPro-XchA-ParamSet 1.2.643.2.2.54.0
  /*28*/        6,8, 42,0x85,3, 7,1,1,2,2, // GOST R 34.11-2012 with 256 bit hash       1.2.643.7.1.1.2.2
  /*38*/    4,32, // OctetString
  /*40*/          0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  /*53*/          0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
  /*72*/
};
typedef struct { unsigned char* apk;int key,size; } apk_t;
static apk_t apk_db[ALG_MAX]={ {0,0,0},
  {apk2001,apk2001_key,apk2001_size},
  {apk2012,apk2012_key,apk2012_size}
};

static int print_cert(my_data_t *data,FILE* output) {
  BIO *bio; apk_t* apk; int rc;

  bio=BIO_new_fp(output,BIO_NOCLOSE|BIO_FP_TEXT);                               if (!bio) { ERROR("no bio"); rc=23; goto err; }
  if (data->parts & MY_DATA_CERT) {
    PEM_write_bio(bio,"CERTIFICATE","",data->cert,data->cert_len);
  }
  if (data->parts & MY_DATA_PRIV) {
    apk=&apk_db[data->alg];
    memcpy(apk->apk+apk->key,data->priv,32);
    PEM_write_bio(bio,"PRIVATE KEY","",apk->apk,apk->size);
    OPENSSL_cleanse(apk->apk+apk->key,32);
    rc=0;
  } else rc=24;
  err:
  if (bio) BIO_free(bio);
  return rc;
}

//------------------------------------------------------------------------------
static void dbg_trace(void* ctx,const char* fmt,...) {
  va_list v; va_start(v,fmt); vfprintf(stderr,fmt,v); va_end(v);
}
int get_cpcert(const char* path,const char* pass) {
  enum { buf_size=8192, buf1_size=64, buf2_size=64 };
  unsigned char buf[buf_size], buf1[buf1_size], buf2[buf2_size];
  packet_t header[1], masks[1], primary[1];
  asn1_parser_cfg_t cfg[1];
  my_data_t data[1]; int rc;
  enum { max_fn=2048 }; char fn[max_fn];
  
  memset(data,0,sizeof(*data));
  data->trace_ctx=0;
  data->trace=dbg_trace;
  cfg->tag_ctx=data;

  cfg->tag=header_handler;
  pkt_init(header,buf,buf_size);
  sprintf(fn,"%s%cheader.key",path,DIR_SEP);
  #ifdef CFG_DEBUG
  data->trace(data->trace_ctx,"[%s]\n",fn);
  #endif
  if (pkt_readfile(header,fn)) { ERROR("read header"); rc=25; goto err; }
  if (asn1_parse(header,cfg)) { ERROR("parse header"); rc=26; goto err; }

  cfg->tag=primary_handler;
  pkt_init(primary,buf,buf_size);
  sprintf(fn,"%s%cprimary.key",path,DIR_SEP);
  #ifdef CFG_DEBUG
  data->trace(data->trace_ctx,"[%s]\n",fn);
  #endif
  if (pkt_readfile(primary,fn)) { ERROR("read primary"); rc=27; goto err; }
  if (asn1_parse(primary,cfg)) { ERROR("parse primary"); rc=28; goto err; }

  cfg->tag=masks_handler;
  pkt_init(masks,buf,buf_size);
  sprintf(fn,"%s%cmasks.key",path,DIR_SEP);
  #ifdef CFG_DEBUG
  data->trace(data->trace_ctx,"[%s]\n",fn);
  #endif
  if (pkt_readfile(masks,fn)) { ERROR("read masks"); rc=29; goto err; }
  if (asn1_parse(masks,cfg)) { ERROR("parse masks"); rc=30; goto err; }

  data->password=pass;
  if (extract_priv(data)) { ERROR("unable to get private key"); rc=31; goto err; }
  if (print_cert(data,stdout)) { ERROR("print"); rc=32; goto err; }
  OPENSSL_cleanse(data->priv,32);
  rc=0; err:
  return rc;
}

//------------------------------------------------------------------------------

int main(int argc,char** argv) {
  if (argc<2) {
	fprintf(stderr,"usage: get-cpcert dir [pass]\n");
	return -1;
  }
  return get_cpcert(argv[1],argc>2 ? argv[2] : "");
}
