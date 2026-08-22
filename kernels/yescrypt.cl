/*
 * yescrypt_crack OpenCL yescrypt RW backend.
 *
 * The yescrypt algorithm follows Solar Designer's public yescrypt design and
 * reference implementation.
 *
 * Portions of the cooperative GPU SMix/PWX implementation are adapted from
 * hashcat's MIT-licensed yescrypt OpenCL implementation:
 *
 *   https://github.com/hashcat/hashcat/blob/master/OpenCL/inc_hash_yescrypt.cl
 *
 * The surrounding kernel implementation, OpenCL host integration, batching,
 * device management, and yescrypt_crack-specific runtime are part of
 * yescrypt_crack.
 *
 * See THIRD_PARTY_NOTICES.md for upstream attribution and license information.
 */

#pragma OPENCL EXTENSION cl_khr_byte_addressable_store : enable

#ifndef YC_N
#define YC_N 4096
#endif
#ifndef YC_R
#define YC_R 32
#endif

#define YC_WG_SIZE 32
#define YC_LOOP_CHUNK 2048U
#define YC_STATE_WORDS (16 * YC_R)
#define YC_STATE_BYTES (128 * YC_R)
#define YC_SCRATCH_WORDS ((YC_STATE_WORDS < 32) ? 32 : YC_STATE_WORDS)
#define YC_NLOOP ((((YC_N + 2U) / 3U) + 1U) & ~1U)
#define YC_PREHASH_N (YC_N / 64U)
#define YC_PREHASH_NEEDED ((YC_N >= 256U) && ((YC_N * YC_R) >= 0x20000U))

#define MAX_PW 256
#define MAX_R 32
#define B_STRIDE (128 * MAX_R)
#define XY_STRIDE_WORDS (32 * MAX_R)
#define S_WORDS 1536
#define S_THIRD_WORDS 512
#define PWX_SIMPLE 2
#define PWX_GATHER 4
#define PWX_ROUNDS 6
#define S_MASK 4080U

__constant uint K256[64] = {
  0x428a2f98U,0x71374491U,0xb5c0fbcfU,0xe9b5dba5U,0x3956c25bU,0x59f111f1U,0x923f82a4U,0xab1c5ed5U,
  0xd807aa98U,0x12835b01U,0x243185beU,0x550c7dc3U,0x72be5d74U,0x80deb1feU,0x9bdc06a7U,0xc19bf174U,
  0xe49b69c1U,0xefbe4786U,0x0fc19dc6U,0x240ca1ccU,0x2de92c6fU,0x4a7484aaU,0x5cb0a9dcU,0x76f988daU,
  0x983e5152U,0xa831c66dU,0xb00327c8U,0xbf597fc7U,0xc6e00bf3U,0xd5a79147U,0x06ca6351U,0x14292967U,
  0x27b70a85U,0x2e1b2138U,0x4d2c6dfcU,0x53380d13U,0x650a7354U,0x766a0abbU,0x81c2c92eU,0x92722c85U,
  0xa2bfe8a1U,0xa81a664bU,0xc24b8b70U,0xc76c51a3U,0xd192e819U,0xd6990624U,0xf40e3585U,0x106aa070U,
  0x19a4c116U,0x1e376c08U,0x2748774cU,0x34b0bcb5U,0x391c0cb3U,0x4ed8aa4aU,0x5b9cca4fU,0x682e6ff3U,
  0x748f82eeU,0x78a5636fU,0x84c87814U,0x8cc70208U,0x90befffaU,0xa4506cebU,0xbef9a3f7U,0xc67178f2U
};

typedef struct {
  uint h[8];
  ulong total;
  uchar buf[64];
  uint used;
} sha256_ctx_t;

typedef struct {
  sha256_ctx_t inner;
  sha256_ctx_t outer;
} hmac256_base_t;

inline uint rotr32(const uint x, const uint n) { return (x >> n) | (x << (32U - n)); }
inline uint load_be32_p(__private const uchar *p) {
  return ((uint)p[0] << 24) | ((uint)p[1] << 16) | ((uint)p[2] << 8) | (uint)p[3];
}
inline uint load_le32_g(__global const uchar *p) {
  return (uint)p[0] | ((uint)p[1] << 8) | ((uint)p[2] << 16) | ((uint)p[3] << 24);
}
inline void store_le32_g(__global uchar *p, const uint v) {
  p[0]=(uchar)v; p[1]=(uchar)(v>>8); p[2]=(uchar)(v>>16); p[3]=(uchar)(v>>24);
}
inline void store_be32_p(__private uchar *p, const uint v) {
  p[0]=(uchar)(v>>24); p[1]=(uchar)(v>>16); p[2]=(uchar)(v>>8); p[3]=(uchar)v;
}

inline void sha256_init(__private sha256_ctx_t *c) {
  c->h[0]=0x6a09e667U; c->h[1]=0xbb67ae85U; c->h[2]=0x3c6ef372U; c->h[3]=0xa54ff53aU;
  c->h[4]=0x510e527fU; c->h[5]=0x9b05688cU; c->h[6]=0x1f83d9abU; c->h[7]=0x5be0cd19U;
  c->total=0; c->used=0;
}

inline void sha256_transform(__private sha256_ctx_t *c, __private const uchar block[64]) {
  uint w[16];
  for (uint i=0;i<16;i++) w[i]=load_be32_p(block + 4*i);
  uint a=c->h[0], b=c->h[1], cc=c->h[2], d=c->h[3], e=c->h[4], f=c->h[5], g=c->h[6], h=c->h[7];
  for (uint i=0;i<64;i++) {
    uint wi;
    if (i < 16) {
      wi = w[i];
    } else {
      uint x=w[(i-15)&15], y=w[(i-2)&15];
      uint s0=rotr32(x,7)^rotr32(x,18)^(x>>3);
      uint s1=rotr32(y,17)^rotr32(y,19)^(y>>10);
      wi = w[i&15] = w[(i-16)&15] + s0 + w[(i-7)&15] + s1;
    }
    uint S1=rotr32(e,6)^rotr32(e,11)^rotr32(e,25);
    uint ch=(e&f)^((~e)&g);
    uint t1=h+S1+ch+K256[i]+wi;
    uint S0=rotr32(a,2)^rotr32(a,13)^rotr32(a,22);
    uint maj=(a&b)^(a&cc)^(b&cc);
    uint t2=S0+maj;
    h=g; g=f; f=e; e=d+t1; d=cc; cc=b; b=a; a=t1+t2;
  }
  c->h[0]+=a; c->h[1]+=b; c->h[2]+=cc; c->h[3]+=d;
  c->h[4]+=e; c->h[5]+=f; c->h[6]+=g; c->h[7]+=h;
}

inline void sha256_update_byte(__private sha256_ctx_t *c, const uchar x) {
  c->buf[c->used++] = x;
  c->total++;
  if (c->used == 64) { sha256_transform(c,c->buf); c->used=0; }
}
inline void sha256_update_private(__private sha256_ctx_t *c, __private const uchar *p, const uint n) {
  for (uint i=0;i<n;i++) sha256_update_byte(c,p[i]);
}
inline void sha256_update_global(__private sha256_ctx_t *c, __global const uchar *p, const uint n) {
  for (uint i=0;i<n;i++) sha256_update_byte(c,p[i]);
}
inline void sha256_final(__private sha256_ctx_t *c, __private uchar out[32]) {
  ulong bits=c->total*8UL;
  c->buf[c->used++]=0x80;
  if (c->used > 56) {
    while (c->used<64) c->buf[c->used++]=0;
    sha256_transform(c,c->buf); c->used=0;
  }
  while (c->used<56) c->buf[c->used++]=0;
  for (uint i=0;i<8;i++) c->buf[56+i]=(uchar)(bits>>(56-8*i));
  sha256_transform(c,c->buf);
  for (uint i=0;i<8;i++) store_be32_p(out+4*i,c->h[i]);
}

inline void sha256_private_msg(__private const uchar *msg, const uint len, __private uchar out[32]) {
  sha256_ctx_t c; sha256_init(&c); sha256_update_private(&c,msg,len); sha256_final(&c,out);
}
inline void sha256_global_msg(__global const uchar *msg, const uint len, __private uchar out[32]) {
  sha256_ctx_t c; sha256_init(&c); sha256_update_global(&c,msg,len); sha256_final(&c,out);
}

inline void hmac_init_private_key(__private const uchar *key, uint keylen, __private hmac256_base_t *base) {
  uchar k0[64]; for (uint i=0;i<64;i++) k0[i]=0;
  if (keylen > 64) {
    uchar kh[32]; sha256_private_msg(key,keylen,kh); for (uint i=0;i<32;i++) k0[i]=kh[i];
  } else {
    for (uint i=0;i<keylen;i++) k0[i]=key[i];
  }
  uchar pad[64];
  for (uint i=0;i<64;i++) pad[i]=k0[i]^0x36;
  sha256_init(&base->inner); sha256_update_private(&base->inner,pad,64);
  for (uint i=0;i<64;i++) pad[i]=k0[i]^0x5c;
  sha256_init(&base->outer); sha256_update_private(&base->outer,pad,64);
}

inline void hmac_init_global_key(__global const uchar *key, uint keylen, __private hmac256_base_t *base) {
  uchar k0[64]; for (uint i=0;i<64;i++) k0[i]=0;
  if (keylen > 64) {
    uchar kh[32]; sha256_global_msg(key,keylen,kh); for (uint i=0;i<32;i++) k0[i]=kh[i];
  } else {
    for (uint i=0;i<keylen;i++) k0[i]=key[i];
  }
  uchar pad[64];
  for (uint i=0;i<64;i++) pad[i]=k0[i]^0x36;
  sha256_init(&base->inner); sha256_update_private(&base->inner,pad,64);
  for (uint i=0;i<64;i++) pad[i]=k0[i]^0x5c;
  sha256_init(&base->outer); sha256_update_private(&base->outer,pad,64);
}

inline void hmac_finish(__private const hmac256_base_t *base, __private sha256_ctx_t *inner, __private uchar out[32]) {
  uchar ih[32]; sha256_final(inner,ih);
  sha256_ctx_t outer=base->outer; sha256_update_private(&outer,ih,32); sha256_final(&outer,out);
}

inline void hmac_private_private(__private const uchar *key, uint keylen, __private const uchar *msg, uint msglen, __private uchar out[32]) {
  hmac256_base_t b; hmac_init_private_key(key,keylen,&b);
  sha256_ctx_t in=b.inner; sha256_update_private(&in,msg,msglen); hmac_finish(&b,&in,out);
}
inline void hmac_private_global(__private const uchar *key, uint keylen, __global const uchar *msg, uint msglen, __private uchar out[32]) {
  hmac256_base_t b; hmac_init_private_key(key,keylen,&b);
  sha256_ctx_t in=b.inner; sha256_update_global(&in,msg,msglen); hmac_finish(&b,&in,out);
}
inline void hmac_global_private(__global const uchar *key, uint keylen, __private const uchar *msg, uint msglen, __private uchar out[32]) {
  hmac256_base_t b; hmac_init_global_key(key,keylen,&b);
  sha256_ctx_t in=b.inner; sha256_update_private(&in,msg,msglen); hmac_finish(&b,&in,out);
}

inline void pbkdf2_fill_b(__private const uchar key[32], __global const uchar *salt, uint saltlen, __global uchar *B, uint outlen) {
  hmac256_base_t base; hmac_init_private_key(key,32,&base);
  uint pos=0;
  for (uint blk=1; pos<outlen; blk++) {
    uchar ctr[4]; store_be32_p(ctr,blk);
    sha256_ctx_t in=base.inner;
    sha256_update_global(&in,salt,saltlen);
    sha256_update_private(&in,ctr,4);
    uchar u[32]; hmac_finish(&base,&in,u);
    uint take=(outlen-pos<32)?(outlen-pos):32;
    for (uint j=0;j<take;j++) B[pos+j]=u[j];
    pos+=take;
  }
}

inline void pbkdf2_b_to_32(__private const uchar key[32], __global const uchar *B, uint blen, __private uchar out[32]) {
  hmac256_base_t base; hmac_init_private_key(key,32,&base);
  uchar ctr[4]={0,0,0,1};
  sha256_ctx_t in=base.inner;
  sha256_update_global(&in,B,blen);
  sha256_update_private(&in,ctr,4);
  hmac_finish(&base,&in,out);
}

inline void copy_words(__global ulong *dst, __global const ulong *src, uint n) {
  for (uint i=0;i<n;i++) dst[i]=src[i];
}
inline void xor_words(__global ulong *dst, __global const ulong *src, uint n) {
  for (uint i=0;i<n;i++) dst[i]^=src[i];
}

inline void salsa_xor(__private ulong tmp[8], __global const ulong *in, __global ulong *out, uint rounds) {
  ulong d0=tmp[0]^in[0], d1=tmp[1]^in[1], d2=tmp[2]^in[2], d3=tmp[3]^in[3];
  ulong d4=tmp[4]^in[4], d5=tmp[5]^in[5], d6=tmp[6]^in[6], d7=tmp[7]^in[7];
  uint x0=(uint)d0, x1=(uint)(d6>>32), x2=(uint)d5, x3=(uint)(d3>>32);
  uint x4=(uint)d2, x5=(uint)(d0>>32), x6=(uint)d7, x7=(uint)(d5>>32);
  uint x8=(uint)d4, x9=(uint)(d2>>32), x10=(uint)d1, x11=(uint)(d7>>32);
  uint x12=(uint)d6, x13=(uint)(d4>>32), x14=(uint)d3, x15=(uint)(d1>>32);
  for (uint i=0;i<rounds;i+=2) {
    x4^=rotate(x0+x12,7U); x8^=rotate(x4+x0,9U); x12^=rotate(x8+x4,13U); x0^=rotate(x12+x8,18U);
    x9^=rotate(x5+x1,7U); x13^=rotate(x9+x5,9U); x1^=rotate(x13+x9,13U); x5^=rotate(x1+x13,18U);
    x14^=rotate(x10+x6,7U); x2^=rotate(x14+x10,9U); x6^=rotate(x2+x14,13U); x10^=rotate(x6+x2,18U);
    x3^=rotate(x15+x11,7U); x7^=rotate(x3+x15,9U); x11^=rotate(x7+x3,13U); x15^=rotate(x11+x7,18U);
    x1^=rotate(x0+x3,7U); x2^=rotate(x1+x0,9U); x3^=rotate(x2+x1,13U); x0^=rotate(x3+x2,18U);
    x6^=rotate(x5+x4,7U); x7^=rotate(x6+x5,9U); x4^=rotate(x7+x6,13U); x5^=rotate(x4+x7,18U);
    x11^=rotate(x10+x9,7U); x8^=rotate(x11+x10,9U); x9^=rotate(x8+x11,13U); x10^=rotate(x9+x8,18U);
    x12^=rotate(x15+x14,7U); x13^=rotate(x12+x15,9U); x14^=rotate(x13+x12,13U); x15^=rotate(x14+x13,18U);
  }
  d0=(ulong)((uint)d0+x0)|((ulong)((uint)(d0>>32)+x5)<<32);
  d1=(ulong)((uint)d1+x10)|((ulong)((uint)(d1>>32)+x15)<<32);
  d2=(ulong)((uint)d2+x4)|((ulong)((uint)(d2>>32)+x9)<<32);
  d3=(ulong)((uint)d3+x14)|((ulong)((uint)(d3>>32)+x3)<<32);
  d4=(ulong)((uint)d4+x8)|((ulong)((uint)(d4>>32)+x13)<<32);
  d5=(ulong)((uint)d5+x2)|((ulong)((uint)(d5>>32)+x7)<<32);
  d6=(ulong)((uint)d6+x12)|((ulong)((uint)(d6>>32)+x1)<<32);
  d7=(ulong)((uint)d7+x6)|((ulong)((uint)(d7>>32)+x11)<<32);
  out[0]=tmp[0]=d0; out[1]=tmp[1]=d1; out[2]=tmp[2]=d2; out[3]=tmp[3]=d3;
  out[4]=tmp[4]=d4; out[5]=tmp[5]=d5; out[6]=tmp[6]=d6; out[7]=tmp[7]=d7;
}

inline void block_mix_classic(__global ulong *in, __global ulong *out, uint r) {
  ulong tmp[8];
  for (uint j=0;j<8;j++) tmp[j]=in[(2*r-1)*8+j];
  for (uint i=0;i<2*r;i+=2) {
    salsa_xor(tmp,in+i*8,out+i*4,8);
    salsa_xor(tmp,in+i*8+8,out+i*4+r*8,8);
  }
}

inline uint integerify(__global const ulong *x, uint r) { return (uint)x[(2*r-1)*8]; }
inline uint p2floor_u(uint x) { while ((x&(x-1U))!=0U) x&=x-1U; return x; }
inline uint wrap_u(uint x,uint i) { uint n=p2floor_u(i); return (x&(n-1U))+(i-n); }

inline void load_b_to_x(__global const uchar *B, uint r, __global ulong *X) {
  uint R=16*r, j=0;
  for (uint i=0;i<R;i++) {
    uint idx=(j&~63U)|((j*5U)&63U); uint lo=load_le32_g(B+idx); j+=4;
    idx=(j&~63U)|((j*5U)&63U); uint hi=load_le32_g(B+idx); j+=4;
    X[i]=(ulong)lo|((ulong)hi<<32);
  }
}
inline void store_x_to_b(__global const ulong *X, uint r, __global uchar *B) {
  uint R=16*r, j=0;
  for (uint i=0;i<R;i++) {
    ulong v=X[i];
    uint idx=(j&~63U)|((j*5U)&63U); store_le32_g(B+idx,(uint)v); j+=4;
    idx=(j&~63U)|((j*5U)&63U); store_le32_g(B+idx,(uint)(v>>32)); j+=4;
  }
}

inline void sbox_init(__global uchar *B, __global ulong *S, __global ulong *XY) {
  __global ulong *x=XY;
  __global ulong *y=XY+16;
  load_b_to_x(B,1,x);
  for (uint i=0;i<96;i+=2) {
    copy_words(S+i*16,x,16);
    block_mix_classic(x,y,1);
    copy_words(S+(i+1)*16,y,16);
    block_mix_classic(y,x,1);
  }
  store_x_to_b(x,1,B);
}

inline void pwxform(__private ulong X[8], __global ulong *S, __private uint *s0off, __private uint *s1off, __private uint *s2off, __private uint *wptr) {
  uint s0=*s0off, s1=*s1off, s2=*s2off, w=*wptr;
  for (uint i=0;i<PWX_ROUNDS;i++) {
    for (uint j=0;j<PWX_GATHER;j++) {
      ulong x=X[2*j]; uint xl=(uint)x, xh=(uint)(x>>32);
      x=(ulong)xh*(ulong)xl;
      xl=(xl&S_MASK)>>3; xh=(xh&S_MASK)>>3;
      x=(x+S[s0+xl])^S[s1+xh]; X[2*j]=x;
      ulong y=X[2*j+1];
      y=((y>>32)*(ulong)((uint)y)+S[s0+xl+1])^S[s1+xh+1]; X[2*j+1]=y;
      if (i!=0 && i!=PWX_ROUNDS-1) { S[s2+w]=x; S[s2+w+1]=y; w+=2; }
    }
  }
  *s0off=s2; *s1off=s0; *s2off=s1; *wptr=w&511U;
}

inline void block_mix_pwx(__global ulong *B, uint r, __global ulong *S, __private uint *s0, __private uint *s1, __private uint *s2, __private uint *w) {
  ulong X[8]; uint r1=2*r;
  for (uint j=0;j<8;j++) X[j]=B[(r1-1)*8+j];
  for (uint i=0;i<r1;i++) {
    for (uint j=0;j<8;j++) X[j]^=B[i*8+j];
    pwxform(X,S,s0,s1,s2,w);
    for (uint j=0;j<8;j++) B[i*8+j]=X[j];
  }
  for (uint j=0;j<8;j++) X[j]=0;
  // salsa_xor needs a private tmp and global input/output.
  salsa_xor(X,B+(r1-1)*8,B+(r1-1)*8,2);
}

inline void smix_rw(__global uchar *B, uint r, uint N, __global ulong *V, __global ulong *XY, __global ulong *S) {
  uint R=16*r;
  __global ulong *x=XY;
  load_b_to_x(B,r,x);
  uint s0=2*S_THIRD_WORDS, s1=S_THIRD_WORDS, s2=0, w=0;
  for (uint i=0;i<N;i++) {
    copy_words(V+(ulong)i*R,x,R);
    if (i>1) {
      uint j=wrap_u(integerify(x,r),i);
      xor_words(x,V+(ulong)j*R,R);
    }
    block_mix_pwx(x,r,S,&s0,&s1,&s2,&w);
  }
  uint nloop=((N+2U)/3U+1U)&~1U;
  for (uint i=0;i<nloop;i++) {
    uint j=integerify(x,r)&(N-1U);
    xor_words(x,V+(ulong)j*R,R);
    copy_words(V+(ulong)j*R,x,R);
    block_mix_pwx(x,r,S,&s0,&s1,&s2,&w);
  }
  store_x_to_b(x,r,B);
}

inline void smix_yescrypt(__global uchar *B, uint r, uint N, __global ulong *V, __global ulong *XY, __global ulong *S, __private uchar ppass[32]) {
  sbox_init(B,S,XY);
  uchar next[32];
  hmac_global_private(B+64*(2*r-1),64,ppass,32,next);
  for (uint i=0;i<32;i++) ppass[i]=next[i];
  smix_rw(B,r,N,V,XY,S);
}


/*
 * Per-candidate context kept in global memory between init/loop/final.
 * The hot state itself is P_all (shuffled X) and S_all (PWX S-box).
 */
typedef struct {
  uchar passwd[32];
  uint phase;
  uint iter;
  uint s_state;
  uint w;
} yescrypt_gpu_ctx_t;

inline uint integerify_local(__local const ulong *X) {
  return (uint)X[(2U * YC_R - 1U) * 8U];
}

/* Salsa20/2 on one 64-byte block already held in private memory. */
inline void salsa_self_private(__private ulong v[8], const uint rounds) {
  ulong d0=v[0], d1=v[1], d2=v[2], d3=v[3];
  ulong d4=v[4], d5=v[5], d6=v[6], d7=v[7];
  uint x0=(uint)d0, x1=(uint)(d6>>32), x2=(uint)d5, x3=(uint)(d3>>32);
  uint x4=(uint)d2, x5=(uint)(d0>>32), x6=(uint)d7, x7=(uint)(d5>>32);
  uint x8=(uint)d4, x9=(uint)(d2>>32), x10=(uint)d1, x11=(uint)(d7>>32);
  uint x12=(uint)d6, x13=(uint)(d4>>32), x14=(uint)d3, x15=(uint)(d1>>32);
  for (uint i=0;i<rounds;i+=2) {
    x4^=rotate(x0+x12,7U); x8^=rotate(x4+x0,9U); x12^=rotate(x8+x4,13U); x0^=rotate(x12+x8,18U);
    x9^=rotate(x5+x1,7U); x13^=rotate(x9+x5,9U); x1^=rotate(x13+x9,13U); x5^=rotate(x1+x13,18U);
    x14^=rotate(x10+x6,7U); x2^=rotate(x14+x10,9U); x6^=rotate(x2+x14,13U); x10^=rotate(x6+x2,18U);
    x3^=rotate(x15+x11,7U); x7^=rotate(x3+x15,9U); x11^=rotate(x7+x3,13U); x15^=rotate(x11+x7,18U);
    x1^=rotate(x0+x3,7U); x2^=rotate(x1+x0,9U); x3^=rotate(x2+x1,13U); x0^=rotate(x3+x2,18U);
    x6^=rotate(x5+x4,7U); x7^=rotate(x6+x5,9U); x4^=rotate(x7+x6,13U); x5^=rotate(x4+x7,18U);
    x11^=rotate(x10+x9,7U); x8^=rotate(x11+x10,9U); x9^=rotate(x8+x11,13U); x10^=rotate(x9+x8,18U);
    x12^=rotate(x15+x14,7U); x13^=rotate(x12+x15,9U); x14^=rotate(x13+x12,13U); x15^=rotate(x14+x13,18U);
  }
  v[0]=(ulong)((uint)d0+x0)|((ulong)((uint)(d0>>32)+x5)<<32);
  v[1]=(ulong)((uint)d1+x10)|((ulong)((uint)(d1>>32)+x15)<<32);
  v[2]=(ulong)((uint)d2+x4)|((ulong)((uint)(d2>>32)+x9)<<32);
  v[3]=(ulong)((uint)d3+x14)|((ulong)((uint)(d3>>32)+x3)<<32);
  v[4]=(ulong)((uint)d4+x8)|((ulong)((uint)(d4>>32)+x13)<<32);
  v[5]=(ulong)((uint)d5+x2)|((ulong)((uint)(d5>>32)+x7)<<32);
  v[6]=(ulong)((uint)d6+x12)|((ulong)((uint)(d6>>32)+x1)<<32);
  v[7]=(ulong)((uint)d7+x6)|((ulong)((uint)(d7>>32)+x11)<<32);
}

/*
 * Cooperative PWX blockmix.  Four lanes own the four PWX gather lanes, two
 * 64-bit words apiece.  The other lanes participate in state/V transfers.
 * S2 writes are independent during a PWX call; the barrier after each 64-byte
 * segment makes them visible before the S-box thirds rotate for the next one.
 */
inline void coop_block_mix_pwx(
    __local ulong *X,
    __local ulong *S,
    __private uint *s_state,
    __private uint *w_ptr,
    const uint lid)
{
  const uint r1 = 2U * YC_R;
  const int do_lane = (lid < PWX_GATHER);

  ulong px0=0, px1=0;
  if (do_lane) {
    const uint last=(r1-1U)*8U + lid*2U;
    px0=X[last+0U];
    px1=X[last+1U];
  }

  uint ss=*s_state;
  uint ww=*w_ptr;

  for (uint i=0;i<r1;i++) {
    if (do_lane) {
      const uint base=i*8U + lid*2U;
      px0 ^= X[base+0U];
      px1 ^= X[base+1U];

      const uint s0off=((ss==0U)?2U:(ss==1U)?0U:1U)*S_THIRD_WORDS;
      const uint s1off=((ss==0U)?1U:(ss==1U)?2U:0U)*S_THIRD_WORDS;
      const uint s2off=((ss==0U)?0U:(ss==1U)?1U:2U)*S_THIRD_WORDS;

      for (uint round=0;round<PWX_ROUNDS;round++) {
        const uint xl=(uint)px0;
        const uint xh=(uint)(px0>>32);
        const uint p0=(xl&S_MASK)>>3;
        const uint p1=(xh&S_MASK)>>3;

        /* p0/p1 are even, so each vload2 reads one aligned 16-byte S entry pair. */
        const ulong2 s0v=vload2(0,S+s0off+p0);
        const ulong2 s1v=vload2(0,S+s1off+p1);

        ulong x=((ulong)((uint)(px0>>32))*(ulong)((uint)px0) + s0v.s0) ^ s1v.s0;
        ulong y=((ulong)((uint)(px1>>32))*(ulong)((uint)px1) + s0v.s1) ^ s1v.s1;
        px0=x;
        px1=y;

        if (round!=0U && round!=(PWX_ROUNDS-1U)) {
          const uint ai=round-1U;
          const uint wslot=ww + ai*8U + lid*2U;
          S[s2off+wslot+0U]=px0;
          S[s2off+wslot+1U]=px1;
        }
      }

      X[base+0U]=px0;
      X[base+1U]=px1;
    }

    ss=(ss+1U)%3U;
    ww=(ww+32U)&511U;
    barrier(CLK_LOCAL_MEM_FENCE);
  }

  if (lid==0U) {
    ulong salsa[8];
    const uint off=(r1-1U)*8U;
    for (uint i=0;i<8U;i++) salsa[i]=X[off+i];
    salsa_self_private(salsa,2U);
    for (uint i=0;i<8U;i++) X[off+i]=salsa[i];
  }
  barrier(CLK_LOCAL_MEM_FENCE);

  *s_state=ss;
  *w_ptr=ww;
}

inline void coop_smix1_step(
    __local ulong *X,
    __global ulong *V,
    __local ulong *S,
    __private uint *s_state,
    __private uint *w_ptr,
    const uint iter,
    const uint lid,
    const uint lsz)
{
  __global ulong *Vi=V+(ulong)iter*YC_STATE_WORDS;
  for (uint j=lid;j<YC_STATE_WORDS;j+=lsz) Vi[j]=X[j];
  barrier(CLK_LOCAL_MEM_FENCE | CLK_GLOBAL_MEM_FENCE);

  if (iter>1U) {
    const uint idx=wrap_u(integerify_local(X),iter);
    __global ulong *Vj=V+(ulong)idx*YC_STATE_WORDS;
    /* Every lane must derive idx from the same pre-XOR state. */
    barrier(CLK_LOCAL_MEM_FENCE);
    for (uint j=lid;j<YC_STATE_WORDS;j+=lsz) X[j]^=Vj[j];
    barrier(CLK_LOCAL_MEM_FENCE);
  }
  coop_block_mix_pwx(X,S,s_state,w_ptr,lid);
}

inline void coop_smix2_step(
    __local ulong *X,
    __global ulong *V,
    __local ulong *S,
    __private uint *s_state,
    __private uint *w_ptr,
    const uint lid,
    const uint lsz)
{
  const uint idx=integerify_local(X)&(YC_N-1U);
  __global ulong *Vj=V+(ulong)idx*YC_STATE_WORDS;
  barrier(CLK_LOCAL_MEM_FENCE);
  for (uint j=lid;j<YC_STATE_WORDS;j+=lsz) X[j]^=Vj[j];
  barrier(CLK_LOCAL_MEM_FENCE);
  for (uint j=lid;j<YC_STATE_WORDS;j+=lsz) Vj[j]=X[j];
  barrier(CLK_LOCAL_MEM_FENCE | CLK_GLOBAL_MEM_FENCE);
  coop_block_mix_pwx(X,S,s_state,w_ptr,lid);
}

/*
 * Stage 1.  One ordinary work-item initializes one candidate.  The optional
 * yescrypt prehash pass is much smaller than the main pass for the common j9T
 * parameters.  The main shuffled state and S-box are left in P_all/S_all.
 */
__kernel void yescrypt_init(
  __global const uchar *passwords,
  __global const uint *pw_lens,
  __global const uchar *salt,
  const uint salt_len,
  const uint count,
  __global ulong *P_all,
  __global ulong *scratch_all,
  __global ulong *S_all,
  __global yescrypt_gpu_ctx_t *ctx_all,
  __global ulong *V0,
  __global ulong *V1,
  __global ulong *V2,
  __global ulong *V3)
{
  const uint gid=get_global_id(0);
  if (gid>=count) return;
  const uint pwlen=pw_lens[gid];
  if (pwlen>MAX_PW) return;

  __global const uchar *pw=passwords+(ulong)gid*MAX_PW;
  __global ulong *P=P_all+(ulong)gid*YC_STATE_WORDS;
  __global uchar *B=(__global uchar *)P;
  __global ulong *scratch=scratch_all+(ulong)gid*YC_SCRATCH_WORDS;
  __global ulong *S=S_all+(ulong)gid*S_WORDS;
  __global yescrypt_gpu_ctx_t *ctx=&ctx_all[gid];

  const ulong vwords=(ulong)YC_STATE_WORDS*(ulong)YC_N;
  const ulong slot=(ulong)(gid>>2);
  __global ulong *V;
  switch (gid&3U) {
    case 0U: V=V0+slot*vwords; break;
    case 1U: V=V1+slot*vwords; break;
    case 2U: V=V2+slot*vwords; break;
    default: V=V3+slot*vwords; break;
  }

  uchar ppass[32];
  uchar key[32];

#if YC_PREHASH_NEEDED
  {
    uchar prekey[16]={'y','e','s','c','r','y','p','t','-','p','r','e','h','a','s','h'};
    hmac256_base_t hb; hmac_init_private_key(prekey,16,&hb);
    sha256_ctx_t hin=hb.inner; sha256_update_global(&hin,pw,pwlen); hmac_finish(&hb,&hin,ppass);

    pbkdf2_fill_b(ppass,salt,salt_len,B,YC_STATE_BYTES);
    for (uint i=0;i<32U;i++) ppass[i]=B[i];
    smix_yescrypt(B,YC_R,YC_PREHASH_N,V,scratch,S,ppass);
    pbkdf2_b_to_32(ppass,B,YC_STATE_BYTES,key);
    for (uint i=0;i<32U;i++) ppass[i]=key[i];
  }
#endif

  {
    uchar yeskey[8]={'y','e','s','c','r','y','p','t'};
    hmac256_base_t hb; hmac_init_private_key(yeskey,8,&hb);
    sha256_ctx_t hin=hb.inner;
#if YC_PREHASH_NEEDED
    sha256_update_private(&hin,ppass,32);
#else
    sha256_update_global(&hin,pw,pwlen);
#endif
    hmac_finish(&hb,&hin,ppass);
  }

  /* Main-pass KDF setup, but stop before the expensive SMix. */
  pbkdf2_fill_b(ppass,salt,salt_len,B,YC_STATE_BYTES);
  for (uint i=0;i<32U;i++) ppass[i]=B[i];
  sbox_init(B,S,scratch);
  {
    uchar next[32];
    hmac_global_private(B+64U*(2U*YC_R-1U),64,ppass,32,next);
    for (uint i=0;i<32U;i++) ppass[i]=next[i];
  }
  load_b_to_x(B,YC_R,scratch);
  for (uint i=0;i<YC_STATE_WORDS;i++) P[i]=scratch[i];

  for (uint i=0;i<32U;i++) ctx->passwd[i]=ppass[i];
  ctx->phase=0U;
  ctx->iter=0U;
  ctx->s_state=0U;
  ctx->w=0U;
}

/*
 * Stage 2.  One 32-work-item workgroup owns one password.  X and the entire
 * 12 KiB S-box stay in local/shared memory for the duration of the launch.
 */
__attribute__((reqd_work_group_size(YC_WG_SIZE,1,1)))
__kernel void yescrypt_loop(
  const uint count,
  const uint loop_count,
  __global ulong *P_all,
  __global ulong *S_all,
  __global yescrypt_gpu_ctx_t *ctx_all,
  __global ulong *V0,
  __global ulong *V1,
  __global ulong *V2,
  __global ulong *V3)
{
  const uint bid=get_group_id(0);
  const uint lid=get_local_id(0);
  const uint lsz=get_local_size(0);
  if (bid>=count) return;

  __global ulong *P=P_all+(ulong)bid*YC_STATE_WORDS;
  __global ulong *Sg=S_all+(ulong)bid*S_WORDS;
  __global yescrypt_gpu_ctx_t *ctx=&ctx_all[bid];

  __local ulong X[YC_STATE_WORDS];
  __local ulong S[S_WORDS];

  for (uint i=lid;i<YC_STATE_WORDS;i+=lsz) X[i]=P[i];
  for (uint i=lid;i<S_WORDS;i+=lsz) S[i]=Sg[i];

  uint phase=ctx->phase;
  uint iter=ctx->iter;
  uint s_state=ctx->s_state;
  uint w=ctx->w;

  const ulong vwords=(ulong)YC_STATE_WORDS*(ulong)YC_N;
  const ulong slot=(ulong)(bid>>2);
  __global ulong *V;
  switch (bid&3U) {
    case 0U: V=V0+slot*vwords; break;
    case 1U: V=V1+slot*vwords; break;
    case 2U: V=V2+slot*vwords; break;
    default: V=V3+slot*vwords; break;
  }

  barrier(CLK_LOCAL_MEM_FENCE);

  for (uint loop=0;loop<loop_count;loop++) {
    if (phase==0U) {
      if (iter<YC_N) {
        coop_smix1_step(X,V,S,&s_state,&w,iter,lid,lsz);
        iter++;
        if (iter>=YC_N) { phase=1U; iter=0U; }
      }
    } else {
      if (iter>=YC_NLOOP) break;
      coop_smix2_step(X,V,S,&s_state,&w,lid,lsz);
      iter++;
    }
  }

  barrier(CLK_LOCAL_MEM_FENCE);
  for (uint i=lid;i<YC_STATE_WORDS;i+=lsz) P[i]=X[i];
  for (uint i=lid;i<S_WORDS;i+=lsz) Sg[i]=S[i];
  barrier(CLK_GLOBAL_MEM_FENCE);

  if (lid==0U) {
    ctx->phase=phase;
    ctx->iter=iter;
    ctx->s_state=s_state;
    ctx->w=w;
  }
}

/* Stage 3.  One ordinary work-item derives and writes the final 32-byte key. */
__kernel void yescrypt_final(
  const uint count,
  __global ulong *P_all,
  __global ulong *scratch_all,
  __global yescrypt_gpu_ctx_t *ctx_all,
  __global uchar *out_all)
{
  const uint gid=get_global_id(0);
  if (gid>=count) return;

  __global ulong *P=P_all+(ulong)gid*YC_STATE_WORDS;
  __global ulong *scratch=scratch_all+(ulong)gid*YC_SCRATCH_WORDS;
  __global uchar *B=(__global uchar *)P;
  __global yescrypt_gpu_ctx_t *ctx=&ctx_all[gid];

  for (uint i=0;i<YC_STATE_WORDS;i++) scratch[i]=P[i];
  store_x_to_b(scratch,YC_R,B);

  uchar ppass[32];
  uchar key[32];
  for (uint i=0;i<32U;i++) ppass[i]=ctx->passwd[i];
  pbkdf2_b_to_32(ppass,B,YC_STATE_BYTES,key);

  uchar client[10]={'C','l','i','e','n','t',' ','K','e','y'};
  uchar h1[32], final[32];
  hmac_private_private(key,32,client,10,h1);
  sha256_private_msg(h1,32,final);
  for (uint i=0;i<32U;i++) out_all[(ulong)gid*32U+i]=final[i];
}
