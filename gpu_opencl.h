#ifndef YESCRYPT_CRACK_GPU_OPENCL_H
#define YESCRYPT_CRACK_GPU_OPENCL_H

#include <stddef.h>
#include <stdint.h>

#define YCL_GPU_CANCELLED 1

typedef struct ycl_gpu_ctx ycl_gpu_ctx;

int ycl_opencl_device_count(char *err, size_t errlen);
int ycl_opencl_device_info(int index, char *name, size_t namelen,
                           uint64_t *global_mem, uint64_t *max_alloc,
                           char *err, size_t errlen);

ycl_gpu_ctx *ycl_gpu_create(int index, const char *source, size_t source_len,
                            char *err, size_t errlen);
int ycl_gpu_configure(ycl_gpu_ctx *g, uint32_t N, uint32_t r,
                      uint32_t batch_hint, uint32_t *capacity,
                      char *err, size_t errlen);
int ycl_gpu_hash(ycl_gpu_ctx *g,
                 const unsigned char *passwords,
                 const uint32_t *pw_lens,
                 uint32_t count,
                 const unsigned char *salt,
                 uint32_t salt_len,
                 unsigned char *out,
                 char *err, size_t errlen);
void ycl_gpu_cancel(ycl_gpu_ctx *g);
void ycl_gpu_reset_cancel(ycl_gpu_ctx *g);
void ycl_gpu_destroy(ycl_gpu_ctx *g);

#endif
