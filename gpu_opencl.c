#include "gpu_opencl.h"

#include <dlfcn.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

/* Minimal OpenCL 1.2 ABI declarations. We intentionally do not include
 * CL/cl.h so the binary can be built without OpenCL development headers. */
typedef int32_t  cl_int;
typedef uint32_t cl_uint;
typedef uint64_t cl_ulong;
typedef cl_ulong cl_bitfield;
typedef cl_bitfield cl_device_type;
typedef cl_bitfield cl_mem_flags;
typedef cl_bitfield cl_command_queue_properties;
typedef uint32_t cl_bool;
typedef intptr_t cl_context_properties;
typedef struct _cl_platform_id *cl_platform_id;
typedef struct _cl_device_id *cl_device_id;
typedef struct _cl_context *cl_context;
typedef struct _cl_command_queue *cl_command_queue;
typedef struct _cl_mem *cl_mem;
typedef struct _cl_program *cl_program;
typedef struct _cl_kernel *cl_kernel;
typedef struct _cl_event *cl_event;

#define CL_SUCCESS 0
#define CL_DEVICE_NOT_FOUND -1
#define CL_PLATFORM_NOT_FOUND_KHR -1001
#define CL_DEVICE_TYPE_GPU (1ULL << 2)
#define CL_DEVICE_NAME 0x102B
#define CL_DEVICE_GLOBAL_MEM_SIZE 0x101F
#define CL_DEVICE_MAX_MEM_ALLOC_SIZE 0x1010
#define CL_PROGRAM_BUILD_LOG 0x1183
#define CL_MEM_READ_WRITE (1ULL << 0)
#define CL_MEM_WRITE_ONLY (1ULL << 1)
#define CL_MEM_READ_ONLY  (1ULL << 2)
#define CL_FALSE 0
#define CL_TRUE 1

#define MAX_GPU_DEVICES 32
#define MAX_PW 256ULL
#define MAX_R 32ULL
#define B_STRIDE (128ULL * MAX_R)
#define XY_STRIDE_WORDS (32ULL * MAX_R)
#define S_WORDS 1536ULL
#define ONE_MIB (1024ULL * 1024ULL)

static void *ocl_lib;

#define DECL(name, ret, args) static ret (*p_##name) args
DECL(clGetPlatformIDs, cl_int, (cl_uint, cl_platform_id *, cl_uint *));
DECL(clGetDeviceIDs, cl_int, (cl_platform_id, cl_device_type, cl_uint, cl_device_id *, cl_uint *));
DECL(clGetDeviceInfo, cl_int, (cl_device_id, cl_uint, size_t, void *, size_t *));
DECL(clCreateContext, cl_context, (const cl_context_properties *, cl_uint, const cl_device_id *, void (*)(const char *, const void *, size_t, void *), void *, cl_int *));
DECL(clCreateCommandQueue, cl_command_queue, (cl_context, cl_device_id, cl_command_queue_properties, cl_int *));
DECL(clCreateProgramWithSource, cl_program, (cl_context, cl_uint, const char **, const size_t *, cl_int *));
DECL(clBuildProgram, cl_int, (cl_program, cl_uint, const cl_device_id *, const char *, void (*)(cl_program, void *), void *));
DECL(clGetProgramBuildInfo, cl_int, (cl_program, cl_device_id, cl_uint, size_t, void *, size_t *));
DECL(clCreateKernel, cl_kernel, (cl_program, const char *, cl_int *));
DECL(clCreateBuffer, cl_mem, (cl_context, cl_mem_flags, size_t, void *, cl_int *));
DECL(clSetKernelArg, cl_int, (cl_kernel, cl_uint, size_t, const void *));
DECL(clEnqueueWriteBuffer, cl_int, (cl_command_queue, cl_mem, cl_bool, size_t, size_t, const void *, cl_uint, const cl_event *, cl_event *));
DECL(clEnqueueNDRangeKernel, cl_int, (cl_command_queue, cl_kernel, cl_uint, const size_t *, const size_t *, const size_t *, cl_uint, const cl_event *, cl_event *));
DECL(clEnqueueReadBuffer, cl_int, (cl_command_queue, cl_mem, cl_bool, size_t, size_t, void *, cl_uint, const cl_event *, cl_event *));
DECL(clFinish, cl_int, (cl_command_queue));
DECL(clReleaseMemObject, cl_int, (cl_mem));
DECL(clReleaseKernel, cl_int, (cl_kernel));
DECL(clReleaseProgram, cl_int, (cl_program));
DECL(clReleaseCommandQueue, cl_int, (cl_command_queue));
DECL(clReleaseContext, cl_int, (cl_context));
#undef DECL

static int seterr(char *err, size_t errlen, const char *fmt, ...) {
    if (err && errlen) {
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(err, errlen, fmt, ap);
        va_end(ap);
    }
    return -1;
}

static int load_opencl(char *err, size_t errlen) {
    if (ocl_lib) return 0;
    const char *libs[] = {"libOpenCL.so.1", "libOpenCL.so", NULL};
    for (int i = 0; libs[i]; i++) {
        ocl_lib = dlopen(libs[i], RTLD_NOW | RTLD_LOCAL);
        if (ocl_lib) break;
    }
    if (!ocl_lib) return seterr(err, errlen, "OpenCL loader not found: %s", dlerror());

#define LOAD(name) do { *(void **)(&p_##name) = dlsym(ocl_lib, #name); if (!p_##name) return seterr(err, errlen, "OpenCL symbol %s missing", #name); } while (0)
    LOAD(clGetPlatformIDs); LOAD(clGetDeviceIDs); LOAD(clGetDeviceInfo);
    LOAD(clCreateContext); LOAD(clCreateCommandQueue); LOAD(clCreateProgramWithSource);
    LOAD(clBuildProgram); LOAD(clGetProgramBuildInfo); LOAD(clCreateKernel);
    LOAD(clCreateBuffer); LOAD(clSetKernelArg); LOAD(clEnqueueWriteBuffer);
    LOAD(clEnqueueNDRangeKernel); LOAD(clEnqueueReadBuffer); LOAD(clFinish);
    LOAD(clReleaseMemObject); LOAD(clReleaseKernel); LOAD(clReleaseProgram);
    LOAD(clReleaseCommandQueue); LOAD(clReleaseContext);
#undef LOAD
    return 0;
}

static int enumerate_gpus(cl_device_id *out, int maxout, char *err, size_t errlen) {
    if (load_opencl(err, errlen) != 0) return -1;
    cl_uint np = 0;
    cl_int rc = p_clGetPlatformIDs(0, NULL, &np);
    if (rc == CL_PLATFORM_NOT_FOUND_KHR || np == 0) return 0;
    if (rc != CL_SUCCESS) return seterr(err, errlen, "clGetPlatformIDs failed: %d", rc);
    cl_platform_id *plats = calloc(np, sizeof(*plats));
    if (!plats) return seterr(err, errlen, "out of memory enumerating OpenCL platforms");
    rc = p_clGetPlatformIDs(np, plats, NULL);
    if (rc != CL_SUCCESS) { free(plats); return seterr(err, errlen, "clGetPlatformIDs(list) failed: %d", rc); }
    int count = 0;
    for (cl_uint p = 0; p < np && count < maxout; p++) {
        cl_uint nd = 0;
        rc = p_clGetDeviceIDs(plats[p], CL_DEVICE_TYPE_GPU, 0, NULL, &nd);
        if (rc == CL_DEVICE_NOT_FOUND || nd == 0) continue;
        if (rc != CL_SUCCESS) continue;
        cl_device_id *devs = calloc(nd, sizeof(*devs));
        if (!devs) continue;
        if (p_clGetDeviceIDs(plats[p], CL_DEVICE_TYPE_GPU, nd, devs, NULL) == CL_SUCCESS) {
            for (cl_uint d = 0; d < nd && count < maxout; d++) out[count++] = devs[d];
        }
        free(devs);
    }
    free(plats);
    return count;
}

int ycl_opencl_device_count(char *err, size_t errlen) {
    cl_device_id devs[MAX_GPU_DEVICES];
    return enumerate_gpus(devs, MAX_GPU_DEVICES, err, errlen);
}

int ycl_opencl_device_info(int index, char *name, size_t namelen,
                           uint64_t *global_mem, uint64_t *max_alloc,
                           char *err, size_t errlen) {
    cl_device_id devs[MAX_GPU_DEVICES];
    int n = enumerate_gpus(devs, MAX_GPU_DEVICES, err, errlen);
    if (n < 0) return -1;
    if (index < 0 || index >= n) return seterr(err, errlen, "OpenCL GPU index %d out of range (found %d)", index, n);
    cl_device_id d = devs[index];
    if (name && namelen) {
        if (p_clGetDeviceInfo(d, CL_DEVICE_NAME, namelen, name, NULL) != CL_SUCCESS) snprintf(name, namelen, "OpenCL GPU %d", index);
        name[namelen - 1] = 0;
    }
    cl_ulong gm = 0, ma = 0;
    if (p_clGetDeviceInfo(d, CL_DEVICE_GLOBAL_MEM_SIZE, sizeof(gm), &gm, NULL) != CL_SUCCESS) return seterr(err, errlen, "cannot query GPU global memory");
    if (p_clGetDeviceInfo(d, CL_DEVICE_MAX_MEM_ALLOC_SIZE, sizeof(ma), &ma, NULL) != CL_SUCCESS) return seterr(err, errlen, "cannot query GPU max allocation");
    if (global_mem) *global_mem = gm;
    if (max_alloc) *max_alloc = ma;
    return 0;
}

struct ycl_gpu_ctx {
    int index;
    cl_device_id dev;
    cl_context ctx;
    cl_command_queue queue;

    char *source;
    size_t source_len;
    cl_program program;
    cl_kernel init_kernel;
    cl_kernel loop_kernel;
    cl_kernel final_kernel;

    cl_ulong global_mem;
    cl_ulong max_alloc;
    uint32_t N, r, capacity;
    atomic_int cancel_requested;

    cl_mem passwords;
    cl_mem pw_lens;
    cl_mem salt;
    cl_mem P;
    cl_mem scratch;
    cl_mem S;
    cl_mem yctx;
    cl_mem V[4];
    cl_mem out;
};

static void release_buffers(ycl_gpu_ctx *g) {
    cl_mem *all[] = {
        &g->passwords, &g->pw_lens, &g->salt,
        &g->P, &g->scratch, &g->S, &g->yctx,
        &g->V[0], &g->V[1], &g->V[2], &g->V[3], &g->out
    };
    for (size_t i = 0; i < sizeof(all) / sizeof(all[0]); i++) {
        if (*all[i]) {
            p_clReleaseMemObject(*all[i]);
            *all[i] = NULL;
        }
    }
    g->capacity = 0;
}

static void release_program(ycl_gpu_ctx *g) {
    if (g->init_kernel)  { p_clReleaseKernel(g->init_kernel);  g->init_kernel = NULL; }
    if (g->loop_kernel)  { p_clReleaseKernel(g->loop_kernel);  g->loop_kernel = NULL; }
    if (g->final_kernel) { p_clReleaseKernel(g->final_kernel); g->final_kernel = NULL; }
    if (g->program)      { p_clReleaseProgram(g->program);     g->program = NULL; }
    g->N = 0;
    g->r = 0;
}

void ycl_gpu_cancel(ycl_gpu_ctx *g) {
    if (g) atomic_store_explicit(&g->cancel_requested, 1, memory_order_relaxed);
}

void ycl_gpu_reset_cancel(ycl_gpu_ctx *g) {
    if (g) atomic_store_explicit(&g->cancel_requested, 0, memory_order_relaxed);
}

void ycl_gpu_destroy(ycl_gpu_ctx *g) {
    if (!g) return;
    release_buffers(g);
    release_program(g);
    if (g->queue) p_clReleaseCommandQueue(g->queue);
    if (g->ctx) p_clReleaseContext(g->ctx);
    free(g->source);
    free(g);
}

static int build_specialized_program(ycl_gpu_ctx *g, uint32_t N, uint32_t r,
                                     char *err, size_t errlen) {
    if (g->program && g->N == N && g->r == r) return 0;

    release_program(g);

    cl_int rc;
    const char *sources[1] = {g->source};
    size_t lengths[1] = {g->source_len};
    g->program = p_clCreateProgramWithSource(g->ctx, 1, sources, lengths, &rc);
    if (!g->program || rc != CL_SUCCESS) {
        release_program(g);
        return seterr(err, errlen, "clCreateProgramWithSource failed: %d", rc);
    }

    char options[256];
    snprintf(options, sizeof(options), "-cl-std=CL1.2 -DYC_N=%u -DYC_R=%u", N, r);
    rc = p_clBuildProgram(g->program, 1, &g->dev, options, NULL, NULL);
    if (rc != CL_SUCCESS) {
        size_t logsz = 0;
        p_clGetProgramBuildInfo(g->program, g->dev, CL_PROGRAM_BUILD_LOG, 0, NULL, &logsz);
        char *log = calloc(logsz + 1, 1);
        if (log) p_clGetProgramBuildInfo(g->program, g->dev, CL_PROGRAM_BUILD_LOG, logsz, log, NULL);
        seterr(err, errlen, "OpenCL kernel build failed (%d) [%s]: %s", rc, options, log ? log : "no build log");
        free(log);
        release_program(g);
        return -1;
    }

    g->init_kernel = p_clCreateKernel(g->program, "yescrypt_init", &rc);
    if (!g->init_kernel || rc != CL_SUCCESS) {
        seterr(err, errlen, "clCreateKernel(yescrypt_init) failed: %d", rc);
        release_program(g);
        return -1;
    }
    g->loop_kernel = p_clCreateKernel(g->program, "yescrypt_loop", &rc);
    if (!g->loop_kernel || rc != CL_SUCCESS) {
        seterr(err, errlen, "clCreateKernel(yescrypt_loop) failed: %d", rc);
        release_program(g);
        return -1;
    }
    g->final_kernel = p_clCreateKernel(g->program, "yescrypt_final", &rc);
    if (!g->final_kernel || rc != CL_SUCCESS) {
        seterr(err, errlen, "clCreateKernel(yescrypt_final) failed: %d", rc);
        release_program(g);
        return -1;
    }

    g->N = N;
    g->r = r;
    return 0;
}

ycl_gpu_ctx *ycl_gpu_create(int index, const char *source, size_t source_len,
                            char *err, size_t errlen) {
    cl_device_id devs[MAX_GPU_DEVICES];
    int n = enumerate_gpus(devs, MAX_GPU_DEVICES, err, errlen);
    if (n < 0) return NULL;
    if (index < 0 || index >= n) {
        seterr(err, errlen, "OpenCL GPU index %d out of range (found %d)", index, n);
        return NULL;
    }
    if (!source || source_len == 0) {
        seterr(err, errlen, "empty OpenCL source");
        return NULL;
    }

    ycl_gpu_ctx *g = calloc(1, sizeof(*g));
    if (!g) {
        seterr(err, errlen, "out of memory creating GPU context");
        return NULL;
    }
    atomic_init(&g->cancel_requested, 0);
    g->index = index;
    g->dev = devs[index];
    g->source = malloc(source_len + 1);
    if (!g->source) {
        seterr(err, errlen, "out of memory copying OpenCL source");
        ycl_gpu_destroy(g);
        return NULL;
    }
    memcpy(g->source, source, source_len);
    g->source[source_len] = 0;
    g->source_len = source_len;

    p_clGetDeviceInfo(g->dev, CL_DEVICE_GLOBAL_MEM_SIZE, sizeof(g->global_mem), &g->global_mem, NULL);
    p_clGetDeviceInfo(g->dev, CL_DEVICE_MAX_MEM_ALLOC_SIZE, sizeof(g->max_alloc), &g->max_alloc, NULL);

    cl_int rc;
    g->ctx = p_clCreateContext(NULL, 1, &g->dev, NULL, NULL, &rc);
    if (!g->ctx || rc != CL_SUCCESS) {
        seterr(err, errlen, "clCreateContext failed: %d", rc);
        ycl_gpu_destroy(g);
        return NULL;
    }
    g->queue = p_clCreateCommandQueue(g->ctx, g->dev, 0, &rc);
    if (!g->queue || rc != CL_SUCCESS) {
        seterr(err, errlen, "clCreateCommandQueue failed: %d", rc);
        ycl_gpu_destroy(g);
        return NULL;
    }
    return g;
}

static cl_mem mkbuf(ycl_gpu_ctx *g, cl_mem_flags flags, size_t size,
                    const char *what, char *err, size_t errlen) {
    cl_int rc;
    if (size == 0) size = 8;
    cl_mem m = p_clCreateBuffer(g->ctx, flags, size, NULL, &rc);
    if (!m || rc != CL_SUCCESS) {
        seterr(err, errlen, "clCreateBuffer(%s, %.2f MiB) failed: %d",
               what, (double)size / (1024.0 * 1024.0), rc);
        return NULL;
    }
    return m;
}

int ycl_gpu_configure(ycl_gpu_ctx *g, uint32_t N, uint32_t r,
                      uint32_t batch_hint, uint32_t *capacity,
                      char *err, size_t errlen) {
    if (!g || !N || !r || r > MAX_R || (N & (N - 1U)))
        return seterr(err, errlen, "invalid yescrypt GPU parameters N=%u r=%u", N, r);

    /* Rebuild only when the yescrypt geometry changes. N/r become compile-time
     * constants so the OpenCL compiler can specialize the cooperative inner loop. */
    const int geometry_changed = (g->N != N || g->r != r || !g->program);
    if (!geometry_changed && g->capacity && (!batch_hint || batch_hint == g->capacity)) {
        if (capacity) *capacity = g->capacity;
        return 0;
    }

    release_buffers(g);
    if (build_specialized_program(g, N, r, err, errlen) != 0) return -1;

    const uint64_t state_bytes = 128ULL * (uint64_t)r;
    const uint64_t vbytes = state_bytes * (uint64_t)N;
    const uint64_t scratch_bytes = state_bytes < 256ULL ? 256ULL : state_bytes;
    const uint64_t ctx_bytes = 48ULL;
    const uint64_t workspace = MAX_PW + sizeof(cl_uint) + 64ULL
                             + state_bytes + scratch_bytes
                             + S_WORDS * sizeof(cl_ulong)
                             + ctx_bytes + 32ULL;

    uint64_t reserve = g->global_mem / 10ULL;
    if (reserve < 512ULL * ONE_MIB) reserve = 512ULL * ONE_MIB;
    if (reserve >= g->global_mem) reserve = g->global_mem / 5ULL;
    const uint64_t usable = g->global_mem - reserve;
    uint64_t cap_mem = usable / (vbytes + workspace);

    const uint64_t alloc_limit = (g->max_alloc * 95ULL) / 100ULL;
    const uint64_t slots_per_segment = vbytes ? alloc_limit / vbytes : 0;
    uint64_t cap_alloc = slots_per_segment * 4ULL;
    uint64_t cap = cap_mem;
    if (cap > cap_alloc) cap = cap_alloc;
    if (cap > 4096ULL) cap = 4096ULL;
    if (batch_hint) {
        if (cap > batch_hint) cap = batch_hint;
    } else {
        cap = (cap * 95ULL) / 100ULL;
        if (cap >= 32ULL) cap = (cap / 32ULL) * 32ULL;
    }
    if (cap == 0)
        return seterr(err, errlen,
                      "GPU cannot allocate one yescrypt V region: need %.2f MiB/candidate, max allocation %.2f MiB",
                      (double)vbytes / ONE_MIB, (double)g->max_alloc / ONE_MIB);
    if (cap >= 4ULL) cap = (cap / 4ULL) * 4ULL;
    if (cap == 0) cap = 1;

    g->capacity = (uint32_t)cap;
    const uint64_t c = cap;

    g->passwords = mkbuf(g, CL_MEM_READ_ONLY, (size_t)(c * MAX_PW), "passwords", err, errlen); if (!g->passwords) goto fail;
    g->pw_lens   = mkbuf(g, CL_MEM_READ_ONLY, (size_t)(c * sizeof(cl_uint)), "pw_lens", err, errlen); if (!g->pw_lens) goto fail;
    g->salt      = mkbuf(g, CL_MEM_READ_ONLY, 64, "salt", err, errlen); if (!g->salt) goto fail;
    g->P         = mkbuf(g, CL_MEM_READ_WRITE, (size_t)(c * state_bytes), "P", err, errlen); if (!g->P) goto fail;
    g->scratch   = mkbuf(g, CL_MEM_READ_WRITE, (size_t)(c * scratch_bytes), "scratch", err, errlen); if (!g->scratch) goto fail;
    g->S         = mkbuf(g, CL_MEM_READ_WRITE, (size_t)(c * S_WORDS * sizeof(cl_ulong)), "S", err, errlen); if (!g->S) goto fail;
    g->yctx      = mkbuf(g, CL_MEM_READ_WRITE, (size_t)(c * ctx_bytes), "context", err, errlen); if (!g->yctx) goto fail;

    for (int seg = 0; seg < 4; seg++) {
        const uint64_t segcount = (c + (uint64_t)(3 - seg)) / 4ULL;
        char label[16];
        snprintf(label, sizeof(label), "V%d", seg);
        g->V[seg] = mkbuf(g, CL_MEM_READ_WRITE, (size_t)(segcount * vbytes), label, err, errlen);
        if (!g->V[seg]) goto fail;
    }

    g->out = mkbuf(g, CL_MEM_WRITE_ONLY, (size_t)(c * 32ULL), "output", err, errlen); if (!g->out) goto fail;
    if (capacity) *capacity = g->capacity;
    return 0;

fail:
    release_buffers(g);
    return -1;
}

#define CLCHK(call, what) do { \
    cl_int _rc = (call); \
    if (_rc != CL_SUCCESS) return seterr(err, errlen, "%s failed: %d", what, _rc); \
} while (0)

#define SET_MEM(kernel, argno, memobj, label) do { \
    cl_mem _m = (memobj); \
    CLCHK(p_clSetKernelArg((kernel), (argno)++, sizeof(_m), &_m), label); \
} while (0)

#define SET_U32(kernel, argno, value, label) do { \
    cl_uint _v = (cl_uint)(value); \
    CLCHK(p_clSetKernelArg((kernel), (argno)++, sizeof(_v), &_v), label); \
} while (0)

int ycl_gpu_hash(ycl_gpu_ctx *g,
                 const unsigned char *passwords,
                 const uint32_t *pw_lens,
                 uint32_t count,
                 const unsigned char *salt,
                 uint32_t salt_len,
                 unsigned char *out,
                 char *err, size_t errlen) {
    if (!g || !g->capacity || !g->program || count == 0 || count > g->capacity)
        return seterr(err, errlen, "bad GPU batch count %u (capacity %u)", count, g ? g->capacity : 0);
    if (salt_len > 64) return seterr(err, errlen, "salt too long for GPU (%u)", salt_len);
    if (atomic_load_explicit(&g->cancel_requested, memory_order_relaxed))
        return YCL_GPU_CANCELLED;

    /* Queue transfers without host-side synchronization.  The command queue is
     * in-order, and the final blocking read keeps the Go-owned host buffers
     * alive until all three GPU stages have consumed them. */
    CLCHK(p_clEnqueueWriteBuffer(g->queue, g->passwords, CL_FALSE, 0,
                                 (size_t)count * MAX_PW, passwords, 0, NULL, NULL),
          "write passwords");
    CLCHK(p_clEnqueueWriteBuffer(g->queue, g->pw_lens, CL_FALSE, 0,
                                 (size_t)count * sizeof(cl_uint), pw_lens, 0, NULL, NULL),
          "write password lengths");
    unsigned char saltbuf[64] = {0};
    if (salt_len) memcpy(saltbuf, salt, salt_len);
    CLCHK(p_clEnqueueWriteBuffer(g->queue, g->salt, CL_FALSE, 0, 64,
                                 saltbuf, 0, NULL, NULL),
          "write salt");

    /* Init: one work-item per candidate. */
    cl_uint a = 0;
    SET_MEM(g->init_kernel, a, g->passwords, "set init passwords");
    SET_MEM(g->init_kernel, a, g->pw_lens,   "set init lengths");
    SET_MEM(g->init_kernel, a, g->salt,      "set init salt");
    SET_U32(g->init_kernel, a, salt_len,     "set init salt_len");
    SET_U32(g->init_kernel, a, count,        "set init count");
    SET_MEM(g->init_kernel, a, g->P,         "set init P");
    SET_MEM(g->init_kernel, a, g->scratch,   "set init scratch");
    SET_MEM(g->init_kernel, a, g->S,         "set init S");
    SET_MEM(g->init_kernel, a, g->yctx,      "set init context");
    SET_MEM(g->init_kernel, a, g->V[0],      "set init V0");
    SET_MEM(g->init_kernel, a, g->V[1],      "set init V1");
    SET_MEM(g->init_kernel, a, g->V[2],      "set init V2");
    SET_MEM(g->init_kernel, a, g->V[3],      "set init V3");
    size_t global_init = count;
    CLCHK(p_clEnqueueNDRangeKernel(g->queue, g->init_kernel, 1, NULL,
                                   &global_init, NULL, 0, NULL, NULL),
          "launch yescrypt init");

    /* Split the long SMix into resumable chunks. 2048 iterations gives Ctrl+C
     * a chance to stop between launches without materially changing GPU throughput. */
    const uint64_t nloop = ((((uint64_t)g->N + 2ULL) / 3ULL) + 1ULL) & ~1ULL;
    uint64_t remaining = (uint64_t)g->N + nloop;
    const size_t local_loop = 32;
    const size_t global_loop = (size_t)count * local_loop;
    while (remaining) {
        if (atomic_load_explicit(&g->cancel_requested, memory_order_relaxed)) {
            (void)p_clFinish(g->queue);
            return YCL_GPU_CANCELLED;
        }

        const uint32_t chunk = (remaining > 2048ULL) ? 2048U : (uint32_t)remaining;
        a = 0;
        SET_U32(g->loop_kernel, a, count,   "set loop count");
        SET_U32(g->loop_kernel, a, chunk,   "set loop chunk");
        SET_MEM(g->loop_kernel, a, g->P,    "set loop P");
        SET_MEM(g->loop_kernel, a, g->S,    "set loop S");
        SET_MEM(g->loop_kernel, a, g->yctx, "set loop context");
        SET_MEM(g->loop_kernel, a, g->V[0], "set loop V0");
        SET_MEM(g->loop_kernel, a, g->V[1], "set loop V1");
        SET_MEM(g->loop_kernel, a, g->V[2], "set loop V2");
        SET_MEM(g->loop_kernel, a, g->V[3], "set loop V3");
        CLCHK(p_clEnqueueNDRangeKernel(g->queue, g->loop_kernel, 1, NULL,
                                       &global_loop, &local_loop, 0, NULL, NULL),
              "launch yescrypt cooperative loop");
        CLCHK(p_clFinish(g->queue), "wait for yescrypt cooperative loop");

        if (atomic_load_explicit(&g->cancel_requested, memory_order_relaxed))
            return YCL_GPU_CANCELLED;
        remaining -= chunk;
    }

    if (atomic_load_explicit(&g->cancel_requested, memory_order_relaxed))
        return YCL_GPU_CANCELLED;

    /* Final: one work-item per candidate. */
    a = 0;
    SET_U32(g->final_kernel, a, count,      "set final count");
    SET_MEM(g->final_kernel, a, g->P,       "set final P");
    SET_MEM(g->final_kernel, a, g->scratch, "set final scratch");
    SET_MEM(g->final_kernel, a, g->yctx,    "set final context");
    SET_MEM(g->final_kernel, a, g->out,     "set final output");
    size_t global_final = count;
    CLCHK(p_clEnqueueNDRangeKernel(g->queue, g->final_kernel, 1, NULL,
                                   &global_final, NULL, 0, NULL, NULL),
          "launch yescrypt final");

    CLCHK(p_clEnqueueReadBuffer(g->queue, g->out, CL_TRUE, 0,
                                (size_t)count * 32ULL, out, 0, NULL, NULL),
          "read yescrypt output");
    CLCHK(p_clFinish(g->queue), "clFinish");
    return 0;
}

#undef SET_U32
#undef SET_MEM
#undef CLCHK
