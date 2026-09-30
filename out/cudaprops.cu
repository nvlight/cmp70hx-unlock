// cudaprops.cu — прямой запрос свойств CUDA-устройства.
//
// Зачем он нужен. Мы дважды ловились на том, что GPU-Z показывает ерунду:
// сначала «Boost 1395» у карты, реально идущей на 1545, потом «TMU 120 против
// 224» у 50HX, где 224 физически невозможно. После этого «число SM» в
// наших расчётах — тоже цифра GPU-Z, которой мы не имеем права доверять.
//
// cudaGetDeviceProperties обращается к драйверу напрямую и отдаёт конфиг,
// который драйвер реально выставил. Это единственный источник, которому
// здесь можно верить.
//
// Вывод построчный key=value, только ASCII: файлы снимаются с двух карт и
// потом сравниваются diff-ом, поэтому никаких таблиц и рамок.
//
// Сборка: nvcc -O2 -o cudaprops.exe cudaprops.cu -cudart static

#include <cstdio>
#include <cuda_runtime.h>

#define QUERY(name, attr)                                                    \
    do {                                                                     \
        int v = 0;                                                          \
        cudaError_t e = cudaDeviceGetAttribute(&v, attr, dev);               \
        if (e == cudaSuccess) {                                             \
            printf("  %-34s = %d\n", name, v);                              \
        } else {                                                             \
            printf("  %-34s = <error %s>\n", name, cudaGetErrorString(e));  \
        }                                                                    \
    } while (0)

int main()
{
    int n = 0;
    cudaError_t e = cudaGetDeviceCount(&n);
    if (e != cudaSuccess || n == 0) {
        printf("cudaGetDeviceCount failed: %s (devices=%d)\n",
               cudaGetErrorString(e), n);
        return 1;
    }
    printf("devices.visible = %d\n", n);

    for (int dev = 0; dev < n; dev++) {
        cudaDeviceProp p;
        cudaError_t pe = cudaGetDeviceProperties(&p, dev);
        if (pe != cudaSuccess) {
            printf("device %d: properties failed: %s\n", dev, cudaGetErrorString(pe));
            continue;
        }
        printf("\n[device %d]\n", dev);
        printf("  %-34s = %s\n", "name", p.name);
        printf("  %-34s = %d.%d\n", "compute_capability", p.major, p.minor);
        printf("  %-34s = %d\n", "multiProcessorCount", p.multiProcessorCount);

        // Ресурсы на один SM. Это то, ради чего запрос и делается: если
        // драйвер режет что-то на уровне SM, здесь будет видно.
        QUERY("maxThreadsPerMultiProcessor", cudaDevAttrMaxThreadsPerMultiProcessor);
        QUERY("maxRegistersPerMultiprocessor", cudaDevAttrMaxRegistersPerMultiprocessor);
        QUERY("maxSharedMemoryPerMultiprocessor", cudaDevAttrMaxSharedMemoryPerMultiprocessor);
        QUERY("maxBlocksPerMultiProcessor", cudaDevAttrMaxBlocksPerMultiprocessor);
        QUERY("warpSize", cudaDevAttrWarpSize);
        QUERY("maxThreadsPerBlock", cudaDevAttrMaxThreadsPerBlock);
        QUERY("regsPerBlock", cudaDevAttrMaxRegistersPerBlock);
        QUERY("sharedMemPerBlock", cudaDevAttrMaxSharedMemoryPerBlock);

        // Кэш и память. В CUDA 13 поля clockRate и memoryClockRate убраны из
        // cudaDeviceProp, поэтому берём их через атрибуты - единственный путь,
        // который компилируется на 13.3.
        int busW = 0, memClk = 0, smClk = 0, l2 = 0;
        cudaDeviceGetAttribute(&l2, cudaDevAttrL2CacheSize, dev);
        cudaDeviceGetAttribute(&busW, cudaDevAttrGlobalMemoryBusWidth, dev);
        cudaDeviceGetAttribute(&memClk, cudaDevAttrMemoryClockRate, dev);
        cudaDeviceGetAttribute(&smClk, cudaDevAttrClockRate, dev);

        printf("  %-34s = %d bytes\n", "l2CacheSize", l2);
        printf("  %-34s = %d bit\n", "memoryBusWidth", busW);
        printf("  %-34s = %d kHz\n", "memoryClockRate", memClk);
        printf("  %-34s = %d kHz\n", "clockRate", smClk);
        printf("  %-34s = %llu bytes\n", "totalGlobalMem",
               (unsigned long long)p.totalGlobalMem);

        // Признаки «карта не совсем та, за кем себя выдаёт».
        QUERY("integrated", cudaDevAttrIntegrated);
        QUERY("isMultiGpuBoard", cudaDevAttrIsMultiGpuBoard);
        QUERY("concurrentKernels", cudaDevAttrConcurrentKernels);
        QUERY("cooperativeLaunch", cudaDevAttrCooperativeLaunch);
        QUERY("unifiedAddressing", cudaDevAttrUnifiedAddressing);
        QUERY("asyncEngineCount", cudaDevAttrAsyncEngineCount);
        QUERY("canMapHostMemory", cudaDevAttrCanMapHostMemory);
        QUERY("ECCEnabled", cudaDevAttrEccEnabled);

        // Производное: элементарная пропускная способность памяти в ГБ/с.
        // ВАЖНО: для GDDR6X/PAM3 memoryClockRate из CUDA - это тактовый вход,
        // а не эффективная скорость передачи, поэтому число НЕЛЬЗЯ сравнивать
        // с маркировкой GDDR6 напрямую. Рядом печатается сырьё, чтобы решение
        // принималось по числам, а не по подписям.
        double gbs = 2.0 * (double)memClk * 1000.0
                     * (double)busW / 8.0 / 1e9;
        printf("  %-34s = %.1f GB/s (2x, raw clock)\n", "derived_mem_bandwidth", gbs);
        printf("  %-34s = %d MHz\n", "derived_sm_clock", smClk / 1000);

        printf("  %-34s = %d\n", "deviceOrdinal", dev);
        int pciBus = -1, pciDev = -1, pciDomain = -1;
        cudaDeviceGetAttribute(&pciBus, cudaDevAttrPciBusId, dev);
        cudaDeviceGetAttribute(&pciDev, cudaDevAttrPciDeviceId, dev);
        cudaDeviceGetAttribute(&pciDomain, cudaDevAttrPciDomainId, dev);
        printf("  %-34s = %04x:%02x:%02x.0\n", "pci", p.pciDomainID, p.pciBusID, p.pciDeviceID);
        (void)pciBus; (void)pciDev; (void)pciDomain;
    }

    return 0;
}
