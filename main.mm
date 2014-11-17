/*
 *
 * Author: Grant Douglas (@Hexploitable)
 *
 * Description: Use this when the binary has been stripped and the function isn't exported.
 *              I.e. when you can't use MSFindSymbol().
 *
 * Usage:       Open app in disassembler, grab first 16 bytes (might need to tweak this)
 *              of your target method. Use this as signature.
 *
 */
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <mach/vm_map.h>
#include <mach/vm_region.h>
#include <mach-o/dyld_images.h>
#include <string.h>
#include <limits.h>
#include <errno.h>

#define red   "\033[1;31m"        /* 0 -> normal ;  31 -> red */
#define redU   "\033[4;31m"
#define cyan  "\033[0;36m"        /* 1 -> bold ;  36 -> cyan */
#define cyanU "\033[4;36m"
#define green "\033[0;32m"        /* 4 -> underline ;  32 -> green */
#define yellow "\033[0;33m"
#define yellowU "\033[4;33m"
#define blue  "\033[0;34m"        /* 9 -> strike ;  34 -> blue */
#define blueU "\033[4;34m"
#define black  "\033[0;30m"
#define brown  "\033[0;33m"
#define magenta  "\033[0;35m"
#define gray  "\033[0;37m"
#define uline   "\033[4;0m"
#define none   "\033[0m"        /* to flush the previous property */


int pid = 0;
int g_pid = 0;
int needleLen = 0;
int verbose = 0;
unsigned char *nBuffer;
char *version = "1.0";


void printHeader(void)
{
    printf(red);

    //ROW1
    printf(" __   __ ");
    printf(" _______ ");
    printf(" __   __ ");
    printf(" _______ ");
    printf(" _______ ");
    printf(" _______ ");
    printf(" __    _ \n");

    //ROW2
    printf("|  |_|  |");
    printf("|       |");
    printf("|  |_|  |");
    printf("|       |");
    printf("|       |");
    printf("|   _   |");
    printf("|  |  | |\n");

    //ROW3
    printf("|       |");
    printf("|    ___|");
    printf("|       |");
    printf("|  _____|");
    printf("|       |");
    printf("|  |_|  |");
    printf("|   |_| |\n");

    //ROW4
    printf("|       |");
    printf("|   |___ ");
    printf("|       |");
    printf("| |_____ ");
    printf("|       |");
    printf("|       |");
    printf("|       |\n");

    printf(cyan);

    //ROW5
    printf("|       |");
    printf("|    ___|");
    printf("|       |");
    printf("|_____  |");
    printf("|      _|");
    printf("|       |");
    printf("|  _    |\n");

    //ROW6
    printf("| ||_|| |");
    printf("|   |___ ");
    printf("| ||_|| |");
    printf(" _____| |");
    printf("|     |_ ");
    printf("|   _   |");
    printf("| | |   |\n");

    //ROW7
    printf("|_|   |_|");
    printf("|_______|");
    printf("|_|   |_|");
    printf("|_______|");
    printf("|_______|");
    printf("|__| |__|");
    printf("|_|  |__|\n");

    printf("\n%sAuthor: %sGrant Douglas (@Hexploitable)%s", none, cyan, none);
    printf("\nVersion: %s%s%s\n\n", cyan, version, none);
}

void printUsage(void) 
{
    printf("Usage:\n-------\n");
    printf("Verbose mode: -v\n");
    printf("Dump memory to a file: memscan [-p <PID>] -d\n");
    printf("Search memory for a sequence of bytes: memscan [-p <PID>] -s <INPUT_FILE>\n");
}


extern kern_return_t vm_region
(
     vm_map_t target_task,
     mach_vm_address_t *address,
     mach_vm_size_t *size,
     vm_region_flavor_t flavor,
     vm_region_info_t info,
     mach_msg_type_number_t *infoCnt,
     mach_port_t *object_name
 );

extern kern_return_t vm_read
(
     vm_map_t target_task,
     mach_vm_address_t address,
     mach_vm_size_t size,
     Size data_out,
     mach_vm_size_t data_count
 );

extern kern_return_t vm_read_overwrite
(
     vm_map_t target_task,
     mach_vm_address_t address,
     mach_vm_size_t size,
     mach_vm_address_t data,
     mach_vm_size_t *outsize
 );

mach_vm_address_t *scanMem(int pid, mach_vm_address_t addr, mach_msg_type_number_t size, int shouldPrint)
{
    task_t t;
    task_for_pid(mach_task_self(), pid, &t);
    mach_msg_type_number_t dataCnt = size;
    mach_vm_address_t max = addr + size;
    int bytesRead = 0;
    kern_return_t kr_val;
    pointer_t strt;
    mach_vm_address_t memStart = 0;
    uint32_t sz = 0;
    FILE *f = fopen("output.bin", "w+");

    if (shouldPrint == 1)
    {
    	unsigned char *readbuffer = NULL;
    	readbuffer = (unsigned char*)malloc(size);

	    kr_val = vm_read(t, addr, size, &strt, &sz);

        if (kr_val == KERN_SUCCESS)
        {
        	printf("Size of read: %d\n", sz);
            memcpy(readbuffer, (const void*)strt, sz);
			printf("readbuffer: %02x\n", readbuffer);
        }
        else 
        {
        	printf("KR: %d\n", kr_val);
        	printf("Size: %d\n", size);
        }
        fwrite(readbuffer, size, 1, f);
    	fclose(f);
	    exit(0);
    }
    else 
    {
        unsigned char buffer[needleLen];
        FILE *f = fopen("output.bin", "w+");
        while (bytesRead < size)
        {
            if ((kr_val = vm_read(t, addr, sizeof(unsigned char), &strt, &sz)) == KERN_SUCCESS)
            {
                memcpy(buffer, (const void *)strt, sz);
                if (memcmp(buffer, nBuffer, needleLen) == 0)
                {
                    fflush(stdout);
                    return (unsigned long long *)addr;
                }
                else
                    printf("[%s-%s] %s%p%s ---> vm_read()\r", red, none, redU, addr, none);
                fflush(stdout);
            }
            else
            {
                printf("[%s-%s] %s%p%s ---> vm_read()\r", red, none, redU, addr, none);
                fflush(stdout);
            }
            addr += sizeof(unsigned char);
            bytesRead += sizeof(unsigned char);
        }
        printf("[%si%s] Scanning ended without a match.\r\n", yellow, none);
        fflush(stdout);
    }
    return NULL;
}

unsigned int *getMemRegions(task_t task, vm_address_t address, int shouldPrint)
{
    kern_return_t kret;
    vm_region_basic_info_data_t info;
    vm_size_t size;
    mach_port_t object_name;
    mach_msg_type_number_t count;
    vm_address_t firstRegionBegin;
    vm_address_t lastRegionEnd;
    vm_size_t fullSize = 0;
    count = VM_REGION_BASIC_INFO_COUNT_64;
    int regionCount = 0;
    int flag = 0;
    
    printf("[%si%s] Cycling through memory regions, please wait...\n", yellow, none);

    while (flag == 0)
    {
        char *name = "Region: ";
        char cated_string[15];
        sprintf(cated_string,"%s%d", name, regionCount);
        if (verbose)
            printf("Region: %d\n", regionCount);
        FILE *f = fopen("output.bin", "a+");
        fwrite(cated_string, 10, 1, f);

        //Attempts to get the region info for given task
        kret = vm_region(task, &address, &size, VM_REGION_BASIC_INFO, (vm_region_info_t) &info, &count, &object_name);
        if (kret == KERN_SUCCESS)
        {
            if (regionCount == 0)
            {
                firstRegionBegin = address;
            }
            regionCount += 1;
            if (shouldPrint == 1)
            {
                task_t t;
                task_for_pid(mach_task_self(), pid, &t);
                kern_return_t kr_val;
                pointer_t strt;
                uint32_t sz = 0;
                unsigned char *readbuffer = NULL;
                readbuffer = (unsigned char*)malloc(size);

                kr_val = vm_read(t, address, size, &strt, &sz);

                if (kr_val == KERN_SUCCESS)
                {
                    if (verbose)
                        printf("Region start: %p\nSize of read: %d\n\n", address, sz);
                    memcpy(readbuffer, (const void*)strt, sz);
                }
                else 
                {
                    if (verbose)
                        printf("Region start: %p\nSize of read: %d\n\n", address, sz);
                }
                fwrite(readbuffer, size, 1, f);
                if (verbose)
                    printf("[%si%s] Memory dumped: %s\r\n", yellow, none, cated_string);

            }
            fullSize += size;
            address += size;
        }
        else
            flag = 1;
        fclose(f);

    }
    if (shouldPrint == 1)
    {
        printf("[%si%s] Operation Completed.\r\n", blue, none);
        exit(0);
    }
    lastRegionEnd = address;
    printf("[%si%s] Proc Space: %s%p%s - %s%p%s\n", yellow, none, yellowU, firstRegionBegin, none, blueU, lastRegionEnd, none);
    
    unsigned int *ptrToFunc = (unsigned int *)scanMem(pid, firstRegionBegin, fullSize, shouldPrint);
    return ptrToFunc;
}

int main(int argc, char** argv) {
    kern_return_t rc;
    mach_port_t task;
    mach_vm_address_t addr = 1;
    
    int shouldDump = 0;
    char *inputFile = NULL;
    printHeader();
    while (1) 
    {
        char c;
        c = getopt(argc, argv, "ds:vp:");
        if (c == -1)
            break;
        switch (c) 
        {
            case 'd':
                shouldDump = 1;
                break;
            case 's':
                inputFile = optarg;
                break;
            case 'p':
                pid = atoi(optarg);
                break;
            case 'v':
                verbose = 1;
                break;
            default:
                printUsage();
                break;
        }
    }

    argc -= optind;
    argv += optind;

    if (shouldDump == 0 && inputFile == NULL)
    {
        printUsage();
        exit(-1);
    }

    if (inputFile)
    {
        g_pid = pid; //Required for fw >= 6.0    
        rc = task_for_pid(mach_task_self(), pid, &task);
        if (rc)
        {
            fprintf(stderr, "[%s-%s] task_for_pid() failed, error %d - %s%s", red, none, rc, red, mach_error_string(rc), none);
            exit(1);
        }

        FILE *f = fopen(inputFile, "rb");
        if (f)
        {
            fseek(f, 0, SEEK_END);
            needleLen = ftell(f);
            fclose(f);
        }
        
        unsigned char buf[needleLen+1];
        FILE *fr;
        fr = fopen(inputFile, "rb");
        long int cnt = 0;
        while ((cnt = (long)fread(buf, sizeof(unsigned char), needleLen, fr))>0)
            nBuffer = buf;
        fclose(fr);

        printf("[%s+%s] PID: %s%d%s\n", green, none, blueU, pid, none);
        printf("[%si%s] Task: %s%d%s\n", yellow, none, blueU, task, none);
        printf("[%si%s] Attempting to search for bytes\n", yellow, none);
        printf("[%s+%s] Needle Length: %s%d%s %sbytes%s\n", green, none, blue, needleLen, none, blueU, none);
        unsigned int *sym = getMemRegions(task, addr, 0);
        if (sym != NULL)
            printf("\n\n[%s$%s] Located target function ---> %s%p%s\n\n", cyan, none, cyanU, sym, none);
        else
            printf("[%s-%s] Didn\'t find the function.\n", red, none);
    }
    else if (shouldDump)
    {
        g_pid = pid; //Required for fw >= 6.0    
        rc = task_for_pid(mach_task_self(), pid, &task);
        if (rc)
        {
            fprintf(stderr, "[%s-%s] task_for_pid() failed, error %d - %s%s", red, none, rc, red, mach_error_string(rc), none);
            exit(1);
        }

        printf("[%s+%s] PID: %s%d%s\n", green, none, blueU, pid, none);
        printf("[%si%s] Task: %s%d%s\n", yellow, none, blueU, task, none);
        printf("[%si%s] Attempting to print all strings found in memory\n", yellow, none);
        unsigned int *sym = getMemRegions(task, addr, 1);
    }
    else
    {
        printUsage();
        exit(-1);
    }
    return 0;
}
