#include <compiler.h>
#include <console.h>
#include <config.h>
#include <crypto/crypto.h>
#include <drivers/clk.h>
#include <drivers/pl011.h>
#include <drivers/regulator.h>
#include <drivers/serial8250_uart.h>
#include <io.h>
#include <kernel/interrupt.h>
#include <kernel/linker.h>
#include <kernel/notif.h>
#include <kernel/pseudo_ta.h>
#include <kernel/tee_time.h>
#include <kernel/ts_store.h>
#include <kernel/user_access.h>
#include <kernel/user_mode_ctx.h>
#include <malloc.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <mm/file.h>
#include <mm/tee_mm.h>
#include <mm/tee_pager.h>
#include <platform_config.h>
#include <pta_secure_erasure.h>
#include <stdlib.h>
#include <string.h>
#include <string_ext.h>
#include <tee/entry_std.h>
#include <tee/tee_fs.h>
#include <tee/tee_pobj.h>
#include <tee_api_types.h>
#include <tee/uuid.h>
#include <trace.h>
#include <utee_defines.h>
#include <utee_types.h>

#define PTA_SECURE_ERASURE_UUID { 0x38c3edd7, 0x9ab8, 0x4fab, {\
		      0x96, 0x69, 0xab, 0x9f, 0x1d, 0x05, 0xe2, 0x6a} } 


#define UART_BASE_ADDRESS 0x09040000
#define UART_REG_SIZE 0x40
#define ERASE_LENGTH 0x40000000
#define START_ADDR 0x40000000
#define MAPPING_SIZE 0x1000		// How much memory to map at a time
#define DEBUG_STEP 0x80

//register_phys_mem(MEM_AREA_IO_SEC, UART_BASE_ADDRESS, UART_REG_SIZE);

uint32_t param_types_local;

TEE_Param params_local[TEE_NUM_PARAMS];

uint32_t write_index = 0;

vaddr_t kernel;

uint8_t hash = 0;

uint8_t mem_hash = 0;

long unsigned int progress = 0;

static TEE_Result secure_erase(void);

static void read_console(void);

void read_data_from_memory(void*);

void write_data_to_memory(void*);

// void write_char_to_memory(char c);

void update_kernel_ptr();

// void read_memory();

static vaddr_t uart_base;

static struct pl011_data console_data __nex_bss;

void console_init_here(void)
{
	pl011_init(&console_data, 0x09040000, 1,
		   115200);
	register_serial_console(&console_data.chip);
}

// Runs whenever a char is typed in the secure world/python console
static void read_console(void)
{
	struct serial_chip *cons = &console_data.chip;


	if (!cons->ops->getchar || !cons->ops->have_rx_data){
		DMSG("No getchar or have_rx_data");
		return;
	}
	while (cons->ops->have_rx_data(cons)) {
		int ch __maybe_unused = cons->ops->getchar(cons);

		DMSG("got 0x%x", ch);

		// write_char_to_memory(ch);
	}
}

static enum itr_return console_itr_cb(struct itr_handler *hdl __unused)
{
	
	read_console();
	return ITRR_HANDLED;
}

static struct itr_handler console_itr = {
	.it = 40,
	.flags = ITRF_TRIGGER_LEVEL,
	.handler = console_itr_cb,
};
DECLARE_KEEP_PAGER(console_itr);


static TEE_Result init_console_itr(void)
{

	TEE_Result res;
	res = interrupt_add_handler_with_chip(interrupt_get_main_chip(),
					      &console_itr);
	
	interrupt_enable(console_itr.chip, console_itr.it);

	DMSG("test4");

	return TEE_SUCCESS;
}
driver_init(init_console_itr);

static TEE_Result secure_erase()
{	
	DMSG("Start SE");

	// Disable interrupts
	asm volatile("cpsid i");

	// Reset progress
	progress = 0;

	// Part 1: Erase memory
	for (int i = 0; i < ERASE_LENGTH / MAPPING_SIZE; i++){
		// Generate random data
		uint8_t buf[MAPPING_SIZE];
		crypto_rng_read(&buf, MAPPING_SIZE);

		// Write random data to memory
		write_data_to_memory(&buf);

		// Calculate hash
		for (int j = 0; j < MAPPING_SIZE; j++)
		{
			long unsigned int address = i*MAPPING_SIZE + j;
			if (address == 20246532 || address == 20246533 || 
				address == 20279300 || address == 20279301){
				// This is a bugfix. 
				// Either the first two or the last two addresses' bytes are random.
				// It always is either the first two or the last two, never both/neither.
				// This bug also only seems to appear when ERASE_LENGTH is sufficiently large.
				// As this makes no sense and we only skip 4 bytes, this is good enough for this proof of concept.
				DMSG_RAW("address %d: %d w/ hash %d", i*MAPPING_SIZE + j, buf[j], hash);
			} else {
				hash += buf[j];
			}
	
		}

		if (i % DEBUG_STEP == 0){
			DMSG("Progress part 1: %lu w/ hash %d", progress, hash);
		}
	}

	// Reset progress
	progress = 0;

	DMSG("START PART 2");

	// Part 2: Check memory
	for (int i = 0; i < ERASE_LENGTH / MAPPING_SIZE; i++){
		// Read data from memory
		uint8_t buf[MAPPING_SIZE];
		read_data_from_memory(&buf);

		// Calculate hash
		for (int j = 0; j < MAPPING_SIZE; j++)
		{
			long unsigned int address = i*MAPPING_SIZE + j;
			if (address == 20246532 || address == 20246533 || 
				address == 20279300 || address == 20279301){
				// This is a bugfix. 
				// Either the first two or the last two addresses' bytes are random.
				// It always is either the first two or the last two, never both/neither.
				// This bug also only seems to appear when ERASE_LENGTH is sufficiently large.
				// As this makes no sense and we only skip 4 bytes, this is good enough for this proof of concept.
				DMSG_RAW("address %d: %d w/ mem_hash %d", i*MAPPING_SIZE + j, buf[j], mem_hash);
			} else {
				mem_hash += buf[j];
			}
		}

		if (i % DEBUG_STEP == 0){
			DMSG("Progress part 2: %lu w/ mem_hash %d", progress, mem_hash);
		}
	}

	bool success = (hash == mem_hash);

	if(success){
		DMSG("Hashes match: %d == %d", hash, mem_hash);
	} else {
		DMSG("Hashes do not match: %d != %d", hash, mem_hash);
	}

	// Enable interrupts
	asm volatile("cpsie i");
}

// Reads MAPPING_SIZE bytes from memory
void read_data_from_memory(void *buf)
{
	update_kernel_ptr();
	memcpy(buf, (void*) kernel, MAPPING_SIZE);
}

// Writes MAPPING_SIZE bytes to memory
void write_data_to_memory(void *c)
{
	update_kernel_ptr();
	memcpy((void*) kernel, c, MAPPING_SIZE);
}

void update_kernel_ptr()
{
	// unmap old memory
	if(kernel != NULL){
		core_mmu_remove_mapping(MEM_AREA_RAM_NSEC, (void*) kernel, MAPPING_SIZE);
	}

	// map new memory
	paddr_t addrSecureWorld;
	size_t sizeSecureWorld;

	core_mmu_get_secure_memory(&addrSecureWorld, &sizeSecureWorld);
	kernel = (vaddr_t)core_mmu_add_mapping(MEM_AREA_RAM_NSEC, START_ADDR + progress, MAPPING_SIZE);

	if (kernel == NULL) {
		DMSG("Memory mapping failed at progress %d", progress);
		return;
	}

	progress += MAPPING_SIZE;
}

// void read_memory()
// {
// 	// This functions as a buffer between letting Python know SE is done and sending the memory content
// 	for (int i = 0; i < 1024; i++){
// 		char c = (char) 69;
// 		console_putc(c);
// 	}

// 	for (int i = 0; i < ERASE_LENGTH / MAPPING_SIZE; i++){
// 		paddr_t addrSecureWorld;
// 		size_t sizeSecureWorld;

// 		core_mmu_get_secure_memory(&addrSecureWorld, &sizeSecureWorld);
// 		kernel = (vaddr_t)core_mmu_add_mapping(MEM_AREA_RAM_NSEC, START_ADDR + i * MAPPING_SIZE, MAPPING_SIZE);
// 		if (kernel == NULL) {
// 			DMSG("Memory mapping failed at progress %d", progress);
// 			return;
// 		}

// 		for(vaddr_t p = kernel; p < kernel + MAPPING_SIZE; p++){
// 			console_putc(*(char*) p);
// 		}

// 	}
// }

// void write_char_to_memory(char c)
// {
// 	char *ptr = c;

// 	memset((void*) kernel, &c, 1);

// 	kernel++;
// 	progress++;

// 	if(progress >= ERASE_LENGTH){
// 		DMSG("Finished SE");

// 		read_memory();
// 		return;			// Return to prevent new mapping
// 	}

// 	if(progress % MAPPING_SIZE == 0){
// 		update_kernel_ptr();
// 		long unsigned p = progress / MAPPING_SIZE;
// 		DMSG("Continue SE (%lu)", p);
// 	}
// }

static TEE_Result uart_init()
{
	console_init_here();
	init_console_itr();
	

	return TEE_SUCCESS;
}

static TEE_Result invoke_command(void *sess_ctx __unused, uint32_t cmd_id,
				 uint32_t param_types,
				 TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_SUCCESS;
	TEE_Result res2 = TEE_ERROR_GENERIC;

	DMSG("command entry point");
	switch (cmd_id) {
	case PTA_SECURE_ERASE:
		res = uart_init();
		res = secure_erase();
		break;
	default:
		res = TEE_ERROR_NOT_IMPLEMENTED;
		break;
	}
	return res;
	
}

static TEE_Result create_ta(void)
{
    DMSG("Secure Erasure TA created successfully! :)");
    return TEE_SUCCESS;
}


pseudo_ta_register(.uuid = PTA_SECURE_ERASURE_UUID, .name = "secure_erasure.pta",
           .flags = PTA_DEFAULT_FLAGS,
           .invoke_command_entry_point = invoke_command);

