/*
 *  host/umsdl.c
 *
 *  Copyright (c) Quantenna Communications Incorporated 2007.
 *  All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 *
 * An application for downloading images to Quantenna UMS devices via the
 * serial port.  Frames that are not downloaded correctly are retried until
 * they are accepted.
 *
 */

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/time.h>
#include <signal.h>

#include "umsdl.h"
#include "ums_platform.h"

/* Offset into the u-boot binary where the offset of the table holding
 * the load, execute & DRAM initialisation information is.
 */
#define UBOOT_TABLE_PTR 0x14

/* If no -c option is specified for u-boot image downloads, then the copy 
 * of the image for FLASH programming purposes is made at the load address
 * minus COPY_OFFSET.
 */
#define COPY_OFFSET (0x100000)

struct uboot_info {
	u8 magic[4]; 	/* "UBIS" */
	u32 load;	/* Image load address */
	u32 exec;	/* Image entry point */
	u32 copy_addr;	/* Copy of u-boot image used for programming FLASH */
	u32 ddr_start;	/* DDR controller values table start */
	u32 ddr_end;	/* DDR controller values table end */
	u32 name_len;	/* Size of DDR name field immediately following this */
};

static void register_handlers(int register_handlers);
int verbose;
int send_ctrlc = 0;

static unsigned char init_frame[] = 
		{ 0x00, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00, 0x00, 0x39 };

static void usage(void)
{
	fprintf(stderr, 
		"Usage1: cat <file> | umsdl [options] <serial port device>\n"
		"  <file> should be generated by bin2ums.\n"
		"  -v print details of download (verbose mode).\n"
		"  -b <value> specifies the baud rate to use.\n"
		"  -t <value in ms> specifies the frame acknowledgement\n"
		"      timeout before retrying a frame (default is 500ms).\n"
		"  -p <value in ms> specifies the rebaud timeout.  If two\n"
		"      consecutive frames fail, then umsdl waits for this\n"
		"      period before resending.  This tells the receiver\n"
		"      to redetect the sending baud rate (default is 2sec).\n"
		"Usage2: umsdl [options] -f <binary file> -a <address> [-x <exec_addr>] <serial port device>\n"
		"  <binary file> is a raw binary file to convert and send\n"
		"  and <address> is the address to download it to.\n"
		"  If the -x option is specified then umsdl will tell the target to execute\n"
		"  the downloaded image at the address given.\n"
		"Usage3: umsdl [options] [-c addr] -u <bootloader> <serial port device>\n"
		"  <bootloader> is a raw binary bootloader file (u-boot.bin).\n"
		"  This option automatically sets-up the target DRAM before\n"
		"  downloading the bootloader into its normal location and\n"
		"  running it.  The user can then program the bootloader into\n"
		"  the target FLASH using the image copy made to the address\n"
		"  specified by the -c option.  If no -c option is given, then\n"
		"  the copy is made at the image load address minus 1MB.\n\n"
		"  To send ctrl-c to a downloaded application, use ctrl-\\.\n"
		);
}

static int poll_char(int serial_fd, unsigned long ms_timeout)
{
	struct timeval time;
	unsigned char ch;
	time_t seconds;
	suseconds_t usec;
	
	seconds = ms_timeout / 1000;
	usec = (ms_timeout - seconds * 1000) * 1000;

	gettimeofday(&time, NULL);
	usec += time.tv_usec;
	seconds += time.tv_sec + (usec / 1000000);
	usec %= 1000000;

	while (read(serial_fd, &ch, 1) == 0) {
		gettimeofday(&time, NULL);
		if ((time.tv_sec > seconds) || 
			((time.tv_sec == seconds) && (time.tv_usec >= usec))) {
			return EOF;
		}
	}
	return (unsigned int)ch;
}

static int baudrate_constant(int baud_rate)
{
	static struct { int baud; int speed; } bauds[] = {
		{ 1200, B1200 },
		{ 2400, B2400 },
		{ 4800, B4800 },
		{ 9600, B9600 },
		{ 19200, B19200 },
		{ 38400, B38400 },
		{ 57600, B57600 },
		{ 115200, B115200 },
	};
	int i;
	
	for (i = 0; i < sizeof(bauds) / sizeof(bauds[0]); i++) {
		if (bauds[i].baud == baud_rate) {
			return bauds[i].speed;
		}
	}
	return -1;
}

static unsigned char get_escaped_char(unsigned char **ppc)
{
	unsigned char ch;
	
	ch = **ppc;
	(*ppc)++;
	if (ch == ESC_CHAR) {
		ch = ~**ppc;
		(*ppc)++;
	}
	return ch;
}

static void parse_frame_hdr(unsigned char *buf, u32 *paddr, u8 *plen)
{
	u8 len;
	u32 addr;
	unsigned char *p;
	
	p = buf;
	addr = get_escaped_char(&p);
	addr += (u32)get_escaped_char(&p) << 8;
	addr += (u32)get_escaped_char(&p) << 16;
	addr += (u32)get_escaped_char(&p) << 24;
	
	if (paddr) {
		*paddr = addr;
	}
	
	len = get_escaped_char(&p);
	if (plen) {
		*plen = len;
	}
}

static int nonblock(int state, int flag)
{
	struct termios ttystate;
	int lflag;
	
	tcgetattr(STDIN_FILENO, &ttystate);
	if (state)
	{
		//turn off canonical mode
		lflag = ttystate.c_lflag;
		ttystate.c_lflag = lflag & ~ICANON & ~ECHO;
		ttystate.c_cc[VMIN] = 1;
	}
	else
	{
		ttystate.c_lflag = flag;
	}
	tcsetattr(STDIN_FILENO, TCSANOW, &ttystate);
	return (state) ? lflag : flag;
}

static int kbhit()
{
	struct timeval tv;
	fd_set fds;
	tv.tv_sec = 0;
	tv.tv_usec = 0;
	FD_ZERO(&fds);
	FD_SET(STDIN_FILENO, &fds);
	select(STDIN_FILENO+1, &fds, NULL, NULL, &tv);
	return FD_ISSET(STDIN_FILENO, &fds);
}

static void poll_input_chars(int serial_fd)
{
	int ch;
	
	if (send_ctrlc) {
		send_ctrlc = 0;
		ch = 3; /* echo Ctrl-C to program */
		write(serial_fd, &ch, 1);
	}
	if (kbhit()) {
		if (read(STDIN_FILENO, &ch, 1) == 1) {
			write(serial_fd, &ch, 1);
		}
	}
}

void signal_handler(int signum)
{
	send_ctrlc = 1;
}

static void register_handlers(int register_handlers)
{
	static void (*old_sigquit_handler)(int) = SIG_ERR;

	if (register_handlers) {
		old_sigquit_handler = signal(SIGQUIT, &signal_handler);
	} else {
		if (old_sigquit_handler != SIG_ERR) {
			signal(SIGQUIT, old_sigquit_handler);
		}
	}
}

static int wait_until_exec_complete(int serial_fd, FILE *data)
{
	/* Print output from program running on the target until
	 * it signals that it has finished by sending an unescaped
	 * END_OF_PROGRAM character.
	 * Accept input from stdin and pass it to the program, but
	 * only if we are reading data from a file and not stdin.
	 */
	unsigned char ch;
	int lflag;

	send_ctrlc = 0;
	register_handlers(1);

	if (data != stdin) {
		lflag = nonblock(1, 0);
	}
	do {
		while (read(serial_fd, &ch, 1) != 1) {
			if (data != stdin) {
				poll_input_chars(serial_fd);
			}
		}
		if (ch == ESC_CHAR) {
			while (read(serial_fd, &ch, 1) != 1) {
				if (data != stdin) {
					poll_input_chars(serial_fd);
				}
			}
			ch = ~ch;
		}
		if (ch != END_OF_PROGRAM_OK && ch != END_OF_PROGRAM_FAIL) {
			putchar(ch);
		} else if (verbose) {
			puts("<Program completed>");
		}
	} while (ch != END_OF_PROGRAM_OK && ch != END_OF_PROGRAM_FAIL);
	
	if (data != stdin) {
		nonblock(0, lflag);
	}

	register_handlers(0);	
	return ch == END_OF_PROGRAM_OK;
}

static int get_uboot_info(FILE *in, struct uboot_info *info, char *name, int len, int *table_offset)
{
	u32 offset;
	int ch;
	
	if (!in || !info) {
		return -1;
	}
	if (fseek(in, UBOOT_TABLE_PTR, SEEK_SET) != 0) {
		return -1;
	}
	offset = fgetc(in) + (fgetc(in) << 8) + (fgetc(in) << 16)
							+ (fgetc(in) << 24);
	if (feof(in) || (fseek(in, offset, SEEK_SET) != 0) || 
				(fread(info, sizeof(struct uboot_info), 1, in) != 1)) {
		return -1;
	}
	if (info->magic[0] != 'U' || info->magic[1] != 'B' ||
		info->magic[2] != 'I' || info->magic[3] != 'S') {
		return -2; /* No U-Boot table */
	}
	if (name) {
		while (--len && (ch = fgetc(in)) != EOF && ch != '\0') {
			*name++ = ch;
		}
		*name = '\0';
		if (ch == EOF) {
			return -3; /* Unexpected end of name string */
		}
	}
	rewind(in);
	info->ddr_start -= info->load;
	info->ddr_end -= info->load;
	if (table_offset) {
		*table_offset = offset;
	}
	return 0;
}

static int add_init_ddr_cmds(FILE *in, struct uboot_info *info, FILE *out)
{
	/* Initialise target DDR based on */
	u32 val, addr;
	int rc, i;
	
	if (!in || !out || !info) {
		return 0;
	}
	
	/* Release DRAM block controller from reset */
	rc = 
		ums_single_write(out, UMS_REGS_SYSCTRL + SYSCTRL_RESET_MASK,
			4, SYSCTRL_DDR_RUN) &&
		ums_single_write(out, UMS_REGS_SYSCTRL + SYSCTRL_RESET, 4,
			SYSCTRL_DDR_RUN) &&
		ums_single_write(out, UMS_REGS_SYSCTRL + SYSCTRL_RESET_MASK,
			4, 0);
		
	if (!rc) {
		return 0;
	}
	
	addr = UMS_REGS_DDR;
	if (fseek(in, info->ddr_start, SEEK_SET)) {
		return 0;
	}
	for (i = 0; i < (info->ddr_end - info->ddr_start) / sizeof(val); i++) {
		if (fread(&val, sizeof(val), 1, in) != 1) {
			return 0;
		}
		if (!ums_single_write(out, addr, 4, val)) {
			return 0;
		}
		addr += 4;
	}
	/* Enable the controller & Map DDR at address 0 */
	rc = 
		ums_single_write(out, UMS_REGS_DDR + 0x14, 4, 0x110) &&
		ums_single_write(out, UMS_REGS_SYSCTRL + SYSCTRL_CTRL_MASK, 4,
				SYSCTRL_REMAP(3) | SYSCTRL_REMAP_SRAM) &&
		ums_single_write(out, UMS_REGS_SYSCTRL + SYSCTRL_CTRL, 4, 0) &&
		ums_single_write(out, UMS_REGS_SYSCTRL + SYSCTRL_CTRL_MASK, 4, 0);
	
	rewind(in);
	return (rc) ? 1 : 0;
}

int main(int argc, char *argv[])
{
	/* Big enough to hold a frame allowing for worst case escaping
	 * of the characters.
	 */
	unsigned char frame[1 + 2 * sizeof(struct umsdl_hdr) +
					2 * (UMS_MAX_DATA + 1) + 2];
	struct timespec long_pause;
	struct timeval timeout;
	struct termios serial_ios;
	int c, i, j, failures, done, resp;
	int addr_specified, copy_addr_specified, table_offset;
	int exec_addr_specified;
	long resp_timeout = 500;
	long rebaud_pause = 2000;
	unsigned char flag_chr = FLAG_CHAR;
	const int max_consec_failures = 5;
	int serial_fd, baud_rate, speed;
	char *uboot_file, *bin_file, *infile, *pserial_port, ch;
	u32 addr, copy_addr, exec_addr, ulen;
	FILE *in, *out, *data;
	struct uboot_info info;
	char name[32];
	u8 len;
	
	if (argc < 2) {
		usage();
		return -1;
	}
		
	baud_rate = 115200;
	verbose = 0;
	uboot_file = NULL;
	bin_file = NULL;
	infile = NULL;
	pserial_port = NULL;
	in = NULL;
	out = NULL;
	copy_addr_specified = 0;
	
	addr_specified = 1;
	exec_addr_specified = 1;
	addr = 0x80000000;
	exec_addr = 0x80000000;
	
	pserial_port = argv[argc - 1];
	i = 1;
	/* Parse all options */
	while (i < argc - 1) {
		if (argv[i][0] != '-') {
			usage();
			return -1;
		}
		
		ch = argv[i++][1];
		
		/* Options needing no further arguments */
		if (ch == 'v') {
			verbose++;
			continue;
		}
		
		/* Options needing 1 further argument */
		if (i + 1 >= argc) {
			usage();
			return -1;
		}
		
		switch(ch) {
		case 't':
			resp_timeout = strtoul(argv[i], NULL, 0);
			break;
		case 'p':
			rebaud_pause = strtoul(argv[i], NULL, 0);
			break;
		case 'b':
			baud_rate = strtoul(argv[i], NULL, 0);
			break;
		case 'a':
			addr = strtoul(argv[i], NULL, 0);
			addr_specified = 1;
			break;
		case 'c':
			copy_addr = strtoul(argv[i], NULL, 0);
			copy_addr_specified = 1;
			break;
		case 'x':
			exec_addr = strtoul(argv[i], NULL, 0);
			exec_addr_specified = 1;
			break;
		case 'f':
			bin_file = argv[i];
			break;
		case 'u':
			uboot_file = argv[i];
			break;
		case '\0':
			fprintf(stderr, "No option letter after -\n"); 
			usage();
			return -1;
		default:
			fprintf(stderr, "Unknown option %c\n", ch); 
			usage();
			return -1;
		}
		i++;
	}
	
	if ((uboot_file && bin_file) || (bin_file && !addr_specified) ||
						(!bin_file && addr_specified)) {
		usage();
		return -1;
	}
	if (uboot_file) {
		infile = uboot_file;
	}
	if (bin_file) {
		infile = bin_file;
	}
	
	if (infile) {
		if ((in = fopen(infile, "rb")) == NULL) {
			fprintf(stderr, "Cannot open %s\n", infile);
			return -1;
		} else if ((out = tmpfile()) == NULL) {
			fprintf(stderr, "Failed to open temporary file\n");
			return -1;
		} else {
			if (uboot_file) {
				/* For a bootloader (U-Boot) file we extract
				 * the load/execution and DRAM setup info
				 * directly from the image.  This allows us
				 * to setup the DRAM, download the image and
				 * run it.
				 */
				if (get_uboot_info(in, &info, name,
							sizeof(name), &table_offset)) {
					fprintf(stderr, 
						"Cannot read U-Boot information"
						" table (not a U-Boot binary?)\n");
					return -1;
				}
				
				fseek(in, 0L, SEEK_END);
				ulen = ftell(in);
				rewind(in);
				if (copy_addr_specified) {
					info.copy_addr = copy_addr & ~3;
				} else {
					info.copy_addr = (info.load & ~3) - COPY_OFFSET;
				}
				
				printf( "DDR type    : %s\n"
					"Byte length : 0x%08lx\n"
					"Load addr   : 0x%08lx\n"
					"Exec addr   : 0x%08lx\n"
					"Copy addr   : 0x%08lx\n"
					"Table offset: 0x%08lx\n"
					"Table length: 0x%08lx\n",
					name, ulen,
					info.load, info.exec, info.copy_addr,
					info.ddr_start,
					info.ddr_end - info.ddr_start);
				
				if (!add_init_ddr_cmds(in, &info, out)) {
					fprintf(stderr, 
						"Failed to prepend DDR commands\n");
					return -1;
				}
				
				addr = info.load;
			}

			if (!bin2ums(in, out, addr)) {
				fprintf(stderr, "Failed to convert file\n");
				return -1;
			}

			/* Patch the U-Boot info structure in the downloaded image
			 * with the user specified address of where to make a
			 * copy of the image when u-boot runs.
			 */
			if (uboot_file && 
				!ums_single_write(out, info.load +
					table_offset + 
					offsetof(struct uboot_info, copy_addr), 
					sizeof(info.copy_addr),
					info.copy_addr)) {
				fprintf(stderr, "Failed to set copy address\n");
				return -1;
			}
			
			if (uboot_file && !ums_exec(out, info.exec)) {
				fprintf(stderr, "Failed to add exec command\n");
				return -1;
			}
			
			if (bin_file && exec_addr_specified && !ums_exec(out, exec_addr)) {
				fprintf(stderr, "Failed to add exec command\n");
				return -1;
			}
		}
	}
	
	if (pserial_port) {
		/* Connect to the specified serial port */
		serial_fd = open(pserial_port, O_RDWR | O_NOCTTY | O_NONBLOCK);
		if (serial_fd < 0) {
			fprintf(stderr, "Failed to open %s\n", pserial_port);
			return -1;
		}
		if (tcgetattr(serial_fd, &serial_ios) < 0) {
			fprintf(stderr, "Failed to get serial port "
				"attributes for %s\n", pserial_port);
			close(serial_fd);
			return -1;
		}
		serial_ios.c_iflag = 0;
		serial_ios.c_oflag = 0;
		serial_ios.c_cflag = CS8 | CREAD | CLOCAL;
		serial_ios.c_lflag = 0;
		serial_ios.c_cc[VMIN] = 0;
		serial_ios.c_cc[VTIME] = 0;
		
		/* Set the serial port speed */
		speed = baudrate_constant(baud_rate);
		
		if (speed < 0) {
			fprintf(stderr, "Unsupported baud rate %d\n", baud_rate);
			close(serial_fd);
			return -1;
		}
		if (cfsetispeed(&serial_ios, speed)) {
			fprintf(stderr, "Failed to set input baud rate\n");
			close(serial_fd);
			return -1;
		}
		if (cfsetospeed(&serial_ios, speed)) {
			fprintf(stderr, "Failed to set output baud rate\n");
			close(serial_fd);
			return -1;
		}
		
		if (tcsetattr(serial_fd, TCSANOW, &serial_ios)) {
			fprintf(stderr, "Cannot update serial port settings\n");
			close(serial_fd);
			return -1;
		}
	} else {
		fprintf(stderr, "No serial port specified\n");
		usage();
		return -1;
	}

	
	/* This pause needs to be long enough so that the receiver
	 * sees the serial line is idle for > 128e6 AHB bus clock ticks
	 * (about 1s to 1.6s depending on the chip clock selection).
	 * The receiver will then re-enter the autobaud detection mode.
	 * We do need to take account of any outgoing buffering that is
	 * going on, so we push the delay up to 2s by default.
	 */
	long_pause.tv_sec = rebaud_pause / 1000;
	long_pause.tv_nsec = (rebaud_pause - long_pause.tv_sec * 1000) * 1000000;
	
	/* How long to wait for a response from the receiver */
	timeout.tv_sec = resp_timeout / 1000;
	timeout.tv_usec = (resp_timeout - timeout.tv_sec * 1000) * 1000;

	/* Make stdout non-buffered so we see the serial download progress */
	setvbuf(stdout, (char *) NULL, _IONBF, 0);
	
	/* Tell chip to turn on its serial output.  The response is expected
	 * to be 0xFF, PACKET_ACK with the possibility that the 0xFF gets
	 * corrupted by the UART turn on.
	 */
	i = 3;
	if (verbose) {
		printf("Wait for initial response from target\n");
	}
	
	do {
		write(serial_fd, &flag_chr, 1);
		write(serial_fd, &init_frame[0], sizeof(init_frame));
		c = poll_char(serial_fd, rebaud_pause);
		if (c == 0xff) {
			c = poll_char(serial_fd, rebaud_pause);
		}
	} while ((c != PACKET_ACK) && --i);
	
	if (i == 0) {
		fprintf(stderr, "Failed to sync with receiver\n");
		return -1;
	}

	if (verbose) {
		printf("Response received\n");
	}

	if (infile) {
		data = out;
		rewind(data);
	} else {
		data = stdin;
	}
	
	c = fgetc(data);
	do {
		/* Read and send one frame at a time until done */
		if (verbose) {
			putchar('F');
		}
		if (c != FLAG_CHAR) {
			fprintf(stderr, 
				"Bad file format (Expected %04x, got %04x)\n",
								FLAG_CHAR, c);
			return -1;
		}
		frame[0] = c;
		i = 1;
		do {
			c = fgetc(data);
			done = (c == EOF) || (c == FLAG_CHAR);
			if (!done) {
				if (i >= sizeof(frame)) {
					fprintf(stderr, 
						"Overlength frame error\n");
					return -1;
				}
				frame[i++] = (unsigned char)c;
			}
		} while (!done);

		if (verbose) {
			putchar('f');
		}
		failures = 0;
		
		do {
			if (verbose) {
				putchar('S');
			}
			
			/* Send whole frame */
			if (verbose > 1) {
				printf("\n");
				for (j = 0; j < i; j++) {
					printf("%02x ", frame[j]);
				}
				printf("\n");
			}
			write(serial_fd, &frame[0], i);
			if (verbose) {
				putchar('s');
			}
			
			/* Wait for receiver response */
			resp = poll_char(serial_fd, resp_timeout);
			if (resp != PACKET_ACK) {
				if (resp == PACKET_NAK)
				{
					putchar('N');
				} else if (resp == EOF) {
					putchar('-');
				} else {
					if (verbose) {
						printf("(%02x?)", resp);
					} else {
						putchar('_');
					}
				}
				if (failures++ & 1) {
					/* Try renegotiation of baud rate */
					nanosleep(&long_pause, NULL);
				}
			} else {
				putchar('.');
				failures = 0;
			}
			
			/* If we have just run a program on the target
			 * we suspend the download and just report characters
			 * sent back to us until the "program-finished"
			 * character is received.
			 */
			parse_frame_hdr(&frame[1], &addr, &len);
			if (verbose) {
				printf("[Addr %08lx, Len %02x]\n", addr, len);
			}
			if (len == 0) {
				if (!wait_until_exec_complete(serial_fd, data)) {
					fprintf(stderr, "\nDownloaded program returned error. Exiting\n");
					return -1;
				}
			}
			
		} while (resp != PACKET_ACK && failures < max_consec_failures);
		
		if (failures >= max_consec_failures) {
			/* Abort download: excessive consecutive failures */
			fprintf(stderr, "\nToo many consecutive errors.\n");
			return -1;
		}
	} while (c != EOF);
	printf("\n");
	return 0;
}	

