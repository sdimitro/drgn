// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * dratini - Lightweight crash dump triage tool
 *
 * This tool is designed to run in the kdump kernel after a host kernel crash.
 * It reads /proc/vmcore (or a specified vmcore path) to quickly extract
 * preliminary crash data without needing to capture the full crash dump.
 *
 * On systems with a lot of RAM, capturing a full crash dump with makedumpfile
 * can take a long time. This tool allows a quick assessment of whether the
 * crash is a known/duplicate issue or something new, enabling faster decisions
 * about whether a full dump capture is necessary.
 *
 * Data collected:
 *   - Kernel command line
 *   - dmesg (kernel log buffer) including panic message
 *   - Loaded kernel modules (with sizes and refcounts)
 *   - Panicked/crashing thread identification and stack trace
 *   - Stack traces for all tasks
 *
 * Usage: dratini [OPTIONS] [VMCORE_PATH]
 *   --json             Output in JSON format
 *   --text             Output in human-readable text (default)
 *   --no-stacktraces   Skip collecting stack traces (faster)
 *   -o, --output FILE  Write output to FILE instead of stdout
 *   VMCORE_PATH        Path to vmcore (default: /proc/vmcore)
 */

#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "drgn.h"

#define DEFAULT_VMCORE_PATH "/proc/vmcore"

/* Output format */
enum output_format {
	OUTPUT_TEXT,
	OUTPUT_JSON,
};

/* Global options */
static struct {
	const char *vmcore_path;
	const char *output_path;
	enum output_format format;
	bool collect_stacktraces;
} opts = {
	.vmcore_path = DEFAULT_VMCORE_PATH,
	.output_path = NULL,
	.format = OUTPUT_TEXT,
	.collect_stacktraces = true,
};

/* Output file handle (stdout by default) */
static FILE *out;

/* Forward declarations */
static int collect_cmdline(struct drgn_program *prog);
static int collect_dmesg(struct drgn_program *prog);
static int collect_modules(struct drgn_program *prog);
static int collect_stack_traces(struct drgn_program *prog);

/* --------------------------------------------------------------------------
 * JSON output helpers
 * -------------------------------------------------------------------------- */

/* Escape a string for JSON output. Caller must free the result. */
static char *json_escape(const char *s)
{
	if (!s)
		return strdup("null");

	size_t len = strlen(s);
	/* Worst case: every char needs \uXXXX (6 chars) + quotes + nul */
	char *buf = malloc(len * 6 + 3);
	if (!buf)
		return NULL;

	char *p = buf;
	*p++ = '"';
	for (size_t i = 0; i < len; i++) {
		unsigned char c = (unsigned char)s[i];
		switch (c) {
		case '"':  *p++ = '\\'; *p++ = '"'; break;
		case '\\': *p++ = '\\'; *p++ = '\\'; break;
		case '\b': *p++ = '\\'; *p++ = 'b'; break;
		case '\f': *p++ = '\\'; *p++ = 'f'; break;
		case '\n': *p++ = '\\'; *p++ = 'n'; break;
		case '\r': *p++ = '\\'; *p++ = 'r'; break;
		case '\t': *p++ = '\\'; *p++ = 't'; break;
		default:
			if (c < 0x20) {
				p += sprintf(p, "\\u%04x", c);
			} else {
				*p++ = c;
			}
			break;
		}
	}
	*p++ = '"';
	*p = '\0';
	return buf;
}

/* --------------------------------------------------------------------------
 * drgn helper: read a kernel string variable by name
 * -------------------------------------------------------------------------- */

/*
 * Read a kernel string (char *) variable by name.
 * Returns a malloc'd string on success, NULL on failure.
 */
static char *read_kernel_string(struct drgn_program *prog, const char *name)
{
	struct drgn_error *err;
	struct drgn_object obj;
	char *str = NULL;

	drgn_object_init(&obj, prog);

	err = drgn_program_find_object(prog, name, NULL,
				       DRGN_FIND_OBJECT_ANY, &obj);
	if (err) {
		drgn_error_destroy(err);
		goto out;
	}

	err = drgn_object_read_c_string(&obj, &str);
	if (err) {
		drgn_error_destroy(err);
		str = NULL;
		goto out;
	}

out:
	drgn_object_deinit(&obj);
	return str;
}

/* --------------------------------------------------------------------------
 * Kernel command line
 * -------------------------------------------------------------------------- */

static int collect_cmdline(struct drgn_program *prog)
{
	char *cmdline = read_kernel_string(prog, "saved_command_line");
	if (!cmdline) {
		/* Try boot_command_line as fallback (older kernels) */
		struct drgn_error *err;
		struct drgn_object obj;
		drgn_object_init(&obj, prog);
		err = drgn_program_find_object(prog, "boot_command_line", NULL,
					       DRGN_FIND_OBJECT_ANY, &obj);
		if (!err) {
			/*
			 * boot_command_line is a char array, not a pointer.
			 * We need to read it via its address.
			 */
			if (obj.kind == DRGN_OBJECT_REFERENCE) {
				err = drgn_program_read_c_string(
					prog, obj.address,
					false, 4096, &cmdline);
				if (err) {
					drgn_error_destroy(err);
					cmdline = NULL;
				}
			}
		} else {
			drgn_error_destroy(err);
		}
		drgn_object_deinit(&obj);
	}

	if (opts.format == OUTPUT_JSON) {
		char *escaped = json_escape(cmdline);
		fprintf(out, "  \"cmdline\": %s", escaped ? escaped : "null");
		free(escaped);
	} else {
		fprintf(out, "=== Kernel Command Line ===\n");
		if (cmdline)
			fprintf(out, "%s\n", cmdline);
		else
			fprintf(out, "(unavailable)\n");
		fprintf(out, "\n");
	}

	free(cmdline);
	return 0;
}

/* --------------------------------------------------------------------------
 * dmesg - kernel log buffer
 *
 * Supports two formats:
 *   1. New printk ringbuffer (5.10+): struct printk_ringbuffer (prb)
 *   2. Legacy log_buf (pre-5.10 kernels): struct printk_log records
 *
 * We try the new approach first, then fall back to the legacy approach.
 * -------------------------------------------------------------------------- */

/*
 * Legacy dmesg: read log_buf directly.
 *
 * The kernel log buffer (pre-5.10) is structured as:
 *   log_buf: pointer to buffer
 *   log_buf_len: length of buffer
 *
 * Each record in the buffer is a struct printk_log (or struct log):
 *   u64 ts_nsec;
 *   u16 len;       // total record length including padding
 *   u16 text_len;  // length of text
 *   u16 dict_len;  // length of dictionary
 *   u8  facility;
 *   u8  flags:5, level:3;
 *   char text[];   // text follows the struct
 *
 * We use drgn's type-aware API to parse these correctly.
 */
static int collect_dmesg_legacy(struct drgn_program *prog)
{
	struct drgn_error *err;
	struct drgn_object log_buf_obj, log_buf_len_obj;
	struct drgn_object log_first_idx_obj, log_next_idx_obj;
	uint64_t log_buf_addr, log_buf_len;
	uint64_t log_first_idx, log_next_idx;
	char *buf = NULL;
	int rc = -1;
	bool first_json = true;

	drgn_object_init(&log_buf_obj, prog);
	drgn_object_init(&log_buf_len_obj, prog);
	drgn_object_init(&log_first_idx_obj, prog);
	drgn_object_init(&log_next_idx_obj, prog);

	/* Find log buffer variables */
	err = drgn_program_find_object(prog, "log_buf", NULL,
				       DRGN_FIND_OBJECT_ANY, &log_buf_obj);
	if (err) {
		drgn_error_destroy(err);
		goto out;
	}
	err = drgn_object_read_unsigned(&log_buf_obj, &log_buf_addr);
	if (err) {
		drgn_error_destroy(err);
		goto out;
	}

	err = drgn_program_find_object(prog, "log_buf_len", NULL,
				       DRGN_FIND_OBJECT_ANY, &log_buf_len_obj);
	if (err) {
		drgn_error_destroy(err);
		goto out;
	}
	err = drgn_object_read_unsigned(&log_buf_len_obj, &log_buf_len);
	if (err) {
		drgn_error_destroy(err);
		goto out;
	}

	if (log_buf_len == 0 || log_buf_len > 64 * 1024 * 1024) {
		fprintf(stderr, "warning: log_buf_len %" PRIu64
			" looks invalid\n", log_buf_len);
		goto out;
	}

	/*
	 * Read log_first_idx and log_next_idx to know the valid range.
	 * These may not exist in all kernel versions; if not, just read
	 * the whole buffer.
	 */
	err = drgn_program_find_object(prog, "log_first_idx", NULL,
				       DRGN_FIND_OBJECT_ANY,
				       &log_first_idx_obj);
	if (err) {
		drgn_error_destroy(err);
		log_first_idx = 0;
	} else {
		err = drgn_object_read_unsigned(&log_first_idx_obj,
						&log_first_idx);
		if (err) {
			drgn_error_destroy(err);
			log_first_idx = 0;
		}
	}

	err = drgn_program_find_object(prog, "log_next_idx", NULL,
				       DRGN_FIND_OBJECT_ANY,
				       &log_next_idx_obj);
	if (err) {
		drgn_error_destroy(err);
		log_next_idx = log_buf_len;
	} else {
		err = drgn_object_read_unsigned(&log_next_idx_obj,
						&log_next_idx);
		if (err) {
			drgn_error_destroy(err);
			log_next_idx = log_buf_len;
		}
	}

	/* Read the raw log buffer */
	buf = malloc(log_buf_len);
	if (!buf) {
		fprintf(stderr, "error: failed to allocate %" PRIu64
			" bytes for log buffer\n", log_buf_len);
		goto out;
	}

	err = drgn_program_read_memory(prog, buf, log_buf_addr,
				       (size_t)log_buf_len, false);
	if (err) {
		fprintf(stderr, "warning: failed to read log buffer: ");
		drgn_error_fwrite(stderr, err);
		fprintf(stderr, "\n");
		drgn_error_destroy(err);
		goto out;
	}

	/*
	 * Parse the struct printk_log records.
	 * Use drgn's type system to get the correct struct layout.
	 */
	struct drgn_qualified_type printk_log_type;
	const char *record_type_name = "struct printk_log";

	err = drgn_program_find_type(prog, record_type_name, NULL,
				     &printk_log_type);
	if (err) {
		drgn_error_destroy(err);
		/* Try older name */
		record_type_name = "struct log";
		err = drgn_program_find_type(prog, record_type_name, NULL,
					     &printk_log_type);
		if (err) {
			drgn_error_destroy(err);
			if (opts.format == OUTPUT_JSON) {
				fprintf(out, "  \"dmesg\": [\"(raw log buffer"
				       " - struct type not found)\"]");
			} else {
				fprintf(out, "(raw log buffer - struct type "
				       "not found)\n");
			}
			rc = 0;
			goto out;
		}
	}

	/* Get field offsets using drgn_type_offsetof */
	uint64_t ts_nsec_off, len_off, text_len_off;

	err = drgn_type_offsetof(printk_log_type.type, "ts_nsec",
				 &ts_nsec_off);
	if (err) {
		drgn_error_destroy(err);
		goto out;
	}
	err = drgn_type_offsetof(printk_log_type.type, "len", &len_off);
	if (err) {
		drgn_error_destroy(err);
		goto out;
	}
	err = drgn_type_offsetof(printk_log_type.type, "text_len",
				 &text_len_off);
	if (err) {
		drgn_error_destroy(err);
		goto out;
	}

	uint64_t header_size;
	err = drgn_type_sizeof(printk_log_type.type, &header_size);
	if (err) {
		drgn_error_destroy(err);
		goto out;
	}

	/*
	 * Parse records starting from log_first_idx, wrapping around.
	 * A record with len == 0 means wrap around to the start of the buffer.
	 */
	if (opts.format == OUTPUT_JSON)
		fprintf(out, "  \"dmesg\": [\n");

	uint64_t idx = log_first_idx;
	size_t count = 0;
	size_t max_records = log_buf_len / header_size + 1;

	while (count < max_records) {
		uint16_t rec_len, text_len;
		uint64_t ts_nsec;

		if (idx >= log_buf_len)
			idx = 0;

		if (idx == log_next_idx && count > 0)
			break;

		memcpy(&rec_len, buf + idx + len_off, sizeof(rec_len));
		if (rec_len == 0) {
			idx = 0;
			if (idx == log_next_idx)
				break;
			memcpy(&rec_len, buf + idx + len_off, sizeof(rec_len));
			if (rec_len == 0)
				break;
		}

		memcpy(&text_len, buf + idx + text_len_off, sizeof(text_len));
		memcpy(&ts_nsec, buf + idx + ts_nsec_off, sizeof(ts_nsec));

		if (text_len > 0 && idx + header_size + text_len <= log_buf_len) {
			char *text = buf + idx + header_size;
			uint64_t secs = ts_nsec / 1000000000ULL;
			uint64_t usecs = (ts_nsec % 1000000000ULL) / 1000;

			if (opts.format == OUTPUT_JSON) {
				char saved = text[text_len];
				text[text_len] = '\0';
				char *escaped = json_escape(text);
				text[text_len] = saved;

				if (!first_json)
					fprintf(out, ",\n");
				fprintf(out,
					"    {\"timestamp\": %"PRIu64
					".%06"PRIu64", \"message\": %s}",
					secs, usecs,
					escaped ? escaped : "null");
				free(escaped);
				first_json = false;
			} else {
				fprintf(out, "[%5"PRIu64".%06"PRIu64"] %.*s\n",
					secs, usecs, (int)text_len, text);
			}
		}

		idx += rec_len;
		count++;
	}

	if (opts.format == OUTPUT_JSON)
		fprintf(out, "\n  ]");

	rc = 0;

out:
	free(buf);
	drgn_object_deinit(&log_next_idx_obj);
	drgn_object_deinit(&log_first_idx_obj);
	drgn_object_deinit(&log_buf_len_obj);
	drgn_object_deinit(&log_buf_obj);
	return rc;
}

/*
 * New dmesg: printk ringbuffer (prb) - Linux 5.10+
 *
 * The new printk uses a lock-free ring buffer (struct printk_ringbuffer)
 * accessed through the global pointer `prb`.
 */
static int collect_dmesg_prb(struct drgn_program *prog)
{
	struct drgn_error *err;
	struct drgn_object prb_obj, desc_ring, text_data_ring;
	struct drgn_object descs, infos, tmp, tmp2;
	uint64_t count_bits, head_id, tail_id;
	uint64_t text_size_bits;
	uint64_t text_data_addr;
	char *text_buf = NULL;
	int rc = -1;
	bool first_json = true;

	drgn_object_init(&prb_obj, prog);
	drgn_object_init(&desc_ring, prog);
	drgn_object_init(&text_data_ring, prog);
	drgn_object_init(&descs, prog);
	drgn_object_init(&infos, prog);
	drgn_object_init(&tmp, prog);
	drgn_object_init(&tmp2, prog);

	/* Find prb (struct printk_ringbuffer *) */
	err = drgn_program_find_object(prog, "prb", NULL,
				       DRGN_FIND_OBJECT_ANY, &prb_obj);
	if (err) {
		drgn_error_destroy(err);
		goto out;
	}

	/* prb->desc_ring */
	err = drgn_object_member_dereference(&desc_ring, &prb_obj, "desc_ring");
	if (err) {
		drgn_error_destroy(err);
		goto out;
	}

	/* prb->desc_ring.count_bits */
	err = drgn_object_member(&tmp, &desc_ring, "count_bits");
	if (err) {
		drgn_error_destroy(err);
		goto out;
	}
	err = drgn_object_read_unsigned(&tmp, &count_bits);
	if (err) {
		drgn_error_destroy(err);
		goto out;
	}

	uint64_t desc_count = 1ULL << count_bits;
	uint64_t desc_mask = desc_count - 1;

	/* prb->desc_ring.tail_id.counter */
	err = drgn_object_member(&tmp, &desc_ring, "tail_id");
	if (err) {
		drgn_error_destroy(err);
		goto out;
	}
	err = drgn_object_member(&tmp2, &tmp, "counter");
	if (err) {
		drgn_error_destroy(err);
		goto out;
	}
	err = drgn_object_read_unsigned(&tmp2, &tail_id);
	if (err) {
		drgn_error_destroy(err);
		goto out;
	}

	/* prb->desc_ring.head_id.counter */
	err = drgn_object_member(&tmp, &desc_ring, "head_id");
	if (err) {
		drgn_error_destroy(err);
		goto out;
	}
	err = drgn_object_member(&tmp2, &tmp, "counter");
	if (err) {
		drgn_error_destroy(err);
		goto out;
	}
	err = drgn_object_read_unsigned(&tmp2, &head_id);
	if (err) {
		drgn_error_destroy(err);
		goto out;
	}

	/* prb->desc_ring.infos */
	err = drgn_object_member(&infos, &desc_ring, "infos");
	if (err) {
		drgn_error_destroy(err);
		goto out;
	}

	/* prb->text_data_ring */
	err = drgn_object_member_dereference(&text_data_ring, &prb_obj,
					     "text_data_ring");
	if (err) {
		drgn_error_destroy(err);
		goto out;
	}

	/* text_data_ring.size_bits */
	err = drgn_object_member(&tmp, &text_data_ring, "size_bits");
	if (err) {
		drgn_error_destroy(err);
		goto out;
	}
	err = drgn_object_read_unsigned(&tmp, &text_size_bits);
	if (err) {
		drgn_error_destroy(err);
		goto out;
	}

	uint64_t text_data_size = 1ULL << text_size_bits;
	uint64_t text_data_mask = text_data_size - 1;

	/* text_data_ring.data (pointer to char) */
	err = drgn_object_member(&tmp, &text_data_ring, "data");
	if (err) {
		drgn_error_destroy(err);
		goto out;
	}
	err = drgn_object_read_unsigned(&tmp, &text_data_addr);
	if (err) {
		drgn_error_destroy(err);
		goto out;
	}

	if (text_data_size > 64 * 1024 * 1024) {
		fprintf(stderr, "warning: text data ring size %" PRIu64
			" too large\n", text_data_size);
		goto out;
	}

	text_buf = malloc(text_data_size);
	if (!text_buf) {
		fprintf(stderr, "error: failed to allocate %" PRIu64
			" bytes for text data\n", text_data_size);
		goto out;
	}

	err = drgn_program_read_memory(prog, text_buf, text_data_addr,
				       text_data_size, false);
	if (err) {
		fprintf(stderr, "warning: failed to read text data ring: ");
		drgn_error_fwrite(stderr, err);
		fprintf(stderr, "\n");
		drgn_error_destroy(err);
		goto out;
	}

	if (opts.format == OUTPUT_JSON)
		fprintf(out, "  \"dmesg\": [\n");

	/* prb->desc_ring.descs */
	err = drgn_object_member(&descs, &desc_ring, "descs");
	if (err) {
		drgn_error_destroy(err);
		goto out;
	}

	for (uint64_t id = tail_id; id <= head_id; id++) {
		uint64_t didx = id & desc_mask;
		uint64_t ts_nsec, text_len;
		uint64_t begin_lpos;

		/* infos[didx].ts_nsec */
		err = drgn_object_subscript(&tmp, &infos, (int64_t)didx);
		if (err) {
			drgn_error_destroy(err);
			continue;
		}
		err = drgn_object_member(&tmp2, &tmp, "ts_nsec");
		if (err) {
			drgn_error_destroy(err);
			continue;
		}
		err = drgn_object_read_unsigned(&tmp2, &ts_nsec);
		if (err) {
			drgn_error_destroy(err);
			continue;
		}

		/* infos[didx].text_len */
		err = drgn_object_member(&tmp2, &tmp, "text_len");
		if (err) {
			drgn_error_destroy(err);
			continue;
		}
		err = drgn_object_read_unsigned(&tmp2, &text_len);
		if (err) {
			drgn_error_destroy(err);
			continue;
		}

		/* descs[didx].text_blk_lpos.begin */
		err = drgn_object_subscript(&tmp, &descs, (int64_t)didx);
		if (err) {
			drgn_error_destroy(err);
			continue;
		}
		err = drgn_object_member(&tmp2, &tmp, "text_blk_lpos");
		if (err) {
			drgn_error_destroy(err);
			continue;
		}
		err = drgn_object_member(&tmp, &tmp2, "begin");
		if (err) {
			drgn_error_destroy(err);
			continue;
		}
		err = drgn_object_read_unsigned(&tmp, &begin_lpos);
		if (err) {
			drgn_error_destroy(err);
			continue;
		}

		if (text_len == 0)
			continue;

		/*
		 * The text starts at (begin_lpos & text_data_mask) in the
		 * data ring. The actual text starts after a data block header
		 * (sizeof(unsigned long) for the id).
		 */
		uint64_t data_off = begin_lpos & text_data_mask;

		/* Skip the data block header (sizeof(unsigned long)) */
		uint64_t text_off = data_off + sizeof(unsigned long);
		if (text_off >= text_data_size)
			text_off -= text_data_size;

		if (text_len > text_data_size)
			continue;

		/* Build the text string (may wrap around the ring) */
		char *text = malloc(text_len + 1);
		if (!text)
			continue;

		uint64_t first_part = text_data_size - text_off;
		if (first_part >= text_len) {
			memcpy(text, text_buf + text_off, text_len);
		} else {
			memcpy(text, text_buf + text_off, first_part);
			memcpy(text + first_part, text_buf,
			       text_len - first_part);
		}
		text[text_len] = '\0';

		uint64_t secs = ts_nsec / 1000000000ULL;
		uint64_t usecs = (ts_nsec % 1000000000ULL) / 1000;

		if (opts.format == OUTPUT_JSON) {
			char *escaped = json_escape(text);
			if (!first_json)
				fprintf(out, ",\n");
			fprintf(out,
				"    {\"timestamp\": %"PRIu64".%06"PRIu64
				", \"message\": %s}",
				secs, usecs, escaped ? escaped : "null");
			free(escaped);
			first_json = false;
		} else {
			fprintf(out, "[%5"PRIu64".%06"PRIu64"] %s\n",
				secs, usecs, text);
		}

		free(text);
	}

	if (opts.format == OUTPUT_JSON)
		fprintf(out, "\n  ]");

	rc = 0;

out:
	free(text_buf);
	drgn_object_deinit(&tmp2);
	drgn_object_deinit(&tmp);
	drgn_object_deinit(&infos);
	drgn_object_deinit(&descs);
	drgn_object_deinit(&text_data_ring);
	drgn_object_deinit(&desc_ring);
	drgn_object_deinit(&prb_obj);
	return rc;
}

static int collect_dmesg(struct drgn_program *prog)
{
	if (opts.format == OUTPUT_TEXT)
		fprintf(out, "=== Kernel Log (dmesg) ===\n");

	/* Try the new prb-based approach first (5.10+), fall back to legacy. */
	if (collect_dmesg_prb(prog) == 0) {
		if (opts.format == OUTPUT_TEXT)
			fprintf(out, "\n");
		return 0;
	}

	if (collect_dmesg_legacy(prog) == 0) {
		if (opts.format == OUTPUT_TEXT)
			fprintf(out, "\n");
		return 0;
	}

	if (opts.format == OUTPUT_JSON) {
		fprintf(out, "  \"dmesg\": []");
	} else {
		fprintf(out, "(unable to read kernel log buffer)\n\n");
	}
	return -1;
}

/* --------------------------------------------------------------------------
 * Loaded kernel modules
 *
 * Walk the modules linked list:
 *   for each entry in list_for_each_entry("struct module", &modules, "list"):
 *       name = mod->name
 *       size = mod->core_layout.size (or mod->core_size for older kernels)
 *       refcnt = mod->refcnt.counter - 1
 * -------------------------------------------------------------------------- */

static int collect_modules(struct drgn_program *prog)
{
	struct drgn_error *err;
	struct drgn_object modules_head, mod_obj, tmp;
	struct drgn_qualified_type module_type;
	uint64_t head_addr, next_addr, list_offset;
	int rc = -1;
	bool first_json = true;

	drgn_object_init(&modules_head, prog);
	drgn_object_init(&mod_obj, prog);
	drgn_object_init(&tmp, prog);

	/* Find the 'modules' list head */
	err = drgn_program_find_object(prog, "modules", NULL,
				       DRGN_FIND_OBJECT_ANY, &modules_head);
	if (err) {
		fprintf(stderr, "warning: could not find 'modules': ");
		drgn_error_fwrite(stderr, err);
		fprintf(stderr, "\n");
		drgn_error_destroy(err);
		goto out;
	}

	/* Get the address of the modules list head */
	err = drgn_object_address_of(&tmp, &modules_head);
	if (err) {
		drgn_error_destroy(err);
		goto out;
	}
	err = drgn_object_read_unsigned(&tmp, &head_addr);
	if (err) {
		drgn_error_destroy(err);
		goto out;
	}

	/* Find struct module type and the offset of 'list' member */
	err = drgn_program_find_type(prog, "struct module", NULL,
				     &module_type);
	if (err) {
		fprintf(stderr, "warning: could not find struct module: ");
		drgn_error_fwrite(stderr, err);
		fprintf(stderr, "\n");
		drgn_error_destroy(err);
		goto out;
	}

	err = drgn_type_offsetof(module_type.type, "list", &list_offset);
	if (err) {
		fprintf(stderr, "warning: could not find module.list offset: ");
		drgn_error_fwrite(stderr, err);
		fprintf(stderr, "\n");
		drgn_error_destroy(err);
		goto out;
	}

	if (opts.format == OUTPUT_JSON) {
		fprintf(out, "  \"modules\": [\n");
	} else {
		fprintf(out, "=== Loaded Kernel Modules ===\n");
		fprintf(out, "%-24s %10s  %s\n", "Module", "Size", "Refcount");
	}

	/*
	 * Read modules_head.next to get the first list entry.
	 * Then walk the list until we loop back to head_addr.
	 */
	err = drgn_object_member(&tmp, &modules_head, "next");
	if (err) {
		drgn_error_destroy(err);
		goto out_close;
	}
	err = drgn_object_read(&tmp, &tmp);
	if (err) {
		drgn_error_destroy(err);
		goto out_close;
	}
	err = drgn_object_read_unsigned(&tmp, &next_addr);
	if (err) {
		drgn_error_destroy(err);
		goto out_close;
	}

	for (size_t count = 0; count < 10000 && next_addr != head_addr; count++) {
		uint64_t mod_addr;
		char *name = NULL;
		struct drgn_object name_obj, size_obj, refcnt_obj, counter_obj;

		/* container_of(next_addr, struct module, list) */
		mod_addr = next_addr - list_offset;

		drgn_object_init(&name_obj, prog);
		drgn_object_init(&size_obj, prog);
		drgn_object_init(&refcnt_obj, prog);
		drgn_object_init(&counter_obj, prog);

		err = drgn_object_set_reference(&mod_obj, module_type,
						mod_addr, 0, 0);
		if (err) {
			drgn_error_destroy(err);
			drgn_object_deinit(&counter_obj);
			drgn_object_deinit(&refcnt_obj);
			drgn_object_deinit(&size_obj);
			drgn_object_deinit(&name_obj);
			break;
		}

		/* Read module name (char array member) */
		err = drgn_object_member(&name_obj, &mod_obj, "name");
		if (!err && name_obj.kind == DRGN_OBJECT_REFERENCE) {
			err = drgn_program_read_c_string(prog,
							 name_obj.address,
							 false, 256, &name);
			if (err) {
				drgn_error_destroy(err);
				name = strdup("(unknown)");
			}
		} else {
			if (err)
				drgn_error_destroy(err);
			name = strdup("(unknown)");
		}

		/* Read module size - try core_layout.size, fall back to core_size */
		uint64_t mod_size = 0;
		err = drgn_object_member(&size_obj, &mod_obj, "core_layout");
		if (!err) {
			err = drgn_object_member(&counter_obj, &size_obj, "size");
			if (!err) {
				drgn_object_read_unsigned(&counter_obj, &mod_size);
			} else {
				drgn_error_destroy(err);
			}
		} else {
			drgn_error_destroy(err);
			err = drgn_object_member(&size_obj, &mod_obj, "core_size");
			if (!err) {
				drgn_object_read_unsigned(&size_obj, &mod_size);
			} else {
				drgn_error_destroy(err);
			}
		}

		/* Read refcount: mod->refcnt.counter - 1 */
		int64_t refcnt = -1;
		err = drgn_object_member(&refcnt_obj, &mod_obj, "refcnt");
		if (!err) {
			err = drgn_object_member(&counter_obj, &refcnt_obj, "counter");
			if (!err) {
				union drgn_value val;
				err = drgn_object_read_integer(&counter_obj, &val);
				if (!err)
					refcnt = val.svalue - 1;
				else
					drgn_error_destroy(err);
			} else {
				drgn_error_destroy(err);
			}
		} else {
			drgn_error_destroy(err);
		}

		if (opts.format == OUTPUT_JSON) {
			char *escaped = json_escape(name);
			if (!first_json)
				fprintf(out, ",\n");
			fprintf(out, "    {\"name\": %s, \"size\": %"PRIu64,
			       escaped ? escaped : "null", mod_size);
			if (refcnt >= 0)
				fprintf(out, ", \"refcount\": %"PRId64, refcnt);
			fprintf(out, "}");
			free(escaped);
			first_json = false;
		} else {
			fprintf(out, "%-24s %10"PRIu64, name, mod_size);
			if (refcnt >= 0)
				fprintf(out, "  %"PRId64, refcnt);
			fprintf(out, "\n");
		}

		free(name);
		drgn_object_deinit(&counter_obj);
		drgn_object_deinit(&refcnt_obj);
		drgn_object_deinit(&size_obj);
		drgn_object_deinit(&name_obj);

		/*
		 * Advance: read the next pointer from the list_head at
		 * next_addr (which points to list_head.next).
		 */
		err = drgn_program_read_word(prog, next_addr, false,
					     &next_addr);
		if (err) {
			drgn_error_destroy(err);
			break;
		}
	}

out_close:
	if (opts.format == OUTPUT_JSON) {
		fprintf(out, "\n  ]");
	} else {
		fprintf(out, "\n");
	}
	rc = 0;

out:
	drgn_object_deinit(&tmp);
	drgn_object_deinit(&mod_obj);
	drgn_object_deinit(&modules_head);
	return rc;
}

/* --------------------------------------------------------------------------
 * Stack traces
 *
 * Walk all tasks using the init_task.tasks linked list and collect stack
 * traces. Also identify the panicking/crashed thread.
 * -------------------------------------------------------------------------- */

/*
 * Try to determine the panicking CPU.
 * Returns -1 if unknown.
 */
static int64_t find_panic_cpu(struct drgn_program *prog)
{
	struct drgn_error *err;
	struct drgn_object obj, counter;
	union drgn_value val;

	drgn_object_init(&obj, prog);
	drgn_object_init(&counter, prog);

	/* Try panic_cpu (atomic_t with .counter member in newer kernels) */
	err = drgn_program_find_object(prog, "panic_cpu", NULL,
				       DRGN_FIND_OBJECT_ANY, &obj);
	if (!err) {
		err = drgn_object_member(&counter, &obj, "counter");
		if (!err) {
			err = drgn_object_read_integer(&counter, &val);
			if (!err && val.svalue >= 0) {
				drgn_object_deinit(&counter);
				drgn_object_deinit(&obj);
				return val.svalue;
			}
			if (err)
				drgn_error_destroy(err);
		} else {
			drgn_error_destroy(err);
			/* Maybe it's a plain int */
			err = drgn_object_read_integer(&obj, &val);
			if (!err && val.svalue >= 0) {
				drgn_object_deinit(&counter);
				drgn_object_deinit(&obj);
				return val.svalue;
			}
			if (err)
				drgn_error_destroy(err);
		}
	} else {
		drgn_error_destroy(err);
	}

	/* Try crashing_cpu */
	err = drgn_program_find_object(prog, "crashing_cpu", NULL,
				       DRGN_FIND_OBJECT_ANY, &obj);
	if (!err) {
		err = drgn_object_read_integer(&obj, &val);
		if (!err && val.svalue >= 0) {
			drgn_object_deinit(&counter);
			drgn_object_deinit(&obj);
			return val.svalue;
		}
		if (err)
			drgn_error_destroy(err);
	} else {
		drgn_error_destroy(err);
	}

	drgn_object_deinit(&counter);
	drgn_object_deinit(&obj);
	return -1;
}

/*
 * Read PID and comm from a task_struct reference object.
 */
static void read_task_info(struct drgn_program *prog,
			   struct drgn_object *task_obj,
			   uint32_t *pid_out, char **comm_out,
			   int32_t *cpu_out)
{
	struct drgn_error *err;
	struct drgn_object tmp;

	drgn_object_init(&tmp, prog);

	*pid_out = 0;
	*comm_out = NULL;
	*cpu_out = -1;

	/* Read PID */
	err = drgn_object_member(&tmp, task_obj, "pid");
	if (!err) {
		union drgn_value val;
		err = drgn_object_read_integer(&tmp, &val);
		if (!err)
			*pid_out = (uint32_t)val.uvalue;
		else
			drgn_error_destroy(err);
	} else {
		drgn_error_destroy(err);
	}

	/* Read comm */
	err = drgn_object_member(&tmp, task_obj, "comm");
	if (!err && tmp.kind == DRGN_OBJECT_REFERENCE) {
		err = drgn_program_read_c_string(prog, tmp.address,
						 false, 16, comm_out);
		if (err) {
			drgn_error_destroy(err);
			*comm_out = NULL;
		}
	} else {
		if (err)
			drgn_error_destroy(err);
	}

	/* Read CPU (task_struct.cpu field, if present) */
	err = drgn_object_member(&tmp, task_obj, "cpu");
	if (!err) {
		union drgn_value val;
		err = drgn_object_read_integer(&tmp, &val);
		if (!err)
			*cpu_out = (int32_t)val.svalue;
		else
			drgn_error_destroy(err);
	} else {
		drgn_error_destroy(err);
	}

	drgn_object_deinit(&tmp);
}

/*
 * Get a formatted stack trace for a task. Returns a malloc'd string or NULL.
 */
static char *get_task_stack_trace(struct drgn_object *task_obj)
{
	struct drgn_error *err;
	struct drgn_stack_trace *trace = NULL;
	char *trace_str = NULL;

	err = drgn_object_stack_trace(task_obj, &trace);
	if (err) {
		drgn_error_destroy(err);
		return NULL;
	}

	err = drgn_format_stack_trace(trace, &trace_str);
	if (err) {
		drgn_error_destroy(err);
		trace_str = NULL;
	}

	drgn_stack_trace_destroy(trace);
	return trace_str;
}

/*
 * Output a single task entry (for stack trace collection).
 */
static void output_task_entry(uint32_t pid, const char *comm, int32_t cpu,
			      const char *trace_str, bool is_panicked,
			      bool *first_json)
{
	if (opts.format == OUTPUT_JSON) {
		char *comm_esc = json_escape(comm);
		char *trace_esc = json_escape(trace_str);
		if (!*first_json)
			fprintf(out, ",\n");
		fprintf(out,
			"    {\"pid\": %u, \"comm\": %s, \"cpu\": %d",
			pid,
			comm_esc ? comm_esc : "null",
			cpu);
		if (is_panicked)
			fprintf(out, ", \"panicked\": true");
		fprintf(out, ", \"stack_trace\": %s}",
			trace_esc ? trace_esc : "null");
		free(comm_esc);
		free(trace_esc);
		*first_json = false;
	} else {
		if (is_panicked)
			fprintf(out, "--- PID %u (%s) CPU %d [PANICKED] ---\n",
				pid, comm ? comm : "?", cpu);
		else
			fprintf(out, "--- PID %u (%s) CPU %d ---\n",
				pid, comm ? comm : "?", cpu);
		if (trace_str)
			fprintf(out, "%s\n", trace_str);
		else
			fprintf(out, "  (no stack trace available)\n\n");
	}
}

static int collect_stack_traces(struct drgn_program *prog)
{
	struct drgn_error *err;
	struct drgn_object init_task, task_obj, tmp;
	struct drgn_qualified_type task_type;
	uint64_t init_tasks_addr, tasks_offset;
	bool first_json = true;

	drgn_object_init(&init_task, prog);
	drgn_object_init(&task_obj, prog);
	drgn_object_init(&tmp, prog);

	/* Find panicking CPU */
	int64_t panic_cpu = find_panic_cpu(prog);

	if (opts.format == OUTPUT_JSON) {
		fprintf(out, "  \"panic_cpu\": %"PRId64",\n", panic_cpu);
	} else {
		fprintf(out, "=== Stack Traces ===\n");
		if (panic_cpu >= 0)
			fprintf(out, "Panicking CPU: %"PRId64"\n\n", panic_cpu);
	}

	/* Find struct task_struct and tasks member offset */
	err = drgn_program_find_type(prog, "struct task_struct", NULL,
				     &task_type);
	if (err) {
		fprintf(stderr, "warning: could not find struct task_struct: ");
		drgn_error_fwrite(stderr, err);
		fprintf(stderr, "\n");
		drgn_error_destroy(err);
		goto out_close;
	}

	err = drgn_type_offsetof(task_type.type, "tasks", &tasks_offset);
	if (err) {
		fprintf(stderr, "warning: could not find task_struct.tasks offset: ");
		drgn_error_fwrite(stderr, err);
		fprintf(stderr, "\n");
		drgn_error_destroy(err);
		goto out_close;
	}

	/* Get init_task */
	err = drgn_program_find_object(prog, "init_task", NULL,
				       DRGN_FIND_OBJECT_ANY, &init_task);
	if (err) {
		fprintf(stderr, "warning: could not find init_task: ");
		drgn_error_fwrite(stderr, err);
		fprintf(stderr, "\n");
		drgn_error_destroy(err);
		goto out_close;
	}

	/* Get &init_task.tasks to use as the list sentinel */
	err = drgn_object_member(&tmp, &init_task, "tasks");
	if (err) {
		drgn_error_destroy(err);
		goto out_close;
	}
	err = drgn_object_address_of(&tmp, &tmp);
	if (err) {
		drgn_error_destroy(err);
		goto out_close;
	}
	err = drgn_object_read_unsigned(&tmp, &init_tasks_addr);
	if (err) {
		drgn_error_destroy(err);
		goto out_close;
	}

	if (opts.format == OUTPUT_JSON)
		fprintf(out, "  \"stack_traces\": [\n");

	/* Process init_task (PID 0) */
	{
		uint32_t pid;
		char *comm = NULL;
		int32_t cpu;
		read_task_info(prog, &init_task, &pid, &comm, &cpu);

		char *trace_str = get_task_stack_trace(&init_task);
		bool is_panicked = (panic_cpu >= 0 && cpu == panic_cpu);

		output_task_entry(pid, comm ? comm : "swapper", cpu,
				  trace_str, is_panicked, &first_json);

		free(comm);
		free(trace_str);
	}

	/* Walk the task list: init_task.tasks.next ... back to init_task.tasks */
	uint64_t next_addr;
	err = drgn_object_member(&tmp, &init_task, "tasks");
	if (err) {
		drgn_error_destroy(err);
		goto out_close;
	}
	err = drgn_object_member(&tmp, &tmp, "next");
	if (err) {
		drgn_error_destroy(err);
		goto out_close;
	}
	err = drgn_object_read(&tmp, &tmp);
	if (err) {
		drgn_error_destroy(err);
		goto out_close;
	}
	err = drgn_object_read_unsigned(&tmp, &next_addr);
	if (err) {
		drgn_error_destroy(err);
		goto out_close;
	}

	for (size_t count = 0;
	     count < 100000 && next_addr != init_tasks_addr;
	     count++) {
		uint64_t task_addr;
		uint32_t pid;
		char *comm = NULL;
		int32_t cpu;

		/* container_of(next_addr, struct task_struct, tasks) */
		task_addr = next_addr - tasks_offset;

		err = drgn_object_set_reference(&task_obj, task_type,
						task_addr, 0, 0);
		if (err) {
			drgn_error_destroy(err);
			break;
		}

		read_task_info(prog, &task_obj, &pid, &comm, &cpu);

		char *trace_str = get_task_stack_trace(&task_obj);
		bool is_panicked = (panic_cpu >= 0 && cpu == panic_cpu);

		output_task_entry(pid, comm, cpu, trace_str, is_panicked,
				  &first_json);

		free(comm);
		free(trace_str);

		/*
		 * Advance: read the next pointer from the list_head.
		 * next_addr points to a struct list_head; its first field
		 * is .next which is a pointer.
		 */
		err = drgn_program_read_word(prog, next_addr, false,
					     &next_addr);
		if (err) {
			drgn_error_destroy(err);
			break;
		}
	}

out_close:
	if (opts.format == OUTPUT_JSON)
		fprintf(out, "\n  ]");

	drgn_object_deinit(&tmp);
	drgn_object_deinit(&task_obj);
	drgn_object_deinit(&init_task);
	return 0;
}

/* --------------------------------------------------------------------------
 * Main
 * -------------------------------------------------------------------------- */

static void usage(const char *progname)
{
	fprintf(stderr,
		"Usage: %s [OPTIONS] [VMCORE_PATH]\n"
		"\n"
		"Lightweight crash dump triage tool for kdump environments.\n"
		"Quickly extracts preliminary crash data from a vmcore.\n"
		"\n"
		"Options:\n"
		"  --json              Output in JSON format\n"
		"  --text              Output in human-readable text (default)\n"
		"  --no-stacktraces    Skip collecting stack traces (faster)\n"
		"  -o, --output FILE   Write output to FILE instead of stdout\n"
		"  -h, --help          Show this help message\n"
		"\n"
		"VMCORE_PATH defaults to /proc/vmcore\n",
		progname);
}

int main(int argc, char *argv[])
{
	struct drgn_error *err;
	struct drgn_program *prog;
	int ret = 0;

	static const struct option long_options[] = {
		{"json",            no_argument,       NULL, 'j'},
		{"text",            no_argument,       NULL, 't'},
		{"no-stacktraces",  no_argument,       NULL, 'S'},
		{"output",          required_argument, NULL, 'o'},
		{"help",            no_argument,       NULL, 'h'},
		{NULL, 0, NULL, 0},
	};

	int c;
	while ((c = getopt_long(argc, argv, "jtSo:h", long_options, NULL)) != -1) {
		switch (c) {
		case 'j':
			opts.format = OUTPUT_JSON;
			break;
		case 't':
			opts.format = OUTPUT_TEXT;
			break;
		case 'S':
			opts.collect_stacktraces = false;
			break;
		case 'o':
			opts.output_path = optarg;
			break;
		case 'h':
			usage(argv[0]);
			return 0;
		default:
			usage(argv[0]);
			return 1;
		}
	}

	if (optind < argc)
		opts.vmcore_path = argv[optind];

	/* Set up output file */
	if (opts.output_path) {
		out = fopen(opts.output_path, "w");
		if (!out) {
			fprintf(stderr, "error: could not open '%s': %s\n",
				opts.output_path, strerror(errno));
			return 1;
		}
	} else {
		out = stdout;
	}

	/* Open the vmcore */
	fprintf(stderr, "Opening vmcore: %s\n", opts.vmcore_path);

	err = drgn_program_from_core_dump(opts.vmcore_path, &prog);
	if (err) {
		fprintf(stderr, "error: failed to open vmcore '%s': ",
			opts.vmcore_path);
		drgn_error_fwrite(stderr, err);
		fprintf(stderr, "\n");
		drgn_error_destroy(err);
		ret = 1;
		goto out_file;
	}

	/*
	 * Load debug info. This is best-effort: we proceed even if some
	 * debug info is missing. Stack traces will be less detailed but
	 * dmesg and module list will still work.
	 */
	fprintf(stderr, "Loading debug info...\n");

	err = drgn_program_load_debug_info(prog, NULL, 0, true, true);
	if (err) {
		if (err->code == DRGN_ERROR_MISSING_DEBUG_INFO) {
			fprintf(stderr,
				"warning: some debug info not available: ");
			drgn_error_fwrite(stderr, err);
			fprintf(stderr, "\n");
		} else {
			fprintf(stderr, "warning: failed to load debug info: ");
			drgn_error_fwrite(stderr, err);
			fprintf(stderr, "\n");
		}
		drgn_error_destroy(err);
		/* Continue anyway */
	}

	fprintf(stderr, "Collecting crash data...\n");

	/* JSON opening */
	if (opts.format == OUTPUT_JSON)
		fprintf(out, "{\n");

	/* Collect kernel command line */
	collect_cmdline(prog);

	if (opts.format == OUTPUT_JSON)
		fprintf(out, ",\n");

	/* Collect dmesg */
	collect_dmesg(prog);

	if (opts.format == OUTPUT_JSON)
		fprintf(out, ",\n");

	/* Collect loaded modules */
	collect_modules(prog);

	/* Collect stack traces */
	if (opts.collect_stacktraces) {
		if (opts.format == OUTPUT_JSON)
			fprintf(out, ",\n");
		collect_stack_traces(prog);
	}

	/* JSON closing */
	if (opts.format == OUTPUT_JSON)
		fprintf(out, "\n}\n");

	drgn_program_destroy(prog);

	if (opts.output_path)
		fprintf(stderr, "Output written to: %s\n", opts.output_path);
	fprintf(stderr, "Done.\n");

out_file:
	if (out && out != stdout)
		fclose(out);
	return ret;
}
