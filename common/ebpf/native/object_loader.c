// Copyright 2026, Asterisk4Magisk contributors
// Copyright 2026, sing-box contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include "singbox_ebpf.h"

#include <elf.h>
#include <errno.h>
#include <linux/bpf.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef R_BPF_64_64
#define R_BPF_64_64 1U
#endif
#ifndef R_BPF_64_32
#define R_BPF_64_32 10U
#endif

static bool object_range_valid(size_t offset, size_t size, size_t total) {
	return offset <= total && size <= total - offset;
}

static const Elf64_Shdr *object_section(const Elf64_Ehdr *header, size_t object_size, size_t index) {
	if (index >= header->e_shnum ||
	    header->e_shentsize != sizeof(Elf64_Shdr) ||
	    !object_range_valid(header->e_shoff, (size_t)header->e_shnum * sizeof(Elf64_Shdr), object_size)) {
		return NULL;
	}
	return (const Elf64_Shdr *)((const uint8_t *)header + header->e_shoff + index * sizeof(Elf64_Shdr));
}

static const char *object_section_name(
	const Elf64_Ehdr *header,
	size_t object_size,
	const Elf64_Shdr *section) {
	const Elf64_Shdr *strings = object_section(header, object_size, header->e_shstrndx);
	if (strings == NULL || strings->sh_type != SHT_STRTAB ||
	    !object_range_valid(strings->sh_offset, strings->sh_size, object_size) ||
	    section->sh_name >= strings->sh_size) {
		return NULL;
	}
	return (const char *)header + strings->sh_offset + section->sh_name;
}

static const Elf64_Shdr *object_find_section(
	const Elf64_Ehdr *header,
	size_t object_size,
	const char *name,
	size_t *index_out) {
	for (size_t index = 0U; index < header->e_shnum; ++index) {
		const Elf64_Shdr *section = object_section(header, object_size, index);
		const char *current = section == NULL ? NULL : object_section_name(header, object_size, section);
		if (current != NULL && strcmp(current, name) == 0) {
			if (index_out != NULL) {
				*index_out = index;
			}
			return section;
		}
	}
	errno = ENOENT;
	return NULL;
}

struct sb_btf_ext_header {
	uint16_t magic;
	uint8_t version;
	uint8_t flags;
	uint32_t hdr_len;
	uint32_t func_info_off;
	uint32_t func_info_len;
	uint32_t line_info_off;
	uint32_t line_info_len;
	uint32_t core_relo_off;
	uint32_t core_relo_len;
};

/* This loader consumes standard BTF map metadata but deliberately does not
 * pretend to apply CO-RE field relocations.  Programs using preserve_access_index
 * must be rejected until a relocation engine is present; silently ignoring
 * .BTF.ext core_relo would create kernel-dependent memory accesses. */
static int object_validate_btf_ext(const Elf64_Ehdr *header, size_t object_size) {
	const Elf64_Shdr *btf = object_find_section(header, object_size, ".BTF", NULL);
	const Elf64_Shdr *btf_ext = object_find_section(header, object_size, ".BTF.ext", NULL);
	if (btf == NULL && btf_ext == NULL) {
		errno = 0;
		return 0;
	}
	if (btf == NULL || btf_ext == NULL ||
	    !object_range_valid(btf->sh_offset, btf->sh_size, object_size) ||
	    !object_range_valid(btf_ext->sh_offset, btf_ext->sh_size, object_size) ||
	    btf_ext->sh_size < sizeof(struct sb_btf_ext_header)) {
		errno = ENOEXEC;
		return -1;
	}
	const struct sb_btf_ext_header *ext =
		(const struct sb_btf_ext_header *)((const uint8_t *)header + btf_ext->sh_offset);
	if (ext->magic != 0xeb9fU || ext->version != 1U ||
	    ext->hdr_len < sizeof(*ext) || ext->hdr_len > btf_ext->sh_size ||
	    ext->core_relo_off > btf_ext->sh_size - ext->hdr_len ||
	    ext->core_relo_len > btf_ext->sh_size - ext->hdr_len - ext->core_relo_off) {
		errno = ENOEXEC;
		return -1;
	}
	if (ext->core_relo_len != 0U) {
		errno = ENOTSUP;
		return -1;
	}
	return 0;
}

static int object_map_fd(const char *name, const struct sb_ebpf_object_map_table *maps) {
	if (name == NULL || maps == NULL || maps->entries == NULL) {
		errno = ENOENT;
		return -1;
	}
	for (size_t i = 0U; i < maps->count; ++i) {
		if (maps->entries[i].name != NULL && strcmp(name, maps->entries[i].name) == 0) {
			if (maps->entries[i].fd < 0) {
				errno = EINVAL;
				return -1;
			}
			return maps->entries[i].fd;
		}
	}
	errno = ENOENT;
	return -1;
}

static int object_relocate_section(
	const Elf64_Ehdr *header,
	size_t object_size,
	size_t source_section_index,
	size_t source_base,
	size_t text_section_index,
	size_t text_base,
	struct bpf_insn *instructions,
	size_t instruction_count,
	const struct sb_ebpf_object_map_table *maps) {
	for (size_t index = 0U; index < header->e_shnum; ++index) {
		const Elf64_Shdr *relocations = object_section(header, object_size, index);
		if (relocations == NULL || relocations->sh_type != SHT_REL ||
		    relocations->sh_info != source_section_index) {
			continue;
		}
		const Elf64_Shdr *symbols = object_section(header, object_size, relocations->sh_link);
		if (symbols == NULL || symbols->sh_type != SHT_SYMTAB ||
		    symbols->sh_entsize != sizeof(Elf64_Sym) ||
		    !object_range_valid(symbols->sh_offset, symbols->sh_size, object_size)) {
			errno = ENOEXEC;
			return -1;
		}
		const Elf64_Shdr *strings = object_section(header, object_size, symbols->sh_link);
		if (strings == NULL || strings->sh_type != SHT_STRTAB ||
		    !object_range_valid(strings->sh_offset, strings->sh_size, object_size) ||
		    relocations->sh_entsize != sizeof(Elf64_Rel) ||
		    !object_range_valid(relocations->sh_offset, relocations->sh_size, object_size)) {
			errno = ENOEXEC;
			return -1;
		}
		const Elf64_Rel *entries = (const Elf64_Rel *)((const uint8_t *)header + relocations->sh_offset);
		size_t relocation_count = relocations->sh_size / sizeof(Elf64_Rel);
		const Elf64_Sym *symbol_table = (const Elf64_Sym *)((const uint8_t *)header + symbols->sh_offset);
		size_t symbol_count = symbols->sh_size / sizeof(Elf64_Sym);
		const char *string_table = (const char *)header + strings->sh_offset;
		for (size_t relocation_index = 0U; relocation_index < relocation_count; ++relocation_index) {
			const Elf64_Rel *relocation = &entries[relocation_index];
			size_t symbol_index = ELF64_R_SYM(relocation->r_info);
			if (symbol_index >= symbol_count ||
			    relocation->r_offset % sizeof(struct bpf_insn) != 0U) {
				errno = ENOEXEC;
				return -1;
			}
			size_t instruction_index = source_base + relocation->r_offset / sizeof(struct bpf_insn);
			const Elf64_Sym *symbol = &symbol_table[symbol_index];
			if (instruction_index >= instruction_count || symbol->st_name >= strings->sh_size) {
				errno = ENOEXEC;
				return -1;
			}
			uint32_t relocation_type = ELF64_R_TYPE(relocation->r_info);
			if (relocation_type == R_BPF_64_64) {
				if (instruction_index + 1U >= instruction_count) {
					errno = ENOEXEC;
					return -1;
				}
				int map_fd = object_map_fd(string_table + symbol->st_name, maps);
				if (map_fd < 0) {
					return -1;
				}
				instructions[instruction_index].src_reg = BPF_PSEUDO_MAP_FD;
				instructions[instruction_index].imm = map_fd;
				instructions[instruction_index + 1U].imm = 0;
			} else if (relocation_type == R_BPF_64_32) {
				size_t target_base;
				if (symbol->st_shndx == text_section_index) {
					target_base = text_base;
				} else if (symbol->st_shndx == source_section_index) {
					target_base = source_base;
				} else {
					errno = ENOEXEC;
					return -1;
				}
				if (symbol->st_value % sizeof(struct bpf_insn) != 0U) {
					errno = ENOEXEC;
					return -1;
				}
				size_t target_index = target_base + symbol->st_value / sizeof(struct bpf_insn);
				if (target_index >= instruction_count) {
					errno = ENOEXEC;
					return -1;
				}
				instructions[instruction_index].imm =
					(int32_t)(target_index - instruction_index - 1U);
			} else {
				errno = ENOEXEC;
				return -1;
			}
		}
	}
	return 0;
}

int sb_ebpf_object_load_section(
	const uint8_t *object,
	size_t object_size,
	const char *section_name,
	const char *program_name,
	enum bpf_prog_type prog_type,
	enum bpf_attach_type expected_attach_type,
	const struct sb_ebpf_object_map_table *maps) {
	if (object == NULL || section_name == NULL || program_name == NULL || maps == NULL ||
	    object_size < sizeof(Elf64_Ehdr)) {
		errno = EINVAL;
		return -1;
	}
	const Elf64_Ehdr *header = (const Elf64_Ehdr *)object;
	if (memcmp(header->e_ident, ELFMAG, SELFMAG) != 0 ||
	    header->e_ident[EI_CLASS] != ELFCLASS64 ||
	    header->e_ident[EI_DATA] != ELFDATA2LSB ||
	    header->e_machine != EM_BPF) {
		errno = ENOEXEC;
		return -1;
	}
	if (object_validate_btf_ext(header, object_size) != 0) {
		fprintf(stderr, "%s BTF/CO-RE validation failed: errno=%d\n", section_name, errno);
		return -1;
	}

	size_t section_index = 0U;
	size_t text_section_index = 0U;
	const Elf64_Shdr *section = object_find_section(header, object_size, section_name, &section_index);
	/* .text may be empty (standalone program sections like sk_skb/*). */
	const Elf64_Shdr *text_section = object_find_section(header, object_size, ".text", &text_section_index);
	bool has_text = text_section != NULL && text_section->sh_size > 0U;
	if (section == NULL || section->sh_size == 0U ||
	    section->sh_size % sizeof(struct bpf_insn) != 0U ||
	    !object_range_valid(section->sh_offset, section->sh_size, object_size) ||
	    (has_text &&
	     (text_section->sh_size % sizeof(struct bpf_insn) != 0U ||
	      !object_range_valid(text_section->sh_offset, text_section->sh_size, object_size)))) {
		fprintf(
			stderr,
			"%s section validation failed: section=%p text=%p object_size=%zu errno=%d\n",
			section_name,
			(const void *)section,
			(const void *)text_section,
			object_size,
			errno);
		errno = ENOEXEC;
		return -1;
	}

	size_t text_size = has_text ? text_section->sh_size : 0U;
	size_t combined_size = section->sh_size + text_size;
	struct bpf_insn *instructions = malloc(combined_size);
	if (instructions == NULL) {
		return -1;
	}
	memcpy(instructions, (const uint8_t *)header + section->sh_offset, section->sh_size);
	if (has_text) {
		memcpy(
			(uint8_t *)instructions + section->sh_size,
			(const uint8_t *)header + text_section->sh_offset,
			text_section->sh_size);
	}
	size_t entry_instruction_count = section->sh_size / sizeof(struct bpf_insn);
	size_t instruction_count = combined_size / sizeof(struct bpf_insn);
	int result = -1;
	/*
	 * When .text is empty/absent, do NOT pass section_index as text_section_index:
	 * R_BPF_64_32 would match local symbols against the wrong base (audit P2).
	 * Use an impossible index so only source_section_index matches.
	 */
	size_t reloc_text_index = has_text ? text_section_index : (size_t)-1;
	size_t reloc_text_base = has_text ? entry_instruction_count : 0U;
	int entry_relocation = object_relocate_section(
		header,
		object_size,
		section_index,
		0U,
		reloc_text_index,
		reloc_text_base,
		instructions,
		instruction_count,
		maps);
	int text_relocation = 0;
	if (entry_relocation == 0 && has_text) {
		text_relocation = object_relocate_section(
			header,
			object_size,
			text_section_index,
			entry_instruction_count,
			text_section_index,
			entry_instruction_count,
			instructions,
			instruction_count,
			maps);
	}
	if (entry_relocation == 0 && text_relocation == 0) {
		result = sb_ebpf_load_prog(
			instructions,
			instruction_count,
			program_name,
			prog_type,
			expected_attach_type,
			true);
	} else {
		fprintf(
			stderr,
			"%s relocation failed: entry=%d text=%d errno=%d\n",
			section_name,
			entry_relocation,
			text_relocation,
			errno);
	}
	int saved_errno = errno;
	free(instructions);
	errno = saved_errno;
	return result;
}
