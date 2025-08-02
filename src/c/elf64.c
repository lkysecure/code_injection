/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   elf64.c                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jdecorte42 <jdecorte42@student.42.fr>      +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/11/07 12:37:51 by mbucci            #+#    #+#             */
/*   Updated: 2023/11/20 16:29:38 by mbucci           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <fcntl.h>
#include "ci_generic.h"
#include "ci_elf.h"

/* Import ASM Function */
extern void _rc4_elf64(void *bytes, uint64_t length, const char *key, uint32_t keysize);

/* Global Variables */
// Base address of injected code and existed code
static Elf64_Addr g_codeseg_addr = 0;
static Elf64_Addr g_handler_addr = 0;
static Elf64_Addr g_parasite_addr = 0;
static Elf64_Addr g_decryptor_addr = 0;

// Offset address of injected code and existed code
static Elf64_Off g_codeseg_off = 0;
static Elf64_Off g_handler_off = 0;
static Elf64_Off g_parasite_off = 0;
static Elf64_Off g_decryptor_off = 0;

// Size of injected code and existed code
static uint64_t g_codeseg_size = 0;
static uint64_t g_handler_size = 0;
static uint64_t g_parasite_size = 0;
static uint64_t g_decryptor_size = 0;
static uint64_t g_total_payload_size = 0;

static int check_boundaries(const t_ci *context)
{
	Elf64_Ehdr *elf = (Elf64_Ehdr *)context->base;

	// ELF 파일의 각 Program Segment와 Section 정보의 유효성 검사
	if ((elf->e_shoff + (sizeof(Elf64_Shdr) * elf->e_shnum) > context->size)
		|| (elf->e_phoff + (sizeof(Elf64_Phdr) * elf->e_phnum) > context->size)
		|| ((elf->e_phentsize * elf->e_phnum) > (sizeof(Elf64_Phdr) * elf->e_phnum))
		|| ((elf->e_shentsize * elf->e_shnum) > (sizeof(Elf64_Shdr) * elf->e_shnum))
		|| (elf->e_ehsize > sizeof(Elf64_Ehdr))
	)
		return 1;

	return 0;
}

static void set_payload_values(Elf64_Off beginoff, Elf64_Addr beginaddr)
{
	g_parasite_off = beginoff;
	g_parasite_addr = beginaddr;

	g_decryptor_off = g_parasite_off + g_parasite_size;
	g_decryptor_addr = g_parasite_addr + g_parasite_size;

	g_handler_off = g_decryptor_off + g_decryptor_size;
	g_handler_addr = g_decryptor_addr + g_decryptor_size;
}

static void patch_section_offsets(const Elf64_Ehdr *elf)
{
	Elf64_Shdr *sh_tab = (Elf64_Shdr *)((void *)elf + elf->e_shoff);

	for (uint16_t i = 0; i < elf->e_shnum; ++i)
	{
		if (sh_tab[i].sh_offset + sh_tab[i].sh_size == g_parasite_off)
		{
			sh_tab[i].sh_size += g_total_payload_size;
			return;
		}
	}
}

static uint8_t not_injectable(Elf64_Ehdr *elf)
{
	Elf64_Phdr *ph_tab = (Elf64_Phdr *)((void *)elf + elf->e_phoff);
	uint64_t padding = 0;
	int8_t found_code = 0;

	for (uint16_t i = 0; i < elf->e_phnum && !found_code; ++i)
	{
		// 프로그램 헤더 순차적 탐색
		// 헤더의 타입이 PT_LOAD, 실행 권한이 R|X 인지 여부 판별 -> Code Segment 탐색
		if (ph_tab[i].p_type == PT_LOAD && ph_tab[i].p_flags == (PF_R | PF_X))
		{
			found_code = 1;

			// 헤더 정보 추출
			g_codeseg_addr = ph_tab[i].p_vaddr;  // virtual address
			g_codeseg_off = ph_tab[i].p_offset;  // offset
			g_codeseg_size = ph_tab[i].p_filesz; // file size

			// 삽입 가능한 코드 사이즈 영역 산출
			// padding = ${다음 segment의 offset} - ( ${code segment의 offset} + ${code segment의 size}
			if (i < elf->e_phnum)
				padding = ph_tab[i + 1].p_offset - (g_codeseg_off + g_codeseg_size);

			// 삽입할 코드의 사이즈가 injection할 padding 영역 사이즈보다 적으면 injection failed
			if (padding < g_total_payload_size)
				return write_error(NULL, PADD_ERR);
			else
			{
				ph_tab[i].p_filesz += g_total_payload_size;
				ph_tab[i].p_memsz += g_total_payload_size;
				ph_tab[i].p_flags |= PF_W;
			}
			break;
		}
	}

	if (!found_code)
		return write_error(NULL, LOAD_ERR);

	set_payload_values(g_codeseg_off + g_codeseg_size, g_codeseg_addr + g_codeseg_size);
	patch_section_offsets(elf);

	return 0;
}

int ci_elf64(t_ci *context)
{
	// 타겟 ELF 파일 boundary 유효성 검사
	if (check_boundaries(context))
		return write_error(context->param_name, CORRUPT_ERR);

	// rc4에서 생성할 암호키 생성 (urandom 기반)
	context->key = generate_key(URANDOM, DFLT_KEY_LEN);
	if (!context->keyisparam && !context->key)
		return 1;

	// handler binary 로드
	void *handler = read_file(HANDLER_ELF64_PATH, &g_handler_size);
	if (!handler)
	{
		free_payloads(context->key, NULL, NULL, NULL);
		write_error(context->param_name, HANDLER_ERR);
	}

	// parasite binary 로드
	void *parasite = read_file(PARASITE_ELF64_PATH, &g_parasite_size);
	if (!parasite)
	{
		free_payloads(context->key, handler, NULL, NULL);
		write_error(context->param_name, PARASITE_ERR);
	}

	// get decryptor
	void *decryptor = read_file(DECRYPTOR_ELF64_PATH, &g_decryptor_size);
	if (!decryptor)
	{
		free_payloads(context->key, handler, parasite, NULL);
		write_error(context->param_name, DECRYPTOR_ERR);
	}

	// key size 추출
	uint32_t keysz = DFLT_KEY_LEN;

	// code injection할 코드들의 전체 사이즈 산출
	g_total_payload_size = g_parasite_size
						+ g_decryptor_size
						+ g_handler_size
						+ (sizeof(char) * keysz);

	// 타겟 ELF 파일이 PT_LOAD 기반의 zero-padding injection이 가능한지 여부 판별
	Elf64_Ehdr *elf = (Elf64_Ehdr *)context->base;
	if (not_injectable(elf))
	{
		free_payloads(context->key, handler, parasite, decryptor);
		return 1;
	}

	// create ci
	int ci_fd = -1;
	if ((ci_fd = open(PATCH, (O_CREAT | O_WRONLY | O_TRUNC), 0755)) == -1)
	{
		free_payloads(context->key, handler, parasite, decryptor);
		return write_error(PATCH, NULL);
	}

	// time to print the key
	if (!context->keyisparam)
		print_key(context->key, DFLT_KEY_LEN);

	// set entrypoint to start of payload
	Elf64_Addr code_entry = elf->e_entry;
	if (elf->e_type == ET_EXEC)
	{
		elf->e_entry = g_handler_addr;
		patch_payload_addr64(handler, g_handler_size, 0x4242424242424242, g_parasite_addr); // offset to parasite
		patch_payload_addr64(handler, g_handler_size, 0xAAAAAAAAAAAAAAAA, 0);
	}
	else
	{
		elf->e_entry = g_handler_off;
		patch_payload_addr64(handler, g_handler_size, 0x4242424242424242, g_parasite_off); // offset to parasite
		patch_payload_addr64(handler, g_handler_size, 0xAAAAAAAAAAAAAAAA, 1);
	}

	patch_payload_addr32(handler, g_handler_size, 0x55555555, keysz); // key size
	patch_payload_addr64(handler, g_handler_size, 0x4444444444444444, g_handler_off + g_handler_size); // offset to key
	patch_payload_addr64(handler, g_handler_size, 0x1942194219421942, g_codeseg_size + g_parasite_size); // text size
	patch_payload_addr64(handler, g_handler_size, 0x2222222222222222, g_codeseg_off); // text offset
	patch_payload_addr64(handler, g_handler_size, 0x1919191919191919, g_decryptor_off); // offset to rc4
	patch_payload_addr64(handler, g_handler_size, 0x3333333333333333, code_entry); // return controlflow

	// inject parasite
	void *inject_addr = context->base + g_parasite_off;
	ft_memmove(inject_addr, parasite, g_parasite_size);

	// inject decryptor
	inject_addr += g_parasite_size;
	ft_memmove(inject_addr, decryptor, g_decryptor_size);

	// inject handler
	inject_addr += g_decryptor_size;
	ft_memmove(inject_addr, handler, g_handler_size);

	// inject key
	inject_addr += g_handler_size;
	ft_memmove(inject_addr, context->key, keysz);

	// encrypt code segment
	_rc4_elf64(context->base + g_codeseg_off, g_codeseg_size + g_parasite_size, context->key, keysz);

	free_payloads(context->key, handler, parasite, decryptor);

	// dump file into ci
	if (write(ci_fd, context->base, context->size) == -1)
	{
		write_error(PATCH, NULL);
		close(ci_fd);
		return 1;
	}

	close(ci_fd);

	return 0;
}
