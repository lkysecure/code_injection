#include "ci_generic.h"
#include "ci_elf.h"

static int check_arg(const char *filename)
{
	t_ci context = {filename, 0, NULL, NULL, 0};

	int err = 1;

	// 타겟 ELF 파일의 Header 위치와 전체 파일 사이즈 저장 
	if (!(context.base = read_file(filename, &context.size)))
		return err;

	// 1.타겟 ELF Magic number 유효성 검사
	Elf64_Ehdr *elf = (Elf64_Ehdr *)context.base;
	const unsigned char *f_ident = elf->e_ident;
	if (f_ident[EI_MAG0] != ELFMAG0
			|| f_ident[EI_MAG1] != ELFMAG1
			|| f_ident[EI_MAG2] != ELFMAG2
			|| f_ident[EI_MAG3] != ELFMAG3
	   )
		write_error(filename, ELF_ERR);

	// 2.ELF Header Class가 ELF64인지 검사
	else if (f_ident[EI_CLASS] != ELFCLASS64)
		write_error(filename, FORMAT_ERR);

	// check if file type is executable
	else if (elf->e_type != ET_EXEC && elf->e_type != ET_DYN)
		write_error(filename, ELFEXEC_ERR);

	else
	{
		// Code Injection 수행
		err = ci_elf64(&context);
	}

	free(context.base);

	return err;
}

int main(int argc, char **argv)
{
	// [USAGE] : ./code_injection [original executable]
	if (argc != 2)
		return write_error(NULL, USAGE_ERR);

	return check_arg(argv[1]);
}
