BITS 64

global _start

section .text

_start:
	push rax
	push rdx
	push rdi
	push rsi

	mov rax, 1              ; syscall 번호 1 (sys_write)
    mov rdi, rax            ; 파일 디스크립터: 1 (stdout)
    lea rsi, [rel mystr]    ; 출력할 문자열 주소를 rsi에 로드
    mov rdx, 16             ; 출력할 길이: 16바이트
    syscall                 ; syscall 수행 (write(stdout, mystr, 16))

	pop rsi
	pop rdi
	pop rdx
	pop rax

	ret

mystr: db	"....COONTEC....",10,0
