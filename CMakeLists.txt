cmake_minimum_required(VERSION 3.16)
project(binary_encryption C)

set(CMAKE_C_STANDARD 11)

set(CMAKE_VERBOSE_MAKEFILE ON)

# 컴파일 플래그 설정
include_directories(include libft/includes)

# libft 서브디렉토리 추가
add_subdirectory(libft)

# 소스 파일 목록
set(SRC_DIR ${CMAKE_SOURCE_DIR}/src/c)
set(ASM_SRC_DIR ${CMAKE_SOURCE_DIR}/src/asm)
set(PAYLOAD_DIR payloads)

set(C_SOURCES
    ${SRC_DIR}/main.c
    ${SRC_DIR}/utils.c
    ${SRC_DIR}/elf64.c
)

# NASM 오브젝트 (링크용)
set(RC4_ASM ${ASM_SRC_DIR}/rc4_elf64.s)
set(RC4_OBJ ${CMAKE_CURRENT_BINARY_DIR}/rc4_elf64.o)

add_custom_command(
    OUTPUT ${RC4_OBJ}
    COMMAND nasm -f elf64 ${RC4_ASM} -o ${RC4_OBJ}
    DEPENDS ${RC4_ASM}
    COMMENT "Assembling rc4_elf64.s with nasm"
)


# main 바이너리 타겟
add_executable(${PROJECT_NAME} ${RC4_OBJ} ${C_SOURCES})
target_link_libraries(${PROJECT_NAME} PRIVATE ft)

# payloads 디렉토리 생성
file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/${PAYLOAD_DIR})

# payload .s 파일을 .bin으로 변환
set(PAYLOAD_ASM
    handler_elf64.s
    parasite_elf64.s
    rc4_elf64.s
)

foreach(sfile IN LISTS PAYLOAD_ASM)
    get_filename_component(base ${sfile} NAME_WE)
    set(src_path ${ASM_SRC_DIR}/${sfile})
    set(bin_path ${CMAKE_BINARY_DIR}/${PAYLOAD_DIR}/${base}.bin)

    add_custom_command(
        OUTPUT ${bin_path}
        COMMAND nasm -f bin ${src_path} -o ${bin_path}
        DEPENDS ${src_path}
        COMMENT "Assembling payload: ${sfile}"
    )

    list(APPEND PAYLOAD_BINARIES ${bin_path})
endforeach()

# payload 타겟 추가
add_custom_target(payloads ALL DEPENDS ${PAYLOAD_BINARIES})

# main 빌드 전에 payloads 생성
add_dependencies(${PROJECT_NAME} payloads)

# clean_payloads 추가
add_custom_target(clean_payloads
    COMMAND ${CMAKE_COMMAND} -E remove_directory ${CMAKE_BINARY_DIR}/${PAYLOAD_DIR}
    COMMENT "Cleaning payloads"
)
