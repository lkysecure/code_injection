cmake_minimum_required(VERSION 3.16)
project(ft C)

set(CMAKE_C_STANDARD 11)

# include 디렉토리 추가
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

# 소스 디렉토리
set(SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src)

# 소스 파일 목록
set(SOURCES
    ${SRC_DIR}/ft_atoi.c
    ${SRC_DIR}/ft_bzero.c
    ${SRC_DIR}/ft_calloc.c
    ${SRC_DIR}/ft_isalnum.c
    ${SRC_DIR}/ft_isalpha.c
    ${SRC_DIR}/ft_isascii.c
    ${SRC_DIR}/ft_isdigit.c
    ${SRC_DIR}/ft_isprint.c
    ${SRC_DIR}/ft_itoa.c
    ${SRC_DIR}/ft_memchr.c
    ${SRC_DIR}/ft_memcmp.c
    ${SRC_DIR}/ft_memmove.c
    ${SRC_DIR}/ft_memset.c
    ${SRC_DIR}/ft_putchar_fd.c
    ${SRC_DIR}/ft_putendl_fd.c
    ${SRC_DIR}/ft_putnbr_fd.c
    ${SRC_DIR}/ft_putstr_fd.c
    ${SRC_DIR}/ft_split.c
    ${SRC_DIR}/ft_strchr.c
    ${SRC_DIR}/ft_strdup.c
    ${SRC_DIR}/ft_striteri.c
    ${SRC_DIR}/ft_strjoin.c
    ${SRC_DIR}/ft_strlcat.c
    ${SRC_DIR}/ft_strlcpy.c
    ${SRC_DIR}/ft_strlen.c
    ${SRC_DIR}/ft_strmapi.c
    ${SRC_DIR}/ft_strncmp.c
    ${SRC_DIR}/ft_strnstr.c
    ${SRC_DIR}/ft_strrchr.c
    ${SRC_DIR}/ft_strtrim.c
    ${SRC_DIR}/ft_swap.c
    ${SRC_DIR}/ft_substr.c
    ${SRC_DIR}/ft_tolower.c
    ${SRC_DIR}/ft_toupper.c
)

# 정적 라이브러리 생성
add_library(ft STATIC ${SOURCES})
