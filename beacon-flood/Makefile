# 컴파일러 설정
CC = gcc
CFLAGS = -Wall -Wextra -O2
LDFLAGS = -lpthread

# 실행 파일 및 소스 코드
TARGET = mdk_s
SRC = mdk_s.c

# 기본 빌드 규칙
all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) $(LDFLAGS)

# 실행 파일 삭제
clean:
	rm -f $(TARGET)
