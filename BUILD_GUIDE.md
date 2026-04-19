# Bootkit Analysis Framework - Build Guide

## 빌드 가이드 (한국어)

### 필수 요구사항

#### 사용자 모드 컴포넌트 (Tools, Tests)
- Windows 10/11
- Visual Studio 2019 이상
- C++ 데스크톱 개발 워크로드

#### 드라이버 컴포넌트 (BootkitDriver)
- 위의 모든 요구사항 +
- Windows Driver Kit (WDK) 10
- Windows SDK 10

### 빌드 방법

#### 옵션 1: 사용자 모드만 빌드 (권장 - WDK 불필요)

```batch
build_usermode.bat
```

또는 특정 구성으로 빌드:
```batch
build_usermode.bat Debug
build_usermode.bat Release
```

이 방법은 다음을 빌드합니다:
- BootkitTools.exe - 분석 도구
- BootkitTests.exe - 테스트 스위트

#### 옵션 2: 전체 솔루션 빌드 (WDK 필요)

```batch
build.bat
```

또는 특정 구성으로 빌드:
```batch
build.bat Debug
build.bat Release
build.bat TestSign
```

이 방법은 다음을 빌드합니다:
- BootkitDriver.sys - 커널 드라이버
- BootkitTools.exe - 분석 도구
- BootkitTests.exe - 테스트 스위트

#### 옵션 3: Visual Studio에서 빌드

1. `BootkitAnalysisFramework.sln` 파일을 Visual Studio에서 엽니다
2. 솔루션 탐색기에서 빌드할 프로젝트를 선택합니다:
   - BootkitTools (WDK 불필요)
   - BootkitTests (WDK 불필요)
   - BootkitDriver (WDK 필요)
3. 빌드 > 솔루션 빌드 (Ctrl+Shift+B)

### 빌드 구성

- **Debug**: 디버깅 정보 포함, 최적화 없음
- **Release**: 최적화됨, 디버깅 정보 포함
- **TestSign**: Release + 테스트 서명 (드라이버용)

### 출력 위치

빌드된 파일은 다음 위치에 생성됩니다:
```
bin/x64/[Configuration]/
  ├── BootkitDriver.sys    (드라이버)
  ├── BootkitTools.exe     (도구)
  └── BootkitTests.exe     (테스트)
```

### 실행 방법

#### 테스트 실행
```batch
cd bin\x64\Release
BootkitTests.exe
```

#### 도구 사용
```batch
cd bin\x64\Release
BootkitTools.exe analyze
BootkitTools.exe monitor
BootkitTools.exe report
```

#### 드라이버 설치 (관리자 권한 필요)

1. 테스트 서명 모드 활성화:
```batch
scripts\enable_test_signing.bat
```

2. 시스템 재부팅

3. 드라이버 설치:
```batch
sc create BootkitDriver type= kernel binPath= "C:\path\to\BootkitDriver.sys"
sc start BootkitDriver
```

### 문제 해결

#### "Windows Driver Kit not found" 오류
- WDK를 설치하거나 `build_usermode.bat`를 사용하세요
- WDK 다운로드: https://docs.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk

#### "MSBuild not found" 오류
- Visual Studio Installer를 실행하고 "C++ 데스크톱 개발" 워크로드를 설치하세요

#### "Platform Toolset" 오류
- Visual Studio 버전과 프로젝트 파일의 PlatformToolset이 일치하는지 확인하세요
- Visual Studio 2022: v143
- Visual Studio 2019: v142

#### 링크 오류
- Windows SDK가 설치되어 있는지 확인하세요
- Visual Studio Installer에서 "Windows 10 SDK" 또는 "Windows 11 SDK"를 설치하세요

### 개발 환경 설정

#### Visual Studio 2022 권장 워크로드
- C++ 데스크톱 개발
- Windows 10 SDK (10.0.19041.0 이상)
- Windows Driver Kit (드라이버 개발용)

#### 선택적 도구
- Visual Studio Code (코드 편집용)
- WinDbg (커널 디버깅용)
- OSR Driver Loader (드라이버 테스트용)

---

## Build Guide (English)

### Prerequisites

#### User-Mode Components (Tools, Tests)
- Windows 10/11
- Visual Studio 2019 or later
- C++ Desktop Development workload

#### Driver Component (BootkitDriver)
- All of the above +
- Windows Driver Kit (WDK) 10
- Windows SDK 10

### Build Instructions

#### Option 1: Build User-Mode Only (Recommended - No WDK Required)

```batch
build_usermode.bat
```

Or build specific configuration:
```batch
build_usermode.bat Debug
build_usermode.bat Release
```

This builds:
- BootkitTools.exe - Analysis tools
- BootkitTests.exe - Test suite

#### Option 2: Build Full Solution (WDK Required)

```batch
build.bat
```

Or build specific configuration:
```batch
build.bat Debug
build.bat Release
build.bat TestSign
```

This builds:
- BootkitDriver.sys - Kernel driver
- BootkitTools.exe - Analysis tools
- BootkitTests.exe - Test suite

#### Option 3: Build in Visual Studio

1. Open `BootkitAnalysisFramework.sln` in Visual Studio
2. Select project to build in Solution Explorer:
   - BootkitTools (No WDK required)
   - BootkitTests (No WDK required)
   - BootkitDriver (WDK required)
3. Build > Build Solution (Ctrl+Shift+B)

### Build Configurations

- **Debug**: Debug info included, no optimization
- **Release**: Optimized, debug info included
- **TestSign**: Release + test signing (for driver)

### Output Location

Built files are located at:
```
bin/x64/[Configuration]/
  ├── BootkitDriver.sys    (driver)
  ├── BootkitTools.exe     (tools)
  └── BootkitTests.exe     (tests)
```

### Running

#### Run Tests
```batch
cd bin\x64\Release
BootkitTests.exe
```

#### Use Tools
```batch
cd bin\x64\Release
BootkitTools.exe analyze
BootkitTools.exe monitor
BootkitTools.exe report
```

#### Install Driver (Administrator Required)

1. Enable test signing:
```batch
scripts\enable_test_signing.bat
```

2. Reboot system

3. Install driver:
```batch
sc create BootkitDriver type= kernel binPath= "C:\path\to\BootkitDriver.sys"
sc start BootkitDriver
```

### Troubleshooting

#### "Windows Driver Kit not found" Error
- Install WDK or use `build_usermode.bat`
- Download WDK: https://docs.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk

#### "MSBuild not found" Error
- Run Visual Studio Installer and install "Desktop development with C++" workload

#### "Platform Toolset" Error
- Ensure Visual Studio version matches project PlatformToolset
- Visual Studio 2022: v143
- Visual Studio 2019: v142

#### Link Errors
- Ensure Windows SDK is installed
- Install "Windows 10 SDK" or "Windows 11 SDK" via Visual Studio Installer

### Development Environment Setup

#### Recommended Visual Studio 2022 Workloads
- Desktop development with C++
- Windows 10 SDK (10.0.19041.0 or later)
- Windows Driver Kit (for driver development)

#### Optional Tools
- Visual Studio Code (for code editing)
- WinDbg (for kernel debugging)
- OSR Driver Loader (for driver testing)
