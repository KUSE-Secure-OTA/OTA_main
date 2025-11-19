# OTA_main
## Branch for Director Repository

### Director
- Director Repository
### Image
- Image Repositoy
- 임시
## Upload
- Watchdog 구현
- 해당 디렉터리에 업데이트 파일 업로드
### 상위 디렉터리(Local)
- root 메타데이터 생성

## 수정 필요
1. 코드 상에서 metadata 저장 위치, key 이름 및 참조 위치 변경 필요
2. root 생성 시 Director, Image 다른 키 쓰도록 바꿔야 함


# OTA System Setup & Execution Guide

이 문서는 OTA Director Server와 Primary ECU 간의 OTA 업데이트 환경을
구성하고 실행하는 절차를 정리한 가이드입니다.

------------------------------------------------------------------------

## 📌 1. MQTT 및 HTTP 인증서 제작 및 설정

MQTT 브로커와 Flask 서버 통신을 위해 필요한 인증서를 제작하고 아래
경로에 배치합니다.

-   `OTA_Director_Server/src/utils/certs`
-   `Primary_ECU/utils/certs`

인증서 제작 방법 참고:\
🔗 https://www.notion.so/Linux-2484ccbeeb28809ca4dcd98faaedbfdd?pvs=21

------------------------------------------------------------------------

## 📌 2. MQTT 브로커 및 Flask 서버 IP 설정

다음 파일에서 MQTT 및 HTTP 서버 IP 주소를 환경에 맞게 수정합니다.

-   `OTA_Director_Server/src/Image_Repository.py`
-   `Primary_ECU/Prime_ECU.py`

------------------------------------------------------------------------

## 📌 3. Chunking Watchdog 실행

이미지 chunking 상태를 모니터링하기 위해 watchdog을 실행합니다.

``` bash
python3 OTA_Director_Server/src/chunking_watchdog.py
```

------------------------------------------------------------------------

## 📌 4. 컨테이너 이미지 준비 및 배포 파일 배치

OTA 업데이트에 사용할 `HU_ver1.tar.xz` 파일을 아래 디렉터리에
배치합니다.

-   `OTA_Director_Server/src_add/stage`

이미지는 Docker Hub에서 가져와 oci-archive 형식으로 변환해 사용합니다.

``` bash
podman pull hanbin6157/seame_hu_app:1.0.0
podman save --format oci-archive -o HU_ver1.tar.xz seame_hu_app:1.0.0
```

------------------------------------------------------------------------

## 📌 5. Image Repository 실행

컨테이너 이미지 chunk 생성 및 OTA 파일 배포 기능을 수행하는 Image
Repository를 실행합니다.

``` bash
python3 OTA_Director_Server/src/Image_Repository.py
```

------------------------------------------------------------------------

## 📌 6. Prime ECU 실행

ECU 측에서 업데이트 요청 및 수신을 담당하는 Prime ECU 프로그램을
실행합니다.

``` bash
python3 Primary_ECU/Prime_ECU.py
```

------------------------------------------------------------------------

## 📌 7. 컨테이너 이미지 빌드 및 자동 실행

Prime ECU 실행과 동시에 다운로드가 진행되며, Prime ECU에서 전송된 이미지로 컨테이너를 자동 빌드 및
실행 됨

------------------------------------------------------------------------

## ⚠️ 디렉터리 구조 확인

    /Primary_ECU/download
    /OTA_Director_Server/src_add/stage
    /OTA_Director_Server/src_add/tmp
    /OTA_Director_Server/Image_Repo/chunks_storage