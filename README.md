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

------------------------------------------------------------------------
# OTA_main : targets 형식 변경
- OTA_Director_Server에서 새로운 형식대로 메타데이터 생성하도록 코드 수정하였습니다.
## chunking_watchdog.py
- ../src_add/stage에 올라가는 새로운 이미지(.tar) 감지
- fastcdc_chunking.py의 split_all()에 넣어서 청크 분할
- 리턴값 이용해 manifest(ex.ivi_1.0.0.json) 생성
- manifest 첨가된 targets.json 최신화
## fastcdc_chunking.py
- 전달받은 .tar 형식 이미지 압축 해제 후 분할
- manifest의 signed 부분 형식에 맞게 넣어서 리턴
## 전체 흐름
### 1. 이미지 업로드
- 이미지 파일명 : {image}_x.y.z.tar (ex. ivi_1.0.0.tar)
- ../src_add/stage에 업로드
### 2. 이미지 청크 분할
- 청크들은 로컬과 Image Repository에 각각 동일하게 저장.
- 둘 다 /chunks_storage 디렉터리에 중복 제거 후 저장됨.
### 3. 이미지에 대한 Manifest 생성
- Manifest 파일명 : {image}_x.y.z.json (ex. ivi_1.0.0.json)
- Image Repository와 Director Repository의 /meta/targets 디렉터리에 동일하게 저장됨.
- 디렉터리 구조 예시
  ```
  targets
  ├── cluster
  │   └── cluster_image
  │       └── cluster_1.0.0.json
  └── ivi
      └── ivi_image
          ├── ivi_1.0.0.json
          └── ivi_2.0.0.json
  ```
### 4. targets 생성
- 파일명 : targets.json
- 원본 이미지에 대한 정보와 각 manifest에 대한 키 정보 등이 담김.
- Image Repository와 Director Repository의 /meta/ 디렉터리에 동일하게 저장됨.
