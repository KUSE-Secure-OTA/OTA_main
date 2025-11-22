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
