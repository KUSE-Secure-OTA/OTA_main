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
