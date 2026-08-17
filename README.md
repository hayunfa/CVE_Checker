# ai-cve-watch — AI 오픈소스 CVE 자동 수집기

인터넷망에서 **하루 1회 자동 실행**되어 AI 오픈소스(PyTorch·vLLM·LangChain 등 55종)의
**신규 CVE를 수집** → **엑셀(`CVE_YYYYMMDD.xls`) 생성** → **메일 발송** → **DB 적재** →
**웹 페이지 열람**까지 처리합니다. 전부 무료 서비스만 씁니다(신용카드 불필요).

생성된 엑셀은 **폐쇄망(내부망) SW관리도구로 반입되어 그대로 파싱**됩니다.
그래서 [5. 엑셀 출력 규격](#5-엑셀-출력-규격-내부망-담당자-전달용)은 **한 글자도 바꾸면 안 됩니다.**

```
GitHub Actions (매일 06:00 KST)
   └─ 수집 NVD·OSV·GHSA·KEV
        └─ 병합·정규화 (버전범위 문자열 변환)
             ├─ output/CVE_YYYYMMDD.xls   ← 내부망 반입용 정본
             ├─ 메일 발송 (개별 발송)
             ├─ data/cve.db (SQLite, 저장소에 커밋)
             └─ docs/ (GitHub Pages 열람 페이지)
```

---

## 목차

1. [5분 셋업](#1-5분-셋업)
2. [감시 대상(watchlist) 추가하기](#2-감시-대상watchlist-추가하기)
3. [Gmail 앱 비밀번호 발급](#3-gmail-앱-비밀번호-발급)
4. [60일 자동 비활성화 대응](#4-60일-자동-비활성화-대응)
5. [엑셀 출력 규격 (내부망 담당자 전달용)](#5-엑셀-출력-규격-내부망-담당자-전달용)
6. [무료 티어 한계와 Supabase 전환](#6-무료-티어-한계와-supabase-전환)
7. [수집 범위(Scope) 조절하기](#7-수집-범위scope-조절하기)
8. [CLI 사용법](#8-cli-사용법)
9. [저장소 구조](#9-저장소-구조)
10. [문제 해결](#10-문제-해결)
11. [SUMMARY 한국어 번역](#11-summary-한국어-번역)

---

## 1. 5분 셋업

> **순서를 지켜 주세요.** ①②③④ 를 마쳐 저장소에 파일이 올라가고 `docs/` 가 만들어진 **뒤에야**
> ⑤ GitHub Pages 설정이 가능합니다. 비어 있는 저장소에서 Settings → Pages 로 먼저 가면
> *"You must first add content to your repository"* 만 뜨고 **Branch 드롭다운이 `None` 하나뿐**이라
> `/docs` 를 고를 수 없습니다.

### ① 저장소 준비 + 코드 올리기 (1분)

이 저장소를 **Public** 으로 포크하거나, 새로 만든 뒤 이 폴더의 내용을 push 합니다.

```bash
git init
git add .
git commit -m "init: ai-cve-watch"
git branch -M main
git remote add origin https://github.com/<사용자명>/<저장소명>.git
git push -u origin main
```

> Public 이어야 GitHub Actions 가 **무제한 무료**입니다. Private 은 월 2,000분 제한이 있습니다.

### ② Secrets 등록 (2분)

저장소 → **Settings → Secrets and variables → Actions → New repository secret**

| 이름 | 필수 | 값 | 설명 |
|---|:---:|---|---|
| `SMTP_HOST` | ✅ | `smtp.gmail.com` | 네이버는 `smtp.naver.com` |
| `SMTP_PORT` | ✅ | `587` | SSL 을 쓰려면 `465` |
| `SMTP_USER` | ✅ | `your@gmail.com` | 보내는 계정 |
| `SMTP_PASS` | ✅ | 앱 비밀번호 16자리 | **계정 비밀번호 아님** → [3장](#3-gmail-앱-비밀번호-발급) |
| `MAIL_FROM` | ✅ | `AI CVE Watch <your@gmail.com>` | 보내는 사람 표시 |
| `NVD_API_KEY` | ⬜ | NVD 발급 키 | 없어도 동작(요청 간 6.5초 대기). 있으면 0.7초로 단축 |
| `GITHUB_TOKEN` | — | 자동 | Actions 가 자동 주입. 직접 등록 불필요 |

> `NVD_API_KEY` 는 https://nvd.nist.gov/developers/request-an-api-key 에서 무료로 받습니다.
> 55종을 매일 도는 데 키가 없으면 약 6분, 있으면 약 1분 걸립니다. **넣는 것을 권장합니다.**

### ③ 수신자 등록 (30초)

`mail_list.txt` 를 열어 받을 사람의 주소를 **1줄에 1개씩** 적습니다.

```
security-team@example.com
sbom-admin@example.com
# 앞에 #을 붙이면 잠시 제외됩니다
```

### ④ 수동으로 1회 실행 (30초 + 대기)

저장소 → **Actions → daily-cve-collect → Run workflow**

- 첫 실행은 `preset` 을 **`backfill`** 로 두면 과거 데이터까지 채웁니다(시간이 오래 걸립니다).
- 가볍게 확인만 하려면 `preset = urgent`, `sources = osv,kev` 로 두세요 (2~3분).

실행이 끝나면 `output/CVE_YYYYMMDD.xls` 가 커밋되고, 메일이 발송되고, **`docs/` 폴더가 만들어집니다.**
**Code** 탭에서 `docs` 폴더가 보이는지 확인한 뒤 ⑤로 넘어가세요.

> Actions 탭에서 *"Workflows aren't being run on this forked repository"* 배너가 보이면
> **`I understand my workflows, go ahead and enable them`** 을 눌러 주세요(포크한 경우에만 나옵니다).

### ⑤ GitHub Pages 켜기 (1분)

저장소 → **Settings → Pages** 로 이동해서

| 항목 | 선택할 값 |
|---|---|
| **Source** | `Deploy from a branch` |
| **Branch** | `main` ← ④를 마쳐야 목록에 나타납니다 |
| **Folder** | `/docs`  ← ★ 루트가 아니라 docs 입니다. 브랜치를 고르면 오른쪽에 생깁니다 |

**Save** 를 누르면 1~2분 뒤 `https://<사용자명>.github.io/<저장소명>` 에서 열람 페이지가 열립니다.

> **Branch 목록에 `main` 이 없고 `None` 뿐이라면** 아직 저장소에 코드가 안 올라간 것입니다.
> ①의 push 가 끝났는지, **Code** 탭에 파일이 보이는지 먼저 확인하세요.
> 폴더 드롭다운(`/ (root)`, `/docs`)은 **브랜치를 먼저 선택해야** 나타납니다.

---

## 2. 감시 대상(watchlist) 추가하기

`config/watchlist.yml` 에 항목을 추가합니다.

```yaml
- canonical_name: PyTorch          # ★ 내부망 TB_SW.SW_NM 과 반드시 일치시킬 것
  aliases: [torch, pytorch, "pytorch/pytorch"]
  ecosystem: pypi                  # pypi / npm / github / other
  pypi: torch                      # OSV 조회용 (npm: / go: 도 가능)
  github: pytorch/pytorch          # GHSA 조회·참고 URL용
  cpe_keyword: pytorch             # NVD keywordSearch 검색어
  vendor: PyTorch Foundation       # 엑셀 VENDOR 컬럼 기본값
  group: framework                 # framework/serving/library/app/ui/vectordb/mlops/base
  enabled: true                    # false 면 수집 대상에서 완전 제외
  in_use: true                     # 내부망에 실제 반입된 S/W 인지
```

> ### ⚠️ 가장 중요한 주의사항
>
> **`canonical_name` 은 내부망 `TB_SW.SW_NM` 값과 글자 하나까지 똑같아야 합니다.**
>
> 엑셀 `SW_NAME` 컬럼에는 원본 패키지명(`torch`)이 아니라 이 `canonical_name`(`PyTorch`)이 들어갑니다.
> 내부망 관리도구는 이 값으로 자산을 매칭하기 때문에,
> 내부망에 `PyTorch` 로 등록돼 있는데 여기에 `Pytorch` 나 `torch` 로 적으면
> **취약점이 어느 자산에도 붙지 않고 그냥 사라집니다.**
>
> 새 S/W 를 추가할 때는 **먼저 내부망 목록에서 정확한 이름을 확인**한 뒤 그대로 옮겨 적으세요.

추가 후 확인:

```bash
python -m src.aicve.main --show-scope --sw-names "새로추가한이름"
# 대상 S/W 1종: 새로추가한이름   ← 이렇게 나오면 정상
```

`in_use` 를 정확히 관리해 두면 `--only-in-use` 로 **실제 반입한 S/W 만** 좁혀 볼 수 있습니다.

---

## 3. Gmail 앱 비밀번호 발급

Gmail 은 2023년부터 일반 비밀번호로 SMTP 로그인이 안 됩니다. **앱 비밀번호**가 필요합니다.

1. **2단계 인증을 먼저 켭니다** → https://myaccount.google.com/security
   → `2단계 인증` → 안내에 따라 설정 (앱 비밀번호는 2단계 인증이 켜져 있어야 나옵니다)
2. https://myaccount.google.com/apppasswords 접속
3. 앱 이름에 `ai-cve-watch` 입력 → **만들기**
4. `abcd efgh ijkl mnop` 형태의 **16자리**가 뜹니다 → **공백을 빼고** `abcdefghijklmnop` 로 복사
5. GitHub Secrets 의 `SMTP_PASS` 에 붙여넣기 (이 화면을 닫으면 다시 볼 수 없습니다)

**네이버 메일**을 쓴다면: 네이버 메일 → 환경설정 → POP3/IMAP 설정 → **IMAP/SMTP 사용함**,
그리고 `SMTP_HOST=smtp.naver.com`, `SMTP_PORT=587`, `SMTP_USER` 는 아이디(@naver.com 포함).

---

## 4. 60일 자동 비활성화 대응

> **GitHub 규칙**: Public 저장소의 `schedule` 워크플로는 **60일간 저장소에 활동(커밋)이 없으면
> 자동으로 비활성화**됩니다.

**이 저장소는 대개 문제없습니다.** 매일 실행될 때마다 `data/cve.db`·`output/`·`docs/` 를
자동 커밋하므로 활동이 계속 기록되기 때문입니다.

다만 아래 경우에는 멈출 수 있습니다.

- 오랫동안 신규 CVE가 0건이라 커밋할 변경이 없었던 경우
- 워크플로가 계속 실패해서 커밋 단계까지 못 갔던 경우

### 비활성화되면 이렇게 되살립니다

1. 저장소 → **Actions** 탭 → 노란 배너
   *"This scheduled workflow is disabled because there hasn't been activity in this repository for 60 days"*
2. 배너의 **`Enable workflow`** 버튼 클릭 → 즉시 재개됩니다.
3. 배너가 없다면 왼쪽 목록에서 `daily-cve-collect` 선택 → 오른쪽 **`Enable workflow`**

### 예방책

- 워크플로에 **`workflow_dispatch`(수동 실행) 트리거가 이미 포함**되어 있습니다.
  한 달에 한 번쯤 **Run workflow** 를 눌러 주기만 해도 활동으로 인정됩니다.
- 알림을 받으려면: 저장소 → **Watch → Custom → Actions** 체크
  (워크플로 실패 시 메일이 옵니다. 종료 코드 `1` 로 실패를 알리도록 만들어져 있습니다.)

---

## 5. 엑셀 출력 규격 (내부망 담당자 전달용)

> **이 장을 내부망 관리도구 담당자에게 그대로 전달하세요.**
> 이 규격은 고정이며, 변경하려면 양쪽(수집기·내부망 파서)을 동시에 고쳐야 합니다.

### 파일

| 항목 | 값 |
|---|---|
| 파일명 | **`CVE_YYYYMMDD.xls`** — 반드시 대문자 `CVE_` 로 시작 (내부망 도구가 접두사를 검증) |
| 포맷 | **BIFF8 `.xls`** (`xlwt` 생성) — **이것이 정본** |
| 부가 파일 | 같은 내용의 `.xlsx`(openpyxl), `.csv`(UTF-8 BOM). 반입용은 어디까지나 `.xls` |
| 시트1 | **`CVE_LIST`** — 1행 헤더, 2행부터 데이터 |
| 시트2 | **`META`** — `KEY` \| `VALUE` 2열 |

### 시트1 `CVE_LIST` — 헤더 16개 (순서·철자 고정)

| # | 헤더 | 값 규칙 |
|---|---|---|
| 1 | `CVE_ID` | `CVE-YYYY-NNNN` |
| 2 | `SW_NAME` | watchlist 의 `canonical_name` (= 내부망 `TB_SW.SW_NM`) |
| 3 | `VENDOR` | 제작사/조직 |
| 4 | `AFFECTED_RANGE` | 아래 버전범위 문법, **공백 없음** |
| 5 | `FIXED_VERSION` | 없으면 빈 문자열 |
| 6 | `SEVERITY` | `CRITICAL` / `HIGH` / `MEDIUM` / `LOW` / `NONE` |
| 7 | `CVSS_SCORE` | `0.0`~`10.0`, **문자열 셀** |
| 8 | `CVSS_VECTOR` | 예: `CVSS:3.1/AV:N/AC:L/...` |
| 9 | `PUBLISHED_DATE` | `YYYYMMDD` **문자열 셀** |
| 10 | `MODIFIED_DATE` | `YYYYMMDD` **문자열 셀** |
| 11 | `KEV_YN` | `Y` / `N` (CISA 실제 악용 확인 여부) |
| 12 | `SUMMARY` | 1000자 이내, 개행·탭은 공백으로 치환됨. **기본값은 한국어 번역문** ([11장](#11-summary-한국어-번역)) |
| 13 | `REFERENCE_URL` | 대표 URL 1개 |
| 14 | `SOURCE` | `NVD` / `OSV` / `GHSA` (병합 시 `NVD+OSV`) |
| 15 | `ECOSYSTEM` | `pypi` / `npm` / `github` / `other` |
| 16 | `COLLECTED_AT` | `YYYYMMDDHHmmss` **문자열 셀** |

### ★ 모든 셀은 문자열(text)입니다

숫자형으로 쓰면 버전 `1.10` → `1.1`, 날짜 → 시리얼값(`45123`)으로 깨져 POI 파싱에서 오류가 납니다.
그래서 **점수·날짜를 포함한 모든 셀을 문자열로 기록**합니다.
`None`/`NaN` 은 빈 문자열(`""`)입니다. 읽는 쪽에서도 문자열로 받아 주세요.

### 버전범위(`AFFECTED_RANGE`) 문법

```
 ,  = AND        |  = OR        연산자: >= > <= < ==        전체 영향 = *

 ">=1.0.0,<1.4.2"                 1.0.0 이상 1.4.2 미만
 ">=2.0.0,<2.3.1|>=3.0.0,<3.0.4"  두 구간 중 하나라도 해당되면 취약
 "==1.2.3"                        정확히 그 버전만
 "<2.6.0"                         2.6.0 미만 전부 (하한이 0이면 생략)
 "*"                              전 버전 영향 또는 범위 불명
```

- **문자열에 공백이 없습니다.** 길이가 500자를 넘으면 대표 범위만 남기고 자릅니다.
- 범위를 알아낼 수 없으면 `*` 로 쓰고, `SUMMARY` 앞에 **`[버전범위 불명확] `** 을 붙입니다.
  → 이 접두사가 보이면 담당자가 수동 확인이 필요하다는 뜻입니다.

### 정렬

`SEVERITY`(CRITICAL→NONE) → `CVSS_SCORE` 내림차순 → `SW_NAME` → `CVE_ID`

### 시트2 `META` 키 (수집 조건 추적용)

`RUN_ID`, `COLLECTED_AT`, `SCOPE_DESC`, `DATE_FROM`, `DATE_TO`, `MIN_SEVERITY`, `GROUPS`,
`SW_NAMES`, `ONLY_IN_USE`, `SOURCES`, `EXCEL_SCOPE`, `MAX_ROWS`, `TRUNCATED_CNT`,
`TOTAL_CNT`, `NEW_CNT`, `UPDATED_CNT`, `TOOL_VERSION`

- **`SCOPE_DESC`** 에 이 파일이 어떤 조건으로 뽑혔는지 한 줄로 들어 있습니다.
  예: `SCOPE lookback=3 sev>=MEDIUM groups=all sw=- in_use=False src=nvd,osv,ghsa,kev scope=delta max=300`
- **`TRUNCATED_CNT`** 가 0보다 크면 **최대 행수 제한으로 잘려 나간 건이 있다**는 뜻입니다.
  전체 목록은 GitHub Pages 열람 페이지에서 확인하세요.

### 행 수 제한

`xlwt`(BIFF8)는 시트당 65,536행이 한계라, 초과 시 `CVE_LIST`, `CVE_LIST_2`, `CVE_LIST_3` …
으로 나누고 `META` 에 `SHEET_COUNT`·`SHEET_NAMES` 를 적습니다.
(기본 `max_rows: 300` 이라 실제로는 거의 발생하지 않습니다.)

---

## 6. 무료 티어 한계와 Supabase 전환

### 현재 구성의 한계

| 항목 | 한계 | 실제 여유 |
|---|---|---|
| GitHub Actions | Public 무제한 / Private 월 2,000분 | 하루 5~10분 → **Public 이면 걱정 없음** |
| 저장소 용량 | 권장 1GB, 경고 5GB | CVE 1건 ≈ 1KB → 10만 건이어도 100MB 수준 |
| SQLite 파일 커밋 | 매일 바이너리 1개가 커밋되어 히스토리가 쌓임 | 하루 수십~수백KB. 수년은 버팁니다 |
| GitHub Pages | 저장소 1GB, 월 100GB 전송 | 정적 HTML 이라 여유 |
| NVD API | 키 없이 30초당 5요청 | 55종 × 1요청 ≈ 6분. 키 있으면 1분 |
| Gmail SMTP | 하루 500통 | 수신자 수 × 1통 |

### 언제 옮겨야 하나

- CVE 누적이 **10만 건**을 넘어 `data/cve.db` 가 수백 MB가 될 때
- 저장소 히스토리 용량이 부담될 때 (매일 커밋되는 바이너리라 히스토리가 누적됩니다)
- 여러 시스템에서 **동시에** DB를 읽고 써야 할 때

### Supabase(무료 Postgres) 전환 방법

`store.py` 는 **`Store` 추상 클래스 + `SqliteStore` 구현**으로 나뉘어 있어
**파일 1개만 추가**하면 교체됩니다.

1. https://supabase.com 가입 → 새 프로젝트 → **Settings → Database → Connection string** 복사
   (무료 티어: 500MB DB, 프로젝트 2개)
2. `requirements.txt` 에 `psycopg2-binary==2.9.9` 추가
3. `src/aicve/store_supabase.py` 를 만들고 `Store` 를 상속해 아래 메서드를 구현합니다.
   ```python
   from .store import Store

   class SupabaseStore(Store):
       def init_schema(self): ...        # store.py 의 SCHEMA 를 Postgres 문법으로
       def start_run(self, run_id, scope): ...
       def finish_run(self, run_id, **fields): ...
       def upsert_findings(self, findings, run_id): ...   # ON CONFLICT DO UPDATE
       def fetch_run_cves(self, run_id): ...
       def fetch_all_cves(self, limit=None): ...
       def fetch_runs(self, limit=30): ...
       def log_mail(self, run_id, recipient, subject, status, error_msg="", attach_file=""): ...
       def fetch_mail_logs(self, run_id=None): ...
       def close(self): ...
   ```
   SQL 문법 차이는 세 군데뿐입니다:
   `INTEGER PRIMARY KEY AUTOINCREMENT` → `SERIAL PRIMARY KEY`,
   `INSERT OR REPLACE` → `INSERT ... ON CONFLICT (cve_id, sw_name) DO UPDATE SET ...`,
   플레이스홀더 `?` → `%s`.
4. `main.py` 에서 생성 부분 **한 줄**만 바꿉니다.
   ```python
   # store = SqliteStore(args.db)
   store = SupabaseStore(os.environ["DATABASE_URL"])
   ```
5. `DATABASE_URL` 을 GitHub Secrets 에 등록하고, 워크플로의 커밋 단계에서 `data/` 를 제외합니다.

> `site.py` 는 통계용 메서드(`severity_counts`·`sw_counts`·`mail_stat_by_run`·`total_cve_count`)도
> 씁니다. 함께 옮기거나, 우선 `SqliteStore` 를 상속해 필요한 것만 덮어써도 됩니다.

---

## 7. 수집 범위(Scope) 조절하기

전량 수집은 NVD 레이트 리밋 때문에 느리고, 엑셀이 수백 행이 되면 내부망에서 검토가 버겁습니다.
그래서 **9개 축**으로 범위를 좁힐 수 있습니다.

| # | 축 | 키 / CLI | 기본값 | 설명 |
|---|---|---|---|---|
| 1 | 기간 | `lookback_days` / `--lookback` | `3` | 최근 N일 |
| 2 | 절대 구간 | `date_from`·`date_to` / `--from`·`--to` | 없음 | 지정 시 ①을 무시 |
| 3 | 심각도 하한 | `min_severity` / `--min-severity` | `MEDIUM` | `ALL` 이면 필터 안 함 |
| 4 | 대상 그룹 | `groups` / `--groups` | `all` | `framework,serving,ui` … |
| 5 | 대상 S/W | `sw_names` / `--sw-names` | 없음 | **지정 시 ④⑥을 무시** |
| 6 | 반입분 한정 | `only_in_use` / `--only-in-use` | `false` | `in_use: true` 만 |
| 7 | 소스 | `sources` / `--sources` | `nvd,osv,ghsa,kev` | 일부만 선택 가능 |
| 8 | 결과 범위 | `excel_scope` / `--excel-scope` | `delta` | `delta`=신규·변경만 / `all`=전량 |
| 9 | 최대 행수 | `max_rows` / `--max-rows` | `300` | 초과분은 심각도·점수 순으로 잘라냄 |

**우선순위: `settings.yml` 기본값 → `preset` → CLI/Actions 입력** (뒤가 앞을 덮어씀).
빈 값(`""`)은 앞 단계를 덮어쓰지 않습니다.

### 알아 두면 좋은 규칙

- **KEV(실제 악용 확인) 등재 건은 심각도 하한과 무관하게 항상 포함**됩니다.
- `sw_names` 를 주면 `groups`·`only_in_use` 는 무시합니다(가장 좁은 조건이 이깁니다).
- 대상이 0건이면 즉시 종료하고 `run_log.status='SKIPPED'` 와 사유를 남깁니다.
- 확정된 조건은 실행 로그 첫 줄, `run_log.scope_desc`, 엑셀 `META`, 메일 본문 상단에
  **똑같은 한 줄**로 실립니다.
  ```
  SCOPE lookback=3 sev>=HIGH groups=serving,ui sw=- in_use=False src=osv,kev scope=delta max=300
  ```

### 프리셋 (`settings.yml: presets`)

| 이름 | 조합 | 쓰임새 |
|---|---|---|
| `daily` | 3일 / MEDIUM 이상 / delta / 300행 | **기본 일일 수집** |
| `urgent` | 1일 / HIGH 이상 / delta / 50행 | 급할 때 빠르게 |
| `in_use` | 7일 / LOW 이상 / 반입분만 / 200행 | 내부망 반입 S/W 집중 점검 |
| `monthly` | 30일 / HIGH 이상 / 전량 / 1000행 | 월간 보고용 |
| `backfill` | 2026-01-01~ / HIGH 이상 / 전량 / 5000행 | **최초 1회** 과거 데이터 채우기 |

---

## 8. CLI 사용법

```bash
# 로컬 실행 준비
python -m venv .venv && .venv/Scripts/activate      # Linux/Mac: source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env                                 # 값을 채우고 환경변수로 export
```

```bash
# 조건만 확인 (API 호출 없음) — 실수 방지용으로 항상 먼저 돌려 보세요
python -m src.aicve.main --show-scope --preset urgent --groups serving,ui

# 기본 일일 수집
python -m src.aicve.main --preset daily

# 특정 S/W만, 메일 없이
python -m src.aicve.main --sw-names "PyTorch,vLLM" --skip-mail

# 메일 발송 없이 본문 미리보기만 저장 (output/mail_preview_*.html)
python -m src.aicve.main --preset daily --dry-run

# 과거 구간 백필 (전량 엑셀)
python -m src.aicve.main --from 2026-01-01 --to 2026-06-30 --excel-scope all --max-rows 5000

# 첫 실행 30일치
python -m src.aicve.main --backfill 30
```

### 전체 옵션

```
--preset {daily|urgent|in_use|monthly|backfill}
--lookback N          --backfill N        --from YYYY-MM-DD    --to YYYY-MM-DD
--min-severity {CRITICAL|HIGH|MEDIUM|LOW|ALL}
--groups framework,serving                --sw-names PyTorch,vLLM      --only-in-use
--sources nvd,osv,ghsa,kev                --excel-scope {delta|all}    --max-rows N
--skip-mail           --dry-run           --show-scope         --skip-site
--config / --watchlist / --db / --out-dir / --docs-dir / --templates / --mail-list
```

### 결과 확인 (DB 조회)

"메일이 실제로 나갔나", "지난주에 뭘 보냈나" 를 확인하는 도구입니다. **읽기 전용**이라 안전합니다.

```bash
python -m src.aicve.report                      # 최근 실행 + 메일 성공/실패 요약
python -m src.aicve.report --mails              # 메일 발송 로그 전체 (수신자·시각·상태)
python -m src.aicve.report --run 20260816211121 # 특정 회차 상세 (CVE 목록 + 발송 로그)
python -m src.aicve.report --cves               # 누적 CVE 목록
python -m src.aicve.report --stats              # 심각도·S/W별 통계
python -m src.aicve.report --sql "SELECT * FROM mail_log WHERE status='FAILED'"
```

최신 DB 를 보려면 실행 전에 `git pull` 로 저장소를 받아 두세요(워크플로가 매일 `data/cve.db` 를 커밋합니다).

> 같은 내용을 **[열람 페이지](#6-열람-페이지)** 에서도 볼 수 있습니다.
> 설치 없이 보려면 대시보드 실행 이력 표의 `메일(성공/실패)` 칸과 `보기` 링크를 쓰세요.
> GUI 로 DB 를 직접 열어 보고 싶으면 무료 프로그램
> [DB Browser for SQLite](https://sqlitebrowser.org/) 에서 `data/cve.db` 를 열면 됩니다.

### 소스별 단독 실행 (디버깅용)

```bash
python -m src.aicve.sources.kev
python -m src.aicve.sources.osv  --sw-names "vLLM" --lookback 90
python -m src.aicve.sources.nvd  --sw-names "PyTorch" --lookback 30
python -m src.aicve.sources.ghsa --groups ui --lookback 30      # GITHUB_TOKEN 필요
python -m src.aicve.site                                        # 수집 없이 docs/ 만 재생성
```

### 테스트

```bash
python -m pytest tests/ -q
```

`tests/test_version_range.py` 는 버전범위 변환을 **양방향**으로 검증합니다.
문자열 생성뿐 아니라 "이 범위에 1.4.1 은 포함되고 1.4.2 는 빠지는가"까지 확인해,
표기만 맞고 의미가 틀리는 사고를 막습니다.

### 종료 코드

| 코드 | 의미 |
|---|---|
| `0` | `SUCCESS` / `PARTIAL`(일부 소스 실패) / `SKIPPED`(대상 0건) |
| `1` | `FAILED` — Actions 가 실패 알림을 보냅니다 |

**어떤 단계가 실패해도 나머지는 진행합니다.** 소스 하나가 죽으면 나머지 소스로 계속하고,
메일이 실패해도 엑셀·DB·페이지는 정상 생성됩니다.

---

## 9. 저장소 구조

```
ai-cve-watch/
├── .github/workflows/daily.yml   매일 06:00 KST 자동 실행 + 수동 실행
├── config/
│   ├── watchlist.yml             ★ 감시 대상 55종 (핵심 설정)
│   └── settings.yml              기본값 + 프리셋 + 재시도 설정
├── mail_list.txt                 수신자 (1줄 1개, '#' 주석 허용)
├── src/aicve/
│   ├── main.py                   오케스트레이션 진입점 (CLI)
│   ├── scope.py                  ★ 수집 범위 확정 (settings → preset → CLI)
│   ├── sources/
│   │   ├── base.py               재시도·백오프가 붙은 HTTP 클라이언트
│   │   ├── nvd.py                NVD CVE API 2.0   (CVSS·요약이 정확)
│   │   ├── osv.py                OSV.dev           (★ 버전범위가 가장 정확)
│   │   ├── ghsa.py               GitHub Advisory GraphQL
│   │   └── kev.py                CISA 실제 악용 목록 → KEV_YN
│   ├── normalize.py              ★ 공통 스키마 + 버전범위 변환 + CVSS 계산
│   ├── excel.py                  ★ CVE_YYYYMMDD.xls / .xlsx / .csv
│   ├── mailer.py                 SMTP 개별 발송 + 결과 기록
│   ├── store.py                  Store 추상 + SqliteStore (Supabase 교체 지점)
│   ├── site.py                   Jinja2 → docs/ 정적 페이지
│   └── logutil.py                로깅 + 비밀정보 마스킹
├── templates/                    base / index / run / cve / mail (.html.j2)
├── data/cve.db                   SQLite (커밋 대상)
├── output/                       CVE_YYYYMMDD.xls (커밋 대상, 90일 보관)
├── docs/                         GitHub Pages 산출물 (커밋 대상)
└── tests/                        pytest
```

### 데이터 병합 규칙

동일 `(CVE_ID, SW_NAME)` 은 1행으로 합칩니다.

| 필드 | 우선순위 | 이유 |
|---|---|---|
| 버전범위 · 조치버전 | **OSV > GHSA > NVD** | OSV 가 패키지 버전 정보를 가장 정확히 관리 |
| CVSS · 요약 · 참고URL | **NVD > GHSA > OSV** | NVD 가 공식 점수·설명을 제공 |

`SEVERITY` 는 CVSS v3.1 점수 기준(`9.0↑ CRITICAL / 7.0↑ HIGH / 4.0↑ MEDIUM / 0.1↑ LOW`)이며,
점수가 없으면 벡터에서 직접 계산하고, 그것도 없으면 소스가 준 등급 문자열을 씁니다.

### 신규/변경 판정

`content_hash = sha256(affected_range|fixed_version|severity|cvss_score|summary)`
→ 기존 행과 다르면 **변경(updated)**, 행 자체가 없으면 **신규(new)**.
엑셀·메일에는 기본적으로 이번 실행의 **신규·변경 건만** 담깁니다(`excel_scope: delta`).

---

## 10. 문제 해결

| 증상 | 원인과 해결 |
|---|---|
| 메일이 안 옴 | ① 신규 0건이면 발송하지 않습니다(정상). `settings.yml: send_when_empty: true` 로 바꾸면 항상 발송 ② `SMTP_PASS` 에 앱 비밀번호 대신 계정 비밀번호를 넣지 않았는지 확인 ③ 실행 상세 페이지의 **메일 발송 로그** 에서 실패 사유 확인 |
| Pages 가 404 | Settings → Pages 의 폴더가 `/docs` 인지, `docs/index.html` 이 커밋됐는지 확인 |
| Pages 설정에서 `/docs` 를 못 고름 | Branch 가 `None` 뿐이면 저장소가 비어 있는 것입니다. 코드를 push 하고 워크플로를 1회 돌려 `docs/` 를 만든 뒤 다시 오세요 ([1장 ④⑤](#1-5분-셋업)) |
| NVD 수집이 매우 느림 | 정상입니다(키 없으면 요청 간 6.5초). `NVD_API_KEY` 를 등록하면 6배 빨라집니다 |
| GHSA 가 항상 0건 | `GITHUB_TOKEN` 이 없으면 이 소스만 건너뜁니다. 로컬 실행 시에는 PAT 를 직접 넣어야 합니다 |
| 워크플로가 안 돌아감 | [4장 60일 자동 비활성화](#4-60일-자동-비활성화-대응) 참고 |
| 엑셀 행이 잘림 | `META` 의 `TRUNCATED_CNT` 확인 → `--max-rows` 를 올리거나 조건을 좁히세요 |
| `SUMMARY` 앞에 `[버전범위 불명확]` | 어느 소스도 버전 범위를 주지 않아 `*` 로 기록된 건입니다. 수동 확인이 필요합니다 |
| 커밋 충돌로 푸시 실패 | 워크플로가 `pull --rebase` 로 3회 재시도합니다. 계속 실패하면 수동 실행으로 재시도하세요 |
| 로컬에서 한글이 깨짐 | Windows 콘솔이면 `set PYTHONIOENCODING=utf-8` 후 실행 |

### 로그 보는 법

- **Actions 로그**: 저장소 → Actions → 해당 실행 → `수집 실행` 스텝
- **파일 로그**: 실행 산출물(artifact) `cve-output-*` 안의 `logs/run_*.log` (30일 보관)
- 비밀번호·토큰·메일 주소는 기록 직전에 자동 마스킹되므로 로그가 공개돼도 안전합니다.

---

## 11. SUMMARY 한국어 번역

취약점 설명(`SUMMARY`)은 원래 영문입니다. **기본으로 한국어 번역이 켜져 있습니다.**

```yaml
# config/settings.yml
output:
  translate:
    enabled: true
    provider: google        # google(키 불필요) / papago / deepl / none
    mode: replace           # replace = 한국어만 / append = 한국어 + 영문 원문
```

### 어디에 어떻게 반영되나

| 위치 | 내용 |
|---|---|
| 엑셀 `SUMMARY` | **한국어** (헤더 16개 규격은 그대로 — 컬럼을 추가하지 않습니다) |
| 메일 본문 | 한국어 |
| 열람 페이지 | 한국어 + **`영문 원문` 을 펼쳐 보기** 가능 |
| DB `cve.summary_en` | 영문 원문 항상 보존 |

검색은 한국어·영문 어느 쪽으로도 됩니다.

### 번역 비용과 한도

**한 번 번역한 문장은 DB(`translation` 표)에 캐시되어 다시 번역하지 않습니다.**
매일 새로 잡히는 건수만 번역하므로(보통 수 건~수십 건) 무료 한도로 충분합니다.

| 제공자 | 키 | 한도 | 비고 |
|---|---|---|---|
| `google` (기본) | 불필요 | 명시 없음 | 무료 엔드포인트. 대량 요청 시 일시 차단될 수 있음 |
| `papago` | `NAVER_CLIENT_ID`/`NAVER_CLIENT_SECRET` | 1만자/일 | 네이버 개발자센터 무료 등록(카드 불필요) |
| `deepl` | `DEEPL_API_KEY` | 50만자/월 | 품질이 가장 좋음. 가입 시 카드 확인이 필요할 수 있음 |

제공자를 바꾸려면 `settings.yml` 의 `provider` 를 고치고, 해당 키를 GitHub Secrets 에 넣으면 됩니다.

### 안전장치

- **번역이 실패해도 실행은 계속됩니다.** 실패한 건은 영문 원문이 그대로 들어갑니다.
- **CVE 번호·URL 은 번역기에 넘기지 않습니다.** `CVE-2026-1234` 가 깨지지 않도록
  자리표시자로 빼놨다가 되돌립니다.
- `[버전범위 불명확] ` 접두사는 번역하지 않고 그대로 유지합니다.
- **번역을 켜고 꺼도 "변경" 알림이 쏟아지지 않습니다.** 변경 감지 해시는
  번역문이 아니라 **영문 원문**을 기준으로 계산하기 때문입니다.

### 끄고 싶으면

```yaml
output:
  translate:
    enabled: false     # 영문 원문 그대로
```

> 오역 가능성이 있으므로 **조치 판단은 `REFERENCE_URL` 의 원문을 확인**하고 하시길 권합니다.
> 번역문은 빠르게 훑어보는 용도입니다.

---

## 라이선스 / 데이터 출처

- [NVD](https://nvd.nist.gov/) (미국 NIST, 공개 도메인)
- [OSV.dev](https://osv.dev/) (Google, CC-BY 4.0)
- [GitHub Advisory Database](https://github.com/advisories) (CC-BY 4.0)
- [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) (공개 도메인)

각 소스의 이용약관을 준수해 주세요. 상업적 재배포 시에는 출처 표기가 필요합니다.
