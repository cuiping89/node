#!/usr/bin/env bash
#==============================================================================
# tools/publish-check.sh — 推送后、安装前的"发布自检"
#
# 解决你反复踩的两类部署事故,在你跑 install 之前就给出 GO / NO-GO:
#
#   A) 漏推 / 混源(本轮事故）
#      bootstrap.sh 清单声明的哈希,与仓库里实际文件对不上。
#      例:更新了 bootstrap.sh 却没推对应的 subscription.sh。
#      → 等待无效,必须重新推送。本工具用 codeload 打包取"仓库真实内容"判定,
#        不受 raw 缓存与 API 限速影响。
#
#   B) raw CDN 缓存延迟（上一轮事故）
#      仓库已正确,但 raw.githubusercontent.com 还在提供旧文件缓存。
#      → 等几分钟即可;或用新版 bootstrap 的 commit-SHA 锁定直接装。
#
# 自包含,无需参数。用法（任选其一）:
#   bash tools/publish-check.sh                                  # 本地仓库里直接跑
#   curl -fsSL https://raw.githubusercontent.com/cuiping89/node/main/tools/publish-check.sh | bash
#
# 退出码: 0 = 仓库一致(可安装)  1 = 仓库不一致(漏推,需重推)
#==============================================================================

set -u

REPO="${EDGEBOX_REPO:-cuiping89/node}"
BRANCH="${EDGEBOX_BRANCH:-main}"
SUBDIR="ENV"

_c() { if [[ -t 1 ]]; then printf '\033[%sm%s\033[0m\n' "$1" "$2"; else printf '%s\n' "$2"; fi; }
red(){ _c '0;31' "$*"; }
grn(){ _c '0;32' "$*"; }
ylw(){ _c '0;33' "$*"; }
cyn(){ _c '0;36' "$*"; }

for t in curl tar sha256sum mktemp awk; do
    command -v "$t" >/dev/null 2>&1 || { red "缺少必要工具: $t"; exit 1; }
done

TMP="$(mktemp -d -t eb-publish-check.XXXXXX)"
trap 'rm -rf "$TMP" 2>/dev/null || true' EXIT

cyn "============================================================"
cyn " EdgeBox 发布自检   repo=${REPO}  branch=${BRANCH}"
cyn "============================================================"

# ---- 1) 取仓库真实内容(codeload 打包,绕过 raw 缓存 + API 限速) ----
echo "[1/3] 下载仓库快照 (codeload tar.gz) ..."
if ! curl -fsSL --connect-timeout 15 --max-time 120 \
        "https://codeload.github.com/${REPO}/tar.gz/refs/heads/${BRANCH}" \
        -o "$TMP/repo.tar.gz"; then
    red "下载仓库打包失败,检查网络或分支名 '${BRANCH}'。"
    exit 1
fi
tar xzf "$TMP/repo.tar.gz" -C "$TMP" 2>/dev/null || { red "解包失败。"; exit 1; }
ROOT="$(find "$TMP" -maxdepth 1 -type d -name 'node-*' | head -1)"
ENVDIR="$ROOT/$SUBDIR"
BS="$ENVDIR/bootstrap.sh"
[[ -f "$BS" ]] || { red "仓库快照里找不到 ${SUBDIR}/bootstrap.sh。"; exit 1; }

# ---- 2) 解析 bootstrap.sh 的 EDGEBOX_FILES 清单 ----
echo "[2/3] 解析 bootstrap.sh 清单 ..."
mapfile -t ENTRIES < <(awk '/EDGEBOX_FILES=\(/{f=1;next} /^\)/{f=0} f' "$BS" \
                       | grep -oE '"[^"]+\|[^"]+\|[a-f0-9]{64}"' | tr -d '"')
if (( ${#ENTRIES[@]} == 0 )); then
    red "未能从 bootstrap.sh 解析出清单条目(格式可能变了)。"
    exit 1
fi
echo "       清单含 ${#ENTRIES[@]} 个文件。"

# ---- 3) 双重核对 ----
echo "[3/3] 核对「仓库一致性」+「raw CDN 传播」..."
echo ""
RAW_BASE="https://raw.githubusercontent.com/${REPO}/${BRANCH}/${SUBDIR}"
bad_push=0; cdn_lag=0

printf '  %-44s %-12s %-12s\n' "文件" "仓库一致" "CDN已传播"
printf '  %-44s %-12s %-12s\n' "--------------------------------------------" "--------" "---------"
for e in "${ENTRIES[@]}"; do
    remote="${e%%|*}"; rest="${e#*|}"; sha="${rest#*|}"
    repo_file="$ENVDIR/$remote"
    a_state="?"; b_state="?"; actual=""

    # A) 仓库实际文件 vs 清单声明
    if [[ -f "$repo_file" ]]; then
        actual="$(sha256sum "$repo_file" | awk '{print $1}')"
        if [[ "$actual" == "$sha" ]]; then a_state="OK"; else a_state="✗不一致"; bad_push=1; fi
    else
        a_state="✗缺文件"; bad_push=1
    fi

    # B) raw /branch/ 当前内容 vs 清单声明(传播到位 = raw 已等于清单)
    raw_hash="$(curl -fsSL --connect-timeout 10 --max-time 60 "$RAW_BASE/$remote" 2>/dev/null | sha256sum | awk '{print $1}')"
    if [[ "$raw_hash" == "$sha" ]]; then b_state="OK"; else b_state="✗滞后"; cdn_lag=1; fi

    printf '  %-44s %-12s %-12s\n' "$remote" "$a_state" "$b_state"
done
echo ""

# ---- 结论 ----
if (( bad_push )); then
    red "============================================================"
    red " ✗ 不可安装:仓库内部不一致（漏推 / 混源）"
    red "============================================================"
    red "  bootstrap 清单声明的哈希,与仓库里实际文件对不上。"
    red "  典型原因:只推了部分文件(如改了 bootstrap.sh 却没推对应的某个 .sh）。"
    red "  处理:把整个 ENV/ 的最新版**整套覆盖后再 push**(别只挑单个文件),"
    red "        然后重新运行本自检。**等待无效——这不是缓存。**"
    exit 1
fi

if (( cdn_lag )); then
    ylw "============================================================"
    ylw " ⏳ 仓库已一致,但 raw CDN 仍在传播(标 ✗滞后 的文件）"
    ylw "============================================================"
    ylw "  · 用新版 bootstrap(已带 commit-SHA 锁定）可**直接安装,无视此延迟**。"
    ylw "  · 若用旧 bootstrap 或 API 被限速回退到 /main/,请等 1-5 分钟后重跑本自检。"
    grn ""
    grn "  仓库内容正确,可以推进安装。"
    exit 0
fi

grn "============================================================"
grn " ✓ 可以安装:仓库一致,且 raw CDN 已全部传播"
grn "============================================================"
exit 0
