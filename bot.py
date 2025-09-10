import os, re, pathlib, asyncio, time, random, string, mimetypes
from typing import List, Optional, Tuple
from dataclasses import dataclass
from urllib.parse import urlparse, urljoin

import httpx, aiofiles, boto3
import discord
from discord.ext import commands
import yt_dlp

# ========== ENV ==========
DISCORD_TOKEN = os.getenv("DISCORD_TOKEN", "")
MAX_DISCORD_BYTES = int(os.getenv("UPLOAD_LIMIT_BYTES", str(24 * 1024 * 1024)))

# ขนาดสูงสุดที่ยอมดาวน์โหลดล่วงหน้าถ้าไม่ได้ตั้ง S3 (กันดิสก์แตก) สำหรับโหมด direct (ไม่ใช่ yt-dlp)
MAX_FETCH_MB = int(os.getenv("MAX_FETCH_MB", "350"))
MAX_FETCH_BYTES = MAX_FETCH_MB * 1024 * 1024

# S3 (อัปไฟล์ใหญ่เกินลิมิตแนบไฟล์)
S3_BUCKET = os.getenv("S3_BUCKET", "")
S3_REGION = os.getenv("S3_REGION", "")
AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID", "")
AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY", "")
S3_PUBLIC_BASE = (os.getenv("S3_PUBLIC_BASE", "") or "").rstrip("/")

# yt-dlp settings (เปิดเฉพาะโดเมนที่อนุญาต)
YTDLP_ENABLED = os.getenv("ENABLE_YTDLP", "0") == "1"
YTDLP_DOMAINS = set(
    d.strip().lower() for d in (os.getenv("YTDLP_DOMAINS") or "").split(",") if d.strip()
)
YTDLP_MAX_BYTES = int(os.getenv("YTDLP_MAX_BYTES", str(MAX_FETCH_BYTES)))  # default = direct limit
YTDLP_COOKIES_FROM_BROWSER = os.getenv("YTDLP_COOKIES_FROM_BROWSER")  # e.g. "chrome"

# ใช้ allowlist ห้อง/เธรด (ไฟล์แยก)
try:
    from channel_allowlist import ALLOWED_CHANNEL_IDS  # set[int]
except Exception:
    ALLOWED_CHANNEL_IDS: set[int] = set()

# ========== Discord ==========
INTENTS = discord.Intents.default()
INTENTS.message_content = True
COMMAND_PREFIXES = tuple((os.getenv("COMMAND_PREFIXES") or "!").split(","))  # กันยิงซ้ำกับ on_message
bot = commands.Bot(command_prefix=COMMAND_PREFIXES[0], intents=INTENTS)

DOWNLOAD_DIR = pathlib.Path("downloads")
DOWNLOAD_DIR.mkdir(parents=True, exist_ok=True)

VIDEO_EXTS = {".mp4", ".mov", ".webm", ".mkv", ".m4v", ".ts"}

DEFAULT_HEADERS = {
    "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36",
    "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "accept-language": "en-US,en;q=0.8,th;q=0.7",
}

# ---------- Blocked domains (TOS/DRM risk) ----------
# หมายเหตุ: อย่าใส่ YouTube ที่นี่ถ้าคุณจะใช้ yt-dlp ดาวน์โหลด YouTube
BLOCKED_DOMAINS = {
    # ตัวอย่าง OTT/DRM/สมาชิก (ปรับตามนโยบายคุณ)
    "netflix.com", "disneyplus.com", "primevideo.com", "hulu.com",
    "max.com", "paramountplus.com", "peacocktv.com", "tv.apple.com",
    "crunchyroll.com",
    "onlyfans.com", "fansly.com",
    "patreon.com",
}

def hostof(url: str) -> str:
    return urlparse(url).netloc.split(":")[0].lower()

def is_blocked_host(host: str) -> bool:
    host = (host or "").lower()
    return any(host == d or host.endswith("." + d) for d in BLOCKED_DOMAINS)

def is_ytdlp_allowed_for(url: str) -> bool:
    if not YTDLP_ENABLED or not YTDLP_DOMAINS:
        return False
    h = hostof(url)
    return any(h == d or h.endswith("." + d) for d in YTDLP_DOMAINS)

URL_RE = re.compile(r"https?://\S+")

class NotAllowed(Exception): ...
class FetchError(Exception): ...

# ---------- Audio formats ----------
SUPPORTED_AUDIO_EXTS = ["mp3", "m4a", "aac", "opus", "ogg", "wav", "flac"]

def audio_ffmpeg_args(ext: str) -> List[str]:
    ext = ext.lower()
    if ext == "mp3":
        return ["-c:a","libmp3lame","-b:a","192k"]
    if ext == "m4a":
        return ["-c:a","aac","-b:a","192k","-movflags","+faststart"]
    if ext == "aac":
        return ["-c:a","aac","-b:a","192k","-f","adts"]
    if ext == "opus":
        return ["-c:a","libopus","-b:a","128k"]
    if ext == "ogg":
        return ["-c:a","libvorbis","-q:a","5"]
    if ext == "wav":
        return ["-c:a","pcm_s16le"]
    if ext == "flac":
        return ["-c:a","flac"]
    raise ValueError(f"unsupported audio ext: {ext}")

async def extract_audio_generic(input_path_or_url: str, out_path: pathlib.Path, ext: str, referer: Optional[str] = None):
    args = audio_ffmpeg_args(ext)
    cmd = ["ffmpeg","-y"]
    # ถ้าเป็น URL ให้ใส่ UA/Referer ให้ ffmpeg ด้วย
    if "://" in input_path_or_url:
        cmd += ["-user_agent", DEFAULT_HEADERS["user-agent"]]
        if referer:
            cmd += ["-referer", referer]
    cmd += ["-i", input_path_or_url, "-vn", *args, str(out_path)]
    proc = await asyncio.create_subprocess_exec(
        *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )
    _, err = await proc.communicate()
    if proc.returncode != 0:
        raise FetchError(f"ffmpeg (audio:{ext}) failed: {err.decode(errors='ignore')[:300]}")

# ---------- Permissions ----------
def require_allowed_channel():
    async def predicate(ctx: commands.Context):
        cid = getattr(ctx.channel, "id", None)
        if not ALLOWED_CHANNEL_IDS or cid in ALLOWED_CHANNEL_IDS:
            return True
        try:
            await ctx.reply("🚫 ห้องนี้ไม่ได้รับอนุญาตให้ใช้คำสั่งนี้", mention_author=False)
        except Exception:
            pass
        return False
    return commands.check(predicate)

# ---------- Helpers ----------
def sanitize_filename(name: str) -> str:
    name = re.sub(r"[^\w\-. ]+", "_", name)
    return (name[:200] or "media").strip()

def s3_enabled() -> bool:
    return all([S3_BUCKET, S3_REGION, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, S3_PUBLIC_BASE])

def s3_upload(local_path: pathlib.Path) -> str:
    key = f"publicfetch/{int(time.time())}_{''.join(random.choices(string.ascii_lowercase+string.digits,k=10))}_{sanitize_filename(local_path.name)}"
    session = boto3.session.Session(
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
        region_name=S3_REGION,
    )
    s3 = session.client("s3")
    ct = mimetypes.guess_type(local_path.name)[0] or "application/octet-stream"
    s3.upload_file(str(local_path), S3_BUCKET, key, ExtraArgs={"ACL": "public-read", "ContentType": ct})
    return f"{S3_PUBLIC_BASE}/{key}"

async def http_head_ok(url: str, referer: Optional[str] = None) -> Tuple[str, int]:
    headers = DEFAULT_HEADERS.copy()
    if referer:
        headers["referer"] = referer
    async with httpx.AsyncClient(follow_redirects=True, timeout=30, headers=headers) as client:
        r = await client.head(url)
        if r.status_code in (405, 403):
            r = await client.get(url, stream=True)
            await r.aclose()
        r.raise_for_status()
        ct = r.headers.get("content-type","").lower()
        cl = int(r.headers.get("content-length") or 0)
        return ct, cl

def is_hls_content_type(ct: str) -> bool:
    ct = (ct or "").lower()
    return ("application/x-mpegurl" in ct) or ("application/vnd.apple.mpegurl" in ct) or (ct == "audio/mpegurl")

def is_dash_content_type(ct: str) -> bool:
    ct = (ct or "").lower()
    return ("application/dash+xml" in ct) or ("video/vnd.mpeg.dash.mpd" in ct)

async def is_direct_video(url: str) -> bool:
    try:
        # ส่ง referer เป็นตัวเอง ช่วยผ่าน 403/anti-hotlink
        ct, _ = await http_head_ok(url, referer=url)
        if ct.startswith("video/"):
            return True
        suffix = pathlib.Path(urlparse(url).path).suffix.lower()
        return suffix in VIDEO_EXTS
    except Exception:
        return False

async def fetch_text(url: str, referer: Optional[str] = None) -> str:
    headers = DEFAULT_HEADERS.copy()
    if referer:
        headers["referer"] = referer
    async with httpx.AsyncClient(follow_redirects=True, timeout=40, headers=headers) as client:
        r = await client.get(url)
        r.raise_for_status()
        return r.text

async def stream_download(url: str, dest: pathlib.Path, chunk=1<<16, referer: Optional[str] = None):
    headers = DEFAULT_HEADERS.copy()
    if referer:
        headers["referer"] = referer
    async with httpx.AsyncClient(follow_redirects=True, timeout=None, headers=headers) as client:
        async with client.get(url) as r:
            r.raise_for_status()
            async with aiofiles.open(dest, "wb") as f:
                async for b in r.aiter_bytes(chunk_size=chunk):
                    await f.write(b)
    return dest

# ---------- HLS ----------
def hls_is_encrypted(m3u8_text: str) -> bool:
    for line in m3u8_text.splitlines():
        if line.startswith("#EXT-X-KEY"):
            m = re.search(r"METHOD=([^,]+)", line)
            method = (m.group(1) if m else "").upper()
            if method and method != "NONE":
                return True
    return False

@dataclass
class HlsVariant:
    url: str
    resolution: Optional[str]  # e.g. "1920x1080"
    bandwidth: Optional[int]   # bps

def parse_hls_master(text: str, base_url: str) -> List[HlsVariant]:
    variants: List[HlsVariant] = []
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    for i, line in enumerate(lines):
        if line.startswith("#EXT-X-STREAM-INF"):
            res = None; bw = None
            m = re.search(r"RESOLUTION=(\d+x\d+)", line, flags=re.I)
            if m: res = m.group(1)
            m2 = re.search(r"BANDWIDTH=(\d+)", line, flags=re.I)
            if m2:
                try: bw = int(m2.group(1))
                except: bw = None
            # next non-comment line is playlist URL
            j = i + 1
            while j < len(lines) and lines[j].startswith("#"):
                j += 1
            if j < len(lines):
                u = lines[j]
                if not urlparse(u).scheme:
                    u = urljoin(base_url, u)
                variants.append(HlsVariant(url=u, resolution=res, bandwidth=bw))
    return variants

async def download_hls_to_mp4(m3u8_url: str, out_path: pathlib.Path):
    text = await fetch_text(m3u8_url)
    if hls_is_encrypted(text):
        raise NotAllowed("พบการเข้ารหัสใน .m3u8 (DRM/KEY) — ไม่รองรับ")

    base_cmd = [
        "ffmpeg","-y",
        "-user_agent", DEFAULT_HEADERS["user-agent"],
        "-referer", m3u8_url,
        "-protocol_whitelist","file,http,https,tcp,tls,crypto",
        "-i", m3u8_url,
        "-c","copy",
        "-movflags","+faststart",
    ]
    # รอบแรก: กรณีสตรีม AAC ใน HLS
    cmd1 = [*base_cmd, "-bsf:a","aac_adtstoasc", str(out_path)]
    p1 = await asyncio.create_subprocess_exec(*cmd1, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    _, e1 = await p1.communicate()
    if p1.returncode == 0:
        return

    # Fallback: ถ้าไม่ได้เป็น AAC
    cmd2 = [*base_cmd, str(out_path)]
    p2 = await asyncio.create_subprocess_exec(*cmd2, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    _, e2 = await p2.communicate()
    if p2.returncode != 0:
        msg = (e2 or e1).decode(errors="ignore")[:300]
        raise FetchError(f"ffmpeg failed: {msg}")

# ---------- HTML candidates ----------
# ดึงลิงก์จาก JSON/สคริปต์ยอดฮิต + fallback ครอบคลุม schemeless/relative
JSON_URL_RE = re.compile(
    r'(?:"|\')?(?:file|src|url)(?:"|\')?\s*:\s*["\']((?:https?:)?//[^\s"\']+?\.(?:m3u8|mp4|webm|mov)(?:\?[^\s"\']*)?|/[^\s"\']+?\.(?:m3u8|mp4|webm|mov)(?:\?[^\s"\']*)?)["\']',
    re.I
)
JSON_SOURCES_RE = re.compile(
    r'sources?\s*:\s*\[\s*{[^{}]*?src\s*:\s*["\']((?:https?:)?//[^\s"\']+?\.(?:m3u8|mp4|webm|mov)(?:\?[^\s"\']*)?|/[^\s"\']+?\.(?:m3u8|mp4|webm|mov)(?:\?[^\s"\']*)?)["\']',
    re.I | re.S
)
FALLBACK_MEDIA_URL_RE = re.compile(
    r'((?:https?:)?//[^\s"\'<>]+?\.(?:m3u8|mp4|webm|mov)(?:\?[^\s"\'<>]*)?|/[^\s"\'<>]+?\.(?:m3u8|mp4|webm|mov)(?:\?[^\s"\'<>]*)?)',
    re.I
)
ANY_URL_RE = re.compile(r'https?://[^\s"\'<>]+', re.I)

def looks_like_media_url(u: str) -> bool:
    lu = u.lower()
    return (
        any(x in lu for x in (".m3u8", ".mp4", ".webm", ".mov")) or
        any(x in lu for x in ("/hls", "/dash", "manifest", "playlist"))
    )

def _normalize_url(u: str, base_url: str) -> str:
    u = (u or "").strip()
    if u.startswith("//"):
        u = ("https:" if base_url.lower().startswith("https") else "http:") + u
    if not urlparse(u).scheme:
        u = urljoin(base_url, u)
    return u

VIDEO_CANDIDATE_PATTERNS = [
    r'<meta[^>]+property=["\']og:video["\'][^>]+content=["\']([^"\']+)["\']',
    r'<meta[^>]+property=["\']og:video:url["\'][^>]+content=["\']([^"\']+)["\']',
    r'<meta[^>]+property=["\']og:video:secure_url["\'][^>]+content=["\']([^"\']+)["\']',
    r'<meta[^>]+name=["\']twitter:player:stream["\'][^>]+content=["\']([^"\']+)["\']',
    r'<video[^>]+src=["\']([^"\']+)["\']',
    r'<source[^>]+src=["\']([^"\']+)["\'][^>]*?(?:type=["\']video/[^"\']+["\'])?',
    r'<link[^>]+rel=["\']preload["\'][^>]+as=["\']video["\'][^>]+href=["\']([^"\']+)["\']',
]
def find_video_candidates(html: str, base_url: str) -> List[str]:
    html = html or ""
    urls: List[str] = []

    # เดิม: meta/video/source/link
    for pat in VIDEO_CANDIDATE_PATTERNS:
        for m in re.finditer(pat, html, flags=re.I):
            u = (m.group(1) or "").strip()
            if u:
                urls.append(_normalize_url(u, base_url))

    # JSON/สคริปต์ยอดฮิต
    for rx in (JSON_URL_RE, JSON_SOURCES_RE):
        for m in rx.finditer(html):
            u = (m.group(1) or "").strip()
            if u:
                urls.append(_normalize_url(u, base_url))

    # Fallback: ยิงกว้างทั้งเอกสาร
    for m in FALLBACK_MEDIA_URL_RE.finditer(html):
        u = (m.group(1) or "").strip()
        if u:
            urls.append(_normalize_url(u, base_url))

    # unique (preserve order)
    seen = set(); out = []
    for u in urls:
        if u not in seen:
            seen.add(u); out.append(u)
    return out

# ---------- URL utils ----------
def extract_first_url(text: str) -> Optional[str]:
    m = URL_RE.search(text or "")
    if not m:
        return None
    url = m.group(0)
    # ตัดตัวปิดบางอย่างที่ดีสคอร์ดอาจผนวกมา
    return url.rstrip(">)].,!?\"'")

# ---------- Resolver ----------
async def resolve_public_video(url: str):
    host = hostof(url)
    if is_blocked_host(host):
        raise NotAllowed("โดเมนนี้ไม่รองรับ (เสี่ยง TOS/DRM)")

    # 0) HEAD เช็คชนิดไฟล์ก่อน (ใส่ referer=url)
    try:
        ct, _ = await http_head_ok(url, referer=url)
        if ct.startswith("video/"):
            return {"mode": "direct", "url": url, "variants": None}
        if is_hls_content_type(ct):
            text = await fetch_text(url, referer=url)
            if hls_is_encrypted(text):
                raise NotAllowed("พบการเข้ารหัสใน .m3u8 — ไม่รองรับ")
            variants = parse_hls_master(text, base_url=url)
            return {"mode": "m3u8", "url": url, "variants": variants or None}
        if is_dash_content_type(ct) or ("manifest" in url.lower() or "/dash" in url.lower()):
            raise NotAllowed("พบ DASH/MPD (ไม่รองรับ) — รองรับเฉพาะไฟล์ตรง (.mp4) หรือ HLS (.m3u8)")
    except Exception:
        pass

    # 1) นามสกุลไฟล์ตรง?
    if await is_direct_video(url):
        return {"mode": "direct", "url": url, "variants": None}

    # 2) HLS จากนามสกุล .m3u8
    path = urlparse(url).path.lower()
    if path.endswith(".m3u8"):
        text = await fetch_text(url, referer=url)
        if hls_is_encrypted(text):
            raise NotAllowed("พบการเข้ารหัสใน .m3u8 — ไม่รองรับ")
        variants = parse_hls_master(text, base_url=url)
        return {"mode": "m3u8", "url": url, "variants": variants or None}

    # 3) HTML → หาคลู่วิดีโอ
    try:
        html = await fetch_text(url, referer=url)
        cands = find_video_candidates(html, base_url=url)
        for cu in cands:
            h2 = hostof(cu)
            if is_blocked_host(h2):
                continue  # ข้ามไปลองตัวอื่น
            try:
                cct, _ = await http_head_ok(cu, referer=url)
                if cct.startswith("video/"):
                    return {"mode": "direct", "url": cu, "variants": None}
                if is_hls_content_type(cct) or cu.lower().endswith(".m3u8"):
                    text2 = await fetch_text(cu, referer=url)
                    if hls_is_encrypted(text2):
                        continue
                    variants = parse_hls_master(text2, base_url=cu)
                    return {"mode": "m3u8", "url": cu, "variants": variants or None}
                if is_dash_content_type(cct) or ("manifest" in cu.lower() or "/dash" in cu.lower()):
                    # แจ้งชัดว่าไม่รองรับ DASH
                    raise NotAllowed("พบ DASH/MPD (ไม่รองรับ) — รองรับเฉพาะไฟล์ตรง (.mp4) หรือ HLS (.m3u8)")
            except NotAllowed:
                raise
            except Exception:
                pass
    except Exception:
        pass

    # 4) Aggressive fallback: เก็บ URL ทั้งหน้าแล้ว HEAD คัดเอง
    try:
        if 'html' not in locals():
            html = await fetch_text(url, referer=url)
        urls_guess = [m.group(0) for m in ANY_URL_RE.finditer(html)]
        urls_guess = [_normalize_url(u, url) for u in urls_guess if looks_like_media_url(u)]

        # จำกัดจำนวนตรวจเพื่อความเร็ว
        seen = set(); pruned = []
        for u in urls_guess:
            if u not in seen:
                seen.add(u); pruned.append(u)
            if len(pruned) >= 60:
                break

        for cu in pruned:
            h2 = hostof(cu)
            if is_blocked_host(h2):
                continue
            try:
                cct, _ = await http_head_ok(cu, referer=url)
                if cct.startswith("video/"):
                    return {"mode": "direct", "url": cu, "variants": None}
                if is_hls_content_type(cct) or cu.lower().endswith(".m3u8"):
                    text2 = await fetch_text(cu, referer=url)
                    if hls_is_encrypted(text2):
                        continue
                    variants = parse_hls_master(text2, base_url=cu)
                    return {"mode": "m3u8", "url": cu, "variants": variants or None}
                if is_dash_content_type(cct) or ("manifest" in cu.lower() or "/dash" in cu.lower()):
                    raise NotAllowed("พบ DASH/MPD (ไม่รองรับ) — รองรับเฉพาะไฟล์ตรง (.mp4) หรือ HLS (.m3u8)")
            except NotAllowed:
                raise
            except Exception:
                pass
    except Exception:
        pass

    raise NotAllowed("ไม่พบไฟล์วิดีโอที่ดึงตรงได้จากหน้านี้")

# ---------- Discord UI ----------
class FormatChoice(discord.ui.View):
    def __init__(self, requester_id: int, timeout: int = 120):
        super().__init__(timeout=timeout)
        self.requester_id = requester_id
        self.choice: Optional[str] = None  # "mp4" | "mp3"

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        if interaction.user.id != self.requester_id:
            await interaction.response.send_message("คำสั่งนี้สำหรับคนที่เรียกเท่านั้น", ephemeral=False)
            return False
        return True

    @discord.ui.button(label="MP4 (วิดีโอ)", style=discord.ButtonStyle.primary)
    async def mp4(self, button: discord.ui.Button, interaction: discord.Interaction):
        self.choice = "mp4"
        await interaction.response.defer()
        self.stop()

    @discord.ui.button(label="MP3 (เสียงล้วน)", style=discord.ButtonStyle.secondary)
    async def mp3(self, button: discord.ui.Button, interaction: discord.Interaction):
        self.choice = "mp3"
        await interaction.response.defer()
        self.stop()

class VariantSelect(discord.ui.View):
    def __init__(self, requester_id: int, variants: List['HlsVariant'], timeout: int = 120):
        super().__init__(timeout=timeout)
        self.requester_id = requester_id
        self.variants = variants
        self.selected_variant: Optional['HlsVariant'] = None

        opts = []
        for i, v in enumerate(variants):
            res = v.resolution or "unknown"
            kbps = f"{(v.bandwidth or 0)//1000} kbps" if v.bandwidth else ""
            label = f"{res} {kbps}".strip()
            if len(label) > 100: label = label[:97] + "..."
            opts.append(discord.SelectOption(label=label, value=str(i), description=v.url[:100]))

        select = discord.ui.Select(placeholder="เลือกความละเอียด/บิตเรต", options=opts, min_values=1, max_values=1)
        async def _on_select(interaction: discord.Interaction):
            if interaction.user.id != self.requester_id:
                await interaction.response.send_message("คำสั่งนี้สำหรับคนที่เรียกเท่านั้น", ephemeral=False)
                return
            idx = int(select.values[0])
            self.selected_variant = self.variants[idx]
            await interaction.response.defer()
            self.stop()
        select.callback = _on_select  # type: ignore
        self.add_item(select)

class AudioExtSelect(discord.ui.View):
    def __init__(self, requester_id: int, timeout: int = 120):
        super().__init__(timeout=timeout)
        self.requester_id = requester_id
        self.chosen_ext: Optional[str] = None
        options = [discord.SelectOption(label=ext.upper(), value=ext) for ext in SUPPORTED_AUDIO_EXTS]
        self.select = discord.ui.Select(placeholder="เลือกนามสกุลไฟล์เสียง", options=options, min_values=1, max_values=1)
        self.select.callback = self._on_select  # type: ignore
        self.add_item(self.select)

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        if interaction.user.id != self.requester_id:
            await interaction.response.send_message("คำสั่งนี้สำหรับผู้ที่อัปไฟล์เท่านั้น", ephemeral=False)
            return False
        return True

    async def _on_select(self, interaction: discord.Interaction):
        self.chosen_ext = self.select.values[0]
        await interaction.response.defer()
        self.stop()

# ---------- yt-dlp helper ----------
async def download_with_ytdlp(url: str, audio_only: bool, progress_msg: Optional[discord.Message]) -> pathlib.Path:
    """
    ดาวน์โหลดด้วย yt-dlp
    - audio_only=True จะออกเป็น .mp3 (192 kbps)
    - otherwise จะได้ไฟล์ .mp4 (merge video+audio)
    - คืนค่าเป็น path ของไฟล์ผลลัพธ์
    """
    latest_file_path: Optional[pathlib.Path] = None
    last_edit = 0.0
    loop = asyncio.get_running_loop()

    async def update_progress(d: dict):
        nonlocal latest_file_path, last_edit
        if not progress_msg:
            return
        now = time.time()
        if now - last_edit < 0.7:
            return
        last_edit = now

        status = d.get("status")
        if status == "downloading":
            p = (d.get("_percent_str") or "").strip()
            s = (d.get("_speed_str") or "").strip()
            e = d.get("eta")
            eta = f" ETA {int(e)}s" if isinstance(e, (int,float)) and e > 0 else ""
            txt = f"⬇️ ดาวน์โหลดด้วย yt-dlp… {p} {s}{eta}"
            try: await progress_msg.edit(content=txt)
            except Exception: pass
        elif status == "finished":
            try: await progress_msg.edit(content="🔄 กำลังรวม/แปลงไฟล์ (ffmpeg)…")
            except Exception: pass

        fn = d.get("filename")
        if fn and not str(fn).endswith(".part"):
            latest_file_path = pathlib.Path(fn)

    def hook(d):
        # เรียกจาก thread อื่น → สะพานเข้า event loop ปัจจุบัน
        loop.call_soon_threadsafe(asyncio.create_task, update_progress(d))

    outtmpl = str(DOWNLOAD_DIR / "%(title).200B [%(id)s].%(ext)s")

    ydl_opts = {
        "quiet": True, "no_warnings": True,
        "outtmpl": outtmpl,
        "noprogress": True,
        "progress_hooks": [hook],
        "max_filesize": YTDLP_MAX_BYTES,
        "merge_output_format": "mp4",
        "http_headers": {
            "User-Agent": DEFAULT_HEADERS["user-agent"],
            "Accept-Language": DEFAULT_HEADERS["accept-language"],
        },
    }

    if audio_only:
        ydl_opts.update({
            "format": "bestaudio/best",
            "postprocessors": [{
                "key": "FFmpegExtractAudio",
                "preferredcodec": "mp3",
                "preferredquality": "192",
            }],
        })
    else:
        ydl_opts.update({
            "format": "bv*+ba/b",   # best video+audio if possible, else best
        })

    if YTDLP_COOKIES_FROM_BROWSER:
        ydl_opts["cookiesfrombrowser"] = (YTDLP_COOKIES_FROM_BROWSER, )

    def _run():
        with yt_dlp.YoutubeDL(ydl_opts) as ydl:
            return ydl.extract_info(url, download=True)

    try:
        info = await asyncio.to_thread(_run)
    except yt_dlp.utils.DownloadError as e:
        raise FetchError(f"yt-dlp failed: {e}") from e

    candidate = info.get("_filename")
    if candidate:
        p = pathlib.Path(candidate)
        if not audio_only and p.suffix.lower() != ".mp4":
            vid = info.get("id", "")
            found = sorted(DOWNLOAD_DIR.glob(f"*[{vid}]*.mp4"), key=lambda x: x.stat().st_mtime, reverse=True)
            if found:
                p = found[0]
        if p.exists() and not str(p).endswith(".part"):
            latest_file_path = p

    if not latest_file_path or not latest_file_path.exists():
        vid = info.get("id", "")
        cand = [q for q in DOWNLOAD_DIR.glob(f"*[{vid}]*") if q.is_file() and not str(q).endswith(".part")]
        if cand:
            latest_file_path = sorted(cand, key=lambda x: x.stat().st_mtime, reverse=True)[0]

    if not latest_file_path or not latest_file_path.exists():
        raise FetchError("ไม่พบไฟล์ผลลัพธ์หลังดาวน์โหลด (postprocess)")

    return latest_file_path

# ---------- Core (link flow) ----------
async def _do_ytdlp_flow(ctx_like, link_msg: discord.Message, url: str):
    fmt_view = FormatChoice(ctx_like.author.id)
    ask_msg = await link_msg.reply(
        "ต้องการโหลดเป็น **MP4** หรือ **MP3** ? (yt-dlp)",
        mention_author=False,
        view=fmt_view
    )
    await fmt_view.wait()
    if not fmt_view.choice:
        try: await ask_msg.edit(content="หมดเวลาเลือกฟอร์แมตแล้ว", view=None)
        except: pass
        return
    fmt = fmt_view.choice

    progress = None
    final_path: Optional[pathlib.Path] = None
    try:
        try: await ask_msg.delete()
        except: pass
        progress = await link_msg.reply("⏳ เริ่มดาวน์โหลดด้วย yt-dlp…", mention_author=False)

        audio_only = (fmt == "mp3")
        final_path = await download_with_ytdlp(url, audio_only=audio_only, progress_msg=progress)

        size = final_path.stat().st_size
        if size <= MAX_DISCORD_BYTES:
            if progress:
                await progress.edit(content=f"✅ เสร็จแล้ว: `{final_path.name}` ({size/1024/1024:.2f} MB)")
            await link_msg.reply(file=discord.File(str(final_path)), mention_author=False)
        else:
            if s3_enabled():
                url_pub = s3_upload(final_path)
                if progress:
                    await progress.edit(content=f"✅ เสร็จแล้ว แต่ไฟล์ใหญ่ {size/1024/1024:.2f} MB (เกินลิมิตแนบไฟล์)\n📤 อัปขึ้น S3 ให้แล้ว: {url_pub}")
                else:
                    await link_msg.reply(f"✅ เสร็จแล้ว แต่ไฟล์ใหญ่ {size/1024/1024:.2f} MB (เกินลิมิตแนบไฟล์)\n📤 อัปขึ้น S3 ให้แล้ว: {url_pub}", mention_author=False)
            else:
                if progress:
                    await progress.edit(content=f"✅ เสร็จแล้ว: `{final_path.name}` ({size/1024/1024:.2f} MB)\n⚠️ เกินลิมิตแนบไฟล์ — ตั้งค่า S3 เพื่ออัปอัตโนมัติ")
                else:
                    await link_msg.reply(f"✅ เสร็จแล้ว: `{final_path.name}` ({size/1024/1024:.2f} MB)\n⚠️ เกินลิมิตแนบไฟล์ — ตั้งค่า S3 เพื่ออัปอัตโนมัติ", mention_author=False)
    except FetchError as e:
        if progress:
            await progress.edit(content=f"❌ FetchError: {e}")
        else:
            await link_msg.reply(f"❌ FetchError: {e}", mention_author=False)
    except Exception as e:
        if progress:
            await progress.edit(content=f"❌ Error: {type(e).__name__}: {e}")
        else:
            await link_msg.reply(f"❌ Error: {type(e).__name__}: {e}", mention_author=False)
    finally:
        try:
            if final_path and final_path.exists():
                final_path.unlink(missing_ok=True)
        except Exception:
            pass

async def do_download_flow(ctx_like, link_msg: discord.Message, url: str):
    # 1) พยายามด้วย resolver เดิมก่อน (ไฟล์ตรง/HLS)
    try:
        info = await resolve_public_video(url)
    except NotAllowed as e:
        # ถ้าโดเมนนี้อนุญาตให้ใช้ yt-dlp และเปิดใช้งาน → ลองต่อด้วย yt-dlp
        if is_ytdlp_allowed_for(url):
            await link_msg.reply("↪️ โดเมนนี้จะใช้ **yt-dlp** จัดการให้…", mention_author=False)
            return await _do_ytdlp_flow(ctx_like, link_msg, url)
        await link_msg.reply(f"❌ โหลดไม่ได้: {e}", mention_author=False)
        return
    except Exception as e:
        # ถ้าพังด้วยเหตุอื่น ก็ลอง yt-dlp ถ้าอนุญาต
        if is_ytdlp_allowed_for(url):
            await link_msg.reply("↪️ ลองดาวน์โหลดด้วย **yt-dlp** …", mention_author=False)
            return await _do_ytdlp_flow(ctx_like, link_msg, url)
        await link_msg.reply(f"❌ Error while resolving: {type(e).__name__}: {e}", mention_author=False)
        return

    mode = info["mode"]
    variants: Optional[List[HlsVariant]] = info.get("variants")

    # ถามฟอร์แมต
    fmt_view = FormatChoice(ctx_like.author.id)
    ask_msg = await link_msg.reply(
        "ต้องการโหลดเป็น **MP4** หรือ **MP3** ?",
        mention_author=False,
        view=fmt_view
    )
    await fmt_view.wait()
    if not fmt_view.choice:
        try: await ask_msg.edit(content="หมดเวลาเลือกฟอร์แมตแล้ว", view=None)
        except: pass
        return
    fmt = fmt_view.choice

    # เลือกความละเอียด (เฉพาะ HLS หลายแทร็ก)
    selected_url = info["url"]
    if fmt == "mp4" and mode == "m3u8" and variants:
        vview = VariantSelect(ctx_like.author.id, variants)
        await ask_msg.edit(content="เลือกความละเอียด/บิตเรต (HLS):", view=vview)
        await vview.wait()
        if not vview.selected_variant:
            try: await ask_msg.edit(content="หมดเวลาเลือกความละเอียดแล้ว", view=None)
            except: pass
            return
        selected_url = vview.selected_variant.url

    # ลบกล่องตัวเลือก
    try:
        await ask_msg.delete()
    except Exception:
        pass

    # ประมวลผลและส่งไฟล์
    base_name = sanitize_filename(os.path.basename(urlparse(selected_url).path)) or "video"
    out_path = (
        DOWNLOAD_DIR / (base_name.rsplit(".",1)[0] + ".mp3")
        if fmt == "mp3" else
        DOWNLOAD_DIR / (base_name if base_name.lower().endswith(".mp4") else base_name.rsplit(".",1)[0] + ".mp4")
    )

    source_page = url  # ใช้เป็น referer
    progress: Optional[discord.Message] = None

    try:
        progress = await link_msg.reply("⏳ กำลังประมวลผล/ดาวน์โหลด...", mention_author=False)

        # กันไฟล์ใหญ่มากถ้าไม่ได้ตั้ง S3 (เฉพาะโหลดแบบ direct)
        if fmt == "mp4" and mode == "direct" and not s3_enabled():
            try:
                _, cl = await http_head_ok(selected_url, referer=source_page)
                if cl and cl > MAX_FETCH_BYTES:
                    await progress.edit(content=f"⚠️ ไฟล์ใหญ่ ~{cl/1024/1024:.1f} MB (> {MAX_FETCH_MB} MB) และยังไม่ได้ตั้งค่า S3 — ยกเลิก")
                    return
            except Exception:
                pass

        if fmt == "mp4":
            if mode == "direct":
                await stream_download(selected_url, out_path, referer=source_page)
            else:
                await download_hls_to_mp4(selected_url, out_path)
        else:
            if mode == "direct":
                tmp = DOWNLOAD_DIR / (base_name if pathlib.Path(base_name).suffix.lower() in VIDEO_EXTS else base_name + ".mp4")
                await stream_download(selected_url, tmp, referer=source_page)
                await extract_audio_generic(str(tmp), out_path, "mp3")
                try: tmp.unlink(missing_ok=True)
                except: pass
            else:
                await extract_audio_generic(selected_url, out_path, "mp3", referer=source_page)

        size = out_path.stat().st_size
        if size <= MAX_DISCORD_BYTES:
            await (progress.edit(content=f"✅ เสร็จแล้ว: `{out_path.name}` ({size/1024/1024:.2f} MB)") if progress else link_msg.reply(f"✅ เสร็จแล้ว: `{out_path.name}` ({size/1024/1024:.2f} MB)", mention_author=False))
            await link_msg.reply(file=discord.File(str(out_path)), mention_author=False)
        else:
            if s3_enabled():
                url_pub = s3_upload(out_path)
                await (progress.edit(content=f"✅ เสร็จแล้ว แต่ไฟล์ใหญ่ {size/1024/1024:.2f} MB (เกินลิมิตแนบไฟล์)\n📤 อัปขึ้น S3 ให้แล้ว: {url_pub}") if progress else link_msg.reply(f"✅ เสร็จแล้ว แต่ไฟล์ใหญ่ {size/1024/1024:.2f} MB (เกินลิมิตแนบไฟล์)\n📤 อัปขึ้น S3 ให้แล้ว: {url_pub}", mention_author=False))
            else:
                await (progress.edit(content=f"✅ เสร็จแล้ว: `{out_path.name}` ({size/1024/1024:.2f} MB)\n⚠️ เกินลิมิตแนบไฟล์ — ตั้งค่า S3 เพื่ออัปอัตโนมัติ") if progress else link_msg.reply(f"✅ เสร็จแล้ว: `{out_path.name}` ({size/1024/1024:.2f} MB)\n⚠️ เกินลิมิตแนบไฟล์ — ตั้งค่า S3 เพื่ออัปอัตโนมัติ", mention_author=False))
    except NotAllowed as e:
        if is_ytdlp_allowed_for(url):
            # สลับไป yt-dlp ถ้าอนุญาต
            await (progress.edit(content="↪️ สลับไปดาวน์โหลดด้วย **yt-dlp** …") if progress else link_msg.reply("↪️ สลับไปดาวน์โหลดด้วย **yt-dlp** …", mention_author=False))
            return await _do_ytdlp_flow(ctx_like, link_msg, url)
        if progress:
            await progress.edit(content=f"❌ {e}")
        else:
            await link_msg.reply(f"❌ {e}", mention_author=False)
    except FetchError as e:
        if progress:
            await progress.edit(content=f"❌ FetchError: {e}")
        else:
            await link_msg.reply(f"❌ FetchError: {e}", mention_author=False)
    except Exception as e:
        if is_ytdlp_allowed_for(url):
            await (progress.edit(content="↪️ ลองดาวน์โหลดด้วย **yt-dlp** …") if progress else link_msg.reply("↪️ ลองดาวน์โหลดด้วย **yt-dlp** …", mention_author=False))
            return await _do_ytdlp_flow(ctx_like, link_msg, url)
        if progress:
            await progress.edit(content=f"❌ Error: {type(e).__name__}: {e}")
        else:
            await link_msg.reply(f"❌ Error: {type(e).__name__}: {e}", mention_author=False)
    finally:
        # ล้างไฟล์ผลลัพธ์ ป้องกันดิสก์เต็ม
        try: out_path.unlink(missing_ok=True)
        except: pass

# ---------- Commands ----------
@bot.command(name="fetch", aliases=["grab"])
@require_allowed_channel()
async def fetch_cmd(ctx: commands.Context, url: Optional[str] = None):
    link_msg: discord.Message = ctx.message
    if ctx.message.reference and ctx.message.reference.resolved:
        link_msg = ctx.message.reference.resolved  # type: ignore

    target_text = (url or "").strip() or link_msg.content
    u = extract_first_url(target_text or "")
    if not u:
        await ctx.reply("โปรดใส่ลิงก์ หรือ reply ไปที่ข้อความที่มีลิงก์ก่อน", mention_author=False)
        return

    if is_blocked_host(hostof(u)):
        await link_msg.reply("🚫 โดเมนนี้ไม่รองรับ (เสี่ยง TOS/DRM)", mention_author=False)
        return

    await do_download_flow(ctx, link_msg, u)

@bot.command(name="ytfetch")
@require_allowed_channel()
async def ytfetch_cmd(ctx: commands.Context, url: Optional[str] = None):
    if not YTDLP_ENABLED:
        await ctx.reply("yt-dlp ถูกปิดใช้งาน (ตั้งค่า ENABLE_YTDLP=1 และ YTDLP_DOMAINS ก่อน)", mention_author=False)
        return
    link_msg: discord.Message = ctx.message
    target_text = (url or "").strip() or link_msg.content
    u = extract_first_url(target_text or "")
    if not u:
        await ctx.reply("โปรดใส่ลิงก์ หรือ reply ไปที่ข้อความที่มีลิงก์ก่อน", mention_author=False)
        return
    if not is_ytdlp_allowed_for(u):
        await ctx.reply("โดเมนนี้ไม่ได้อยู่ใน YTDLP_DOMAINS", mention_author=False)
        return
    await _do_ytdlp_flow(ctx, link_msg, u)

@bot.command(name="fetchdiag")
@require_allowed_channel()
async def fetchdiag(ctx: commands.Context, url: str):
    try:
        host = hostof(url)
        ok0, ct0, cl0 = True, "", 0
        try:
            ct0, cl0 = await http_head_ok(url, referer=url)
        except Exception as e:
            ok0, ct0 = False, f"ERR:{type(e).__name__}"

        path = urlparse(url).path.lower()
        ext = pathlib.Path(path).suffix.lower()
        direct_by_ext = ext in {".mp4",".mov",".webm",".mkv",".m4v",".ts"}
        direct_by_head = ct0.startswith("video/")
        hls_by_ct = is_hls_content_type(ct0)
        hls_by_ext = path.endswith(".m3u8")
        dash_by_ct = is_dash_content_type(ct0) or ("manifest" in url.lower() or "/dash" in url.lower())

        cand_cnt = 0; cand_preview = []
        try:
            html = await fetch_text(url, referer=url)
            cands = find_video_candidates(html, base_url=url)
            cand_cnt = len(cands); cand_preview = cands[:3]
        except Exception as e:
            cand_cnt = -1; cand_preview = [f"ERR:{type(e).__name__}"]

        await ctx.reply(
            f"**Diag** `{url}`\n"
            f"- host=`{host}` blocked=`{is_blocked_host(host)}` ytdlp_allowed=`{is_ytdlp_allowed_for(url)}`\n"
            f"- HEAD ok=`{ok0}` ct=`{ct0}` size=`{cl0}`\n"
            f"- ext=`{ext}` direct_by_ext=`{direct_by_ext}` direct_by_head=`{direct_by_head}`\n"
            f"- hls_by_ct=`{hls_by_ct}` hls_by_ext=`{hls_by_ext}` dash=`{dash_by_ct}`\n"
            f"- html_candidates=`{cand_cnt}` -> {cand_preview}",
            mention_author=False
        )
    except Exception as e:
        await ctx.reply(f"diag error: {type(e).__name__}: {e}", mention_author=False)

# ---------- Attachment flow: drop .mp4 -> ask audio ext -> convert ----------
class _DummyCtx:
    def __init__(self, user_id: int):
        self.author = type("U",(object,),{"id": user_id})()

async def handle_mp4_attachment_message(message: discord.Message):
    if ALLOWED_CHANNEL_IDS and (message.channel.id not in ALLOWED_CHANNEL_IDS):
        return
    if message.author.bot:
        return

    target_att: Optional[discord.Attachment] = None
    for att in message.attachments:
        filename = (att.filename or "").lower()
        ctype = (att.content_type or "").lower()
        if filename.endswith(".mp4") or ctype.startswith("video/mp4"):
            target_att = att
            break
    if not target_att:
        return

    view = AudioExtSelect(requester_id=message.author.id)
    ask_msg = await message.reply(
        f"แปลงไฟล์ **{target_att.filename}** เป็นไฟล์เสียงล้วน รูปแบบไหนดี?",
        mention_author=False,
        view=view
    )
    await view.wait()
    if not view.chosen_ext:
        try: await ask_msg.edit(content="หมดเวลาเลือกนามสกุลไฟล์เสียงแล้ว", view=None)
        except: pass
        return
    chosen = view.chosen_ext

    try: await ask_msg.delete()
    except: pass

    base = sanitize_filename(os.path.splitext(target_att.filename)[0]) or "video"
    src_path = DOWNLOAD_DIR / f"{base}.mp4"
    out_path = DOWNLOAD_DIR / f"{base}.{chosen}"

    try:
        await target_att.save(fp=str(src_path))
        await extract_audio_generic(str(src_path), out_path, chosen)

        size = out_path.stat().st_size
        if size <= MAX_DISCORD_BYTES:
            await message.reply(
                f"✅ เสร็จแล้ว: `{out_path.name}` ({size/1024/1024:.2f} MB)",
                file=discord.File(str(out_path)),
                mention_author=False
            )
        else:
            if s3_enabled():
                link = s3_upload(out_path)
                await message.reply(
                    f"✅ เสร็จแล้ว แต่ไฟล์ใหญ่ {size/1024/1024:.2f} MB (เกินลิมิตแนบไฟล์)\n"
                    f"📤 อัปขึ้น S3 ให้แล้ว: {link}",
                    mention_author=False
                )
            else:
                await message.reply(
                    f"✅ เสร็จแล้ว: `{out_path.name}` ({size/1024/1024:.2f} MB)\n"
                    f"⚠️ เกินลิมิตแนบไฟล์ — ตั้งค่า S3 เพื่ออัปอัตโนมัติ",
                    mention_author=False
                )
    except FetchError as e:
        await message.reply(f"❌ FetchError: {e}", mention_author=False)
    except Exception as e:
        await message.reply(f"❌ Error: {type(e).__name__}: {e}", mention_author=False)
    finally:
        try: src_path.unlink(missing_ok=True)
        except: pass
        try: out_path.unlink(missing_ok=True)
        except: pass

# ---------- Link flow: detect link in any message ----------
async def handle_link_message(message: discord.Message):
    if ALLOWED_CHANNEL_IDS and (message.channel.id not in ALLOWED_CHANNEL_IDS):
        return
    if message.author.bot:
        return

    u = extract_first_url(message.content or "")
    if not u:
        return

    if is_blocked_host(hostof(u)):
        await message.reply("🚫 โดเมนนี้ไม่รองรับ (เสี่ยง TOS/DRM)", mention_author=False)
        return

    await do_download_flow(_DummyCtx(message.author.id), message, u)

# ---------- Global message hook ----------
@bot.event
async def on_message(message: discord.Message):
    # กันยิงซ้ำถ้าเป็นคำสั่ง
    content = (message.content or "").lstrip()
    is_cmd = any(content.startswith(pfx) for pfx in COMMAND_PREFIXES)
    try:
        if not is_cmd:
            await handle_mp4_attachment_message(message)  # โยนไฟล์ .mp4 → ถามนามสกุลเสียง
            await handle_link_message(message)            # แปะลิงก์ → เปิด flow อัตโนมัติ / บอกเหตุผลถ้าบล็อก
    finally:
        await bot.process_commands(message)

# ---------- Boot ----------
if __name__ == "__main__":
    if not DISCORD_TOKEN:
        raise SystemExit("กรุณาตั้งค่า DISCORD_TOKEN ใน Environment")
    bot.run(DISCORD_TOKEN)
