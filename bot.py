# bot.py — yt-dlp only + GCS + 403-hardened (PO token, client rotate, fragment tuning, HLS fallback)
import os, re, json, time, asyncio, pathlib, random, string, mimetypes, datetime, base64
from typing import List, Optional
from urllib.parse import urlparse

import aiofiles
import discord
from discord.ext import commands

import yt_dlp
from google.cloud import storage
from google.oauth2 import service_account

# ========== ENV ==========
DISCORD_TOKEN = os.getenv("DISCORD_TOKEN", "")
MAX_DISCORD_BYTES = int(os.getenv("UPLOAD_LIMIT_BYTES", str(24 * 1024 * 1024)))  # Discord attach limit

# yt-dlp basic
YTDLP_ENABLED = True  # ใช้ yt-dlp เท่านั้น
YTDLP_DOMAINS = set(d.strip().lower() for d in (os.getenv("YTDLP_DOMAINS") or "youtube.com,youtu.be,youtube-nocookie.com").split(",") if d.strip())
YTDLP_MAX_BYTES = int(os.getenv("YTDLP_MAX_BYTES", str(350 * 1024 * 1024)))  # 350 MB
YTDLP_FORCE_IPV4 = os.getenv("YTDLP_FORCE_IPV4", "1") == "1"
YTDLP_PROXY = os.getenv("YTDLP_PROXY") or None
YTDLP_COOKIES_B64 = os.getenv("YTDLP_COOKIES_B64")  # เนื้อไฟล์ cookies.txt base64
YTDLP_COOKIES_FROM_BROWSER = os.getenv("YTDLP_COOKIES_FROM_BROWSER")  # e.g. "chrome"
YTDLP_GEO = os.getenv("YTDLP_GEO", "TH")
YTDLP_DEBUG = os.getenv("YTDLP_DEBUG", "0") == "1"

# YouTube extractor hardening
# ลำดับ clients จะถูกลองตามค่านี้ (กรณีเฟลจะสลับตัวถัดไปอัตโนมัติ)
YTDLP_YT_CLIENTS = [c.strip() for c in (os.getenv("YTDLP_YT_CLIENTS") or "web,android").split(",") if c.strip()]
# ถ้ามี PO token ให้ตั้ง เช่น ios.gvs+<TOKEN> หรือ web+<TOKEN>
YTDLP_YT_PO_TOKEN = os.getenv("YTDLP_YT_PO_TOKEN")
# ลด concurrent fragments เพื่อลด 403 ระหว่างดาวน์โหลด DASH/HLS
YTDLP_CONCURRENT_FRAGMENTS = int(os.getenv("YTDLP_CONCURRENT_FRAGMENTS", "1"))  # 1 คือปลอดภัยสุด

# GCS
GCS_BUCKET = os.getenv("GCS_BUCKET", "")
GCS_PUBLIC_BASE = (os.getenv("GCS_PUBLIC_BASE", "") or "").rstrip("/")
GCS_LINK_MODE = (os.getenv("GCS_LINK_MODE") or "presign").lower()  # "presign" | "public"
GCS_TTL_SECONDS = max(0, int(os.getenv("GCS_TTL_SECONDS", "3600")))  # อายุลิงก์หรือนำไปลบ (วินาที)

# GCP credential (เลือกอย่างใดอย่างหนึ่งพอ)
GOOGLE_APPLICATION_CREDENTIALS = os.getenv("GOOGLE_APPLICATION_CREDENTIALS", "")
GCS_CREDENTIALS_JSON = os.getenv("GCS_CREDENTIALS_JSON")
GCP_SERVICE_ACCOUNT_B64 = os.getenv("GCP_SERVICE_ACCOUNT_B64")

# ใช้ allowlist ห้อง/เธรด (ถ้ามีไฟล์)
try:
    from channel_allowlist import ALLOWED_CHANNEL_IDS  # set[int]
except Exception:
    ALLOWED_CHANNEL_IDS: set[int] = set()

# ========== Discord ==========
INTENTS = discord.Intents.default()
INTENTS.message_content = True
COMMAND_PREFIXES = tuple((os.getenv("COMMAND_PREFIXES") or "!").split(","))
bot = commands.Bot(command_prefix=COMMAND_PREFIXES[0], intents=INTENTS)

DOWNLOAD_DIR = pathlib.Path("downloads")
DOWNLOAD_DIR.mkdir(parents=True, exist_ok=True)

DEFAULT_HEADERS = {
    "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36",
    "accept-language": "en-US,en;q=0.8,th;q=0.7",
}

# ---------- Blocked domains (TOS/DRM risk) ----------
BLOCKED_DOMAINS = {
    "netflix.com", "disneyplus.com", "primevideo.com", "hulu.com",
    "max.com", "paramountplus.com", "peacocktv.com", "tv.apple.com",
    "crunchyroll.com", "hotstar.com", "viu.com",
    "onlyfans.com", "fansly.com",
    "patreon.com",
}

# ---------- Utils ----------
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
def extract_first_url(text: str) -> Optional[str]:
    m = URL_RE.search(text or "")
    if not m: return None
    u = m.group(0)
    return u.rstrip(">)].,!?\"'")

def sanitize_filename(name: str) -> str:
    return (re.sub(r"[^\w\-. ]+", "_", name)[:200] or "media").strip()

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

# ---------- Audio conversion (สำหรับไฟล์แนบ .mp4 -> audio) ----------
SUPPORTED_AUDIO_EXTS = ["mp3", "m4a", "aac", "opus", "ogg", "wav", "flac"]

def audio_ffmpeg_args(ext: str) -> List[str]:
    ext = ext.lower()
    if ext == "mp3":  return ["-c:a","libmp3lame","-b:a","192k"]
    if ext == "m4a":  return ["-c:a","aac","-b:a","192k","-movflags","+faststart"]
    if ext == "aac":  return ["-c:a","aac","-b:a","192k","-f","adts"]
    if ext == "opus": return ["-c:a","libopus","-b:a","128k"]
    if ext == "ogg":  return ["-c:a","libvorbis","-q:a","5"]
    if ext == "wav":  return ["-c:a","pcm_s16le"]
    if ext == "flac": return ["-c:a","flac"]
    raise ValueError(f"unsupported audio ext: {ext}")

async def extract_audio_generic(input_path: str, out_path: pathlib.Path, ext: str):
    args = audio_ffmpeg_args(ext)
    cmd = ["ffmpeg","-y","-i", input_path, "-vn", *args, str(out_path)]
    proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    _, err = await proc.communicate()
    if proc.returncode != 0:
        raise RuntimeError(f"ffmpeg (audio:{ext}) failed: {err.decode(errors='ignore')[:300]}")

# ---------- GCS helpers ----------
_GCS_CLIENT: Optional[storage.Client] = None

def gcs_enabled() -> bool:
    return bool(GCS_BUCKET)

def _get_gcs_client() -> storage.Client:
    global _GCS_CLIENT
    if _GCS_CLIENT is not None:
        return _GCS_CLIENT
    if GCS_CREDENTIALS_JSON:
        info = json.loads(GCS_CREDENTIALS_JSON)
        creds = service_account.Credentials.from_service_account_info(info)
        _GCS_CLIENT = storage.Client(credentials=creds, project=creds.project_id)
    elif GCP_SERVICE_ACCOUNT_B64:
        info = json.loads(base64.b64decode(GCP_SERVICE_ACCOUNT_B64).decode("utf-8"))
        creds = service_account.Credentials.from_service_account_info(info)
        _GCS_CLIENT = storage.Client(credentials=creds, project=creds.project_id)
    else:
        _GCS_CLIENT = storage.Client()
    return _GCS_CLIENT

async def _gcs_delete_after(object_name: str, delay_seconds: int):
    try:
        delay_seconds = max(30, int(delay_seconds))
        await asyncio.sleep(delay_seconds)
        client = _get_gcs_client()
        bucket = client.bucket(GCS_BUCKET)
        bucket.blob(object_name).delete()
    except Exception:
        pass

def gcs_upload(local_path: pathlib.Path) -> tuple[str, str]:
    client = _get_gcs_client()
    bucket = client.bucket(GCS_BUCKET)

    object_name = f"publicfetch/{int(time.time())}_{''.join(random.choices(string.ascii_lowercase+string.digits,k=10))}_{sanitize_filename(local_path.name)}"
    blob = bucket.blob(object_name)

    content_type = mimetypes.guess_type(local_path.name)[0] or "application/octet-stream"
    blob.cache_control = "no-store" if GCS_LINK_MODE == "presign" else "public, max-age=3600"
    blob.upload_from_filename(str(local_path), content_type=content_type)

    if GCS_LINK_MODE == "public":
        try: blob.make_public()
        except Exception: pass
        if GCS_PUBLIC_BASE:
            return f"{GCS_PUBLIC_BASE}/{object_name}", object_name
        return f"https://storage.googleapis.com/{GCS_BUCKET}/{object_name}", object_name

    expires = datetime.timedelta(seconds=min(max(GCS_TTL_SECONDS or 3600, 60), 7*24*3600))
    url = blob.generate_signed_url(expiration=expires, version="v4", method="GET")
    return url, object_name

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
    async def mp4(self, interaction: discord.Interaction, button: discord.ui.Button):
        self.choice = "mp4"
        await interaction.response.defer()
        self.stop()

    @discord.ui.button(label="MP3 (เสียงล้วน)", style=discord.ButtonStyle.secondary)
    async def mp3(self, interaction: discord.Interaction, button: discord.ui.Button):
        self.choice = "mp3"
        await interaction.response.defer()
        self.stop()

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

# ---------- yt-dlp core (403-hardened) ----------
async def download_with_ytdlp(url: str, audio_only: bool, progress_msg: Optional[discord.Message]) -> pathlib.Path:
    latest_file_path: Optional[pathlib.Path] = None
    last_edit = 0.0
    loop = asyncio.get_running_loop()
    tmp_cookiefile: Optional[pathlib.Path] = None

    async def update_progress(d: dict):
        nonlocal latest_file_path, last_edit
        if not progress_msg:
            return
        now = time.time()
        if now - last_edit < 0.6:
            return
        last_edit = now

        status = d.get("status")
        if status == "downloading":
            p = (d.get("_percent_str") or "").strip()
            s = (d.get("_speed_str") or "").strip()
            e = d.get("eta")
            eta = f" ETA {int(e)}s" if isinstance(e, (int,float)) and e > 0 else ""
            try: await progress_msg.edit(content=f"⬇️ yt-dlp… {p} {s}{eta}")
            except Exception: pass
        elif status == "finished":
            try: await progress_msg.edit(content="🔄 รวม/แปลงไฟล์…")
            except Exception: pass

        fn = d.get("filename")
        if fn and not str(fn).endswith(".part"):
            latest_file_path = pathlib.Path(fn)

    def hook(d):
        loop.call_soon_threadsafe(asyncio.create_task, update_progress(d))

    outtmpl = str(DOWNLOAD_DIR / "%(title).200B [%(id)s].%(ext)s")

    # สร้างออปชั่นพื้นฐาน (จะถูกคัดลอก/แก้ในแต่ละรอบลอง)
    base_opts = {
        "quiet": not YTDLP_DEBUG,
        "no_warnings": not YTDLP_DEBUG,
        "verbose": YTDLP_DEBUG,
        "outtmpl": outtmpl,
        "noprogress": True,
        "progress_hooks": [hook],
        "max_filesize": YTDLP_MAX_BYTES,
        "merge_output_format": "mp4",
        "retries": 10,
        "fragment_retries": 50,
        "skip_unavailable_fragments": True,
        "sleep_interval_requests": 0.5,
        "geo_bypass": True,
        "geo_bypass_country": YTDLP_GEO,
        "http_headers": {
            "User-Agent": DEFAULT_HEADERS["user-agent"],
            "Accept-Language": DEFAULT_HEADERS["accept-language"],
            "Referer": url,
        },
        # ลดการยิงพร้อมกันของ fragment (ป้องกัน 403 จากบาง PoP)
        "concurrent_fragment_downloads": max(1, YTDLP_CONCURRENT_FRAGMENTS),
    }

    if YTDLP_FORCE_IPV4:
        base_opts["source_address"] = "0.0.0.0"
    if YTDLP_PROXY:
        base_opts["proxy"] = YTDLP_PROXY
    if YTDLP_COOKIES_FROM_BROWSER:
        base_opts["cookiesfrombrowser"] = (YTDLP_COOKIES_FROM_BROWSER, )

    if YTDLP_COOKIES_B64:
        try:
            tmp_cookiefile = DOWNLOAD_DIR / "cookies.txt"
            tmp_cookiefile.write_text(base64.b64decode(YTDLP_COOKIES_B64).decode("utf-8"), encoding="utf-8")
            base_opts["cookiefile"] = str(tmp_cookiefile)
        except Exception:
            tmp_cookiefile = None

    # แผนการลอง (matrix): สลับ client และบังคับ HLS เป็นลำดับ fallback
    # หมายเหตุ: ถ้ามี PO token ค่อยลอง ios.gvs (หรือ client อื่นที่ต้อง token)
    client_sequences: List[List[str]] = []
    if YTDLP_YT_CLIENTS:
        client_sequences.append(YTDLP_YT_CLIENTS)
    # เพิ่ม fallback เฉพาะเจาะจง
    client_sequences += [["web"], ["android"]]
    if YTDLP_YT_PO_TOKEN:
        client_sequences += [["ios"]]  # ios.gvs ต้องมี po_token

    # formats ที่จะลองในแต่ละ client
    fmt_default_video = "bv*+ba/b"
    fmt_hls_first = "bestvideo*[protocol*=m3u8]+bestaudio/best[protocol*=m3u8]/best"
    fmt_audio = "bestaudio/best"

    format_sequences = [[fmt_audio] if audio_only else [fmt_default_video, fmt_hls_first]]

    last_error: Optional[Exception] = None

    for clients in client_sequences:
        for fmts in format_sequences:
            ydl_opts = dict(base_opts)  # clone
            # extractor-args: player_client + po_token (ถ้ามี)
            ex_args = {"youtube": {}}
            if clients:
                ex_args["youtube"]["player_client"] = clients
            if YTDLP_YT_PO_TOKEN:
                ex_args["youtube"]["po_token"] = YTDLP_YT_PO_TOKEN
            ydl_opts["extractor_args"] = ex_args

            # format
            ydl_opts["format"] = fmts[0]

            # ถ้าเป็น audio-only ให้ postprocessor แปลงเป็น mp3
            if audio_only:
                ydl_opts["postprocessors"] = [{
                    "key": "FFmpegExtractAudio",
                    "preferredcodec": "mp3",
                    "preferredquality": "192",
                }]

            # ฟังก์ชันรันจริง
            def _run():
                with yt_dlp.YoutubeDL(ydl_opts) as ydl:
                    return ydl.extract_info(url, download=True)

            try:
                info = await asyncio.to_thread(_run)
                # หาไฟล์เอาต์พุต
                p: Optional[pathlib.Path] = None
                cand = info.get("_filename")
                if cand:
                    p = pathlib.Path(cand)
                if p and (not p.exists() or str(p).endswith(".part")):
                    p = None
                if not p:
                    vid = info.get("id", "")
                    files = [q for q in DOWNLOAD_DIR.glob(f"*[{vid}]*") if q.is_file() and not str(q).endswith(".part")]
                    if files:
                        p = sorted(files, key=lambda x: x.stat().st_mtime, reverse=True)[0]
                if not p:
                    raise RuntimeError("ไม่พบไฟล์ผลลัพธ์หลังดาวน์โหลด (postprocess)")
                return p
            except Exception as e:
                last_error = e
                # ถ้าล้มเหลวด้วย 403 ให้ลอง format ถัดไป (เช่น HLS) หรือสลับ client
                continue

    # ถ้ามาถึงตรงนี้แปลว่าทุกรอบล้มเหลว
    if last_error:
        raise RuntimeError(f"yt-dlp failed: {last_error}")
    raise RuntimeError("yt-dlp failed: unknown error")

# ---------- Core flow ----------
async def _do_ytdlp_flow(ctx_like, link_msg: discord.Message, url: str):
    if not is_ytdlp_allowed_for(url):
        await link_msg.reply("โดเมนนี้ไม่ได้อยู่ใน YTDLP_DOMAINS", mention_author=False)
        return
    if is_blocked_host(hostof(url)):
        await link_msg.reply("🚫 โดเมนนี้ไม่รองรับ (เสี่ยง TOS/DRM)", mention_author=False)
        return

    fmt_view = FormatChoice(ctx_like.author.id)
    ask_msg = await link_msg.reply("ต้องการโหลดเป็น **MP4** หรือ **MP3** ? (yt-dlp)", mention_author=False, view=fmt_view)
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
            if progress: await progress.edit(content=f"✅ เสร็จแล้ว: `{final_path.name}` ({size/1024/1024:.2f} MB)")
            await link_msg.reply(file=discord.File(str(final_path)), mention_author=False)
        else:
            if gcs_enabled():
                url_pub, object_name = gcs_upload(final_path)
                ttl_msg = ""
                if GCS_TTL_SECONDS > 0:
                    if GCS_LINK_MODE == "presign":
                        ttl_msg = f"\n⏳ ลิงก์จะหมดอายุใน ~{GCS_TTL_SECONDS//60} นาที"
                    else:
                        ttl_msg = f"\n⏳ จะลบไฟล์จาก GCS ภายใน ~{GCS_TTL_SECONDS//60} นาที"
                    asyncio.create_task(_gcs_delete_after(object_name, GCS_TTL_SECONDS + 30))
                if progress:
                    await progress.edit(content=f"✅ เสร็จแล้ว แต่ไฟล์ใหญ่ {size/1024/1024:.2f} MB (เกินลิมิตแนบไฟล์)\n📤 อัปขึ้น GCS: {url_pub}{ttl_msg}")
                else:
                    await link_msg.reply(f"✅ เสร็จแล้ว แต่ไฟล์ใหญ่ {size/1024/1024:.2f} MB (เกินลิมิตแนบไฟล์)\n📤 อัปขึ้น GCS: {url_pub}{ttl_msg}", mention_author=False)
            else:
                if progress:
                    await progress.edit(content=f"✅ เสร็จแล้ว: `{final_path.name}` ({size/1024/1024:.2f} MB)\n⚠️ เกินลิมิตแนบไฟล์ — ตั้งค่า GCS เพื่ออัปอัตโนมัติ")
                else:
                    await link_msg.reply(f"✅ เสร็จแล้ว: `{final_path.name}` ({size/1024/1024:.2f} MB)\n⚠️ เกินลิมิตแนบไฟล์ — ตั้งค่า GCS เพื่ออัปอัตโนมัติ", mention_author=False)
    except Exception as e:
        if progress: await progress.edit(content=f"❌ Error: {type(e).__name__}: {e}")
        else: await link_msg.reply(f"❌ Error: {type(e).__name__}: {e}", mention_author=False)
    finally:
        try:
            if final_path and final_path.exists():
                final_path.unlink(missing_ok=True)  # ลบไฟล์ local ทันที
        except Exception:
            pass

async def do_download_flow(ctx_like, link_msg: discord.Message, url: str):
    await _do_ytdlp_flow(ctx_like, link_msg, url)

# ---------- Commands ----------
@bot.command(name="fetch", aliases=["grab","ytfetch"])
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
    await do_download_flow(ctx, link_msg, u)

@bot.command(name="ytfetchdiag")
@require_allowed_channel()
async def ytfetchdiag(ctx: commands.Context, url: str):
    try:
        h = hostof(url)
        await ctx.reply(
            f"**Diag (yt-dlp)** `{url}`\n"
            f"- host=`{h}` blocked=`{is_blocked_host(h)}`\n"
            f"- YTDLP_ALLOWED=`{is_ytdlp_allowed_for(url)}` max_bytes=`{YTDLP_MAX_BYTES}`\n"
            f"- force_ipv4=`{YTDLP_FORCE_IPV4}` proxy=`{bool(YTDLP_PROXY)}` geo=`{YTDLP_GEO}`\n"
            f"- cookies_b64=`{bool(YTDLP_COOKIES_B64)}` cookies_browser=`{bool(YTDLP_COOKIES_FROM_BROWSER)}`\n"
            f"- clients=`{','.join(YTDLP_YT_CLIENTS)}` po_token=`{bool(YTDLP_YT_PO_TOKEN)}`\n"
            f"- concurrent_fragments=`{YTDLP_CONCURRENT_FRAGMENTS}`\n"
            f"- GCS enabled=`{gcs_enabled()}` mode=`{GCS_LINK_MODE}` ttl=`{GCS_TTL_SECONDS}`",
            mention_author=False
        )
    except Exception as e:
        await ctx.reply(f"diag error: {type(e).__name__}: {e}", mention_author=False)

# ---------- Attachment flow ----------
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
            if gcs_enabled():
                url_pub, object_name = gcs_upload(out_path)
                ttl_msg = ""
                if GCS_TTL_SECONDS > 0:
                    if GCS_LINK_MODE == "presign":
                        ttl_msg = f"\n⏳ ลิงก์จะหมดอายุใน ~{GCS_TTL_SECONDS//60} นาที"
                    else:
                        ttl_msg = f"\n⏳ จะลบไฟล์นี้จาก GCS ภายใน ~{GCS_TTL_SECONDS//60} นาที"
                    asyncio.create_task(_gcs_delete_after(object_name, GCS_TTL_SECONDS + 30))
                await message.reply(
                    f"✅ เสร็จแล้ว แต่ไฟล์ใหญ่ {size/1024/1024:.2f} MB (เกินลิมิตแนบไฟล์)\n"
                    f"📤 อัปขึ้น GCS ให้แล้ว: {url_pub}{ttl_msg}",
                    mention_author=False
                )
            else:
                await message.reply(
                    f"✅ เสร็จแล้ว: `{out_path.name}` ({size/1024/1024:.2f} MB)\n"
                    f"⚠️ เกินลิมิตแนบไฟล์ — ตั้งค่า GCS เพื่ออัปอัตโนมัติ",
                    mention_author=False
                )
    except Exception as e:
        await message.reply(f"❌ Error: {type(e).__name__}: {e}", mention_author=False)
    finally:
        try: src_path.unlink(missing_ok=True)
        except: pass
        try: out_path.unlink(missing_ok=True)
        except: pass

# ---------- Link flow ----------
async def handle_link_message(message: discord.Message):
    if ALLOWED_CHANNEL_IDS and (message.channel.id not in ALLOWED_CHANNEL_IDS):
        return
    if message.author.bot:
        return

    u = extract_first_url(message.content or "")
    if not u:
        return
    await do_download_flow(_DummyCtx(message.author.id), message, u)

# ---------- Global hook ----------
@bot.event
async def on_message(message: discord.Message):
    content = (message.content or "").lstrip()
    is_cmd = any(content.startswith(pfx) for pfx in COMMAND_PREFIXES)
    try:
        if not is_cmd:
            await handle_mp4_attachment_message(message)
            await handle_link_message(message)
    finally:
        await bot.process_commands(message)

# ---------- Boot ----------
if __name__ == "__main__":
    if not DISCORD_TOKEN:
        raise SystemExit("กรุณาตั้งค่า DISCORD_TOKEN ใน Environment")
    bot.run(DISCORD_TOKEN)
