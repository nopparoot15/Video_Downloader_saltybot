# bot.py
import os, re, pathlib, asyncio, time, random, string
from typing import List, Optional, Tuple
from dataclasses import dataclass
from urllib.parse import urlparse, urljoin

import httpx, aiofiles, boto3
import discord
from discord.ext import commands

# ========== ENV ==========
DISCORD_TOKEN = os.getenv("DISCORD_TOKEN", "")
MAX_DISCORD_BYTES = int(os.getenv("UPLOAD_LIMIT_BYTES", str(24 * 1024 * 1024)))

# S3 (อัปไฟล์ใหญ่เกินลิมิตแนบไฟล์)
S3_BUCKET = os.getenv("S3_BUCKET", "")
S3_REGION = os.getenv("S3_REGION", "")
AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID", "")
AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY", "")
S3_PUBLIC_BASE = (os.getenv("S3_PUBLIC_BASE", "") or "").rstrip("/")

# ใช้ allowlist ห้อง/เธรด (ไฟล์แยก)
try:
    from channel_allowlist import ALLOWED_CHANNEL_IDS  # set[int]
except Exception:
    ALLOWED_CHANNEL_IDS: set[int] = set()

# ========== Discord ==========
INTENTS = discord.Intents.default()
INTENTS.message_content = True
bot = commands.Bot(command_prefix="!", intents=INTENTS)

DOWNLOAD_DIR = pathlib.Path("downloads")
DOWNLOAD_DIR.mkdir(parents=True, exist_ok=True)

VIDEO_EXTS = {".mp4", ".mov", ".webm", ".mkv", ".m4v", ".ts"}
HLS_EXTS = {".m3u8"}

# โดเมนที่เสี่ยง TOS/DRM — ไม่แตะ
BLOCKED_HOSTS = {

}

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

async def extract_audio_generic(input_path_or_url: str, out_path: pathlib.Path, ext: str):
    args = audio_ffmpeg_args(ext)
    cmd = ["ffmpeg","-y","-i", input_path_or_url, "-vn", *args, str(out_path)]
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
def hostof(url: str) -> str:
    return urlparse(url).netloc.lower()

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
    s3.upload_file(str(local_path), S3_BUCKET, key, ExtraArgs={"ACL": "public-read"})
    return f"{S3_PUBLIC_BASE}/{key}"

def is_hls_content_type(ct: str) -> bool:
    ct = (ct or "").lower()
    return ("application/x-mpegurl" in ct or
            "application/vnd.apple.mpegurl" in ct or
            ct == "audio/mpegurl")

async def http_head_ok(url: str) -> Tuple[str, int]:
    async with httpx.AsyncClient(follow_redirects=True, timeout=30) as client:
        r = await client.head(url)
        if r.status_code in (405, 403):
            r = await client.get(url, stream=True)
            await r.aclose()
        r.raise_for_status()
        ct = r.headers.get("content-type","").lower()
        cl = int(r.headers.get("content-length") or 0)
        return ct, cl

async def is_direct_video(url: str) -> bool:
    try:
        ct, _ = await http_head_ok(url)
        if ct.startswith("video/"):
            return True
        suffix = pathlib.Path(urlparse(url).path).suffix.lower()
        return suffix in VIDEO_EXTS
    except Exception:
        return False

async def fetch_text(url: str) -> str:
    async with httpx.AsyncClient(follow_redirects=True, timeout=40) as client:
        r = await client.get(url)
        r.raise_for_status()
        return r.text

async def stream_download(url: str, dest: pathlib.Path, chunk=1<<16):
    async with httpx.AsyncClient(follow_redirects=True, timeout=None) as client:
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
    cmd = [
        "ffmpeg","-y",
        "-protocol_whitelist","file,http,https,tcp,tls,crypto",
        "-i", m3u8_url,
        "-c","copy",
        str(out_path)
    ]
    proc = await asyncio.create_subprocess_exec(
        *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )
    _, err = await proc.communicate()
    if proc.returncode != 0:
        raise FetchError(f"ffmpeg failed: {err.decode(errors='ignore')[:300]}")

# ---------- HTML candidates ----------
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
    urls = []
    for pat in VIDEO_CANDIDATE_PATTERNS:
        for m in re.finditer(pat, html, flags=re.I):
            u = (m.group(1) or "").strip()
            if not u:
                continue
            if not urlparse(u).scheme:
                u = urljoin(base_url, u)
            urls.append(u)
    # unique preserve order
    seen = set(); out = []
    for u in urls:
        if u not in seen:
            seen.add(u); out.append(u)
    return out

# ---------- Resolver ----------
async def resolve_public_video(url: str):
    host = hostof(url)
    if any(b in host for b in BLOCKED_HOSTS):
        raise NotAllowed("โดเมนนี้ไม่รองรับ (เสี่ยง TOS/DRM)")

    # 0) HEAD เช็คชนิดไฟล์ก่อน
    try:
        ct, _ = await http_head_ok(url)
        if ct.startswith("video/"):
            return {"mode": "direct", "url": url, "variants": None}
        if is_hls_content_type(ct):
            # อาจเป็น media playlist (.m3u8) แม้ URL ไม่ลงท้าย .m3u8
            text = await fetch_text(url)
            if hls_is_encrypted(text):
                raise NotAllowed("พบการเข้ารหัสใน .m3u8 — ไม่รองรับ")
            variants = parse_hls_master(text, base_url=url)
            # ถ้าเป็น media playlist จะไม่มี STREAM-INF → ไม่มี variants ก็ยังโหลดได้
            return {"mode": "m3u8", "url": url, "variants": variants or None}
    except Exception:
        # ถ้า HEAD ล้มเหลวก็ไปลำดับถัดไป
        pass

    # 1) นามสกุลไฟล์ตรง?
    if await is_direct_video(url):
        return {"mode": "direct", "url": url, "variants": None}

    # 2) HLS จากนามสกุล .m3u8
    path = urlparse(url).path.lower()
    if path.endswith(".m3u8"):
        text = await fetch_text(url)
        if hls_is_encrypted(text):
            raise NotAllowed("พบการเข้ารหัสใน .m3u8 — ไม่รองรับ")
        variants = parse_hls_master(text, base_url=url)
        return {"mode": "m3u8", "url": url, "variants": variants or None}

    # 3) HTML → หา og:video/<video>/<source>/twitter:player:stream
    try:
        html = await fetch_text(url)
        cands = find_video_candidates(html, base_url=url)
        for cu in cands:
            # ลอง HEAD ของ candidate ด้วยเผื่อเป็น HLS
            try:
                cct, _ = await http_head_ok(cu)
                if cct.startswith("video/"):
                    return {"mode": "direct", "url": cu, "variants": None}
                if is_hls_content_type(cct) or cu.lower().endswith(".m3u8"):
                    text2 = await fetch_text(cu)
                    if hls_is_encrypted(text2):
                        continue
                    variants = parse_hls_master(text2, base_url=cu)
                    return {"mode": "m3u8", "url": cu, "variants": variants or None}
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
    def __init__(self, requester_id: int, variants: List[HlsVariant], timeout: int = 120):
        super().__init__(timeout=timeout)
        self.requester_id = requester_id
        self.variants = variants
        self.selected_variant: Optional[HlsVariant] = None

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

# ---------- Core (link flow) ----------
async def do_download_flow(ctx_like, link_msg: discord.Message, url: str):
    # 1) Resolve (จับ NotAllowed ให้ตอบกลับแทนการ error เงียบ)
    try:
        info = await resolve_public_video(url)
    except NotAllowed as e:
        await link_msg.reply(f"❌ โหลดไม่ได้: {e}", mention_author=False)
        return
    except Exception as e:
        await link_msg.reply(f"❌ Error while resolving: {type(e).__name__}: {e}", mention_author=False)
        return

    mode = info["mode"]
    variants: Optional[List[HlsVariant]] = info.get("variants")

    # 2) ถามฟอร์แมต (reply ไปที่ "ข้อความลิงก์" แบบสาธารณะ)
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

    # 3) ถ้า m3u8 + MP4 + มีหลายแทร็ก → ให้เลือกความละเอียดก่อน
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

    # 4) ลบ “ข้อความตัวเลือก”
    try:
        await ask_msg.delete()
    except Exception:
        pass

    # 5) ประมวลผลและส่งไฟล์กลับ “ตอบข้อความลิงก์”
    base_name = sanitize_filename(os.path.basename(urlparse(selected_url).path)) or "video"
    out_path = (
        DOWNLOAD_DIR / (base_name.rsplit(".",1)[0] + ".mp3")
        if fmt == "mp3" else
        DOWNLOAD_DIR / (base_name if base_name.lower().endswith(".mp4") else base_name.rsplit(".",1)[0] + ".mp4")
    )

    try:
        if fmt == "mp4":
            if mode == "direct":
                await stream_download(selected_url, out_path)
            else:
                await download_hls_to_mp4(selected_url, out_path)
        else:
            # สำหรับโฟลว์ลิงก์ เลือกเป็น MP3 เป็นดีฟอลต์
            if mode == "direct":
                tmp = DOWNLOAD_DIR / (base_name if base_name.lower().endswith(tuple(VIDEO_EXTS)) else base_name + ".mp4")
                await stream_download(selected_url, tmp)
                await extract_audio_generic(str(tmp), out_path, "mp3")
                try: tmp.unlink(missing_ok=True)
                except: pass
            else:
                await extract_audio_generic(selected_url, out_path, "mp3")

        size = out_path.stat().st_size
        if size <= MAX_DISCORD_BYTES:
            await link_msg.reply(
                f"✅ เสร็จแล้ว: `{out_path.name}` ({size/1024/1024:.2f} MB)",
                file=discord.File(str(out_path)),
                mention_author=False
            )
        else:
            if s3_enabled():
                url_pub = s3_upload(out_path)
                await link_msg.reply(
                    f"✅ เสร็จแล้ว แต่ไฟล์ใหญ่ {size/1024/1024:.2f} MB (เกินลิมิตแนบไฟล์)\n📤 อัปขึ้น S3 ให้แล้ว: {url_pub}",
                    mention_author=False
                )
            else:
                await link_msg.reply(
                    f"✅ เสร็จแล้ว: `{out_path.name}` ({size/1024/1024:.2f} MB)\n"
                    f"⚠️ เกินลิมิตแนบไฟล์ — ตั้งค่า S3 เพื่ออัปอัตโนมัติ",
                    mention_author=False
                )
    except NotAllowed as e:
        await link_msg.reply(f"❌ {e}", mention_author=False)
    except FetchError as e:
        await link_msg.reply(f"❌ FetchError: {e}", mention_author=False)
    except Exception as e:
        await link_msg.reply(f"❌ Error: {type(e).__name__}: {e}", mention_author=False)

# ---------- Commands (optional) ----------
@bot.command(name="fetch", aliases=["grab"])
@require_allowed_channel()
async def fetch_cmd(ctx: commands.Context, url: Optional[str] = None):
    """
    ใช้ได้ 2 แบบ:
      1) !fetch <url>
      2) Reply ไปที่ข้อความที่มีลิงก์ แล้วพิมพ์ !fetch
    (แต่อัตโนมัติจาก on_message ก็มีอยู่แล้ว)
    """
    link_msg: discord.Message = ctx.message
    if ctx.message.reference and ctx.message.reference.resolved:
        link_msg = ctx.message.reference.resolved  # type: ignore

    target_text = (url or "").strip() or link_msg.content
    m = URL_RE.search(target_text or "")
    if not m:
        await ctx.reply("โปรดใส่ลิงก์ หรือ reply ไปที่ข้อความที่มีลิงก์ก่อน", mention_author=False)
        return

    link_url = m.group(0)
    host = hostof(link_url)
    if any(b in host for b in BLOCKED_HOSTS):
        await link_msg.reply("🚫 โดเมนนี้ไม่รองรับ (เสี่ยง TOS/DRM)", mention_author=False)
        return

    await do_download_flow(ctx, link_msg, link_url)

# ---------- Attachment flow: drop .mp4 -> ask audio ext -> convert ----------
class _DummyCtx:
    def __init__(self, user_id: int):
        self.author = type("U",(object,),{"id": user_id})()

async def handle_mp4_attachment_message(message: discord.Message):
    # allowlist
    if ALLOWED_CHANNEL_IDS and (message.channel.id not in ALLOWED_CHANNEL_IDS):
        return
    if message.author.bot:
        return

    # หาไฟล์แนบ .mp4 ตัวแรก
    target_att: Optional[discord.Attachment] = None
    for att in message.attachments:
        filename = (att.filename or "").lower()
        ctype = (att.content_type or "").lower()
        if filename.endswith(".mp4") or ctype.startswith("video/mp4"):
            target_att = att
            break
    if not target_att:
        return

    # ถามนามสกุลเสียง
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

    # ลบกล่องตัวเลือก
    try: await ask_msg.delete()
    except: pass

    # ดาวน์โหลด & แปลง
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

# ---------- Link flow: detect link in any message ----------
def extract_first_url(text: str) -> Optional[str]:
    m = URL_RE.search(text or "")
    return m.group(0) if m else None

async def handle_link_message(message: discord.Message):
    # allowlist
    if ALLOWED_CHANNEL_IDS and (message.channel.id not in ALLOWED_CHANNEL_IDS):
        return
    if message.author.bot:
        return

    url = extract_first_url(message.content or "")
    if not url:
        return

    host = hostof(url)
    if any(b in host for b in BLOCKED_HOSTS):
        await message.reply("🚫 โดเมนนี้ไม่รองรับ (เสี่ยง TOS/DRM)", mention_author=False)
        return

    # run flow (ใช้ dummy ctx ที่มี author.id)
    await do_download_flow(_DummyCtx(message.author.id), message, url)

# ---------- Global message hook ----------
@bot.event
async def on_message(message: discord.Message):
    try:
        await handle_mp4_attachment_message(message)  # โยนไฟล์ .mp4 → ถามนามสกุลเสียง
        await handle_link_message(message)            # แปะลิงก์ → เปิด flow อัตโนมัติ / บอกเหตุผลถ้าบล็อก
    finally:
        await bot.process_commands(message)

# ---------- Boot ----------
if __name__ == "__main__":
    if not DISCORD_TOKEN:
        raise SystemExit("กรุณาตั้งค่า DISCORD_TOKEN ใน Environment")
    bot.run(DISCORD_TOKEN)
