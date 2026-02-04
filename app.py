"""
Flask LSB Image Steganography – Hide/extract TEXT, AUDIO, IMAGE, VIDEO, DOCUMENT in PNG.
Payload format: STEGO|<ENC_FLAG>|<FILE_TYPE>|<FILE_SIZE>|<DATA>
Encryption (AES-256-CBC) only inside build_payload(); decode requires password when ENC_FLAG==ENC.

Adaptive Image Capacity Enhancement Module:
- If payload exceeds image capacity, the image is automatically upscaled (aspect ratio preserved,
  LANCZOS resampling) until capacity is sufficient, so large audio/video/documents can be encoded
  without manual image resizing. Decode is unchanged and works regardless of image dimensions.
"""
import base64
import json
from io import BytesIO

from flask import Flask, redirect, render_template, request, send_file
from PIL import Image
from PIL import UnidentifiedImageError
from werkzeug.exceptions import RequestEntityTooLarge

from crypto_utils import STEGO_PREFIX, build_payload, decrypt_body

app = Flask(__name__)
# Allow decoding large auto-upscaled stego images (and large payload encodes).
# Must be set immediately after Flask app initialization.
app.config["MAX_CONTENT_LENGTH"] = 200 * 1024 * 1024  # 200 MB

# Cover/stego images accepted (decoded by Pillow). GIF uses first frame only.
ALLOWED_IMAGE_FORMATS = {"PNG", "JPEG", "BMP", "TIFF", "WEBP", "GIF"}

# File type (lowercase) -> (mimetype, download_extension)
FILE_TYPE_INFO = {
    "txt": ("text/plain", "txt"),
    "wav": ("audio/wav", "wav"),
    "mp3": ("audio/mpeg", "mp3"),
    "pdf": ("application/pdf", "pdf"),
    "doc": ("application/msword", "doc"),
    "docx": ("application/vnd.openxmlformats-officedocument.wordprocessingml.document", "docx"),
    "png": ("image/png", "png"),
    "jpg": ("image/jpeg", "jpg"),
    "jpeg": ("image/jpeg", "jpg"),
    "gif": ("image/gif", "gif"),
    "webp": ("image/webp", "webp"),
    "bmp": ("image/bmp", "bmp"),
    "mp4": ("video/mp4", "mp4"),
    "webm": ("video/webm", "webm"),
    "avi": ("video/x-msvideo", "avi"),
    "mov": ("video/quicktime", "mov"),
    "bin": ("application/octet-stream", "bin"),
}

@app.errorhandler(RequestEntityTooLarge)
def handle_request_entity_too_large(_e):
    """
    User-friendly handler for oversized uploads (HTTP 413).
    Keeps server running and shows the error in the appropriate UI page.
    """
    msg = (
        "Uploaded file is too large. Please upload a smaller PNG stego image, "
        "or increase the server upload limit."
    )
    # Decode is the common failure case after auto-upscaling; render decode UI there.
    if request.path.startswith("/decode"):
        return render_template("decode.html", error=msg), 413
    return render_template("encode.html", error=msg), 413


def normalize_to_png_rgb(image_bytes: bytes) -> tuple[bytes, dict]:
    """
    Normalize any Pillow-supported image to lossless PNG bytes in RGB.
    Also returns metadata (original_format/mode/size) for reference only.
    """
    img = Image.open(BytesIO(image_bytes))
    original_format = (img.format or "UNKNOWN").upper()
    if original_format not in ALLOWED_IMAGE_FORMATS:
        raise ValueError("Unsupported image format")
    # GIF (first frame only)
    try:
        if getattr(img, "is_animated", False):
            img.seek(0)
    except Exception:
        pass
    original_mode = img.mode
    original_size = img.size
    img = img.convert("RGB")
    out = BytesIO()
    img.save(out, format="PNG")
    return out.getvalue(), {
        "original_format": original_format,
        "original_mode": original_mode,
        "original_size": original_size,
    }


def image_capacity_from_dimensions(width: int, height: int) -> int:
    """
    Image capacity in bytes: (width × height × 3) / 8 minus 32 bits for length prefix.
    LSB stores 1 bit per R,G,B channel per pixel.
    """
    return max(0, (width * height * 3 - 32) // 8)


def body_capacity_bytes(image_bytes: bytes) -> int:
    """Max payload size in bytes that can be embedded (32-bit length prefix + payload)."""
    img = Image.open(BytesIO(image_bytes)).convert("RGB")
    w, h = img.size
    return image_capacity_from_dimensions(w, h)


# --- Adaptive Image Capacity Enhancement Module ---
# Max upscale attempts to avoid infinite loop; each step doubles width and height.
MAX_UPSCALE_ATTEMPTS = 10
UPSCALE_FACTOR = 2

# Optional payload compression (conceptual; not implemented here):
# - Audio: WAV is uncompressed; converting to lower-bitrate MP3 before embedding would reduce
#   payload size and thus required image capacity, at the cost of quality and extra dependency.
# - Video: Reducing bitrate or resolution before embedding would similarly reduce payload size.
# - Implementation would require optional pre-processing (e.g. ffmpeg) and format conversion;
#   decode would return the compressed form. Current design keeps original bytes and relies
#   on image upscaling when capacity is insufficient.


def upscale_image_to_capacity(image_bytes: bytes, min_capacity_bytes: int) -> bytes:
    """
    Automatically upscale the image (maintaining aspect ratio, LANCZOS resampling)
    until capacity >= min_capacity_bytes. Used when payload is larger than current
    image capacity so encoding can succeed without user intervention.

    Loop: double width and height each time until capacity is sufficient or
    MAX_UPSCALE_ATTEMPTS is reached. Raises ValueError if still insufficient.

    Image upscaling does NOT affect encryption or payload content; decode returns
    exact original data regardless of carrier image dimensions.
    """
    img = Image.open(BytesIO(image_bytes)).convert("RGB")
    w, h = img.size
    for _ in range(MAX_UPSCALE_ATTEMPTS):
        capacity = image_capacity_from_dimensions(w, h)
        if capacity >= min_capacity_bytes:
            break
        w, h = w * UPSCALE_FACTOR, h * UPSCALE_FACTOR
    if image_capacity_from_dimensions(w, h) < min_capacity_bytes:
        raise ValueError(
            f"Payload too large: image could not be upscaled enough within {MAX_UPSCALE_ATTEMPTS} attempts. "
            "Use a larger source image or a smaller file."
        )
    if (w, h) != img.size:
        img = img.resize((w, h), Image.Resampling.LANCZOS)
    out = BytesIO()
    img.save(out, format="PNG")
    return out.getvalue()


def embed_lsb(image_bytes: bytes, payload: bytes) -> bytes:
    """
    Embed payload in PNG LSB of R, G, B. Payload is already complete (from build_payload).
    Prepend 32-bit big-endian length. Row-major, R then G then B per pixel.
    """
    img = Image.open(BytesIO(image_bytes)).convert("RGB")
    pixels = img.load()
    w, h = img.size
    capacity_bits = w * h * 3
    needed_bits = 32 + len(payload) * 8
    if capacity_bits < needed_bits:
        raise ValueError("Image too small for payload")

    length_bits = [(len(payload) >> (31 - i)) & 1 for i in range(32)]
    payload_bits = []
    for b in payload:
        for i in range(8):
            payload_bits.append((b >> (7 - i)) & 1)
    bits = length_bits + payload_bits
    idx = 0

    for y in range(h):
        for x in range(w):
            r, g, b = pixels[x, y]
            if idx < len(bits):
                r = (r & 0xFE) | bits[idx]
                idx += 1
            if idx < len(bits):
                g = (g & 0xFE) | bits[idx]
                idx += 1
            if idx < len(bits):
                b = (b & 0xFE) | bits[idx]
                idx += 1
            pixels[x, y] = (r, g, b)
            if idx >= len(bits):
                break
        if idx >= len(bits):
            break

    out = BytesIO()
    img.save(out, format="PNG")
    return out.getvalue()


def extract_lsb(image_bytes: bytes) -> bytes:
    """Extract raw payload bytes from PNG LSBs (full payload including STEGO|...|DATA)."""
    img = Image.open(BytesIO(image_bytes)).convert("RGB")
    pixels = img.load()
    w, h = img.size
    total_bits = w * h * 3
    if total_bits < 32:
        raise ValueError("Image too small to contain a valid message")

    bits = []
    for y in range(h):
        for x in range(w):
            r, g, b = pixels[x, y]
            bits.append(r & 1)
            bits.append(g & 1)
            bits.append(b & 1)
            if len(bits) >= total_bits:
                break
        if len(bits) >= total_bits:
            break

    length = 0
    for i in range(32):
        length = (length << 1) | bits[i]
    payload_bits_count = length * 8
    if length <= 0 or 32 + payload_bits_count > total_bits:
        raise ValueError("Invalid stego image")

    payload_bits = bits[32 : 32 + payload_bits_count]
    payload_bytes = bytearray()
    for i in range(0, len(payload_bits), 8):
        byte = 0
        for j in range(8):
            if i + j < len(payload_bits):
                byte = (byte << 1) | payload_bits[i + j]
        payload_bytes.append(byte)
    return bytes(payload_bytes)


def parse_payload(raw: bytes):
    """
    Parse payload: STEGO|<ENC_FLAG>|<FILE_TYPE>|<FILE_SIZE>|<DATA>
    Returns (enc_flag, file_type, file_size, data_bytes).
    """
    if len(raw) < len(STEGO_PREFIX) or raw[: len(STEGO_PREFIX)] != STEGO_PREFIX:
        raise ValueError("Invalid stego image")
    rest = raw[len(STEGO_PREFIX) :]
    parts = rest.split(b"|", 3)
    if len(parts) != 4:
        raise ValueError("Invalid stego payload format")
    enc_flag = parts[0].decode("ascii").upper()
    file_type = parts[1].decode("ascii").strip().lower() or "bin"
    try:
        file_size = int(parts[2].decode("ascii"))
    except ValueError:
        raise ValueError("Invalid stego payload format")
    data = parts[3]
    if enc_flag not in ("ENC", "NOENC"):
        raise ValueError("Invalid stego payload format")
    return enc_flag, file_type, file_size, data


def file_type_from_filename(filename: str) -> str:
    """Return canonical file type (e.g. txt, wav, pdf) from filename."""
    if not filename or "." not in filename:
        return "bin"
    return filename.lower().rsplit(".", 1)[-1].strip()


@app.route("/")
def index():
    return redirect("/encode")


@app.route("/encode", methods=["GET", "POST"])
def encode():
    # Strict UI rule: this handler renders the template exactly once, at the end.
    # Internal processing steps (encryption, capacity checks, etc.) are never exposed to the UI.
    error = None
    status = None

    if request.method == "POST":
        # 1) Load cover image
        f = request.files.get("image")
        if not f or not getattr(f, "filename", ""):
            error = "No image selected."

        # 2) Read payload (file takes precedence over text)
        message = request.form.get("message", "").strip()
        secret_file = request.files.get("file")
        password = request.form.get("key", "").strip() or None

        data = None
        file_type = None
        if error is None:
            if secret_file and secret_file.filename:
                try:
                    data = secret_file.read()
                except Exception as e:
                    error = f"Could not read file: {e}"
                else:
                    if not data:
                        error = "Selected file is empty."
                    else:
                        file_type = file_type_from_filename(secret_file.filename)
                        # PDF payloads are Base64-wrapped before optional encryption,
                        # so they can be safely reconstructed during decode.
                        if file_type == "pdf":
                            data = base64.b64encode(data)
            elif message:
                data = message.encode("utf-8")
                file_type = "txt"
            else:
                error = "Provide a secret message or upload a file (text, audio, image, video, document)."

        image_bytes = None
        original_size = None
        final_size = None
        was_upscaled = False
        payload_size = None
        encoded_image_data_url = None

        if error is None:
            try:
                raw_cover_bytes = f.read()
                # Normalize to PNG for internal processing (lossless), always RGB.
                image_bytes, meta = normalize_to_png_rgb(raw_cover_bytes)
                original_size = meta["original_size"]  # (w, h) from original upload
            except Exception as e:
                if isinstance(e, UnidentifiedImageError):
                    error = "Unsupported or corrupted image. Please upload a valid image file."
                elif str(e) == "Unsupported image format":
                    error = "Unsupported image format. Please upload PNG, JPG/JPEG, BMP, TIFF, WEBP, or GIF."
                else:
                    error = f"Could not read image: {e}"

        if error is None:
            # 3) Encrypt payload if password is provided (internal-only; log for debugging)
            if password:
                app.logger.info("Encoding with encryption enabled (AES-256-CBC).")

            # 4) Calculate payload size AFTER encryption (build_payload applies encryption internally)
            payload = build_payload(data, file_type, password)
            payload_size = len(payload)

            # 5) Calculate image capacity
            capacity = body_capacity_bytes(image_bytes)

            # 6) Auto-upscale image if capacity is insufficient
            if payload_size > capacity:
                try:
                    image_bytes = upscale_image_to_capacity(image_bytes, payload_size)
                    was_upscaled = True
                except ValueError as e:
                    error = str(e)

        if error is None:
            try:
                # Track final image dimensions (after any upscaling)
                final_img = Image.open(BytesIO(image_bytes)).convert("RGB")
                final_size = final_img.size

                # 7) Embed payload using LSB
                out_bytes = embed_lsb(image_bytes, payload)

                # 8) Save encoded image (provided to UI as a download data URL)
                encoded_image_b64 = base64.b64encode(out_bytes).decode("utf-8")
                encoded_image_data_url = f"data:image/png;base64,{encoded_image_b64}"
            except Exception as e:
                error = f"Encode failed: {e}"

        # 9) Prepare FINAL status object (UI-safe, final-only)
        if error is None:
            status = {
                "original_image_size": f"{original_size[0]}×{original_size[1]}",
                "payload_size": f"{payload_size:,}",
                "was_upscaled": was_upscaled,
                "final_image_size": f"{final_size[0]}×{final_size[1]}",
                "encode_success": True,
                "encoded_image_data_url": encoded_image_data_url,
            }

    # Single render_template() call (must be at the end of this function).
    return render_template("encode.html", error=error, status=status)


@app.route("/decode", methods=["GET", "POST"])
def decode():
    if request.method == "GET":
        return render_template("decode.html")
    if "image" not in request.files:
        return render_template("decode.html", error="No image selected.")
    f = request.files["image"]
    if not f or f.filename == "":
        return render_template("decode.html", error="No image selected.")

    password = request.form.get("key", "").strip() or None
    try:
        # Accept any common image format; decode works only if LSB survived.
        image_bytes = f.read()
        # Validate it is a supported/correct image early for clean error handling.
        normalize_to_png_rgb(image_bytes)  # discard result; extraction reads original bytes
        raw = extract_lsb(image_bytes)
        enc_flag, file_type, file_size, data = parse_payload(raw)

        # Security: decoding works regardless of carrier image size (including auto-upscaled).
        # ENC payloads strictly require password; wrong password raises below.
        if enc_flag == "ENC":
            if not password:
                return render_template(
                    "decode.html",
                    error="Password required to decode encrypted data",
                )
            try:
                data = decrypt_body(password, data)
            except Exception:
                return render_template(
                    "decode.html",
                    error="Invalid password or corrupted data",
                )

        # Serve by file type
        if file_type == "txt":
            try:
                text = data.decode("utf-8")
            except UnicodeDecodeError:
                text = data.decode("utf-8", errors="replace")
            return render_template("decode.html", text=text, extracted_type="txt")

        # PDF payloads are stored as Base64 bytes (possibly encrypted). Reconstruct here.
        # Backward compatible: if payload isn't valid Base64, treat as raw bytes.
        if file_type == "pdf":
            try:
                data = base64.b64decode(data, validate=True)
            except Exception:
                # Old stego images (or non-Base64 payloads) still download as-is.
                pass

        mimetype, ext = FILE_TYPE_INFO.get(
            file_type, ("application/octet-stream", file_type or "bin")
        )
        download_name = f"extracted.{ext}"
        return send_file(
            BytesIO(data),
            mimetype=mimetype,
            as_attachment=True,
            download_name=download_name,
        )
    except ValueError as e:
        return render_template("decode.html", error=str(e))
    except Exception as e:
        if isinstance(e, UnidentifiedImageError):
            return render_template(
                "decode.html",
                error="Unsupported or corrupted image. Please upload a valid image file.",
            )
        return render_template("decode.html", error=f"Decode failed: {e}")


@app.route("/encode/capacity", methods=["POST"])
def encode_capacity():
    """Return JSON { capacity_bytes } for the uploaded PNG image."""
    if "image" not in request.files:
        return json.dumps({"error": "No image"}), 400, {"Content-Type": "application/json"}
    f = request.files["image"]
    if not f or not f.filename:
        return json.dumps({"error": "Invalid or missing image"}), 400, {"Content-Type": "application/json"}
    try:
        raw_bytes = f.read()
        png_bytes, _meta = normalize_to_png_rgb(raw_bytes)
        capacity = body_capacity_bytes(png_bytes)
        return json.dumps({"capacity_bytes": capacity}), 200, {"Content-Type": "application/json"}
    except Exception as e:
        if isinstance(e, UnidentifiedImageError) or str(e) == "Unsupported image format":
            return (
                json.dumps({"error": "Unsupported or corrupted image"}),
                400,
                {"Content-Type": "application/json"},
            )
        return json.dumps({"error": "Could not read image"}), 400, {"Content-Type": "application/json"}


if __name__ == "__main__":
    app.run(debug=True)
