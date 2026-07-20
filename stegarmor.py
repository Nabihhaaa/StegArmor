#!/usr/bin/env python3
"""
StegArmor - Encrypted Steganography Tool
==========================================

A cross-platform (Windows / Linux) command-line tool that combines
AES-256-GCM encryption with LSB (Least Significant Bit) image
steganography to hide encrypted text messages inside PNG images.

Author:  [YOUR NAME HERE]
License: MIT
Repository: [INSERT GITHUB REPOSITORY LINK HERE]

Usage:
    python stegarmor.py embed   -i cover.png -o stego.png -m "secret text" -p "MyPassword"
    python stegarmor.py embed   -i cover.png -o stego.png -f secret.txt   -p "MyPassword"
    python stegarmor.py extract -i stego.png -p "MyPassword"
    python stegarmor.py extract -i stego.png -p "MyPassword" -o recovered.txt
    python stegarmor.py capacity -i cover.png
"""

import argparse
import os
import sys
import struct

from PIL import Image
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

# ----------------------------------------------------------------------
# Constants
# ----------------------------------------------------------------------
SALT_SIZE = 16          # bytes, for PBKDF2
NONCE_SIZE = 12          # bytes, recommended size for AES-GCM
KEY_SIZE = 32          # bytes -> AES-256
PBKDF2_ITERATIONS = 390_000     # OWASP-recommended minimum ballpark (2024+)
LENGTH_HEADER_BITS = 32          # 32-bit big-endian length prefix, in bits
MAGIC = b"SA1"      # 3-byte format marker ("StegArmor v1")


# ----------------------------------------------------------------------
# Custom Exceptions
# ----------------------------------------------------------------------
class StegArmorError(Exception):
    """Base exception for all StegArmor-specific errors."""


class InsufficientCapacityError(StegArmorError):
    """Raised when the cover image cannot hold the payload."""


class InvalidPasswordError(StegArmorError):
    """Raised when decryption fails, most likely due to a wrong password."""


class NoHiddenDataError(StegArmorError):
    """Raised when the image does not appear to contain StegArmor data."""


# ----------------------------------------------------------------------
# Cryptography Layer
# ----------------------------------------------------------------------
def derive_key(password: str, salt: bytes) -> bytes:
    """
    Derive a 256-bit AES key from a user password using PBKDF2-HMAC-SHA256.

    The salt ensures that the same password never produces the same key
    twice, protecting against rainbow-table / precomputation attacks.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_message(plaintext: bytes, password: str) -> bytes:
    """
    Encrypt plaintext with AES-256-GCM.

    Output layout (all binary, concatenated):
        MAGIC (3 bytes) | SALT (16 bytes) | NONCE (12 bytes) | CIPHERTEXT+TAG
    """
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    key = derive_key(password, salt)

    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=MAGIC)

    return MAGIC + salt + nonce + ciphertext


def decrypt_message(blob: bytes, password: str) -> bytes:
    """
    Reverse of encrypt_message(). Raises InvalidPasswordError if the
    password is wrong or the data has been tampered with (GCM auth tag
    verification failure).
    """
    if len(blob) < len(MAGIC) + SALT_SIZE + NONCE_SIZE:
        raise NoHiddenDataError("Extracted data is too short to be valid StegArmor content.")

    magic = blob[:len(MAGIC)]
    if magic != MAGIC:
        raise NoHiddenDataError(
            "No valid StegArmor payload found in this image (magic header mismatch)."
        )

    offset = len(MAGIC)
    salt = blob[offset:offset + SALT_SIZE]
    offset += SALT_SIZE
    nonce = blob[offset:offset + NONCE_SIZE]
    offset += NONCE_SIZE
    ciphertext = blob[offset:]

    key = derive_key(password, salt)
    aesgcm = AESGCM(key)

    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data=MAGIC)
    except InvalidTag:
        raise InvalidPasswordError(
            "Decryption failed. The password is incorrect, or the stego "
            "image has been modified/corrupted since embedding."
        )
    return plaintext


# ----------------------------------------------------------------------
# Steganography Layer (LSB embedding in PNG)
# ----------------------------------------------------------------------
def _bytes_to_bits(data: bytes):
    """Yield each bit (MSB first) of every byte in `data`."""
    for byte in data:
        for i in range(7, -1, -1):
            yield (byte >> i) & 1


def _bits_to_bytes(bits) -> bytes:
    """Pack an iterable of bits (MSB first) into bytes."""
    out = bytearray()
    bit_buffer = 0
    bit_count = 0
    for bit in bits:
        bit_buffer = (bit_buffer << 1) | bit
        bit_count += 1
        if bit_count == 8:
            out.append(bit_buffer)
            bit_buffer = 0
            bit_count = 0
    return bytes(out)


def get_image_capacity_bytes(image: Image.Image) -> int:
    """
    Return the maximum number of payload bytes that can be hidden in
    the given image, after reserving space for the 32-bit length header.
    Uses 1 LSB per color channel (R, G, B) -- alpha is left untouched.
    """
    width, height = image.size
    channels = 3  # R, G, B (skip alpha to preserve transparency data)
    total_bits = width * height * channels
    usable_bits = total_bits - LENGTH_HEADER_BITS
    return max(usable_bits // 8, 0)


def embed_data_in_image(image: Image.Image, payload: bytes) -> Image.Image:
    """
    Hide `payload` inside the LSBs of `image` and return a new Image object.
    A 32-bit big-endian length header is embedded first so the extractor
    knows exactly how many payload bits follow.
    """
    capacity = get_image_capacity_bytes(image)
    if len(payload) > capacity:
        raise InsufficientCapacityError(
            f"Payload is {len(payload)} bytes but this image can only hold "
            f"{capacity} bytes. Use a larger image or a shorter message."
        )

    image = image.convert("RGB")
    width, height = image.size
    pixels = list(image.getdata())  # NOTE: Pillow may rename getdata() in future releases;
    # re-check the Pillow changelog if you upgrade past Pillow 14.

    header = struct.pack(">I", len(payload))  # 4 bytes, big-endian length
    bitstream = list(_bytes_to_bits(header)) + list(_bytes_to_bits(payload))

    new_pixels = []
    bit_index = 0
    total_bits = len(bitstream)

    for pixel in pixels:
        r, g, b = pixel
        channels = [r, g, b]
        for c in range(3):
            if bit_index < total_bits:
                channels[c] = (channels[c] & 0xFE) | bitstream[bit_index]
                bit_index += 1
        new_pixels.append(tuple(channels))
        if bit_index >= total_bits:
            # Remaining pixels are appended unchanged below
            new_pixels.extend(pixels[len(new_pixels):])
            break

    stego_image = Image.new("RGB", (width, height))
    stego_image.putdata(new_pixels)
    return stego_image


def extract_data_from_image(image: Image.Image) -> bytes:
    """
    Extract the hidden payload from a stego image produced by
    embed_data_in_image(). Reads the 32-bit length header first, then
    exactly that many bytes of payload.
    """
    image = image.convert("RGB")
    pixels = image.getdata()

    def channel_bit_generator():
        for pixel in pixels:
            for channel_value in pixel:  # r, g, b
                yield channel_value & 1

    bit_gen = channel_bit_generator()

    header_bits = []
    try:
        for _ in range(LENGTH_HEADER_BITS):
            header_bits.append(next(bit_gen))
    except StopIteration:
        raise NoHiddenDataError("Image is too small to contain a valid StegArmor header.")

    header_bytes = _bits_to_bytes(header_bits)
    payload_length = struct.unpack(">I", header_bytes)[0]

    max_possible = get_image_capacity_bytes(image)
    if payload_length == 0 or payload_length > max_possible:
        raise NoHiddenDataError(
            "No valid StegArmor payload detected (length header out of range). "
            "This image may not contain hidden data."
        )

    payload_bits = []
    try:
        for _ in range(payload_length * 8):
            payload_bits.append(next(bit_gen))
    except StopIteration:
        raise NoHiddenDataError("Image data ended before the declared payload length. "
                                 "The image may be corrupted or truncated.")

    return _bits_to_bytes(payload_bits)


# ----------------------------------------------------------------------
# High-level operations (used by the CLI)
# ----------------------------------------------------------------------
def do_embed(image_path: str, output_path: str, message_bytes: bytes, password: str) -> None:
    if not os.path.isfile(image_path):
        raise FileNotFoundError(f"Cover image not found: '{image_path}'")

    try:
        image = Image.open(image_path)
    except Exception as exc:
        raise StegArmorError(f"Could not open '{image_path}' as an image: {exc}")

    encrypted_blob = encrypt_message(message_bytes, password)
    stego_image = embed_data_in_image(image, encrypted_blob)

    if not output_path.lower().endswith(".png"):
        output_path += ".png"

    stego_image.save(output_path, format="PNG")  # PNG is lossless -- mandatory
    print(f"[+] Message encrypted (AES-256-GCM) and embedded successfully.")
    print(f"[+] Stego image written to: {output_path}")


def do_extract(image_path: str, password: str, output_path: str = None) -> str:
    if not os.path.isfile(image_path):
        raise FileNotFoundError(f"Stego image not found: '{image_path}'")

    try:
        image = Image.open(image_path)
    except Exception as exc:
        raise StegArmorError(f"Could not open '{image_path}' as an image: {exc}")

    encrypted_blob = extract_data_from_image(image)
    plaintext = decrypt_message(encrypted_blob, password)

    try:
        decoded = plaintext.decode("utf-8")
    except UnicodeDecodeError:
        decoded = None

    if output_path:
        mode = "wb" if decoded is None else "w"
        with open(output_path, mode) as f:
            f.write(plaintext if decoded is None else decoded)
        print(f"[+] Message decrypted and saved to: {output_path}")
    else:
        print("[+] Decrypted message:")
        print("-" * 50)
        print(decoded if decoded is not None else plaintext)
        print("-" * 50)

    return decoded if decoded is not None else plaintext


def do_capacity(image_path: str) -> None:
    if not os.path.isfile(image_path):
        raise FileNotFoundError(f"Image not found: '{image_path}'")
    image = Image.open(image_path)
    capacity = get_image_capacity_bytes(image)
    print(f"[i] Image: {image_path}  ({image.size[0]}x{image.size[1]} px)")
    print(f"[i] Maximum payload capacity: {capacity} bytes "
          f"(~{capacity // 1024} KB) before AES/format overhead.")
    print(f"[i] Note: StegArmor overhead per message is "
          f"{len(MAGIC) + SALT_SIZE + NONCE_SIZE + 16} bytes "
          f"(magic + salt + nonce + GCM tag).")


# ----------------------------------------------------------------------
# Command-Line Interface
# ----------------------------------------------------------------------
def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="stegarmor",
        description="StegArmor - Hide AES-256 encrypted messages inside PNG images.",
        epilog="Examples:\n"
               '  stegarmor embed -i cover.png -o stego.png -m "top secret" -p "hunter2"\n'
               "  stegarmor extract -i stego.png -p \"hunter2\"\n"
               "  stegarmor capacity -i cover.png\n",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # embed
    embed_p = subparsers.add_parser("embed", help="Encrypt a message and hide it in an image.")
    embed_p.add_argument("-i", "--image", required=True, help="Path to the cover PNG image.")
    embed_p.add_argument("-o", "--output", required=True, help="Path to save the output stego PNG.")
    group = embed_p.add_mutually_exclusive_group(required=True)
    group.add_argument("-m", "--message", help="Message text to hide.")
    group.add_argument("-f", "--file", help="Path to a text file whose contents will be hidden.")
    embed_p.add_argument("-p", "--password", required=True, help="Password used to derive the AES-256 key.")

    # extract
    extract_p = subparsers.add_parser("extract", help="Extract and decrypt a hidden message from an image.")
    extract_p.add_argument("-i", "--image", required=True, help="Path to the stego PNG image.")
    extract_p.add_argument("-p", "--password", required=True, help="Password used during embedding.")
    extract_p.add_argument("-o", "--output", help="Optional path to save the recovered message to a file.")

    # capacity
    capacity_p = subparsers.add_parser("capacity", help="Show how many bytes an image can hide.")
    capacity_p.add_argument("-i", "--image", required=True, help="Path to the image to analyze.")

    return parser


def main(argv=None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "embed":
            if args.file:
                if not os.path.isfile(args.file):
                    raise FileNotFoundError(f"Message file not found: '{args.file}'")
                with open(args.file, "rb") as f:
                    message_bytes = f.read()
            else:
                message_bytes = args.message.encode("utf-8")

            do_embed(args.image, args.output, message_bytes, args.password)

        elif args.command == "extract":
            do_extract(args.image, args.password, args.output)

        elif args.command == "capacity":
            do_capacity(args.image)

        return 0

    except FileNotFoundError as e:
        print(f"[!] File error: {e}", file=sys.stderr)
        return 2
    except InsufficientCapacityError as e:
        print(f"[!] Capacity error: {e}", file=sys.stderr)
        return 3
    except InvalidPasswordError as e:
        print(f"[!] Authentication error: {e}", file=sys.stderr)
        return 4
    except NoHiddenDataError as e:
        print(f"[!] Extraction error: {e}", file=sys.stderr)
        return 5
    except StegArmorError as e:
        print(f"[!] StegArmor error: {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\n[!] Operation cancelled by user.", file=sys.stderr)
        return 130
    except Exception as e:  # noqa: BLE001 - top-level safety net for a CLI tool
        print(f"[!] Unexpected error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
#!/usr/bin/env python3
"""
StegArmor - Encrypted Steganography Tool
==========================================

A cross-platform (Windows / Linux) command-line tool that combines
AES-256-GCM encryption with LSB (Least Significant Bit) image
steganography to hide encrypted text messages inside PNG images.

Author:  [YOUR NAME HERE]
License: MIT
Repository: [INSERT GITHUB REPOSITORY LINK HERE]

Usage:
    python stegarmor.py embed   -i cover.png -o stego.png -m "secret text" -p "MyPassword"
    python stegarmor.py embed   -i cover.png -o stego.png -f secret.txt   -p "MyPassword"
    python stegarmor.py extract -i stego.png -p "MyPassword"
    python stegarmor.py extract -i stego.png -p "MyPassword" -o recovered.txt
    python stegarmor.py capacity -i cover.png
"""

import argparse
import os
import sys
import struct

from PIL import Image
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

# ----------------------------------------------------------------------
# Constants
# ----------------------------------------------------------------------
SALT_SIZE = 16          # bytes, for PBKDF2
NONCE_SIZE = 12          # bytes, recommended size for AES-GCM
KEY_SIZE = 32          # bytes -> AES-256
PBKDF2_ITERATIONS = 390_000     # OWASP-recommended minimum ballpark (2024+)
LENGTH_HEADER_BITS = 32          # 32-bit big-endian length prefix, in bits
MAGIC = b"SA1"      # 3-byte format marker ("StegArmor v1")


# ----------------------------------------------------------------------
# Custom Exceptions
# ----------------------------------------------------------------------
class StegArmorError(Exception):
    """Base exception for all StegArmor-specific errors."""


class InsufficientCapacityError(StegArmorError):
    """Raised when the cover image cannot hold the payload."""


class InvalidPasswordError(StegArmorError):
    """Raised when decryption fails, most likely due to a wrong password."""


class NoHiddenDataError(StegArmorError):
    """Raised when the image does not appear to contain StegArmor data."""


# ----------------------------------------------------------------------
# Cryptography Layer
# ----------------------------------------------------------------------
def derive_key(password: str, salt: bytes) -> bytes:
    """
    Derive a 256-bit AES key from a user password using PBKDF2-HMAC-SHA256.

    The salt ensures that the same password never produces the same key
    twice, protecting against rainbow-table / precomputation attacks.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_message(plaintext: bytes, password: str) -> bytes:
    """
    Encrypt plaintext with AES-256-GCM.

    Output layout (all binary, concatenated):
        MAGIC (3 bytes) | SALT (16 bytes) | NONCE (12 bytes) | CIPHERTEXT+TAG
    """
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    key = derive_key(password, salt)

    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=MAGIC)

    return MAGIC + salt + nonce + ciphertext


def decrypt_message(blob: bytes, password: str) -> bytes:
    """
    Reverse of encrypt_message(). Raises InvalidPasswordError if the
    password is wrong or the data has been tampered with (GCM auth tag
    verification failure).
    """
    if len(blob) < len(MAGIC) + SALT_SIZE + NONCE_SIZE:
        raise NoHiddenDataError("Extracted data is too short to be valid StegArmor content.")

    magic = blob[:len(MAGIC)]
    if magic != MAGIC:
        raise NoHiddenDataError(
            "No valid StegArmor payload found in this image (magic header mismatch)."
        )

    offset = len(MAGIC)
    salt = blob[offset:offset + SALT_SIZE]
    offset += SALT_SIZE
    nonce = blob[offset:offset + NONCE_SIZE]
    offset += NONCE_SIZE
    ciphertext = blob[offset:]

    key = derive_key(password, salt)
    aesgcm = AESGCM(key)

    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data=MAGIC)
    except InvalidTag:
        raise InvalidPasswordError(
            "Decryption failed. The password is incorrect, or the stego "
            "image has been modified/corrupted since embedding."
        )
    return plaintext


# ----------------------------------------------------------------------
# Steganography Layer (LSB embedding in PNG)
# ----------------------------------------------------------------------
def _bytes_to_bits(data: bytes):
    """Yield each bit (MSB first) of every byte in `data`."""
    for byte in data:
        for i in range(7, -1, -1):
            yield (byte >> i) & 1


def _bits_to_bytes(bits) -> bytes:
    """Pack an iterable of bits (MSB first) into bytes."""
    out = bytearray()
    bit_buffer = 0
    bit_count = 0
    for bit in bits:
        bit_buffer = (bit_buffer << 1) | bit
        bit_count += 1
        if bit_count == 8:
            out.append(bit_buffer)
            bit_buffer = 0
            bit_count = 0
    return bytes(out)


def get_image_capacity_bytes(image: Image.Image) -> int:
    """
    Return the maximum number of payload bytes that can be hidden in
    the given image, after reserving space for the 32-bit length header.
    Uses 1 LSB per color channel (R, G, B) -- alpha is left untouched.
    """
    width, height = image.size
    channels = 3  # R, G, B (skip alpha to preserve transparency data)
    total_bits = width * height * channels
    usable_bits = total_bits - LENGTH_HEADER_BITS
    return max(usable_bits // 8, 0)


def embed_data_in_image(image: Image.Image, payload: bytes) -> Image.Image:
    """
    Hide `payload` inside the LSBs of `image` and return a new Image object.
    A 32-bit big-endian length header is embedded first so the extractor
    knows exactly how many payload bits follow.
    """
    capacity = get_image_capacity_bytes(image)
    if len(payload) > capacity:
        raise InsufficientCapacityError(
            f"Payload is {len(payload)} bytes but this image can only hold "
            f"{capacity} bytes. Use a larger image or a shorter message."
        )

    image = image.convert("RGB")
    width, height = image.size
    pixels = list(image.getdata())  # NOTE: Pillow may rename getdata() in future releases;
    # re-check the Pillow changelog if you upgrade past Pillow 14.

    header = struct.pack(">I", len(payload))  # 4 bytes, big-endian length
    bitstream = list(_bytes_to_bits(header)) + list(_bytes_to_bits(payload))

    new_pixels = []
    bit_index = 0
    total_bits = len(bitstream)

    for pixel in pixels:
        r, g, b = pixel
        channels = [r, g, b]
        for c in range(3):
            if bit_index < total_bits:
                channels[c] = (channels[c] & 0xFE) | bitstream[bit_index]
                bit_index += 1
        new_pixels.append(tuple(channels))
        if bit_index >= total_bits:
            # Remaining pixels are appended unchanged below
            new_pixels.extend(pixels[len(new_pixels):])
            break

    stego_image = Image.new("RGB", (width, height))
    stego_image.putdata(new_pixels)
    return stego_image


def extract_data_from_image(image: Image.Image) -> bytes:
    """
    Extract the hidden payload from a stego image produced by
    embed_data_in_image(). Reads the 32-bit length header first, then
    exactly that many bytes of payload.
    """
    image = image.convert("RGB")
    pixels = image.getdata()

    def channel_bit_generator():
        for pixel in pixels:
            for channel_value in pixel:  # r, g, b
                yield channel_value & 1

    bit_gen = channel_bit_generator()

    header_bits = []
    try:
        for _ in range(LENGTH_HEADER_BITS):
            header_bits.append(next(bit_gen))
    except StopIteration:
        raise NoHiddenDataError("Image is too small to contain a valid StegArmor header.")

    header_bytes = _bits_to_bytes(header_bits)
    payload_length = struct.unpack(">I", header_bytes)[0]

    max_possible = get_image_capacity_bytes(image)
    if payload_length == 0 or payload_length > max_possible:
        raise NoHiddenDataError(
            "No valid StegArmor payload detected (length header out of range). "
            "This image may not contain hidden data."
        )

    payload_bits = []
    try:
        for _ in range(payload_length * 8):
            payload_bits.append(next(bit_gen))
    except StopIteration:
        raise NoHiddenDataError("Image data ended before the declared payload length. "
                                 "The image may be corrupted or truncated.")

    return _bits_to_bytes(payload_bits)


# ----------------------------------------------------------------------
# High-level operations (used by the CLI)
# ----------------------------------------------------------------------
def do_embed(image_path: str, output_path: str, message_bytes: bytes, password: str) -> None:
    if not os.path.isfile(image_path):
        raise FileNotFoundError(f"Cover image not found: '{image_path}'")

    try:
        image = Image.open(image_path)
    except Exception as exc:
        raise StegArmorError(f"Could not open '{image_path}' as an image: {exc}")

    encrypted_blob = encrypt_message(message_bytes, password)
    stego_image = embed_data_in_image(image, encrypted_blob)

    if not output_path.lower().endswith(".png"):
        output_path += ".png"

    stego_image.save(output_path, format="PNG")  # PNG is lossless -- mandatory
    print(f"[+] Message encrypted (AES-256-GCM) and embedded successfully.")
    print(f"[+] Stego image written to: {output_path}")


def do_extract(image_path: str, password: str, output_path: str = None) -> str:
    if not os.path.isfile(image_path):
        raise FileNotFoundError(f"Stego image not found: '{image_path}'")

    try:
        image = Image.open(image_path)
    except Exception as exc:
        raise StegArmorError(f"Could not open '{image_path}' as an image: {exc}")

    encrypted_blob = extract_data_from_image(image)
    plaintext = decrypt_message(encrypted_blob, password)

    try:
        decoded = plaintext.decode("utf-8")
    except UnicodeDecodeError:
        decoded = None

    if output_path:
        mode = "wb" if decoded is None else "w"
        with open(output_path, mode) as f:
            f.write(plaintext if decoded is None else decoded)
        print(f"[+] Message decrypted and saved to: {output_path}")
    else:
        print("[+] Decrypted message:")
        print("-" * 50)
        print(decoded if decoded is not None else plaintext)
        print("-" * 50)

    return decoded if decoded is not None else plaintext


def do_capacity(image_path: str) -> None:
    if not os.path.isfile(image_path):
        raise FileNotFoundError(f"Image not found: '{image_path}'")
    image = Image.open(image_path)
    capacity = get_image_capacity_bytes(image)
    print(f"[i] Image: {image_path}  ({image.size[0]}x{image.size[1]} px)")
    print(f"[i] Maximum payload capacity: {capacity} bytes "
          f"(~{capacity // 1024} KB) before AES/format overhead.")
    print(f"[i] Note: StegArmor overhead per message is "
          f"{len(MAGIC) + SALT_SIZE + NONCE_SIZE + 16} bytes "
          f"(magic + salt + nonce + GCM tag).")


# ----------------------------------------------------------------------
# Command-Line Interface
# ----------------------------------------------------------------------
def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="stegarmor",
        description="StegArmor - Hide AES-256 encrypted messages inside PNG images.",
        epilog="Examples:\n"
               '  stegarmor embed -i cover.png -o stego.png -m "top secret" -p "hunter2"\n'
               "  stegarmor extract -i stego.png -p \"hunter2\"\n"
               "  stegarmor capacity -i cover.png\n",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # embed
    embed_p = subparsers.add_parser("embed", help="Encrypt a message and hide it in an image.")
    embed_p.add_argument("-i", "--image", required=True, help="Path to the cover PNG image.")
    embed_p.add_argument("-o", "--output", required=True, help="Path to save the output stego PNG.")
    group = embed_p.add_mutually_exclusive_group(required=True)
    group.add_argument("-m", "--message", help="Message text to hide.")
    group.add_argument("-f", "--file", help="Path to a text file whose contents will be hidden.")
    embed_p.add_argument("-p", "--password", required=True, help="Password used to derive the AES-256 key.")

    # extract
    extract_p = subparsers.add_parser("extract", help="Extract and decrypt a hidden message from an image.")
    extract_p.add_argument("-i", "--image", required=True, help="Path to the stego PNG image.")
    extract_p.add_argument("-p", "--password", required=True, help="Password used during embedding.")
    extract_p.add_argument("-o", "--output", help="Optional path to save the recovered message to a file.")

    # capacity
    capacity_p = subparsers.add_parser("capacity", help="Show how many bytes an image can hide.")
    capacity_p.add_argument("-i", "--image", required=True, help="Path to the image to analyze.")

    return parser


def main(argv=None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "embed":
            if args.file:
                if not os.path.isfile(args.file):
                    raise FileNotFoundError(f"Message file not found: '{args.file}'")
                with open(args.file, "rb") as f:
                    message_bytes = f.read()
            else:
                message_bytes = args.message.encode("utf-8")

            do_embed(args.image, args.output, message_bytes, args.password)

        elif args.command == "extract":
            do_extract(args.image, args.password, args.output)

        elif args.command == "capacity":
            do_capacity(args.image)

        return 0

    except FileNotFoundError as e:
        print(f"[!] File error: {e}", file=sys.stderr)
        return 2
    except InsufficientCapacityError as e:
        print(f"[!] Capacity error: {e}", file=sys.stderr)
        return 3
    except InvalidPasswordError as e:
        print(f"[!] Authentication error: {e}", file=sys.stderr)
        return 4
    except NoHiddenDataError as e:
        print(f"[!] Extraction error: {e}", file=sys.stderr)
        return 5
    except StegArmorError as e:
        print(f"[!] StegArmor error: {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\n[!] Operation cancelled by user.", file=sys.stderr)
        return 130
    except Exception as e:  # noqa: BLE001 - top-level safety net for a CLI tool
        print(f"[!] Unexpected error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
#!/usr/bin/env python3
"""
StegArmor - Encrypted Steganography Tool
==========================================

A cross-platform (Windows / Linux) command-line tool that combines
AES-256-GCM encryption with LSB (Least Significant Bit) image
steganography to hide encrypted text messages inside PNG images.

Author:  [YOUR NAME HERE]
License: MIT
Repository: [INSERT GITHUB REPOSITORY LINK HERE]

Usage:
    python stegarmor.py embed   -i cover.png -o stego.png -m "secret text" -p "MyPassword"
    python stegarmor.py embed   -i cover.png -o stego.png -f secret.txt   -p "MyPassword"
    python stegarmor.py extract -i stego.png -p "MyPassword"
    python stegarmor.py extract -i stego.png -p "MyPassword" -o recovered.txt
    python stegarmor.py capacity -i cover.png
"""

import argparse
import os
import sys
import struct

from PIL import Image
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

# ----------------------------------------------------------------------
# Constants
# ----------------------------------------------------------------------
SALT_SIZE = 16          # bytes, for PBKDF2
NONCE_SIZE = 12          # bytes, recommended size for AES-GCM
KEY_SIZE = 32          # bytes -> AES-256
PBKDF2_ITERATIONS = 390_000     # OWASP-recommended minimum ballpark (2024+)
LENGTH_HEADER_BITS = 32          # 32-bit big-endian length prefix, in bits
MAGIC = b"SA1"      # 3-byte format marker ("StegArmor v1")


# ----------------------------------------------------------------------
# Custom Exceptions
# ----------------------------------------------------------------------
class StegArmorError(Exception):
    """Base exception for all StegArmor-specific errors."""


class InsufficientCapacityError(StegArmorError):
    """Raised when the cover image cannot hold the payload."""


class InvalidPasswordError(StegArmorError):
    """Raised when decryption fails, most likely due to a wrong password."""


class NoHiddenDataError(StegArmorError):
    """Raised when the image does not appear to contain StegArmor data."""


# ----------------------------------------------------------------------
# Cryptography Layer
# ----------------------------------------------------------------------
def derive_key(password: str, salt: bytes) -> bytes:
    """
    Derive a 256-bit AES key from a user password using PBKDF2-HMAC-SHA256.

    The salt ensures that the same password never produces the same key
    twice, protecting against rainbow-table / precomputation attacks.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_message(plaintext: bytes, password: str) -> bytes:
    """
    Encrypt plaintext with AES-256-GCM.

    Output layout (all binary, concatenated):
        MAGIC (3 bytes) | SALT (16 bytes) | NONCE (12 bytes) | CIPHERTEXT+TAG
    """
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    key = derive_key(password, salt)

    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=MAGIC)

    return MAGIC + salt + nonce + ciphertext


def decrypt_message(blob: bytes, password: str) -> bytes:
    """
    Reverse of encrypt_message(). Raises InvalidPasswordError if the
    password is wrong or the data has been tampered with (GCM auth tag
    verification failure).
    """
    if len(blob) < len(MAGIC) + SALT_SIZE + NONCE_SIZE:
        raise NoHiddenDataError("Extracted data is too short to be valid StegArmor content.")

    magic = blob[:len(MAGIC)]
    if magic != MAGIC:
        raise NoHiddenDataError(
            "No valid StegArmor payload found in this image (magic header mismatch)."
        )

    offset = len(MAGIC)
    salt = blob[offset:offset + SALT_SIZE]
    offset += SALT_SIZE
    nonce = blob[offset:offset + NONCE_SIZE]
    offset += NONCE_SIZE
    ciphertext = blob[offset:]

    key = derive_key(password, salt)
    aesgcm = AESGCM(key)

    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data=MAGIC)
    except InvalidTag:
        raise InvalidPasswordError(
            "Decryption failed. The password is incorrect, or the stego "
            "image has been modified/corrupted since embedding."
        )
    return plaintext


# ----------------------------------------------------------------------
# Steganography Layer (LSB embedding in PNG)
# ----------------------------------------------------------------------
def _bytes_to_bits(data: bytes):
    """Yield each bit (MSB first) of every byte in `data`."""
    for byte in data:
        for i in range(7, -1, -1):
            yield (byte >> i) & 1


def _bits_to_bytes(bits) -> bytes:
    """Pack an iterable of bits (MSB first) into bytes."""
    out = bytearray()
    bit_buffer = 0
    bit_count = 0
    for bit in bits:
        bit_buffer = (bit_buffer << 1) | bit
        bit_count += 1
        if bit_count == 8:
            out.append(bit_buffer)
            bit_buffer = 0
            bit_count = 0
    return bytes(out)


def get_image_capacity_bytes(image: Image.Image) -> int:
    """
    Return the maximum number of payload bytes that can be hidden in
    the given image, after reserving space for the 32-bit length header.
    Uses 1 LSB per color channel (R, G, B) -- alpha is left untouched.
    """
    width, height = image.size
    channels = 3  # R, G, B (skip alpha to preserve transparency data)
    total_bits = width * height * channels
    usable_bits = total_bits - LENGTH_HEADER_BITS
    return max(usable_bits // 8, 0)


def embed_data_in_image(image: Image.Image, payload: bytes) -> Image.Image:
    """
    Hide `payload` inside the LSBs of `image` and return a new Image object.
    A 32-bit big-endian length header is embedded first so the extractor
    knows exactly how many payload bits follow.
    """
    capacity = get_image_capacity_bytes(image)
    if len(payload) > capacity:
        raise InsufficientCapacityError(
            f"Payload is {len(payload)} bytes but this image can only hold "
            f"{capacity} bytes. Use a larger image or a shorter message."
        )

    image = image.convert("RGB")
    width, height = image.size
    pixels = list(image.getdata())  # NOTE: Pillow may rename getdata() in future releases;
    # re-check the Pillow changelog if you upgrade past Pillow 14.

    header = struct.pack(">I", len(payload))  # 4 bytes, big-endian length
    bitstream = list(_bytes_to_bits(header)) + list(_bytes_to_bits(payload))

    new_pixels = []
    bit_index = 0
    total_bits = len(bitstream)

    for pixel in pixels:
        r, g, b = pixel
        channels = [r, g, b]
        for c in range(3):
            if bit_index < total_bits:
                channels[c] = (channels[c] & 0xFE) | bitstream[bit_index]
                bit_index += 1
        new_pixels.append(tuple(channels))
        if bit_index >= total_bits:
            # Remaining pixels are appended unchanged below
            new_pixels.extend(pixels[len(new_pixels):])
            break

    stego_image = Image.new("RGB", (width, height))
    stego_image.putdata(new_pixels)
    return stego_image


def extract_data_from_image(image: Image.Image) -> bytes:
    """
    Extract the hidden payload from a stego image produced by
    embed_data_in_image(). Reads the 32-bit length header first, then
    exactly that many bytes of payload.
    """
    image = image.convert("RGB")
    pixels = image.getdata()

    def channel_bit_generator():
        for pixel in pixels:
            for channel_value in pixel:  # r, g, b
                yield channel_value & 1

    bit_gen = channel_bit_generator()

    header_bits = []
    try:
        for _ in range(LENGTH_HEADER_BITS):
            header_bits.append(next(bit_gen))
    except StopIteration:
        raise NoHiddenDataError("Image is too small to contain a valid StegArmor header.")

    header_bytes = _bits_to_bytes(header_bits)
    payload_length = struct.unpack(">I", header_bytes)[0]

    max_possible = get_image_capacity_bytes(image)
    if payload_length == 0 or payload_length > max_possible:
        raise NoHiddenDataError(
            "No valid StegArmor payload detected (length header out of range). "
            "This image may not contain hidden data."
        )

    payload_bits = []
    try:
        for _ in range(payload_length * 8):
            payload_bits.append(next(bit_gen))
    except StopIteration:
        raise NoHiddenDataError("Image data ended before the declared payload length. "
                                 "The image may be corrupted or truncated.")

    return _bits_to_bytes(payload_bits)


# ----------------------------------------------------------------------
# High-level operations (used by the CLI)
# ----------------------------------------------------------------------
def do_embed(image_path: str, output_path: str, message_bytes: bytes, password: str) -> None:
    if not os.path.isfile(image_path):
        raise FileNotFoundError(f"Cover image not found: '{image_path}'")

    try:
        image = Image.open(image_path)
    except Exception as exc:
        raise StegArmorError(f"Could not open '{image_path}' as an image: {exc}")

    encrypted_blob = encrypt_message(message_bytes, password)
    stego_image = embed_data_in_image(image, encrypted_blob)

    if not output_path.lower().endswith(".png"):
        output_path += ".png"

    stego_image.save(output_path, format="PNG")  # PNG is lossless -- mandatory
    print(f"[+] Message encrypted (AES-256-GCM) and embedded successfully.")
    print(f"[+] Stego image written to: {output_path}")


def do_extract(image_path: str, password: str, output_path: str = None) -> str:
    if not os.path.isfile(image_path):
        raise FileNotFoundError(f"Stego image not found: '{image_path}'")

    try:
        image = Image.open(image_path)
    except Exception as exc:
        raise StegArmorError(f"Could not open '{image_path}' as an image: {exc}")

    encrypted_blob = extract_data_from_image(image)
    plaintext = decrypt_message(encrypted_blob, password)

    try:
        decoded = plaintext.decode("utf-8")
    except UnicodeDecodeError:
        decoded = None

    if output_path:
        mode = "wb" if decoded is None else "w"
        with open(output_path, mode) as f:
            f.write(plaintext if decoded is None else decoded)
        print(f"[+] Message decrypted and saved to: {output_path}")
    else:
        print("[+] Decrypted message:")
        print("-" * 50)
        print(decoded if decoded is not None else plaintext)
        print("-" * 50)

    return decoded if decoded is not None else plaintext


def do_capacity(image_path: str) -> None:
    if not os.path.isfile(image_path):
        raise FileNotFoundError(f"Image not found: '{image_path}'")
    image = Image.open(image_path)
    capacity = get_image_capacity_bytes(image)
    print(f"[i] Image: {image_path}  ({image.size[0]}x{image.size[1]} px)")
    print(f"[i] Maximum payload capacity: {capacity} bytes "
          f"(~{capacity // 1024} KB) before AES/format overhead.")
    print(f"[i] Note: StegArmor overhead per message is "
          f"{len(MAGIC) + SALT_SIZE + NONCE_SIZE + 16} bytes "
          f"(magic + salt + nonce + GCM tag).")


# ----------------------------------------------------------------------
# Command-Line Interface
# ----------------------------------------------------------------------
def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="stegarmor",
        description="StegArmor - Hide AES-256 encrypted messages inside PNG images.",
        epilog="Examples:\n"
               '  stegarmor embed -i cover.png -o stego.png -m "top secret" -p "hunter2"\n'
               "  stegarmor extract -i stego.png -p \"hunter2\"\n"
               "  stegarmor capacity -i cover.png\n",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # embed
    embed_p = subparsers.add_parser("embed", help="Encrypt a message and hide it in an image.")
    embed_p.add_argument("-i", "--image", required=True, help="Path to the cover PNG image.")
    embed_p.add_argument("-o", "--output", required=True, help="Path to save the output stego PNG.")
    group = embed_p.add_mutually_exclusive_group(required=True)
    group.add_argument("-m", "--message", help="Message text to hide.")
    group.add_argument("-f", "--file", help="Path to a text file whose contents will be hidden.")
    embed_p.add_argument("-p", "--password", required=True, help="Password used to derive the AES-256 key.")

    # extract
    extract_p = subparsers.add_parser("extract", help="Extract and decrypt a hidden message from an image.")
    extract_p.add_argument("-i", "--image", required=True, help="Path to the stego PNG image.")
    extract_p.add_argument("-p", "--password", required=True, help="Password used during embedding.")
    extract_p.add_argument("-o", "--output", help="Optional path to save the recovered message to a file.")

    # capacity
    capacity_p = subparsers.add_parser("capacity", help="Show how many bytes an image can hide.")
    capacity_p.add_argument("-i", "--image", required=True, help="Path to the image to analyze.")

    return parser


def main(argv=None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "embed":
            if args.file:
                if not os.path.isfile(args.file):
                    raise FileNotFoundError(f"Message file not found: '{args.file}'")
                with open(args.file, "rb") as f:
                    message_bytes = f.read()
            else:
                message_bytes = args.message.encode("utf-8")

            do_embed(args.image, args.output, message_bytes, args.password)

        elif args.command == "extract":
            do_extract(args.image, args.password, args.output)

        elif args.command == "capacity":
            do_capacity(args.image)

        return 0

    except FileNotFoundError as e:
        print(f"[!] File error: {e}", file=sys.stderr)
        return 2
    except InsufficientCapacityError as e:
        print(f"[!] Capacity error: {e}", file=sys.stderr)
        return 3
    except InvalidPasswordError as e:
        print(f"[!] Authentication error: {e}", file=sys.stderr)
        return 4
    except NoHiddenDataError as e:
        print(f"[!] Extraction error: {e}", file=sys.stderr)
        return 5
    except StegArmorError as e:
        print(f"[!] StegArmor error: {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\n[!] Operation cancelled by user.", file=sys.stderr)
        return 130
    except Exception as e:  # noqa: BLE001 - top-level safety net for a CLI tool
        print(f"[!] Unexpected error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
#!/usr/bin/env python3
"""
StegArmor - Encrypted Steganography Tool
==========================================

A cross-platform (Windows / Linux) command-line tool that combines
AES-256-GCM encryption with LSB (Least Significant Bit) image
steganography to hide encrypted text messages inside PNG images.

Author:  [YOUR NAME HERE]
License: MIT
Repository: [INSERT GITHUB REPOSITORY LINK HERE]

Usage:
    python stegarmor.py embed   -i cover.png -o stego.png -m "secret text" -p "MyPassword"
    python stegarmor.py embed   -i cover.png -o stego.png -f secret.txt   -p "MyPassword"
    python stegarmor.py extract -i stego.png -p "MyPassword"
    python stegarmor.py extract -i stego.png -p "MyPassword" -o recovered.txt
    python stegarmor.py capacity -i cover.png
"""

import argparse
import os
import sys
import struct

from PIL import Image
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

# ----------------------------------------------------------------------
# Constants
# ----------------------------------------------------------------------
SALT_SIZE = 16          # bytes, for PBKDF2
NONCE_SIZE = 12          # bytes, recommended size for AES-GCM
KEY_SIZE = 32          # bytes -> AES-256
PBKDF2_ITERATIONS = 390_000     # OWASP-recommended minimum ballpark (2024+)
LENGTH_HEADER_BITS = 32          # 32-bit big-endian length prefix, in bits
MAGIC = b"SA1"      # 3-byte format marker ("StegArmor v1")


# ----------------------------------------------------------------------
# Custom Exceptions
# ----------------------------------------------------------------------
class StegArmorError(Exception):
    """Base exception for all StegArmor-specific errors."""


class InsufficientCapacityError(StegArmorError):
    """Raised when the cover image cannot hold the payload."""


class InvalidPasswordError(StegArmorError):
    """Raised when decryption fails, most likely due to a wrong password."""


class NoHiddenDataError(StegArmorError):
    """Raised when the image does not appear to contain StegArmor data."""


# ----------------------------------------------------------------------
# Cryptography Layer
# ----------------------------------------------------------------------
def derive_key(password: str, salt: bytes) -> bytes:
    """
    Derive a 256-bit AES key from a user password using PBKDF2-HMAC-SHA256.

    The salt ensures that the same password never produces the same key
    twice, protecting against rainbow-table / precomputation attacks.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_message(plaintext: bytes, password: str) -> bytes:
    """
    Encrypt plaintext with AES-256-GCM.

    Output layout (all binary, concatenated):
        MAGIC (3 bytes) | SALT (16 bytes) | NONCE (12 bytes) | CIPHERTEXT+TAG
    """
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    key = derive_key(password, salt)

    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=MAGIC)

    return MAGIC + salt + nonce + ciphertext


def decrypt_message(blob: bytes, password: str) -> bytes:
    """
    Reverse of encrypt_message(). Raises InvalidPasswordError if the
    password is wrong or the data has been tampered with (GCM auth tag
    verification failure).
    """
    if len(blob) < len(MAGIC) + SALT_SIZE + NONCE_SIZE:
        raise NoHiddenDataError("Extracted data is too short to be valid StegArmor content.")

    magic = blob[:len(MAGIC)]
    if magic != MAGIC:
        raise NoHiddenDataError(
            "No valid StegArmor payload found in this image (magic header mismatch)."
        )

    offset = len(MAGIC)
    salt = blob[offset:offset + SALT_SIZE]
    offset += SALT_SIZE
    nonce = blob[offset:offset + NONCE_SIZE]
    offset += NONCE_SIZE
    ciphertext = blob[offset:]

    key = derive_key(password, salt)
    aesgcm = AESGCM(key)

    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data=MAGIC)
    except InvalidTag:
        raise InvalidPasswordError(
            "Decryption failed. The password is incorrect, or the stego "
            "image has been modified/corrupted since embedding."
        )
    return plaintext


# ----------------------------------------------------------------------
# Steganography Layer (LSB embedding in PNG)
# ----------------------------------------------------------------------
def _bytes_to_bits(data: bytes):
    """Yield each bit (MSB first) of every byte in `data`."""
    for byte in data:
        for i in range(7, -1, -1):
            yield (byte >> i) & 1


def _bits_to_bytes(bits) -> bytes:
    """Pack an iterable of bits (MSB first) into bytes."""
    out = bytearray()
    bit_buffer = 0
    bit_count = 0
    for bit in bits:
        bit_buffer = (bit_buffer << 1) | bit
        bit_count += 1
        if bit_count == 8:
            out.append(bit_buffer)
            bit_buffer = 0
            bit_count = 0
    return bytes(out)


def get_image_capacity_bytes(image: Image.Image) -> int:
    """
    Return the maximum number of payload bytes that can be hidden in
    the given image, after reserving space for the 32-bit length header.
    Uses 1 LSB per color channel (R, G, B) -- alpha is left untouched.
    """
    width, height = image.size
    channels = 3  # R, G, B (skip alpha to preserve transparency data)
    total_bits = width * height * channels
    usable_bits = total_bits - LENGTH_HEADER_BITS
    return max(usable_bits // 8, 0)


def embed_data_in_image(image: Image.Image, payload: bytes) -> Image.Image:
    """
    Hide `payload` inside the LSBs of `image` and return a new Image object.
    A 32-bit big-endian length header is embedded first so the extractor
    knows exactly how many payload bits follow.
    """
    capacity = get_image_capacity_bytes(image)
    if len(payload) > capacity:
        raise InsufficientCapacityError(
            f"Payload is {len(payload)} bytes but this image can only hold "
            f"{capacity} bytes. Use a larger image or a shorter message."
        )

    image = image.convert("RGB")
    width, height = image.size
    pixels = list(image.getdata())  # NOTE: Pillow may rename getdata() in future releases;
    # re-check the Pillow changelog if you upgrade past Pillow 14.

    header = struct.pack(">I", len(payload))  # 4 bytes, big-endian length
    bitstream = list(_bytes_to_bits(header)) + list(_bytes_to_bits(payload))

    new_pixels = []
    bit_index = 0
    total_bits = len(bitstream)

    for pixel in pixels:
        r, g, b = pixel
        channels = [r, g, b]
        for c in range(3):
            if bit_index < total_bits:
                channels[c] = (channels[c] & 0xFE) | bitstream[bit_index]
                bit_index += 1
        new_pixels.append(tuple(channels))
        if bit_index >= total_bits:
            # Remaining pixels are appended unchanged below
            new_pixels.extend(pixels[len(new_pixels):])
            break

    stego_image = Image.new("RGB", (width, height))
    stego_image.putdata(new_pixels)
    return stego_image


def extract_data_from_image(image: Image.Image) -> bytes:
    """
    Extract the hidden payload from a stego image produced by
    embed_data_in_image(). Reads the 32-bit length header first, then
    exactly that many bytes of payload.
    """
    image = image.convert("RGB")
    pixels = image.getdata()

    def channel_bit_generator():
        for pixel in pixels:
            for channel_value in pixel:  # r, g, b
                yield channel_value & 1

    bit_gen = channel_bit_generator()

    header_bits = []
    try:
        for _ in range(LENGTH_HEADER_BITS):
            header_bits.append(next(bit_gen))
    except StopIteration:
        raise NoHiddenDataError("Image is too small to contain a valid StegArmor header.")

    header_bytes = _bits_to_bytes(header_bits)
    payload_length = struct.unpack(">I", header_bytes)[0]

    max_possible = get_image_capacity_bytes(image)
    if payload_length == 0 or payload_length > max_possible:
        raise NoHiddenDataError(
            "No valid StegArmor payload detected (length header out of range). "
            "This image may not contain hidden data."
        )

    payload_bits = []
    try:
        for _ in range(payload_length * 8):
            payload_bits.append(next(bit_gen))
    except StopIteration:
        raise NoHiddenDataError("Image data ended before the declared payload length. "
                                 "The image may be corrupted or truncated.")

    return _bits_to_bytes(payload_bits)


# ----------------------------------------------------------------------
# High-level operations (used by the CLI)
# ----------------------------------------------------------------------
def do_embed(image_path: str, output_path: str, message_bytes: bytes, password: str) -> None:
    if not os.path.isfile(image_path):
        raise FileNotFoundError(f"Cover image not found: '{image_path}'")

    try:
        image = Image.open(image_path)
    except Exception as exc:
        raise StegArmorError(f"Could not open '{image_path}' as an image: {exc}")

    encrypted_blob = encrypt_message(message_bytes, password)
    stego_image = embed_data_in_image(image, encrypted_blob)

    if not output_path.lower().endswith(".png"):
        output_path += ".png"

    stego_image.save(output_path, format="PNG")  # PNG is lossless -- mandatory
    print(f"[+] Message encrypted (AES-256-GCM) and embedded successfully.")
    print(f"[+] Stego image written to: {output_path}")


def do_extract(image_path: str, password: str, output_path: str = None) -> str:
    if not os.path.isfile(image_path):
        raise FileNotFoundError(f"Stego image not found: '{image_path}'")

    try:
        image = Image.open(image_path)
    except Exception as exc:
        raise StegArmorError(f"Could not open '{image_path}' as an image: {exc}")

    encrypted_blob = extract_data_from_image(image)
    plaintext = decrypt_message(encrypted_blob, password)

    try:
        decoded = plaintext.decode("utf-8")
    except UnicodeDecodeError:
        decoded = None

    if output_path:
        mode = "wb" if decoded is None else "w"
        with open(output_path, mode) as f:
            f.write(plaintext if decoded is None else decoded)
        print(f"[+] Message decrypted and saved to: {output_path}")
    else:
        print("[+] Decrypted message:")
        print("-" * 50)
        print(decoded if decoded is not None else plaintext)
        print("-" * 50)

    return decoded if decoded is not None else plaintext


def do_capacity(image_path: str) -> None:
    if not os.path.isfile(image_path):
        raise FileNotFoundError(f"Image not found: '{image_path}'")
    image = Image.open(image_path)
    capacity = get_image_capacity_bytes(image)
    print(f"[i] Image: {image_path}  ({image.size[0]}x{image.size[1]} px)")
    print(f"[i] Maximum payload capacity: {capacity} bytes "
          f"(~{capacity // 1024} KB) before AES/format overhead.")
    print(f"[i] Note: StegArmor overhead per message is "
          f"{len(MAGIC) + SALT_SIZE + NONCE_SIZE + 16} bytes "
          f"(magic + salt + nonce + GCM tag).")


# ----------------------------------------------------------------------
# Command-Line Interface
# ----------------------------------------------------------------------
def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="stegarmor",
        description="StegArmor - Hide AES-256 encrypted messages inside PNG images.",
        epilog="Examples:\n"
               '  stegarmor embed -i cover.png -o stego.png -m "top secret" -p "hunter2"\n'
               "  stegarmor extract -i stego.png -p \"hunter2\"\n"
               "  stegarmor capacity -i cover.png\n",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # embed
    embed_p = subparsers.add_parser("embed", help="Encrypt a message and hide it in an image.")
    embed_p.add_argument("-i", "--image", required=True, help="Path to the cover PNG image.")
    embed_p.add_argument("-o", "--output", required=True, help="Path to save the output stego PNG.")
    group = embed_p.add_mutually_exclusive_group(required=True)
    group.add_argument("-m", "--message", help="Message text to hide.")
    group.add_argument("-f", "--file", help="Path to a text file whose contents will be hidden.")
    embed_p.add_argument("-p", "--password", required=True, help="Password used to derive the AES-256 key.")

    # extract
    extract_p = subparsers.add_parser("extract", help="Extract and decrypt a hidden message from an image.")
    extract_p.add_argument("-i", "--image", required=True, help="Path to the stego PNG image.")
    extract_p.add_argument("-p", "--password", required=True, help="Password used during embedding.")
    extract_p.add_argument("-o", "--output", help="Optional path to save the recovered message to a file.")

    # capacity
    capacity_p = subparsers.add_parser("capacity", help="Show how many bytes an image can hide.")
    capacity_p.add_argument("-i", "--image", required=True, help="Path to the image to analyze.")

    return parser


def main(argv=None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "embed":
            if args.file:
                if not os.path.isfile(args.file):
                    raise FileNotFoundError(f"Message file not found: '{args.file}'")
                with open(args.file, "rb") as f:
                    message_bytes = f.read()
            else:
                message_bytes = args.message.encode("utf-8")

            do_embed(args.image, args.output, message_bytes, args.password)

        elif args.command == "extract":
            do_extract(args.image, args.password, args.output)

        elif args.command == "capacity":
            do_capacity(args.image)

        return 0

    except FileNotFoundError as e:
        print(f"[!] File error: {e}", file=sys.stderr)
        return 2
    except InsufficientCapacityError as e:
        print(f"[!] Capacity error: {e}", file=sys.stderr)
        return 3
    except InvalidPasswordError as e:
        print(f"[!] Authentication error: {e}", file=sys.stderr)
        return 4
    except NoHiddenDataError as e:
        print(f"[!] Extraction error: {e}", file=sys.stderr)
        return 5
    except StegArmorError as e:
        print(f"[!] StegArmor error: {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\n[!] Operation cancelled by user.", file=sys.stderr)
        return 130
    except Exception as e:  # noqa: BLE001 - top-level safety net for a CLI tool
        print(f"[!] Unexpected error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
