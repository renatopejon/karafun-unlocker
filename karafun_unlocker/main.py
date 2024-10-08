import tkinter as tk
from tkinter import filedialog
import webbrowser
import os
from configparser import ConfigParser
from dataclasses import dataclass, field
from enum import Enum
from io import StringIO
import struct
from typing import Any, BinaryIO

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class KFNSubfileType(Enum):
    SONG = 1
    AUDIO = 2
    IMAGE = 3
    FONT = 4
    VIDEO = 5
    MILKDROP = 6
    CDG = 7


# 1 = vertical text
# 2 = classic karaoke
# 21 = sprites
# 51 = background
# 53 = Milkdrop
# 61 = CDG
# 62 = video
VALID_EFFECT_IDS = set([1, 2, 21, 51, 53, 61, 62])


@dataclass
class KFNSubfile:
    name: bytes
    ftype: KFNSubfileType
    data: bytes
    length: int
    is_encrypted: bool


@dataclass
class KFNFile:
    headers: dict[str, int | bytes] = field(default_factory=dict)
    subfiles: list[KFNSubfile] = field(default_factory=list)


# Helper function for writing 4-byte words (little endian)
def write_word_le(stream: BinaryIO, word: int):
    stream.write(word.to_bytes(4, byteorder="little"))


def read_kfn(stream: BinaryIO) -> KFNFile:
    kfn = KFNFile()
    stream.seek(0)

    # Read file signature
    (magic,) = struct.unpack("<4s", stream.read(4))
    if magic != b"KFNB":
        raise ValueError("unexpected file signature")

    # Read headers
    while True:
        header, flag = struct.unpack("<4sB", stream.read(5))
        header = header.decode()

        if flag == 1:
            # Single number
            (data,) = struct.unpack("I", stream.read(4))
        elif flag == 2:
            # String with length
            (length,) = struct.unpack("I", stream.read(4))
            data = stream.read(length)
        else:
            raise ValueError(
                f"unexpected flag for header {header}: {flag}",
            )

        # If ENDH header is reached, stop processing headers
        if header == "ENDH":
            break

        kfn.headers[header] = data

    # Read subfile metadata
    subfile_info: dict[bytes, tuple[Any, ...]] = {}
    (subfile_count,) = struct.unpack("I", stream.read(4))
    for _ in range(subfile_count):
        (subfile_name_length,) = struct.unpack("I", stream.read(4))
        subfile_name = stream.read(subfile_name_length)
        subfile_metadata = struct.unpack("IIIII", stream.read(20))

        subfile_info[subfile_name] = subfile_metadata

    # Read subfile data
    subfiles_start = stream.tell()
    for name, metadata in subfile_info.items():
        ftype, length, offset, encrypted_length, is_encrypted = metadata
        ftype = KFNSubfileType(ftype)
        is_encrypted = bool(is_encrypted)

        # Get data at offset in file, relative to start of subfile data
        stream.seek(subfiles_start + offset)
        data = stream.read(encrypted_length)

        subfile = KFNSubfile(
            name=name,
            ftype=ftype,
            data=data,
            length=length,
            is_encrypted=is_encrypted,
        )
        kfn.subfiles.append(subfile)

    return kfn


def write_kfn(kfn: KFNFile, stream: BinaryIO):
    # Write file signature
    stream.write(b"KFNB")

    # Write headers
    for header, data in kfn.headers.items():
        stream.write(bytes(header, encoding="utf-8"))

        # If data is integer
        if isinstance(data, int):
            # Flag = 1
            stream.write(b"\x01")
            write_word_le(stream, data)
        # If data is string
        else:
            # Flag = 2
            stream.write(b"\x02")
            write_word_le(stream, len(data))
            stream.write(data)
    # Write ENDH header
    stream.write(b"ENDH\x01\xff\xff\xff\xff")

    # Write subfile metadata
    write_word_le(stream, len(kfn.subfiles))
    offset = 0
    for subfile in kfn.subfiles:
        # Name length + name
        write_word_le(stream, len(subfile.name))
        stream.write(subfile.name)
        # File type
        write_word_le(stream, subfile.ftype.value)
        # Unencrypted data length
        write_word_le(stream, subfile.length)
        # Offset of data (relative to start of subfile data)
        write_word_le(stream, offset)
        # Encrypted data length
        write_word_le(stream, len(subfile.data))
        # Is this file encrypted?
        write_word_le(stream, int(subfile.is_encrypted))

        # Increase offset
        offset += len(subfile.data)

    # Write subfile data
    for subfile in kfn.subfiles:
        stream.write(subfile.data)


def unlock_kfn(kfn: KFNFile):
    # Step 1: Reverse the encryption
    # If encryption key is nonzero
    all_zeroes = (0).to_bytes(16)
    if kfn.headers["FLID"] != all_zeroes:
        # Create decryptor
        cipher = Cipher(algorithms.AES128(kfn.headers["FLID"]), modes.ECB())
        decryptor = cipher.decryptor()
        # Zero out the encryption key
        kfn.headers["FLID"] = all_zeroes

        # Decrypt encrypted subfiles
        for subfile in kfn.subfiles:
            # Skip unencrypted subfiles
            if not subfile.is_encrypted:
                continue

            subfile.data = decryptor.update(subfile.data)[:subfile.length]
            subfile.is_encrypted = False

    # Step 2: Change the publishing rights
    if "RGHT" in kfn.headers:
        kfn.headers["RGHT"] = 0

    # Step 3: Remove invalid effects
    for subfile in kfn.subfiles:
        # Skip all files except for song config files
        if subfile.ftype != KFNSubfileType.SONG:
            continue

        # Parse song config
        config = ConfigParser()
        config.read_string(subfile.data.decode("cp1252"))
        for section in config.sections():
            # Skip sections that aren't effects
            if not section.lower().startswith("eff"):
                continue
            # Skip sections that are valid effect types
            if config.getint(section, "id") in VALID_EFFECT_IDS:
                continue

            # This section is an invalid effect; delete this section
            del config[section]

        # Write back new song config
        config_io = StringIO()
        config.write(config_io)
        config_io.seek(0)
        subfile.data = config_io.read().encode("cp1252")
        subfile.length = len(subfile.data)

    return kfn


def main():
    def select_file():
        file_path = filedialog.askopenfilename(filetypes=[("KFN files", "*.kfn")])
        if file_path:
            input_entry.delete(0, tk.END)
            input_entry.insert(0, file_path)
            
            # Generate output file name
            dir_name, file_name = os.path.split(file_path)
            base_name, ext = os.path.splitext(file_name)
            output_file = os.path.join(dir_name, f"{base_name}-Unlocked{ext}")
            output_entry.delete(0, tk.END)
            output_entry.insert(0, output_file)

    def unlock_file():
        in_path = input_entry.get()
        out_path = output_entry.get()
        
        if not in_path or not out_path:
            status_label.config(text="Please select input and output files.")
            return

        try:
            with open(in_path, "rb") as stream:
                kfn = read_kfn(stream)
            kfn = unlock_kfn(kfn)
            with open(out_path, "wb") as stream:
                write_kfn(kfn, stream)
            status_label.config(text="File unlocked successfully!")
        except Exception as e:
            status_label.config(text=f"Error: {str(e)}")

    def open_link(event):
        webbrowser.open_new("https://github.com/renatopejon/karafun-unlocker")

    # Create the main window
    root = tk.Tk()
    root.title("KFN File Unlocker")
    root.geometry("400x230")  # Increased height to accommodate footer

    # Input file selection
    tk.Label(root, text="Input File:").grid(row=0, column=0, padx=5, pady=5, sticky="e")
    input_entry = tk.Entry(root, width=40)
    input_entry.grid(row=0, column=1, padx=5, pady=5)
    tk.Button(root, text="Browse", command=select_file).grid(row=0, column=2, padx=5, pady=5)

    # Output file display
    tk.Label(root, text="Output File:").grid(row=1, column=0, padx=5, pady=5, sticky="e")
    output_entry = tk.Entry(root, width=40)
    output_entry.grid(row=1, column=1, padx=5, pady=5)

    # Unlock button
    unlock_button = tk.Button(root, text="Unlock File", command=unlock_file)
    unlock_button.grid(row=2, column=1, padx=5, pady=20)

    # Status label
    status_label = tk.Label(root, text="")
    status_label.grid(row=3, column=0, columnspan=3, padx=5, pady=5)

    # Footer with credits
    footer_frame = tk.Frame(root, bg="light gray")
    footer_frame.grid(row=4, column=0, columnspan=3, sticky="ew")
    root.grid_rowconfigure(4, weight=1)
    root.grid_columnconfigure(1, weight=1)

    credits_label = tk.Label(footer_frame, text="Repository on", bg="light gray")
    credits_label.pack(side="left")

    link_label = tk.Label(footer_frame, text="GitHub", fg="blue", cursor="hand2", bg="light gray")
    link_label.pack(side="left")
    link_label.bind("<Button-1>", open_link)

    root.mainloop()

if __name__ == "__main__":
    main()
