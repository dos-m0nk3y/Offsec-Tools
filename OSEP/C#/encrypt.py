import base64


def main():
    for filename in ["shellcode32.bin", "shellcode64.bin"]:
        with open(filename, "rb") as fd:
            shellcode = fd.read()

        shellcode = bytes([ch ^ 0xFF for ch in shellcode])
        shellcode = base64.b64encode(shellcode)

        with open(filename + ".enc", "wb") as fd:
            fd.write(shellcode)


if __name__ == "__main__":
    main()
