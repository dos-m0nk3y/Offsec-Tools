from shellcode import buf


def main():
    line = "  buf = Array("
    for i in range(0, len(buf)):
        line += str(buf[i] ^ 0xFF) + ","
        if (i + 1) % 80 == 0:
            print(line + " _")
            line = "  "
    print(line + "\b)")


if __name__ == "__main__":
    main()
