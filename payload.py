import sys
import os

def read_source(file_name):
    """
    C++ kaynak dosyasını oku.
    """
    with open(file_name, "rt") as source:
        return source.read()

def read_shellcode(file_name):
    """
    Read bin file containing shellcode.
    """
    with open(file_name, "rb") as payload:
        return payload.read()

def format_shellcode(shellcode):
    """
    Prepare the shellcode as a string in C++ format.
    """
    return '"\\x' + '\\x'.join(hex(byte)[2:].zfill(2) for byte in shellcode) + '";'

def write_new_source(file_name, new_code):
    """
    Write updated source code.
    """
    with open(file_name, "w") as new_file:
        new_file.write(new_code)

def main():
    cpp_file = "poc.cpp"
    bin_file = "payload.bin"
    new_cpp_file = "new-poc.cpp"
    output_exe = "poc.exe"

    # Read source and shellcode
    source_code = read_source(cpp_file)
    shellcode = read_shellcode(bin_file)

    # Convert shellcode to proper format
    formatted_shellcode = format_shellcode(shellcode)

    # Yeni kaynak kodunu oluştur
    new_code = source_code.replace('unsigned char shellcode[] = "";', f'unsigned char shellcode[] = {formatted_shellcode}')

    # Write updated code
    write_new_source(new_cpp_file, new_code)

    # Compile C++ file
    os.system(f"x86_64-w64-mingw32-g++ --static {new_cpp_file} -o {output_exe}")

if __name__ == "__main__":
    main()
