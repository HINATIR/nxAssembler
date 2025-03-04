import tkinter as tk
from tkinter import ttk
import re
import subprocess


def exec_tool(exe,args):
    try:

        result = subprocess.run(
            [exe] + args,
            capture_output=True,
            text=True,
            check=True
        )
        
        if("ERROR" in result.stdout.strip()):
            return f"{args[1]} .."

        return result.stdout.strip()

    except subprocess.CalledProcessError as e:
        return f"{args[1]} .."

    except Exception as e:
        raise f"cstool.exe の実行に失敗しました:\n入力コード: {args}"
    
def format_cheats(lines):
    result = []
    for line in lines:
        blocks = re.findall('.{8}', re.sub(r'\s+', '', line))
        if not blocks:
            continue

        second_char = blocks[0][1]
        if second_char == '8':
            result.append(blocks[3])
            result.append(blocks[2])
        elif second_char == '4':
            result.append(blocks[2])

    return '\n'.join(result)


def convert_endian(input_text):
    lines = input_text.split('\n')

    result = []
    for line in lines:
        # 2文字ごとに分割
        bytes_list = [line[i:i+2] for i in range(0, len(line), 2)]
        if not bytes_list:
            result.append('')
            continue
        # リストを逆順にして再結合
        result.append(''.join(reversed(bytes_list)))

    return '\n'.join(result)

def get_offset(input_text):
    offset = int(input_text[10:18], 16)
    return format(offset, 'X')

def cheat_coding(lines, offset):
    code = ""

    # オフセットを16進数文字列から整数に変換
    offset_int = int(offset, 16)

    # ペアごとに処理
    for i in range(len(lines) // 2):
        code += f"08000000 {(offset_int + 8 * i):08X} {lines[2 * i + 1].strip()} {lines[2 * i].strip()}\n"

    # 残り1行がある場合の処理
    if len(lines) % 2 == 1:
        code += f"04000000 {(offset_int + 4 * (len(lines) - 1)):08X} {lines[-1].strip()}\n"
        
    return code

def ips_coding(lines, offset):
    code = ""
    i = 0

    for line in lines:
        if i % 10 == 0:
            if i != 0:
                code += "\n"
            # オフセット計算
            code += f"{(int(offset, 16) + 4 * i):08X} "
        # 行を追加
        code += line.strip()
        i += 1

    return code



def input_labels(asm, offset):
    lines = asm.split("\n")
    labels = []
    pos = []
    errors = []

    for i, line in enumerate(lines):
        match = re.search(r"<=(.+)", line)
        if match:
            label = match.group(1).strip()
            
            for existing_label in labels:
                if existing_label in label or label in existing_label:
                    errors.append(f"ラベルエラー:  {i + 1}行 : 同名か似た名前のラベル '{label}' が複数存在します..")
            
            lines[i] = line.split("<=")[0]
            
            labels.append(label)
            pos.append(f"#0x{(int(offset, 16) + 4 * i):X}")
    
    result = "\n".join(lines)
    
    for label, position in zip(labels, pos):
        aresult = result.replace(label, position)
        if(aresult == result):
            errors.append(f"ラベルエラー: ジャンプ元のラベル'{label}'が存在しません..") 
        result = aresult

    return [result, errors]

def remove_empty_lines(asm):
    return "\n".join([line for line in asm.split("\n") if line.strip() != ""])

def remove_comment(input):
    return "\n".join([line.split(';')[0] for line in input.split("\n")])

def assemble(source,offset):
    try:
        startaddress = int(offset, 16)
        errors = ["エラー一覧:"]
        
        if startaddress % 4 != 0:
            errors.append(f"アドレスエラー : {startaddress:x}")
        
        asmsource = remove_comment(remove_empty_lines(source)).replace(r'[\r\n]+', '\n')
        inputted = input_labels(asmsource, hex(startaddress))

        if(inputted[1]):
            errors.extend(inputted[1])
        
        instructions = inputted[0].split("\n")
        
        results = []
        for i in range(len(instructions)):
            result = exec_tool('./kstool.exe', ['arm64', instructions[i], hex(startaddress + (4 * i))[2:]])
            if ".." in result:
                errors.append(f"文法エラー : {i + 1}行 : {instructions[i]}")
            else:
                results.append(convert_endian(result.split("=")[1].replace("[", '').replace("]", '').replace(" ", '').upper()))
        
        if len(errors) > 1:
            return "\n".join(errors)
        
        return cheat_coding( results , hex(startaddress))
    
    except Exception as error:
        return "\n".join(errors) + error

def ips_assemble(source,offset):
    try:
        startaddress = int(offset, 16)
        errors = ["エラー一覧:"]
        
        if startaddress % 4 != 0:
            errors.append(f"アドレスエラー : {startaddress:x}")
        
        asmsource = remove_comment(remove_empty_lines(source)).replace(r'[\r\n]+', '\n')
        inputted = input_labels(asmsource, hex(startaddress))

        if(inputted[1]):
            errors.extend(inputted[1])
        
        instructions = inputted[0].split("\n")
        
        results = []
        for i in range(len(instructions)):
            result = exec_tool('./kstool.exe', ['arm64', instructions[i], hex(startaddress + (4 * i))[2:]])
            if ".." in result:
                errors.append(f"文法エラー : {i + 1}行 : {instructions[i]}")
            else:
                results.append(result.split("=")[1].replace("[", '').replace("]", '').replace(" ", '').upper())
        
        if len(errors) > 1:
            return "\n".join(errors)
        
        return ips_coding( results , hex(startaddress))
    
    except Exception as error:
        return "\n".join(errors) + error

def write_wchar(source,offset):
    asci = [format(ord(char), '08X') if char != '\n' else '00000000' for char in source]
    asci.append("00000000")

    return f"{cheat_coding(asci, offset)}\n\n{wchar_getoffset(source, offset)}"

def write_wchar_asips(source,offset):
    asci = [convert_endian(format(ord(char), '08X')) if char != '\n' else '00000000' for char in source]
    asci.append("00000000")

    return f"{ips_coding(asci, offset)}\n\n{wchar_getoffset(source, offset)}"

def wchar_getoffset(source, offset):
    startaddress = int(offset, 16)
    lines = source.splitlines()
    formatted = []
    
    current_offset =  startaddress
    
    for line in lines:
        hex_offset = format(current_offset, 'X')
        formatted.append(f"0x{hex_offset} : {line}")
        
        current_offset = current_offset + len(line)* 4 + 4

    return "\n".join(formatted)

def toChar(source, offset):
    hex_string = source.encode("utf-8").hex().upper()
    hex_string = [hex_string[i:i+8] for i in range(0, len(hex_string), 8)]
    hex_string[len(hex_string)-1] = hex_string[len(hex_string) -1].ljust(8, '0')

    result = []
    for line in hex_string:
        # 2文字ごとに分割
        bytes_list = [line[i:i+2] for i in range(0, len(line), 2)]
        if not bytes_list:
            result.append('')
            continue
        # リストを逆順にして再結合
        result.append(''.join(reversed(bytes_list)))


    return f"{cheat_coding(result, offset)}"

def toCharips(source, offset):
    hex_string = source.encode("utf-8").hex().upper()
    hex_string = [hex_string[i:i+8] for i in range(0, len(hex_string), 8)]
    hex_string[len(hex_string)-1] = hex_string[len(hex_string) -1].ljust(8, '0')



    return f"{ips_coding(hex_string, offset)}"
    

def on_run():
    offset = top_textbox.get()
    source = rich_textbox.get("1.0", tk.END).strip()
    mode = mode_var.get()
    if(mode == "Assemble"):
        output = assemble(source,offset)
    
    if(mode == "Assemble2ips"):
        output = ips_assemble(source,offset)

    if(mode == "write_wchar"):
        output = write_wchar(source,offset)

    if(mode == "write_wchar_asips"):
        output = write_wchar_asips(source,offset)

    if(mode == "toChar"):
        output = toChar(source,offset)

    if(mode == "toCharips"):
        output = toCharips(source,offset)

    # 出力ボックスに結果を表示
    output_box.config(state=tk.NORMAL)
    output_box.delete("1.0", tk.END)
    output_box.insert(tk.END, output)
    output_box.config(state=tk.DISABLED)

def on_copy():
    content = output_box.get("1.0", tk.END).strip()
    root.clipboard_clear()
    root.clipboard_append(content)


root = tk.Tk()
root.title("makomo")
root.geometry(f"700x400")

left_frame = tk.Frame(root, width=100, padx=5, pady=10, bg="white smoke")
left_frame.pack(side=tk.LEFT, fill=tk.Y)

top_section = tk.Frame(left_frame, bg="white smoke")
top_section.pack(pady=5, fill=tk.X)

top_textbox = tk.Entry(top_section, width=25)
top_textbox.pack(side=tk.LEFT, padx=5)

mode_var = tk.StringVar(value="Assemble")
mode_menu = ttk.Combobox(top_section, textvariable=mode_var, values=["Assemble", "Assemble2ips", "write_wchar","write_wchar_asips","toChar","toCharips"], state="readonly", width=15)
mode_menu.pack(side=tk.LEFT, padx=5)

rich_textbox = tk.Text(left_frame, wrap=tk.WORD, height=3, width=20)  # heightを小さく、widthを指定
rich_textbox.pack(pady=5, fill=tk.BOTH, expand=True)

submit_button = tk.Button(left_frame, text="実行", command=on_run)
submit_button.pack(pady=5, fill=tk.X)

right_frame = tk.Frame(root, width=300, padx=10, pady=10)
right_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

output_box = tk.Text(right_frame, wrap=tk.WORD, state=tk.DISABLED, height=25)
output_box.pack(pady=5, fill=tk.BOTH, expand=True)

copy_button = tk.Button(right_frame, text="コピー", command=on_copy)
copy_button.pack(pady=5, fill=tk.X)

root.mainloop()