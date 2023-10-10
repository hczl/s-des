import re
import tkinter as tk
from tkinter import ttk


# 密钥扩展函数
def key_expansion(key):
    p10 = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]
    p8 = [6, 3, 7, 4, 8, 5, 10, 9]

    def shift(lst, n):
        return lst[n:] + lst[:n]

    # Apply P10 permutation
    permuted_key = [key[i - 1] for i in p10]

    # Perform left shifts
    shifted1 = shift(permuted_key[:5], 1) + shift(permuted_key[5:], 1)
    shifted2 = shift(shifted1[:5], 2) + shift(shifted1[5:], 2)

    # Apply P8 permutation to get subkeys
    subkey1 = [shifted1[i - 1] for i in p8]
    subkey2 = [shifted2[i - 1] for i in p8]

    return subkey1, subkey2


# 初始置换函数
def initial_permutation(input_data):
    ip = [2, 6, 3, 1, 4, 8, 5, 7]
    return [input_data[i - 1] for i in ip]


# 逆初始置换函数
def inverse_initial_permutation(input_data):
    ip_inv = [4, 1, 3, 5, 7, 2, 8, 6]
    return [input_data[i - 1] for i in ip_inv]


# 轮函数
def round_function(input_data, subkey):
    ep_box = [4, 1, 2, 3, 2, 3, 4, 1]
    sbox1 = [[1, 0, 3, 2], [3, 2, 1, 0], [0, 2, 1, 3], [3, 1, 0, 2]]
    sbox2 = [[0, 1, 2, 3], [2, 3, 1, 0], [3, 0, 1, 2], [2, 1, 0, 3]]
    p4 = [2, 4, 3, 1]
    # Apply expansion permutation
    expanded_data = [input_data[i - 1] for i in ep_box]
    # XOR with subkey
    xor_result = [expanded_data[i] ^ subkey[i] for i in range(8)]
    # S-Box substitutions
    sbox1_row = xor_result[:4]
    sbox2_row = xor_result[4:]
    sbox1_output = sbox1[sbox1_row[0] * 2 + sbox1_row[3]][sbox1_row[1] * 2 + sbox1_row[2]]
    sbox2_output = sbox2[sbox2_row[0] * 2 + sbox2_row[3]][sbox2_row[1] * 2 + sbox2_row[2]]

    # Apply P4 permutation
    p4_output = [sbox1_output // 2, sbox1_output % 2, sbox2_output // 2, sbox2_output % 2]
    final_output = [p4_output[i - 1] for i in p4]
    return final_output


# S-DES 加密函数
def sdes_encrypt(plaintext, key):
    subkey1, subkey2 = key_expansion(key)
    plaintext = initial_permutation(plaintext)
    # Initial round
    round1_output = round_function(plaintext[4:], subkey1)
    new_right = [plaintext[i] ^ round1_output[i] for i in range(4)]
    new_left = plaintext[4:]
    # Swap and perform second round
    round2_output = round_function(new_right, subkey2)
    final_left = [new_left[i] ^ round2_output[i] for i in range(4)]
    final_right = new_right

    # Inverse initial permutation
    ciphertext = final_left + final_right
    ciphertext = inverse_initial_permutation(ciphertext)
    return ciphertext


# S-DES 解密函数
def sdes_decrypt(ciphertext, key):
    subkey1, subkey2 = key_expansion(key)
    ciphertext = initial_permutation(ciphertext)
    # Initial round
    round1_output = round_function(ciphertext[4:], subkey2)
    new_right = [ciphertext[i] ^ round1_output[i] for i in range(4)]
    new_left = ciphertext[4:]
    # Swap and perform second round
    round2_output = round_function(new_right, subkey1)
    final_left = [new_left[i] ^ round2_output[i] for i in range(4)]
    final_right = new_right

    # Inverse initial permutation
    plaintext = final_left + final_right
    plaintext = inverse_initial_permutation(plaintext)
    return plaintext


# 主函数 根据操作选择执行加密或解密
def sdes_process_data(operation, text, key):
    # 判断是否为8位2进制数
    determine = bool(re.match(r'^[01]+$', text)) and len(text) % 8 == 0
    if determine:
        text_num = int(len(text) / 8)
        binary_text = [int(bit) for bit in text]
    # 将不是的转换为2进制字符串
    else:
        text_num = len(text)
        binary_text = ''.join(format(ord(char), '08b') for char in text)
    binary_key = [int(bit) for bit in key]
    result = ''
    # 加解密
    if operation == 'encrypt':
        for i in range(text_num):
            t = [int(binary_text[j + i * 8]) for j in range(8)]
            result += ''.join(map(str, sdes_encrypt(t, binary_key)))
    else:
        for i in range(text_num):
            t = [int(binary_text[j + i * 8]) for j in range(8)]
            result += ''.join(map(str, sdes_decrypt(t, binary_key)))
    # 输出结果
    if determine:
        return result
    else:
        # 将二进制字符串分组，每组8位
        binary_chunks = [result[i:i + 8] for i in range(0, len(result), 8)]

        # 将每组转换为ASCII码
        ascii_characters = [chr(int(chunk, 2)) for chunk in binary_chunks]

        # 将结果连接成一个字符串
        result = ''.join(ascii_characters)
        return result


def create_sdes_ui():
    def on_focus_in_1(event):
        if text1.get("1.0", "end-1c") == "请在此输入明文":
            text1.delete("1.0", "end-1c")
            text1.config(fg='#7f7f7f')

    def on_focus_out_1(event):
        if not text1.get("1.0", "end-1c").strip():
            text1.insert("1.0", "请在此输入明文")
            text1.config(fg='#7f7f7f')

    def on_focus_in_2(event):
        if text2.get("1.0", "end-1c") == "请在此输入密文":
            text2.delete("1.0", "end-1c")
            text2.config(fg='#7f7f7f')

    def on_focus_out_2(event):
        if not text2.get("1.0", "end-1c").strip():
            text2.insert("1.0", "请在此输入密文")
            text2.config(fg='#7f7f7f')

    def encrypt():
        if text1.get("1.0", 'end-1c') != "请在此输入明文":
            text2.delete(1.0, tk.END)
            text2.insert(tk.END, sdes_process_data('encrypt', text1.get("1.0", 'end-1c'), key.get()))
        else:
            return

    def decrypt():
        if text2.get("1.0", 'end-1c') != "请在此输入密文":
            text1.delete(1.0, tk.END)
            text1.insert(tk.END, sdes_process_data('decrypt', text2.get("1.0", 'end-1c'), key.get()))
        else:
            return

    def validate_binary_input(char, input_value):
        return char in '01' and len(input_value) <= 10

    root = tk.Tk()
    root.title("S-DES 加密解密")

    # 设置背景颜色
    root.configure(bg='#add8e6')

    text1 = tk.Text(root, wrap="word", bg='#d3eaf6', fg='#000000', height=5, width=20)  # 设置文本框样式
    text1.tag_configure("placeholder", foreground='#7f7f7f')
    text1.insert("1.0", "请在此输入明文", "placeholder")
    text1.bind("<FocusIn>", on_focus_in_1)
    text1.bind("<FocusOut>", on_focus_out_1)
    text1.grid(row=0, column=0, padx=5, pady=5, sticky="nsew")

    text2 = tk.Text(root, wrap="word", bg='#d3eaf6', fg='#000000', height=5, width=20)  # 设置文本框样式
    text2.tag_configure("placeholder", foreground='#7f7f7f')
    text2.insert("1.0", "请在此输入密文", "placeholder")
    text2.bind("<FocusIn>", on_focus_in_2)
    text2.bind("<FocusOut>", on_focus_out_2)
    text2.grid(row=0, column=2, padx=5, pady=5, sticky="nsew")

    key_validator = root.register(validate_binary_input)
    key = ttk.Entry(root, validate="key", validatecommand=(key_validator, "%S", "%P"), foreground='#000000')
    key.grid(row=1, column=0, columnspan=3, padx=5, pady=5, sticky="nsew")


    button_encrypt = ttk.Button(root, text="加密", command=encrypt, style='TButton', state='disabled')  # 设置按钮样式
    button_encrypt.grid(row=2, column=0, columnspan=3, padx=5, pady=5, sticky="nsew")

    button_decrypt = ttk.Button(root, text="解密", command=decrypt, style='TButton', state='disabled')  # 设置按钮样式
    button_decrypt.grid(row=3, column=0, columnspan=3, padx=5, pady=5, sticky="nsew")

    # 定义按钮样式
    style = ttk.Style()
    style.configure('TButton', font=('Arial', 12), background='#4caf50', foreground='#ffffff')

    root.grid_rowconfigure(0, weight=1)
    root.grid_columnconfigure(0, weight=1)
    root.grid_columnconfigure(1, weight=1)
    root.grid_columnconfigure(2, weight=1)

    def update_button_state(*args):
        if len(key.get()) == 10:
            button_encrypt['state'] = 'normal'
            button_decrypt['state'] = 'normal'
        else:
            button_encrypt['state'] = 'disabled'
            button_decrypt['state'] = 'disabled'

    key.bind('<KeyRelease>', update_button_state)

    root.mainloop()


# 调用函数以创建界面
# 调用函数以创建界面
create_sdes_ui()
