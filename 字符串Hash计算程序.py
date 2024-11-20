import tkinter as tk
from tkinter import ttk, Menu
import hashlib
import zlib
import ttkbootstrap as tb

def calculate_hashes(input_string):
    md5_result = hashlib.md5(input_string.encode()).hexdigest()
    sha1_result = hashlib.sha1(input_string.encode()).hexdigest()
    sha256_result = hashlib.sha256(input_string.encode()).hexdigest()
    sha512_result = hashlib.sha512(input_string.encode()).hexdigest()
    crc32_result = format(zlib.crc32(input_string.encode()), '08x')
    
    return {
        'MD5': (md5_result, md5_result.upper(), len(md5_result)),
        'SHA-1': (sha1_result, sha1_result.upper(), len(sha1_result)),
        'SHA-256': (sha256_result, sha256_result.upper(), len(sha256_result)),
        'SHA-512': (sha512_result, sha512_result.upper(), len(sha512_result)),
        'CRC32': (crc32_result, crc32_result.upper(), len(crc32_result))
    }

def on_button_click():
    input_string = entry.get()
    if input_string:
        hashes = calculate_hashes(input_string)
        for i, algo in enumerate(['MD5', 'SHA-1', 'SHA-256', 'SHA-512', 'CRC32']):
            result, upper_result, length = hashes[algo]
            tree.set(tree.get_children()[i], column='result', value=result)
            tree.set(tree.get_children()[i], column='upper_result', value=upper_result)
            tree.set(tree.get_children()[i], column='length', value=length)

def on_entry_key_press(event):
    if event.keysym == 'Return':
        on_button_click()

def clear_focus(event):
    if not isinstance(event.widget, (tk.Entry, ttk.Entry)):
        root.focus_set()
        tree.selection_remove(tree.focus())

def copy_to_clipboard(item_id, column_id=None):
    if item_id:
        item_values = tree.item(item_id, 'values')
        if column_id is not None:
            item_value = item_values[column_id]
        else:
            item_value = '\t'.join(item_values)
        root.clipboard_clear()
        root.clipboard_append(item_value)
        root.update()
        show_success_popup()

def on_select(event):
    region = tree.identify_region(event.x, event.y)
    if region == "cell":
        selected_item = tree.identify_row(event.y)
        selected_column = tree.identify_column(event.x)
        if selected_item and selected_column:
            column_index = int(selected_column.lstrip('#')) - 1
            item_values = tree.item(selected_item, 'values')
            item_value = item_values[column_index]
            tree.selection_set(selected_item)
            tree.focus(selected_item)
            tree.see(selected_item)
            root.clipboard_clear()
            root.clipboard_append(item_value)
            root.update()
            show_success_popup()

def on_copy(event):
    try:
        selected_items = tree.selection()
        if selected_items:
            item_id = selected_items[0]
            item_values = tree.item(item_id, 'values')
            item_value = '\t'.join(item_values)
            root.clipboard_clear()
            root.clipboard_append(item_value)
            root.update()
            show_success_popup()
    except Exception as e:
        print(e)

def show_success_popup():
    global popup
    popup = tk.Toplevel(root)
    popup.title("Success")
    popup.geometry(f"+{root.winfo_x() + root.winfo_width() // 2 - 75}+{root.winfo_y() + root.winfo_height() // 2 - 25}")
    popup.overrideredirect(True)
    popup.attributes('-alpha', 0.9)

    frame = tk.Frame(popup, bg="#d4edda", bd=1, relief="solid", highlightbackground="#c3e6cb", highlightcolor="#c3e6cb", highlightthickness=1)
    frame.pack(padx=10, pady=10)

    label = tk.Label(frame, text="复制成功!", fg="#155724", bg="#d4edda", font=("Microsoft YaHei UI", 12))
    label.pack(pady=5)

    popup.after(1000, popup.destroy)

# 创建窗口
root = tb.Window(themename="cosmo")
root.title("字符串Hash计算程序")
root.geometry("1200x700")

# 创建一个Frame来包含输入框和按钮
frame = tb.Frame(root, padding="10")
frame.pack(side=tk.TOP, fill=tk.X, pady=(10, 0))

# 输入框和按钮的容器
entry_frame = tb.Frame(frame, bootstyle="light", borderwidth=2, relief="solid")
entry_frame.pack(fill=tk.X, padx=10)

# 输入框
entry_var = tk.StringVar(value="输入字符串并计算hash")
entry = tb.Entry(entry_frame, textvariable=entry_var, font=("Microsoft YaHei UI", 12), width=40, bootstyle="light")
entry.pack(side=tk.LEFT, padx=(5, 0), pady=5, fill=tk.BOTH, expand=True)

# 计算
entry.bind('<KeyPress>', on_entry_key_press)
button = tb.Button(entry_frame, text="计算", command=on_button_click, bootstyle="primary", width=5)
button.pack(side=tk.RIGHT, padx=(0, 5), pady=5)

entry.bind('<FocusIn>', lambda event: entry_var.set('') if entry_var.get() == "输入字符串并计算hash" else None)
entry.bind('<FocusOut>', lambda event: entry_var.set("输入字符串并计算hash") if not entry.get() else None)

# 创建结果表格
tree = tb.Treeview(root, columns=('algorithm', 'result', 'upper_result', 'length'), show='headings', height=5, selectmode='browse')
tree.heading('algorithm', text='算法', anchor=tk.CENTER)
tree.heading('result', text='结果', anchor=tk.CENTER)
tree.heading('upper_result', text='大写结果', anchor=tk.CENTER)
tree.heading('length', text='长度', anchor=tk.CENTER)

# 计算可用宽度
total_width = 1200 - 2 * 15  # 总宽度减去两边的15px
remaining_width = total_width - 115 * 2  # 减去两个115px的列宽
half_remaining_width = remaining_width // 2  # 剩余宽度的一半

tree.column('algorithm', width=115, anchor=tk.CENTER)
tree.column('result', width=half_remaining_width, anchor=tk.CENTER)
tree.column('upper_result', width=half_remaining_width, anchor=tk.CENTER)
tree.column('length', width=110, anchor=tk.CENTER)

for i, algo in enumerate(['MD5', 'SHA-1', 'SHA-256', 'SHA-512', 'CRC32']):
    tree.insert('', 'end', values=(algo, '', '', ''), tags=('odd' if i % 2 else 'even'))

tree.tag_configure('odd', background='#f9f9f9')
tree.tag_configure('even', background='#e9ecef')

tree.pack(pady=(200, 0), padx=15, fill=tk.X)  # 设置左右padding为15px

# 样式配置
style = tb.Style()
style.configure('.', font=('Microsoft YaHei UI', 10))
style.configure('Treeview', rowheight=25, fieldbackground='white', background='white', font=('Microsoft YaHei UI', 10))
style.layout('Treeview.Item', [('Treeitem.padding', {'sticky': 'nswe'}), ('Treeitem.indicator', {'side': 'left', 'sticky': ''}), ('Treeitem.image', {'side': 'left', 'sticky': ''}), ('Treeitem.text', {'sticky': 'w'})])
style.map('Treeview', background=[('selected', '#add8e6')])
style.configure('TEntry', fieldbackground='white', bordercolor='transparent', lightcolor='transparent', darkcolor='transparent')
style.map('TEntry', fieldbackground=[('focus', 'white')])
style.configure('TButton', background='blue', foreground='white')

# 复制结果
root.bind("<Button-1>", clear_focus)
tree.bind("<Button-1>", on_select)
root.bind("<Control-c>", on_copy)

root.mainloop()
