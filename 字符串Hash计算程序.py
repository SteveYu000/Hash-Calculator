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
            item_value = item_values[column_id]  # Adjust index to match column order
        else:
            item_value = '\t'.join(item_values)  # Join all columns if no specific column is selected
        root.clipboard_clear()
        root.clipboard_append(item_value)
        root.update()


def on_select(event):
    region = tree.identify_region(event.x, event.y)
    if region == "cell":
        selected_item = tree.identify_row(event.y)
        selected_column = tree.identify_column(event.x)
        if selected_item and selected_column:
            column_index = int(selected_column.lstrip('#')) - 1  # Convert column identifier to zero-based index
            item_values = tree.item(selected_item, 'values')
            item_value = item_values[column_index]  # Get the value of the selected cell
            tree.selection_set(selected_item)
            tree.focus(selected_item)
            tree.see(selected_item)
            root.clipboard_clear()
            root.clipboard_append(item_value)
            root.update()

def on_copy(event):
    try:
        selected_items = tree.selection()
        if selected_items:
            item_id = selected_items[0]
            item_values = tree.item(item_id, 'values')
            item_value = '\t'.join(item_values)  # Join all columns if multiple items are selected
            root.clipboard_clear()
            root.clipboard_append(item_value)
            root.update()
    except Exception as e:
        print(e)

root = tb.Window(themename="cosmo")  # 使用cosmo主题接近Fluent Design
root.title("字符串Hash计算程序")
root.geometry("600x600")

# 创建一个Frame来包含输入框和按钮
frame = tb.Frame(root, padding="10")
frame.pack(side=tk.TOP, fill=tk.X, pady=(10, 0))

# 输入框和按钮的容器
entry_frame = tb.Frame(frame, bootstyle="light", borderwidth=2, relief="solid")
entry_frame.pack(fill=tk.X, padx=10)

# 输入框
entry_var = tk.StringVar(value="输入字符串并计算hash")
entry = tb.Entry(entry_frame, textvariable=entry_var, font=("Segoe UI", 12), width=40, bootstyle="light")
entry.pack(side=tk.LEFT, padx=(5, 0), pady=5, fill=tk.BOTH, expand=True)

# 绑定回车键事件
entry.bind('<KeyPress>', on_entry_key_press)

# 计算按钮
button = tb.Button(entry_frame, text="计算", command=on_button_click, bootstyle="primary", width=5)
button.pack(side=tk.RIGHT, padx=(0, 5), pady=5)

# 绑定事件处理函数
entry.bind('<FocusIn>', lambda event: entry_var.set('') if entry_var.get() == "输入字符串并计算hash" else None)
entry.bind('<FocusOut>', lambda event: entry_var.set("输入字符串并计算hash") if not entry.get() else None)

# 创建结果表格
tree = tb.Treeview(root, columns=('algorithm', 'result', 'upper_result', 'length'), show='headings', height=5, selectmode='browse')
tree.heading('algorithm', text='算法', anchor=tk.CENTER)
tree.heading('result', text='结果', anchor=tk.CENTER)
tree.heading('upper_result', text='大写结果', anchor=tk.CENTER)
tree.heading('length', text='长度', anchor=tk.CENTER)

tree.column('algorithm', width=100, anchor=tk.CENTER)
tree.column('result', width=150, anchor=tk.CENTER)
tree.column('upper_result', width=150, anchor=tk.CENTER)
tree.column('length', width=50, anchor=tk.CENTER)

for i, algo in enumerate(['MD5', 'SHA-1', 'SHA-256', 'SHA-512', 'CRC32']):
    tree.insert('', 'end', values=(algo, '', '', ''), tags=('odd' if i % 2 else 'even'))

tree.tag_configure('odd', background='#f9f9f9')
tree.tag_configure('even', background='#e9ecef')

tree.pack(pady=(200, 0), padx=10, fill=tk.X)

# 添加表格线样式
style = tb.Style()
style.configure('Treeview', rowheight=25, fieldbackground='white', background='white', font=('Segoe UI', 10))
style.layout('Treeview.Item', [('Treeitem.padding', {'sticky': 'nswe'}), ('Treeitem.indicator', {'side': 'left', 'sticky': ''}), ('Treeitem.image', {'side': 'left', 'sticky': ''}), ('Treeitem.text', {'sticky': 'w'})])
style.map('Treeview', background=[('selected', '#add8e6')])

# 自定义样式以移除灰色底纹并添加圆角
style.configure('TEntry', fieldbackground='white', bordercolor='transparent', lightcolor='transparent', darkcolor='transparent')
style.map('TEntry', fieldbackground=[('focus', 'white')])
style.configure('TButton', background='blue', foreground='white')

# 绑定点击其他区域取消焦点
root.bind("<Button-1>", clear_focus)


# 左键点击选择单元格并复制内容
tree.bind("<Button-1>", on_select)

# 绑定 Control+C 复制选中的行内容
root.bind("<Control-c>", on_copy)

root.mainloop()
