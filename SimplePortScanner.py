# Copyright © 2022 yohane <mii@li.cm>
import tkinter as tk
from tkinter import ttk
from scapy.all import *
import threading
from queue import Queue
import socket
import time
import csv

reader = csv.reader(open('port.csv', 'r'))
next(reader, None)
portDict = dict()
for row in reader:
    if row:
        portDict[row[1]] = row[0]


root = tk.Tk()
root.call('source', 'sun-valley.tcl')
root.call('set_theme', 'light')
root.title('Simple Port Scanner')
# root.geometry('378x650')
# root.resizable(0,0)

def port2list(ports):
    portList = []
    ports = ports.split(',')
    for port in ports:
        if '-' in port:
            port = port.split('-')
            for i in range(int(port[0]), int(port[1])):
                portList.append(i)
        else:
            portList.append(int(port))
    return portList
                  
q = Queue()

# scan port by tcp connection

def scan_port_tcp_thread():
    t1 = threading.Thread(target=scan_port_tcp)
    t1.start()

def threader():
        global stop
        while True:
            if q.empty():
                break
            worker = q.get()
            scan(worker)
            q.task_done()

def scan(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.5)
    ip = e_ip.get()
    try:
        s.connect((ip, int(port)))
        s.shutdown(2)
        result_text.insert(tk.END, f'{ip}:{port} is open\n')
        try:
            open_text.insert(tk.END, f'{ip}:{port}({portDict[str(port)]})\n')
        except:
            open_text.insert(tk.END, f'{ip}:{port}(unknown)\n')
        result_text.update()
        result_text.see('end')
        open_text.update()
    except:
        result_text.insert(tk.END, f'{ip}:{port} is closed\n')
        result_text.update()
        result_text.see('end')
    
def scan_port_tcp():
    start = time.clock()
    global q
    result_text.delete('1.0', 'end')
    open_text.delete('1.0', 'end')
    ip = e_ip.get()
    port1 = e_port.get()
    
    ports = port2list(port1)
    
    for worker in ports:
        q.put(worker)
    for t in range(int(e_th.get())):
        t = threading.Thread(target=threader)
        t.daemon = True
        t.start()
    q.join()    
    end = time.clock()
    result_text.insert(tk.END, f'Scanning finished, time: {end-start}s')

# sacn port by syn

def scan_port_semi_conn_thread():
    t1 = threading.Thread(target=scan_port_semi_conn)
    t1.start()

def threader_semi():
    global q
    while True:
        if q.empty():
            break
        worker = q.get()
        scan_semi(worker)
        q.task_done()

def scan_semi(port):
    ip = e_ip.get()
    #sr1 向目标发送一个SYN分组（packet）
    a = sr1(IP(dst=ip) / TCP(dport=port), timeout=0.8, verbose=0)
    if a == None:
        pass
    else:
        #接收返回的数据包验证flags 的值 即ACK+SYN回包的16进制数据转为10进制 0X12
        # 转成int 来判断是否回包是ACK+SYN的值18是表示端口开放
        if int(a[TCP].flags) == 18:
            result_text.insert(tk.END, f'{ip}:{port} is open\n')
            try:
                open_text.insert(tk.END, f'{ip}:{port}({portDict[str(port)]})\n')
            except:
                open_text.insert(tk.END, f'{ip}:{port}(unknown)\n')
            result_text.update()
            result_text.see('end')
            open_text.update()
        else:
            result_text.insert(tk.END, f'{ip}:{port} is closed\n')
            result_text.update()
            result_text.see('end')

def scan_port_semi_conn():
    start = time.clock()
    global q
    result_text.delete('1.0', 'end')
    open_text.delete('1.0', 'end')
    ip = e_ip.get()
    port1 = e_port.get()
    
    ports = port2list(port1)

    for worker in ports:
        q.put(worker)
    for t in range(int(e_th.get())):
        t = threading.Thread(target=threader_semi)
        t.daemon = True
        t.start()
    q.join()    
    end = time.clock()
    result_text.insert(tk.END, f'Scanning finished, time: {end-start}s')
            

#scan port by null
def scan_port_null_thread():
    t1 = threading.Thread(target=scan_port_null)
    t1.start()

def threader_null():
    global q
    while True:
        if q.empty():
            break
        worker = q.get()
        scan_null(worker)
        q.task_done()

def scan_null(port):
    ip = e_ip.get()
    a = sr1(IP(dst=ip) / TCP(dport=port, flags=''), timeout=0.5, verbose=0)
    if a == None:
        result_text.insert(tk.END, f'{ip}:{port} is open\n')
        try:
            open_text.insert(tk.END, f'{ip}:{port}({portDict[str(port)]})\n')
        except:
            open_text.insert(tk.END, f'{ip}:{port}(unknown)\n')
        result_text.update()
        result_text.see('end')
        open_text.update()
    else:
        if a != None and a[TCP].flags == 'RA':
            result_text.insert(tk.END, f'{ip}:{port} is closed\n')
            result_text.update()
            result_text.see('end')

def scan_port_null():
    start = time.clock()
    global q
    result_text.delete('1.0', 'end')
    open_text.delete('1.0', 'end')
    ip = e_ip.get()
    port1 = e_port.get()

    ports = port2list(port1)

    for worker in ports:
        q.put(worker)
    for t in range(int(e_th.get())):
        t = threading.Thread(target=threader_null)
        t.daemon = True
        t.start()
    q.join()
    end = time.clock()
    result_text.insert(tk.END, f'Scanning finished, time: {end-start}s')

#scan port by fin
def scan_port_fin_thread():
    t1 = threading.Thread(target=scan_port_fin)
    t1.start()

def threader_fin():
    global q
    while True:
        if q.empty():
            break
        worker = q.get()
        scan_fin(worker)
        q.task_done()

def scan_fin(port):
    ip = e_ip.get()
    a = sr1(IP(dst=ip) / TCP(dport=port, flags="F"), timeout=0.5, verbose=0)
    if a == None:
        result_text.insert(tk.END, f'{ip}:{port} is open\n')
        try:
            open_text.insert(tk.END, f'{ip}:{port}({portDict[str(port)]})\n')
        except:
            open_text.insert(tk.END, f'{ip}:{port}(unknown)\n')
        result_text.update()
        result_text.see('end')
        open_text.update()
    else:
        if(a[TCP].flags == "RA"):
            result_text.insert(tk.END, f'{ip}:{port} is closed\n')
            result_text.update()
            result_text.see('end')
            
def scan_port_fin():
    start = time.clock()
    global q
    result_text.delete('1.0', 'end')
    open_text.delete('1.0', 'end')
    ip = e_ip.get()
    port1 = e_port.get()

    ports = port2list(port1)

    for worker in ports:
        q.put(worker)
    
    for t in range(int(e_th.get())):
        t = threading.Thread(target=threader_fin)
        t.daemon = True
        t.start()
    q.join()
    end = time.clock()
    result_text.insert(tk.END, f'Scanning finished, time: {end-start}s')
                


str1 = tk.StringVar()
l_ip = ttk.Label(root, text='IP:')
str1.set(r'192.168.0.1')
l_ip.grid(row=0, column=0, sticky='e', padx=(10, 0))
e_ip = ttk.Entry(root, textvariable=str1)
e_ip.grid(row=0, column=1, pady=5,padx=(0, 10))
l_port = ttk.Label(root, text='Ports(e.g. 1,33-44):')
l_port.grid(row=1, column=0, sticky='e')
e_port = ttk.Entry(root)
e_port.grid(row=1, column=1, pady=5 ,padx=(0, 10))

str2 = tk.StringVar()
str2.set(r'10')
l_th = ttk.Label(root, text='Number of Threads:')
l_th.grid(row=2, column=0, sticky='e', pady=(5), padx=(10, 0))
e_th = ttk.Entry(root, textvariable=str2)
e_th.grid(row=2, column=1, pady=(5,10), padx=(0, 10))

b_scan = ttk.Button(root, text='Scan_conncect', command=scan_port_tcp_thread)
b_scan.grid(row=3, column=0, pady=(0,5))

b_scan2 = ttk.Button(root, text='Scan_semi_conn', command=scan_port_semi_conn_thread)
b_scan2.grid(row=3, column=1, pady=5)

b_scan3 = ttk.Button(root, text='Scan_null', command=scan_port_null_thread)
b_scan3.grid(row=4, column=0, pady=(5,10))

b_scan4 = ttk.Button(root, text='Scan_fin', command=scan_port_fin_thread)
b_scan4.grid(row=4, column=1, pady=(5,10))

l_res1 = ttk.Label(root, text='All Result:')
l_res1.grid(row=6, column=0, sticky='w', padx=10)
result_text = tk.Text(root, width=50, height=20, bg='#A8D8B9')
result_text.grid(row=7, column=0, columnspan=2, padx=10, pady=10)

l_res2 = ttk.Label(root, text='Open Port:')
l_res2.grid(row=8, column=0, sticky='w', padx=10)
open_text = tk.Text(root, width=50, height=10, bg='#B5CAA0', fg='red')
open_text.grid(row=9, column=0, columnspan=2, padx=10, pady=10)

root.mainloop()