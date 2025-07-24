#12313
import logging
import serial
import struct
import time
import threading
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import datetime
import csv
import traceback
import serial.tools.list_ports

# --- CRC16 Modbus implementation ---
def crc16(data: bytes) -> int:
    crc = 0xFFFF
    for pos in data:
        crc ^= pos
        for _ in range(8):
            if (crc & 0x0001) != 0:
                crc >>= 1
                crc ^= 0xA001
            else:
                crc >>= 1
    return crc

def parse_modbus_request(frame: bytes):
    if not frame or len(frame) < 2:
        return ""
    addr = frame[0]
    func = frame[1]
    info = f"Addr: {addr} | Func: {func:02X}"
    if func == 0x01:
        if len(frame) >= 6:
            reg = int.from_bytes(frame[2:4], "big")
            cnt = int.from_bytes(frame[4:6], "big")
            info += f" | Coil Addr: {reg} | Qty: {cnt}"
    elif func == 0x03 or func == 0x04:
        if len(frame) >= 6:
            reg = int.from_bytes(frame[2:4], "big")
            cnt = int.from_bytes(frame[4:6], "big")
            info += f" | Reg: {reg} | Cnt: {cnt}"
    elif func == 0x06:
        if len(frame) >= 6:
            reg = int.from_bytes(frame[2:4], "big")
            val = int.from_bytes(frame[4:6], "big")
            info += f" | Reg: {reg} | Val: {val}"
    elif func == 0x10:
        if len(frame) >= 7:
            reg = int.from_bytes(frame[2:4], "big")
            cnt = int.from_bytes(frame[4:6], "big")
            info += f" | Reg: {reg} | Cnt: {cnt}"
    return info

HELP_TEXT = """Сниффер Modbus RTU. Выберите COM-порт и скорость, чтобы начать захват трафика.
Поддерживаются функции: 01, 03, 04, 06, 10 и др.
Лог отображается с подсветкой CRC и возможностью экспорта."""

class ModbusRS485SnifferGUI:
    def __init__(self, master):
        self.master = master
        master.title("Modbus RTU RS485 Sniffer")

        self.serial_conn = None
        self.sniffing = False
        self.thread = None
        self.log_lines = []

        # Logging setup
        logging.basicConfig(filename="sniffer_errors.log", level=logging.ERROR)

        # --- Интерфейс ---
        frame = ttk.Frame(master)
        frame.pack(padx=10, pady=10, fill="x")

        ttk.Label(frame, text="COM-порт:").grid(row=0, column=0, sticky="w")
        self.port_var = tk.StringVar()
        self.port_combo = ttk.Combobox(frame, textvariable=self.port_var, width=12, state="readonly")
        self.port_combo['values'] = self.get_serial_ports()
        self.port_combo.grid(row=0, column=1, padx=(0, 10))
        if self.port_combo['values']:
            self.port_combo.current(0)

        ttk.Label(frame, text="Скорость:").grid(row=0, column=2, sticky="w")
        self.baud_var = tk.StringVar(value="19200")
        self.baud_combo = ttk.Combobox(frame, textvariable=self.baud_var, width=10, state="readonly")
        self.baud_combo['values'] = ["9600", "19200", "38400", "57600", "115200"]
        self.baud_combo.grid(row=0, column=3, padx=(0, 10))

        ttk.Label(frame, text="Фильтр по адресу:").grid(row=0, column=4, sticky="w")
        self.addr_filter_var = tk.StringVar()
        self.addr_filter_entry = ttk.Entry(frame, textvariable=self.addr_filter_var, width=6)
        self.addr_filter_entry.grid(row=0, column=5, padx=(0, 10))

        self.start_button = ttk.Button(frame, text="Старт", command=self.start_sniffer)
        self.start_button.grid(row=0, column=6, padx=(0, 5))
        self.stop_button = ttk.Button(frame, text="Стоп", command=self.stop_sniffer, state="disabled")
        self.stop_button.grid(row=0, column=7, padx=(0, 5))

        self.save_button = ttk.Button(frame, text="Сохранить лог", command=self.save_log)
        self.save_button.grid(row=0, column=8, padx=(0, 5))

        self.help_button = ttk.Button(frame, text="Help", command=self.show_help)
        self.help_button.grid(row=0, column=9)

        # Лог
        self.log_text = tk.Text(master, wrap="none", height=25, font=("Courier New", 10))
        self.log_text.pack(padx=10, pady=(0, 10), fill="both", expand=True)
        self.log_text.config(state="disabled")

        master.protocol("WM_DELETE_WINDOW", self.on_close)

    def get_serial_ports(self):
        try:
            return [p.device for p in serial.tools.list_ports.comports()]
        except Exception as e:
            logging.error("Ошибка получения портов: %s", e)
            return []

    def log_to_file(self, msg):
        with open("modbus_sniffer_log.txt", "a", encoding="utf-8") as log_file:
            log_file.write(f"{msg}")

    def log(self, msg, color=None):
        timestamp = datetime.datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
        full_msg = f"{timestamp} {msg}"
        self.log_lines.append(full_msg)

        self.log_text.config(state="normal")
        self.log_text.insert("end", full_msg + "")
        if color:
            self.log_text.tag_add(color, "end-2l", "end-1l")
            self.log_text.tag_config("green", foreground="green")
            self.log_text.tag_config("red", foreground="red")
        self.log_text.see("end")
        self.log_text.config(state="disabled")
        self.log_to_file(full_msg)

    def start_sniffer(self):
        port = self.port_var.get()
        if not port:
            messagebox.showerror("Ошибка", "COM-порт не выбран.")
            return
        try:
            baud = int(self.baud_var.get())
        except ValueError:
            messagebox.showerror("Ошибка", "Некорректная скорость.")
            return

        self.sniffing = True
        self.start_button.config(state="disabled")
        self.stop_button.config(state="normal")
        self.log_lines.clear()
        self.log_text.config(state="normal")
        self.log_text.delete(1.0, "end")
        self.log_text.config(state="disabled")

        self.thread = threading.Thread(target=self.sniff, args=(port, baud), daemon=True)
        self.thread.start()

    def stop_sniffer(self):
        self.sniffing = False
        self.start_button.config(state="normal")
        self.stop_button.config(state="disabled")
        if self.serial_conn and self.serial_conn.is_open:
            self.serial_conn.close()
        self.log("Сниффер остановлен.")

    def sniff(self, port, baud):
        try:
            self.serial_conn = serial.Serial(
                port=port,
                baudrate=baud,
                bytesize=serial.EIGHTBITS,
                parity=serial.PARITY_NONE,
                stopbits=serial.STOPBITS_ONE,
                timeout=0.01
            )
            self.log(f"Подключено к {port} @ {baud} бод.")
        except Exception as e:
            self.log(f"Ошибка подключения: {e}", color="red")
            logging.error("Traceback: %s", traceback.format_exc())
            self.stop_sniffer()
            return

        buffer = bytearray()
        direction = "RX"
        last_data_time = time.time()

        while self.sniffing:
            try:
                now = time.time()
                waiting = self.serial_conn.in_waiting
                if waiting > 0:
                    data = self.serial_conn.read(waiting)
                    buffer.extend(data)
                    last_data_time = now
                elif buffer and (now - last_data_time > 0.02):
                    idx = 0
                    while idx + 4 <= len(buffer):
                        for end in range(idx + 4, len(buffer) + 1):
                            candidate = buffer[idx:end]
                            frame_wo_crc = candidate[:-2]
                            crc_recv = int.from_bytes(candidate[-2:], "little")
                            crc_calc = crc16(frame_wo_crc)
                            if crc_calc == crc_recv:
                                addr = candidate[0]
                                if self.addr_filter_var.get() and str(addr) != self.addr_filter_var.get():
                                    idx = end
                                    continue
                                hex_str = ' '.join(f"{b:02X}" for b in candidate)
                                info = parse_modbus_request(candidate)
                                self.log(f"{direction} | Addr: {addr} | CRC: OK | {hex_str} | {info}", color="green")
                                idx = end
                                break
                        else:
                            idx += 1
                    if idx < len(buffer):
                        remain = buffer[idx:]
                        hex_str = ' '.join(f"{b:02X}" for b in remain)
                        addr = remain[0] if remain else "-"
                        self.log(f"{direction} | Addr: {addr} | CRC: BAD/Incomplete | {hex_str}", color="red")
                    buffer.clear()
                    direction = "RX" if direction == "TX" else "TX"
                time.sleep(0.001)
            except Exception as e:
                self.log(f"Ошибка: {e}", color="red")
                logging.error("Traceback: %s", traceback.format_exc())
                break
        self.sniffing = False

    def save_log(self):
        if not self.log_lines:
            messagebox.showinfo("Сохранение", "Лог пуст.")
            return
        file_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv")])
        if file_path:
            with open(file_path, "w", encoding="utf-8", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["Time", "Message"])
                for line in self.log_lines:
                    ts, msg = line.split(" ", 1)
                    writer.writerow([ts.strip("[]"), msg])
            messagebox.showinfo("Готово", f"Лог сохранён в: {file_path}")

    def show_help(self):
        win = tk.Toplevel(self.master)
        win.title("Справка")
        win.geometry("600x400")
        txt = tk.Text(win, wrap="word")
        txt.insert("1.0", HELP_TEXT)
        txt.config(state="disabled")
        txt.pack(expand=True, fill="both", padx=10, pady=10)
        ttk.Button(win, text="Закрыть", command=win.destroy).pack(pady=5)

    def on_close(self):
        self.sniffing = False
        time.sleep(0.1)
        self.master.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = ModbusRS485SnifferGUI(root)
    root.mainloop()
