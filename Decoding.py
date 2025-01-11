import tkinter as tk
from tkinter import messagebox, Listbox

def decode_nrz(signal):
    return [1 if level > 0 else 0 for level in signal]

def decode_nrz_l(signal):
    return [0 if level > 0 else 1 for level in signal]

def decode_nrz_i(signal):
    binary = []
    current_level = signal[0]
    binary.append(0)
    for i in range(1, len(signal)):
        if signal[i] != current_level:
            binary.append(1)
            current_level = signal[i]
        else:
            binary.append(0)
    binary[0] = 1
    return binary

def decode_manchester(signal):
    binary = []
    if len(signal) % 2 != 0:
        raise ValueError("Invalid Manchester signal length, must be even.")
    for i in range(0, len(signal), 2):
        if signal[i] == -1 and signal[i + 1] == 1:
            binary.append(1)
        elif signal[i] == 1 and signal[i + 1] == -1:
            binary.append(0)
        else:
            raise ValueError("Invalid Manchester signal pair.")
    return binary

def decode_manchester_differential(signal):
    binary = []
    if len(signal) % 2 != 0:
        raise ValueError("Invalid Differential Manchester signal length, must be even.")
    prev_level = signal[0]
    for i in range(0, len(signal), 2):
        current_first_level = signal[i]
        if current_first_level != prev_level:
            bit = 0
        else:
            bit = 1
        binary.append(bit)
        prev_level = signal[i + 1]
    return binary

def decode_rz(signal):
    binary = []
    if len(signal) % 2 != 0:
        raise ValueError("Invalid RZ signal length, must be even.")
    for i in range(0, len(signal), 2):
        if signal[i] == 1 and signal[i + 1] == 0:
            binary.append(1)
        elif signal[i] == -1 and signal[i + 1] == 0:
            binary.append(0)
        elif signal[i] == 0 and signal[i + 1] == 0:
            binary.append(0)
        else:
            raise ValueError(f"Invalid RZ signal pair at index {i}: {signal[i:i+2]}")
    return binary

def perform_decoding():
    try:
        choice = listbox.curselection()
        if not choice:
            raise ValueError("Please select a decoding method.")

        method_name, decode_func = decoding_methods[choice[0]]
        signal_input = signal_entry.get().strip()

        if not signal_input:
            raise ValueError("Please enter a signal.")

        signal = [int(x) for x in signal_input.split()]
        decoded_signal = decode_func(signal)

        messagebox.showinfo("Decoded Signal", f"Decoded {method_name} Signal: {decoded_signal}")
    except ValueError as e:
        messagebox.showerror("Error", str(e))

def create_gui():
    global listbox, signal_entry

    root = tk.Tk()
    root.title("Signal Decoder")

    tk.Label(root, text="Select Decoding Method:").pack(pady=5)

    listbox = Listbox(root, height=len(decoding_methods), selectmode=tk.SINGLE)
    for name, _ in decoding_methods:
        listbox.insert(tk.END, name)
    listbox.pack(pady=5)

    tk.Label(root, text="Enter the signal as space-separated integers (e.g., 1 -1 1 0):").pack(pady=5)

    signal_entry = tk.Entry(root, width=50)
    signal_entry.pack(pady=5)

    decode_button = tk.Button(root, text="Decode", command=perform_decoding)
    decode_button.pack(pady=10)

    root.mainloop()

decoding_methods = [
    ('NRZ', decode_nrz),
    ('NRZ-L', decode_nrz_l),
    ('NRZ-I', decode_nrz_i),
    ('Manchester', decode_manchester),
    ('Manchester Differential', decode_manchester_differential),
    ('RZ', decode_rz)
]

if __name__ == "__main__":
    create_gui()
