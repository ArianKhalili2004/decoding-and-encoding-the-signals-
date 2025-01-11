import turtle
import tkinter as tk

class NRZ:
    def __init__(self, signal: str):
        self.signal = signal
        self.logic_high = 50
        self.logic_low = -50
        self.distance = 50

    def draw(self):
        for bit in self.signal:
            if bit == '0':
                self.zero()
            elif bit == '1':
                self.one()

    def zero(self):
        t.sety(self.logic_low) 
        t.forward(self.distance)

    def one(self):
        t.sety(self.logic_high) 
        t.forward(self.distance)
class NRZ_I:
    def __init__(self, signal: str, start_high: bool = True):
        self.signal = signal
        self.logic_high = 50
        self.logic_low = -50
        self.distance = 50
        self.start_high = start_high

    def draw(self):
        # Set initial position based on start_high
        if self.start_high:
            t.sety(self.logic_high)
        else:
            t.sety(self.logic_low)

        for bit in self.signal:
            if bit == '0':
                self.zero()
            elif bit == '1':
                self.one()

    def zero(self):
        t.forward(self.distance)

    def one(self):
        posx, posy = t.pos()
        if self.logic_low - 1 < posy < self.logic_low + 1:
            t.sety(self.logic_high)
        elif self.logic_high - 1 < posy < self.logic_high + 1:
            t.sety(self.logic_low)
        t.forward(self.distance)
        print(f"NRZ-I: Moved to {t.pos()}")

class NRZ_L:
    def __init__(self, signal: str):
        self.signal = signal
        self.logic_high = 50
        self.logic_low = -50
        self.distance = 50

    def draw(self):
        for bit in self.signal:
            if bit == '0':
                self.zero()
            elif bit == '1':
                self.one()

    def zero(self):
        t.sety(self.logic_high)
        t.forward(self.distance)

    def one(self):
        t.sety(self.logic_low)
        t.forward(self.distance)


class RZ:
    def __init__(self, signal: str):
        self.signal = signal
        self.logic_high = 50
        self.logic_low = -50
        self.distance = 50
        self.base = 0

    def draw(self):
        for bit in self.signal:
            if bit == '0':
                self.zero()
            elif bit == '1':
                self.one()

    def zero(self):
        t.sety(self.logic_low)
        t.forward(self.distance)
        t.sety(self.base)
        setTurtle(*invisiline)
        t.write('0', False, 'right', ("Arial", 12, "normal"))
        setTurtle(*default_settings)
        t.forward(self.distance)

    def one(self):
        t.sety(self.logic_high)
        t.forward(self.distance)
        t.sety(self.base)
        setTurtle(*invisiline)
        t.write('1', False, 'right', ("Arial", 12, "normal"))
        setTurtle(*default_settings)
        t.forward(self.distance)


class Manchester:
    def __init__(self, signal: str):
        self.signal = signal
        self.logic_high = 50
        self.logic_low = -50
        self.distance = 50
        self.base = 0

    def draw(self):
        for bit in self.signal:
            if bit == '0':
                self.zero()
            elif bit == '1':
                self.one()

    def zero(self):
        t.sety(self.logic_high)
        t.forward(self.distance)
        setTurtle(*invisiline)
        t.write('0', False, 'right', ("Arial", 12, "normal"))
        setTurtle(*default_settings)
        t.sety(self.logic_low)
        t.forward(self.distance)

    def one(self):
        t.sety(self.logic_low)
        t.forward(self.distance)
        t.sety(self.logic_high)
        setTurtle(*invisiline)
        t.write('1', False, 'right', ("Arial", 12, "normal"))
        setTurtle(*default_settings)
        t.forward(self.distance)


class diff_Manchester:
    def __init__(self, signal: str, start_pattern: int = 2):
        self.signal = signal
        self.logic_high = 50
        self.logic_low = -50
        self.distance = 50
        self.base = 0
        self.start_pattern = start_pattern 

    def draw(self):
        prev_num = self.start_pattern 
        for bit in self.signal:
            if bit == '0':
                self.pattern(prev_num, '0')
            elif bit == '1':
                num = 1 if prev_num == 2 else 2
                self.pattern(num, '1')
                prev_num = num

    def pattern(self, num, write_bit):
        if num == 1:
            t.sety(self.logic_high)
            t.forward(self.distance)
            setTurtle(*invisiline)
            t.write(write_bit, False, 'right', ("Arial", 12, "normal"))
            setTurtle(*default_settings)
            t.sety(self.logic_low)
            t.forward(self.distance)
        elif num == 2:
            t.sety(self.logic_low)
            t.forward(self.distance)
            t.sety(self.logic_high)
            setTurtle(*invisiline)
            t.write(write_bit, False, 'right', ("Arial", 12, "normal"))
            setTurtle(*default_settings)
            t.forward(self.distance)



def drawAxes():
    def drawLineAndBack(distance):
        for _ in range(distance // 50):
            t.forward(50)
            t.dot(5)
        t.backward(distance)

    t.hideturtle()
    t.speed('fastest')
    t.penup()
    t.setx(-len_X // 2 + 100)
    t.pendown()
    drawLineAndBack(len_X)
    t.right(90)
    drawLineAndBack(len_Y)
    t.right(180)
    drawLineAndBack(len_Y)
    t.right(90)


def setTurtle(size, colour, speed, visibility):
    t.pensize(size)
    t.pencolor(colour)
    t.speed(speed)
    if not visibility:
        t.hideturtle()
    else:
        t.showturtle()


def start_drawing():
    drawAxes()
    setTurtle(*default_settings)
    encoding_class = encoding_map.get(encoding)
    if encoding_class:
        encoding_class.draw()
    else:
        print("Invalid encoding selection. Please restart and choose a valid option.")
        
        
        
        
        
        
        
        
def print_terminal_output(encoding, signal, start_pattern=None):
    print("\nTerminal Output Encoding:")
    if encoding == '1':  
        last_level = 1  
        for bit in signal:
            if bit == '0':
                print(last_level, end=" ")
            elif bit == '1':
                last_level = -1 if last_level == 1 else 1
                print(last_level, end=" ")
    elif encoding == '2':  
        for bit in signal:
            print(-1 if bit == '1' else 1, end=" ")
    elif encoding == '3': 
        for bit in signal:
            if bit == '0':
                print("-1 0", end=" ")
            elif bit == '1':
                print("1 0", end=" ")
    elif encoding == '4': 
        for bit in signal:
            if bit == '0':
                print("1 -1", end=" ")
            elif bit == '1':
                print("-1 1", end=" ")
    elif encoding == '5':  
        last_transition = start_pattern
        for bit in signal:
            if bit == '0':
                if last_transition == 1:
                    print("1 -1", end=" ")
                else:
                    print("-1 1", end=" ")
            elif bit == '1':
                if last_transition == 1:
                    print("-1 1", end=" ")
                    last_transition = 2
                else:
                    print("1 -1", end=" ")
                    last_transition = 1
    elif encoding == '6':  
        for bit in signal:
            print(1 if bit == '1' else -1, end=" ")
    print("\n")


print('Input Signal to be plotted (1s and 0s):')
signal = input().strip()
print('\nChoose Encoding Method:')
print('1. NRZ-I')
print('2. NRZ-L')
print('3. RZ')
print('4. Manchester')
print('5. Differential Manchester')
print('6. NRZ')
encoding = input().strip()

start_pattern = None
if encoding == '5':
    print('Choose starting pattern for Differential Manchester:')
    print('1. Start with Pattern 1 (High-to-Low for 1)')
    print('2. Start with Pattern 2 (Low-to-High for 1)')
    start_pattern = int(input().strip())
    if start_pattern not in [1, 2]:
        print("Invalid selection. Defaulting to Pattern 2.")
        start_pattern = 2
start_high = None
if encoding == '1':
    print("Choose starting position for NRZ-I:")
    print("1. Start High")
    print("2. Start Low")
    start_high = input().strip()
    start_high = start_high == '1'
print("Do you want to display the encoded output in the terminal? (yes/no):")
terminal_option = input().strip().lower()
if terminal_option == 'yes':
    print_terminal_output(encoding, signal, start_pattern)

root = tk.Tk()
root.title('Signal Graph')
root.geometry('1200x600')  
cv = turtle.ScrolledCanvas(root, width=1200, height=600)  
cv.pack()


len_X, len_Y = 5000, 350  
screen = turtle.TurtleScreen(cv)
screen.screensize(len_X, len_Y)
t = turtle.RawTurtle(screen)


default_settings = (2, 'red', 'slow', False) 
invisiline = (1, 'black', 'fastest', False)  



encoding_map = {
    '1': NRZ_I(signal, start_high=start_high),
    '2': NRZ_L(signal),
    '3': RZ(signal),
    '4': Manchester(signal),
    '5': diff_Manchester(signal, start_pattern=start_pattern),
    '6': NRZ(signal)  
}


root.after(100, start_drawing)


root.mainloop()
