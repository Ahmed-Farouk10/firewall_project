from pyshark import LiveCapture

print("Available interfaces:")
for interface in LiveCapture().interfaces:
    print(interface)
